//! Platform-specific CEK (Cache Encryption Key) storage.
//!
//! The CEK is a random 256-bit key used to envelope-encrypt the vault cache.
//! It is stored in the OS credential store so that a copied cache file is
//! useless without access to the original machine's credential store.
//!
//! Platform support:
//! - macOS: Keychain Services with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
//! - Linux: Secret Service API via the `keyring` crate (GNOME Keyring / KDE KWallet)
//! - Fallback: no CEK (cache protected by master password only)

use crate::error::SdkError;
use zeroize::Zeroizing;

const SERVICE_NAME: &str = "com.grimoire.vault-cache";
const ACCOUNT_NAME: &str = "cek-v1";

/// Trait for platform-specific CEK storage.
pub trait KeyStore: Send + Sync {
    /// Store the CEK. Overwrites any existing value.
    fn store_cek(&self, cek: &[u8; 32]) -> Result<(), SdkError>;

    /// Load the CEK. Returns None if no CEK is stored.
    /// The returned key is wrapped in `Zeroizing` so it is cleared on drop.
    fn load_cek(&self) -> Result<Option<Zeroizing<[u8; 32]>>, SdkError>;

    /// Delete the CEK.
    fn delete_cek(&self) -> Result<(), SdkError>;

    /// Human-readable name of this keystore backend.
    fn backend_name(&self) -> &'static str;
}

/// Detect and return the best available keystore for this platform.
pub fn platform_keystore() -> Option<Box<dyn KeyStore>> {
    #[cfg(target_os = "macos")]
    {
        Some(Box::new(macos::MacOSKeyStore))
    }

    #[cfg(target_os = "linux")]
    {
        match linux::LinuxKeyStore::new() {
            Ok(ks) => Some(Box::new(ks)),
            Err(e) => {
                tracing::warn!("No Linux credential store available: {e}");
                None
            }
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

/// Generate a random 256-bit CEK. Wrapped in `Zeroizing` for automatic cleanup.
pub fn generate_cek() -> Zeroizing<[u8; 32]> {
    use rand::RngCore;
    let mut cek = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(cek.as_mut());
    cek
}

// --- macOS implementation ---

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    pub struct MacOSKeyStore;

    impl KeyStore for MacOSKeyStore {
        fn store_cek(&self, cek: &[u8; 32]) -> Result<(), SdkError> {
            // Delete any existing item first (set_generic_password updates or creates)
            let _ = delete_generic_password(SERVICE_NAME, ACCOUNT_NAME);

            set_generic_password(SERVICE_NAME, ACCOUNT_NAME, cek)
                .map_err(|e| SdkError::Internal(format!("Keychain store failed: {e}")))?;

            tracing::debug!("CEK stored in macOS Keychain");
            Ok(())
        }

        fn load_cek(&self) -> Result<Option<Zeroizing<[u8; 32]>>, SdkError> {
            match get_generic_password(SERVICE_NAME, ACCOUNT_NAME) {
                Ok(data) => {
                    if data.len() != 32 {
                        return Err(SdkError::Internal(format!(
                            "CEK has wrong length: {} (expected 32)",
                            data.len()
                        )));
                    }
                    let mut cek = Zeroizing::new([0u8; 32]);
                    cek.copy_from_slice(&data);
                    Ok(Some(cek))
                }
                Err(e) => {
                    // errSecItemNotFound means no CEK stored
                    let msg = format!("{e}");
                    if msg.contains("not found") || msg.contains("-25300") {
                        Ok(None)
                    } else {
                        Err(SdkError::Internal(format!("Keychain load failed: {e}")))
                    }
                }
            }
        }

        fn delete_cek(&self) -> Result<(), SdkError> {
            match delete_generic_password(SERVICE_NAME, ACCOUNT_NAME) {
                Ok(()) => {
                    tracing::debug!("CEK deleted from macOS Keychain");
                    Ok(())
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("not found") || msg.contains("-25300") {
                        Ok(()) // Already deleted
                    } else {
                        Err(SdkError::Internal(format!("Keychain delete failed: {e}")))
                    }
                }
            }
        }

        fn backend_name(&self) -> &'static str {
            "macOS Keychain"
        }
    }
}

// --- Linux implementation ---

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    pub struct LinuxKeyStore {
        entry: keyring::Entry,
    }

    impl LinuxKeyStore {
        pub fn new() -> Result<Self, SdkError> {
            let entry = keyring::Entry::new(SERVICE_NAME, ACCOUNT_NAME)
                .map_err(|e| SdkError::Internal(format!("Keyring init failed: {e}")))?;
            Ok(Self { entry })
        }
    }

    impl KeyStore for LinuxKeyStore {
        fn store_cek(&self, cek: &[u8; 32]) -> Result<(), SdkError> {
            self.entry
                .set_secret(cek)
                .map_err(|e| SdkError::Internal(format!("Keyring store failed: {e}")))?;
            tracing::debug!("CEK stored in Linux credential store");
            Ok(())
        }

        fn load_cek(&self) -> Result<Option<Zeroizing<[u8; 32]>>, SdkError> {
            match self.entry.get_secret() {
                Ok(data) => {
                    if data.len() != 32 {
                        return Err(SdkError::Internal(format!(
                            "CEK has wrong length: {} (expected 32)",
                            data.len()
                        )));
                    }
                    let mut cek = Zeroizing::new([0u8; 32]);
                    cek.copy_from_slice(&data);
                    Ok(Some(cek))
                }
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(SdkError::Internal(format!("Keyring load failed: {e}"))),
            }
        }

        fn delete_cek(&self) -> Result<(), SdkError> {
            match self.entry.delete_credential() {
                Ok(()) => {
                    tracing::debug!("CEK deleted from Linux credential store");
                    Ok(())
                }
                Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(SdkError::Internal(format!("Keyring delete failed: {e}"))),
            }
        }

        fn backend_name(&self) -> &'static str {
            "Linux Secret Service"
        }
    }
}
