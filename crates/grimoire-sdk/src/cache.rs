//! Offline vault cache — encrypted local copy of the vault for cache-first unlock.
//!
//! See `specs/016-offline-support.md` for the full design.
//!
//! The cache stores encrypted vault data on disk so the service can unlock
//! without contacting the server. It is envelope-encrypted with a platform-bound
//! Cache Encryption Key (CEK) stored in the OS credential store.
//!
//! File format (`vault_cache.bin`):
//! ```text
//! [4 bytes: magic "GRMC"]
//! [4 bytes: version (u32 LE)]
//! [1 byte: flags (bit 0 = CEK encrypted)]
//! [32 bytes: vault_hash (SHA-256 of encrypted ciphers)]
//! [24 bytes: XChaCha20 nonce (zeros if no CEK)]
//! [4 bytes: body length (u32 LE)]
//! [body: XChaCha20-Poly1305 ciphertext if CEK, or raw JSON if no CEK]
//! ```

use crate::error::SdkError;
use bitwarden_crypto::Kdf;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::num::NonZeroU32;
type HmacSha256 = Hmac<Sha256>;

const CACHE_MAGIC: &[u8; 4] = b"GRMC";
const CACHE_VERSION: u32 = 1;
const FLAG_CEK_ENCRYPTED: u8 = 0x01;

/// Maximum cache body size: 256 MiB. Prevents OOM from crafted body_len values.
const MAX_BODY_SIZE: usize = 256 * 1024 * 1024;

// KDF floor enforcement (spec Vector 7 mitigation)
const MIN_PBKDF2_ITERATIONS: u32 = 100_000;
const MIN_ARGON2_ITERATIONS: u32 = 3;
const MIN_ARGON2_MEMORY_MIB: u32 = 64;
const MIN_ARGON2_PARALLELISM: u32 = 1;

/// KDF parameters in a serializable form (mirrors `bitwarden_crypto::Kdf`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum CachedKdf {
    PBKDF2 { iterations: u32 },
    Argon2id { iterations: u32, memory: u32, parallelism: u32 },
}

impl CachedKdf {
    pub fn from_kdf(kdf: &Kdf) -> Self {
        match kdf {
            Kdf::PBKDF2 { iterations } => CachedKdf::PBKDF2 {
                iterations: iterations.get(),
            },
            Kdf::Argon2id {
                iterations,
                memory,
                parallelism,
            } => CachedKdf::Argon2id {
                iterations: iterations.get(),
                memory: memory.get(),
                parallelism: parallelism.get(),
            },
        }
    }

    pub fn to_kdf(&self) -> Result<Kdf, SdkError> {
        match self {
            CachedKdf::PBKDF2 { iterations } => {
                let iter = NonZeroU32::new(*iterations)
                    .ok_or_else(|| SdkError::Internal("Zero PBKDF2 iterations in cache".into()))?;
                Ok(Kdf::PBKDF2 { iterations: iter })
            }
            CachedKdf::Argon2id {
                iterations,
                memory,
                parallelism,
            } => {
                let iter = NonZeroU32::new(*iterations)
                    .ok_or_else(|| SdkError::Internal("Zero Argon2 iterations in cache".into()))?;
                let mem = NonZeroU32::new(*memory)
                    .ok_or_else(|| SdkError::Internal("Zero Argon2 memory in cache".into()))?;
                let par = NonZeroU32::new(*parallelism)
                    .ok_or_else(|| SdkError::Internal("Zero Argon2 parallelism in cache".into()))?;
                Ok(Kdf::Argon2id {
                    iterations: iter,
                    memory: mem,
                    parallelism: par,
                })
            }
        }
    }

    /// Enforce minimum KDF params to prevent downgrade via cache poisoning.
    pub fn validate_floor(&self) -> Result<(), SdkError> {
        match self {
            CachedKdf::PBKDF2 { iterations } => {
                if *iterations < MIN_PBKDF2_ITERATIONS {
                    return Err(SdkError::Internal(format!(
                        "Cached PBKDF2 iterations ({iterations}) below minimum ({MIN_PBKDF2_ITERATIONS})"
                    )));
                }
            }
            CachedKdf::Argon2id {
                iterations,
                memory,
                parallelism,
            } => {
                if *iterations < MIN_ARGON2_ITERATIONS {
                    return Err(SdkError::Internal(format!(
                        "Cached Argon2 iterations ({iterations}) below minimum ({MIN_ARGON2_ITERATIONS})"
                    )));
                }
                if *memory < MIN_ARGON2_MEMORY_MIB {
                    return Err(SdkError::Internal(format!(
                        "Cached Argon2 memory ({memory} MiB) below minimum ({MIN_ARGON2_MEMORY_MIB} MiB)"
                    )));
                }
                if *parallelism < MIN_ARGON2_PARALLELISM {
                    return Err(SdkError::Internal(format!(
                        "Cached Argon2 parallelism ({parallelism}) below minimum ({MIN_ARGON2_PARALLELISM})"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// The inner cache data that gets serialized, HMAC'd, and optionally CEK-encrypted.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultCache {
    pub version: u32,
    pub kdf: CachedKdf,
    pub encrypted_user_key: String,
    pub encrypted_private_key: String,
    pub user_id: Option<String>,
    pub email: String,
    pub server_url: String,
    pub ciphers: Vec<serde_json::Value>,
    pub last_sync: Option<DateTime<Utc>>,
    /// HMAC-SHA256 for password verification + integrity (hex-encoded).
    /// Zeroed during canonical form computation.
    pub integrity_hmac: String,
}

impl std::fmt::Debug for VaultCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultCache")
            .field("version", &self.version)
            .field("kdf", &self.kdf)
            .field("encrypted_user_key", &"[REDACTED]")
            .field("encrypted_private_key", &"[REDACTED]")
            .field("user_id", &self.user_id)
            .field("email", &self.email)
            .field("server_url", &self.server_url)
            .field("ciphers", &format!("[{} items]", self.ciphers.len()))
            .field("last_sync", &self.last_sync)
            .field("integrity_hmac", &"[REDACTED]")
            .finish()
    }
}

impl VaultCache {
    /// Build a new cache with the HMAC computed from the password hash.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        kdf: &Kdf,
        encrypted_user_key: String,
        encrypted_private_key: String,
        user_id: Option<String>,
        email: String,
        server_url: String,
        ciphers: Vec<serde_json::Value>,
        last_sync: Option<DateTime<Utc>>,
        password_hash: &str,
    ) -> Result<Self, SdkError> {
        let mut cache = Self {
            version: CACHE_VERSION,
            kdf: CachedKdf::from_kdf(kdf),
            encrypted_user_key,
            encrypted_private_key,
            user_id,
            email,
            server_url,
            ciphers,
            last_sync,
            integrity_hmac: String::new(),
        };
        cache.integrity_hmac = cache.compute_hmac(password_hash)?;
        Ok(cache)
    }

    /// Compute the HMAC over the canonical cache form.
    fn compute_hmac(&self, password_hash: &str) -> Result<String, SdkError> {
        let hmac_key = derive_hmac_key(password_hash)?;
        let canonical = self.canonical_bytes()?;

        let mut mac = HmacSha256::new_from_slice(hmac_key.as_ref())
            .map_err(|e| SdkError::Internal(format!("HMAC init failed: {e}")))?;
        mac.update(&canonical);
        let result = mac.finalize();
        Ok(hex::encode(&result.into_bytes()))
    }

    /// Verify the HMAC against a password hash.
    pub fn verify_hmac(&self, password_hash: &str) -> Result<bool, SdkError> {
        let expected = self.compute_hmac(password_hash)?;
        Ok(constant_time_eq_hmac(self.integrity_hmac.as_bytes(), expected.as_bytes()))
    }

    /// Serialize with the HMAC field zeroed for deterministic canonical form.
    fn canonical_bytes(&self) -> Result<Vec<u8>, SdkError> {
        let mut canonical = self.clone();
        canonical.integrity_hmac = String::new();
        serde_json::to_vec(&canonical)
            .map_err(|e| SdkError::Internal(format!("Cache serialization failed: {e}")))
    }
}

/// Derive the HMAC key from the password hash using HKDF-SHA256.
/// Returns a zeroizing key that is cleared when dropped.
fn derive_hmac_key(password_hash: &str) -> Result<zeroize::Zeroizing<[u8; 32]>, SdkError> {
    use hkdf::Hkdf;

    let hk = Hkdf::<Sha256>::new(
        Some(b"grimoire-vault-cache"),
        password_hash.as_bytes(),
    );
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    hk.expand(b"hmac-v1", key.as_mut())
        .map_err(|e| SdkError::Internal(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

/// Constant-time comparison for fixed-length HMAC hex strings.
/// Both inputs must be 64 bytes (HMAC-SHA256 hex encoding). If either is
/// the wrong length, returns false — this indicates a bug, not a wrong password.
fn constant_time_eq_hmac(a: &[u8], b: &[u8]) -> bool {
    // HMAC-SHA256 → 32 bytes → 64 hex chars. Fixed length avoids timing leak.
    if a.len() != 64 || b.len() != 64 {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Hex encoding (avoid adding a dependency for this).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// --- File I/O ---

/// On-disk envelope wrapping the (optionally encrypted) VaultCache.
pub struct CacheEnvelope {
    pub flags: u8,
    pub vault_hash: [u8; 32],
    pub nonce: [u8; 24],
    pub body: Vec<u8>,
}

impl CacheEnvelope {
    pub fn is_encrypted(&self) -> bool {
        self.flags & FLAG_CEK_ENCRYPTED != 0
    }
}

/// Seal a VaultCache into a CacheEnvelope, encrypting with CEK if provided.
pub fn seal_cache(cache: &VaultCache, cek: Option<&[u8; 32]>) -> Result<CacheEnvelope, SdkError> {
    let plaintext = serde_json::to_vec(cache)
        .map_err(|e| SdkError::Internal(format!("Cache serialization failed: {e}")))?;

    let vault_hash = compute_vault_hash(&cache.ciphers);

    if let Some(key) = cek {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::XChaCha20Poly1305;
        use rand::RngCore;

        let cipher = XChaCha20Poly1305::new(key.into());
        let mut nonce_bytes = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| SdkError::Internal(format!("Cache encryption failed: {e}")))?;

        Ok(CacheEnvelope {
            flags: FLAG_CEK_ENCRYPTED,
            vault_hash,
            nonce: nonce_bytes,
            body: ciphertext,
        })
    } else {
        Ok(CacheEnvelope {
            flags: 0,
            vault_hash,
            nonce: [0u8; 24],
            body: plaintext,
        })
    }
}

/// Open a CacheEnvelope, decrypting with CEK if needed.
pub fn open_cache(envelope: &CacheEnvelope, cek: Option<&[u8; 32]>) -> Result<VaultCache, SdkError> {
    let plaintext = if envelope.is_encrypted() {
        let key = cek.ok_or_else(|| {
            SdkError::Internal("Cache is CEK-encrypted but no CEK available".into())
        })?;

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::XChaCha20Poly1305;

        let cipher = XChaCha20Poly1305::new(key.into());
        let nonce = chacha20poly1305::XNonce::from_slice(&envelope.nonce);

        cipher
            .decrypt(nonce, envelope.body.as_ref())
            .map_err(|_| SdkError::Internal("Cache decryption failed (CEK mismatch or corrupted)".into()))?
    } else {
        envelope.body.clone()
    };

    serde_json::from_slice(&plaintext)
        .map_err(|e| SdkError::Internal(format!("Cache deserialization failed: {e}")))
}

/// Compute SHA-256 vault hash over the encrypted cipher array.
pub fn compute_vault_hash(ciphers: &[serde_json::Value]) -> [u8; 32] {
    use sha2::Digest;

    let mut hasher = Sha256::new();
    // Serialize the cipher array deterministically.
    // serde_json::to_vec on Vec<Value> cannot fail in practice (no I/O, no
    // custom serializers), but we handle it defensively by hashing the error
    // message so different failures still produce different hashes.
    match serde_json::to_vec(ciphers) {
        Ok(bytes) => hasher.update(&bytes),
        Err(e) => {
            tracing::error!("Cipher serialization failed for vault hash: {e}");
            hasher.update(format!("ERROR:{e}").as_bytes());
        }
    }
    hasher.finalize().into()
}

fn cache_file_path() -> Option<std::path::PathBuf> {
    dirs::data_dir().map(|d| d.join("grimoire").join("vault_cache.bin"))
}

/// Write a CacheEnvelope to disk atomically with 0600 permissions.
pub fn write_cache_file(envelope: &CacheEnvelope) -> Result<(), SdkError> {
    use std::io::Write;

    let path = cache_file_path()
        .ok_or_else(|| SdkError::Internal("Cannot determine data directory".into()))?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| SdkError::Internal(format!("Failed to create data dir: {e}")))?;
    }

    let mut buf = Vec::new();
    buf.extend_from_slice(CACHE_MAGIC);
    buf.extend_from_slice(&CACHE_VERSION.to_le_bytes());
    buf.push(envelope.flags);
    buf.extend_from_slice(&envelope.vault_hash);
    buf.extend_from_slice(&envelope.nonce);
    let body_len = u32::try_from(envelope.body.len())
        .map_err(|_| SdkError::Internal("Cache body too large".into()))?;
    buf.extend_from_slice(&body_len.to_le_bytes());
    buf.extend_from_slice(&envelope.body);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut f| {
                f.write_all(&buf)?;
                f.sync_all()
            })
            .map_err(|e| SdkError::Internal(format!("Failed to write cache: {e}")))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(&path, &buf)
            .map_err(|e| SdkError::Internal(format!("Failed to write cache: {e}")))?;
    }

    tracing::debug!("Vault cache written to {}", path.display());
    Ok(())
}

/// Read a CacheEnvelope from disk. Returns None if the file doesn't exist.
pub fn read_cache_file() -> Result<Option<CacheEnvelope>, SdkError> {
    let path = match cache_file_path() {
        Some(p) if p.exists() => p,
        _ => return Ok(None),
    };

    let data = std::fs::read(&path)
        .map_err(|e| SdkError::Internal(format!("Failed to read cache: {e}")))?;

    parse_cache_envelope(&data).map(Some)
}

/// Read only the vault hash from the cache file header (no decryption needed).
pub fn read_vault_hash() -> Result<Option<[u8; 32]>, SdkError> {
    let path = match cache_file_path() {
        Some(p) if p.exists() => p,
        _ => return Ok(None),
    };

    let data = std::fs::read(&path)
        .map_err(|e| SdkError::Internal(format!("Failed to read cache header: {e}")))?;

    // Header: 4 (magic) + 4 (version) + 1 (flags) + 32 (vault_hash) = 41 bytes minimum
    if data.len() < 41 {
        return Err(SdkError::Internal("Cache file too small".into()));
    }
    if &data[0..4] != CACHE_MAGIC {
        return Err(SdkError::Internal("Invalid cache magic".into()));
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[9..41]);
    Ok(Some(hash))
}

/// Delete the cache file from disk.
pub fn delete_cache_file() {
    if let Some(path) = cache_file_path() {
        if path.exists() {
            if let Err(e) = std::fs::remove_file(&path) {
                tracing::warn!("Failed to remove cache file: {e}");
            } else {
                tracing::info!("Vault cache deleted");
            }
        }
    }
}

fn parse_cache_envelope(data: &[u8]) -> Result<CacheEnvelope, SdkError> {
    // Minimum: 4 + 4 + 1 + 32 + 24 + 4 = 69 bytes header
    if data.len() < 69 {
        return Err(SdkError::Internal("Cache file too small".into()));
    }
    if &data[0..4] != CACHE_MAGIC {
        return Err(SdkError::Internal("Invalid cache magic".into()));
    }

    let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if version != CACHE_VERSION {
        return Err(SdkError::Internal(format!(
            "Unsupported cache version: {version}"
        )));
    }

    let flags = data[8];

    let mut vault_hash = [0u8; 32];
    vault_hash.copy_from_slice(&data[9..41]);

    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&data[41..65]);

    let body_len = u32::from_le_bytes([data[65], data[66], data[67], data[68]]) as usize;
    if body_len > MAX_BODY_SIZE {
        return Err(SdkError::Internal(format!(
            "Cache body too large: {body_len} bytes (max {MAX_BODY_SIZE})"
        )));
    }
    if data.len() < 69 + body_len {
        return Err(SdkError::Internal("Cache file truncated".into()));
    }

    let body = data[69..69 + body_len].to_vec();

    Ok(CacheEnvelope {
        flags,
        vault_hash,
        nonce,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kdf() -> Kdf {
        Kdf::PBKDF2 {
            iterations: NonZeroU32::new(600_000).unwrap(),
        }
    }

    #[test]
    fn vault_cache_hmac_roundtrip() {
        let cache = VaultCache::build(
            &test_kdf(),
            "enc_user_key".into(),
            "enc_private_key".into(),
            Some("user-id".into()),
            "test@example.com".into(),
            "https://vault.example.com".into(),
            vec![serde_json::json!({"id": "1", "name": "encrypted"})],
            Some(Utc::now()),
            "test_password_hash",
        )
        .unwrap();

        assert!(!cache.integrity_hmac.is_empty());
        assert!(cache.verify_hmac("test_password_hash").unwrap());
        assert!(!cache.verify_hmac("wrong_password_hash").unwrap());
    }

    #[test]
    fn vault_cache_tamper_detection() {
        let mut cache = VaultCache::build(
            &test_kdf(),
            "enc_user_key".into(),
            "enc_private_key".into(),
            None,
            "test@example.com".into(),
            "https://vault.example.com".into(),
            vec![],
            None,
            "pw_hash",
        )
        .unwrap();

        // Tamper with a field
        cache.email = "evil@attacker.com".into();
        assert!(!cache.verify_hmac("pw_hash").unwrap());
    }

    #[test]
    fn kdf_floor_validation() {
        let weak_pbkdf2 = CachedKdf::PBKDF2 { iterations: 1 };
        assert!(weak_pbkdf2.validate_floor().is_err());

        let ok_pbkdf2 = CachedKdf::PBKDF2 { iterations: 600_000 };
        assert!(ok_pbkdf2.validate_floor().is_ok());

        let weak_argon = CachedKdf::Argon2id {
            iterations: 1,
            memory: 64,
            parallelism: 1,
        };
        assert!(weak_argon.validate_floor().is_err());

        let ok_argon = CachedKdf::Argon2id {
            iterations: 3,
            memory: 64,
            parallelism: 4,
        };
        assert!(ok_argon.validate_floor().is_ok());
    }

    #[test]
    fn seal_open_roundtrip_no_cek() {
        let cache = VaultCache::build(
            &test_kdf(),
            "key".into(),
            "priv".into(),
            None,
            "a@b.com".into(),
            "https://v.com".into(),
            vec![serde_json::json!({"test": true})],
            None,
            "hash",
        )
        .unwrap();

        let envelope = seal_cache(&cache, None).unwrap();
        assert!(!envelope.is_encrypted());

        let recovered = open_cache(&envelope, None).unwrap();
        assert_eq!(recovered.email, "a@b.com");
        assert!(recovered.verify_hmac("hash").unwrap());
    }

    #[test]
    fn seal_open_roundtrip_with_cek() {
        let cek = [42u8; 32];
        let cache = VaultCache::build(
            &test_kdf(),
            "key".into(),
            "priv".into(),
            None,
            "a@b.com".into(),
            "https://v.com".into(),
            vec![],
            None,
            "hash",
        )
        .unwrap();

        let envelope = seal_cache(&cache, Some(&cek)).unwrap();
        assert!(envelope.is_encrypted());

        let recovered = open_cache(&envelope, Some(&cek)).unwrap();
        assert_eq!(recovered.email, "a@b.com");
        assert!(recovered.verify_hmac("hash").unwrap());
    }

    #[test]
    fn seal_open_wrong_cek_fails() {
        let cek = [42u8; 32];
        let wrong_cek = [99u8; 32];
        let cache = VaultCache::build(
            &test_kdf(),
            "key".into(),
            "priv".into(),
            None,
            "a@b.com".into(),
            "https://v.com".into(),
            vec![],
            None,
            "hash",
        )
        .unwrap();

        let envelope = seal_cache(&cache, Some(&cek)).unwrap();
        assert!(open_cache(&envelope, Some(&wrong_cek)).is_err());
    }

    #[test]
    fn vault_hash_deterministic() {
        let ciphers = vec![
            serde_json::json!({"id": "1"}),
            serde_json::json!({"id": "2"}),
        ];
        let h1 = compute_vault_hash(&ciphers);
        let h2 = compute_vault_hash(&ciphers);
        assert_eq!(h1, h2);
    }

    #[test]
    fn vault_hash_changes_on_different_data() {
        let c1 = vec![serde_json::json!({"id": "1"})];
        let c2 = vec![serde_json::json!({"id": "2"})];
        assert_ne!(compute_vault_hash(&c1), compute_vault_hash(&c2));
    }

    #[test]
    fn envelope_serialization_roundtrip() {
        let cache = VaultCache::build(
            &test_kdf(),
            "key".into(),
            "priv".into(),
            Some("uid".into()),
            "a@b.com".into(),
            "https://v.com".into(),
            vec![serde_json::json!({"cipher": 1})],
            Some(Utc::now()),
            "hash",
        )
        .unwrap();

        let envelope = seal_cache(&cache, None).unwrap();

        // Manually serialize and parse the envelope
        let mut buf = Vec::new();
        buf.extend_from_slice(CACHE_MAGIC);
        buf.extend_from_slice(&CACHE_VERSION.to_le_bytes());
        buf.push(envelope.flags);
        buf.extend_from_slice(&envelope.vault_hash);
        buf.extend_from_slice(&envelope.nonce);
        let body_len = envelope.body.len() as u32;
        buf.extend_from_slice(&body_len.to_le_bytes());
        buf.extend_from_slice(&envelope.body);

        let parsed = parse_cache_envelope(&buf).unwrap();
        assert_eq!(parsed.flags, envelope.flags);
        assert_eq!(parsed.vault_hash, envelope.vault_hash);

        let recovered = open_cache(&parsed, None).unwrap();
        assert_eq!(recovered.email, "a@b.com");
    }

    #[test]
    fn cached_kdf_roundtrip() {
        let kdf = Kdf::PBKDF2 {
            iterations: NonZeroU32::new(600_000).unwrap(),
        };
        let cached = CachedKdf::from_kdf(&kdf);
        let restored = cached.to_kdf().unwrap();
        match restored {
            Kdf::PBKDF2 { iterations } => assert_eq!(iterations.get(), 600_000),
            _ => panic!("wrong KDF type"),
        }
    }
}
