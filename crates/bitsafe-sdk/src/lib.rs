pub mod auth;
pub mod crypto;
pub mod error;
pub mod persist;
pub mod ssh;
mod state;
pub mod sync;
pub mod vault;

pub use error::SdkError;

use bitwarden_core::key_management::{
    EphemeralPinEnvelopeState, LocalUserDataKeyState, UserKeyState,
};
use bitwarden_core::{ClientSettings, DeviceType, FromClient};
use bitwarden_pm::PasswordManagerClient;
use bitwarden_state::DatabaseConfiguration;
use bitwarden_vault::{Cipher, Folder};
use state::InMemoryRepository;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// The central SDK wrapper. Holds a `PasswordManagerClient` and exposes sub-clients
/// for auth, vault, sync, and SSH operations.
///
/// All BitSafe crates depend on this wrapper, never on `bitwarden-*` crates directly.
pub struct BitsafeClient {
    pub(crate) inner: Arc<Mutex<PasswordManagerClient>>,
    pub(crate) token_store: Arc<auth::TokenStore>,
}

impl BitsafeClient {
    /// Create a new client configured for the given server URL.
    ///
    /// For Vaultwarden, `server_url` is the base URL (e.g. `https://vault.example.com`).
    /// The identity and API endpoints are derived by appending `/identity` and `/api`.
    pub async fn new(server_url: &str) -> Self {
        let url = server_url.trim_end_matches('/');
        let settings = ClientSettings {
            identity_url: format!("{url}/identity"),
            api_url: format!("{url}/api"),
            user_agent: "BitSafe/0.1".into(),
            device_type: DeviceType::LinuxDesktop,
            ..ClientSettings::default()
        };
        let token_store = Arc::new(auth::TokenStore {
            access_token: tokio::sync::RwLock::new(None),
        });
        let pm = PasswordManagerClient::new_with_client_tokens(Some(settings), token_store.clone());

        // Initialize the SDK's state database (SQLite) for SDK-managed repositories.
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("bitsafe");
        if let Err(e) = std::fs::create_dir_all(&data_dir) {
            tracing::warn!("Failed to create data dir {}: {e}", data_dir.display());
        }

        let db_config = DatabaseConfiguration::Sqlite {
            db_name: "bitsafe".to_string(),
            folder_path: data_dir,
        };
        let migrations = bitwarden_pm::migrations::get_sdk_managed_migrations();

        if let Err(e) = pm
            .0
            .platform()
            .state()
            .initialize_database(db_config, migrations)
            .await
        {
            tracing::warn!("Failed to initialize state database: {e}");
        }

        // Register client-managed in-memory repositories for state types
        // that the SDK expects but aren't in the SQLite migrations.
        let state_client = pm.0.platform().state();
        state_client.register_client_managed::<InMemoryRepository<LocalUserDataKeyState>, LocalUserDataKeyState>(
            Arc::new(InMemoryRepository::new()),
        );
        state_client.register_client_managed::<InMemoryRepository<Cipher>, Cipher>(
            Arc::new(InMemoryRepository::new()),
        );
        state_client.register_client_managed::<InMemoryRepository<Folder>, Folder>(
            Arc::new(InMemoryRepository::new()),
        );
        state_client.register_client_managed::<InMemoryRepository<EphemeralPinEnvelopeState>, EphemeralPinEnvelopeState>(
            Arc::new(InMemoryRepository::new()),
        );
        state_client.register_client_managed::<InMemoryRepository<UserKeyState>, UserKeyState>(
            Arc::new(InMemoryRepository::new()),
        );

        // Register the folder sync handler so folders are populated on sync.
        {
            use bitwarden_sync::SyncClientExt;
            if let Ok(handler) = bitwarden_vault::FolderSyncHandler::from_client(&pm.0) {
                pm.0.sync().register_sync_handler(Arc::new(handler));
            }
        }

        Self {
            inner: Arc::new(Mutex::new(pm)),
            token_store,
        }
    }

    pub fn auth(&self) -> auth::AuthClient {
        auth::AuthClient {
            client: self.inner.clone(),
            token_store: self.token_store.clone(),
        }
    }

    pub fn vault(&self) -> vault::VaultClient {
        vault::VaultClient {
            client: self.inner.clone(),
        }
    }

    pub fn sync(&self) -> sync::SyncClient {
        sync::SyncClient {
            client: self.inner.clone(),
            token_store: self.token_store.clone(),
        }
    }

    pub fn ssh(&self) -> ssh::SshClient {
        ssh::SshClient {
            client: self.inner.clone(),
        }
    }
}
