use thiserror::Error;

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Vault is locked")]
    VaultLocked,

    #[error("Not logged in")]
    NotLoggedIn,

    #[error("Sync failed: {0}")]
    SyncFailed(String),

    #[error("Authentication revoked by server")]
    AuthRevoked,

    #[error("Item not found: {0}")]
    NotFound(String),

    #[error("SDK error: {0}")]
    Internal(String),
}
