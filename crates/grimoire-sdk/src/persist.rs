//! Persistent login state — survives service restarts.
//!
//! After a successful login, we save email + server_url to disk so
//! the user only needs `grimoire unlock` (master password) on next startup.
//! The master password is never stored — unlock re-authenticates with the server.

use crate::auth::LoginState;
use crate::error::SdkError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
struct PersistedLogin {
    email: String,
    server_url: String,
}

fn state_file_path() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("grimoire").join("login.json"))
}

/// Save login state to disk after successful login.
pub fn save_login_state(state: &LoginState) -> Result<(), SdkError> {
    let path = state_file_path()
        .ok_or_else(|| SdkError::Internal("Cannot determine data directory".into()))?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| SdkError::Internal(format!("Failed to create data dir: {e}")))?;
    }

    let persisted = PersistedLogin {
        email: state.email.clone(),
        server_url: state.server_url.clone(),
    };

    let json = serde_json::to_string_pretty(&persisted)
        .map_err(|e| SdkError::Internal(format!("Failed to serialize: {e}")))?;

    fs::write(&path, &json)
        .map_err(|e| SdkError::Internal(format!("Failed to write {}: {e}", path.display())))?;

    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|e| SdkError::Internal(format!("Failed to set permissions: {e}")))?;

    tracing::info!("Login state saved to {}", path.display());
    Ok(())
}

/// Load persisted login state from disk. Returns None if no saved state exists.
pub fn load_login_state() -> Result<Option<LoginState>, SdkError> {
    let path = match state_file_path() {
        Some(p) if p.exists() => p,
        _ => return Ok(None),
    };

    let json = fs::read_to_string(&path)
        .map_err(|e| SdkError::Internal(format!("Failed to read {}: {e}", path.display())))?;

    let persisted: PersistedLogin = serde_json::from_str(&json)
        .map_err(|e| SdkError::Internal(format!("Failed to parse login state: {e}")))?;

    Ok(Some(LoginState {
        email: persisted.email,
        server_url: persisted.server_url,
    }))
}

/// Delete persisted login state (on logout).
pub fn clear_login_state() {
    if let Some(path) = state_file_path() {
        if path.exists() {
            if let Err(e) = fs::remove_file(&path) {
                tracing::warn!("Failed to remove {}: {e}", path.display());
            } else {
                tracing::info!("Login state cleared");
            }
        }
    }
}
