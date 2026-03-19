//! Sync — fetches vault data from the server.
//!
//! Like the official Bitwarden CLI, we do our own HTTP call to /api/sync
//! and populate the cipher repository ourselves.

use crate::auth::TokenStore;
use crate::error::SdkError;
use bitwarden_pm::PasswordManagerClient;
use bitwarden_state::repository::Repository;
use bitwarden_vault::{Cipher, CipherId};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct SyncClient {
    pub(crate) client: Arc<Mutex<PasswordManagerClient>>,
    pub(crate) token_store: Arc<TokenStore>,
}

impl SyncClient {
    pub fn new() -> Self {
        Self {
            client: Arc::new(Mutex::new(PasswordManagerClient::new(None))),
            token_store: Arc::new(TokenStore {
                access_token: tokio::sync::RwLock::new(None),
            }),
        }
    }

    /// Trigger a full vault sync.
    pub async fn sync(&self, server_url: &str) -> Result<(), SdkError> {
        let token = self
            .token_store
            .access_token
            .read()
            .await
            .clone()
            .ok_or_else(|| SdkError::SyncFailed("No access token".into()))?;

        let url = format!("{}/api/sync", server_url.trim_end_matches('/'));
        let http = reqwest::Client::new();
        let resp = http
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Bitwarden-Client-Name", "desktop")
            .header("Bitwarden-Client-Version", "2025.1.1")
            .header("Device-Type", "8")
            .send()
            .await
            .map_err(|e| SdkError::SyncFailed(format!("Sync request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(SdkError::SyncFailed(format!(
                "Sync failed: HTTP {}",
                resp.status()
            )));
        }

        // Parse the sync response as loose JSON to avoid SDK model compat issues.
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SdkError::SyncFailed(format!("Failed to parse sync response: {e}")))?;

        let pm = self.client.lock().await;
        let repo: Arc<dyn Repository<Cipher>> = pm
            .0
            .platform()
            .state()
            .get::<Cipher>()
            .map_err(|e| SdkError::SyncFailed(format!("No cipher repository: {e}")))?;

        // Log top-level keys to diagnose field naming
        if let Some(obj) = body.as_object() {
            let keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
            tracing::debug!(keys = ?keys, "Sync response top-level keys");
        }

        // Extract ciphers — try both camelCase and PascalCase keys
        let cipher_array = body
            .get("ciphers")
            .or_else(|| body.get("Ciphers"))
            .and_then(|v| v.as_array());

        if let Some(ciphers_json) = cipher_array {
            tracing::info!(
                json_count = ciphers_json.len(),
                "Found ciphers in sync response"
            );

            let mut ciphers: Vec<(CipherId, Cipher)> = Vec::new();

            for c in ciphers_json {
                // Vaultwarden sends `data` as a JSON object, but the SDK model
                // expects it as a String (or null). Stringify it to avoid deser failure.
                let mut patched = c.clone();
                if let Some(obj) = patched.as_object_mut() {
                    if let Some(data) = obj.get("data") {
                        if data.is_object() {
                            let stringified = serde_json::to_string(data).ok();
                            obj.insert("data".to_string(), serde_json::json!(stringified));
                        }
                    }
                    if let Some(data) = obj.get("Data") {
                        if data.is_object() {
                            let stringified = serde_json::to_string(data).ok();
                            obj.insert("Data".to_string(), serde_json::json!(stringified));
                        }
                    }
                }

                match serde_json::from_value::<bitwarden_api_api::models::CipherDetailsResponseModel>(
                    patched,
                ) {
                    Ok(model) => match Cipher::try_from(model) {
                        Ok(cipher) => {
                            if let Some(id) = cipher.id {
                                ciphers.push((id, cipher));
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to convert cipher: {e}");
                        }
                    },
                    Err(e) => {
                        tracing::warn!("Failed to deserialize cipher: {e}");
                    }
                }
            }

            tracing::info!(count = ciphers.len(), "Synced ciphers to repository");
            repo.replace_all(ciphers)
                .await
                .map_err(|e| SdkError::SyncFailed(format!("Failed to store ciphers: {e}")))?;
        } else {
            tracing::warn!("No ciphers array in sync response");
        }

        Ok(())
    }
}
