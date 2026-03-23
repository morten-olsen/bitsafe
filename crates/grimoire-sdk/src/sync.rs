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

/// Result from a successful sync, including the raw cipher JSON for caching.
pub struct SyncResult {
    /// Raw encrypted cipher JSON values (as received from the server, with
    /// Vaultwarden `data` field patching applied). Used for vault cache.
    pub raw_ciphers: Vec<serde_json::Value>,
}

pub struct SyncClient {
    pub(crate) client: Arc<Mutex<PasswordManagerClient>>,
    pub(crate) token_store: Arc<TokenStore>,
}

impl SyncClient {
    /// Trigger a full vault sync. Returns the raw cipher JSON for cache updates.
    pub async fn sync(&self, server_url: &str) -> Result<SyncResult, SdkError> {
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
            .header("Authorization", format!("Bearer {}", &*token))
            .header("Bitwarden-Client-Name", "desktop")
            .header("Bitwarden-Client-Version", "2025.1.1")
            .header("Device-Type", "8")
            .send()
            .await
            .map_err(|e| SdkError::SyncFailed(format!("Sync request failed: {e}")))?;

        // Detect account revocation (spec Vector 4 mitigation)
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED
            || status == reqwest::StatusCode::FORBIDDEN
        {
            return Err(SdkError::AuthRevoked);
        }

        if !status.is_success() {
            return Err(SdkError::SyncFailed(format!(
                "Sync failed: HTTP {status}"
            )));
        }

        // Parse the sync response as loose JSON to avoid SDK model compat issues.
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SdkError::SyncFailed(format!("Failed to parse sync response: {e}")))?;

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

        let raw_ciphers = if let Some(ciphers_json) = cipher_array {
            tracing::info!(
                json_count = ciphers_json.len(),
                "Found ciphers in sync response"
            );

            let patched = patch_cipher_data(ciphers_json);
            self.store_ciphers(&patched).await?;
            patched
        } else {
            tracing::warn!("No ciphers array in sync response");
            Vec::new()
        };

        Ok(SyncResult { raw_ciphers })
    }

    /// Populate the cipher repository from cached raw cipher JSON.
    /// Used during cache-first unlock to restore ciphers without a network call.
    pub async fn populate_from_cache(
        &self,
        cached_ciphers: &[serde_json::Value],
    ) -> Result<(), SdkError> {
        self.store_ciphers(cached_ciphers).await
    }

    /// Parse and store cipher JSON values into the SDK cipher repository.
    async fn store_ciphers(&self, patched_ciphers: &[serde_json::Value]) -> Result<(), SdkError> {
        let pm = self.client.lock().await;
        let repo: Arc<dyn Repository<Cipher>> =
            pm.0.platform()
                .state()
                .get::<Cipher>()
                .map_err(|e| SdkError::SyncFailed(format!("No cipher repository: {e}")))?;

        let mut ciphers: Vec<(CipherId, Cipher)> = Vec::new();

        for c in patched_ciphers {
            match serde_json::from_value::<bitwarden_api_api::models::CipherDetailsResponseModel>(
                c.clone(),
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

        tracing::info!(count = ciphers.len(), "Stored ciphers in repository");
        repo.replace_all(ciphers)
            .await
            .map_err(|e| SdkError::SyncFailed(format!("Failed to store ciphers: {e}")))?;

        Ok(())
    }
}

/// Patch Vaultwarden's `data` field format (JSON object → stringified JSON).
/// The SDK model expects `data` as `Option<String>`, but Vaultwarden sends it as a JSON object.
fn patch_cipher_data(ciphers_json: &[serde_json::Value]) -> Vec<serde_json::Value> {
    ciphers_json
        .iter()
        .map(|c| {
            let mut patched = c.clone();
            if let Some(obj) = patched.as_object_mut() {
                for key in &["data", "Data"] {
                    if let Some(data) = obj.get(*key) {
                        if data.is_object() {
                            let stringified = serde_json::to_string(data).ok();
                            obj.insert(key.to_string(), serde_json::json!(stringified));
                        }
                    }
                }
            }
            patched
        })
        .collect()
}
