//! Authentication — prelogin, login, and crypto initialization.
//!
//! Following the pattern of the official Bitwarden CLI: prelogin, login (token request),
//! and sync are done via our own HTTP calls. The SDK is only used for crypto operations
//! (key derivation and vault decryption) via `initialize_user_crypto()`.

use crate::error::SdkError;
use bitwarden_core::key_management::account_cryptographic_state::WrappedAccountCryptographicState;
use bitwarden_core::key_management::crypto::{InitUserCryptoMethod, InitUserCryptoRequest};
use bitwarden_core::key_management::{MasterPasswordAuthenticationData, MasterPasswordUnlockData};
use bitwarden_crypto::{EncString, Kdf};
use bitwarden_pm::PasswordManagerClient;
use std::num::NonZeroU32;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use zeroize::Zeroizing;

pub struct LoginCredentials {
    pub email: String,
    pub password: Zeroizing<String>,
    pub server_url: String,
}

pub struct LoginResult {
    pub email: String,
    pub server_url: String,
}

pub struct LoginState {
    pub email: String,
    pub server_url: String,
}

/// Token store shared with the SDK via `ClientManagedTokens`.
///
/// The access token is stored in `Zeroizing<String>` so it is zeroed on drop.
/// The SDK trait requires returning a plain `String`, so we clone on read —
/// the SDK internally uses `ZeroizingAllocator` which mitigates that copy.
pub(crate) struct TokenStore {
    pub(crate) access_token: RwLock<Option<Zeroizing<String>>>,
}

impl std::fmt::Debug for TokenStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenStore")
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

#[async_trait::async_trait]
impl bitwarden_core::auth::auth_tokens::ClientManagedTokens for TokenStore {
    async fn get_access_token(&self) -> Option<String> {
        self.access_token
            .read()
            .await
            .as_ref()
            .map(|t| t.to_string())
    }
}

pub struct AuthClient {
    pub(crate) client: Arc<Mutex<PasswordManagerClient>>,
    pub(crate) token_store: Arc<TokenStore>,
}

impl AuthClient {
    /// Login: verify credentials against the server but do NOT initialize crypto.
    /// The vault stays locked after login — unlock is a separate step.
    pub async fn login(
        &self,
        creds: LoginCredentials,
    ) -> Result<(LoginResult, LoginState), SdkError> {
        // Only verify credentials + store token. Skip crypto init so the
        // SDK client stays in a clean state for unlock later.
        self.verify_credentials(&creds.email, &creds.password, &creds.server_url)
            .await?;
        Ok((
            LoginResult {
                email: creds.email.clone(),
                server_url: creds.server_url.clone(),
            },
            LoginState {
                email: creds.email,
                server_url: creds.server_url,
            },
        ))
    }

    /// Unlock: verify credentials and initialize crypto so vault operations work.
    pub async fn unlock(
        &self,
        password: &Zeroizing<String>,
        login_state: &LoginState,
    ) -> Result<(), SdkError> {
        self.auth_and_init_crypto(&login_state.email, password, &login_state.server_url)
            .await
    }

    /// Verify a master password against the server without reinitializing crypto.
    /// Also refreshes the stored access token.
    pub async fn verify_password(
        &self,
        email: &str,
        password: &Zeroizing<String>,
        server_url: &str,
    ) -> Result<(), SdkError> {
        self.verify_credentials(email, password, server_url).await
    }

    /// Steps 1-4 only: Prelogin, derive, token request, store token.
    /// Verifies credentials against the server without touching SDK crypto state.
    async fn verify_credentials(
        &self,
        email: &str,
        password: &str,
        server_url: &str,
    ) -> Result<(), SdkError> {
        let url = server_url.trim_end_matches('/');
        let http = reqwest::Client::new();

        let kdf = prelogin(&http, url, email).await?;

        let master_auth = MasterPasswordAuthenticationData::derive(password, &kdf, email)
            .map_err(|e| SdkError::AuthFailed(format!("Key derivation failed: {e}")))?;

        let password_hash = master_auth.master_password_authentication_hash.to_string();

        let token_response = login_token_request(&http, url, email, &password_hash).await?;

        *self.token_store.access_token.write().await =
            Some(Zeroizing::new(token_response.access_token.clone()));

        Ok(())
    }

    /// Full auth flow (steps 1-5), matching what the official Bitwarden CLI does:
    /// 1. Prelogin (our HTTP call) — get KDF params
    /// 2. Derive master key hash locally (SDK crypto)
    /// 3. Login token request (our HTTP call) — get access token + encrypted keys
    /// 4. Store access token for API calls
    /// 5. Initialize user crypto (SDK) — decrypt vault keys
    async fn auth_and_init_crypto(
        &self,
        email: &str,
        password: &str,
        server_url: &str,
    ) -> Result<(), SdkError> {
        let url = server_url.trim_end_matches('/');
        let http = reqwest::Client::new();

        let kdf = prelogin(&http, url, email).await?;

        let master_auth = MasterPasswordAuthenticationData::derive(password, &kdf, email)
            .map_err(|e| SdkError::AuthFailed(format!("Key derivation failed: {e}")))?;

        let password_hash = master_auth.master_password_authentication_hash.to_string();

        let token_response = login_token_request(&http, url, email, &password_hash).await?;

        *self.token_store.access_token.write().await =
            Some(Zeroizing::new(token_response.access_token.clone()));

        // Step 5: Initialize user crypto
        let private_key: EncString = token_response
            .private_key
            .as_ref()
            .ok_or_else(|| SdkError::AuthFailed("No private key in login response".into()))?
            .parse()
            .map_err(|e| SdkError::Internal(format!("Failed to parse private key: {e}")))?;

        let user_key: EncString = token_response
            .key
            .as_ref()
            .ok_or_else(|| SdkError::AuthFailed("No user key in login response".into()))?
            .parse()
            .map_err(|e| SdkError::Internal(format!("Failed to parse user key: {e}")))?;

        let user_id = user_id_from_jwt(&token_response.access_token);

        let pm = self.client.lock().await;
        let request = InitUserCryptoRequest {
            user_id,
            kdf_params: kdf.clone(),
            email: email.to_string(),
            account_cryptographic_state: WrappedAccountCryptographicState::V1 { private_key },
            method: InitUserCryptoMethod::MasterPasswordUnlock {
                // The SDK takes a plain String here. We minimize the lifetime of
                // this unzeroized copy — the SDK's ZeroizingAllocator handles it
                // once ownership transfers to the SDK.
                password: password.to_string(),
                master_password_unlock: MasterPasswordUnlockData {
                    kdf,
                    master_key_wrapped_user_key: user_key,
                    salt: email.to_string(),
                },
            },
            upgrade_token: None,
        };

        pm.crypto()
            .initialize_user_crypto(request)
            .await
            .map_err(|e| {
                let msg = format!("{e}");
                if msg.contains("Wrong") || msg.contains("wrong") {
                    SdkError::AuthFailed("Wrong master password".into())
                } else {
                    SdkError::AuthFailed(format!("Failed to initialize crypto: {e}"))
                }
            })?;

        Ok(())
    }

    pub async fn lock(&self) -> Result<(), SdkError> {
        *self.token_store.access_token.write().await = None;
        Ok(())
    }

    pub async fn logout(&self) -> Result<(), SdkError> {
        *self.token_store.access_token.write().await = None;
        Ok(())
    }
}

fn user_id_from_jwt(token: &str) -> Option<bitwarden_core::UserId> {
    use base64::Engine;
    let payload = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    let sub = claims.get("sub")?.as_str()?;
    sub.parse().ok()
}

// --- HTTP calls matching the official Bitwarden CLI ---

/// POST /identity/accounts/prelogin
async fn prelogin(http: &reqwest::Client, server_url: &str, email: &str) -> Result<Kdf, SdkError> {
    let resp = http
        .post(format!("{server_url}/identity/accounts/prelogin"))
        .json(&serde_json::json!({ "email": email }))
        .send()
        .await
        .map_err(|e| SdkError::AuthFailed(format!("Cannot reach server: {e}")))?;

    if !resp.status().is_success() {
        return Err(SdkError::AuthFailed(format!(
            "Prelogin failed: HTTP {}",
            resp.status()
        )));
    }

    let data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| SdkError::AuthFailed(format!("Failed to parse prelogin: {e}")))?;

    let kdf_type = data["kdf"]
        .as_i64()
        .or_else(|| data["Kdf"].as_i64())
        .unwrap_or(0);
    let iterations = data["kdfIterations"]
        .as_i64()
        .or_else(|| data["KdfIterations"].as_i64())
        .unwrap_or(600000);

    // Safe cast helper — rejects negative values and values > u32::MAX.
    let to_u32 = |v: i64, name: &str| -> Result<u32, SdkError> {
        u32::try_from(v)
            .map_err(|_| SdkError::Internal(format!("KDF {name} out of u32 range: {v}")))
    };

    // Upper bounds prevent a malicious server from causing DoS via extreme KDF params.
    let bounded_u32 = |v: i64, name: &str, max: u32| -> Result<u32, SdkError> {
        let val = to_u32(v, name)?;
        if val > max {
            return Err(SdkError::Internal(format!(
                "KDF {name} exceeds maximum ({val} > {max})"
            )));
        }
        Ok(val)
    };

    match kdf_type {
        0 => Ok(Kdf::PBKDF2 {
            iterations: NonZeroU32::new(bounded_u32(iterations, "iterations", 2_000_000)?)
                .ok_or_else(|| SdkError::Internal("Zero KDF iterations".into()))?,
        }),
        1 => {
            let memory = data["kdfMemory"]
                .as_i64()
                .or_else(|| data["KdfMemory"].as_i64())
                .ok_or_else(|| SdkError::Internal("Missing Argon2 memory".into()))?;
            let parallelism = data["kdfParallelism"]
                .as_i64()
                .or_else(|| data["KdfParallelism"].as_i64())
                .ok_or_else(|| SdkError::Internal("Missing Argon2 parallelism".into()))?;
            Ok(Kdf::Argon2id {
                iterations: NonZeroU32::new(bounded_u32(iterations, "iterations", 20)?)
                    .ok_or_else(|| SdkError::Internal("Zero iterations".into()))?,
                memory: NonZeroU32::new(bounded_u32(memory, "memory", 4096)?)
                    .ok_or_else(|| SdkError::Internal("Zero memory".into()))?,
                parallelism: NonZeroU32::new(bounded_u32(parallelism, "parallelism", 16)?)
                    .ok_or_else(|| SdkError::Internal("Zero parallelism".into()))?,
            })
        }
        other => Err(SdkError::Internal(format!("Unknown KDF type: {other}"))),
    }
}

/// Login token response — only the fields we need.
#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default, alias = "Key")]
    key: Option<String>,
    #[serde(default, alias = "PrivateKey")]
    private_key: Option<String>,
}

/// POST /identity/connect/token
async fn login_token_request(
    http: &reqwest::Client,
    server_url: &str,
    email: &str,
    password_hash: &str,
) -> Result<TokenResponse, SdkError> {
    let resp = http
        .post(format!("{server_url}/identity/connect/token"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Bitwarden-Client-Name", "desktop")
        .header("Bitwarden-Client-Version", "2025.1.1")
        .body(
            serde_urlencoded::to_string([
                ("grant_type", "password"),
                ("username", email),
                ("password", password_hash),
                ("scope", "api offline_access"),
                ("client_id", "desktop"),
                ("deviceType", "8"),
                ("deviceIdentifier", "grimoire"),
                ("deviceName", "Grimoire"),
            ])
            .map_err(|e| SdkError::Internal(format!("Failed to encode form: {e}")))?,
        )
        .send()
        .await
        .map_err(|e| SdkError::AuthFailed(format!("Cannot reach server: {e}")))?;

    if !resp.status().is_success() {
        // Try to extract error message from Vaultwarden's response
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let msg = body["message"]
            .as_str()
            .or_else(|| body["error_description"].as_str())
            .unwrap_or("Unknown error");
        return Err(SdkError::AuthFailed(format!("{msg} (HTTP {status})")));
    }

    resp.json::<TokenResponse>()
        .await
        .map_err(|e| SdkError::AuthFailed(format!("Failed to parse login response: {e}")))
}
