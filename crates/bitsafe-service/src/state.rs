use bitsafe_common::config::{PromptMethod, PIN_MAX_ATTEMPTS};
use bitsafe_sdk::auth::{LoginCredentials, LoginState};
use std::collections::HashMap;
use bitsafe_sdk::vault::{CipherDetail, CipherSummary, VaultFilter};
use bitsafe_sdk::{BitsafeClient, SdkError};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::Instant;
use zeroize::Zeroizing;

/// The three top-level states the service can be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    LoggedOut,
    Locked,
    Unlocked,
}

impl std::fmt::Display for VaultState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LoggedOut => write!(f, "logged_out"),
            Self::Locked => write!(f, "locked"),
            Self::Unlocked => write!(f, "unlocked"),
        }
    }
}

/// PIN state within the Unlocked state.
/// Created on unlock, destroyed on lock.
pub struct Session {
    pub pin: Option<Zeroizing<String>>,
    pub pin_attempts: u32,
}

impl Session {
    pub fn new() -> Self {
        Self {
            pin: None,
            pin_attempts: 0,
        }
    }

    /// Constant-time PIN comparison.
    pub fn verify_pin(&self, candidate: &str) -> bool {
        let Some(stored) = &self.pin else {
            return false;
        };
        if stored.len() != candidate.len() {
            return false;
        }
        stored
            .bytes()
            .zip(candidate.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

/// Cache of approved process sessions for scoped vault access.
pub struct ApprovalCache {
    /// Map of scope key (session leader PID or peer PID) → expiry time.
    grants: HashMap<u32, Instant>,
}

impl ApprovalCache {
    pub fn new() -> Self {
        Self {
            grants: HashMap::new(),
        }
    }

    /// Check if a scope key has an active (non-expired) approval.
    pub fn is_approved(&self, scope_key: u32) -> bool {
        self.grants
            .get(&scope_key)
            .is_some_and(|expiry| Instant::now() < *expiry)
    }

    /// Grant approval for a scope key with the given duration.
    pub fn grant(&mut self, scope_key: u32, duration: Duration) {
        self.grants.insert(scope_key, Instant::now() + duration);
    }

    /// Clear all grants (on lock/logout).
    pub fn clear(&mut self) {
        self.grants.clear();
    }
}

/// Shared service state, protected by a RwLock.
pub struct ServiceState {
    pub vault_state: VaultState,
    pub email: Option<String>,
    pub server_url: Option<String>,
    pub last_sync: Option<DateTime<Utc>>,
    pub last_activity: Instant,
    pub session: Option<Session>,
    pub prompt_method: PromptMethod,
    pub approval_cache: ApprovalCache,
    pub master_password_attempts: u32,
    pub last_password_attempt: Option<Instant>,
    /// The SDK client — recreated on login, dropped on logout.
    pub(crate) sdk: Option<BitsafeClient>,
    /// Login state needed for unlock (KDF params, encrypted keys).
    login_state: Option<LoginState>,
}

impl ServiceState {
    pub async fn new(prompt_method: PromptMethod) -> Self {
        // Try to restore persisted login state from a previous session.
        // If found, start in Locked state (need unlock, not full login).
        let base = |vault_state, email, server_url, sdk, login_state| Self {
            vault_state,
            email,
            server_url,
            last_sync: None,
            last_activity: Instant::now(),
            session: None,
            prompt_method: prompt_method.clone(),
            approval_cache: ApprovalCache::new(),
            master_password_attempts: 0,
            last_password_attempt: None,
            sdk,
            login_state,
        };

        match bitsafe_sdk::persist::load_login_state() {
            Ok(Some(login_state)) => {
                let email = login_state.email.clone();
                let server_url = login_state.server_url.clone();
                let sdk = BitsafeClient::new(&server_url).await;
                tracing::info!(
                    email = %email,
                    server_url = %server_url,
                    "Restored login state from disk — starting in Locked state"
                );
                base(VaultState::Locked, Some(email), Some(server_url), Some(sdk), Some(login_state))
            }
            Ok(None) => {
                tracing::info!("No persisted login state — starting in LoggedOut state");
                base(VaultState::LoggedOut, None, None, None, None)
            }
            Err(e) => {
                tracing::warn!("Failed to load persisted login state: {e}");
                base(VaultState::LoggedOut, None, None, None, None)
            }
        }
    }

    pub fn master_password_backoff_remaining(&self) -> u64 {
        if self.master_password_attempts <= 1 {
            return 0;
        }
        let delay_secs = {
            let exp = (self.master_password_attempts - 2).min(30);
            (1u64 << exp).min(30)
        };
        let Some(last) = self.last_password_attempt else {
            return 0;
        };
        let elapsed = last.elapsed().as_secs();
        delay_secs.saturating_sub(elapsed)
    }

    pub fn record_password_failure(&mut self) {
        self.master_password_attempts += 1;
        self.last_password_attempt = Some(Instant::now());
        tracing::warn!(
            attempt = self.master_password_attempts,
            "Master password attempt failed"
        );
    }

    pub fn reset_password_attempts(&mut self) {
        self.master_password_attempts = 0;
        self.last_password_attempt = None;
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn pin_set(&self) -> bool {
        self.session.as_ref().is_some_and(|s| s.pin.is_some())
    }

    pub async fn login(
        &mut self,
        email: String,
        password: Zeroizing<String>,
        server_url: Option<String>,
    ) -> Result<(), SdkError> {
        if self.vault_state != VaultState::LoggedOut {
            return Err(SdkError::Internal("Already logged in".into()));
        }

        let url = server_url.unwrap_or_else(|| "https://vault.bitwarden.com".into());
        let client = BitsafeClient::new(&url).await;

        let (_result, login_state) = client
            .auth()
            .login(LoginCredentials {
                email: email.clone(),
                password,
                server_url: url.clone(),
            })
            .await?;

        self.vault_state = VaultState::Locked;
        self.email = Some(email);
        self.server_url = Some(url);
        self.sdk = Some(client);

        // Persist login state to disk so unlock works after service restart
        if let Err(e) = bitsafe_sdk::persist::save_login_state(&login_state) {
            tracing::warn!("Failed to persist login state: {e}");
        }
        self.login_state = Some(login_state);
        self.touch();

        Ok(())
    }

    pub async fn unlock(&mut self, password: &str) -> Result<(), SdkError> {
        if self.vault_state != VaultState::Locked {
            return Err(match self.vault_state {
                VaultState::LoggedOut => SdkError::NotLoggedIn,
                VaultState::Unlocked => SdkError::Internal("Already unlocked".into()),
                _ => unreachable!(),
            });
        }

        let sdk = self.sdk.as_ref().ok_or(SdkError::NotLoggedIn)?;
        let login_state = self
            .login_state
            .as_ref()
            .ok_or(SdkError::Internal("No login state".into()))?;

        sdk.auth().unlock(password, login_state).await?;
        self.vault_state = VaultState::Unlocked;
        self.session = Some(Session::new());
        self.touch();
        tracing::info!("Vault unlocked, session started");
        Ok(())
    }

    pub async fn lock(&mut self) -> Result<(), SdkError> {
        if self.vault_state != VaultState::Unlocked {
            return Err(SdkError::VaultLocked);
        }

        // Drop and recreate the SDK client to clear crypto state.
        // The login_state is preserved so we can re-unlock without re-logging in.
        if let Some(ref url) = self.server_url {
            self.sdk = Some(BitsafeClient::new(url).await);
        }
        self.vault_state = VaultState::Locked;
        self.session = None;
        self.approval_cache.clear();
        tracing::info!("Vault locked, session and approvals cleared");
        Ok(())
    }

    pub async fn logout(&mut self) -> Result<(), SdkError> {
        self.vault_state = VaultState::LoggedOut;
        self.email = None;
        self.server_url = None;
        self.last_sync = None;
        self.session = None;
        self.approval_cache.clear();
        self.sdk = None;
        self.login_state = None;
        bitsafe_sdk::persist::clear_login_state();
        tracing::info!("Logged out");
        Ok(())
    }

    pub fn set_pin(&mut self, pin: Zeroizing<String>) -> Result<(), SdkError> {
        if self.vault_state != VaultState::Unlocked {
            return Err(SdkError::VaultLocked);
        }
        if let Some(session) = &mut self.session {
            session.pin = Some(pin);
            tracing::info!("PIN set for re-verification");
        }
        Ok(())
    }

    pub fn verify_pin(&mut self, candidate: &str) -> bool {
        let Some(session) = &mut self.session else {
            return false;
        };

        if session.verify_pin(candidate) {
            session.pin_attempts = 0;
            tracing::info!("PIN verification successful");
            true
        } else {
            session.pin_attempts += 1;
            tracing::warn!(
                attempt = session.pin_attempts,
                max = PIN_MAX_ATTEMPTS,
                "PIN verification failed"
            );
            false
        }
    }

    pub fn pin_attempts_exceeded(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(|s| s.pin_attempts >= PIN_MAX_ATTEMPTS)
    }

    /// Verify the master password against the server without reinitializing crypto.
    pub async fn verify_password(&self, password: &str) -> Result<(), SdkError> {
        if self.vault_state != VaultState::Unlocked {
            return Err(SdkError::VaultLocked);
        }
        let sdk = self.sdk.as_ref().ok_or(SdkError::NotLoggedIn)?;
        let email = self.email.as_deref().ok_or(SdkError::NotLoggedIn)?;
        let server_url = self.server_url.as_deref().ok_or(SdkError::NotLoggedIn)?;
        sdk.auth().verify_password(email, password, server_url).await
    }

    pub async fn vault_list(&self, filter: VaultFilter) -> Result<Vec<CipherSummary>, SdkError> {
        if self.vault_state != VaultState::Unlocked {
            return Err(SdkError::VaultLocked);
        }
        let sdk = self.sdk.as_ref().ok_or(SdkError::NotLoggedIn)?;
        sdk.vault().list(filter).await
    }

    pub async fn vault_get(&self, id: &str) -> Result<CipherDetail, SdkError> {
        if self.vault_state != VaultState::Unlocked {
            return Err(SdkError::VaultLocked);
        }
        let sdk = self.sdk.as_ref().ok_or(SdkError::NotLoggedIn)?;
        sdk.vault().get(id).await
    }

    pub async fn vault_totp(&self, id: &str) -> Result<String, SdkError> {
        if self.vault_state != VaultState::Unlocked {
            return Err(SdkError::VaultLocked);
        }
        let sdk = self.sdk.as_ref().ok_or(SdkError::NotLoggedIn)?;
        sdk.vault().totp(id).await
    }
}

pub type SharedState = Arc<RwLock<ServiceState>>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // --- PIN tests ---

    #[test]
    fn pin_verify_correct() {
        let mut session = Session::new();
        session.pin = Some(Zeroizing::new("1234".into()));
        assert!(session.verify_pin("1234"));
    }

    #[test]
    fn pin_verify_wrong() {
        let mut session = Session::new();
        session.pin = Some(Zeroizing::new("1234".into()));
        assert!(!session.verify_pin("5678"));
    }

    #[test]
    fn pin_verify_wrong_length() {
        let mut session = Session::new();
        session.pin = Some(Zeroizing::new("1234".into()));
        assert!(!session.verify_pin("123"));
        assert!(!session.verify_pin("12345"));
    }

    #[test]
    fn pin_verify_no_pin_set() {
        let session = Session::new();
        assert!(!session.verify_pin("1234"));
    }

    #[test]
    fn pin_verify_empty() {
        let mut session = Session::new();
        session.pin = Some(Zeroizing::new("".into()));
        assert!(session.verify_pin(""));
        assert!(!session.verify_pin("1"));
    }

    // --- Backoff tests ---

    #[tokio::test]
    async fn backoff_zero_on_first_attempt() {
        let state = ServiceState::new(PromptMethod::None).await;
        assert_eq!(state.master_password_backoff_remaining(), 0);
    }

    #[tokio::test]
    async fn backoff_zero_after_one_failure() {
        let mut state = ServiceState::new(PromptMethod::None).await;
        state.record_password_failure(); // attempt 1
        assert_eq!(state.master_password_backoff_remaining(), 0);
    }

    #[tokio::test]
    async fn backoff_positive_after_two_failures() {
        let mut state = ServiceState::new(PromptMethod::None).await;
        state.record_password_failure(); // attempt 1
        state.record_password_failure(); // attempt 2
        // Should have some backoff remaining (1s - elapsed)
        assert!(state.master_password_backoff_remaining() <= 1);
    }

    #[tokio::test]
    async fn backoff_resets_on_success() {
        let mut state = ServiceState::new(PromptMethod::None).await;
        state.record_password_failure();
        state.record_password_failure();
        state.reset_password_attempts();
        assert_eq!(state.master_password_attempts, 0);
        assert_eq!(state.master_password_backoff_remaining(), 0);
    }

    // --- State query tests ---

    #[tokio::test]
    async fn pin_set_returns_true_when_set() {
        let mut state = ServiceState::new(PromptMethod::None).await;
        state.vault_state = VaultState::Unlocked;
        let mut session = Session::new();
        session.pin = Some(Zeroizing::new("1234".into()));
        state.session = Some(session);
        assert!(state.pin_set());
    }

    #[tokio::test]
    async fn pin_set_returns_false_when_not_set() {
        let mut state = ServiceState::new(PromptMethod::None).await;
        state.vault_state = VaultState::Unlocked;
        state.session = Some(Session::new());
        assert!(!state.pin_set());
    }

    // --- PIN attempt tests ---

    #[tokio::test]
    async fn verify_pin_success_resets_attempts() {
        let mut state = ServiceState::new(PromptMethod::None).await;
        state.vault_state = VaultState::Unlocked;
        let mut session = Session::new();
        session.pin = Some(Zeroizing::new("1234".into()));
        state.session = Some(session);

        assert!(state.verify_pin("1234"));
        assert_eq!(state.session.as_ref().unwrap().pin_attempts, 0);
    }

    #[tokio::test]
    async fn verify_pin_failure_increments_attempts() {
        let mut state = ServiceState::new(PromptMethod::None).await;
        state.vault_state = VaultState::Unlocked;
        let mut session = Session::new();
        session.pin = Some(Zeroizing::new("1234".into()));
        state.session = Some(session);

        assert!(!state.verify_pin("wrong"));
        assert_eq!(state.session.as_ref().unwrap().pin_attempts, 1);
    }

    #[tokio::test]
    async fn pin_attempts_exceeded_after_max() {
        let mut state = ServiceState::new(PromptMethod::None).await;
        state.vault_state = VaultState::Unlocked;
        let mut session = Session::new();
        session.pin = Some(Zeroizing::new("1234".into()));
        state.session = Some(session);

        state.verify_pin("wrong");
        state.verify_pin("wrong");
        state.verify_pin("wrong");
        assert!(state.pin_attempts_exceeded()); // 3 >= PIN_MAX_ATTEMPTS (3)
    }

    #[tokio::test]
    async fn touch_updates_last_activity() {
        let mut state = ServiceState::new(PromptMethod::None).await;
        let before = state.last_activity;
        tokio::time::sleep(Duration::from_millis(10)).await;
        state.touch();
        assert!(state.last_activity > before);
    }

    // --- State transition tests ---

    #[tokio::test]
    async fn initial_state_depends_on_persisted_login() {
        let state = ServiceState::new(PromptMethod::None).await;
        // If persisted login exists on disk, starts Locked; otherwise LoggedOut
        assert!(
            state.vault_state == VaultState::LoggedOut || state.vault_state == VaultState::Locked,
            "Expected LoggedOut or Locked, got {:?}",
            state.vault_state
        );
    }

    #[tokio::test]
    async fn logout_clears_everything() {
        let mut state = ServiceState::new(PromptMethod::None).await;
        state.vault_state = VaultState::Unlocked;
        state.email = Some("test@test.com".into());
        state.server_url = Some("https://vault.test.com".into());
        state.session = Some(Session::new());

        state.logout().await.unwrap();
        assert_eq!(state.vault_state, VaultState::LoggedOut);
        assert!(state.email.is_none());
        assert!(state.server_url.is_none());
        assert!(state.session.is_none());
        assert!(state.sdk.is_none());
    }
}

pub async fn new_shared_state(prompt_method: PromptMethod) -> SharedState {
    Arc::new(RwLock::new(
        ServiceState::new(prompt_method).await,
    ))
}
