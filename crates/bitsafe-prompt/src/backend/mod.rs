mod terminal;

#[cfg(target_os = "linux")]
mod zenity;

#[cfg(target_os = "macos")]
mod macos;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PromptError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Backend error: {0}")]
    Backend(String),
    #[error("Biometric not available")]
    BiometricUnavailable,
}

/// Trait implemented by each platform-specific prompt backend.
pub trait PromptBackend {
    /// Prompt the user for a password. Returns `Ok(None)` if cancelled.
    fn prompt_password(&self, message: &str) -> Result<Option<String>, PromptError>;

    /// Prompt the user for a PIN. Returns `Ok(None)` if cancelled.
    fn prompt_pin(&self, message: &str) -> Result<Option<String>, PromptError>;

    /// Verify identity via biometric. Returns `Ok(true)` if verified, `Ok(false)` if cancelled.
    fn verify_biometric(&self, reason: &str) -> Result<bool, PromptError>;

    /// Name of this backend for logging.
    fn name(&self) -> &'static str;
}

/// Auto-detect the best available prompt backend for the current platform.
/// Returns `None` if no GUI backend is available — terminal fallback is not
/// useful because the prompt is spawned by the service, not the user.
pub fn detect() -> Option<Box<dyn PromptBackend>> {
    #[cfg(target_os = "macos")]
    {
        if macos::is_available() {
            tracing::debug!("Using macOS prompt backend");
            return Some(Box::new(macos::MacOsBackend));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if zenity::is_available() {
            tracing::debug!("Using zenity/kdialog prompt backend");
            return Some(Box::new(zenity::ZenityBackend::detect()));
        }
    }

    tracing::warn!("No GUI prompt backend available");
    None
}
