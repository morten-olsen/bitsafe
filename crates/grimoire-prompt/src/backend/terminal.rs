use super::{PromptBackend, PromptError};

/// Fallback backend that prompts on the terminal via stderr/stdin.
pub struct TerminalBackend;

impl PromptBackend for TerminalBackend {
    fn prompt_password(&self, message: &str) -> Result<Option<String>, PromptError> {
        match rpassword::prompt_password(message) {
            Ok(pw) if pw.is_empty() => Ok(None),
            Ok(pw) => Ok(Some(pw)),
            Err(e) => Err(PromptError::Io(e)),
        }
    }

    fn prompt_pin(&self, message: &str) -> Result<Option<String>, PromptError> {
        // PIN uses the same mechanism as password (hidden input)
        self.prompt_password(message)
    }

    fn verify_biometric(&self, _reason: &str) -> Result<bool, PromptError> {
        Err(PromptError::BiometricUnavailable)
    }

    fn name(&self) -> &'static str {
        "terminal"
    }
}
