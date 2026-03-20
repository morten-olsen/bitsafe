use super::{PromptBackend, PromptError};
use std::process::Command;

/// macOS prompt backend using osascript for dialogs and
/// the `bioutil` command for Touch ID.
pub struct MacOsBackend;

pub fn is_available() -> bool {
    // osascript is always available on macOS with a GUI session.
    // Check for a window server connection.
    std::env::var("__CFBundleIdentifier").is_ok()
        || Command::new("pgrep")
            .args(["-x", "WindowServer"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

/// Escape a string for safe inclusion in an AppleScript double-quoted string.
/// Replaces backslashes and double quotes with their escaped forms.
fn escape_applescript(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Escape a string for safe inclusion in a Swift string literal.
/// Replaces backslashes, double quotes, and newlines.
fn escape_swift(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

impl PromptBackend for MacOsBackend {
    fn prompt_password(&self, message: &str) -> Result<Option<String>, PromptError> {
        let escaped = escape_applescript(message);
        let script = format!(
            r#"display dialog "{escaped}" with title "Grimoire" default answer "" with hidden answer buttons {{"Cancel", "OK"}} default button "OK"
set theAnswer to text returned of result
return theAnswer"#
        );

        let output = Command::new("osascript")
            .args(["-e", &script])
            .output()?;

        if !output.status.success() {
            return Ok(None);
        }

        let pw = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if pw.is_empty() {
            Ok(None)
        } else {
            Ok(Some(pw))
        }
    }

    fn prompt_pin(&self, message: &str) -> Result<Option<String>, PromptError> {
        self.prompt_password(message)
    }

    fn verify_biometric(&self, reason: &str) -> Result<bool, PromptError> {
        let escaped = escape_swift(reason);
        let swift_code = format!(
            r#"
import LocalAuthentication
import Foundation

let context = LAContext()
var error: NSError?

guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {{
    fputs("biometric_unavailable\n", stderr)
    exit(2)
}}

let semaphore = DispatchSemaphore(value: 0)
var success = false

context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "{escaped}") {{ result, _ in
    success = result
    semaphore.signal()
}}

semaphore.wait()
exit(success ? 0 : 1)
"#
        );

        let output = Command::new("swift").args(["-e", &swift_code]).output()?;

        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(PromptError::BiometricUnavailable),
        }
    }

    fn name(&self) -> &'static str {
        "macos"
    }
}
