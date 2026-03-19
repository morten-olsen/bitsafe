use super::{PromptBackend, PromptError};
use std::process::Command;

/// Linux GUI prompt backend using zenity or kdialog.
pub struct ZenityBackend {
    tool: GuiTool,
}

#[derive(Debug, Clone, Copy)]
enum GuiTool {
    Zenity,
    Kdialog,
}

impl ZenityBackend {
    /// Detect which tool is available, preferring zenity.
    pub fn detect() -> Self {
        let tool = if has_command("zenity") {
            GuiTool::Zenity
        } else {
            GuiTool::Kdialog
        };
        Self { tool }
    }
}

/// Check if any GUI dialog tool is available.
pub fn is_available() -> bool {
    // Also require a display server
    let has_display =
        std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok();
    has_display && (has_command("zenity") || has_command("kdialog"))
}

fn has_command(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

impl PromptBackend for ZenityBackend {
    fn prompt_password(&self, message: &str) -> Result<Option<String>, PromptError> {
        let output = match self.tool {
            GuiTool::Zenity => Command::new("zenity")
                .args(["--password", "--title=BitSafe", "--text", message])
                .output()?,
            GuiTool::Kdialog => Command::new("kdialog")
                .args(["--password", message, "--title", "BitSafe"])
                .output()?,
        };

        if !output.status.success() {
            // User cancelled
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
        // Same as password — both are hidden input dialogs
        self.prompt_password(message)
    }

    fn verify_biometric(&self, reason: &str) -> Result<bool, PromptError> {
        // Try fprintd-verify if available
        if !has_command("fprintd-verify") {
            return Err(PromptError::BiometricUnavailable);
        }

        // Show a notification that we're waiting for fingerprint
        let _ = match self.tool {
            GuiTool::Zenity => Command::new("zenity")
                .args([
                    "--notification",
                    "--text",
                    &format!("{reason}\nPlace your finger on the sensor"),
                ])
                .spawn(),
            GuiTool::Kdialog => Command::new("kdialog")
                .args([
                    "--passivepopup",
                    &format!("{reason}\nPlace your finger on the sensor"),
                    "10",
                ])
                .spawn(),
        };

        let output = Command::new("fprintd-verify").output()?;
        Ok(output.status.success())
    }

    fn name(&self) -> &'static str {
        match self.tool {
            GuiTool::Zenity => "zenity",
            GuiTool::Kdialog => "kdialog",
        }
    }
}
