use anyhow::{Context, Result};
use bitsafe_common::config::PromptMethod;
use serde::Deserialize;
use std::process::Stdio;
use tokio::process::Command;

#[derive(Debug, Deserialize)]
pub struct PromptResponse {
    pub status: String,
    #[serde(default)]
    pub credential: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

/// Find the best available prompt binary.
/// Prefers the platform-native binary, falls back to the generic one.
fn prompt_binary() -> String {
    // Platform-native binary name
    #[cfg(target_os = "macos")]
    let native_name = "bitsafe-prompt-macos";
    #[cfg(target_os = "linux")]
    let native_name = "bitsafe-prompt-linux";
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let native_name = "";

    if let Ok(mut path) = std::env::current_exe() {
        // Check for native binary next to service
        if !native_name.is_empty() {
            path.set_file_name(native_name);
            if path.exists() {
                return path.to_string_lossy().into_owned();
            }
        }
        // Check for generic binary next to service
        path.set_file_name("bitsafe-prompt");
        if path.exists() {
            return path.to_string_lossy().into_owned();
        }
    }

    // Check PATH for native binary
    if !native_name.is_empty() {
        if let Ok(output) = std::process::Command::new("which").arg(native_name).output() {
            if output.status.success() {
                return native_name.into();
            }
        }
    }

    // Fall back to generic
    "bitsafe-prompt".into()
}

/// Spawn `bitsafe-prompt password` and return the master password.
pub async fn prompt_password(method: &PromptMethod) -> Result<Option<String>> {
    if *method == PromptMethod::None {
        anyhow::bail!("Interactive prompting is disabled (prompt.method = \"none\")");
    }

    let mut cmd = Command::new(prompt_binary());
    cmd.arg("password");

    // If method is terminal, set an env hint for the prompt agent
    if *method == PromptMethod::Terminal {
        cmd.env("BITSAFE_PROMPT_TERMINAL", "1");
    }

    cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());
    let output = cmd.output().await.context("Failed to spawn bitsafe-prompt")?;

    if !output.status.success() && output.status.code() == Some(1) {
        return Ok(None); // User cancelled
    }

    let response: PromptResponse =
        serde_json::from_slice(&output.stdout).context("Failed to parse prompt response")?;

    match response.status.as_str() {
        "ok" => Ok(response.credential),
        "cancelled" => Ok(None),
        _ => anyhow::bail!(
            "Prompt error: {}",
            response.message.unwrap_or_else(|| "unknown".into())
        ),
    }
}

/// Spawn `bitsafe-prompt biometric` and return whether verification succeeded.
pub async fn prompt_biometric(method: &PromptMethod, reason: &str) -> Result<bool> {
    if *method == PromptMethod::None || *method == PromptMethod::Terminal {
        anyhow::bail!("Biometric not available with prompt method {:?}", method);
    }

    let mut cmd = Command::new(prompt_binary());
    cmd.args(["biometric", "--reason", reason]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());
    let output = cmd.output().await.context("Failed to spawn bitsafe-prompt")?;

    let response: PromptResponse =
        serde_json::from_slice(&output.stdout).context("Failed to parse prompt response")?;

    match response.status.as_str() {
        "verified" => Ok(true),
        "cancelled" => Ok(false),
        "error" => {
            let msg = response.message.unwrap_or_default();
            if msg.contains("unavailable") {
                Ok(false) // Biometric not available, caller should fall back to PIN
            } else {
                anyhow::bail!("Biometric error: {msg}")
            }
        }
        _ => Ok(false),
    }
}

/// Spawn `bitsafe-prompt pin` and return the entered PIN.
pub async fn prompt_pin(
    method: &PromptMethod,
    attempt: u32,
    max_attempts: u32,
) -> Result<Option<String>> {
    if *method == PromptMethod::None {
        anyhow::bail!("Interactive prompting is disabled");
    }

    let mut cmd = Command::new(prompt_binary());
    cmd.args([
        "pin",
        "--attempt",
        &attempt.to_string(),
        "--max-attempts",
        &max_attempts.to_string(),
    ]);

    if *method == PromptMethod::Terminal {
        cmd.env("BITSAFE_PROMPT_TERMINAL", "1");
    }

    cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());
    let output = cmd.output().await.context("Failed to spawn bitsafe-prompt")?;

    if !output.status.success() && output.status.code() == Some(1) {
        return Ok(None);
    }

    let response: PromptResponse =
        serde_json::from_slice(&output.stdout).context("Failed to parse prompt response")?;

    match response.status.as_str() {
        "ok" => Ok(response.credential),
        "cancelled" => Ok(None),
        _ => anyhow::bail!(
            "PIN prompt error: {}",
            response.message.unwrap_or_else(|| "unknown".into())
        ),
    }
}
