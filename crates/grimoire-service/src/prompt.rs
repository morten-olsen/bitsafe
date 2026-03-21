use anyhow::{Context, Result};
use grimoire_common::config::PromptMethod;
use serde::Deserialize;
use std::process::Stdio;
use tokio::process::Command;
use zeroize::Zeroizing;

#[derive(Debug, Deserialize)]
pub struct PromptResponse {
    pub status: String,
    #[serde(default)]
    pub credential: Option<Zeroizing<String>>,
    #[serde(default)]
    pub message: Option<String>,
}

/// Find the prompt binary adjacent to the service executable.
///
/// SECURITY: Only checks next to `current_exe()`. Never falls back to PATH
/// lookup — a malicious binary earlier in $PATH could intercept master
/// passwords or bypass biometric approval. If not found, returns an error
/// so the caller can surface a clear message.
fn prompt_binary() -> Result<String> {
    // Platform-native binary name
    #[cfg(target_os = "macos")]
    let native_name = "grimoire-prompt-macos";
    #[cfg(target_os = "linux")]
    let native_name = "grimoire-prompt-linux";
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let native_name = "";

    let mut path = std::env::current_exe().context("Cannot determine service executable path")?;

    // Check for native binary next to service
    if !native_name.is_empty() {
        path.set_file_name(native_name);
        if path.exists() {
            return Ok(path.to_string_lossy().into_owned());
        }
    }

    // Check for generic binary next to service
    path.set_file_name("grimoire-prompt");
    if path.exists() {
        return Ok(path.to_string_lossy().into_owned());
    }

    anyhow::bail!(
        "No prompt binary found next to service executable ({}). \
         Install grimoire-prompt or grimoire-prompt-{} alongside the service binary.",
        std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".into()),
        std::env::consts::OS,
    )
}

/// Spawn `grimoire-prompt password` and return the master password.
pub async fn prompt_password(method: &PromptMethod) -> Result<Option<Zeroizing<String>>> {
    if *method == PromptMethod::None {
        anyhow::bail!("Interactive prompting is disabled (prompt.method = \"none\")");
    }

    let mut cmd = Command::new(prompt_binary()?);
    cmd.arg("password");

    // If method is terminal, set an env hint for the prompt agent
    if *method == PromptMethod::Terminal {
        cmd.env("GRIMOIRE_PROMPT_TERMINAL", "1");
    }

    cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());
    let output = cmd
        .output()
        .await
        .context("Failed to spawn grimoire-prompt")?;

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

/// Spawn `grimoire-prompt biometric` and return whether verification succeeded.
pub async fn prompt_biometric(method: &PromptMethod, reason: &str) -> Result<bool> {
    if *method == PromptMethod::None || *method == PromptMethod::Terminal {
        anyhow::bail!("Biometric not available with prompt method {method:?}");
    }

    let mut cmd = Command::new(prompt_binary()?);
    cmd.args(["biometric", "--reason", reason]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());
    let output = cmd
        .output()
        .await
        .context("Failed to spawn grimoire-prompt")?;

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

/// Spawn `grimoire-prompt pin` and return the entered PIN.
pub async fn prompt_pin(
    method: &PromptMethod,
    attempt: u32,
    max_attempts: u32,
) -> Result<Option<Zeroizing<String>>> {
    if *method == PromptMethod::None {
        anyhow::bail!("Interactive prompting is disabled");
    }

    let mut cmd = Command::new(prompt_binary()?);
    cmd.args([
        "pin",
        "--attempt",
        &attempt.to_string(),
        "--max-attempts",
        &max_attempts.to_string(),
    ]);

    if *method == PromptMethod::Terminal {
        cmd.env("GRIMOIRE_PROMPT_TERMINAL", "1");
    }

    cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());
    let output = cmd
        .output()
        .await
        .context("Failed to spawn grimoire-prompt")?;

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
