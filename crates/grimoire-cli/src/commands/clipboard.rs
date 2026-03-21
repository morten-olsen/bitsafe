use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::process::{Command, Stdio};

use grimoire_common::config::CLIPBOARD_CLEAR_SECONDS;

/// Detected clipboard backend.
enum ClipboardBackend {
    /// macOS pbcopy/pbpaste
    Pbcopy,
    /// Wayland wl-copy/wl-paste
    WlCopy,
    /// X11 xclip
    Xclip,
}

impl ClipboardBackend {
    fn detect() -> Result<Self> {
        // Check Wayland first (wl-copy), then X11 (xclip), then macOS (pbcopy)
        if which("wl-copy") {
            return Ok(Self::WlCopy);
        }
        if which("xclip") {
            return Ok(Self::Xclip);
        }
        if which("pbcopy") {
            return Ok(Self::Pbcopy);
        }
        bail!(
            "No clipboard tool found. Install pbcopy (macOS), wl-copy (Wayland), or xclip (X11)."
        );
    }

    fn copy(&self, data: &[u8]) -> Result<()> {
        let mut child = match self {
            Self::Pbcopy => Command::new("pbcopy")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .context("Failed to spawn pbcopy")?,
            Self::WlCopy => Command::new("wl-copy")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .context("Failed to spawn wl-copy")?,
            Self::Xclip => Command::new("xclip")
                .args(["-selection", "clipboard"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .context("Failed to spawn xclip")?,
        };

        // Write secret to stdin pipe — never as a command-line argument
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(data)
                .context("Failed to write to clipboard tool stdin")?;
        }

        let output = child.wait_with_output().context("Clipboard tool failed")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Clipboard tool failed: {stderr}");
        }
        Ok(())
    }

    fn read(&self) -> Result<Vec<u8>> {
        let output = match self {
            Self::Pbcopy => Command::new("pbpaste")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .context("Failed to run pbpaste")?,
            Self::WlCopy => Command::new("wl-paste")
                .arg("--no-newline")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .context("Failed to run wl-paste")?,
            Self::Xclip => Command::new("xclip")
                .args(["-selection", "clipboard", "-o"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .context("Failed to run xclip -o")?,
        };
        Ok(output.stdout)
    }

    fn clear(&self) -> Result<()> {
        self.copy(b"")
    }
}

fn which(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Hash data with SHA-256 and return hex string.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Copy a secret to the clipboard and spawn a background clearer.
pub fn copy_and_schedule_clear(secret: &str, json: bool) -> Result<()> {
    let backend = ClipboardBackend::detect()?;

    // Copy secret to clipboard
    backend.copy(secret.as_bytes())?;

    // Hash the secret immediately, then forget it
    let hash = sha256_hex(secret.as_bytes());

    // Spawn background clearer using current_exe (no PATH lookup)
    let exe = std::env::current_exe().context("Cannot determine executable path")?;
    match Command::new(&exe)
        .args(["clip", "--clear-after", &hash])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(_) => {
            // Clearer spawned successfully
        }
        Err(e) => {
            // Fail-safe: if we can't spawn the clearer, clear immediately
            eprintln!("Warning: failed to spawn clipboard clearer ({e}), clearing immediately");
            backend.clear()?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"copied": true, "cleared": true, "reason": "clearer spawn failed"})
                );
            } else {
                eprintln!("Clipboard cleared immediately (could not schedule delayed clear).");
            }
            return Ok(());
        }
    }

    if json {
        println!(
            "{}",
            serde_json::json!({"copied": true, "clears_in": CLIPBOARD_CLEAR_SECONDS})
        );
    } else {
        eprintln!("Copied to clipboard. Clearing in {CLIPBOARD_CLEAR_SECONDS}s.");
    }

    Ok(())
}

/// Background clearer: sleep, then check hash and clear.
/// Called via `grimoire clip --clear-after <hash>`.
pub fn run_clear_after(expected_hash: &str) -> Result<()> {
    std::thread::sleep(std::time::Duration::from_secs(CLIPBOARD_CLEAR_SECONDS));

    let backend = ClipboardBackend::detect()?;
    let current = backend.read()?;
    let current_hash = sha256_hex(&current);

    if current_hash == expected_hash {
        backend.clear()?;
    }
    // If hashes don't match, user copied something else — don't clear.

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_deterministic() {
        let h1 = sha256_hex(b"test-secret");
        let h2 = sha256_hex(b"test-secret");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn sha256_hex_different_inputs() {
        let h1 = sha256_hex(b"secret-a");
        let h2 = sha256_hex(b"secret-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn sha256_hex_empty() {
        let h = sha256_hex(b"");
        // SHA-256 of empty string is a known constant
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
