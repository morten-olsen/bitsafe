use serde::Deserialize;
use std::path::PathBuf;

// --- Hardcoded security constants ---
// These are not configurable. Configurability in security-critical paths is attack surface.

/// Auto-lock the vault after 15 minutes of inactivity.
pub const AUTO_LOCK_SECONDS: u64 = 900;
/// Background sync every 5 minutes.
pub const SYNC_INTERVAL_SECONDS: u64 = 300;
/// Re-verify after 5 minutes of session.
pub const SESSION_DURATION_SECONDS: u64 = 300;
/// Maximum failed PIN attempts before requiring full master password.
pub const PIN_MAX_ATTEMPTS: u32 = 3;
/// How long an approval grant lasts, in seconds.
pub const APPROVAL_SECONDS: u64 = 300;

/// Config file structure. Only operational settings are configurable —
/// security parameters are hardcoded constants.
#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub prompt: PromptConfig,
    #[serde(default)]
    pub ssh_agent: SshAgentConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_server_url")]
    pub url: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            url: default_server_url(),
        }
    }
}

fn default_server_url() -> String {
    "https://vault.bitwarden.com".to_string()
}

/// How the service obtains credentials interactively.
#[derive(Debug, Deserialize, Default, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PromptMethod {
    /// Auto-detect: GUI if available, terminal fallback.
    #[default]
    Auto,
    /// Always use GUI dialogs (fail if unavailable).
    Gui,
    /// Always use terminal prompts.
    Terminal,
    /// Never prompt interactively — require password in RPC params.
    None,
}

#[derive(Debug, Deserialize)]
pub struct PromptConfig {
    #[serde(default)]
    pub method: PromptMethod,
}

impl Default for PromptConfig {
    fn default() -> Self {
        Self {
            method: PromptMethod::Auto,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SshAgentConfig {
    #[serde(default)]
    pub enabled: bool,
}

impl Default for SshAgentConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Returns the config file path: `~/.config/bitsafe/config.toml`.
pub fn config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("bitsafe").join("config.toml"))
}

/// Parse config from a TOML string.
pub fn parse_config(toml_str: &str) -> Result<Config, toml::de::Error> {
    toml::from_str(toml_str)
}

/// Load config from the default path, returning defaults if the file doesn't exist.
pub fn load_config() -> Config {
    let Some(path) = config_path() else {
        return Config::default();
    };

    match std::fs::read_to_string(&path) {
        Ok(contents) => toml::from_str(&contents).unwrap_or_else(|e| {
            tracing::warn!("Failed to parse config at {}: {e}", path.display());
            Config::default()
        }),
        Err(_) => Config::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sensible() {
        let config = Config::default();
        assert_eq!(config.prompt.method, PromptMethod::Auto);
        assert!(config.ssh_agent.enabled);
        assert_eq!(AUTO_LOCK_SECONDS, 900);
        assert_eq!(SYNC_INTERVAL_SECONDS, 300);
        assert_eq!(SESSION_DURATION_SECONDS, 300);
        assert_eq!(PIN_MAX_ATTEMPTS, 3);
        assert_eq!(APPROVAL_SECONDS, 300);
    }

    #[test]
    fn parse_empty_toml_uses_defaults() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.prompt.method, PromptMethod::Auto);
    }

    #[test]
    fn parse_prompt_method_variants() {
        for (input, expected) in [
            ("auto", PromptMethod::Auto),
            ("gui", PromptMethod::Gui),
            ("terminal", PromptMethod::Terminal),
            ("none", PromptMethod::None),
        ] {
            let toml_str = format!("[prompt]\nmethod = \"{input}\"");
            let config: Config = toml::from_str(&toml_str).unwrap();
            assert_eq!(config.prompt.method, expected);
        }
    }

    #[test]
    fn parse_server_url() {
        let config: Config = toml::from_str("[server]\nurl = \"https://vault.example.com\"").unwrap();
        assert_eq!(config.server.url, "https://vault.example.com");
    }

    #[test]
    fn parse_ssh_agent_disabled() {
        let config: Config = toml::from_str("[ssh_agent]\nenabled = false").unwrap();
        assert!(!config.ssh_agent.enabled);
    }

    #[test]
    fn unknown_sections_are_ignored() {
        // Old configs with removed sections should still parse
        let config: Config = toml::from_str(
            r#"
[server]
url = "https://vault.example.com"

[session]
duration_seconds = 600
pin_max_attempts = 5

[access]
require_approval = false
"#,
        )
        .unwrap();
        assert_eq!(config.server.url, "https://vault.example.com");
        // Security constants remain hardcoded regardless of config file
        assert_eq!(PIN_MAX_ATTEMPTS, 3);
    }
}
