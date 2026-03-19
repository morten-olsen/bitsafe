use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub service: ServiceConfig,
    #[serde(default)]
    pub session: SessionConfig,
    #[serde(default)]
    pub prompt: PromptConfig,
    #[serde(default)]
    pub access: AccessConfig,
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

#[derive(Debug, Deserialize)]
pub struct ServiceConfig {
    #[serde(default = "default_auto_lock")]
    pub auto_lock_seconds: u64,
    #[serde(default = "default_sync_interval")]
    pub sync_interval_seconds: u64,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            auto_lock_seconds: default_auto_lock(),
            sync_interval_seconds: default_sync_interval(),
        }
    }
}

fn default_auto_lock() -> u64 {
    900
}

fn default_sync_interval() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
pub struct SessionConfig {
    /// How long a session remains valid before re-verification is required.
    #[serde(default = "default_session_duration")]
    pub duration_seconds: u64,
    /// Allow PIN for re-verification.
    #[serde(default = "default_true")]
    pub pin_enabled: bool,
    /// Maximum failed PIN attempts before requiring full master password.
    #[serde(default = "default_pin_max_attempts")]
    pub pin_max_attempts: u32,
    /// Try biometric before PIN.
    #[serde(default = "default_true")]
    pub biometric_enabled: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            duration_seconds: default_session_duration(),
            pin_enabled: true,
            pin_max_attempts: default_pin_max_attempts(),
            biometric_enabled: true,
        }
    }
}

fn default_session_duration() -> u64 {
    300
}

fn default_pin_max_attempts() -> u32 {
    3
}

fn default_true() -> bool {
    true
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
    /// Override the GUI backend (auto, zenity, kdialog, osascript).
    #[serde(default)]
    pub gui_backend: Option<String>,
}

impl Default for PromptConfig {
    fn default() -> Self {
        Self {
            method: PromptMethod::Auto,
            gui_backend: None,
        }
    }
}

/// Scoped access approval — gates sensitive operations behind lightweight verification.
#[derive(Debug, Deserialize, Clone)]
pub struct AccessConfig {
    /// Require approval for sensitive operations (vault.get, ssh.sign, etc.)
    #[serde(default = "default_true")]
    pub require_approval: bool,
    /// How long an approval grant lasts, in seconds.
    #[serde(default = "default_approval_seconds")]
    pub approval_seconds: u64,
    /// Scope of approval: session (terminal session), pid (exact process), connection.
    #[serde(default)]
    pub approval_for: ApprovalScope,
}

impl Default for AccessConfig {
    fn default() -> Self {
        Self {
            require_approval: true,
            approval_seconds: default_approval_seconds(),
            approval_for: ApprovalScope::Session,
        }
    }
}

fn default_approval_seconds() -> u64 {
    300
}

#[derive(Debug, Deserialize, Default, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalScope {
    /// Approval covers all processes in the same terminal session.
    #[default]
    Session,
    /// Approval covers only the exact requesting PID and its children.
    Pid,
    /// Approval covers a single socket connection (most restrictive).
    Connection,
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
        assert_eq!(config.service.auto_lock_seconds, 900);
        assert_eq!(config.service.sync_interval_seconds, 300);
        assert_eq!(config.session.duration_seconds, 300);
        assert_eq!(config.session.pin_max_attempts, 3);
        assert!(config.session.pin_enabled);
        assert!(config.session.biometric_enabled);
        assert_eq!(config.prompt.method, PromptMethod::Auto);
        assert!(config.ssh_agent.enabled);
    }

    #[test]
    fn parse_empty_toml_uses_defaults() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.service.auto_lock_seconds, 900);
        assert_eq!(config.session.duration_seconds, 300);
    }

    #[test]
    fn parse_partial_toml_overrides() {
        let config: Config = toml::from_str(
            r#"
[service]
auto_lock_seconds = 60

[session]
pin_max_attempts = 5
"#,
        )
        .unwrap();
        assert_eq!(config.service.auto_lock_seconds, 60);
        assert_eq!(config.session.pin_max_attempts, 5);
        assert_eq!(config.service.sync_interval_seconds, 300);
        assert_eq!(config.session.duration_seconds, 300);
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
}
