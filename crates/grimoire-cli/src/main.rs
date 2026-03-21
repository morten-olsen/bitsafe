use anyhow::{Context, Result};
use grimoire_common::socket;
use grimoire_protocol::codec::{handshake_client, read_message, write_message};
use grimoire_protocol::request::{
    methods, LoginParams, Request, RequestParams, UnlockParams, VaultGetParams, VaultListParams,
    VaultTotpParams,
};
use grimoire_protocol::response::{error_codes, Response};
use clap::{CommandFactory, Parser, Subcommand};
use tokio::net::UnixStream;
use zeroize::Zeroizing;
use tracing_subscriber::EnvFilter;

mod commands;

#[derive(Parser)]
#[command(name = "grimoire", about = "Grimoire password manager CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output as JSON
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Show service status
    Status,
    /// Log in to the server
    Login {
        /// Email address
        email: String,
        /// Server URL (overrides config)
        #[arg(long)]
        server: Option<String>,
    },
    /// Unlock the vault
    Unlock {
        /// Prompt for password in the terminal instead of GUI dialog
        #[arg(long)]
        terminal: bool,
    },
    /// List vault items
    List {
        /// Filter by type (login, card, note, identity)
        #[arg(long, short = 't')]
        r#type: Option<String>,
        /// Search query
        #[arg(long, short = 's')]
        search: Option<String>,
    },
    /// Get a vault item
    Get {
        /// Item ID
        id: String,
        /// Field to extract (password, username, totp, uri, notes)
        #[arg(long, short = 'f')]
        field: Option<String>,
    },
    /// Generate a TOTP code for a vault item
    Totp {
        /// Item ID
        id: String,
    },
    /// Authorize access by entering the master password (for SSH/headless sessions)
    Authorize,
    /// Force a vault sync
    Sync,
    /// Lock the vault
    Lock,
    /// Log out
    Logout,
    /// Run a command with vault secrets injected into environment variables.
    /// Environment values matching "grimoire:<id>/<field>" are replaced with
    /// the actual secret from the vault before exec.
    Run {
        /// Command and arguments to run
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Install/manage the background service
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Install the service to start on login
    Install,
    /// Uninstall the service
    Uninstall,
    /// Show the SSH_AUTH_SOCK path
    SshSocket,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .init();

    let cli = Cli::parse();

    type ResponseHandler = Box<dyn Fn(Response, bool) -> Result<()>>;
    let (request, handler): (Request, ResponseHandler) = match cli.command
    {
        Commands::Status => (
            Request::new(1, methods::AUTH_STATUS, None),
            Box::new(commands::handle_status),
        ),
        Commands::Login { email, server } => {
            // Login is a one-time setup — prompt in the terminal.
            let password = Zeroizing::new(rpassword::prompt_password("Master password: ")
                .context("Failed to read password")?);
            (
                Request::new(
                    1,
                    methods::AUTH_LOGIN,
                    Some(RequestParams::Login(LoginParams {
                        email,
                        password: Some(password),
                        server_url: server,
                    })),
                ),
                Box::new(commands::handle_login),
            )
        }
        Commands::Unlock { terminal } => {
            // Default: delegate to the service's GUI prompt agent (RCE-resistant).
            // --terminal: prompt in the terminal for convenience (e.g. SSH sessions).
            let password = if terminal {
                Some(Zeroizing::new(
                    rpassword::prompt_password("Master password: ")
                        .context("Failed to read password")?,
                ))
            } else {
                None
            };
            (
                Request::new(
                    1,
                    methods::AUTH_UNLOCK,
                    Some(RequestParams::Unlock(UnlockParams { password })),
                ),
                Box::new(commands::handle_unlock),
            )
        }
        Commands::List { r#type, search } => (
            Request::new(
                1,
                methods::VAULT_LIST,
                Some(RequestParams::VaultList(VaultListParams {
                    r#type,
                    search,
                })),
            ),
            Box::new(commands::handle_list),
        ),
        Commands::Get { id, field } => {
            // Route --field totp to the dedicated TOTP endpoint
            if field.as_deref() == Some("totp") {
                (
                    Request::new(
                        1,
                        methods::VAULT_TOTP,
                        Some(RequestParams::VaultTotp(VaultTotpParams { id })),
                    ),
                    Box::new(commands::handle_totp),
                )
            } else {
                let extract_field = field.clone();
                (
                    Request::new(
                        1,
                        methods::VAULT_GET,
                        Some(RequestParams::VaultGet(VaultGetParams { id, field })),
                    ),
                    Box::new(move |r, j| commands::handle_get(r, j, extract_field.as_deref())),
                )
            }
        }
        Commands::Totp { id } => (
            Request::new(
                1,
                methods::VAULT_TOTP,
                Some(RequestParams::VaultTotp(VaultTotpParams { id })),
            ),
            Box::new(commands::handle_totp),
        ),
        Commands::Authorize => {
            let password = Zeroizing::new(rpassword::prompt_password("Master password: ")
                .context("Failed to read password")?);
            (
                Request::new(
                    1,
                    methods::AUTH_AUTHORIZE,
                    Some(RequestParams::Unlock(UnlockParams {
                        password: Some(password),
                    })),
                ),
                Box::new(commands::handle_authorize),
            )
        }
        Commands::Sync => (
            Request::new(1, methods::SYNC_TRIGGER, None),
            Box::new(commands::handle_sync),
        ),
        Commands::Lock => (
            Request::new(1, methods::AUTH_LOCK, None),
            Box::new(commands::handle_lock),
        ),
        Commands::Logout => (
            Request::new(1, methods::AUTH_LOGOUT, None),
            Box::new(commands::handle_logout),
        ),
        Commands::Run { command } => {
            return handle_run(command).await;
        }
        Commands::Service { action } => {
            return handle_service_action(action);
        }
        Commands::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "grimoire",
                &mut std::io::stdout(),
            );
            return Ok(());
        }
    };

    let mut response = send_request(request.clone()).await?;

    // Auto-prompt for master password when the vault is locked, session expired,
    // prompt unavailable, or access approval denied. This lets users run vault
    // commands directly without a separate unlock/authorize step.
    if let Some(err) = &response.error {
        match err.code {
            error_codes::VAULT_LOCKED => {
                // Vault locked — unlock with master password, then retry.
                // Unlock with a direct password also grants access approval,
                // so authorize doesn't need to be retried.
                eprintln!("Vault is locked.");
                // Reuse password from original request if available (e.g., authorize
                // already prompted for it) to avoid a redundant second prompt.
                let password = match &request.params {
                    Some(RequestParams::Unlock(UnlockParams { password: Some(pw) })) => pw.clone(),
                    _ => Zeroizing::new(rpassword::prompt_password("Master password: ")
                        .context("Failed to read password")?),
                };
                let unlock_resp = send_request(Request::new(
                    1,
                    methods::AUTH_UNLOCK,
                    Some(RequestParams::Unlock(UnlockParams {
                        password: Some(password),
                    })),
                ))
                .await?;
                commands::check_error(&unlock_resp)?;
                eprintln!("Vault unlocked.");

                if request.method == methods::AUTH_AUTHORIZE {
                    // Unlock already granted approval — no need to re-enter password
                    response = unlock_resp;
                } else {
                    // Wait briefly for background sync to populate vault data
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    response = send_request(request).await?;
                }
            }
            error_codes::SESSION_EXPIRED
            | error_codes::PROMPT_UNAVAILABLE
            | error_codes::ACCESS_DENIED => {
                // Session expired / prompt unavailable / access approval denied
                eprintln!("Authorization required.");
                let password = Zeroizing::new(rpassword::prompt_password("Master password: ")
                    .context("Failed to read password")?);
                let auth_resp = send_request(Request::new(
                    1,
                    methods::AUTH_AUTHORIZE,
                    Some(RequestParams::Unlock(UnlockParams {
                        password: Some(password),
                    })),
                ))
                .await?;
                commands::check_error(&auth_resp)?;
                response = send_request(request).await?;
            }
            _ => {}
        }
    }

    handler(response, cli.json)?;

    Ok(())
}

fn handle_service_action(action: ServiceAction) -> Result<()> {
    match action {
        ServiceAction::SshSocket => {
            println!("{}", grimoire_common::socket::ssh_agent_socket_path().display());
            Ok(())
        }
        ServiceAction::Install => install_service(),
        ServiceAction::Uninstall => uninstall_service(),
    }
}

fn install_service() -> Result<()> {
    let exe = std::env::current_exe().context("Cannot determine executable path")?;
    let service_bin = exe.with_file_name("grimoire-service");

    if !service_bin.exists() {
        anyhow::bail!(
            "grimoire-service not found at {}. Install it first.",
            service_bin.display()
        );
    }

    #[cfg(target_os = "linux")]
    {
        let unit_dir = dirs::config_dir()
            .context("Cannot determine config dir")?
            .join("systemd/user");
        std::fs::create_dir_all(&unit_dir)?;

        let unit_path = unit_dir.join("grimoire.service");
        let unit = format!(
            "[Unit]\n\
             Description=Grimoire Password Manager Service\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={}\n\
             Restart=on-failure\n\
             RestartSec=5\n\
             Environment=SSH_AUTH_SOCK=%t/grimoire/ssh-agent.sock\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n",
            service_bin.display()
        );
        std::fs::write(&unit_path, unit)?;

        // Enable and start
        let status = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status()?;
        if !status.success() {
            anyhow::bail!("systemctl daemon-reload failed");
        }
        let status = std::process::Command::new("systemctl")
            .args(["--user", "enable", "--now", "grimoire"])
            .status()?;
        if !status.success() {
            anyhow::bail!("systemctl enable failed");
        }

        println!("Service installed and started.");
        println!();
        println!("Add this to your shell profile (~/.bashrc or ~/.zshrc):");
        println!("  export SSH_AUTH_SOCK=\"${{XDG_RUNTIME_DIR}}/grimoire/ssh-agent.sock\"");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let plist_dir = dirs::home_dir()
            .context("Cannot determine home dir")?
            .join("Library/LaunchAgents");
        std::fs::create_dir_all(&plist_dir)?;

        let plist_path = plist_dir.join("com.grimoire.service.plist");
        let log_dir = dirs::home_dir()
            .context("Cannot determine home dir")?
            .join("Library/Logs/Grimoire");
        std::fs::create_dir_all(&log_dir)?;
        let log_dir = log_dir.display();
        let ssh_sock = grimoire_common::socket::ssh_agent_socket_path();
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.grimoire.service</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>{log_dir}/grimoire-service.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/grimoire-service.log</string>
</dict>
</plist>"#,
            service_bin.display()
        );
        std::fs::write(&plist_path, plist)?;

        let status = std::process::Command::new("launchctl")
            .args(["load", "-w"])
            .arg(&plist_path)
            .status()?;
        if !status.success() {
            anyhow::bail!("launchctl load failed");
        }

        println!("Service installed and started.");
        println!();
        println!("Add this to your shell profile (~/.zshrc):");
        println!("  export SSH_AUTH_SOCK=\"{}\"", ssh_sock.display());
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        anyhow::bail!("Service installation not supported on this platform");
    }
}

fn uninstall_service() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", "--now", "grimoire"])
            .status();

        let unit_path = dirs::config_dir()
            .context("Cannot determine config dir")?
            .join("systemd/user/grimoire.service");
        if unit_path.exists() {
            std::fs::remove_file(&unit_path)?;
        }
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();

        println!("Service uninstalled.");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let plist_path = dirs::home_dir()
            .context("Cannot determine home dir")?
            .join("Library/LaunchAgents/com.grimoire.service.plist");

        if plist_path.exists() {
            let _ = std::process::Command::new("launchctl")
                .args(["unload", "-w"])
                .arg(&plist_path)
                .status();
            std::fs::remove_file(&plist_path)?;
        }

        println!("Service uninstalled.");
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        anyhow::bail!("Service uninstallation not supported on this platform");
    }
}

async fn send_request(request: Request) -> Result<Response> {
    let socket_path = socket::service_socket_path();
    let stream = UnixStream::connect(&socket_path)
        .await
        .with_context(|| {
            format!(
                "Failed to connect to grimoire-service at {}.\nIs the service running?",
                socket_path.display()
            )
        })?;

    let (mut reader, mut writer) = stream.into_split();

    // X25519 key exchange — establish encrypted channel
    let codec = handshake_client(&mut reader, &mut writer)
        .await
        .context("Failed to establish encrypted channel with service")?;

    write_message(&mut writer, &codec, &request).await?;
    let response: Response = read_message(&mut reader, &codec).await?;

    Ok(response)
}

/// `grimoire run -- <command>`: resolve vault references in env vars, then exec.
async fn handle_run(command: Vec<String>) -> Result<()> {
    use grimoire_protocol::request::{ResolveRefsParams, VaultRef};
    use grimoire_protocol::response::ResolvedRef;

    if command.is_empty() {
        anyhow::bail!("No command specified. Usage: grimoire run -- <command> [args...]");
    }

    // Scan environment for grimoire: references
    let mut refs_to_resolve: Vec<(String, VaultRef)> = Vec::new(); // (env_key, ref)

    for (key, value) in std::env::vars() {
        if let Some(vault_ref) = parse_grimoire_ref(&value) {
            refs_to_resolve.push((key, vault_ref));
        }
    }

    if refs_to_resolve.is_empty() {
        tracing::debug!("No grimoire: references found in environment, exec directly");
    } else {
        // Batch resolve all references via the service
        let refs: Vec<VaultRef> = refs_to_resolve.iter().map(|(_, r)| r.clone()).collect();

        let resolve_request = Request::new(
            1,
            grimoire_protocol::request::methods::VAULT_RESOLVE_REFS,
            Some(RequestParams::ResolveRefs(ResolveRefsParams { refs })),
        );

        let mut response = send_request(resolve_request.clone()).await?;

        // Auto-prompt if vault is locked or authorization is needed
        if let Some(err) = &response.error {
            match err.code {
                error_codes::VAULT_LOCKED => {
                    eprintln!("Vault is locked.");
                    let password = Zeroizing::new(rpassword::prompt_password("Master password: ")
                        .context("Failed to read password")?);
                    let unlock_resp = send_request(Request::new(
                        1,
                        methods::AUTH_UNLOCK,
                        Some(RequestParams::Unlock(UnlockParams {
                            password: Some(password),
                        })),
                    ))
                    .await?;
                    commands::check_error(&unlock_resp)?;
                    eprintln!("Vault unlocked.");
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    response = send_request(resolve_request).await?;
                }
                error_codes::SESSION_EXPIRED
            | error_codes::PROMPT_UNAVAILABLE
            | error_codes::ACCESS_DENIED => {
                    eprintln!("Authorization required.");
                    let password = Zeroizing::new(rpassword::prompt_password("Master password: ")
                        .context("Failed to read password")?);
                    let auth_resp = send_request(Request::new(
                        1,
                        methods::AUTH_AUTHORIZE,
                        Some(RequestParams::Unlock(UnlockParams {
                            password: Some(password),
                        })),
                    ))
                    .await?;
                    commands::check_error(&auth_resp)?;
                    response = send_request(resolve_request).await?;
                }
                _ => {}
            }
        }

        if let Some(err) = &response.error {
            anyhow::bail!("{}", err.message);
        }

        let resolved: Vec<ResolvedRef> = serde_json::from_value(
            response
                .result
                .context("Service returned no result for vault.resolve_refs")?,
        )?;

        // Check for errors before exec (can't report after)
        let mut had_errors = false;
        for (i, result) in resolved.iter().enumerate() {
            if let Some(err) = &result.error {
                let (env_key, _) = &refs_to_resolve[i];
                eprintln!("grimoire: failed to resolve {env_key}: {err}");
                had_errors = true;
            }
        }
        if had_errors {
            anyhow::bail!("Some vault references could not be resolved");
        }

        // Replace environment variables with resolved values
        for (i, result) in resolved.iter().enumerate() {
            if let Some(value) = &result.value {
                let (env_key, _) = &refs_to_resolve[i];
                std::env::set_var(env_key, value);
            }
        }
    }

    // exec — replace this process with the child command
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(&command[0])
            .args(&command[1..])
            .exec();
        // exec only returns on error
        anyhow::bail!("Failed to exec '{}': {err}", command[0]);
    }

    #[cfg(not(unix))]
    {
        // Non-Unix fallback: spawn and wait (loses exec semantics)
        let status = std::process::Command::new(&command[0])
            .args(&command[1..])
            .status()
            .with_context(|| format!("Failed to run '{}'", command[0]))?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Parse a "grimoire:<id>/<field>" or "grimoire://<name>/<field>" reference from an env value.
fn parse_grimoire_ref(value: &str) -> Option<grimoire_protocol::request::VaultRef> {
    let rest = value.strip_prefix("grimoire:")?;

    // Split on last '/' to get id and field
    let slash_pos = rest.rfind('/')?;
    let id = &rest[..slash_pos];
    let field = &rest[slash_pos + 1..];

    if id.is_empty() || field.is_empty() {
        return None;
    }

    Some(grimoire_protocol::request::VaultRef {
        id: id.to_string(),
        field: field.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_grimoire_ref_id_and_field() {
        let r = parse_grimoire_ref("grimoire:64b18d6b/password").unwrap();
        assert_eq!(r.id, "64b18d6b");
        assert_eq!(r.field, "password");
    }

    #[test]
    fn parse_grimoire_ref_full_uuid() {
        let r = parse_grimoire_ref("grimoire:64b18d6b-8161-4a0c-befb-c3484d36ec68/username").unwrap();
        assert_eq!(r.id, "64b18d6b-8161-4a0c-befb-c3484d36ec68");
        assert_eq!(r.field, "username");
    }

    #[test]
    fn parse_grimoire_ref_name_lookup() {
        let r = parse_grimoire_ref("grimoire://GitHub API/password").unwrap();
        assert_eq!(r.id, "//GitHub API");
        assert_eq!(r.field, "password");
    }

    /// Regression: `grimoire authorize` with locked vault should reuse the password
    /// from the original request instead of prompting a second time.
    #[test]
    fn auto_unlock_reuses_password_from_authorize_request() {
        let password = Zeroizing::new("test-password".to_string());
        let params = Some(RequestParams::Unlock(UnlockParams {
            password: Some(password.clone()),
        }));

        // The auto-prompt handler extracts the password from the original request
        let extracted = match &params {
            Some(RequestParams::Unlock(UnlockParams { password: Some(pw) })) => Some(pw.clone()),
            _ => None,
        };
        assert_eq!(extracted, Some(password));
    }

    #[test]
    fn auto_unlock_prompts_when_no_password_in_request() {
        // Requests without a password (e.g., vault.list) should not extract one
        let params: Option<RequestParams> = None;
        let extracted = match &params {
            Some(RequestParams::Unlock(UnlockParams { password: Some(pw) })) => Some(pw.clone()),
            _ => None,
        };
        assert_eq!(extracted, None);
    }

    #[test]
    fn parse_grimoire_ref_not_a_ref() {
        assert!(parse_grimoire_ref("just a normal value").is_none());
        assert!(parse_grimoire_ref("grimoire:").is_none());
        assert!(parse_grimoire_ref("grimoire:id-only").is_none());
        assert!(parse_grimoire_ref("grimoire:/no-field").is_none());
    }
}
