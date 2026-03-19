use anyhow::{Context, Result};
use bitsafe_common::config::Config;
use bitsafe_common::socket;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tokio::net::UnixListener;
use tokio::signal;

use crate::session;
use crate::state;
use crate::sync_worker;

pub async fn run(config: Config) -> Result<()> {
    let socket_path = socket::service_socket_path();
    let runtime_dir = socket::runtime_dir();

    // Ensure runtime directory exists
    fs::create_dir_all(&runtime_dir)
        .with_context(|| format!("Failed to create runtime dir: {}", runtime_dir.display()))?;
    fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700))?;

    // Remove stale socket
    if socket_path.exists() {
        fs::remove_file(&socket_path)
            .with_context(|| format!("Failed to remove stale socket: {}", socket_path.display()))?;
    }

    // Bind the socket
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("Failed to bind socket: {}", socket_path.display()))?;

    // Set socket permissions to owner-only
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;

    tracing::info!("Listening on {}", socket_path.display());

    let shared_state = state::new_shared_state(config.session, config.prompt.method, config.access).await;

    // Spawn the auto-lock worker
    let auto_lock_state = shared_state.clone();
    let auto_lock_secs = config.service.auto_lock_seconds;
    tokio::spawn(async move {
        sync_worker::auto_lock_worker(auto_lock_state, auto_lock_secs).await;
    });

    // Spawn the background sync worker
    let sync_state = shared_state.clone();
    let sync_interval = config.service.sync_interval_seconds;
    tokio::spawn(async move {
        sync_worker::background_sync_worker(sync_state, sync_interval).await;
    });

    // Spawn the embedded SSH agent on a second socket
    if config.ssh_agent.enabled {
        let ssh_socket_path = socket::ssh_agent_socket_path();
        if ssh_socket_path.exists() {
            let _ = fs::remove_file(&ssh_socket_path);
        }
        let ssh_listener = UnixListener::bind(&ssh_socket_path)
            .with_context(|| format!("Failed to bind SSH agent socket: {}", ssh_socket_path.display()))?;
        fs::set_permissions(&ssh_socket_path, fs::Permissions::from_mode(0o600))?;

        tracing::info!("SSH agent listening on {}", ssh_socket_path.display());
        tracing::info!("export SSH_AUTH_SOCK={}", ssh_socket_path.display());

        let ssh_state = shared_state.clone();
        tokio::spawn(async move {
            let handler = crate::ssh_agent::SshAgentHandler::new(ssh_state);
            if let Err(e) = ssh_agent_lib::agent::listen(ssh_listener, handler).await {
                tracing::error!("SSH agent error: {e}");
            }
        });
    }

    // Accept loop with graceful shutdown
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        // Verify peer credentials (same UID).
                        // Uses SO_PEERCRED on Linux, getpeereid on macOS.
                        let mut peer_pid: Option<u32> = None;

                        #[cfg(unix)]
                        {
                            match stream.peer_cred() {
                                Ok(cred) => {
                                    let my_uid = unsafe { libc::getuid() };
                                    if cred.uid() != my_uid {
                                        tracing::warn!(
                                            peer_uid = cred.uid(),
                                            my_uid = my_uid,
                                            "Rejecting connection from different user"
                                        );
                                        continue;
                                    }
                                    peer_pid = cred.pid().map(|p| p as u32);
                                }
                                Err(e) => {
                                    tracing::warn!("Failed to get peer credentials: {e}");
                                    continue;
                                }
                            }
                        }

                        let client_state = shared_state.clone();
                        tokio::spawn(async move {
                            session::handle_client(stream, client_state, peer_pid).await;
                        });
                    }
                    Err(e) => {
                        tracing::error!("Failed to accept connection: {e}");
                    }
                }
            }
            _ = signal::ctrl_c() => {
                tracing::info!("Received SIGINT, shutting down");
                break;
            }
        }
    }

    // Cleanup
    let _ = fs::remove_file(&socket_path);
    let _ = fs::remove_file(socket::ssh_agent_socket_path());
    tracing::info!("Shut down cleanly");
    Ok(())
}
