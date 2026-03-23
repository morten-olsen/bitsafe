//! Embedded SSH agent — listens on a second socket inside the service process.
//!
//! Accesses vault state directly (no JSON-RPC round-trip). SSH clients connect
//! to $XDG_RUNTIME_DIR/grimoire/ssh-agent.sock and the agent translates
//! SSH protocol messages to vault operations.
//!
//! If the vault is locked when an SSH operation arrives, the agent automatically
//! triggers a GUI unlock prompt (same as CLI auto-unlock). On successful unlock,
//! access approval is granted and a background sync is triggered.
//!
//! Access approval is enforced on signing: the SSH client's peer PID is resolved
//! to a scope key (same as CLI commands). If approval is not cached, the GUI
//! prompt is triggered. For headless sessions, use `grimoire approve`.

use crate::prompt;
use crate::session::resolve_scope_key;
use crate::state::{SharedState, VaultState};
use grimoire_common::config::{PromptMethod, APPROVAL_SECONDS};
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_agent_lib::ssh_key;

/// Agent handler that creates per-connection sessions with peer credentials.
pub struct SshAgentHandler {
    state: SharedState,
}

impl SshAgentHandler {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }
}

impl ssh_agent_lib::agent::Agent<tokio::net::UnixListener> for SshAgentHandler {
    fn new_session(
        &mut self,
        socket: &tokio::net::UnixStream,
    ) -> impl ssh_agent_lib::agent::Session {
        // Verify peer UID matches ours — defense-in-depth matching the main socket check.
        #[cfg(unix)]
        if let Ok(cred) = socket.peer_cred() {
            // SAFETY: getuid() is a read-only syscall with no preconditions.
            let my_uid = unsafe { libc::getuid() };
            if cred.uid() != my_uid {
                tracing::warn!(
                    peer_uid = cred.uid(),
                    my_uid,
                    "SSH agent: rejecting connection from different user"
                );
                return SshAgentSession {
                    state: self.state.clone(),
                    peer_pid: None,
                    rejected: true,
                };
            }
        }

        let peer_pid = socket
            .peer_cred()
            .ok()
            .and_then(|c| c.pid().map(|p| p as u32));
        tracing::debug!(?peer_pid, "SSH agent: new connection");
        SshAgentSession {
            state: self.state.clone(),
            peer_pid,
            rejected: false,
        }
    }
}

/// SSH agent session with direct access to service state.
/// Each connection gets its own session with the connecting process's PID.
#[derive(Clone)]
pub struct SshAgentSession {
    state: SharedState,
    peer_pid: Option<u32>,
    /// Set to true if the UID check failed — all operations return empty/error.
    rejected: bool,
}

#[async_trait::async_trait]
impl ssh_agent_lib::agent::Session for SshAgentSession {
    async fn request_identities(
        &mut self,
    ) -> Result<Vec<Identity>, ssh_agent_lib::error::AgentError> {
        if self.rejected {
            return Ok(vec![]);
        }
        // If vault is locked (but logged in), attempt auto-unlock via GUI prompt.
        {
            let s = self.state.read().await;
            if s.vault_state == VaultState::Locked {
                drop(s);
                if !self.attempt_unlock().await {
                    return Ok(vec![]); // Unlock failed or unavailable — return empty
                }
            } else if s.vault_state != VaultState::Unlocked {
                return Ok(vec![]); // Logged out — return empty
            }
        }

        let s = self.state.read().await;
        let Some(sdk) = &s.sdk else {
            return Ok(vec![]);
        };

        let keys = sdk.ssh().list_keys().await.map_err(agent_err)?;

        let mut identities = Vec::new();
        for key in keys {
            match ssh_key::PublicKey::from_openssh(&key.public_key) {
                Ok(pubkey) => {
                    identities.push(Identity {
                        pubkey: pubkey.key_data().clone(),
                        comment: key.name,
                    });
                }
                Err(e) => {
                    tracing::warn!(name = %key.name, "Failed to parse public key: {e}");
                }
            }
        }

        tracing::debug!(count = identities.len(), "SSH: returning identities");
        Ok(identities)
    }

    async fn sign(
        &mut self,
        request: SignRequest,
    ) -> Result<ssh_key::Signature, ssh_agent_lib::error::AgentError> {
        if self.rejected {
            return Err(agent_err("Connection rejected"));
        }
        // If vault is locked (but logged in), attempt auto-unlock via GUI prompt.
        {
            let s = self.state.read().await;
            if s.vault_state == VaultState::Locked {
                drop(s);
                if !self.attempt_unlock().await {
                    return Err(agent_err(
                        "Vault is locked — unlock failed or unavailable, run `grimoire approve`",
                    ));
                }
            } else if s.vault_state != VaultState::Unlocked {
                return Err(agent_err("Not logged in"));
            }
        }

        // Enforce access approval — same scoping as CLI vault commands
        if !self.check_approval().await? {
            return Err(agent_err(
                "Access approval required — run `grimoire approve` or approve via GUI",
            ));
        }

        let s = self.state.read().await;
        let Some(sdk) = &s.sdk else {
            return Err(agent_err("Vault is locked"));
        };

        // Find the key ID by matching the public key
        let keys = sdk.ssh().list_keys().await.map_err(agent_err)?;

        let key_id = keys
            .iter()
            .find(|k| {
                ssh_key::PublicKey::from_openssh(&k.public_key)
                    .map(|pk| *pk.key_data() == request.pubkey)
                    .unwrap_or(false)
            })
            .map(|k| k.id.clone())
            .ok_or_else(|| agent_err("Key not found in vault"))?;

        tracing::info!(key_id = %key_id, peer_pid = ?self.peer_pid, "SSH: signing request");

        let signature_bytes = sdk
            .ssh()
            .sign(&key_id, &request.data, request.flags)
            .await
            .map_err(agent_err)?;

        // Parse the SSH wire format signature
        parse_ssh_signature(&signature_bytes).map_err(agent_err)
    }
}

impl SshAgentSession {
    /// Attempt to unlock the vault via the GUI prompt when it's in Locked state.
    /// On success, also grants access approval and triggers a background sync.
    /// Returns true if the vault was successfully unlocked.
    async fn attempt_unlock(&self) -> bool {
        tracing::info!(peer_pid = ?self.peer_pid, "SSH agent: vault locked, attempting auto-unlock");

        // Respect master password backoff
        {
            let s = self.state.read().await;
            let remaining = s.master_password_backoff_remaining();
            if remaining > 0 {
                tracing::info!(remaining, "SSH agent: master password backoff active");
                return false;
            }
        }

        // Prompt for password via GUI
        let prompt_method = self.state.read().await.prompt_method.clone();
        if prompt_method == PromptMethod::None {
            tracing::info!("SSH agent: no prompt method available, run `grimoire approve`");
            return false;
        }

        let password = match prompt::prompt_password(&prompt_method).await {
            Ok(Some(pw)) => pw,
            Ok(None) => {
                tracing::info!("SSH agent: unlock cancelled by user");
                return false;
            }
            Err(e) => {
                tracing::warn!("SSH agent: prompt failed: {e}");
                return false;
            }
        };

        // Unlock the vault
        let mut s = self.state.write().await;
        match s.unlock(&password).await {
            Ok(()) => {
                s.reset_password_attempts();

                // Grant access approval — user proved identity via master password
                let scope_key = resolve_scope_key(self.peer_pid);
                let duration = std::time::Duration::from_secs(APPROVAL_SECONDS);
                s.approval_cache.grant(scope_key, duration);
                tracing::info!(scope_key, "SSH agent: vault unlocked and access approved");

                drop(s);

                // Trigger background sync so vault data is available
                let sync_state = self.state.clone();
                tokio::spawn(async move {
                    crate::sync_worker::sync_now(&sync_state).await;
                });

                // Wait briefly for sync to populate keys
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                true
            }
            Err(e) => {
                s.record_password_failure();
                tracing::warn!("SSH agent: unlock failed: {e}");
                false
            }
        }
    }

    /// Check access approval for this connection's scope.
    /// Uses the shared approval flow (biometric → PIN → password with server verification).
    /// If no GUI is available and approval is not cached, returns false.
    async fn check_approval(&self) -> Result<bool, ssh_agent_lib::error::AgentError> {
        let scope_key = resolve_scope_key(self.peer_pid);
        let already_approved = {
            let s = self.state.read().await;
            s.approval_cache.is_approved(scope_key)
        };

        if already_approved {
            return Ok(true);
        }

        tracing::info!(
            scope_key,
            peer_pid = ?self.peer_pid,
            "SSH agent: access approval required, attempting prompt"
        );

        let prompt_method = self.state.read().await.prompt_method.clone();
        let approved =
            crate::approval::attempt_approval(&self.state, &prompt_method, self.peer_pid).await;

        if !approved {
            tracing::info!(
                scope_key,
                "SSH agent: approval denied — run `grimoire approve`"
            );
        }

        Ok(approved)
    }
}

/// Parse an SSH wire-format signature into ssh_key 0.6.x Signature type.
fn parse_ssh_signature(bytes: &[u8]) -> Result<ssh_key::Signature, String> {
    if bytes.len() < 8 {
        return Err("Signature too short".into());
    }
    let algo_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if bytes.len() < 4 + algo_len + 4 {
        return Err("Signature truncated".into());
    }
    let algo_str =
        std::str::from_utf8(&bytes[4..4 + algo_len]).map_err(|e| format!("Bad algo: {e}"))?;
    let sig_offset = 4 + algo_len;
    let sig_len = u32::from_be_bytes([
        bytes[sig_offset],
        bytes[sig_offset + 1],
        bytes[sig_offset + 2],
        bytes[sig_offset + 3],
    ]) as usize;
    if bytes.len() < sig_offset + 4 + sig_len {
        return Err("Signature data truncated".into());
    }
    let sig_data = &bytes[sig_offset + 4..sig_offset + 4 + sig_len];

    let algorithm = algo_str
        .parse::<ssh_key::Algorithm>()
        .map_err(|e| format!("Unknown algorithm {algo_str}: {e}"))?;

    ssh_key::Signature::new(algorithm, sig_data.to_vec())
        .map_err(|e| format!("Signature error: {e}"))
}

fn agent_err(e: impl std::fmt::Display) -> ssh_agent_lib::error::AgentError {
    ssh_agent_lib::error::AgentError::Other(anyhow::anyhow!("{e}").into())
}
