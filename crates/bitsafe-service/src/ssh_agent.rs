//! Embedded SSH agent — listens on a second socket inside the service process.
//!
//! Accesses vault state directly (no JSON-RPC round-trip). SSH clients connect
//! to $XDG_RUNTIME_DIR/bitsafe/ssh-agent.sock and the agent translates
//! SSH protocol messages to vault operations.
//!
//! Access approval is enforced on signing: the SSH client's peer PID is resolved
//! to a scope key (same as CLI commands). If approval is not cached, signing is
//! rejected — the user must pre-authorize via `bitsafe authorize` or the GUI
//! prompt will be triggered (if available).

use bitsafe_common::config::{PIN_MAX_ATTEMPTS, APPROVAL_SECONDS};
use crate::prompt;
use crate::session::resolve_scope_key;
use crate::state::{SharedState, VaultState};
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
    fn new_session(&mut self, socket: &tokio::net::UnixStream) -> impl ssh_agent_lib::agent::Session {
        let peer_pid = socket
            .peer_cred()
            .ok()
            .and_then(|c| c.pid().map(|p| p as u32));
        tracing::debug!(?peer_pid, "SSH agent: new connection");
        SshAgentSession {
            state: self.state.clone(),
            peer_pid,
        }
    }
}

/// SSH agent session with direct access to service state.
/// Each connection gets its own session with the connecting process's PID.
#[derive(Clone)]
pub struct SshAgentSession {
    state: SharedState,
    peer_pid: Option<u32>,
}

#[async_trait::async_trait]
impl ssh_agent_lib::agent::Session for SshAgentSession {
    async fn request_identities(
        &mut self,
    ) -> Result<Vec<Identity>, ssh_agent_lib::error::AgentError> {
        let s = self.state.read().await;
        if s.vault_state != VaultState::Unlocked {
            return Ok(vec![]); // Locked or logged out — return empty
        }
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
        // Check vault is unlocked
        {
            let s = self.state.read().await;
            if s.vault_state != VaultState::Unlocked {
                return Err(agent_err("Vault is locked"));
            }
        }

        // Enforce access approval — same scoping as CLI vault commands
        if !self.check_approval().await? {
            return Err(agent_err(
                "Access approval required — run `bitsafe authorize` or approve via GUI",
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
    /// Check access approval for this connection's scope.
    /// If approval is not cached, tries GUI prompt (biometric → PIN → password).
    /// If no GUI is available, returns false (user must pre-authorize via CLI).
    async fn check_approval(&self) -> Result<bool, ssh_agent_lib::error::AgentError> {
        let prompt_method = self.state.read().await.prompt_method.clone();

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

        // Try GUI prompt — biometric first, then PIN, then password.
        // This is what makes the GUI flow work without requiring pre-authorization.
        let approved =
            match prompt::prompt_biometric(&prompt_method, "BitSafe: approve SSH signing").await {
                Ok(true) => true,
                _ => {
                    // Biometric unavailable or failed — try PIN if set
                    let has_pin = self.state.read().await.pin_set();
                    if has_pin {
                        let attempt = {
                            let s = self.state.read().await;
                            s.session
                                .as_ref()
                                .map(|s| s.pin_attempts + 1)
                                .unwrap_or(1)
                        };
                        match prompt::prompt_pin(&prompt_method, attempt, PIN_MAX_ATTEMPTS).await {
                            Ok(Some(pin)) => self.state.write().await.verify_pin(&pin),
                            _ => false,
                        }
                    } else {
                        // No biometric, no PIN — try password prompt (GUI dialog)
                        match prompt::prompt_password(&prompt_method).await {
                            Ok(Some(_)) => true,
                            _ => false,
                        }
                    }
                }
            };

        if approved {
            let duration = std::time::Duration::from_secs(APPROVAL_SECONDS);
            self.state
                .write()
                .await
                .approval_cache
                .grant(scope_key, duration);
            tracing::info!(scope_key, "SSH agent: access approved");
            Ok(true)
        } else {
            tracing::info!(
                scope_key,
                "SSH agent: approval denied — run `bitsafe authorize`"
            );
            Ok(false)
        }
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
