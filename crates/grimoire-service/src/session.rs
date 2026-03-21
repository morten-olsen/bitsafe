use grimoire_common::config::{PromptMethod, APPROVAL_SECONDS};
use grimoire_protocol::codec::{handshake_server, read_message, write_message};
use grimoire_protocol::request::{
    methods, LoginParams, Request, RequestParams, ResolveRefsParams, SetPinParams, SshSignParams,
    UnlockParams, VaultGetParams, VaultListParams, VaultTotpParams,
};
use grimoire_protocol::response::{
    OkResult, ResolvedRef, Response, RpcError, SshKeyInfo, StatusResult, TotpResult, VaultItem,
    VaultItemDetail,
};
use grimoire_sdk::vault::VaultFilter;
use grimoire_sdk::SdkError;
use tokio::net::UnixStream;

use crate::prompt;
use crate::state::{SharedState, VaultState};

/// Timeout for the initial key exchange handshake.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Timeout for reading a single message from a client.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Handle a single client connection.
pub async fn handle_client(stream: UnixStream, state: SharedState, peer_pid: Option<u32>) {
    let (mut reader, mut writer) = stream.into_split();

    // X25519 key exchange — establish encrypted channel (with timeout)
    let codec = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake_server(&mut reader, &mut writer),
    )
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(grimoire_protocol::codec::CodecError::ConnectionClosed)) => {
            tracing::debug!("Client disconnected during handshake");
            return;
        }
        Ok(Err(e)) => {
            tracing::warn!("Handshake failed: {e}");
            return;
        }
        Err(_) => {
            tracing::warn!("Handshake timed out");
            return;
        }
    };

    loop {
        let request: Request =
            match tokio::time::timeout(READ_TIMEOUT, read_message(&mut reader, &codec)).await {
                Ok(Ok(req)) => req,
                Ok(Err(grimoire_protocol::codec::CodecError::ConnectionClosed)) => {
                    tracing::debug!("Client disconnected");
                    return;
                }
                Ok(Err(e)) => {
                    tracing::warn!("Failed to read request: {e}");
                    return;
                }
                Err(_) => {
                    tracing::debug!("Client idle timeout, disconnecting");
                    return;
                }
            };

        let response = dispatch(&request, &state, peer_pid).await;

        if let Err(e) = write_message(&mut writer, &codec, &response).await {
            tracing::warn!("Failed to write response: {e}");
            return;
        }
    }
}

/// Resolve the scope key for the approval cache.
///
/// Approval is always scoped to the terminal session leader PID.
/// All processes in the same terminal session share one approval grant.
/// When the peer PID cannot be determined, a unique monotonic scope key is used
/// to prevent unrelated connections from sharing approval grants.
pub(crate) fn resolve_scope_key(peer_pid: Option<u32>) -> u32 {
    static UNKNOWN_SCOPE_COUNTER: std::sync::atomic::AtomicU32 =
        std::sync::atomic::AtomicU32::new(u32::MAX);

    peer_pid
        .and_then(crate::peer::get_session_leader)
        .or(peer_pid)
        .unwrap_or_else(|| {
            // Each unresolvable connection gets a unique scope key, counting down from
            // u32::MAX to avoid colliding with real PIDs (which are small positive integers).
            UNKNOWN_SCOPE_COUNTER.fetch_sub(1, std::sync::atomic::Ordering::SeqCst)
        })
}

/// Methods that require vault access and are gated behind access approval.
fn requires_approval(method: &str) -> bool {
    matches!(
        method,
        methods::VAULT_LIST
            | methods::VAULT_GET
            | methods::VAULT_TOTP
            | methods::VAULT_RESOLVE_REFS
            | methods::SSH_LIST_KEYS
            | methods::SSH_SIGN
            | methods::SYNC_TRIGGER
    )
}

// Approval logic is in crate::approval — shared with the SSH agent.

async fn dispatch(request: &Request, state: &SharedState, peer_pid: Option<u32>) -> Response {
    let id = request.id;

    // Unified access approval gate — all vault operations require approval.
    // This is the single security check for both CLI and SSH agent paths.
    if requires_approval(&request.method) {
        // Reset inactivity timer on every vault operation (for auto-lock)
        state.write().await.touch();

        let prompt_method = {
            let s = state.read().await;

            // Must be unlocked
            if s.vault_state != VaultState::Unlocked {
                return Response::error(id, RpcError::vault_locked());
            }

            s.prompt_method.clone()
        };

        // Access approval is always required — not configurable.
        let scope_key = resolve_scope_key(peer_pid);
        let already_approved = state.read().await.approval_cache.is_approved(scope_key);

        if !already_approved {
            tracing::info!(scope_key, "Access approval required, prompting user");

            if crate::approval::attempt_approval(state, &prompt_method, peer_pid).await {
                // Approval granted and cached by attempt_approval
            } else {
                // Check if vault was locked by PIN exhaustion
                if state.read().await.vault_state != VaultState::Unlocked {
                    return Response::error(id, RpcError::vault_locked());
                }
                return Response::error(id, RpcError::access_approval_denied());
            }
        }
    }

    match request.method.as_str() {
        methods::AUTH_STATUS => handle_status(id, state).await,
        methods::AUTH_LOGIN => handle_login(id, &request.params, state).await,
        methods::AUTH_UNLOCK => handle_unlock(id, &request.params, state, peer_pid).await,
        methods::AUTH_LOCK => handle_lock(id, state).await,
        methods::AUTH_LOGOUT => handle_logout(id, state).await,
        methods::AUTH_SET_PIN => handle_set_pin(id, &request.params, state).await,
        methods::AUTH_AUTHORIZE => handle_authorize(id, &request.params, state, peer_pid).await,
        methods::VAULT_LIST => handle_vault_list(id, &request.params, state).await,
        methods::VAULT_GET => handle_vault_get(id, &request.params, state).await,
        methods::VAULT_TOTP => handle_vault_totp(id, &request.params, state).await,
        methods::VAULT_RESOLVE_REFS => handle_resolve_refs(id, &request.params, state).await,
        methods::SSH_LIST_KEYS => handle_ssh_list_keys(id, state).await,
        methods::SSH_SIGN => handle_ssh_sign(id, &request.params, state).await,
        methods::SYNC_TRIGGER => handle_sync_trigger(id, state).await,
        methods::SYNC_STATUS => handle_sync_status(id, state).await,
        _ => Response::error(id, RpcError::method_not_found(&request.method)),
    }
}

async fn handle_status(id: Option<u64>, state: &SharedState) -> Response {
    let s = state.read().await;
    let result = StatusResult {
        state: s.vault_state.to_string(),
        email: s.email.clone(),
        server_url: s.server_url.clone(),
        last_sync: s.last_sync.map(|t| t.to_rfc3339()),
        session_active: None,
        pin_set: if s.vault_state == VaultState::Unlocked {
            Some(s.pin_set())
        } else {
            None
        },
    };
    success_result(id, result)
}

async fn handle_login(
    id: Option<u64>,
    params: &Option<RequestParams>,
    state: &SharedState,
) -> Response {
    let Some(RequestParams::Login(LoginParams {
        email,
        password,
        server_url,
    })) = params
    else {
        return Response::error(id, RpcError::invalid_params("Expected {email}"));
    };

    // Enforce master password backoff
    {
        let s = state.read().await;
        let remaining = s.master_password_backoff_remaining();
        if remaining > 0 {
            return Response::error(
                id,
                RpcError::new(
                    1009,
                    format!("Too many attempts. Try again in {remaining}s"),
                ),
            );
        }
    }

    // Get password — either from params or by spawning the prompt agent
    let password = match password {
        Some(pw) => pw.clone(),
        None => {
            let prompt_method = state.read().await.prompt_method.clone();
            if prompt_method == PromptMethod::None {
                return Response::error(id, RpcError::prompt_unavailable());
            }
            match prompt::prompt_password(&prompt_method).await {
                Ok(Some(pw)) => pw,
                Ok(None) => {
                    return Response::error(id, RpcError::new(1010, "Login cancelled by user"));
                }
                Err(e) => {
                    return Response::error(id, RpcError::internal(e.to_string()));
                }
            }
        }
    };

    let mut s = state.write().await;
    match s.login(email.clone(), password, server_url.clone()).await {
        Ok(_) => {
            s.reset_password_attempts();
            success_result(id, OkResult { ok: true })
        }
        Err(SdkError::AuthFailed(msg)) => {
            s.record_password_failure();
            Response::error(id, RpcError::auth_failed(msg))
        }
        Err(e) => Response::error(id, sdk_err_to_rpc(e)),
    }
}

async fn handle_unlock(
    id: Option<u64>,
    params: &Option<RequestParams>,
    state: &SharedState,
    peer_pid: Option<u32>,
) -> Response {
    // Enforce master password backoff
    {
        let s = state.read().await;
        let remaining = s.master_password_backoff_remaining();
        if remaining > 0 {
            return Response::error(
                id,
                RpcError::new(
                    1009,
                    format!("Too many attempts. Try again in {remaining}s"),
                ),
            );
        }
    }

    // Get password — either from params or by spawning the prompt agent.
    // Either way, the user proves identity by entering the master password,
    // so we grant access approval on successful unlock.
    let password = match params {
        Some(RequestParams::Unlock(UnlockParams { password: Some(pw) })) => pw.clone(),
        _ => {
            // No password provided — try interactive prompt
            let prompt_method = state.read().await.prompt_method.clone();
            if prompt_method == PromptMethod::None {
                return Response::error(id, RpcError::prompt_unavailable());
            }
            match prompt::prompt_password(&prompt_method).await {
                Ok(Some(pw)) => pw,
                Ok(None) => {
                    return Response::error(id, RpcError::new(1010, "Unlock cancelled by user"));
                }
                Err(e) => {
                    return Response::error(id, RpcError::internal(e.to_string()));
                }
            }
        }
    };

    let mut s = state.write().await;
    match s.unlock(&password).await {
        Ok(()) => {
            s.reset_password_attempts();

            // Unlock always grants access approval — the user proved identity
            // by entering the correct master password (whether via CLI or GUI).
            let scope_key = resolve_scope_key(peer_pid);
            let duration = std::time::Duration::from_secs(APPROVAL_SECONDS);
            s.approval_cache.grant(scope_key, duration);
            tracing::info!(scope_key, "Access approved on unlock");

            drop(s); // Release write lock before sync

            // Sync immediately in the background so vault data is ready
            let sync_state = state.clone();
            tokio::spawn(async move {
                crate::sync_worker::sync_now(&sync_state).await;
            });

            success_result(id, OkResult { ok: true })
        }
        Err(SdkError::AuthFailed(msg)) => {
            s.record_password_failure();
            Response::error(id, RpcError::auth_failed(msg))
        }
        Err(e) => Response::error(id, sdk_err_to_rpc(e)),
    }
}

async fn handle_lock(id: Option<u64>, state: &SharedState) -> Response {
    let mut s = state.write().await;
    match s.lock().await {
        Ok(()) => success_result(id, OkResult { ok: true }),
        Err(e) => Response::error(id, sdk_err_to_rpc(e)),
    }
}

async fn handle_logout(id: Option<u64>, state: &SharedState) -> Response {
    let mut s = state.write().await;
    match s.logout().await {
        Ok(()) => success_result(id, OkResult { ok: true }),
        Err(e) => Response::error(id, sdk_err_to_rpc(e)),
    }
}

async fn handle_set_pin(
    id: Option<u64>,
    params: &Option<RequestParams>,
    state: &SharedState,
) -> Response {
    let Some(RequestParams::SetPin(SetPinParams { pin })) = params else {
        return Response::error(id, RpcError::invalid_params("Expected {pin}"));
    };

    let mut s = state.write().await;
    match s.set_pin(pin.clone()) {
        Ok(()) => success_result(id, OkResult { ok: true }),
        Err(e) => Response::error(id, sdk_err_to_rpc(e)),
    }
}

/// Authorize by verifying the master password. Intended for SSH/headless sessions
/// where the GUI prompt agent is unavailable. Verifies the password against the
/// server, then refreshes the session timer and grants scoped access approval.
async fn handle_authorize(
    id: Option<u64>,
    params: &Option<RequestParams>,
    state: &SharedState,
    peer_pid: Option<u32>,
) -> Response {
    // Extract password from UnlockParams (reused — same shape)
    let password = match params {
        Some(RequestParams::Unlock(UnlockParams { password: Some(pw) })) => pw.clone(),
        _ => {
            return Response::error(id, RpcError::invalid_params("Expected {password}"));
        }
    };

    // Must be unlocked
    {
        let s = state.read().await;
        if s.vault_state != VaultState::Unlocked {
            return Response::error(id, RpcError::vault_locked());
        }

        // Enforce master password backoff
        let remaining = s.master_password_backoff_remaining();
        if remaining > 0 {
            return Response::error(
                id,
                RpcError::new(
                    1009,
                    format!("Too many attempts. Try again in {remaining}s"),
                ),
            );
        }
    }

    // Verify against the server
    let result = {
        let s = state.read().await;
        s.verify_password(&password).await
    };

    match result {
        Ok(()) => {
            let mut s = state.write().await;
            s.reset_password_attempts();

            // Grant scoped access approval
            let scope_key = resolve_scope_key(peer_pid);
            let duration = std::time::Duration::from_secs(APPROVAL_SECONDS);
            s.approval_cache.grant(scope_key, duration);

            tracing::info!(scope_key, "Authorized via master password");
            success_result(id, OkResult { ok: true })
        }
        Err(SdkError::AuthFailed(msg)) => {
            state.write().await.record_password_failure();
            Response::error(id, RpcError::auth_failed(msg))
        }
        Err(e) => Response::error(id, sdk_err_to_rpc(e)),
    }
}

async fn handle_vault_list(
    id: Option<u64>,
    params: &Option<RequestParams>,
    state: &SharedState,
) -> Response {
    let filter = match params {
        Some(RequestParams::VaultList(VaultListParams { r#type, search })) => VaultFilter {
            cipher_type: r#type.as_deref().and_then(|t| t.parse().ok()),
            search: search.clone(),
        },
        _ => VaultFilter {
            cipher_type: None,
            search: None,
        },
    };

    let s = state.read().await;
    match s.vault_list(filter).await {
        Ok(items) => {
            let out: Vec<VaultItem> = items
                .into_iter()
                .map(|c| VaultItem {
                    id: c.id,
                    name: c.name,
                    r#type: c.cipher_type.to_string(),
                    username: c.username,
                    uri: c.uri,
                })
                .collect();
            success_result(id, out)
        }
        Err(e) => Response::error(id, sdk_err_to_rpc(e)),
    }
}

async fn handle_vault_get(
    id: Option<u64>,
    params: &Option<RequestParams>,
    state: &SharedState,
) -> Response {
    let Some(RequestParams::VaultGet(VaultGetParams { id: item_id, .. })) = params else {
        return Response::error(id, RpcError::invalid_params("Expected {id}"));
    };

    let s = state.read().await;
    match s.vault_get(item_id).await {
        Ok(detail) => {
            let out = VaultItemDetail {
                id: detail.id,
                name: detail.name,
                r#type: detail.cipher_type.to_string(),
                username: detail.username,
                password: detail.password,
                uri: detail.uri,
                notes: detail.notes,
                totp: detail.totp,
            };
            success_result(id, out)
        }
        Err(e) => Response::error(id, sdk_err_to_rpc(e)),
    }
}

async fn handle_vault_totp(
    id: Option<u64>,
    params: &Option<RequestParams>,
    state: &SharedState,
) -> Response {
    let Some(RequestParams::VaultTotp(VaultTotpParams { id: item_id })) = params else {
        return Response::error(id, RpcError::invalid_params("Expected {id}"));
    };

    let s = state.read().await;
    match s.vault_totp(item_id).await {
        Ok(code) => {
            let out = TotpResult { code, period: 30 };
            success_result(id, out)
        }
        Err(e) => Response::error(id, sdk_err_to_rpc(e)),
    }
}

async fn handle_resolve_refs(
    id: Option<u64>,
    params: &Option<RequestParams>,
    state: &SharedState,
) -> Response {
    let Some(RequestParams::ResolveRefs(ResolveRefsParams { refs })) = params else {
        return Response::error(id, RpcError::invalid_params("Expected {refs: [...]}"));
    };

    let s = state.read().await;
    let Some(sdk) = &s.sdk else {
        return Response::error(id, RpcError::not_logged_in());
    };

    // Get all ciphers once for resolving
    let all_items = match sdk
        .vault()
        .list(grimoire_sdk::vault::VaultFilter {
            cipher_type: None,
            search: None,
        })
        .await
    {
        Ok(items) => items,
        Err(e) => return Response::error(id, sdk_err_to_rpc(e)),
    };

    let mut results = Vec::with_capacity(refs.len());

    for vref in refs {
        let resolved = resolve_single_ref(sdk, &all_items, &vref.id, &vref.field).await;
        results.push(match resolved {
            Ok(value) => ResolvedRef {
                r#ref: format!("{}:{}/{}", "grimoire", vref.id, vref.field),
                value: Some(value),
                error: None,
            },
            Err(msg) => ResolvedRef {
                r#ref: format!("{}:{}/{}", "grimoire", vref.id, vref.field),
                value: None,
                error: Some(msg),
            },
        });
    }

    success_result(id, &results)
}

/// Resolve a single vault reference by ID prefix or name.
async fn resolve_single_ref(
    sdk: &grimoire_sdk::GrimoireClient,
    items: &[grimoire_sdk::vault::CipherSummary],
    ref_id: &str,
    field: &str,
) -> Result<String, String> {
    // Determine if this is a name lookup (//) or ID lookup
    let item_id = if let Some(name) = ref_id.strip_prefix("//") {
        let matches: Vec<_> = items.iter().filter(|i| i.name == name).collect();
        match matches.len() {
            0 => return Err(format!("No item named '{name}'")),
            1 => matches[0].id.clone(),
            n => {
                return Err(format!(
                    "Ambiguous name '{name}' matches {n} items — use ID instead"
                ))
            }
        }
    } else {
        // ID prefix match
        let matches: Vec<_> = items.iter().filter(|i| i.id.starts_with(ref_id)).collect();
        match matches.len() {
            0 => return Err(format!("No item matching ID prefix '{ref_id}'")),
            1 => matches[0].id.clone(),
            n => return Err(format!("Ambiguous ID prefix '{ref_id}' matches {n} items")),
        }
    };

    // Get full item detail
    let detail = sdk
        .vault()
        .get(&item_id)
        .await
        .map_err(|e| format!("Failed to get item: {e}"))?;

    // Extract the requested field
    match field {
        "password" | "pw" => detail.password.ok_or_else(|| "No password field".into()),
        "username" | "user" => detail.username.ok_or_else(|| "No username field".into()),
        "uri" | "url" => detail.uri.ok_or_else(|| "No URI field".into()),
        "notes" | "note" => detail.notes.ok_or_else(|| "No notes field".into()),
        "name" => Ok(detail.name),
        "totp" => sdk
            .vault()
            .totp(&item_id)
            .await
            .map_err(|e| format!("TOTP failed: {e}")),
        other => Err(format!("Unknown field '{other}'")),
    }
}

async fn handle_ssh_list_keys(id: Option<u64>, state: &SharedState) -> Response {
    let s = state.read().await;
    let Some(sdk) = &s.sdk else {
        return Response::error(id, RpcError::not_logged_in());
    };

    match sdk.ssh().list_keys().await {
        Ok(keys) => {
            let out: Vec<SshKeyInfo> = keys
                .into_iter()
                .map(|k| SshKeyInfo {
                    id: k.id,
                    name: k.name,
                    public_key: k.public_key,
                    fingerprint: k.fingerprint,
                })
                .collect();
            success_result(id, out)
        }
        Err(e) => Response::error(id, sdk_err_to_rpc(e)),
    }
}

async fn handle_ssh_sign(
    id: Option<u64>,
    params: &Option<RequestParams>,
    state: &SharedState,
) -> Response {
    let Some(RequestParams::SshSign(SshSignParams {
        key_id,
        data,
        flags,
    })) = params
    else {
        return Response::error(
            id,
            RpcError::invalid_params("Expected {key_id, data, flags}"),
        );
    };

    let s = state.read().await;
    let Some(sdk) = &s.sdk else {
        return Response::error(id, RpcError::not_logged_in());
    };

    match sdk.ssh().sign(key_id, data, *flags).await {
        Ok(signature) => success_result(id, serde_json::json!({ "signature": signature })),
        Err(e) => Response::error(id, sdk_err_to_rpc(e)),
    }
}

async fn handle_sync_trigger(id: Option<u64>, state: &SharedState) -> Response {
    let sync_result = {
        let s = state.read().await;
        if s.vault_state != VaultState::Unlocked {
            return Response::error(id, RpcError::vault_locked());
        }
        let (Some(sdk), Some(server_url)) = (&s.sdk, &s.server_url) else {
            return Response::error(id, RpcError::not_logged_in());
        };
        sdk.sync().sync(server_url).await
    };

    match sync_result {
        Ok(()) => {
            let mut s = state.write().await;
            s.last_sync = Some(chrono::Utc::now());
            success_result(id, OkResult { ok: true })
        }
        Err(e) => Response::error(id, RpcError::new(1004, format!("Sync failed: {e}"))),
    }
}

async fn handle_sync_status(id: Option<u64>, state: &SharedState) -> Response {
    let s = state.read().await;
    let result = serde_json::json!({
        "last_sync": s.last_sync.map(|t| t.to_rfc3339()),
    });
    Response::success(id, result)
}

/// Build a success response, handling the (unlikely) serialization failure gracefully
/// instead of panicking. All response structs are simple `#[derive(Serialize)]` types
/// with primitive fields, so this should never fail in practice.
fn success_result<T: serde::Serialize>(id: Option<u64>, value: T) -> Response {
    match serde_json::to_value(value) {
        Ok(v) => Response::success(id, v),
        Err(e) => Response::error(id, RpcError::internal(format!("Serialization failed: {e}"))),
    }
}

fn sdk_err_to_rpc(e: SdkError) -> RpcError {
    match e {
        SdkError::VaultLocked => RpcError::vault_locked(),
        SdkError::NotLoggedIn => RpcError::not_logged_in(),
        SdkError::AuthFailed(msg) => RpcError::auth_failed(msg),
        SdkError::NotFound(id) => RpcError::item_not_found(&id),
        SdkError::SyncFailed(msg) => RpcError::new(1004, msg),
        SdkError::Internal(msg) => {
            // Log the detailed error server-side; return a generic message to the client
            // to avoid leaking filesystem paths, library errors, or other internal state.
            tracing::error!("Internal error: {msg}");
            RpcError::internal("Internal error")
        }
    }
}
