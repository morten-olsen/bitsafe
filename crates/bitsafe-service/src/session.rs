use bitsafe_common::config::PromptMethod;
use bitsafe_protocol::codec::{handshake_server, read_message, write_message};
use bitsafe_protocol::request::{
    methods, LoginParams, ResolveRefsParams, Request, RequestParams, SetPinParams, SshSignParams,
    UnlockParams, VaultGetParams, VaultListParams, VaultTotpParams,
};
use bitsafe_protocol::response::{
    OkResult, ResolvedRef, Response, RpcError, SshKeyInfo, StatusResult, TotpResult, VaultItem,
    VaultItemDetail,
};
use bitsafe_sdk::vault::VaultFilter;
use bitsafe_sdk::SdkError;
use tokio::net::UnixStream;

use crate::prompt;
use crate::state::{SharedState, VaultState};

/// Handle a single client connection.
pub async fn handle_client(stream: UnixStream, state: SharedState, peer_pid: Option<u32>) {
    let (mut reader, mut writer) = stream.into_split();

    // X25519 key exchange — establish encrypted channel
    let codec = match handshake_server(&mut reader, &mut writer).await {
        Ok(c) => c,
        Err(bitsafe_protocol::codec::CodecError::ConnectionClosed) => {
            tracing::debug!("Client disconnected during handshake");
            return;
        }
        Err(e) => {
            tracing::warn!("Handshake failed: {e}");
            return;
        }
    };

    loop {
        let request: Request = match read_message(&mut reader, &codec).await {
            Ok(req) => req,
            Err(bitsafe_protocol::codec::CodecError::ConnectionClosed) => {
                tracing::debug!("Client disconnected");
                return;
            }
            Err(e) => {
                tracing::warn!("Failed to read request: {e}");
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

/// Resolve the scope key for the approval cache based on the configured scope.
pub(crate) fn resolve_scope_key(scope: &bitsafe_common::config::ApprovalScope, peer_pid: Option<u32>) -> u32 {
    use bitsafe_common::config::ApprovalScope;
    match scope {
        ApprovalScope::Session => {
            // Walk to session leader PID; fall back to peer PID
            peer_pid
                .and_then(crate::peer::get_session_leader)
                .or(peer_pid)
                .unwrap_or(0)
        }
        ApprovalScope::Pid => peer_pid.unwrap_or(0),
        ApprovalScope::Connection => 0, // Always 0 = never matches cached grant = always prompt
    }
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

/// Attempt approval via prompt — biometric, then PIN, then password dialog.
/// Returns true if the user was approved, false if denied or cancelled.
/// On PIN exhaustion, auto-locks the vault and returns false.
async fn attempt_approval(
    state: &SharedState,
    prompt_method: &PromptMethod,
) -> bool {
    // Check PIN exhaustion — too many failures → auto-lock
    {
        let s = state.read().await;
        if s.pin_attempts_exceeded() {
            tracing::info!("PIN attempts exceeded, locking vault");
            drop(s);
            let mut s = state.write().await;
            let _ = s.lock().await;
            return false;
        }
    }

    // Try biometric first
    if *prompt_method != PromptMethod::Terminal {
        match prompt::prompt_biometric(prompt_method, "BitSafe: approve vault access").await {
            Ok(true) => return true,
            Ok(false) => {} // Cancelled or unavailable, fall through
            Err(e) => {
                tracing::debug!("Biometric unavailable: {e}");
            }
        }
    }

    // Try PIN if set
    let has_pin = state.read().await.pin_set();
    if has_pin {
        let (attempt, pin_max) = {
            let s = state.read().await;
            (
                s.session.as_ref().map(|s| s.pin_attempts + 1).unwrap_or(1),
                s.session_config.pin_max_attempts,
            )
        };
        match prompt::prompt_pin(prompt_method, attempt, pin_max).await {
            Ok(Some(pin)) => {
                let mut s = state.write().await;
                if s.verify_pin(&pin) {
                    return true;
                }
                // PIN failed — check if now exceeded
                if s.pin_attempts_exceeded() {
                    tracing::info!("PIN attempts exceeded after failure, locking vault");
                    let _ = s.lock().await;
                }
                return false;
            }
            _ => return false, // Cancelled
        }
    }

    // No biometric, no PIN — fall back to password prompt (GUI dialog)
    match prompt::prompt_password(prompt_method).await {
        Ok(Some(_)) => true,
        _ => false,
    }
}

async fn dispatch(request: &Request, state: &SharedState, peer_pid: Option<u32>) -> Response {
    let id = request.id;

    // Unified access approval gate — all vault operations require approval.
    // This is the single security check for both CLI and SSH agent paths.
    if requires_approval(&request.method) {
        // Reset inactivity timer on every vault operation (for auto-lock)
        state.write().await.touch();

        let (require_approval, approval_seconds, approval_scope, prompt_method) = {
            let s = state.read().await;

            // Must be unlocked
            if s.vault_state != VaultState::Unlocked {
                return Response::error(id, RpcError::vault_locked());
            }

            (
                s.access_config.require_approval,
                s.access_config.approval_seconds,
                s.access_config.approval_for.clone(),
                s.prompt_method.clone(),
            )
        };

        if require_approval {
            let scope_key = resolve_scope_key(&approval_scope, peer_pid);
            let already_approved = state.read().await.approval_cache.is_approved(scope_key);

            if !already_approved {
                tracing::info!(scope_key, "Access approval required, prompting user");

                if attempt_approval(state, &prompt_method).await {
                    let duration = std::time::Duration::from_secs(approval_seconds);
                    state.write().await.approval_cache.grant(scope_key, duration);
                    tracing::info!(scope_key, "Access approved");
                } else {
                    // Check if vault was locked by PIN exhaustion
                    if state.read().await.vault_state != VaultState::Unlocked {
                        return Response::error(id, RpcError::vault_locked());
                    }
                    return Response::error(id, RpcError::access_approval_denied());
                }
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
    Response::success(id, serde_json::to_value(result).unwrap())
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
                RpcError::new(1009, format!("Too many attempts. Try again in {remaining}s")),
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
    match s
        .login(email.clone(), password, server_url.clone())
        .await
    {
        Ok(_) => {
            s.reset_password_attempts();
            Response::success(id, serde_json::to_value(OkResult { ok: true }).unwrap())
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
                RpcError::new(1009, format!("Too many attempts. Try again in {remaining}s")),
            );
        }
    }

    // Track whether password was provided directly (not via GUI prompt).
    // Direct password entry proves identity, so we also grant access approval.
    let password_direct = matches!(
        params,
        Some(RequestParams::Unlock(UnlockParams { password: Some(_) }))
    );

    // Get password — either from params or by spawning the prompt agent
    let password = match params {
        Some(RequestParams::Unlock(UnlockParams {
            password: Some(pw),
        })) => pw.clone(),
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

            // When the password was provided directly (CLI/SSH), also grant
            // access approval — the user already proved identity.
            if password_direct {
                let scope_key = resolve_scope_key(&s.access_config.approval_for, peer_pid);
                let duration = std::time::Duration::from_secs(s.access_config.approval_seconds);
                s.approval_cache.grant(scope_key, duration);
                tracing::info!(scope_key, "Access approved on unlock (direct password)");
            }

            drop(s); // Release write lock before sync

            // Sync immediately in the background so vault data is ready
            let sync_state = state.clone();
            tokio::spawn(async move {
                crate::sync_worker::sync_now(&sync_state).await;
            });

            Response::success(id, serde_json::to_value(OkResult { ok: true }).unwrap())
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
        Ok(()) => Response::success(id, serde_json::to_value(OkResult { ok: true }).unwrap()),
        Err(e) => Response::error(id, sdk_err_to_rpc(e)),
    }
}

async fn handle_logout(id: Option<u64>, state: &SharedState) -> Response {
    let mut s = state.write().await;
    match s.logout().await {
        Ok(()) => Response::success(id, serde_json::to_value(OkResult { ok: true }).unwrap()),
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
        Ok(()) => Response::success(id, serde_json::to_value(OkResult { ok: true }).unwrap()),
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
        Some(RequestParams::Unlock(UnlockParams {
            password: Some(pw),
        })) => pw.clone(),
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
                RpcError::new(1009, format!("Too many attempts. Try again in {remaining}s")),
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
            let scope_key = resolve_scope_key(&s.access_config.approval_for, peer_pid);
            let duration = std::time::Duration::from_secs(s.access_config.approval_seconds);
            s.approval_cache.grant(scope_key, duration);

            tracing::info!(scope_key, "Authorized via master password");
            Response::success(id, serde_json::to_value(OkResult { ok: true }).unwrap())
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
            Response::success(id, serde_json::to_value(out).unwrap())
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
            Response::success(id, serde_json::to_value(out).unwrap())
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
            Response::success(id, serde_json::to_value(out).unwrap())
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
    let all_items = match sdk.vault().list(bitsafe_sdk::vault::VaultFilter {
        cipher_type: None,
        search: None,
    }).await {
        Ok(items) => items,
        Err(e) => return Response::error(id, sdk_err_to_rpc(e)),
    };

    let mut results = Vec::with_capacity(refs.len());

    for vref in refs {
        let resolved = resolve_single_ref(sdk, &all_items, &vref.id, &vref.field).await;
        results.push(match resolved {
            Ok(value) => ResolvedRef {
                r#ref: format!("{}:{}/{}", "bitsafe", vref.id, vref.field),
                value: Some(value),
                error: None,
            },
            Err(msg) => ResolvedRef {
                r#ref: format!("{}:{}/{}", "bitsafe", vref.id, vref.field),
                value: None,
                error: Some(msg),
            },
        });
    }

    Response::success(id, serde_json::to_value(&results).unwrap())
}

/// Resolve a single vault reference by ID prefix or name.
async fn resolve_single_ref(
    sdk: &bitsafe_sdk::BitsafeClient,
    items: &[bitsafe_sdk::vault::CipherSummary],
    ref_id: &str,
    field: &str,
) -> Result<String, String> {
    // Determine if this is a name lookup (//) or ID lookup
    let item_id = if ref_id.starts_with("//") {
        let name = &ref_id[2..];
        let matches: Vec<_> = items.iter().filter(|i| i.name == name).collect();
        match matches.len() {
            0 => return Err(format!("No item named '{name}'")),
            1 => matches[0].id.clone(),
            n => return Err(format!("Ambiguous name '{name}' matches {n} items — use ID instead")),
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
            Response::success(id, serde_json::to_value(out).unwrap())
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
        return Response::error(id, RpcError::invalid_params("Expected {key_id, data, flags}"));
    };

    let s = state.read().await;
    let Some(sdk) = &s.sdk else {
        return Response::error(id, RpcError::not_logged_in());
    };

    match sdk.ssh().sign(key_id, data, *flags).await {
        Ok(signature) => {
            Response::success(id, serde_json::to_value(serde_json::json!({ "signature": signature })).unwrap())
        }
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
            Response::success(id, serde_json::to_value(OkResult { ok: true }).unwrap())
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

fn sdk_err_to_rpc(e: SdkError) -> RpcError {
    match e {
        SdkError::VaultLocked => RpcError::vault_locked(),
        SdkError::NotLoggedIn => RpcError::not_logged_in(),
        SdkError::AuthFailed(msg) => RpcError::auth_failed(msg),
        SdkError::NotFound(id) => RpcError::item_not_found(&id),
        SdkError::SyncFailed(msg) => RpcError::new(1004, msg),
        SdkError::Internal(msg) => RpcError::internal(msg),
    }
}
