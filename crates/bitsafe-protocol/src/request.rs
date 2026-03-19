use serde::{Deserialize, Serialize};

/// A JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<RequestParams>,
}

impl Request {
    pub fn new(id: u64, method: impl Into<String>, params: Option<RequestParams>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: Some(id),
            method: method.into(),
            params,
        }
    }
}

/// Parameters for JSON-RPC requests, keyed by method.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestParams {
    Login(LoginParams),
    Unlock(UnlockParams),
    SetPin(SetPinParams),
    VaultList(VaultListParams),
    VaultGet(VaultGetParams),
    VaultTotp(VaultTotpParams),
    ResolveRefs(ResolveRefsParams),
    SshSign(SshSignParams),
    Empty(EmptyParams),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginParams {
    pub email: String,
    /// If omitted, the service will spawn the prompt agent to ask interactively.
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub server_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlockParams {
    /// If omitted, the service will spawn the prompt agent to ask interactively.
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetPinParams {
    pub pin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultListParams {
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub search: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultGetParams {
    pub id: String,
    #[serde(default)]
    pub field: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultTotpParams {
    pub id: String,
}

/// A single vault reference to resolve.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRef {
    /// Item ID (full UUID or prefix, minimum 6 chars) or name (if prefixed with //)
    pub id: String,
    /// Field to extract: password, username, uri, notes, totp, name
    pub field: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveRefsParams {
    pub refs: Vec<VaultRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshSignParams {
    pub key_id: String,
    pub data: Vec<u8>,
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyParams {}

/// Helper to build requests for each method.
pub mod methods {
    pub const AUTH_LOGIN: &str = "auth.login";
    pub const AUTH_UNLOCK: &str = "auth.unlock";
    pub const AUTH_LOCK: &str = "auth.lock";
    pub const AUTH_LOGOUT: &str = "auth.logout";
    pub const AUTH_STATUS: &str = "auth.status";
    pub const VAULT_LIST: &str = "vault.list";
    pub const VAULT_GET: &str = "vault.get";
    pub const VAULT_TOTP: &str = "vault.totp";
    pub const VAULT_RESOLVE_REFS: &str = "vault.resolve_refs";
    pub const SYNC_TRIGGER: &str = "sync.trigger";
    pub const SYNC_STATUS: &str = "sync.status";
    pub const AUTH_SET_PIN: &str = "auth.set_pin";
    pub const AUTH_VERIFY: &str = "auth.verify";
    pub const SSH_LIST_KEYS: &str = "ssh.list_keys";
    pub const AUTH_AUTHORIZE: &str = "auth.authorize";
    pub const SSH_SIGN: &str = "ssh.sign";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_login_params() {
        let json = r#"{"email":"user@test.com","password":"secret","server_url":"https://vault.example.com"}"#;
        let params: RequestParams = serde_json::from_str(json).unwrap();
        assert!(matches!(params, RequestParams::Login(LoginParams { ref email, .. }) if email == "user@test.com"));
    }

    #[test]
    fn deserialize_login_params_password_optional() {
        let json = r#"{"email":"user@test.com"}"#;
        let params: RequestParams = serde_json::from_str(json).unwrap();
        match params {
            RequestParams::Login(lp) => {
                assert_eq!(lp.email, "user@test.com");
                assert!(lp.password.is_none());
            }
            _ => panic!("Expected Login"),
        }
    }

    #[test]
    fn deserialize_unlock_params_with_password() {
        let json = r#"{"password":"secret"}"#;
        let params: RequestParams = serde_json::from_str(json).unwrap();
        match params {
            RequestParams::Unlock(up) => assert_eq!(up.password, Some("secret".into())),
            _ => panic!("Expected Unlock"),
        }
    }

    #[test]
    fn deserialize_unlock_params_empty() {
        // Empty object should match UnlockParams (password defaults to None)
        let json = r#"{}"#;
        let params: RequestParams = serde_json::from_str(json).unwrap();
        match params {
            RequestParams::Unlock(up) => assert!(up.password.is_none()),
            _ => panic!("Expected Unlock, got {params:?}"),
        }
    }

    #[test]
    fn deserialize_vault_get_not_confused_with_unlock() {
        // This was a real bug — VaultGetParams has {id} which previously matched
        // UnlockParams (password defaulted to None, extra fields ignored).
        // deny_unknown_fields on UnlockParams prevents this.
        let json = r#"{"id":"some-uuid"}"#;
        let params: RequestParams = serde_json::from_str(json).unwrap();
        match params {
            RequestParams::VaultGet(vg) => assert_eq!(vg.id, "some-uuid"),
            other => panic!("Expected VaultGet, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_vault_get_with_field() {
        let json = r#"{"id":"some-uuid","field":"password"}"#;
        let params: RequestParams = serde_json::from_str(json).unwrap();
        match params {
            RequestParams::VaultGet(vg) => {
                assert_eq!(vg.id, "some-uuid");
                assert_eq!(vg.field, Some("password".into()));
            }
            _ => panic!("Expected VaultGet"),
        }
    }

    #[test]
    fn deserialize_vault_totp() {
        let json = r#"{"id":"totp-uuid"}"#;
        // This should match VaultGet (which comes before VaultTotp in enum order)
        // because VaultGet also has a required `id` field.
        // VaultTotp is only reached through method dispatch, not param parsing.
        let params: RequestParams = serde_json::from_str(json).unwrap();
        assert!(matches!(params, RequestParams::VaultGet(_) | RequestParams::VaultTotp(_)));
    }

    #[test]
    fn deserialize_set_pin() {
        let json = r#"{"pin":"1234"}"#;
        let params: RequestParams = serde_json::from_str(json).unwrap();
        match params {
            RequestParams::SetPin(sp) => assert_eq!(sp.pin, "1234"),
            _ => panic!("Expected SetPin"),
        }
    }

    #[test]
    fn request_roundtrip() {
        let req = Request::new(42, "vault.list", Some(RequestParams::VaultList(VaultListParams {
            r#type: Some("login".into()),
            search: None,
        })));
        let json = serde_json::to_string(&req).unwrap();
        let decoded: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, Some(42));
        assert_eq!(decoded.method, "vault.list");
    }
}
