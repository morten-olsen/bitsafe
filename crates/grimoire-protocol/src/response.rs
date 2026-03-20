use serde::{Deserialize, Serialize};

/// A JSON-RPC 2.0 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: String,
    pub id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl Response {
    pub fn success(id: Option<u64>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Option<u64>, error: RpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl RpcError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn method_not_found(method: &str) -> Self {
        Self::new(-32601, format!("Method not found: {method}"))
    }

    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self::new(-32602, msg)
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(-32603, msg)
    }

    pub fn vault_locked() -> Self {
        Self::new(1000, "Vault is locked")
    }

    pub fn not_logged_in() -> Self {
        Self::new(1001, "Not logged in")
    }

    pub fn already_logged_in() -> Self {
        Self::new(1002, "Already logged in")
    }

    pub fn auth_failed(msg: impl Into<String>) -> Self {
        Self::new(1003, msg)
    }

    pub fn item_not_found(id: &str) -> Self {
        Self::new(1005, format!("Item not found: {id}"))
    }

    pub fn session_expired() -> Self {
        Self::new(1006, "Session expired — re-verification required")
    }

    pub fn verification_failed(msg: impl Into<String>) -> Self {
        Self::new(1007, msg)
    }

    pub fn prompt_unavailable() -> Self {
        Self::new(1008, "No interactive prompt available — provide password in params")
    }

    pub fn access_approval_denied() -> Self {
        Self::new(1011, "Access approval denied")
    }
}

/// Convenience type for responses carrying typed data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseResult {
    Status(StatusResult),
    VaultList(Vec<VaultItem>),
    VaultItem(VaultItemDetail),
    SshKeys(Vec<SshKeyInfo>),
    Ok(OkResult),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResult {
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sync: Option<String>,
    /// Whether the session is currently active (not expired).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_active: Option<bool>,
    /// Whether a PIN has been set for re-verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_set: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub id: String,
    pub name: String,
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItemDetail {
    pub id: String,
    pub name: String,
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyInfo {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedRef {
    pub r#ref: String,
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpResult {
    pub code: String,
    pub period: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OkResult {
    pub ok: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_response_has_no_error() {
        let resp = Response::success(Some(1), serde_json::json!({"ok": true}));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("result"));
        assert!(!json.contains("error"));
    }

    #[test]
    fn error_response_has_no_result() {
        let resp = Response::error(Some(1), RpcError::vault_locked());
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("error"));
        assert!(!json.contains("result"));
    }

    #[test]
    fn status_result_omits_none_fields() {
        let status = StatusResult {
            state: "locked".into(),
            email: Some("user@test.com".into()),
            server_url: None,
            last_sync: None,
            session_active: None,
            pin_set: None,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("email"));
        assert!(!json.contains("server_url"));
        assert!(!json.contains("last_sync"));
        assert!(!json.contains("session_active"));
    }

    #[test]
    fn error_codes() {
        assert_eq!(RpcError::vault_locked().code, 1000);
        assert_eq!(RpcError::not_logged_in().code, 1001);
        assert_eq!(RpcError::already_logged_in().code, 1002);
        assert_eq!(RpcError::auth_failed("bad").code, 1003);
        assert_eq!(RpcError::item_not_found("x").code, 1005);
        assert_eq!(RpcError::session_expired().code, 1006);
        assert_eq!(RpcError::prompt_unavailable().code, 1008);
    }

    #[test]
    fn response_roundtrip() {
        let resp = Response::success(Some(5), serde_json::json!({"items": []}));
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, Some(5));
        assert!(decoded.result.is_some());
        assert!(decoded.error.is_none());
    }
}
