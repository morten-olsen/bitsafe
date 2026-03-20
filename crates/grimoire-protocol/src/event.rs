use serde::{Deserialize, Serialize};

/// Server-push notifications (JSON-RPC notifications without an `id`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

impl Notification {
    pub fn new(method: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.into(),
            params: None,
        }
    }

    pub fn vault_locked() -> Self {
        Self::new("vault.locked")
    }

    pub fn vault_synced(timestamp: &str) -> Self {
        let mut n = Self::new("vault.synced");
        n.params = Some(serde_json::json!({ "timestamp": timestamp }));
        n
    }
}
