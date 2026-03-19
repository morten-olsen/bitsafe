use crate::error::SdkError;
use bitwarden_pm::PasswordManagerClient;
use bitwarden_vault::CipherListViewType;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

/// The type of a vault item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CipherType {
    Login,
    SecureNote,
    Card,
    Identity,
    SshKey,
}

impl std::fmt::Display for CipherType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Login => write!(f, "login"),
            Self::SecureNote => write!(f, "note"),
            Self::Card => write!(f, "card"),
            Self::Identity => write!(f, "identity"),
            Self::SshKey => write!(f, "sshkey"),
        }
    }
}

impl std::str::FromStr for CipherType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "login" => Ok(Self::Login),
            "note" | "securenote" => Ok(Self::SecureNote),
            "card" => Ok(Self::Card),
            "identity" => Ok(Self::Identity),
            "sshkey" | "ssh_key" => Ok(Self::SshKey),
            _ => Err(format!("Unknown cipher type: {s}")),
        }
    }
}

/// A summary of a vault item (for listing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherSummary {
    pub id: String,
    pub name: String,
    pub cipher_type: CipherType,
    pub username: Option<String>,
    pub uri: Option<String>,
}

/// Full details of a vault item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherDetail {
    pub id: String,
    pub name: String,
    pub cipher_type: CipherType,
    pub username: Option<String>,
    pub password: Option<String>,
    pub uri: Option<String>,
    pub notes: Option<String>,
    pub totp: Option<String>,
}

/// Filter criteria for listing vault items.
pub struct VaultFilter {
    pub cipher_type: Option<CipherType>,
    pub search: Option<String>,
}

fn map_list_view_type(t: &CipherListViewType) -> CipherType {
    match t {
        CipherListViewType::Login(_) => CipherType::Login,
        CipherListViewType::SecureNote => CipherType::SecureNote,
        CipherListViewType::Card(_) => CipherType::Card,
        CipherListViewType::Identity => CipherType::Identity,
        CipherListViewType::SshKey => CipherType::SshKey,
    }
}

fn map_cipher_type(ct: bitwarden_vault::CipherType) -> CipherType {
    match ct {
        bitwarden_vault::CipherType::Login => CipherType::Login,
        bitwarden_vault::CipherType::SecureNote => CipherType::SecureNote,
        bitwarden_vault::CipherType::Card => CipherType::Card,
        bitwarden_vault::CipherType::Identity => CipherType::Identity,
        bitwarden_vault::CipherType::SshKey => CipherType::SshKey,
    }
}

pub struct VaultClient {
    pub(crate) client: Arc<Mutex<PasswordManagerClient>>,
}

impl VaultClient {
    pub fn new() -> Self {
        Self {
            client: Arc::new(Mutex::new(PasswordManagerClient::new(None))),
        }
    }

    /// List vault items, optionally filtered.
    pub async fn list(&self, filter: VaultFilter) -> Result<Vec<CipherSummary>, SdkError> {
        let pm = self.client.lock().await;
        let result = pm
            .vault()
            .ciphers()
            .list()
            .await
            .map_err(|e| SdkError::Internal(format!("Failed to list ciphers: {e}")))?;

        let mut items: Vec<CipherSummary> = result
            .successes
            .into_iter()
            .map(|c| {
                let ct = map_list_view_type(&c.r#type);
                CipherSummary {
                    id: c.id.map(|id| id.to_string()).unwrap_or_default(),
                    name: c.name,
                    cipher_type: ct,
                    username: Some(c.subtitle).filter(|s| !s.is_empty()),
                    uri: None, // CipherListView doesn't include URIs
                }
            })
            .collect();

        // Apply filters
        if let Some(ref type_filter) = filter.cipher_type {
            items.retain(|c| c.cipher_type == *type_filter);
        }
        if let Some(ref search) = filter.search {
            let q = search.to_lowercase();
            items.retain(|c| {
                c.name.to_lowercase().contains(&q)
                    || c.username.as_deref().is_some_and(|u| u.to_lowercase().contains(&q))
            });
        }

        Ok(items)
    }

    /// Get full details of a single vault item.
    pub async fn get(&self, id: &str) -> Result<CipherDetail, SdkError> {
        let pm = self.client.lock().await;
        let view: bitwarden_vault::CipherView = pm
            .vault()
            .ciphers()
            .get(id)
            .await
            .map_err(|e| SdkError::NotFound(format!("{e}")))?;

        let ct = map_cipher_type(view.r#type);
        let (username, password, uri, totp) = if let Some(ref login) = view.login {
            (
                login.username.clone(),
                login.password.clone(),
                login
                    .uris
                    .as_ref()
                    .and_then(|uris| uris.first())
                    .and_then(|u| u.uri.clone()),
                login.totp.clone(),
            )
        } else {
            (None, None, None, None)
        };

        Ok(CipherDetail {
            id: view.id.map(|id| id.to_string()).unwrap_or_default(),
            name: view.name,
            cipher_type: ct,
            username,
            password,
            uri,
            notes: view.notes,
            totp,
        })
    }

    /// Generate a TOTP code for a vault item.
    pub async fn totp(&self, id: &str) -> Result<String, SdkError> {
        let pm = self.client.lock().await;

        let view: bitwarden_vault::CipherView = pm
            .vault()
            .ciphers()
            .get(id)
            .await
            .map_err(|e| SdkError::NotFound(format!("{e}")))?;

        let totp_key = view
            .login
            .as_ref()
            .and_then(|l| l.totp.as_ref())
            .ok_or_else(|| SdkError::NotFound("No TOTP key for this item".into()))?;

        let response = pm
            .vault()
            .totp()
            .generate_totp(totp_key.clone(), None)
            .map_err(|e| SdkError::Internal(format!("TOTP generation failed: {e}")))?;

        Ok(response.code)
    }
}
