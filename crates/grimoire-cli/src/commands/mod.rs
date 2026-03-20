use anyhow::{bail, Result};
use grimoire_protocol::response::{Response, StatusResult, TotpResult, VaultItem, VaultItemDetail};

pub fn handle_status(response: Response, json: bool) -> Result<()> {
    check_error(&response)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&response.result)?);
        return Ok(());
    }

    let result: StatusResult = serde_json::from_value(response.result.unwrap())?;
    println!("State:  {}", result.state);
    if let Some(email) = &result.email {
        println!("Email:  {email}");
    }
    if let Some(url) = &result.server_url {
        println!("Server: {url}");
    }
    if let Some(sync) = &result.last_sync {
        println!("Synced: {sync}");
    }
    Ok(())
}

pub fn handle_login(response: Response, json: bool) -> Result<()> {
    check_error(&response)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&response.result)?);
    } else {
        println!("Logged in successfully. Vault is locked — run `grimoire unlock` to decrypt.");
    }
    Ok(())
}

pub fn handle_unlock(response: Response, json: bool) -> Result<()> {
    check_error(&response)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&response.result)?);
    } else {
        println!("Vault unlocked.");
    }
    Ok(())
}

pub fn handle_list(response: Response, json: bool) -> Result<()> {
    check_error(&response)?;
    let items: Vec<VaultItem> = serde_json::from_value(response.result.unwrap())?;

    if json {
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }

    if items.is_empty() {
        println!("No items found.");
        return Ok(());
    }

    for item in &items {
        let username = item.username.as_deref().unwrap_or("");
        println!("{:<36}  {:<8}  {}  {}", item.id, item.r#type, item.name, username);
    }
    Ok(())
}

pub fn handle_get(response: Response, json: bool, field: Option<&str>) -> Result<()> {
    check_error(&response)?;
    let detail: VaultItemDetail = serde_json::from_value(response.result.unwrap())?;

    if json {
        println!("{}", serde_json::to_string_pretty(&detail)?);
        return Ok(());
    }

    // Single-field output for piping (no label, no newline prefix)
    if let Some(field) = field {
        let value = match field {
            "password" | "pw" => detail.password.as_deref(),
            "username" | "user" => detail.username.as_deref(),
            "uri" | "url" => detail.uri.as_deref(),
            "notes" | "note" => detail.notes.as_deref(),
            "name" => Some(detail.name.as_str()),
            _ => {
                bail!("Unknown field: {field}. Use: password, username, uri, notes, name, totp");
            }
        };
        match value {
            Some(v) => println!("{v}"),
            None => bail!("Field '{field}' is empty for this item"),
        }
        return Ok(());
    }

    // Full output
    println!("Name:     {}", detail.name);
    println!("Type:     {}", detail.r#type);
    if let Some(u) = &detail.username {
        println!("Username: {u}");
    }
    if let Some(p) = &detail.password {
        println!("Password: {p}");
    }
    if let Some(u) = &detail.uri {
        println!("URI:      {u}");
    }
    if let Some(t) = &detail.totp {
        println!("TOTP key: {t}");
    }
    if let Some(n) = &detail.notes {
        println!("Notes:    {n}");
    }
    Ok(())
}

pub fn handle_totp(response: Response, json: bool) -> Result<()> {
    check_error(&response)?;
    let totp: TotpResult = serde_json::from_value(response.result.unwrap())?;

    if json {
        println!("{}", serde_json::to_string_pretty(&totp)?);
    } else {
        println!("{}", totp.code);
    }
    Ok(())
}

pub fn handle_authorize(response: Response, json: bool) -> Result<()> {
    check_error(&response)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&response.result)?);
    } else {
        println!("Authorized. Session refreshed and access approved.");
    }
    Ok(())
}

pub fn handle_sync(response: Response, json: bool) -> Result<()> {
    check_error(&response)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&response.result)?);
    } else {
        println!("Sync triggered.");
    }
    Ok(())
}

pub fn handle_lock(response: Response, json: bool) -> Result<()> {
    check_error(&response)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&response.result)?);
    } else {
        println!("Vault locked.");
    }
    Ok(())
}

pub fn handle_logout(response: Response, json: bool) -> Result<()> {
    check_error(&response)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&response.result)?);
    } else {
        println!("Logged out.");
    }
    Ok(())
}

pub fn check_error(response: &Response) -> Result<()> {
    if let Some(err) = &response.error {
        bail!("{}", err.message);
    }
    Ok(())
}
