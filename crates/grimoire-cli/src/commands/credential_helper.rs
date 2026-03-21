use anyhow::{bail, Context, Result};
use std::io::BufRead;

/// A parsed git credential request.
#[derive(Debug, Default)]
pub struct CredentialRequest {
    pub protocol: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub username: Option<String>,
}

/// Parse git credential helper protocol from stdin.
/// Format: key=value lines, terminated by a blank line.
pub fn parse_credential_request<R: BufRead>(reader: R) -> Result<CredentialRequest> {
    let mut req = CredentialRequest::default();

    for line in reader.lines() {
        let line = line.context("Failed to read stdin")?;
        if line.is_empty() {
            break;
        }
        let (key, value) = line
            .split_once('=')
            .context("Invalid credential line (missing '=' delimiter)")?;
        match key {
            "protocol" => req.protocol = Some(value.to_string()),
            "host" => req.host = Some(value.to_string()),
            "path" => req.path = Some(value.to_string()),
            "username" => req.username = Some(value.to_string()),
            // Ignore unknown keys (git may add new ones)
            _ => {}
        }
    }

    Ok(req)
}

/// Format a git credential response to stdout.
pub fn write_credential_response(protocol: &str, host: &str, username: &str, password: &str) {
    println!("protocol={protocol}");
    println!("host={host}");
    println!("username={username}");
    println!("password={password}");
    println!();
}

/// Match priority for URI matching.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum MatchPriority {
    HostOnly = 1,
    HostAndPathPrefix = 2,
    Exact = 3,
}

/// Result of matching a vault item URI against a credential request.
struct UriMatch {
    priority: MatchPriority,
    item_id: String,
}

/// Normalize a path for comparison: strip leading/trailing slashes and .git suffix.
fn normalize_path(path: &str) -> &str {
    let path = path.strip_prefix('/').unwrap_or(path);
    let path = path.strip_suffix('/').unwrap_or(path);
    let path = path.strip_suffix(".git").unwrap_or(path);
    path.strip_suffix('/').unwrap_or(path)
}

/// Extract host and path from a URI string.
/// Handles formats like "https://github.com/alice/repo" or "github.com/alice/repo".
fn parse_uri(uri: &str) -> Option<(String, Option<String>)> {
    // Try to parse as a full URL first
    if let Some(rest) = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
    {
        let (host, path) = match rest.find('/') {
            Some(pos) => (&rest[..pos], Some(rest[pos + 1..].to_string())),
            None => (rest, None),
        };
        // Strip port from host
        let host = host.split(':').next().unwrap_or(host);
        return Some((host.to_lowercase(), path));
    }

    // Try bare host/path format
    if !uri.contains(' ') && !uri.is_empty() {
        let (host, path) = match uri.find('/') {
            Some(pos) => (&uri[..pos], Some(uri[pos + 1..].to_string())),
            None => (uri, None),
        };
        let host = host.split(':').next().unwrap_or(host);
        return Some((host.to_lowercase(), path));
    }

    None
}

/// Match vault items against a git credential request.
/// Returns the matched item IDs sorted by priority.
pub fn match_vault_items(
    request_host: &str,
    request_path: Option<&str>,
    items: &[(String, Option<String>)], // (item_id, item_uri)
) -> Result<Option<String>> {
    let request_host = request_host.to_lowercase();
    // Strip port from request host
    let request_host = request_host.split(':').next().unwrap_or(&request_host);

    let mut matches: Vec<UriMatch> = Vec::new();

    for (item_id, item_uri) in items {
        let Some(uri) = item_uri.as_deref() else {
            continue;
        };

        let Some((item_host, item_path)) = parse_uri(uri) else {
            continue;
        };

        // Host must match
        if item_host != request_host {
            continue;
        }

        // Determine match priority
        let priority = match (&item_path, request_path) {
            (Some(item_p), Some(req_p)) => {
                let norm_item = normalize_path(item_p);
                let norm_req = normalize_path(req_p);
                if norm_item == norm_req {
                    MatchPriority::Exact
                } else if norm_req.starts_with(norm_item) {
                    MatchPriority::HostAndPathPrefix
                } else {
                    // Item has a path that doesn't match — skip
                    continue;
                }
            }
            (Some(_), None) => {
                // Item has a path but request doesn't — treat as host-only match
                // (git doesn't send path by default unless credential.useHttpPath is set)
                MatchPriority::HostOnly
            }
            (None, _) => MatchPriority::HostOnly,
        };

        matches.push(UriMatch {
            priority,
            item_id: item_id.clone(),
        });
    }

    if matches.is_empty() {
        return Ok(None);
    }

    // Find the highest priority level
    // Safe: matches is guaranteed non-empty (early return above)
    let Some(best_priority) = matches.iter().map(|m| &m.priority).max() else {
        return Ok(None);
    };

    // Filter to only the best matches
    let best: Vec<&UriMatch> = matches
        .iter()
        .filter(|m| &m.priority == best_priority)
        .collect();

    match best.len() {
        1 => Ok(Some(best[0].item_id.clone())),
        n => bail!(
            "Ambiguous: {n} vault items match at the same priority level. \
             Set more specific URIs on your vault items to disambiguate."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parse_credential_request_basic() {
        let input = "protocol=https\nhost=github.com\npath=alice/repo.git\n\n";
        let req = parse_credential_request(Cursor::new(input)).unwrap();
        assert_eq!(req.protocol.as_deref(), Some("https"));
        assert_eq!(req.host.as_deref(), Some("github.com"));
        assert_eq!(req.path.as_deref(), Some("alice/repo.git"));
    }

    #[test]
    fn parse_credential_request_no_path() {
        let input = "protocol=https\nhost=github.com\n\n";
        let req = parse_credential_request(Cursor::new(input)).unwrap();
        assert_eq!(req.host.as_deref(), Some("github.com"));
        assert!(req.path.is_none());
    }

    #[test]
    fn parse_credential_request_ignores_unknown_keys() {
        let input = "protocol=https\nhost=github.com\nfuture_key=value\n\n";
        let req = parse_credential_request(Cursor::new(input)).unwrap();
        assert_eq!(req.host.as_deref(), Some("github.com"));
    }

    #[test]
    fn normalize_path_strips_git_suffix() {
        assert_eq!(normalize_path("alice/repo.git"), "alice/repo");
        assert_eq!(normalize_path("alice/repo"), "alice/repo");
        assert_eq!(normalize_path("/alice/repo.git/"), "alice/repo");
    }

    #[test]
    fn parse_uri_full_url() {
        let (host, path) = parse_uri("https://github.com/alice/repo").unwrap();
        assert_eq!(host, "github.com");
        assert_eq!(path.as_deref(), Some("alice/repo"));
    }

    #[test]
    fn parse_uri_host_only() {
        let (host, path) = parse_uri("https://github.com").unwrap();
        assert_eq!(host, "github.com");
        assert!(path.is_none());
    }

    #[test]
    fn parse_uri_with_port() {
        let (host, path) = parse_uri("https://gitea.example.com:3000/org/repo").unwrap();
        assert_eq!(host, "gitea.example.com");
        assert_eq!(path.as_deref(), Some("org/repo"));
    }

    #[test]
    fn match_exact_uri() {
        let items = vec![
            ("id1".into(), Some("https://github.com/alice/repo".into())),
            ("id2".into(), Some("https://github.com/bob/repo".into())),
        ];
        let result = match_vault_items("github.com", Some("alice/repo.git"), &items).unwrap();
        assert_eq!(result.as_deref(), Some("id1"));
    }

    #[test]
    fn match_host_only_no_path() {
        let items = vec![("id1".into(), Some("https://github.com".into()))];
        let result = match_vault_items("github.com", None, &items).unwrap();
        assert_eq!(result.as_deref(), Some("id1"));
    }

    #[test]
    fn match_host_plus_path_prefix() {
        let items = vec![
            ("id1".into(), Some("https://github.com/alice".into())),
            ("id2".into(), Some("https://github.com/bob".into())),
        ];
        let result = match_vault_items("github.com", Some("alice/repo.git"), &items).unwrap();
        assert_eq!(result.as_deref(), Some("id1"));
    }

    #[test]
    fn match_prefers_exact_over_prefix() {
        let items = vec![
            ("id-prefix".into(), Some("https://github.com/alice".into())),
            (
                "id-exact".into(),
                Some("https://github.com/alice/repo".into()),
            ),
        ];
        let result = match_vault_items("github.com", Some("alice/repo"), &items).unwrap();
        assert_eq!(result.as_deref(), Some("id-exact"));
    }

    #[test]
    fn match_prefers_exact_over_host_only() {
        let items = vec![
            ("id-host".into(), Some("https://github.com".into())),
            (
                "id-exact".into(),
                Some("https://github.com/alice/repo".into()),
            ),
        ];
        let result = match_vault_items("github.com", Some("alice/repo"), &items).unwrap();
        assert_eq!(result.as_deref(), Some("id-exact"));
    }

    #[test]
    fn match_no_match() {
        let items = vec![("id1".into(), Some("https://gitlab.com".into()))];
        let result = match_vault_items("github.com", None, &items).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn match_skips_items_without_uri() {
        let items = vec![("id1".into(), None)];
        let result = match_vault_items("github.com", None, &items).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn match_ambiguous_errors() {
        let items = vec![
            ("id1".into(), Some("https://github.com".into())),
            ("id2".into(), Some("https://github.com".into())),
        ];
        let result = match_vault_items("github.com", None, &items);
        assert!(result.is_err());
    }

    #[test]
    fn match_different_host_no_match() {
        let items = vec![("id1".into(), Some("https://github.com/alice/repo".into()))];
        let result = match_vault_items("gitlab.com", Some("alice/repo"), &items).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn match_item_path_doesnt_match_request() {
        let items = vec![("id1".into(), Some("https://github.com/bob/other".into()))];
        let result = match_vault_items("github.com", Some("alice/repo"), &items).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn match_case_insensitive_host() {
        let items = vec![("id1".into(), Some("https://GitHub.COM".into()))];
        let result = match_vault_items("github.com", None, &items).unwrap();
        assert_eq!(result.as_deref(), Some("id1"));
    }

    #[test]
    fn parse_credential_request_with_username() {
        let input = "protocol=https\nhost=github.com\nusername=alice\n\n";
        let req = parse_credential_request(Cursor::new(input)).unwrap();
        assert_eq!(req.username.as_deref(), Some("alice"));
    }

    #[test]
    fn parse_credential_request_empty_input() {
        let input = "\n";
        let req = parse_credential_request(Cursor::new(input)).unwrap();
        assert!(req.protocol.is_none());
        assert!(req.host.is_none());
    }

    #[test]
    fn match_host_with_port_in_request() {
        let items = vec![("id1".into(), Some("https://gitea.example.com:3000".into()))];
        let result = match_vault_items("gitea.example.com:3000", None, &items).unwrap();
        assert_eq!(result.as_deref(), Some("id1"));
    }

    #[test]
    fn parse_uri_bare_host() {
        let (host, path) = parse_uri("github.com").unwrap();
        assert_eq!(host, "github.com");
        assert!(path.is_none());
    }

    #[test]
    fn match_item_with_path_request_without_path_is_host_only() {
        // Item has a specific path, but request has no path (git default)
        // Should still match at host-only priority
        let items = vec![("id1".into(), Some("https://github.com/alice/repo".into()))];
        let result = match_vault_items("github.com", None, &items).unwrap();
        assert_eq!(result.as_deref(), Some("id1"));
    }

    #[test]
    fn match_multiple_priorities_picks_best() {
        // One item matches host-only, another matches exactly
        // Even though both match, the exact match should win (different priority levels)
        let items = vec![
            ("id-host".into(), Some("https://github.com".into())),
            ("id-prefix".into(), Some("https://github.com/alice".into())),
            (
                "id-exact".into(),
                Some("https://github.com/alice/repo".into()),
            ),
        ];
        let result = match_vault_items("github.com", Some("alice/repo"), &items).unwrap();
        assert_eq!(result.as_deref(), Some("id-exact"));
    }

    #[test]
    fn normalize_path_handles_edge_cases() {
        assert_eq!(normalize_path(""), "");
        assert_eq!(normalize_path("/"), "");
        assert_eq!(normalize_path(".git"), "");
        assert_eq!(normalize_path("repo.git/"), "repo");
    }
}
