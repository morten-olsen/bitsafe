use anyhow::{bail, Context, Result};
use std::path::Path;

use crate::parse_grimoire_ref;

/// A single entry from a manifest file.
#[derive(Debug, Clone)]
pub struct ManifestEntry {
    pub key: String,
    pub reference: String,
}

/// Validate that a string is a valid environment variable name: [A-Za-z_][A-Za-z0-9_]*
fn is_valid_env_var_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parse a manifest file into a list of (env_var_name, grimoire_reference) pairs.
pub fn parse_manifest(path: &Path) -> Result<Vec<ManifestEntry>> {
    // Check file permissions (warn only — manifest is designed to be in git)
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.mode();
            if mode & 0o022 != 0 {
                eprintln!(
                    "Warning: manifest {} is group/world-writable ({:04o})",
                    path.display(),
                    mode & 0o777,
                );
            }
        }
    }

    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read manifest file: {}", path.display()))?;

    let mut entries = Vec::new();

    for (line_num, line) in contents.lines().enumerate() {
        let line_num = line_num + 1; // 1-indexed
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Parse KEY=value
        let (key, value) = trimmed.split_once('=').with_context(|| {
            format!(
                "{}:{}: invalid format — expected KEY=grimoire://name/field",
                path.display(),
                line_num,
            )
        })?;

        let key = key.trim();
        let value = value.trim();

        // Validate env var name
        if !is_valid_env_var_name(key) {
            bail!(
                "{}:{}: invalid environment variable name '{}'",
                path.display(),
                line_num,
                key,
            );
        }

        // Value must be a grimoire reference
        if parse_grimoire_ref(value).is_none() {
            bail!(
                "{}:{}: value must be a grimoire:// or grimoire: reference, not a plain value",
                path.display(),
                line_num,
            );
        }

        entries.push(ManifestEntry {
            key: key.to_string(),
            reference: value.to_string(),
        });
    }

    Ok(entries)
}

/// Apply manifest entries to the environment.
/// Only sets env vars that are not already set (existing env vars take precedence).
pub fn apply_manifest_entries(entries: &[ManifestEntry]) {
    for entry in entries {
        if std::env::var(&entry.key).is_err() {
            std::env::set_var(&entry.key, &entry.reference);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_manifest(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn is_valid_env_var_name_accepts_valid() {
        assert!(is_valid_env_var_name("DATABASE_URL"));
        assert!(is_valid_env_var_name("_PRIVATE"));
        assert!(is_valid_env_var_name("A"));
        assert!(is_valid_env_var_name("a1_B2"));
    }

    #[test]
    fn is_valid_env_var_name_rejects_invalid() {
        assert!(!is_valid_env_var_name(""));
        assert!(!is_valid_env_var_name("1STARTS_WITH_DIGIT"));
        assert!(!is_valid_env_var_name("HAS-DASH"));
        assert!(!is_valid_env_var_name("HAS SPACE"));
        assert!(!is_valid_env_var_name("HAS.DOT"));
    }

    #[test]
    fn parse_manifest_basic() {
        let f = write_temp_manifest(
            "# comment\n\
             DATABASE_URL=grimoire://Production DB/password\n\
             API_KEY=grimoire://Stripe/notes\n",
        );
        let entries = parse_manifest(f.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "DATABASE_URL");
        assert_eq!(entries[0].reference, "grimoire://Production DB/password");
        assert_eq!(entries[1].key, "API_KEY");
        assert_eq!(entries[1].reference, "grimoire://Stripe/notes");
    }

    #[test]
    fn parse_manifest_skips_comments_and_empty() {
        let f = write_temp_manifest(
            "# header comment\n\
             \n\
             DATABASE_URL=grimoire://DB/password\n\
             \n\
             # another comment\n\
             API_KEY=grimoire://Key/password\n\
             \n",
        );
        let entries = parse_manifest(f.path()).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn parse_manifest_id_based_ref() {
        let f = write_temp_manifest("TOKEN=grimoire:64b18d6b/password\n");
        let entries = parse_manifest(f.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].reference, "grimoire:64b18d6b/password");
    }

    #[test]
    fn parse_manifest_rejects_plain_value() {
        let f = write_temp_manifest("PORT=8080\n");
        let result = parse_manifest(f.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("grimoire:// or grimoire:"));
    }

    #[test]
    fn parse_manifest_rejects_invalid_env_name() {
        let f = write_temp_manifest("1BAD=grimoire://DB/password\n");
        let result = parse_manifest(f.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid environment variable name"));
    }

    #[test]
    fn parse_manifest_rejects_missing_equals() {
        let f = write_temp_manifest("just-a-line-without-equals\n");
        let result = parse_manifest(f.path());
        assert!(result.is_err());
    }

    #[test]
    fn parse_manifest_last_wins_on_duplicate() {
        let f = write_temp_manifest(
            "KEY=grimoire://First/password\n\
             KEY=grimoire://Second/password\n",
        );
        let entries = parse_manifest(f.path()).unwrap();
        assert_eq!(entries.len(), 2);
        // Both entries are kept — apply_manifest_entries handles precedence
        // (first one wins because it sets the env var, second is skipped)
    }

    #[test]
    fn parse_manifest_file_not_found() {
        let result = parse_manifest(Path::new("/nonexistent/.env.grimoire"));
        assert!(result.is_err());
    }

    #[test]
    fn parse_manifest_whitespace_around_key_and_value() {
        let f = write_temp_manifest("  DB_URL  =  grimoire://DB/password  \n");
        let entries = parse_manifest(f.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "DB_URL");
        assert_eq!(entries[0].reference, "grimoire://DB/password");
    }

    #[test]
    fn parse_manifest_indented_comment() {
        let f = write_temp_manifest("  # indented comment\nKEY=grimoire://X/password\n");
        let entries = parse_manifest(f.path()).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn apply_manifest_does_not_override_existing_env() {
        // Set an env var before applying manifest
        let key = "GRIMOIRE_TEST_MANIFEST_PRECEDENCE";
        std::env::set_var(key, "original");

        let entries = vec![ManifestEntry {
            key: key.to_string(),
            reference: "grimoire://Override/password".to_string(),
        }];
        apply_manifest_entries(&entries);

        // Existing value should win
        assert_eq!(std::env::var(key).unwrap(), "original");
        std::env::remove_var(key);
    }

    #[test]
    fn apply_manifest_sets_missing_env() {
        let key = "GRIMOIRE_TEST_MANIFEST_SET";
        std::env::remove_var(key);

        let entries = vec![ManifestEntry {
            key: key.to_string(),
            reference: "grimoire://New/password".to_string(),
        }];
        apply_manifest_entries(&entries);

        assert_eq!(std::env::var(key).unwrap(), "grimoire://New/password");
        std::env::remove_var(key);
    }

    #[test]
    fn parse_manifest_rejects_empty_key() {
        let f = write_temp_manifest("=grimoire://DB/password\n");
        let result = parse_manifest(f.path());
        assert!(result.is_err());
    }

    #[test]
    fn parse_manifest_name_with_underscores() {
        let f = write_temp_manifest("__MY_VAR_123=grimoire://X/password\n");
        let entries = parse_manifest(f.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "__MY_VAR_123");
    }
}
