use anyhow::{bail, Result};
use rand::rngs::OsRng;
use rand::Rng;

const WORDLIST: &str = include_str!("../wordlist.txt");

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMERIC: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}|;:'\",.<>?/~";

/// Minimum password length — anything shorter is too weak to be useful.
const MIN_PASSWORD_LENGTH: usize = 8;

/// Minimum passphrase word count.
const MIN_PASSPHRASE_WORDS: usize = 4;

fn build_charset(spec: &str) -> Result<Vec<u8>> {
    let mut charset = Vec::new();
    for part in spec.split('+') {
        match part.trim() {
            "lowercase" => charset.extend_from_slice(LOWERCASE),
            "uppercase" => charset.extend_from_slice(UPPERCASE),
            "alpha" => {
                charset.extend_from_slice(LOWERCASE);
                charset.extend_from_slice(UPPERCASE);
            }
            "numeric" => charset.extend_from_slice(NUMERIC),
            "alphanumeric" => {
                charset.extend_from_slice(LOWERCASE);
                charset.extend_from_slice(UPPERCASE);
                charset.extend_from_slice(NUMERIC);
            }
            "symbols" => charset.extend_from_slice(SYMBOLS),
            "alphanumeric+symbols" => {
                charset.extend_from_slice(LOWERCASE);
                charset.extend_from_slice(UPPERCASE);
                charset.extend_from_slice(NUMERIC);
                charset.extend_from_slice(SYMBOLS);
            }
            other => bail!(
                "Unknown charset: '{other}'. Use: lowercase, uppercase, alpha, numeric, alphanumeric, symbols"
            ),
        }
    }
    charset.sort_unstable();
    charset.dedup();
    Ok(charset)
}

fn generate_password(length: usize, charset: &[u8]) -> Result<String> {
    if length < MIN_PASSWORD_LENGTH {
        bail!("Password length must be at least {MIN_PASSWORD_LENGTH}");
    }
    if charset.is_empty() {
        bail!("Charset is empty");
    }

    let mut rng = OsRng;
    let password: String = (0..length)
        .map(|_| charset[rng.gen_range(0..charset.len())] as char)
        .collect();
    Ok(password)
}

fn generate_passphrase(words: usize, separator: &str) -> Result<String> {
    if words < MIN_PASSPHRASE_WORDS {
        bail!("Passphrase must have at least {MIN_PASSPHRASE_WORDS} words");
    }

    let wordlist: Vec<&str> = WORDLIST.lines().collect();
    if wordlist.is_empty() {
        bail!("Wordlist is empty");
    }

    let mut rng = OsRng;
    let selected: Vec<&str> = (0..words)
        .map(|_| wordlist[rng.gen_range(0..wordlist.len())])
        .collect();
    Ok(selected.join(separator))
}

fn entropy_bits_password(length: usize, charset_size: usize) -> f64 {
    length as f64 * (charset_size as f64).log2()
}

fn entropy_bits_passphrase(words: usize) -> f64 {
    let wordlist_size = WORDLIST.lines().count();
    words as f64 * (wordlist_size as f64).log2()
}

pub fn handle_generate(
    gen_type: &str,
    length: usize,
    charset_spec: &str,
    words: usize,
    separator: &str,
    json: bool,
) -> Result<()> {
    match gen_type {
        "password" => {
            let charset = build_charset(charset_spec)?;
            let password = generate_password(length, &charset)?;
            let entropy = entropy_bits_password(length, charset.len());

            if json {
                let output = serde_json::json!({
                    "value": password,
                    "type": "password",
                    "entropy_bits": (entropy as u64),
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{password}");
                eprintln!(
                    "# entropy: ~{} bits ({length} chars from {}-char set)",
                    entropy as u64,
                    charset.len()
                );
            }
        }
        "passphrase" => {
            let passphrase = generate_passphrase(words, separator)?;
            let entropy = entropy_bits_passphrase(words);

            if json {
                let output = serde_json::json!({
                    "value": passphrase,
                    "type": "passphrase",
                    "entropy_bits": (entropy as u64),
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{passphrase}");
                let wordlist_size = WORDLIST.lines().count();
                eprintln!(
                    "# entropy: ~{} bits ({words} words from {wordlist_size}-word list)",
                    entropy as u64
                );
            }
        }
        other => bail!("Unknown type: '{other}'. Use: password, passphrase"),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_has_expected_size() {
        let count = WORDLIST.lines().count();
        assert_eq!(count, 7776, "EFF large wordlist should have 7776 words");
    }

    #[test]
    fn wordlist_has_no_empty_lines() {
        for (i, line) in WORDLIST.lines().enumerate() {
            assert!(!line.is_empty(), "Line {i} is empty");
            assert!(
                !line.contains('\t'),
                "Line {i} contains a tab (dice numbers not stripped?)"
            );
        }
    }

    #[test]
    fn build_charset_alphanumeric() {
        let charset = build_charset("alphanumeric").unwrap();
        assert_eq!(charset.len(), 62);
        assert!(charset.contains(&b'a'));
        assert!(charset.contains(&b'Z'));
        assert!(charset.contains(&b'9'));
    }

    #[test]
    fn build_charset_combined() {
        let charset = build_charset("lowercase+numeric").unwrap();
        assert_eq!(charset.len(), 36);
    }

    #[test]
    fn build_charset_full() {
        let charset = build_charset("alphanumeric+symbols").unwrap();
        // 62 alphanumeric + 30 unique symbols = 92 (some symbols overlap with nothing but
        // the SYMBOLS const has 30 unique characters, not 32 as some are multi-byte or duplicated)
        assert_eq!(charset.len(), 92);
    }

    #[test]
    fn build_charset_deduplicates() {
        // alpha = lowercase + uppercase, adding lowercase again shouldn't increase size
        let charset = build_charset("alpha+lowercase").unwrap();
        assert_eq!(charset.len(), 52);
    }

    #[test]
    fn build_charset_unknown_errors() {
        assert!(build_charset("emoji").is_err());
    }

    #[test]
    fn generate_password_correct_length() {
        let charset = build_charset("alphanumeric").unwrap();
        let pw = generate_password(20, &charset).unwrap();
        assert_eq!(pw.len(), 20);
    }

    #[test]
    fn generate_password_uses_charset() {
        let charset = build_charset("numeric").unwrap();
        let pw = generate_password(100, &charset).unwrap();
        for c in pw.chars() {
            assert!(c.is_ascii_digit(), "Expected digit, got '{c}'");
        }
    }

    #[test]
    fn generate_password_rejects_short() {
        let charset = build_charset("alphanumeric").unwrap();
        assert!(generate_password(7, &charset).is_err());
        assert!(generate_password(8, &charset).is_ok());
    }

    #[test]
    fn generate_passphrase_correct_word_count() {
        let pp = generate_passphrase(6, "-").unwrap();
        assert_eq!(pp.split('-').count(), 6);
    }

    #[test]
    fn generate_passphrase_custom_separator() {
        let pp = generate_passphrase(4, ".").unwrap();
        assert_eq!(pp.split('.').count(), 4);
    }

    #[test]
    fn generate_passphrase_rejects_few_words() {
        assert!(generate_passphrase(3, "-").is_err());
        assert!(generate_passphrase(4, "-").is_ok());
    }

    #[test]
    fn entropy_password_sanity() {
        // 20 chars from 92-char set ≈ 130 bits
        let e = entropy_bits_password(20, 92);
        assert!((130.0..131.0).contains(&e));
    }

    #[test]
    fn entropy_passphrase_sanity() {
        // 6 words from 7776-word list ≈ 77 bits
        let e = entropy_bits_passphrase(6);
        assert!((77.0..78.0).contains(&e));
    }

    #[test]
    fn generate_password_empty_charset_errors() {
        assert!(generate_password(20, &[]).is_err());
    }

    #[test]
    fn build_charset_each_variant_works() {
        for (name, expected_min) in [
            ("lowercase", 26),
            ("uppercase", 26),
            ("alpha", 52),
            ("numeric", 10),
            ("alphanumeric", 62),
            ("symbols", 30),
        ] {
            let charset = build_charset(name).unwrap();
            assert!(
                charset.len() >= expected_min,
                "{name}: expected >= {expected_min}, got {}",
                charset.len()
            );
        }
    }

    #[test]
    fn generate_password_all_chars_from_charset() {
        // Generate a long password and verify every char is in the charset
        let charset = build_charset("alphanumeric+symbols").unwrap();
        let pw = generate_password(1000, &charset).unwrap();
        for c in pw.bytes() {
            assert!(
                charset.contains(&c),
                "Password contains char '{}' not in charset",
                c as char
            );
        }
    }

    #[test]
    fn wordlist_words_are_ascii_lowercase_or_hyphen() {
        for (i, word) in WORDLIST.lines().enumerate() {
            assert!(
                word.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "Line {i}: word '{word}' contains unexpected characters"
            );
        }
    }

    #[test]
    fn generate_passphrase_words_from_wordlist() {
        let wordlist: Vec<&str> = WORDLIST.lines().collect();
        let pp = generate_passphrase(6, "-").unwrap();
        for word in pp.split('-') {
            assert!(
                wordlist.contains(&word),
                "Passphrase contains word '{word}' not in wordlist"
            );
        }
    }
}
