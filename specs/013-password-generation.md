# ADR 013: Password and Passphrase Generation

## Status

Implemented

## Context

A security tool that manages passwords should also generate them. Users currently reach for external tools (`openssl rand`, `pwgen`, online generators) to create passwords before storing them in the vault. This is both inconvenient and a security gap — external generators may have weak RNG, and online generators are a direct exposure risk.

`grimoire generate` provides cryptographically strong password and passphrase generation as a built-in CLI command. V1 is output-only (no `--save` to vault — that requires vault write operations not yet implemented).

### Prior Art

- Bitwarden CLI: `bw generate -p --words 5 --separator -` (passphrase), `bw generate --length 32` (password)
- 1Password CLI: `op generate --length 32 --characters`
- `pass generate`: uses `/dev/urandom`
- KeePassXC CLI: `keepassxc-cli generate --length 32`

### What Exists Today

- No generation capability in Grimoire
- `rand` crate with `OsRng` is already a transitive dependency
- No vault write operations (no `--save` support yet)

## Decision

### CLI Interface

```bash
# Random password (default: 20 chars, alphanumeric + symbols)
grimoire generate

# Custom length
grimoire generate --length 32
grimoire generate -l 32

# Character set control
grimoire generate --charset alphanumeric    # a-z, A-Z, 0-9
grimoire generate --charset alpha           # a-z, A-Z
grimoire generate --charset numeric         # 0-9
grimoire generate --charset symbols         # !@#$%^&*...

# Combine charsets with +
grimoire generate --charset alphanumeric+symbols  # default

# Diceware passphrase
grimoire generate --type passphrase
grimoire generate --type passphrase --words 6
grimoire generate --type passphrase --separator .

# JSON output
grimoire generate --json
# {"value": "...", "type": "password", "entropy_bits": 131}
```

### Defaults

| Parameter | Default | Rationale |
|-----------|---------|-----------|
| `--type` | `password` | Most common use case |
| `--length` | `20` | Balances security (~131 bits with full charset) and compatibility |
| `--charset` | `alphanumeric+symbols` | Maximum entropy per character |
| `--words` | `6` | ~77 bits entropy with EFF large list (sufficient for most uses) |
| `--separator` | `-` | Readable, widely compatible |

### Password Generation

Character sets:

| Name | Characters | Size |
|------|-----------|------|
| `lowercase` | `a-z` | 26 |
| `uppercase` | `A-Z` | 26 |
| `alpha` | `a-zA-Z` | 52 |
| `numeric` | `0-9` | 10 |
| `alphanumeric` | `a-zA-Z0-9` | 62 |
| `symbols` | `!@#$%^&*()-_=+[]{}\|;:'",.<>?/~` | 32 |
| `alphanumeric+symbols` | All of the above | 94 |

Characters are sampled uniformly using `rand::Rng::gen_range()` with `OsRng`. Each character is an independent uniform draw from the charset.

Minimum length: 8 (reject shorter — too weak to be useful). No maximum length (reasonable; passwords are short strings).

### Passphrase Generation

- **Wordlist**: EFF large wordlist (7776 words), bundled via `include_str!` at compile time
- **Word selection**: uniform random index via `OsRng`, independent per word
- **Separator**: configurable via `--separator` (default `-`)
- **Capitalization**: none (entropy comes from word count, not case)
- **Minimum words**: 4 (reject fewer — too weak). No practical maximum.

The EFF large wordlist is ~60KB. It's a well-audited, public domain list specifically designed for diceware-style passphrase generation.

### Entropy Estimate

Every generation prints the entropy estimate to stderr:

```
$ grimoire generate -l 32
kX9#mP2$vL7@nQ4&hR8*jT5!wY3^bF6
# entropy: ~210 bits (32 chars from 94-char set)

$ grimoire generate --type passphrase --words 6
correct-horse-battery-staple-river-lamp
# entropy: ~77 bits (6 words from 7776-word list)
```

Formula:
- Password: `length × log2(charset_size)`
- Passphrase: `words × log2(wordlist_size)` = `words × 12.92` (for 7776-word list)

The estimate is printed to stderr so piping the password to another command (e.g., `grimoire generate | pbcopy`) works cleanly.

### Output

- **stdout**: the generated password/passphrase only (for piping)
- **stderr**: entropy estimate (human-readable)
- **`--json`**: JSON to stdout with `value`, `type`, and `entropy_bits` fields. No stderr output in JSON mode.

### RNG

- **Source**: `rand::rngs::OsRng` exclusively — delegates to the OS CSPRNG (`/dev/urandom` on Linux, `SecRandomCopyBytes` on macOS)
- **No fallback**: if `OsRng` fails, propagate the error. Never fall back to a weaker source.
- **No seeding**: `OsRng` is not seedable — it reads from the OS directly.

### Protocol Changes

None. This is a pure CLI command with no service interaction.

### Wordlist File

Add `crates/grimoire-cli/src/wordlist.txt` containing the EFF large wordlist (one word per line, 7776 lines). Loaded via:

```rust
const WORDLIST: &str = include_str!("wordlist.txt");
```

Parsed at first use into a `Vec<&str>` (lazy or at command invocation).

## Consequences

### Positive

- Users can generate and use strong passwords without leaving Grimoire
- Cryptographically strong RNG (OS CSPRNG) — no weak sources
- Entropy estimate helps users understand their password strength
- Bundled wordlist — no external file dependencies, no integrity concerns
- Pipes cleanly with other commands (`grimoire generate | grimoire clip` once clipboard is implemented)

### Negative

- ~60KB binary size increase from bundled wordlist (trivial)
- No `--save` in v1 — users must manually store generated passwords. Future work when vault write ops are added.
- Fixed charset groups — users can't specify arbitrary character sets. This covers 99% of use cases; custom charsets add parser complexity for marginal benefit.

## Security Analysis

### Threat Model Impact

No change to the threat model. This feature runs entirely in the CLI process with no service interaction, no IPC, no network calls. The generated password exists only in CLI process memory and stdout.

### Attack Vectors

| # | Vector | Severity | Description |
|---|--------|----------|-------------|
| 1 | Weak RNG | Critical | Predictable passwords if CSPRNG fails or is poorly seeded |
| 2 | Biased sampling | Medium | Non-uniform character/word selection → less entropy than estimated |
| 3 | Terminal scrollback | Low | Generated password visible in terminal history |

### Planned Mitigations

| Vector | Mitigation | Mechanism |
|--------|-----------|-----------|
| 1 | OS CSPRNG only | `OsRng` delegates to OS. Error propagated on failure — no fallback to weaker source. |
| 2 | Uniform sampling | `OsRng` + `gen_range()` for charset indexing (rejection sampling internally). Wordlist is exactly 7776 entries. |
| 3 | Accept (consistent with `grimoire get`) | Same exposure as any CLI that outputs secrets. Users can pipe to `grimoire clip`. |

### Residual Risk

Terminal scrollback exposure is inherent to CLI secret output and accepted (same as `grimoire get`). OS CSPRNG quality is an OS-level concern outside our scope.

### Implementation Security Notes

- All planned mitigations implemented as designed. No deviations.
- `OsRng` used exclusively via `rand 0.8` crate (consistent with SDK's transitive dependency). `gen_range()` uses rejection sampling — no modulo bias.
- EFF large wordlist bundled at compile time via `include_str!`. 7776 words verified by test `wordlist_has_expected_size`.
- Full charset produces 92 unique characters (not 94 as initially estimated — the SYMBOLS constant has 30 unique chars, not 32). Entropy estimates adjusted accordingly.
- **Regression tests:** Vector 1 (weak RNG) covered by `generate_password_all_chars_from_charset` (1000-char generation verifies charset coverage). Vector 2 (biased sampling) covered by `generate_passphrase_words_from_wordlist` (all words come from wordlist).
