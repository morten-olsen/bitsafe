# ADR 014: Git Credential Helper

## Status

Implemented

## Context

Git supports pluggable credential helpers for HTTPS authentication. Currently, Grimoire covers SSH-based Git auth through its embedded SSH agent, but HTTPS auth (GitHub personal access tokens, GitLab tokens, Gitea passwords) requires users to manually copy credentials or use a separate credential store like `git-credential-osxkeychain` or plaintext `~/.git-credentials`.

`grimoire credential-helper` is a built-in subcommand that implements the [git credential helper protocol](https://git-scm.com/docs/git-credential#IOFMT), providing HTTPS Git credentials from the vault with biometric/PIN approval. Combined with the existing SSH agent, this covers both Git transport protocols.

### Prior Art

- `git-credential-osxkeychain`: macOS Keychain-backed
- `git-credential-store`: plaintext `~/.git-credentials` (insecure)
- `git-credential-cache`: in-memory with timeout (doesn't persist across sessions)
- 1Password: `git-credential-1password` (separate binary)
- Bitwarden: no official git credential helper

### What Exists Today

- SSH agent handles Git SSH auth (via `ssh.sign` RPC)
- `vault.list` returns all items with URIs for matching
- `vault.get` returns full item details including username/password
- Scoped access approval gates all vault operations
- URI field on vault items (set in Bitwarden/Vaultwarden) — used for browser autofill, reusable for Git host matching

### Git Credential Helper Protocol

Git credential helpers communicate via stdin/stdout with a line-based `key=value` format:

**Input** (from git, on stdin):
```
protocol=https
host=github.com
path=alice/grimoire.git

```
(terminated by a blank line)

**Output** (to git, on stdout):
```
protocol=https
host=github.com
username=alice
password=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

```
(terminated by a blank line)

Git calls the helper with an action as the first argument:
- `get`: retrieve credentials for the given input
- `store`: save credentials (after successful auth)
- `erase`: delete credentials (after failed auth)

## Decision

### CLI Interface

```bash
# Git configuration (user runs once)
git config --global credential.helper grimoire

# Or with path-based scoping
git config --global credential.https://github.com.helper grimoire
```

Git will invoke `git-credential-grimoire get` (looking for a binary named `git-credential-grimoire`) or `grimoire credential-helper get` (if configured as just `grimoire`). We implement the subcommand form:

```bash
# Direct invocation (git calls this)
grimoire credential-helper get    # reads stdin, writes stdout
grimoire credential-helper store  # no-op (exit 0)
grimoire credential-helper erase  # no-op (exit 0)
```

Additionally, install a symlink or hard link `git-credential-grimoire` → `grimoire` so git's binary-name discovery works. The `grimoire` binary detects when invoked as `git-credential-grimoire` and routes to the credential helper logic.

### Protocol Filter

Only respond for `protocol=https`. If the protocol is anything else (http, ssh, etc.), exit with no output. SSH auth goes through the SSH agent, and plaintext HTTP should not receive credentials.

### URI Matching

When git requests credentials for `protocol=https, host=github.com, path=alice/grimoire.git`:

1. **List all vault items** via `vault.list` RPC
2. **Filter items with URIs** — skip items with no URI set
3. **Parse each item's URI** into (scheme, host, path) components
4. **Match against the request** with priority scoring:

| Priority | Match Type | Example |
|----------|-----------|---------|
| 1 (highest) | Exact: scheme + host + path | `https://github.com/alice/grimoire` matches `github.com` + `alice/grimoire.git` |
| 2 | Host + path prefix | `https://github.com/alice` matches `github.com` + `alice/*` |
| 3 (lowest) | Host only | `https://github.com` matches `github.com` + any path |

Path matching rules:
- Trailing `.git` suffix is stripped from both the request path and vault URI before comparison
- Trailing `/` is stripped before comparison
- Comparison is case-sensitive (Git URLs are case-sensitive)
- Vault URI scheme is ignored for matching (only host and path matter) — a vault item with `https://github.com` matches regardless of stored scheme

5. **Select the best match**:
   - Take all items at the highest matching priority level
   - If exactly one item matches → use it
   - If multiple items match at the same level → fail with error to stderr (don't guess)
   - If no items match → exit with no output (git will try the next credential helper)

6. **Get the full item** via `vault.get` RPC and return `username` + `password`

### Output

On successful match:
```
protocol=https
host=github.com
username=<vault item username>
password=<vault item password>
```

On no match: exit with no output (exit code 0 — per git protocol, this means "I don't have credentials for this").

On ambiguous match: print error to stderr, exit with no output.

On error (vault locked, approval denied, service unavailable): print error to stderr, exit with non-zero code.

### Read-Only (V1)

- `get`: implemented (lookup and return credentials)
- `store`: no-op, exit 0 (we don't write to the vault)
- `erase`: no-op, exit 0 (we don't modify the vault)

Future versions could implement `store` to save new credentials to the vault (requires vault write operations).

### Binary Name Detection

When the `grimoire` binary is invoked as `git-credential-grimoire` (via symlink, hard link, or rename), it detects this from `argv[0]` and routes directly to the credential helper logic, treating the first argument as the action (`get`, `store`, `erase`).

This is implemented by checking `std::env::args().next()` for a filename ending in `git-credential-grimoire`.

### Protocol Changes

None. Uses existing `vault.list` and `vault.get` RPCs.

## Consequences

### Positive

- Covers HTTPS Git auth — combined with SSH agent, both Git transport protocols are handled
- No separate binary to install (built into `grimoire` CLI)
- Biometric/PIN approval on each `git push` — credentials never stored in plaintext
- Compatible with git's credential helper configuration (per-host, per-path, helper chaining)
- Symlink name detection (`git-credential-grimoire`) works with git's binary discovery

### Negative

- Requires vault items to have URIs set — items without URIs are invisible to the credential helper
- Approval prompt on every git operation that needs auth (push, fetch from private repos) — may feel repetitive. Mitigated by the 300s approval window (one approval covers multiple git ops in the same session).
- Path matching adds complexity compared to host-only matching, but needed for multi-account setups

## Security Analysis

### Threat Model Impact

No new trust boundaries. The credential helper runs as a CLI process, connects to the service over the existing Unix socket, and is gated by the same scoped access approval. Credentials flow: vault → service → CLI → git (via stdout pipe). The pipe is between same-user processes.

### Attack Vectors

| # | Vector | Severity | Description |
|---|--------|----------|-------------|
| 1 | Credential exfiltration via rogue remote | Medium | Attacker adds a git remote to `evil.com`; if a vault item's URI matches, credentials are sent |
| 2 | URI matching ambiguity | Medium | Multiple vault items match → wrong credentials sent to wrong service |
| 3 | Stdin injection | Low | Malformed input from a process impersonating git |
| 4 | Plaintext HTTP credential leak | Medium | If protocol filter is bypassed, credentials sent over unencrypted connection |

### Planned Mitigations

| Vector | Mitigation | Mechanism |
|--------|-----------|-----------|
| 1 | URI-based matching only | Credentials only returned for items whose URI matches the requested host. No fuzzy or name-based matching. Users explicitly set URIs on vault items. |
| 2 | Fail on ambiguity | If multiple items match at the same priority level, return no credentials and log error to stderr. Never guess. |
| 3 | Strict parsing | Parse only known `key=value` keys (`protocol`, `host`, `path`, `username`). Stop at blank line. Reject malformed lines. |
| 4 | HTTPS-only filter | Only respond when `protocol=https`. Any other protocol → exit with no output. |

### Residual Risk

- URI matching depends on users setting URIs on vault items. Items without URIs won't be found — this is by design (opt-in per item).
- A vault item with a URI matching `evil.com` would return credentials to an attacker's server — but the user explicitly configured that URI on the vault item, so this is user error, not a tool vulnerability.
- Git sends the `path` component only if `credential.useHttpPath` is set — by default, git only sends `protocol` + `host`. Users with multi-account setups must enable this git config option for path-based matching to work. Document this.

### Implementation Security Notes

- All planned mitigations implemented as designed. No deviations.
- **Audit finding (Medium):** `VaultItemDetail.password` was not zeroized after writing the credential response. Fixed with explicit `zeroize::Zeroize::zeroize()` call before drop in `handle_credential_get`.
- **Audit finding (Low):** Error message included raw stdin line content. Fixed to use generic "missing '=' delimiter" message without echoing input.
- **Audit finding (Low):** `req.username` hint from git was ignored. Fixed — when git provides a username, vault items are filtered to prefer matching usernames before URI matching.
- **Regression tests:** Vector 2 (URI ambiguity) covered by `match_ambiguous_errors`. Vector 3 (stdin injection) covered by `parse_credential_request_*` tests. Vector 4 (HTTP leak) enforced by protocol check in `handle_credential_get`. URI matching covered by 12+ tests across all priority tiers.
