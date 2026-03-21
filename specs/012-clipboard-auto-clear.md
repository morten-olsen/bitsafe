# ADR 012: Clipboard with Auto-Clear

## Status

Implemented

## Context

Password managers universally offer clipboard integration — copy a secret, auto-clear it after a short window. Grimoire currently requires `grimoire get <id> -f password` and manual copy-paste, leaving the secret in terminal scrollback and the clipboard indefinitely.

`grimoire clip` provides a table-stakes UX improvement: copy a vault secret directly to the system clipboard, then automatically clear it after a fixed timeout. This eliminates the "forgot to clear clipboard" class of secret exposure.

### Prior Art

- Bitwarden CLI: `bw get password <id> | pbcopy` (no auto-clear)
- 1Password CLI: `op read <ref> --clipboard` (auto-clear not documented)
- KeePassXC: 10s auto-clear (configurable)
- `pass`: 45s auto-clear via `xclip`

### What Exists Today

- `vault.get` RPC returns decrypted vault item fields
- `grimoire get -f password` prints to stdout — user must pipe to clipboard manually
- Scoped access approval gates all vault operations
- Platform detection exists in `grimoire-prompt` (macOS/Linux/Wayland/X11)

## Decision

### CLI Interface

```bash
# Copy password (default field) to clipboard
grimoire clip <id>

# Copy a specific field
grimoire clip <id> -f totp
grimoire clip <id> -f username
grimoire clip <id> -f notes
grimoire clip <id> -f uri
```

- `<id>` accepts the same ID prefix or name as `grimoire get`
- `-f` / `--field` selects which field to copy (default: `password`). When `totp`, routes to `vault.totp` RPC (same as `grimoire get -f totp`)
- `--json` outputs `{"copied": true, "field": "password", "clears_in": 15}` instead of human text

### Fixed Timeout

The clipboard is cleared after **15 seconds**. This is **not configurable** — consistent with the project's hardcoded security parameters (auto-lock, approval duration, PIN attempts). No `--timeout` flag.

### Clearing Mechanism

After copying the secret to the clipboard:

1. **Hash the secret** (SHA-256) immediately after writing to clipboard
2. **Zero the secret** in the CLI process — only the hash is retained
3. **Spawn a background clearer** using `std::env::current_exe()` with a hidden subcommand:
   ```
   grimoire clip --clear-after <base64-sha256-hash>
   ```
   This is an internal subcommand, not shown in `--help`.
4. **The clearer process** sleeps for 15 seconds, then:
   - Reads current clipboard contents
   - Hashes the contents (SHA-256)
   - If hashes match → clears the clipboard
   - If hashes don't match → user copied something else, skip clear
5. **The parent process** prints a confirmation message and exits immediately (does not block for 15 seconds)

If spawning the clearer fails, **clear the clipboard immediately** (fail-safe — prefer losing the copy over leaving the secret exposed).

### Platform Clipboard Access

Clipboard access uses platform CLI tools (same approach as `grimoire-prompt` for platform detection):

| Platform | Write | Read | Clear |
|----------|-------|------|-------|
| macOS | `pbcopy` (stdin) | `pbpaste` (stdout) | `pbcopy` with empty stdin |
| Linux/Wayland | `wl-copy` (stdin) | `wl-paste` (stdout) | `wl-copy --clear` |
| Linux/X11 | `xclip -selection clipboard` (stdin) | `xclip -selection clipboard -o` (stdout) | `xclip -selection clipboard` with empty stdin |

Detection order: check for `wl-copy` first (Wayland), then `xclip` (X11), then `pbcopy` (macOS). Error if none found.

The clipboard tools are invoked via `std::process::Command` with stdin piped — secrets pass through the pipe, never as command-line arguments (which would be visible in `/proc/<pid>/cmdline`).

### Secret Lifetime

```
CLI process:
  vault.get RPC → secret in memory → pipe to clipboard tool → SHA-256 hash → zero secret → spawn clearer → exit

Clearer process:
  sleep 15s → read clipboard → SHA-256 hash → compare → clear or skip → exit
  (never holds the original secret — only the hash)
```

The secret is held in the CLI process memory only for the duration of the clipboard write. The clearer process never holds the secret — it only compares hashes.

### Error Handling

| Condition | Behavior |
|-----------|----------|
| Vault locked | Auto-unlock via GUI prompt (existing behavior) |
| Item not found | Error: "No item matching '<id>'" |
| Field not present | Error: "Item '<name>' has no <field> field" |
| No clipboard tool found | Error: "No clipboard tool found. Install pbcopy (macOS), wl-copy (Wayland), or xclip (X11)." |
| Clipboard write fails | Error with tool's stderr |
| Clearer spawn fails | Clear clipboard immediately (fail-safe), warn to stderr |
| TOTP field | Route to `vault.totp` RPC, same as `grimoire get -f totp` |

### Protocol Changes

None. Uses existing `vault.get` and `vault.totp` RPCs.

### Constant

Add to `grimoire-common/src/config.rs`:

```rust
pub const CLIPBOARD_CLEAR_SECONDS: u64 = 15;
```

## Consequences

### Positive

- Table-stakes password manager UX — copy secrets without terminal scrollback exposure
- Auto-clear reduces accidental clipboard exposure window
- Hash-based clear check prevents wiping user's subsequent clipboard contents
- Fail-safe design: if anything goes wrong with the clearer, clipboard is cleared immediately rather than left exposed

### Negative

- Platform dependency on clipboard CLI tools (`pbcopy`, `wl-copy`, `xclip`)
- 15s fixed timeout may frustrate users who want longer — but security over convenience is a project principle
- Cannot prevent clipboard manager history from persisting the secret (out of scope)

## Security Analysis

### Threat Model Impact

No new trust boundaries. The clipboard is accessible to all same-user processes — this is the same threat model as every other password manager's clipboard feature. No changes to `docs/security.md` threat model.

### Attack Vectors

| # | Vector | Severity | Description |
|---|--------|----------|-------------|
| 1 | Clipboard sniffing | Medium | Any same-user process can read the clipboard during the 15s window |
| 2 | Clear failure | Medium | Clearer process killed/crashed → secret persists in clipboard |
| 3 | Clipboard manager history | Medium | Clipboard managers may persist contents beyond our clear |
| 4 | Stale clear | Low | User copies something else; clearer wipes the new content |
| 5 | Clearer binary replacement | Low | Spawned clearer subprocess could be intercepted |

### Planned Mitigations

| Vector | Mitigation | Mechanism |
|--------|-----------|-----------|
| 1 | Fixed 15s timeout | Short window, not user-extendable. Hardcoded constant. |
| 2 | Fail-safe spawn | If clearer spawn fails, clear clipboard immediately. Clearer is a simple sleep+check+clear — minimal failure surface. |
| 3 | Document limitation | Out of scope — clipboard managers are OS-level. Note in help text. |
| 4 | Hash-based content check | SHA-256 hash of secret stored at copy time. Clearer hashes current clipboard and only clears on match. Secret never held by clearer. |
| 5 | No PATH lookup | Clearer spawned via `std::env::current_exe()` — uses the same binary, no PATH search. |

### Residual Risk

Same-user clipboard sniffing is inherent to clipboard usage and accepted by every password manager. Clipboard manager history is out of our control. Both are documented.

### Implementation Security Notes

- All planned mitigations implemented as designed. No deviations.
- **Audit finding (Medium):** Secret extracted from vault response was held as plain `String` without zeroization. Fixed by wrapping in `Zeroizing<String>` — secret is zeroed on drop after clipboard write. See `handle_clip` in `main.rs`.
- **Hash passed as CLI argument:** The SHA-256 hash of the secret is visible in `/proc/<pid>/cmdline` during the 15s clear window. Accepted — the hash doesn't amplify what a local attacker with clipboard access can already do.
- **Regression tests:** Vector 4 (stale clear) covered by `sha256_hex_deterministic` and `sha256_hex_different_inputs`. Vector 5 (clearer binary) mitigated by `current_exe()` — no PATH lookup in code.
