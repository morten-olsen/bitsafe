# Secret Injection: `grimoire run`

Inject vault secrets into environment variables and exec a command — no files on disk, no TTY breakage.

## Basic Usage

```bash
# Set env var to a vault reference, then run
DATABASE_URL="grimoire:64b18d6b/password" grimoire run -- ./my-app

# The app sees DATABASE_URL=<actual password from vault>
```

`grimoire run` scans the environment for values matching `grimoire:...`, resolves them from the vault, replaces the env vars with the real values, then **exec**s the command. The `grimoire` process ceases to exist — the child owns the terminal directly.

## Reference Format

```
grimoire:<item-id>/<field>
```

| Part | Description |
|------|-------------|
| `grimoire:` | Prefix that identifies a vault reference |
| `<item-id>` | Full UUID or prefix (minimum 6 chars) |
| `<field>` | `password`, `username`, `uri`, `notes`, `totp`, `name` |

Short IDs work by prefix match:
```bash
# Full UUID
TOKEN="grimoire:64b18d6b-8161-4a0c-befb-c3484d36ec68/password"

# Short prefix (unambiguous)
TOKEN="grimoire:64b18d/password"
```

### Name-Based Lookup

Use `://` instead of `:` to look up by item name:

```bash
API_KEY="grimoire://GitHub API/password" grimoire run -- ./deploy.sh
```

If multiple items share the same name, it's an error — use the ID form.

### Field Aliases

| Field | Aliases |
|-------|---------|
| `password` | `pw` |
| `username` | `user` |
| `uri` | `url` |
| `notes` | `note` |
| `totp` | — (generates a live TOTP code) |
| `name` | — |

## Examples

```bash
# Single secret
DB_PASS="grimoire:abc123/password" grimoire run -- psql -U admin mydb

# Multiple secrets
DB_PASS="grimoire:abc123/password" \
API_KEY="grimoire:def456/notes" \
grimoire run -- docker compose up

# Works with any program — interactive TUI, colors, readline
DB_URL="grimoire:abc123/uri" grimoire run -- python manage.py shell

# CI/scripts
export DEPLOY_TOKEN="grimoire://Deploy Key/password"
grimoire run -- ./scripts/deploy.sh

# TOTP for MFA automation
MFA_CODE="grimoire:abc123/totp" grimoire run -- ./login-script.sh
```

## How It Works

```
Shell
  │
  ├── grimoire run -- ./my-app
  │     │
  │     ├── 1. Scan env vars for "grimoire:..." values
  │     ├── 2. Batch-resolve all references via service (single RPC call)
  │     ├── 3. Replace env vars with resolved secrets
  │     ├── 4. exec(./my-app)  ← grimoire process is GONE
  │     │
  │     └── (process replaced — ./my-app IS the process now)
  │
  └── ./my-app (PID unchanged, owns TTY, gets signals directly)
```

Step 4 uses `execvp()` — the `grimoire` process is replaced entirely. This is why interactive programs, colors, Ctrl+C, and job control all work perfectly.

## Why No TTY Breakage

1Password's `op run` spawns the child as a subprocess with piped stdio, which breaks:
- Colors (no TTY detected)
- Interactive prompts (no readline)
- Cursor movement (ncurses, TUI apps)
- Signal handling (Ctrl+C, Ctrl+Z)
- Job control (`fg`, `bg`)

`grimoire run` avoids all of this by using `exec` — there is no parent process after the secrets are injected. The child inherits the terminal directly.

## Error Handling

All errors happen **before** exec. Once we exec, we can't report errors.

| Situation | What happens |
|-----------|-------------|
| Service not running | Error, exit 1 |
| Vault locked | Triggers unlock (GUI prompt), then retries |
| Item not found | Error naming which refs failed, exit 1 |
| Ambiguous short ID | Error listing matches, exit 1 |
| Ambiguous name | Error suggesting ID form, exit 1 |
| No `grimoire:` refs in env | Execs the command anyway (no-op passthrough) |
| Field is empty/missing | Error, exit 1 |

## Security

- Secrets exist only in the child's environment (kernel-managed memory)
- Never written to disk
- Not visible in the `grimoire` process (gone after exec)
- **Visible in `/proc/<pid>/environ`** to same-user processes — this is inherent to environment variables on Linux and cannot be avoided without `LD_PRELOAD` tricks (which break Go/static binaries and macOS SIP)
- Vault references in `.env` files are safe to commit — they contain IDs, not secrets

## Compared to 1Password `op run`

| Feature | `op run` | `grimoire run` |
|---------|----------|---------------|
| Secret injection | Environment variables | Environment variables |
| Interactive programs | Broken (piped stdio) | Works (exec, no wrapper) |
| Colors/TUI | Broken (no TTY) | Works |
| Signal handling | Proxied (delays, edge cases) | Native (child owns TTY) |
| Job control | Broken | Works |
| Process tree | Parent + child | Child only (exec) |
| Runtime refresh | No | No |
