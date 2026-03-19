# ADR 007: Secret Injection via `bitsafe run`

## Status

Proposed

## Context

Developers frequently need secrets (API keys, database passwords, tokens) in environment variables when running commands. The common approaches all have problems:

- **Hardcoded in `.env` files**: Secrets in plaintext on disk, accidentally committed to git
- **Shell export**: Secrets visible in `ps`, shell history, `/proc/<pid>/environ`
- **Secret managers with wrappers**: 1Password's `op run` works but breaks interactive programs — it replaces stdin/stdout with pipes, losing TTY features (colors, cursor movement, line editing, signals)

We want `bitsafe run -- <command>` to inject secrets from the vault into environment variables, while keeping the child process as close to a direct terminal execution as possible.

## Decision

### Syntax

```bash
# Environment variables with bitsafe: prefix are replaced
export DATABASE_URL="bitsafe:64b18d6b-8161-4a0c-befb-c3484d36ec68/password"
bitsafe run -- ./my-app

# Or inline
DATABASE_URL="bitsafe:64b18d6b/password" bitsafe run -- ./my-app

# Multiple secrets
API_KEY="bitsafe:abc123/password" DB_PASS="bitsafe:def456/notes" bitsafe run -- ./deploy.sh
```

### Reference Format

```
bitsafe:<item-id>/<field>
```

| Component | Description |
|-----------|-------------|
| `bitsafe:` | Prefix identifying a vault reference |
| `<item-id>` | Cipher UUID (full or shortened prefix, minimum 6 chars) |
| `<field>` | Field to extract: `password`, `username`, `uri`, `notes`, `totp`, `name` |

Short IDs are resolved by prefix match — `bitsafe:64b18d` matches `64b18d6b-8161-4a0c-befb-c3484d36ec68`. Ambiguous matches are an error.

#### Name-based references

```
bitsafe://GitHub/password
bitsafe://My Database/username
```

The `://` prefix (vs `:`) signals a name lookup instead of ID. If multiple items share a name, it's an error — use the ID form.

### Execution Model

The child process must behave identically to running it directly from the shell. Specifically:

1. **PTY passthrough**: The child inherits the parent's TTY directly. No pipe interposition. Colors, cursor control, readline, Ctrl+C — all work natively.
2. **`exec` semantics**: After resolving secrets and setting environment variables, `bitsafe run` uses `exec` to replace itself with the child process. There is no wrapper process sitting between the shell and the child.
3. **Signal transparency**: Because we `exec`, the child receives signals directly from the terminal (SIGINT, SIGTSTP, SIGWINCH) — no signal proxying needed.
4. **Exit code passthrough**: The shell sees the child's exit code directly (consequence of `exec`).

### Implementation

```
bitsafe run -- ./my-app
         │
         ├── 1. Scan environ for values matching "bitsafe:..." pattern
         ├── 2. Collect unique vault references
         ├── 3. Connect to service, resolve all references in one batch
         ├── 4. Replace env vars with resolved plaintext values
         ├── 5. exec(child_command, modified_environ)
         │
         └── (bitsafe process is gone — child IS the process now)
```

Step 5 is critical: we call `execvp()`, not `fork()+exec()`. The `bitsafe` process ceases to exist. The child process owns the TTY, the PID, everything.

### Secret Lifetime

- Secrets exist only in the child's environment (in-memory, managed by the kernel)
- Not written to disk
- Not visible in `bitsafe` process (it's gone after exec)
- Visible in `/proc/<pid>/environ` to same-user processes (same as any env var — this is a kernel limitation, not something we can prevent without LD_PRELOAD tricks)

### Error Handling

All errors must occur **before** exec. Once we exec, we can't report errors.

| Condition | Behavior |
|-----------|----------|
| Service not running | Error, exit 1 |
| Vault locked | Trigger unlock (GUI prompt), then retry |
| Reference not found | Error listing which refs failed, exit 1 |
| Ambiguous short ID | Error listing matches, exit 1 |
| Network error during resolve | Error, exit 1 |
| No `bitsafe:` refs in environ | Warn and exec anyway (no-op) |

### Batch Resolution

All vault references are collected and resolved in a single service call to minimize latency. The service already has the decrypted vault in memory, so resolution is fast (no network calls).

Protocol addition:

```json
{"jsonrpc": "2.0", "id": 1, "method": "vault.resolve_refs", "params": {
  "refs": [
    {"id": "64b18d6b", "field": "password"},
    {"id": "abc123", "field": "notes"}
  ]
}}
```

Response:

```json
{"jsonrpc": "2.0", "id": 1, "result": [
  {"ref": "64b18d6b", "value": "s3cret"},
  {"ref": "abc123", "value": "db connection string here"}
]}
```

### `.env` File Support (Future)

```bash
# Load from a .env file containing bitsafe: references
bitsafe run --env-file .env.secrets -- ./my-app
```

The file is parsed, references resolved, and the resulting env vars are set before exec. The file never contains plaintext secrets.

## Consequences

### Positive

- **No TTY breakage**: `exec` semantics mean the child process is indistinguishable from running directly. Interactive programs, ncurses TUIs, colored output — all work.
- **No secret files on disk**: References in `.env` files are safe to commit — they contain UUIDs, not secrets.
- **Minimal attack surface**: The `bitsafe` process doesn't exist after exec. Secrets are only in the child's environ.
- **Composable**: Works with any program — `docker run`, `terraform`, `npm start`, shell scripts.

### Negative

- **Env var visibility**: `/proc/<pid>/environ` exposes secrets to same-user processes. This is inherent to environment variables — not specific to our implementation.
- **No runtime refresh**: Since we exec, secrets are frozen at startup. Long-running processes don't get updated secrets (same limitation as `op run`).
- **Service must be unlocked**: The vault must be unlocked before `bitsafe run` works. If locked, we trigger an unlock prompt, which may be unexpected in CI contexts. Use `prompt.method = "none"` in config for CI, and pass secrets via `--env` flags directly.

### Why Not LD_PRELOAD?

An alternative approach is to intercept `getenv()` calls via LD_PRELOAD, resolving references lazily. This would avoid `/proc/environ` exposure and enable runtime refresh. However:

- Breaks static binaries, Go binaries, and anything not using glibc's `getenv`
- macOS SIP prevents LD_PRELOAD on system binaries
- Adds complexity and an opaque failure mode
- `exec` with env var replacement is simpler, more portable, and matches user expectations
