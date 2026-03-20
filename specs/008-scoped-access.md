# ADR 008: Scoped Vault Access

## Status

Proposed

## Context

Today the vault is either unlocked or locked — any process running as the same user can connect to the service socket and read secrets. If an attacker achieves RCE (e.g., via a compromised npm package, a browser exploit, or a malicious VS Code extension), they immediately have full vault access for as long as the vault is unlocked.

1Password partially mitigates this with its "biometric unlock" per-app, but the mechanism is opaque and tied to their desktop app.

We want a model where:
- The vault is **unlocked** (keys in memory, ready to decrypt), but
- Individual operations require **approval** scoped to a process tree
- Approval is lightweight (fingerprint, PIN, system password) — not the master password
- Approved access covers the approved process and its children (so `grimoire run -- docker compose up` approves docker and all its child processes)

## Decision

### Two-Layer Model

```
Layer 1: Unlock (master password)
  └── Vault keys loaded into memory, ciphers decryptable

Layer 2: Access Approval (fingerprint / PIN / system password)
  └── Scoped to a process tree, time-limited
  └── Required for sensitive operations (read secrets, sign)
  └── NOT required for: status, list (names only), lock, logout
```

**Unlock** is unchanged — master password, happens once per session. This loads the cryptographic keys.

**Access approval** is new — a lightweight verification that gates actual secret access. It proves a human is intentionally requesting secrets, not a background RCE process.

### What Requires Approval

| Operation | Requires approval? | Rationale |
|-----------|-------------------|-----------|
| `auth.status` | No | No secrets exposed |
| `vault.list` | No | Shows names/IDs only, not secrets |
| `vault.get` | **Yes** | Returns passwords, notes, etc. |
| `vault.totp` | **Yes** | Returns TOTP code |
| `vault.resolve_refs` | **Yes** | Returns secret values |
| `ssh.sign` | **Yes** | Uses private key material |
| `ssh.list_keys` | No | Public keys only |
| `sync.trigger` | No | Network operation, no secrets returned |

### Approval Scope: Process Trees

When a process requests a sensitive operation, the service:

1. Gets the **peer PID** from `SO_PEERCRED` (the `grimoire` CLI process)
2. Walks up the process tree via `/proc/<pid>/status` (Linux) or `proc_pidinfo` (macOS) to find the **session leader** — the shell or terminal that spawned the command
3. Prompts the user for approval via the GUI prompt agent (fingerprint, PIN, or system password)
4. Records an **approval grant**: `(session_leader_pid, expiry_time)`
5. Future requests from any process in that session's tree are approved without re-prompting

```
Terminal (PID 1000, session leader)    ← approval is anchored here
  └── zsh (PID 1001)
       ├── grimoire get (PID 1050)      ← triggers approval prompt
       ├── grimoire run (PID 1060)      ← already approved (same session)
       │    └── docker (PID 1061)      ← already approved (child of approved tree)
       └── grimoire get (PID 1070)      ← already approved
```

A malicious process spawned from a different session (e.g., a cron job, a compromised service, a reverse shell) would be a **different session leader** and require its own approval:

```
sshd (PID 2000, session leader)        ← different session
  └── reverse-shell (PID 2001)
       └── grimoire get (PID 2050)      ← triggers NEW approval prompt
                                          (attacker can't complete GUI prompt)
```

### Approval Lifetime

```toml
[access]
approval_seconds = 300          # Approval valid for 5 minutes
require_approval = true         # Can be disabled for convenience
approval_for = "session"        # "session" | "pid" | "connection"
```

- **`session`** (default): Approval covers all processes in the same terminal session. Best balance of security and usability.
- **`pid`**: Approval covers only the exact requesting PID and its children. More restrictive.
- **`connection`**: Approval covers a single socket connection. Most restrictive — each `grimoire get` requires re-approval.

### Approval Verification Methods

Approval does NOT use the master password — the vault is already unlocked. Instead:

1. **Biometric** (fingerprint / Touch ID) — preferred, fast, proves physical presence
2. **PIN** — fallback, same PIN as session re-verification
3. **System password** — via `pkexec` (Linux) or `osascript` with admin privileges (macOS)

The prompt agent (`grimoire-prompt`) already handles all three.

### Protocol Changes

New field on sensitive responses — when approval is needed, the service returns:

```json
{"jsonrpc": "2.0", "id": 1, "error": {
  "code": 1011,
  "message": "Access approval required",
  "data": {"session_pid": 1000}
}}
```

The client can then call:

```json
{"jsonrpc": "2.0", "id": 2, "method": "auth.approve", "params": {
  "scope_pid": 1000
}}
```

This triggers the GUI prompt. On success, the original request can be retried.

Or the service can handle this transparently: detect approval needed → spawn prompt → wait → complete the original request. The client sees a normal (slow) response.

### Implementation Approach

**Transparent approval** (recommended for v1): The service detects that the requesting process tree has no active approval, spawns the prompt agent, waits for the result, then completes the request. The client doesn't need protocol changes — it just sees a slower response the first time.

The service maintains an approval cache:

```rust
struct ApprovalCache {
    /// Map of session leader PID → approval expiry
    grants: HashMap<u32, Instant>,
}
```

On each sensitive request:
1. Get peer PID from `SO_PEERCRED`
2. Walk to session leader PID via `/proc/<pid>/stat` (field 6 = session ID, which equals the session leader PID)
3. Check `grants[session_leader_pid]`
4. If valid → proceed
5. If expired/missing → spawn prompt → on success, insert grant → proceed

### Process Tree Resolution

**Linux**: Read `/proc/<pid>/stat`, field 6 is the session ID (which equals the session leader's PID). Single syscall, no tree walking needed.

```rust
fn get_session_leader(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<&str> = stat.rsplit(')').next()?.split_whitespace().collect();
    // Field index 3 after the closing ')' is session ID (field 6 in stat)
    fields.get(3)?.parse().ok()
}
```

**macOS**: Use `getsid(pid)` from libc, which returns the session leader PID.

### Edge Cases

| Scenario | Behavior |
|----------|----------|
| SSH session (no display) | Falls back to terminal PIN prompt if `prompt.method = auto` |
| Process dies during approval | Approval still granted (by session, not PID) |
| Session leader dies | Approval expires; new session needs new approval |
| `grimoire run` (exec'd process) | The exec'd process has the same PID, same session — approval carries over |
| Systemd service calling grimoire | Different session, requires its own approval (or use `require_approval = false` for machine-to-machine) |
| `sudo grimoire get` | Different UID → rejected by socket UID check (existing security) |

## Consequences

### Positive

- **RCE resistance**: A compromised process in a different session can't silently read secrets — the GUI prompt will appear on the user's screen and the attacker can't interact with it
- **Minimal friction**: Approval covers the whole terminal session for 5 minutes. Normal interactive use feels unchanged.
- **No master password for approval**: Lightweight verification (fingerprint takes <1s)
- **`grimoire run` compatible**: exec preserves PID and session, so approval carries over to the injected process

### Negative

- **Same-session attacks still work**: If the attacker's RCE is within your shell session (e.g., a malicious npm postinstall script), they share your session leader PID and your approval. This is a fundamental limitation — the attacker is running as your commands do.
- **Platform-specific**: Session leader resolution differs between Linux (`/proc`) and macOS (`getsid`). Fallback to PID-only scoping on unsupported platforms.
- **Latency on first request**: The approval prompt adds ~1-3s to the first sensitive operation in a new session.
- **Not applicable in CI**: Headless environments should set `require_approval = false` in config.

### Security Model Summary

```
Threat: RCE from a different session (e.g., compromised service, reverse shell)
  → Blocked: requires GUI approval that attacker can't interact with

Threat: RCE from same session (e.g., malicious npm script in your terminal)
  → Partially mitigated: if within approval window, attacker has access
  → Mitigation: short approval_seconds, use `grimoire run` to scope env vars

Threat: Physical access with unlocked vault
  → Mitigated: approval required for each session, biometric proves physical presence

Threat: Root access
  → Not mitigated: root can read process memory, attach debugger (out of scope)
```
