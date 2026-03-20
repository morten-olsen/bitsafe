# Application Lifecycle

This document describes the full lifecycle of Grimoire — from first launch to daily use — and how access approval works identically for CLI commands and SSH agent signing.

## Vault States

```
                    ┌─────────────┐
                    │  Logged Out │
                    └──────┬──────┘
                           │ grimoire login <email>
                           │ (master password)
                           ▼
                    ┌─────────────┐
              ┌────▶│   Locked    │◀──── auto-lock (15 min idle)
              │     └──────┬──────┘
              │            │ master password
              │            │ (CLI prompt, GUI dialog, or `grimoire unlock`)
              │            ▼
              │     ┌─────────────┐
   lock/PIN   │     │  Unlocked   │
   exhausted  │     │             │
              │     │  ┌───────────────────────┐
              └─────│  │ approval cache        │
                    │  │  scope_key → expiry   │
                    │  └───────────────────────┘
                    └─────────────┘
```

**Logged Out**: no credentials. Must `grimoire login` with email + master password. One-time setup — login state persists to disk.

**Locked**: credentials stored but vault keys are not in memory. Master password required to unlock. Service starts here if login state exists from a previous session.

**Unlocked**: vault keys in memory, operations possible. Gated by access approval (see below).

## Access Approval

Every sensitive operation — reading a secret (`vault.get`), generating a TOTP code (`vault.totp`), resolving vault references (`vault.resolve_refs`), and SSH signing (`ssh.sign`) — requires access approval. The approval flow is identical for CLI commands and SSH agent requests.

### The flow

```
User runs a command or SSH client requests a signature
         │
         ▼
   Is vault unlocked?
         │
    no ──┤──── yes
         │       │
   CLI: prompt   ▼
   for master   Is caller approved?
   password     (approval cache lookup by scope key)
   & unlock          │
         │      no ──┤──── yes
         │           │       │
         ▼           ▼       ▼
                  Prompt    Proceed
                  user      with
                  (see      operation
                  below)
```

### How approval is granted

There are two paths to approval, depending on whether the user has access to the machine's display.

**Path 1: GUI prompt (interactive session)**

When the user has a display (local terminal, desktop session), the service spawns a GUI dialog automatically on the first sensitive operation:

```
$ grimoire get <id> -f password
  ┌──────────────────────────────┐
  │ Grimoire: approve vault access│
  │                              │
  │  [Fingerprint] [Enter PIN]   │
  └──────────────────────────────┘
  # user approves → result printed
```

The same happens for SSH signing — the first `ssh` or `git` command that needs a signature triggers the GUI dialog:

```
$ ssh git@github.com
  ┌────────────────────────────────┐
  │ Grimoire: approve SSH signing   │
  │                                │
  │  [Fingerprint] [Enter PIN]     │
  └────────────────────────────────┘
  # user approves → SSH connection proceeds
```

The prompt fallback chain is: biometric → PIN (if set) → master password dialog.

**Path 2: CLI pre-authorization (headless/SSH session)**

When there is no display (SSH session, headless server, CI), the GUI prompt is unavailable. The user pre-authorizes by entering their master password:

```
$ grimoire authorize
Master password: ********
Authorized. Session refreshed and access approved.

$ grimoire get <id> -f password    # no prompt, works immediately
$ ssh git@github.com              # no prompt, works immediately
```

The CLI also auto-prompts when needed — running a vault command on a locked vault prompts for the master password and unlocks + authorizes in one step:

```
$ grimoire list
Vault is locked.
Master password: ********
Vault unlocked.
<items listed>
```

### Scope

Approval is scoped — it doesn't apply system-wide. The scope determines which processes share an approval grant.

| Scope | Config value | Behavior |
|-------|-------------|----------|
| Terminal session | `session` (default) | All processes in the same terminal session share approval. This means `grimoire authorize` in one terminal approves `ssh` commands in that same terminal, but not in a different terminal. |
| Process | `pid` | Only the exact PID that was approved. Each command needs its own approval. |
| Connection | `connection` | Each socket connection requires fresh approval. Most restrictive. |

The scope key is resolved from the connecting process's PID:
- **Session scope**: PID → session leader PID (via `/proc/<pid>/stat` on Linux, `getsid` on macOS)
- **PID scope**: the process's own PID
- **Connection scope**: always 0 (never matches cache)

### Duration

Approval lasts for `approval_seconds` (default: 300 seconds / 5 minutes). After expiry, the next sensitive operation triggers a new prompt (GUI) or requires re-authorization (`grimoire authorize`).

## Unified Lifecycle: CLI and SSH

CLI commands and SSH signing go through the same gates:

| Gate | CLI commands | SSH agent |
|------|-------------|-----------|
| Vault must be unlocked | Auto-prompts for master password | Returns empty key list (no keys visible) |
| Access approval required | Checks approval cache → GUI prompt if missing → fails if headless | Checks approval cache → GUI prompt if missing → rejects sign if headless |
| Scope key resolution | From CLI process PID | From SSH client PID |
| Approval grant shared | Yes, same cache | Yes, same cache |

Because both paths use the same approval cache with the same scope key resolution, a single `grimoire authorize` (or a single GUI prompt approval) unlocks both CLI and SSH access for that terminal session.

### Example: SSH session workflow

```sh
# SSH into the machine
local$ ssh server

# Option A: explicit pre-authorization
server$ grimoire authorize
Master password: ********
Authorized.

# Option B: any vault command auto-prompts if locked
server$ grimoire list
Vault is locked.
Master password: ********
Vault unlocked.
<items listed>

# Both CLI and SSH now work for 5 minutes (same terminal session)
server$ grimoire get <id> -f password    # approved
server$ ssh git@github.com              # approved (same session scope)

# After 5 minutes, approval expires
server$ grimoire get <id> -f password
Authorization required.
Master password: ********              # re-authorize
<password printed>
```

### Example: desktop workflow

```sh
# First vault command triggers GUI dialog
$ grimoire get <id> -f password
  [GUI: approve vault access → fingerprint/PIN]
<password printed>

# SSH signing triggers GUI dialog (separate approval check)
$ ssh git@github.com
  [GUI: approve SSH signing → fingerprint/PIN]
  # connected

# Subsequent commands within 5 minutes — no prompts
$ grimoire get <other-id> -f password    # approved
$ git push                              # approved (SSH signing)
```

## PIN Exhaustion

If a PIN is set and the user fails it 3 times (configurable via `pin_max_attempts`), the vault auto-locks. This requires the master password to unlock again — the PIN alone is no longer sufficient.

## Auto-lock

The vault auto-locks after `auto_lock_seconds` of inactivity (default: 900 seconds / 15 minutes). Inactivity is measured by RPC socket activity — every vault or sync operation resets the timer.

SSH agent requests do **not** reset the auto-lock timer. If SSH is the only activity, the vault will auto-lock and keys will disappear from `ssh-add -l`.

To prevent auto-lock during long SSH-only sessions, either:
- Increase `auto_lock_seconds` in config
- Periodically run `grimoire status` (resets the timer)

## Configuration

```toml
# ~/.config/grimoire/config.toml

[service]
auto_lock_seconds = 900         # Inactivity auto-lock (default: 15 min)

[session]
pin_enabled = true              # Allow PIN for approval prompts
pin_max_attempts = 3            # PIN failures before auto-lock
biometric_enabled = true        # Try biometric before PIN

[access]
require_approval = true         # Gate vault ops behind approval (default: true)
approval_seconds = 300          # Approval duration (default: 5 min)
approval_for = "session"        # Scope: session | pid | connection

[prompt]
method = "auto"                 # auto | gui | terminal | none
```

## Quick Reference

| Action | What happens |
|--------|-------------|
| `grimoire login <email>` | One-time setup. Prompts for master password. Moves to Locked state. |
| `grimoire unlock` | GUI dialog for master password. Moves to Unlocked. Grants approval if password given directly. |
| `grimoire unlock --terminal` | Terminal prompt for master password. Moves to Unlocked. Grants approval. |
| `grimoire authorize` | Terminal prompt for master password. Verifies against server. Grants approval. |
| `grimoire list` | If locked, auto-prompts. If approval needed, GUI prompt or fail. |
| `grimoire get <id>` | Requires approval. GUI prompt if not approved, or pre-authorize with `grimoire authorize`. |
| `ssh git@github.com` | Requires approval. GUI prompt if not approved, or pre-authorize with `grimoire authorize`. |
| `grimoire lock` | Scrubs keys, clears all approvals. Master password required to unlock again. |
| `grimoire logout` | Clears everything. Must `grimoire login` again. |
