# ADR 006: Interactive Prompt Agent and Session Management

## Status

Accepted

## Context

In the current design, the CLI client prompts for the master password and sends it to the service over the Unix socket. This works but has drawbacks:

1. **Every client must implement password prompting** — the CLI does it today, but the SSH agent, rofi scripts, and future GUI clients would all need their own prompting logic.
2. **No biometric support** — fingerprint/Touch ID can't be triggered from a CLI pipe.
3. **No session persistence** — every sensitive operation requires the vault to already be unlocked, with no intermediate "re-verify" step.

1Password's model is instructive: unlock once with the master password, then periodically re-verify with biometrics or a PIN via a GUI popup. The popup is owned by the *agent*, not the client, so any client (CLI, SSH, browser extension) gets the same interactive challenge.

## Decision

### Prompt Agent: `grimoire-prompt`

A separate binary that the **service** spawns as a subprocess when it needs interactive authentication from the user. The service itself remains headless.

```
Client ──"unlock"──▶ Service ──spawns──▶ grimoire-prompt (GUI)
                         ◀──credential──┘        │
                         │                        ▼
                     unlocks vault          User sees dialog
                         │
Client ◀──"ok"───────────┘
```

**Prompt modes:**

| Mode | When | What the user sees |
|------|------|--------------------|
| `password` | First unlock, or after lock | Master password dialog |
| `biometric` | Session re-verification | Fingerprint/Touch ID prompt |
| `pin` | Re-verification fallback (no biometric HW) | PIN entry dialog with attempt counter |

**Platform backends:**

| Platform | GUI dialogs | Biometric |
|----------|------------|-----------|
| macOS | Native dialog via `osascript` | Touch ID via `LocalAuthentication.framework` (codesigned helper) |
| Linux (Wayland/X11) | `zenity`, `kdialog`, or `rofi` (auto-detected) | `fprintd` over D-Bus |
| Headless/SSH | Terminal fallback on requesting client's TTY | Not available — PIN or password only |

**Communication protocol** (service ↔ prompt agent):

- Service spawns `grimoire-prompt <mode> [flags]` as a subprocess
- Prompt agent writes a single JSON line to stdout and exits:

```json
{"status": "ok", "credential": "<password-or-pin>"}
{"status": "verified"}
{"status": "cancelled"}
{"status": "error", "message": "..."}
```

- Exit codes: 0 = success, 1 = cancelled by user, 2 = error
- The service reads stdout, parses the result, and proceeds

### Session Management

After a successful unlock, the service starts a **session timer**. While the session is valid, operations proceed without re-authentication. When it expires, the next operation triggers a re-verify challenge.

```
                    ┌───────────────────────────────┐
                    │         Unlocked               │
                    │  ┌─────────┐    ┌───────────┐ │
  ──unlock──▶       │  │ Active  │───▶│  Expired  │ │
                    │  │         │timer│           │ │
                    │  │ (ops ok)│    │(re-verify) │ │
                    │  └────▲────┘    └─────┬─────┘ │
                    │       └──biometric/pin┘       │
                    └───────────────────────────────┘
```

- **Active**: All vault operations proceed normally. Timer resets on each successful re-verify.
- **Expired**: Vault keys are still in memory (not locked), but operations are gated behind a biometric/PIN re-verification. The service spawns `grimoire-prompt biometric` (or `pin` as fallback).
- **Lock**: Scrubs keys entirely. Next access requires full master password.

This means:
- First unlock = master password (always)
- Re-verify = biometric or PIN (lighter weight, keys stay in memory)
- Lock = full scrub, requires master password again

### PIN (No Backoff)

For systems without biometric hardware, PIN is the re-verification fallback.

- 3 attempts, no delay between them
- After 3 failures: vault is locked, requiring full master password to re-unlock

PIN is simple and fast — if you know it, you get through immediately. If you don't, the vault locks quickly to prevent brute force.

The PIN is set by the user via `auth.set_pin`, stored only in service memory (never on disk), and compared in constant time.

### Master Password Backoff

Failed master password attempts (login or unlock) incur exponential backoff enforced by the service:

```
Attempt 1: immediate
Attempt 2: 1s delay
Attempt 3: 2s delay
Attempt 4: 4s delay
Attempt N: min(2^(N-2), 30) seconds delay
```

The delay is enforced server-side — the service rejects attempts made before the backoff period expires. The counter resets on a successful login/unlock.

### Protocol Changes

**`auth.unlock` — password now optional:**

```json
{"jsonrpc": "2.0", "id": 1, "method": "auth.unlock", "params": {}}
```

When no password is provided, the service spawns the prompt agent. When a password is provided (existing behavior), it's used directly — this preserves backward compatibility for scripted/automated usage.

**New method: `auth.set_pin`:**

```json
{"jsonrpc": "2.0", "id": 1, "method": "auth.set_pin", "params": {"pin": "1234"}}
```

Sets the session PIN. Requires Unlocked + Active session. The PIN is held in service memory only.

**New method: `auth.verify`:**

```json
{"jsonrpc": "2.0", "id": 1, "method": "auth.verify", "params": {}}
```

Explicitly triggers a re-verification (biometric/PIN prompt). Useful for clients that want to pre-verify before a sensitive operation. Normally this happens automatically when the session expires.

### Configuration

```toml
[session]
duration_seconds = 300          # Session validity period
prompt_method = "auto"          # auto | gui | terminal | none
pin_enabled = true              # Allow PIN for re-verification
pin_max_attempts = 3            # Lock vault after N failed PINs
biometric_enabled = true        # Try biometric before PIN

[prompt]
gui_backend = "auto"            # auto | zenity | kdialog | osascript
```

`prompt_method = "none"` disables interactive prompting entirely — clients must always provide passwords in the RPC params. This is useful for fully headless/scripted environments.

## Consequences

### Positive

- **Unified prompt**: Every client (CLI, SSH agent, rofi, GUI) gets the same interactive challenge without implementing prompting
- **Biometric support**: Touch ID / fingerprint works for any client, not just GUI ones
- **Session model**: Reduces friction — unlock once with password, re-verify with fingerprint
- **Platform isolation**: All platform-specific code lives in `grimoire-prompt`, keeping the service portable
- **Backward compatible**: Clients that provide a password explicitly still work

### Negative

- **New binary to distribute**: `grimoire-prompt` must be installed alongside `grimoire-service`
- **Platform complexity**: Biometric integration varies across macOS/Linux/distros
- **Security surface**: PIN in memory is weaker than master password re-entry, but matches 1Password's trade-off
- **Subprocess spawning**: Adds latency to the unlock/re-verify path (acceptable for interactive operations)
