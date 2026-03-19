# Architecture

BitSafe is a daemon/client password manager wrapping Bitwarden's `sdk-internal`.

## Components

```
  Clients                          Service                         Backend
  ───────                          ───────                         ───────
  bitsafe (CLI) ── Unix socket ─┐
  GUI (future)  ── Unix socket ─┼─ bitsafe-service ──── HTTPS ─── Vaultwarden
  ssh/git       ── SSH agent  ──┘    ├── SSH agent (embedded, second socket)
                                     ├── bitsafe-prompt (subprocess for GUI auth)
                                     └── bitsafe-sdk (crypto only, SDK for decryption)
```

## Crate Dependency Graph

```
bitsafe-cli ────────┐
                    ├── bitsafe-protocol ── (serde, tokio)
bitsafe-service ────┤
    │               └── bitsafe-common ── (dirs, toml)
    ├── bitsafe-sdk ── bitwarden-pm (+ transitive sdk-internal crates)
    └── bitsafe-prompt (spawned, not linked)
```

## State Machine

```
LoggedOut ──login──▶ Locked ──unlock──▶ Unlocked
    ▲                  ▲                    │
    │                  └────lock────────────┘
    └───────────logout──────────────────────┘
```

Within Unlocked, sessions gate access:

```
Unlocked
  ├── Active (session valid, ops proceed)
  └── Expired (session lapsed, re-verify before ops)
        ├── biometric → Active
        ├── PIN (3 tries) → Active
        ├── PIN exhausted → Locked (full password required)
        └── master password → Active
```

## IPC Protocol

- Transport: Unix socket at `$XDG_RUNTIME_DIR/bitsafe/bitsafe.sock`
- Framing: `[4 bytes u32 BE length][UTF-8 JSON payload]`
- Protocol: JSON-RPC 2.0
- Auth model: socket `0600` + `SO_PEERCRED` UID validation

## Configuration

File: `~/.config/bitsafe/config.toml`

```toml
[server]
url = "https://vaultwarden.example.com"

[service]
auto_lock_seconds = 900
sync_interval_seconds = 300

[session]
duration_seconds = 300
pin_enabled = true
pin_max_attempts = 3
biometric_enabled = true

[prompt]
method = "auto"   # auto | gui | terminal | none

[ssh_agent]
enabled = true
```

## Implementation Status

| Component | Status |
|-----------|--------|
| Workspace + build | Done — compiles clean |
| IPC protocol | Done — codec, request/response types |
| Service state machine | Done — login/unlock/lock/logout/session |
| Prompt agent | Done — zenity/kdialog/osascript/terminal backends |
| Session + re-verify | Done — biometric/PIN/password fallback |
| Master password backoff | Done — exponential, server-enforced |
| SDK wrapper interface | Done — clean API surface defined |
| SDK wrapper wiring | Done — own HTTP for auth/sync, SDK for crypto/decryption |
| Background sync | Done — auto-sync on unlock + periodic (configurable) |
| SSH agent | Done — embedded in service, Ed25519 + RSA signing |
| TOTP | Done — `bitsafe totp <id>` and `bitsafe get <id> -f totp` |
| Single-field output | Done — `bitsafe get <id> -f password` for piping |
| Shell completions | Done — `bitsafe completions bash/zsh/fish` |
| Service installer | Done — `bitsafe service install` (systemd + launchd) |
| Persistent login | Done — survive service restart, only need unlock |
| Secret injection | Done — `bitsafe run -- <cmd>` with exec semantics, no TTY breakage |
| Encrypted IPC codec | Not started |
