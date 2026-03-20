# ADR 001: Architecture Overview

## Status

Accepted

## Context

We run Vaultwarden as a self-hosted password manager backend but want a better client experience than the official Bitwarden clients provide. Key requirements:

- **Unix-native**: First-class CLI, SSH agent integration, scriptability
- **Secure**: No reimplementation of crypto — reuse Bitwarden's battle-tested `sdk-internal`
- **Composable**: Multiple thin clients sharing a single authenticated session
- **Daemon-based**: A persistent service holds the decrypted vault so clients don't each need credentials

## Decision

### Service/Client Architecture

Grimoire uses a daemon/client split modeled after `ssh-agent` and `gpg-agent`:

```
  Clients (CLI, SSH Agent, GUI, rofi/dmenu)
       │
       │  Unix domain socket (JSON-RPC 2.0)
       │
  grimoire-service (daemon)
       │
       │  grimoire-sdk wrapper
       │
  bitwarden sdk-internal (Rust crates)
       │
       │  HTTPS
       │
  Vaultwarden
```

**grimoire-service** is a long-running daemon that:
- Authenticates with Vaultwarden via `sdk-internal`
- Holds the decrypted vault in memory when unlocked
- Exposes operations over a Unix domain socket
- Manages sync, auto-lock, and session lifecycle

**Clients** are thin and stateless:
- Connect to the service socket, send a JSON-RPC request, print the result, exit
- No crypto, no network calls, no vault state
- `grimoire-cli`: Interactive CLI for humans
- `grimoire-ssh-agent`: Speaks the SSH agent protocol, bridges to the service for key operations

### Language: Rust

All components are written in Rust:
- Direct consumption of `sdk-internal` as Cargo git dependencies — no FFI/WASM/binding layer
- Inherits sdk-internal's secure memory handling (`bitwarden-crypto` uses `ZeroizingAllocator`)
- Single toolchain: `cargo build` builds everything
- Tokio async runtime for the service

### Workspace Structure

```
grimoire/
  Cargo.toml              # Workspace root
  crates/
    grimoire-sdk/           # Wrapper over sdk-internal
    grimoire-protocol/      # IPC protocol definitions (shared)
    grimoire-service/       # The daemon
    grimoire-cli/           # CLI client
    grimoire-ssh-agent/     # SSH agent bridge
    grimoire-common/        # Shared utilities (socket paths, config)
```

## Consequences

### Positive

- **Security by delegation**: All crypto is handled by Bitwarden's audited code
- **Session sharing**: One login/unlock serves all clients (CLI, SSH, scripts)
- **Unix composability**: CLI output can be piped, scripted, integrated with rofi/dmenu
- **Incremental clients**: New clients only need to speak JSON-RPC over a Unix socket

### Negative

- **Daemon dependency**: Clients cannot function without the service running
- **SDK coupling**: We depend on an internal, unstable SDK (mitigated by the wrapper crate)
- **Single-user**: The daemon serves one user (same as ssh-agent — this is by design)

### Risks

| Risk | Mitigation |
|------|-----------|
| sdk-internal API breaks | `grimoire-sdk` wrapper isolates changes; pin to git rev |
| Vaultwarden API differences | Vaultwarden tracks upstream; patch in wrapper if needed |
| Token expiry in long-running daemon | SDK handles refresh; test early |
