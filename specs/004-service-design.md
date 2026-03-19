# ADR 004: Service Design

## Status

Accepted

## Context

The service is a long-running daemon that holds the authenticated session and decrypted vault. It must manage state transitions safely, protect sensitive data in memory, and handle concurrent client connections.

## Decision

### State Machine

```
LoggedOut ──login──▶ Locked ──unlock──▶ Unlocked
    ▲                  ▲                    │
    │                  └────lock────────────┘
    └───────────logout──────────────────────┘
```

**LoggedOut**: Only `auth.login` and `auth.status` accepted. No credentials in memory.

**Locked**: Has authenticated session (API token) but vault is encrypted. Accepts `auth.unlock`, `auth.status`, `auth.logout`, `sync.status`.

**Unlocked**: Full vault operations available. Decryption keys held in memory via sdk-internal's secure allocator (`bitwarden-crypto` KeyStore).

State transitions are serialized through a `tokio::sync::RwLock` to prevent races between concurrent client requests.

### Memory Security

At startup (Linux):

```rust
// Prevent swapping of sensitive data
libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);

// Prevent core dumps
libc::prctl(libc::PR_SET_DUMPABLE, 0);
```

Key lifecycle is managed entirely by `bitwarden-crypto`'s `KeyStore` — we never extract or copy keys outside the SDK's secure containers.

### Sync Strategy

- **On unlock**: Immediate sync to get fresh data
- **Background timer**: Sync every N seconds (default 300, configurable)
- **After writes**: Immediate sync after create/update/delete
- **Error handling**: Sync errors are logged but do not fail client requests. The service continues operating with stale data.

### Auto-Lock

- Configurable timer (default 900 seconds)
- Timer resets on any client activity
- On expiry: transition to Locked, scrub decryption keys

### Concurrency Model

- `tokio` async runtime
- One task per client connection
- Shared state behind `Arc<RwLock<ServiceState>>`
- Read lock for queries (vault.list, vault.get)
- Write lock for mutations (login, unlock, lock, create, update, delete)

### Systemd Integration (Phase 4)

```ini
[Unit]
Description=BitSafe Password Manager Service

[Service]
Type=notify
ExecStart=/usr/bin/bitsafe-service
Restart=on-failure
```

## Consequences

### Positive

- **Clear state model**: Each method specifies which state it requires; invalid requests get a clear error
- **Memory protection**: mlockall + no-dump + SDK's zeroizing allocator
- **Concurrent clients**: Multiple CLI invocations, SSH agent, etc. can connect simultaneously
- **Resilient sync**: Network issues don't break local operations

### Negative

- **Single point of failure**: If the service crashes, all clients lose access
- **Memory growth**: Decrypted vault stays in memory while unlocked (acceptable for typical vault sizes)
- **Lock contention**: Write-heavy workloads could block readers (unlikely in practice)
