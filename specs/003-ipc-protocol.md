# ADR 003: IPC Protocol

## Status

Accepted

## Context

The service and clients communicate over IPC. We need a protocol that is:
- Simple to implement in any language (for future clients)
- Debuggable (human-readable)
- Extensible (new methods without breaking old clients)
- Secure enough for local-only communication

## Decision

### Transport: Unix Domain Socket

- Path: `$XDG_RUNTIME_DIR/bitsafe/bitsafe.sock`
- Socket mode: `0600` (owner-only)
- `SO_PEERCRED` validation on each connection (same UID check on Linux)
- Same trust model as `ssh-agent`

### Framing: Length-Prefixed JSON

```
[4 bytes: u32 big-endian payload length][payload: UTF-8 JSON]
```

The codec is abstracted behind a trait for future extensibility:

```rust
#[async_trait]
pub trait Codec: Send + Sync {
    async fn write_message<W: AsyncWrite + Unpin + Send>(
        &self, writer: &mut W, msg: &Message,
    ) -> Result<()>;

    async fn read_message<R: AsyncRead + Unpin + Send>(
        &self, reader: &mut R,
    ) -> Result<Message>;
}
```

Initial implementation: `PlainCodec` (length-prefixed JSON, no encryption).
Future: `EncryptedCodec` wrapping messages in NaCl boxes.

### Protocol: JSON-RPC 2.0

Standard JSON-RPC 2.0 with string method names and structured params.

**Request:**
```json
{"jsonrpc": "2.0", "id": 1, "method": "vault.list", "params": {"type": "login"}}
```

**Response:**
```json
{"jsonrpc": "2.0", "id": 1, "result": [...]}
```

**Error:**
```json
{"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": "Vault is locked"}}
```

### Methods

| Method | State Required | Description |
|--------|---------------|-------------|
| `auth.login` | LoggedOut | Email + master password login |
| `auth.unlock` | Locked | Unlock with master password |
| `auth.lock` | Unlocked | Lock vault, scrub keys |
| `auth.logout` | Any | Log out entirely |
| `auth.status` | Any | Current state, email, server |
| `vault.list` | Unlocked | List items (with optional filters) |
| `vault.get` | Unlocked | Get single item by ID |
| `vault.create` | Unlocked | Create cipher |
| `vault.update` | Unlocked | Update cipher |
| `vault.delete` | Unlocked | Soft-delete cipher |
| `vault.totp` | Unlocked | Generate TOTP code for item |
| `sync.trigger` | Unlocked | Force immediate sync |
| `sync.status` | Locked/Unlocked | Last sync time |
| `ssh.list_keys` | Unlocked | List SSH keys in vault |
| `ssh.sign` | Unlocked | Sign data with SSH key |

### Server-Push Notifications

For long-lived connections, the server may push notifications (JSON-RPC notifications, no `id`):

```json
{"jsonrpc": "2.0", "method": "vault.locked", "params": {}}
{"jsonrpc": "2.0", "method": "vault.synced", "params": {"timestamp": "..."}}
```

### Error Codes

| Code | Meaning |
|------|---------|
| -32600 | Invalid request |
| -32601 | Method not found |
| -32602 | Invalid params |
| -32603 | Internal error |
| 1000 | Vault locked (method requires unlocked state) |
| 1001 | Not logged in |
| 1002 | Already logged in |
| 1003 | Auth failed |
| 1004 | Sync failed |
| 1005 | Item not found |

## Consequences

### Positive

- **Language-agnostic**: Any language that can write to a Unix socket and parse JSON can be a client
- **Debuggable**: `socat` can inspect traffic
- **Extensible**: New methods are additive, old clients ignore unknown notifications
- **Proven framing**: Length-prefixed messages avoid delimiter/escaping issues

### Negative

- **No encryption on IPC**: Relies entirely on socket permissions. Acceptable for same-user, same-machine communication (ssh-agent model), but noted as a future improvement path via the Codec trait.
- **JSON overhead**: Slightly more verbose than binary protocols, but vault operations are infrequent enough that this doesn't matter.
