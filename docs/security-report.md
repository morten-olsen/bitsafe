# Grimoire Security Audit Report

**Date**: 2026-03-21
**Scope**: Full codebase audit — all crates, native prompt binaries, dependencies, build configuration
**Methodology**: Manual code review with threat-model-driven analysis across attack scenarios
**Previous audit**: 2026-03-20 (see git history for diff)

---

## Executive Summary

Grimoire is a single-user password manager daemon with a Unix socket IPC model analogous to `ssh-agent`. This holds the keys to the kingdom — compromise means every password, SSH key, and TOTP seed the user has.

Since the last audit (2026-03-20), significant improvements have been made:

**Fixed from previous audit:**
- **C1/C2 (Password re-verification bypass)**: Eliminated entirely. Access approval now verifies passwords against the server (`approval.rs:81-96`). A prompt binary that returns a fake password is rejected.
- **H6 (Config-based security downgrade)**: Security parameters are now hardcoded constants in `config.rs:4-16` — `AUTO_LOCK_SECONDS`, `PIN_MAX_ATTEMPTS`, `APPROVAL_SECONDS` cannot be overridden via config file. Config only controls operational settings (server URL, prompt method, SSH agent enabled).
- **M1 (Missing `deny_unknown_fields`)**: All `RequestParams` variant structs now have `#[serde(deny_unknown_fields)]` (`request.rs:42-140`).
- **H1 (Partial — Secret zeroization)**: Password and PIN fields across the protocol and state layers now use `Zeroizing<String>`. Token store uses `Zeroizing<String>`. Debug impls redact secrets.
- **IPC encryption added**: X25519 key exchange + ChaCha20-Poly1305 AEAD with directional keys, replay protection, and monotonic nonce counters. This is defense-in-depth — socket permissions remain the primary trust boundary.

**New since last audit:**
- Scoped access approval refactored into shared `approval.rs` module used by both JSON-RPC and SSH agent paths
- RSA SSH key signing support added
- `grimoire approve` command for headless sessions
- CI release pipeline with cosign signing

This audit identified **2 critical findings**, **5 high-severity findings**, and **10 medium-severity findings**. All immediate and short-term findings have been addressed (see Post-Audit Fixes below). The remaining open findings are medium-term items.

### Post-Audit Fixes (2026-03-21)

All immediate and short-term findings from this audit have been fixed:

| Finding | Status | Commit |
|---------|--------|--------|
| **C1** SSH key zeroization | **Fixed** — Ed25519 raw bytes zeroized; `PrivateKey`/`SigningKey` types lack `Zeroize` impl (documented as residual gap) | `security(ssh): zeroize SSH private key material after signing` |
| **C2** PATH prompt binary | **Fixed** — PATH fallback removed entirely, only adjacent to `current_exe()` | `security(service): remove PATH fallback for prompt binary discovery` |
| **H1** Password SDK boundary | **Mitigated** — `Zeroizing<String>` passed through to SDK; SDK requires plain `String` for `InitUserCryptoRequest` (documented gap) | `security(sdk): pass Zeroizing<String> through SDK boundary and bound KDF params` |
| **H2** Connection limits | **Fixed** — 64 max connections, 10s handshake timeout, 60s idle timeout | `security(ipc): add connection limits, timeouts, and reduce message size` |
| **H3** Backoff persistence | **Fixed** — persisted to `backoff.json` | `security(auth): persist password backoff counter across restarts` |
| **H4** Memory hardening | **Fixed** — all hardening failures fatal, no escape hatch; macOS `PT_DENY_ATTACH` added | `security(service): make memory hardening fatal, add macOS PT_DENY_ATTACH` |
| **H5** KDF parameter bounds | **Fixed** — PBKDF2 max 2M iter, Argon2 max 4096 MiB / 16 threads / 20 iter | `security(sdk): pass Zeroizing<String> through SDK boundary and bound KDF params` |
| **M5** SSH agent UID check | **Fixed** — UID peer verification in `new_session()` | `security(ssh): add UID peer verification to SSH agent socket` |
| **M7** Message size limit | **Fixed** — reduced from 16 MiB to 1 MiB | `security(ipc): add connection limits, timeouts, and reduce message size` |
| **M8** cargo-audit in CI | **Fixed** — runs on every push/PR; RUSTSEC-2023-0071 and RUSTSEC-2026-0049 ignored (unfixable SDK transitive deps) | `security(ci): add cargo-audit to CI pipeline` |
| **M10** Config permissions | **Fixed** — refuses to start with group/world-writable config, no fallback | `security(common): reject world/group-writable config file` |

### Remaining open findings (medium-term)

| Finding | Summary |
|---------|---------|
| **M1** | Sync worker holds read lock during HTTP call |
| **M2** | `login.json` has no integrity protection (HMAC) |
| **M3** | `/proc/<pid>/stat` TOCTOU in session leader resolution |
| **M4** | Error messages leak vault item names/counts |
| **M6** | `tokio` uses `features = ["full"]` |
| **M9** | CI actions not pinned to commit SHAs |

---

## Threat Scenarios

Each finding is evaluated against these scenarios:

| Scenario | Attacker Profile |
|---|---|
| **S1: Remote Code Execution** | Attacker has shell access in a user's terminal session (e.g., malicious npm package, compromised dev tool) |
| **S2: Same-user lateral** | Attacker controls a separate process as the same user (e.g., compromised cron job, browser extension with native messaging) |
| **S3: Physical access** | Attacker has brief physical access to an unlocked machine |
| **S4: Supply chain** | Compromised dependency or build tool |
| **S5: Network** | Attacker on the same network as the Bitwarden/Vaultwarden server |
| **S6: Root/privileged** | Attacker has root or can escalate (out of scope for primary defense, but noted where mitigations exist) |

---

## Critical Findings

### C1: SSH private key not zeroized after signing

**Location**: `crates/grimoire-sdk/src/ssh.rs:65-68`, `ssh.rs:85-114`
**Scenarios**: S3, S6

When signing with an SSH key, the parsed `ssh_key::PrivateKey` is held as a local variable and dropped without zeroization:

```rust
// ssh.rs:65-68
let private_key = ssh_key::PrivateKey::from_openssh(&ssh_key_view.private_key)?;
sign_with_key(&private_key, data, flags)
// private_key dropped here — NOT zeroized
```

Inside `sign_with_key`, the situation is worse:

```rust
// ssh.rs:85 (Ed25519)
let signing_key = SigningKey::from_bytes(&kp.private.to_bytes());
// kp.private.to_bytes() creates a temporary [u8; 32] with raw private key bytes
// SigningKey is not wrapped in Zeroizing
```

```rust
// ssh.rs:96-102 (RSA)
let d = BigUint::from_bytes_be(kp.private().d().as_bytes());
let p = BigUint::from_bytes_be(kp.private().p().as_bytes());
let q = BigUint::from_bytes_be(kp.private().q().as_bytes());
// RSA private factors as plain BigUint — not zeroized on drop
```

**Why this is critical for a password manager**: SSH keys stored in Grimoire are often the most operationally sensitive credentials a user has — they grant access to production servers, cloud infrastructure, and code signing. After every SSH signing operation, the full private key material persists in freed heap memory until overwritten by unrelated allocations. A memory dump (core dump, swap, hibernation, or a same-user ptrace) captured at any point after signing reveals the raw private key.

The `ssh_key` crate's `PrivateKey` type *does* implement `Zeroize`. The fix is wrapping it in `Zeroizing<>`. The `ed25519_dalek::SigningKey` and `rsa::RsaPrivateKey` also implement `Zeroize` and can be wrapped.

**Recommendation**:
1. Wrap `private_key` in `Zeroizing<ssh_key::PrivateKey>` at `ssh.rs:65`
2. Wrap `signing_key` in `Zeroizing<SigningKey>` at `ssh.rs:85`
3. For RSA: wrap `RsaPrivateKey` in `Zeroizing<>` at `ssh.rs:102`
4. Explicitly zeroize the intermediate `BigUint` values for RSA (d, p, q)

### C2: Prompt binary discovered via PATH — master password interception

**Location**: `crates/grimoire-service/src/prompt.rs:43-57`
**Scenarios**: S1, S4

The service trusts whatever binary it finds as `grimoire-prompt` without integrity verification. The discovery chain:

1. Native binary next to `current_exe()` — relatively safe
2. Generic binary next to `current_exe()` — relatively safe
3. `which` lookup for native binary — **PATH-dependent**
4. Bare `"grimoire-prompt"` — **PATH-dependent**

```rust
// prompt.rs:43-56
if !native_name.is_empty() {
    if let Ok(output) = std::process::Command::new("which").arg(native_name).output() {
        if output.status.success() {
            return native_name.into();
        }
    }
}
"grimoire-prompt".into()  // Falls back to bare name — resolved via PATH at exec time
```

An attacker who can place a binary earlier in `$PATH` (trivial in S1 — many dev tools prepend to PATH) can intercept the master password. While password-based approval now verifies against the server (`approval.rs:81-96`), the attacker still captures the plaintext master password before it is hashed. The biometric flow (`approval.rs:40-44`) trusts the prompt binary completely — a malicious binary returning `{"status":"verified"}` grants vault access without any server verification.

**Why this is critical**: Unlike the IPC channel (protected by socket permissions + encryption), the prompt binary is discovered via PATH which is user-controlled and routinely manipulated by development tools. A malicious `grimoire-prompt-linux` in `~/.local/bin/` or `~/.npm-global/bin/` intercepts every password entry.

**Recommendation**:
1. **Remove the PATH fallback entirely.** Only look for prompt binaries adjacent to `current_exe()`. If not found, fail with a clear error.
2. **Verify binary ownership and permissions**: binary must be owned by root or the current user, and must not be world-writable.
3. If PATH discovery is retained for development convenience, at minimum verify the binary's owner and permissions before execution.

---

## High Findings

### H1: Password `String` copy at the SDK boundary breaks zeroization chain

**Location**: `crates/grimoire-sdk/src/auth.rs:173`, `auth.rs:112`, `auth.rs:142`
**Scenarios**: S3, S6

Passwords are properly `Zeroizing<String>` through the protocol and state layers. But at the SDK boundary, they are converted to plain `String`:

```rust
// auth.rs:173 — inside InitUserCryptoRequest
method: InitUserCryptoMethod::MasterPasswordUnlock {
    password: password.to_string(),  // Plain String — NOT zeroized on drop
```

```rust
// auth.rs:112, 142 — master password hash
let password_hash = master_auth.master_password_authentication_hash.to_string();
```

The SDK's `ZeroizingAllocator` partially mitigates this (it zeros memory when the allocator frees it), but `password.to_string()` allocates through the standard allocator, creating an unprotected copy. Additionally, `state.rs:233` takes `password: &str`, and `state.rs:330` takes `password: &str`, meaning the `Zeroizing` wrapper is stripped at the function boundary.

**Impact**: The master password — the single credential protecting the entire vault — persists as a plain `String` in freed heap memory. This is the highest-value target for a memory extraction attack.

**Recommendation**: Accept `Zeroizing<String>` through the full call chain to the SDK. Where the SDK requires `String`, document this as a known gap and minimize the lifetime of the copy. Use `Zeroizing::new(password.to_string())` where the SDK takes ownership, so the clone is at least tracked.

### H2: No connection limits, timeouts, or rate limiting on the Unix socket

**Location**: `crates/grimoire-service/src/server.rs:78-130`, `crates/grimoire-service/src/session.rs:19-55`
**Scenarios**: S1, S2

The accept loop spawns an unbounded number of tokio tasks with no:
- Maximum connection count
- Per-connection read/write timeout
- Handshake timeout
- Rate limiting on RPC calls
- Per-connection memory quota

```rust
// server.rs:116-118 — no limit on spawned tasks
let client_state = shared_state.clone();
tokio::spawn(async move {
    session::handle_client(stream, client_state, peer_pid).await;
});
```

```rust
// session.rs:35-54 — read loop with no idle timeout
loop {
    let request: Request = match read_message(&mut reader, &codec).await {
        // Blocks indefinitely waiting for next message
```

The handshake (`session.rs:23`) also has no timeout — a client that sends partial data blocks the handler forever.

A malicious same-user process can:
1. **Connection flood**: Open thousands of connections, each triggering X25519 (CPU) + task allocation (memory)
2. **Slow client**: Connect and send 1 byte/second — `read_exact()` blocks indefinitely
3. **Memory exhaustion**: Send a valid 4-byte length prefix for a 16 MiB message on each of many connections — `vec![0u8; len as usize]` allocates immediately
4. **Lock starvation**: Flood `vault.list` requests to hold read locks continuously

**Impact**: Denial of service against the vault service. The user cannot access their passwords.

**Recommendation**:
1. Add `tokio::time::timeout(Duration::from_secs(30), ...)` wrapping `read_message` calls and the handshake
2. Limit concurrent connections with a `tokio::sync::Semaphore` (e.g., 64 max)
3. Reduce `MAX_MESSAGE_SIZE` from 16 MiB to 1 MiB — vault payloads are JSON summaries
4. Add per-connection idle timeout (60s of no messages → disconnect)

### H3: Backoff counter resets on service restart

**Location**: `crates/grimoire-service/src/state.rs:103-104,124-125`
**Scenarios**: S1, S2, S3

`master_password_attempts` and `last_password_attempt` are in-memory fields initialized to `0`/`None` on every startup:

```rust
// state.rs:124-125 (in ServiceState::new)
master_password_attempts: 0,
last_password_attempt: None,
```

An attacker who can restart the service (e.g., `kill -9` from same-user) gets unlimited password attempts with no backoff. With `Restart=on-failure` in the systemd unit:
1. Try 2 passwords (no backoff on first)
2. Kill the service
3. Wait for restart (5s default)
4. Repeat — ~24 guesses/minute with zero backoff

For a 4-character numeric PIN, 10,000 combinations ÷ 2 per cycle = ~5,000 cycles × 5s = ~7 hours for full enumeration (if the attacker can also bypass PIN lockout via restart). More practically, the master password backoff is what's being bypassed — the PIN lockout is enforced correctly within a single process lifetime.

**Recommendation**: Persist the attempt counter and last attempt timestamp to a file (e.g., `~/.local/share/grimoire/backoff.json` with mode 0600). Load on startup. Clear only on successful authentication.

### H4: Memory hardening is non-fatal and absent on macOS

**Location**: `crates/grimoire-service/src/main.rs:37-51`
**Scenarios**: S3, S6

`mlockall` and `PR_SET_DUMPABLE` failures are logged as warnings and execution continues:

```rust
// main.rs:43-44
if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
    tracing::warn!("mlockall failed — sensitive data may be swapped to disk");
}
```

On macOS, no memory hardening is attempted at all (`#[cfg(target_os = "linux")]` guard).

**Why this matters for a password manager**: The vault service holds decrypted key material, master password hashes, and SSH private keys in memory. Without `mlockall`, the OS can swap these pages to disk where they persist after process exit. Without `PR_SET_DUMPABLE(0)`, any same-user process can `ptrace` and read memory. On macOS, where there is no `mlockall`, pages containing the entire vault can be swapped at any time.

**Recommendation**:
1. **Linux**: Make `mlockall` failure fatal by default, with an explicit opt-out flag (`--allow-insecure-memory`) for constrained environments
2. **macOS**: Use `mlock()` on specific allocations. Use `ptrace(PT_DENY_ATTACH, 0, 0, 0)` to prevent debugger attachment.
3. Both platforms: log the effective memory hardening status at startup so the user knows their protection level

### H5: KDF parameters from server accepted without upper bounds

**Location**: `crates/grimoire-sdk/src/auth.rs:254-293`
**Scenarios**: S5

The prelogin response provides KDF parameters used directly for key derivation:

```rust
// auth.rs:258-261
let iterations = data["kdfIterations"]
    .as_i64()
    .or_else(|| data["KdfIterations"].as_i64())
    .unwrap_or(600000);
```

No upper bound is checked. A compromised or malicious server can specify:
- `iterations: 4294967295` for PBKDF2 → CPU exhaustion (minutes to hours of computation)
- `memory: 4294967295` for Argon2 → attempts to allocate ~4 GiB → OOM kill or swap thrashing
- `parallelism: 4294967295` for Argon2 → spawns billions of threads → system hang

**Impact**: A network attacker who can MITM the prelogin request (TLS-stripping, DNS hijacking, or compromised CA) or a malicious Vaultwarden instance can deny service or force excessive resource consumption. This also applies if `login.json` is tampered to point at a malicious server (see M2).

**Recommendation**: Add reasonable upper bounds before passing to the SDK:
- PBKDF2 iterations: max 2,000,000
- Argon2 memory: max 4,096 MiB
- Argon2 parallelism: max 16
- Argon2 iterations: max 20

---

## Medium Findings

### M1: Background sync holds read lock during HTTP call

**Location**: `crates/grimoire-service/src/sync_worker.rs:39-48`
**Scenarios**: Operational

```rust
// sync_worker.rs:39-48
let sync_result = {
    let s = state.read().await;
    // ... holds read lock during entire HTTP call
    sdk.sync().sync(server_url).await  // Network call — could take seconds
};
```

While the read lock is held, no state mutations (lock, logout, set PIN) can proceed. If the server is slow or unreachable, this blocks all state mutations for the HTTP timeout duration (reqwest default: 30s).

**Recommendation**: Extract `sdk` and `server_url` from the read lock, drop the lock, then sync. The SDK is `Arc<Mutex<>>` so it's safe to use without the state lock.

### M2: Persistent login state file has no integrity protection

**Location**: `crates/grimoire-sdk/src/persist.rs:58-74`
**Scenarios**: S2

`login.json` stores email and server URL with mode 0600 but no integrity check. A same-user attacker can modify `server_url` to point at a malicious server. On next unlock, the service sends the master password hash to the attacker's server.

**Recommendation**: Add an HMAC over the file contents keyed with a per-installation random secret stored in a separate file. This detects tampering — the service refuses to load a modified file.

### M3: `/proc/<pid>/stat` TOCTOU in session leader resolution

**Location**: `crates/grimoire-service/src/peer.rs:30-37`
**Scenarios**: S2

The session leader PID is read from `/proc/<pid>/stat` at connection time. Between read and use, the PID could be recycled. If an attacker's process gets the same PID as a previously approved session leader, it inherits the approval grant.

**Recommendation**: Store `(pid, start_time)` pairs in the approval cache. Read `starttime` from `/proc/<pid>/stat` field 22 and verify on cache lookup.

### M4: Error messages leak vault metadata

**Location**: `crates/grimoire-service/src/session.rs:550-564`
**Scenarios**: S1, S2

Vault reference resolution errors include item names and counts:
- `"No item named 'GitHub API'"` — confirms the item does not exist
- `"Ambiguous name 'Git' matches 3 items"` — reveals count of matching items

**Recommendation**: Return generic errors: `"Reference resolution failed"`. Log details server-side.

### M5: SSH agent socket lacks UID peer verification

**Location**: `crates/grimoire-service/src/ssh_agent.rs:28-43`, `server.rs:69-74`
**Scenarios**: S2

The main JSON-RPC socket has an explicit UID check (`server.rs:89-100`), but the SSH agent socket delegates connection handling to `ssh_agent_lib::agent::listen()` which does not perform UID verification. The SSH agent relies solely on socket filesystem permissions (0600) for access control.

While socket permissions are typically sufficient, the main socket has defense-in-depth via an explicit UID check. The SSH agent socket should have parity.

**Recommendation**: Either verify UID inside `SshAgentHandler::new_session()` or wrap the listener with a UID-checking layer before passing to the SSH agent library.

### M6: `tokio` uses `features = ["full"]` — unnecessarily wide attack surface

**Location**: `Cargo.toml:39`
**Scenarios**: S4

`tokio = "full"` enables ~40 feature flags including `process`, `fs`, `io-std`, and others not needed by the service. Each feature pulls in additional code.

**Recommendation**: Replace with explicit features: `["macros", "rt-multi-thread", "time", "net", "io-util", "signal", "sync"]`.

### M7: 16 MiB message size limit is excessive

**Location**: `crates/grimoire-protocol/src/codec.rs:20`
**Scenarios**: S1, S2

`MAX_MESSAGE_SIZE` is 16 MiB. A typical vault response with thousands of entries is well under 1 MiB. Combined with no connection limit (H2), an attacker can open many connections and allocate 16 MiB on each.

**Recommendation**: Reduce to 1 MiB or 4 MiB.

### M8: No `cargo-audit` or `cargo-deny` in CI

**Location**: `.github/workflows/ci.yml`
**Scenarios**: S4

524 transitive dependencies are never checked for known vulnerabilities. This is a password manager — every dependency is trusted with vault secrets. The `digest 0.11.1` crate is yanked, and 39 pre-release crate versions are in the lockfile.

**Recommendation**: Add `cargo audit` to the CI pipeline. Consider `cargo-deny` for license and advisory checking. Investigate why `digest 0.11.1` was yanked.

### M9: CI actions not pinned to commit SHAs

**Location**: `.github/workflows/*.yml`
**Scenarios**: S4

GitHub Actions are referenced by tag (`actions/checkout@v4`, `sigstore/cosign-installer@v3`) rather than commit SHA. A compromised action repository could inject malicious code into the release pipeline, which signs binaries with cosign.

**Recommendation**: Pin all third-party actions to full commit SHAs. Use Dependabot or Renovate to keep them updated.

### M10: Config file permissions not checked

**Location**: `crates/grimoire-common/src/config.rs:100-112`
**Scenarios**: S2

The config file is loaded without checking ownership or permissions. While security parameters are hardcoded (not configurable), `server.url` IS configurable and is security-relevant — a malicious server URL redirects the master password hash. `prompt.method = "none"` disables interactive prompting.

**Recommendation**: Warn (or refuse to start) if the config file is group/world-writable (`mode & 0o022 != 0`).

---

## Low Findings

### L1: `$XDG_RUNTIME_DIR` trusted without validation

**Location**: `crates/grimoire-common/src/socket.rs:8-9`

The code trusts `$XDG_RUNTIME_DIR` unconditionally. An attacker who can set this env var could redirect socket connections. Mitigated by: this variable is typically set by the login system and is not user-modifiable in normal configurations.

### L2: `request_identities` in SSH agent returns keys without approval

**Location**: `crates/grimoire-service/src/ssh_agent.rs:55-85`

Listing SSH public keys does not require approval — only signing does. Public keys are not secrets, but key names could leak information about what services the user has keys for.

### L3: Shared secret and derived keys not zeroized in codec

**Location**: `crates/grimoire-protocol/src/codec.rs:89-119`

The `shared_secret: [u8; 32]` passed to `EncryptedCodec::new_client/new_server` and the intermediate `c2s_key`/`s2c_key` arrays from `derive_directional_keys` are stack-allocated and not zeroized when they go out of scope.

### L4: `expect()` in production code

**Location**: `crates/grimoire-sdk/src/lib.rs:55`, `crates/grimoire-protocol/src/codec.rs:77,81,171`

Four `expect()` calls exist in non-test code. The codec ones are for mathematically guaranteed conditions (HKDF output length, checked slice length). The `lib.rs:55` one panics if the data directory cannot be determined — this is a startup precondition but still violates the project's no-panic rule.

### L5: Missing `// SAFETY:` comment on `getsid()`

**Location**: `crates/grimoire-service/src/peer.rs:42`

The `unsafe { libc::getsid(pid as i32) }` block lacks the `// SAFETY:` comment required by project conventions. Functionally correct but inconsistent.

### L6: `TokenResponse` fields are plain `String`

**Location**: `crates/grimoire-sdk/src/auth.rs:297-304`

The `access_token`, `key`, and `private_key` fields in `TokenResponse` are deserialized as plain `String` before being wrapped in `Zeroizing`. The deserialization buffer is not zeroized.

### L7: Duplicate `PIN_MAX_ATTEMPTS` constant

**Location**: `crates/grimoire-common/src/config.rs:14`, `crates/grimoire-prompt/src/pin.rs:2`

`PIN_MAX_ATTEMPTS` is defined in two places. If one is updated without the other, behavior diverges.

### L8: JWT parsed without signature verification

**Location**: `crates/grimoire-sdk/src/auth.rs:220-229`

The JWT from the login response is decoded without verifying its signature to extract the `sub` (user ID) claim. A malicious server could send a JWT with a forged `sub` claim. Practical impact depends on how the SDK uses this user ID internally.

### L9: No HTTP response body size limit

**Location**: `crates/grimoire-sdk/src/auth.rs`, `crates/grimoire-sdk/src/sync.rs`

The `reqwest::Client` is used without configuring a response body size limit. A malicious server could send an extremely large sync response to exhaust memory.

### L10: Server error messages forwarded to client

**Location**: `crates/grimoire-sdk/src/auth.rs:336-343`

Server-provided error messages are propagated into `SdkError::AuthFailed`. A malicious server could inject misleading error text displayed to the user.

---

## Positive Findings

These are security properties that are well-implemented and should be preserved:

### P1: Zero panic paths in production code

No `unwrap()` or `panic!()` in any crate. The few `expect()` calls are on mathematically guaranteed conditions. All errors use `Result<T>` propagation. This eliminates panic-based denial of service.

### P2: Scoped access approval is mandatory and server-verified

The approval system (`approval.rs`) is always active, not configurable, and uses a defense-in-depth cascade:
1. Biometric (requires physical presence at the device)
2. PIN (3 attempts, then auto-lock)
3. Master password **verified against the server** (`approval.rs:81-96`) — a malicious prompt binary returning a fake password is rejected

This is a significant improvement over the previous audit where password approval was not verified.

### P3: Security parameters are hardcoded constants

Auto-lock timeout (900s), PIN max attempts (3), approval duration (300s), and sync interval (300s) are hardcoded in `config.rs:4-16`. The config file cannot override them. A test (`config.rs:163-183`) explicitly verifies that old config sections with security overrides are ignored. This eliminates config-based downgrade attacks identified in the previous audit.

### P4: Encrypted IPC with replay protection

The X25519 + ChaCha20-Poly1305 codec (`codec.rs:47-194`) provides:
- Directional keys via HKDF-SHA256 (prevent nonce reuse)
- Monotonic counter nonces (prevent replay)
- Ephemeral keys per connection (forward secrecy)
- Properly documented as unauthenticated (socket permissions are the trust boundary)

### P5: `exec()` semantics for secret injection

`grimoire run` uses `execvp()` — the Grimoire process is replaced entirely. No wrapper process lingers with secrets in memory.

### P6: Crypto delegation to the SDK

Grimoire never handles raw cryptographic keys for vault operations. All crypto goes through the SDK's `PasswordManagerClient` which uses `ZeroizingAllocator` internally.

### P7: Socket peer credential verification

UID check on every connection using `SO_PEERCRED` / `getpeereid`. Connections from other users are immediately rejected.

### P8: TOCTOU double-check in auto-lock

The auto-lock worker (`sync_worker.rs:14-28`) correctly uses a read-check then write-lock-and-recheck pattern.

### P9: No `unsafe` outside justified FFI

Only 4 `unsafe` blocks across the entire codebase: `mlockall()`, `prctl()`, `getuid()`, and `getsid()` — all justified FFI calls with no alternatives. All have `// SAFETY:` comments except `getsid` (noted in L5).

### P10: SDK internal errors sanitized before IPC

`sdk_err_to_rpc()` at `session.rs:682-696` logs detailed errors server-side but returns only `"Internal error"` to the client for `SdkError::Internal`, preventing leakage of filesystem paths and library errors.

---

## Attack Scenario Analysis

### Scenario S1: Remote Code Execution in User Session

**Attack path**: Malicious npm postinstall script runs as the user in a terminal session.

**Current defenses**:
- Scoped access approval (P2): attacker can connect to socket but can't complete the GUI dialog
- Socket UID check + encrypted IPC (P7, P4): attacker is same UID (allowed by design), but can't tamper with messages
- Security parameters hardcoded (P3): attacker can't disable approval via config

**Gaps**:
- Attacker can place fake prompt binary in PATH (C2) → captures master password OR bypasses biometric
- No connection rate limiting (H2) → attacker can DoS the vault
- Attacker can modify config to set `prompt.method = "none"` or change `server.url` (M10)
- Vault metadata leaks in error messages (M4)

**Mitigations needed**: C2 (prompt binary hardening), H2 (rate limiting), M10 (config permissions)

### Scenario S2: Same-User Lateral Movement

**Attack path**: Compromised browser extension with native messaging, or malicious cron job.

**Current defenses**:
- Scoped access approval scoped to terminal session — cron job has different session leader
- GUI prompt requires physical presence
- Password approval verified against server (P2)
- Unknown PIDs get unique monotonic scope keys (`session.rs:64-74`) — no shared key=0 vulnerability

**Gaps**:
- SSH agent socket lacks UID verification (M5)
- `login.json` can be modified to redirect to malicious server (M2)
- Config file can be modified (M10)
- Backoff counter resets on restart (H3) — attacker can kill+restart service for unlimited password attempts

**Mitigations needed**: H3 (persistent backoff), M2 (login.json integrity), M5 (SSH agent UID check)

### Scenario S3: Physical Access

**Attack path**: Attacker at an unlocked laptop.

**Current defenses**:
- Auto-lock timer (900s) — if expired, requires master password
- Approval required for every vault operation (P2)
- Password approval verified against server — entering a wrong password doesn't grant access

**Gaps**:
- No screen-lock integration — if within 15-minute window, vault is accessible to any process
- SSH private keys not zeroized after signing (C1) — memory dump reveals keys
- Password material at SDK boundary not zeroized (H1) — memory dump reveals master password
- No macOS memory hardening (H4) — pages can be swapped to disk

**Mitigations needed**: C1 (SSH key zeroization), H1 (password zeroization), H4 (macOS hardening)

### Scenario S4: Supply Chain

**Attack path**: Compromised dependency introduces malicious code.

**Current defenses**:
- SDK pinned to specific git revision
- Cargo.lock committed
- Rust version pinned
- Release binaries signed with cosign

**Gaps**:
- 524 transitive dependencies — large attack surface
- No `cargo audit` or `cargo-deny` (M8)
- 39 pre-release crate versions (no stability guarantees)
- Yanked `digest 0.11.1` — reason uninvestigated
- CI actions not SHA-pinned (M9)
- `tokio` full features expand surface (M6)

**Mitigations needed**: M6, M8, M9

### Scenario S5: Network

**Attack path**: MITM between Grimoire and Bitwarden/Vaultwarden server.

**Current defenses**:
- HTTPS via `reqwest` with `rustls-tls` (no OpenSSL)
- Master password hash sent, not cleartext password

**Gaps**:
- KDF parameters accepted without upper bounds (H5) — malicious server can DoS via excessive params
- No HTTP response size limit (L9)

**Assessment**: Well-defended. The `rustls` TLS stack has an excellent security record. KDF bounds (H5) are the main gap.

---

## Recommendations by Priority

### Immediate (before any production use)

| # | Finding | Effort |
|---|---------|--------|
| C1 | Wrap SSH private keys in `Zeroizing<>` after signing | Small |
| C2 | Remove PATH fallback for prompt binary discovery | Small |
| H2 | Add connection limits and socket read/handshake timeouts | Medium |
| H3 | Persist backoff counter to disk | Small |

### Short-term (next release)

| # | Finding | Effort |
|---|---------|--------|
| H1 | Pass `Zeroizing<String>` through full SDK boundary | Medium |
| H4 | Make memory hardening failure fatal; add macOS `mlock`/`PT_DENY_ATTACH` | Medium |
| H5 | Add upper bounds on KDF parameters from server | Small |
| M5 | Add UID peer check to SSH agent socket | Small |
| M7 | Reduce `MAX_MESSAGE_SIZE` to 1 MiB | Trivial |
| M8 | Add `cargo audit` to CI | Small |
| M10 | Check config file permissions on load | Small |

### Medium-term

| # | Finding | Effort |
|---|---------|--------|
| M1 | Refactor sync worker to not hold state lock during HTTP calls | Small |
| M2 | Add HMAC integrity check to `login.json` | Medium |
| M3 | Include process start time in approval cache key | Small |
| M4 | Genericize error messages for vault references | Small |
| M6 | Narrow `tokio` features | Trivial |
| M9 | Pin CI actions to commit SHAs | Small |
| L3 | Zeroize shared secret and derived keys in codec | Small |

### Long-term

| Item | Effort |
|------|--------|
| Screen-lock integration (D-Bus on Linux, DistributedNotificationCenter on macOS) | Medium |
| `seccomp` filter on Linux to restrict syscalls | Medium |
| Hardware key (FIDO2/WebAuthn) support for unlock | Large |
| V2 account (COSE) support | Medium |
| SBOM generation for releases | Small |

---

## Changes Since Last Audit (2026-03-20)

### Findings Resolved

| Previous ID | Resolution |
|-------------|-----------|
| C1 (password re-verification bypass) | **Fixed.** Password approval now verified against server (`approval.rs:81-96`) |
| C2 (access approval password bypass) | **Fixed.** Same — shared approval flow verifies all password-based approvals |
| H1 (no secret zeroization) | **Partially fixed.** Protocol and state layers now use `Zeroizing<String>`. SDK boundary still has gaps (now H1). |
| H6 (config-based security downgrade) | **Fixed.** Security parameters hardcoded as constants. Config cannot override them. |
| M1 (missing `deny_unknown_fields`) | **Fixed.** All `RequestParams` variant structs now have it. |
| New | **Added:** Encrypted IPC (X25519 + ChaCha20-Poly1305) |
| New | **Added:** Shared approval module with biometric → PIN → password cascade |
| New | **Added:** RSA SSH key signing |
| New | **Added:** `grimoire approve` for headless sessions |

### Findings Still Open

| Previous ID | Current ID | Notes |
|-------------|-----------|-------|
| C3 (prompt binary PATH) | C2 | Unchanged — PATH fallback still present |
| H2 (no connection limits) | H2 | Unchanged |
| H3 (memory hardening) | H4 | Unchanged |
| H4 (backoff counter reset) | H3 | Unchanged |
| H5 (PIN no delay) | — | Mitigated: PIN exhaustion now auto-locks vault. Still no delay between attempts within a session. |
| M2 (login.json integrity) | M2 | Unchanged |
| M3 (TOCTOU in session leader) | M3 | Unchanged |
| M4 (error messages leak metadata) | M4 | Unchanged |
| M5 (SSH key zeroization) | C1 | Elevated to Critical — SSH keys are the most operationally sensitive credentials |
| M7 (sync holds read lock) | M1 | Unchanged |
| M8 (tokio full features) | M6 | Unchanged |
| M9 (yanked digest) | M8 | Folded into broader CI audit recommendation |

---

## Methodology Notes

This audit was performed through manual code review of the complete codebase. Every `.rs` file in all workspace crates was read in full. The review focused on:

1. **Data flow tracing**: Following secrets (passwords, PINs, keys, tokens) from entry point through storage to destruction — with particular attention to `Zeroizing<String>` chain-of-custody breaks
2. **Trust boundary analysis**: Identifying where untrusted input crosses a boundary and how it's validated
3. **State machine correctness**: Verifying that all state transitions are properly guarded
4. **Concurrency safety**: Checking lock ordering, TOCTOU patterns, and potential deadlocks
5. **Error handling completeness**: Ensuring errors don't leak information or create inconsistent state
6. **Dependency risk assessment**: Evaluating the supply chain surface area
7. **Defense-in-depth evaluation**: For a password manager, every layer must assume every other layer has failed

This audit does not include fuzzing, dynamic analysis, or penetration testing against a running instance. Those would complement this review.
