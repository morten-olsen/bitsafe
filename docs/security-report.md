# BitSafe Security Audit Report

**Date**: 2026-03-20
**Scope**: Full codebase audit — all crates, native prompt binaries, dependencies, build configuration
**Methodology**: Manual code review with threat-model-driven analysis across attack scenarios

---

## Executive Summary

BitSafe is a single-user password manager daemon with a Unix socket IPC model analogous to `ssh-agent`. The architecture is sound: cryptographic operations are delegated to the battle-tested Bitwarden SDK, the IPC trust boundary is enforced by OS-level socket permissions and peer credential checks, and the scoped access approval system provides meaningful defense against remote code execution attacks.

This audit identifies **3 critical findings**, **6 high-severity findings**, and **9 medium-severity findings**. The most impactful issues are:

1. **Password re-verification bypass** — the master password fallback in session re-verification accepts any password without validating it
2. **No secret zeroization** — passwords, PINs, and decrypted user keys persist in memory as plain `String` until garbage collection
3. **No connection limits or timeouts** — the service is vulnerable to resource exhaustion via slow clients or connection flooding

The codebase demonstrates strong fundamentals: zero `unwrap()`/`expect()` calls, zero `unsafe` outside justified memory hardening, and clean error propagation throughout. The primary gaps are in operational hardening and memory hygiene.

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

### C1: Password re-verification accepts any password

**Location**: `crates/bitsafe-service/src/session.rs:258-265`
**Scenarios**: S1, S2, S3

When a session expires and the user falls through biometric and PIN to the master password fallback, the code accepts *any* password without validation:

```rust
// session.rs:258-265
match prompt::prompt_password(&prompt_method).await? {
    Some(_password) => {
        // Already unlocked, just refresh the session
        let mut s = state.write().await;
        s.refresh_session();
        Ok(true)
    }
    None => Ok(false),
}
```

The `_password` is captured but never verified against the master password. Any non-empty response from the prompt refreshes the session.

**Impact**: Session re-verification via master password provides no actual security. The only thing gating access is the GUI prompt dialog — proving physical presence, not knowledge. This is acceptable *only* if the design intent is "prove the human is at the keyboard". If so, this should be explicitly documented as a presence check, not a password check. If the intent is password verification, this must actually verify.

**Recommendation**: Either:
- (a) Verify the password by calling `sdk.auth().unlock(password, login_state)` (same as the unlock flow), or
- (b) Rename this to `prompt_presence_check()` and document that it only proves physical presence, not password knowledge. Remove the password field from the prompt response entirely in this flow.

Option (b) is actually the more honest design — re-deriving keys from the master password on every session expiry would be slow and annoying. The real security comes from the GUI prompt requiring physical interaction. But the current code is deceptive: it looks like it's checking a password when it isn't.

### C2: Access approval password fallback has the same bypass

**Location**: `crates/bitsafe-service/src/session.rs:154-158`
**Scenarios**: S1, S2

The scoped access approval also falls back to a password prompt that accepts any input:

```rust
// session.rs:154-158
match prompt::prompt_password(&prompt_method).await {
    Ok(Some(_)) => true, // User proved presence
    _ => false,
}
```

Same issue as C1. A prompt binary that writes `{"status":"ok","credential":"anything"}` to stdout grants access approval. The comment says "User proved presence" which suggests this is intentional as a presence check — but it's indistinguishable from a password check to the user and to security reviewers.

**Recommendation**: Same as C1.

### C3: Prompt binary is fully trusted with no integrity verification

**Location**: `crates/bitsafe-service/src/prompt.rs:16-53`
**Scenarios**: S1, S4

The service trusts whatever binary it finds as `bitsafe-prompt` without any integrity check. The discovery chain:

1. Native binary next to `current_exe()` — relatively safe
2. Generic binary next to `current_exe()` — relatively safe
3. `which` lookup for native binary — **PATH-dependent**
4. Bare `"bitsafe-prompt"` — **PATH-dependent**

An attacker who can place a binary earlier in `$PATH` (common in S1 — many dev tools prepend to PATH) can intercept all password prompts. The malicious binary would:
- Receive the user's master password in the clear
- Return it to the service (so the user doesn't notice)
- Exfiltrate it

**Why this is critical**: This is the master password entry point. Unlike the IPC channel (which is protected by socket permissions), the prompt binary is discovered via PATH which is user-controlled and commonly manipulated.

**Recommendation**:
1. **Remove the PATH fallback entirely.** Only look for prompt binaries adjacent to `current_exe()`. If not found, fail with a clear error message telling the user to install properly.
2. **Verify binary ownership and permissions** before execution: binary must be owned by root or the current user, and must not be world-writable.
3. Long-term: consider code signing verification on macOS (`codesign --verify`) and checking that the binary is in a trusted location on Linux (e.g., `/usr/bin`, `/usr/local/bin`, or next to service).

---

## High Findings

### H1: No secret zeroization in the BitSafe layer

**Location**: Throughout all crates
**Scenarios**: S3, S6

Passwords and PINs flow as plain `String` through the entire stack:
- `LoginParams.password` / `UnlockParams.password` — protocol types
- `LoginCredentials.password` — SDK wrapper
- `Session.pin` — held in service state as `Option<String>`
- `rpassword::prompt_password()` return value — CLI
- JSON-encoded passwords in IPC messages — codec layer

The SDK uses `ZeroizingAllocator` internally for key material, but all data flowing through BitSafe code is not zeroized. This means passwords persist in freed heap memory until overwritten by subsequent allocations.

The most sensitive instance is `UserKeyState` in `crates/bitsafe-sdk/src/state.rs:14` — the decrypted user key stored as a base64 `String` in a `HashMap`. This key can decrypt the entire vault.

**Impact**: A memory dump (core dump, swap file, hibernation image, cold boot attack) can recover passwords and vault keys. On macOS, where there is no `mlockall`, pages containing passwords can be swapped to disk at any time.

**Recommendation**: Use `zeroize::Zeroizing<String>` for all password and PIN fields. For the `InMemoryRepository` backing `UserKeyState`, implement `Drop` with explicit `zeroize()` on the HashMap values. This is the single highest-value security improvement available.

### H2: No connection limits, rate limiting, or read timeouts on the Unix socket

**Location**: `crates/bitsafe-service/src/server.rs:76-115`, `crates/bitsafe-protocol/src/codec.rs:62-80`
**Scenarios**: S1, S2

The accept loop spawns an unbounded number of tokio tasks with no:
- Maximum connection count
- Per-connection read/write timeout
- Rate limiting on RPC calls
- Per-connection memory quota

A malicious same-user process can:
1. **Connection flood**: Open thousands of connections, each spawning a task and allocating buffers
2. **Slow client attack**: Open a connection and send data 1 byte/second — `read_exact()` blocks indefinitely, keeping the task alive
3. **Memory exhaustion**: Send a valid 4-byte length prefix for a 16 MiB message on each of many connections — `vec![0u8; len as usize]` allocates immediately
4. **Lock starvation**: Flood `vault.list` requests to hold read locks continuously, preventing auto-lock (write lock) from ever acquiring

**Impact**: Denial of service against the vault service. An attacker can prevent legitimate use of the password manager.

**Recommendation**:
1. Add `tokio::time::timeout()` wrapping `read_exact()` calls — 30 seconds is reasonable
2. Limit concurrent connections (e.g., 64 max) with a semaphore
3. Reduce `MAX_MESSAGE_SIZE` from 16 MiB to 1 MiB — vault payloads are JSON summaries, not bulk data
4. Add per-connection request rate limiting (e.g., 100 req/s)

### H3: Memory hardening is non-fatal and absent on macOS

**Location**: `crates/bitsafe-service/src/main.rs:34-46`
**Scenarios**: S3, S6

`mlockall` and `PR_SET_DUMPABLE` failures are logged as warnings and execution continues. On macOS, no memory hardening is attempted at all.

**Why this matters**: The vault service holds decrypted key material in memory. Without `mlockall`, the OS can swap these pages to disk, where they persist after process exit. Without `PR_SET_DUMPABLE(0)`, any same-user process can `ptrace` and read memory.

**Current behavior**:
- Linux: warning log if `mlockall` fails (e.g., `RLIMIT_MEMLOCK` too low), continues with unprotected memory
- macOS: no attempt at all

**Recommendation**:
1. **Linux**: Make `mlockall` failure fatal by default, with a `[security] allow_insecure_memory = false` config option to allow override in constrained environments (containers, low-rlimit systems). This matches GnuPG's approach.
2. **macOS**: Use `mlock()` on specific pages (per-allocation, not process-wide). macOS supports `mlock` for individual ranges. Alternatively, use the Security framework's `SecureEnclave` for key storage.
3. **macOS**: Use `ptrace(PT_DENY_ATTACH, 0, 0, 0)` to prevent debugger attachment (same mechanism used by Apple's security daemon).

### H4: Backoff counter resets on service restart

**Location**: `crates/bitsafe-service/src/state.rs:116,149`
**Scenarios**: S1, S2, S3

`master_password_attempts` and `last_password_attempt` are in-memory fields initialized to `0`/`None` on startup. An attacker who can restart the service (e.g., `kill` + wait for systemd restart) gets unlimited password attempts with no backoff.

On Linux with the systemd unit generated by `bitsafe service install`, the service has `Restart=on-failure` with `RestartSec=5`. An attacker can:
1. Try 2 passwords (no backoff on first two)
2. Kill the service (`SIGKILL` from same-user process)
3. Wait 5 seconds for restart
4. Repeat — ~24 guesses/minute with zero backoff

**Recommendation**: Persist the attempt counter and last attempt timestamp to a file alongside `login.json`. Load on startup. Clear on successful authentication. Use a separate file with `0600` permissions. This is simple and eliminates the restart bypass.

### H5: PIN has no delay between attempts

**Location**: `crates/bitsafe-service/src/state.rs:340-358`
**Scenarios**: S1, S2

PINs have a max attempt limit (3) but no delay between attempts. A 4-digit numeric PIN has 10,000 possibilities. With 3 attempts before auto-lock, then an immediate re-unlock (if the attacker has already exfiltrated the master password from a previous prompt binary attack), the attacker gets unlimited batches of 3 PIN attempts.

Even without knowing the master password, the auto-lock-then-GUI-prompt cycle means the attacker can keep triggering PIN prompts that the legitimate user might respond to (social engineering: "BitSafe keeps asking me to re-enter my password").

**Recommendation**: Add a 1-second delay between PIN attempts. After the 3rd failure (auto-lock), persist the failed count so re-unlock doesn't reset PIN attempts. Require successful master password authentication to reset the PIN attempt counter.

### H6: Config file not validated for permissions or content bounds

**Location**: `crates/bitsafe-common/src/config.rs:198-210`
**Scenarios**: S1, S2

The config file is loaded without checking:
1. **File permissions**: A world-readable config leaks server URL and security settings. A world-writable config allows an attacker to disable security features.
2. **Content bounds**: No validation on any values. An attacker who can write to the config can set:
   - `require_approval = false` — disables access approval entirely
   - `pin_max_attempts = 999999999` — effectively disables PIN lockout
   - `duration_seconds = 999999999` — session never expires
   - `auto_lock_seconds = 0` — disables auto-lock
   - `prompt.method = "none"` — disables interactive prompting

**Recommendation**:
1. **Check permissions on load**: warn and refuse to start if config is group/world-writable (`mode & 0o022 != 0`)
2. **Validate bounds**: reject configs where `duration_seconds > 3600`, `auto_lock_seconds > 86400`, `pin_max_attempts > 10`, etc.
3. **Log the effective security config** at startup so the user can verify

---

## Medium Findings

### M1: `VaultGetParams` and `SshSignParams` missing `#[serde(deny_unknown_fields)]`

**Location**: `crates/bitsafe-protocol/src/request.rs`
**Scenarios**: Protocol confusion

All other parameter structs have `deny_unknown_fields` to prevent the `#[serde(untagged)]` enum from greedily matching. These two are missing it. While the practical impact is low (extra fields are silently ignored), this inconsistency could cause deserialization to match the wrong variant if new similar-shaped structs are added.

**Recommendation**: Add `#[serde(deny_unknown_fields)]` to both structs for consistency with the rest of the protocol.

### M2: Persistent login state file has no integrity protection

**Location**: `crates/bitsafe-sdk/src/persist.rs`
**Scenarios**: S2

`login.json` stores email and server URL. A same-user attacker can modify this file to point at a malicious server. On next unlock, the service would send the master password hash to the attacker's server.

The file is protected by `0600` permissions, but a same-user process can read and write it.

**Impact**: Master password exfiltration via server URL redirection. The user would see a login failure (attacker's server doesn't have their vault), but the password hash has already been sent.

**Recommendation**: Add an HMAC over the file contents, keyed with a per-installation random secret stored in a separate file. This detects tampering — the service refuses to load a file with an invalid HMAC. This doesn't prevent a same-user attacker from reading the file, but it prevents the server URL redirect attack.

### M3: `/proc/<pid>/stat` TOCTOU in session leader resolution

**Location**: `crates/bitsafe-service/src/peer.rs:30-37`
**Scenarios**: S2

The session leader PID is read from `/proc/<pid>/stat` at connection time. Between read and use, the PID could be recycled. If an attacker's process gets the same PID as a previously approved session leader, it inherits the approval grant.

**Impact**: Low probability (PID recycling is rare in the approval window), but the consequence is full vault access without re-approval.

**Recommendation**: Store `(pid, start_time)` pairs in the approval cache. Read the process start time from `/proc/<pid>/stat` field 22 (`starttime`) and verify it matches when checking the cache. This eliminates PID reuse as an attack vector.

### M4: Error messages leak vault metadata

**Location**: `crates/bitsafe-service/src/session.rs:592-608`
**Scenarios**: S1, S2

Vault reference resolution errors include item names and counts:
- `"No item named 'GitHub API'"` — confirms the item does not exist
- `"Ambiguous name 'Git' matches 3 items"` — reveals count of matching items
- `"Ambiguous ID prefix '64b1' matches 2 items"` — confirms items exist with that prefix

**Recommendation**: Return generic errors: `"Reference resolution failed"`. Log the detailed error server-side for debugging.

### M5: SSH private key not zeroized after signing

**Location**: `crates/bitsafe-sdk/src/ssh.rs:76-79`
**Scenarios**: S3, S6

After parsing the SSH private key from OpenSSH format and signing, the `PrivateKey` and `SigningKey` objects are dropped without zeroization:

```rust
let private_key = ssh_key::PrivateKey::from_openssh(&ssh_key_view.private_key)?;
sign_with_key(&private_key, data, flags)
// private_key dropped here — not zeroized
```

The `ed25519_dalek::SigningKey` and `rsa::RsaPrivateKey` do not implement `Zeroize`. The private key bytes persist on the stack and heap after the function returns.

**Recommendation**: This is harder to fix than the `String` zeroization because the crypto types don't implement `Zeroize`. Short-term: document as a known gap. Long-term: wrap the signing operation in a dedicated function that allocates key material in a `mlock`'d region and manually zeros it after use. Consider using `ssh-key`'s own signing API if it handles key lifecycle more carefully.

### M6: Service log file on macOS is world-readable

**Location**: `crates/bitsafe-cli/src/main.rs:327-328`
**Scenarios**: S2

The macOS LaunchAgent plist writes stdout/stderr to `/tmp/bitsafe-service.log`:

```xml
<key>StandardOutPath</key>
<string>/tmp/bitsafe-service.log</string>
<key>StandardErrorPath</key>
<string>/tmp/bitsafe-service.log</string>
```

Files created in `/tmp` inherit the umask of the creating process. If the umask allows it (common default: `0022`), the log file is world-readable. Service logs include:
- Email address (logged at startup)
- Server URL
- Connection details and peer PIDs
- Sync status

**Recommendation**: Use `~/Library/Logs/bitsafe-service.log` instead of `/tmp`. Alternatively, set `StandardOutPath` to a directory with restricted permissions.

### M7: Background sync happens over a read lock that blocks state mutations

**Location**: `crates/bitsafe-service/src/sync_worker.rs:46-55`
**Scenarios**: Operational

Background sync holds a read lock on `state` for the entire duration of the HTTP request to the server:

```rust
let sync_result = {
    let s = state.read().await;
    // ... holds read lock during HTTP call
    sdk.sync().sync(server_url).await  // Network call — could take seconds
};
```

While the read lock is held, no state mutations (lock, logout, set PIN) can proceed. If the server is slow or unreachable, this can block state mutations for the entire HTTP timeout.

**Recommendation**: Extract `sdk` and `server_url` from the read lock, drop the lock, then perform the sync without holding any lock. The SDK client is behind `Arc<Mutex<>>` so it's safe to use without the state lock.

### M8: `tokio` uses `features = ["full"]` — unnecessarily wide attack surface

**Location**: `Cargo.toml` workspace dependencies
**Scenarios**: S4

`tokio = "full"` enables ~40 feature flags including `process`, `fs`, `io-std`, and others not needed by the service. Each feature pulls in additional code and increases the binary size and attack surface.

**Recommendation**: Replace with explicit features: `["macros", "rt-multi-thread", "time", "net", "io-util", "signal", "sync"]`. This cuts unused code paths and reduces transitive dependency surface.

### M9: Yanked `digest 0.11.1` dependency

**Location**: `Cargo.lock`
**Scenarios**: S4

The SDK requires `digest 0.11.1` which has been yanked from crates.io. While Cargo.lock preserves the version, a fresh `cargo update` or CI build without a cached Cargo.lock may fail to resolve this dependency.

**Impact**: Build breakage, not a runtime vulnerability. However, yanked crates are typically yanked due to bugs or security issues — the reason should be investigated.

**Recommendation**: Investigate why `digest 0.11.1` was yanked. If it's a security fix, assess impact on BitSafe. Document the investigation in `UPGRADING.md`. Consider whether a newer SDK revision resolves this.

---

## Positive Findings

These are security properties that are well-implemented and should be preserved:

### P1: Zero panic paths in production code

No `unwrap()`, `expect()`, `panic!()`, `unimplemented!()`, or `unreachable!()` in any crate except `unreachable!()` in one match arm that genuinely can't be reached (`state.rs:280`). All errors use `Result<T>` propagation. This eliminates panic-based denial of service — **industry-leading error handling discipline**.

### P2: Scoped access approval is genuinely valuable

The biometric/PIN approval system gated by session leader PID is an effective defense against S1 (RCE in a terminal session). An attacker who gets shell access can connect to the socket but cannot complete the GUI dialog that appears on the user's display. This is a real security boundary, not theater.

### P3: `exec()` semantics for secret injection

`bitsafe run` uses `execvp()` — the BitSafe process is replaced entirely. No wrapper process lingers with secrets in its memory. No TTY interposition. All resolution errors happen before exec. This is the correct design.

### P4: Crypto delegation to the SDK

BitSafe never handles raw cryptographic keys. All crypto operations go through the SDK's `PasswordManagerClient`, which uses `ZeroizingAllocator` and `KeyStore` internally. Key derivation, encryption, and decryption are entirely within the SDK. This is a sound trust boundary.

### P5: Socket peer credential verification

The UID check on every connection using `SO_PEERCRED` (Linux) / `getpeereid` (macOS) is correctly implemented. The `#[cfg(unix)]` guard covers both platforms. Connections from other users are immediately rejected. This matches `ssh-agent`'s security model.

### P6: TOCTOU double-check in auto-lock

The auto-lock worker correctly uses a read-check then write-lock-and-recheck pattern, preventing a race where the vault is locked while a legitimate operation is in progress.

### P7: No `unsafe` outside justified memory hardening

The only `unsafe` blocks are `libc::mlockall()`, `libc::prctl()`, `libc::getuid()`, and `libc::getsid()` — all justified FFI calls with no alternatives.

---

## Attack Scenario Analysis

### Scenario S1: Remote Code Execution in User Session

**Attack path**: Malicious npm postinstall script runs as the user in a terminal session.

**Current defenses**:
- Scoped access approval (P2): attacker can connect to socket but can't approve the GUI dialog
- Socket UID check: attacker is same user (allowed by design)

**Gaps**:
- If approval is disabled in config (H6), attacker has full vault access
- Attacker can modify config to disable approval, then restart service (H6 + H4)
- Attacker can place fake prompt binary in PATH (C3) to capture master password on next unlock
- No connection rate limiting (H2) — attacker can DoS the vault

**Mitigations needed**: C3 (prompt binary hardening), H6 (config validation), H2 (rate limiting)

### Scenario S2: Same-User Lateral Movement

**Attack path**: Compromised browser extension with native messaging, or malicious cron job.

**Current defenses**:
- Scoped access approval scoped to terminal session — cron job has different session leader
- GUI prompt requires physical presence

**Gaps**:
- With `approval_for = "session"` and scope_key = 0 (no peer PID available), approval is always cached at key 0 — any process without a PID gets free access
- Same gaps as S1 for config modification and prompt binary replacement

**Mitigations needed**: Fix the scope_key=0 fallback — if peer PID is unavailable, deny access rather than granting with a shared key.

### Scenario S3: Physical Access

**Attack path**: Attacker at an unlocked laptop.

**Current defenses**:
- Session timer (300s default) — if expired, requires biometric/PIN/password
- Auto-lock (900s default) — if expired, requires master password

**Gaps**:
- No screen-lock integration — if the user leaves the session unlocked, vault is accessible
- Re-verification password bypass (C1, C2) — entering any password refreshes the session
- Cold boot / memory dump — no zeroization (H1), no macOS memory hardening (H3)

**Mitigations needed**: C1/C2 (re-verification bypass), H1 (zeroization), H3 (macOS memory hardening)

### Scenario S4: Supply Chain

**Attack path**: Compromised dependency introduces malicious code.

**Current defenses**:
- SDK pinned to specific git revision
- Cargo.lock committed
- Rust version pinned to 1.88

**Gaps**:
- 524 transitive dependencies — large attack surface
- Pre-release RustCrypto crates (no semver stability guarantees)
- Yanked `digest 0.11.1` (M9)
- No `cargo audit` or `cargo-deny` in CI
- No SBOM generation

**Mitigations needed**: Add `cargo audit` to CI, reduce `tokio` features (M8), investigate yanked deps (M9)

### Scenario S5: Network

**Attack path**: MITM between BitSafe and Bitwarden/Vaultwarden server.

**Current defenses**:
- HTTPS via `reqwest` with `rustls-tls` (no OpenSSL, certificate verification enabled by default)
- Master password hash sent, not cleartext password

**Assessment**: Well-defended. The `rustls` TLS implementation has an excellent security track record. The master password is never sent in cleartext — only the PBKDF2/Argon2 hash is transmitted. Certificate pinning would add defense-in-depth but is not strictly necessary given proper CA validation.

---

## Recommendations by Priority

### Immediate (before any production use)

| # | Finding | Effort |
|---|---------|--------|
| C1 | Fix password re-verification bypass — either verify or rename to presence check | Small |
| C2 | Fix access approval password fallback — same as C1 | Small |
| C3 | Remove PATH fallback for prompt binary discovery | Small |
| H1 | Add `Zeroizing<String>` for all password/PIN fields | Medium |
| H2 | Add connection limits and socket read timeouts | Medium |

### Short-term (next release)

| # | Finding | Effort |
|---|---------|--------|
| H3 | Make memory hardening failure fatal by default; add macOS `mlock`/`PT_DENY_ATTACH` | Medium |
| H4 | Persist backoff counter to disk | Small |
| H5 | Add PIN attempt delay; persist PIN attempt count across lock/unlock | Small |
| H6 | Validate config file permissions and content bounds | Small |
| M1 | Add `deny_unknown_fields` to remaining param structs | Trivial |
| M6 | Fix macOS log file path | Trivial |
| M8 | Reduce `tokio` features | Trivial |

### Medium-term

| # | Finding | Effort |
|---|---------|--------|
| M2 | Add HMAC integrity check to `login.json` | Medium |
| M3 | Include process start time in approval cache key | Small |
| M4 | Genericize error messages for vault references | Small |
| M5 | Investigate SSH key zeroization options | Medium |
| M7 | Refactor sync worker to not hold state lock during HTTP calls | Small |
| M9 | Investigate yanked `digest` dependency | Small |
| — | Add `cargo audit` and `cargo-deny` to CI | Small |
| — | Generate SBOM | Small |

### Long-term

| Item | Effort |
|------|--------|
| IPC encryption (NaCl box or similar) — defense-in-depth against ptrace | Large |
| `seccomp` filter on Linux to restrict syscalls | Medium |
| Hardware key (FIDO2/WebAuthn) support for unlock | Large |
| Screen-lock integration (D-Bus on Linux, DistributedNotificationCenter on macOS) | Medium |
| V2 account (COSE) support | Medium |

---

## Methodology Notes

This audit was performed through manual code review of the complete codebase. Every `.rs` file in all workspace crates, both native prompt binaries, all specs, and all documentation were read. The review focused on:

1. **Data flow tracing**: Following secrets (passwords, PINs, keys, tokens) from entry point through storage to destruction
2. **Trust boundary analysis**: Identifying where untrusted input crosses a boundary and how it's validated
3. **State machine correctness**: Verifying that all state transitions are properly guarded
4. **Concurrency safety**: Checking lock ordering, TOCTOU patterns, and potential deadlocks
5. **Error handling completeness**: Ensuring errors don't leak information or create inconsistent state
6. **Dependency risk assessment**: Evaluating the supply chain surface area

This audit does not include fuzzing, dynamic analysis, or penetration testing against a running instance. Those would complement this review.
