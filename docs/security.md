# Security

This document covers how Grimoire protects sensitive data, known gaps, and planned improvements. It is a living document — update it when security-relevant code changes.

## Threat Model

Grimoire is a single-user daemon holding decrypted vault keys in memory. The trust boundary is the Unix socket — same model as `ssh-agent`. We defend against:

- **Other users on the same machine**: socket permissions + UID validation
- **Swap/core dump exposure**: mlockall + PR_SET_DUMPABLE
- **Brute force**: master password backoff, PIN attempt limits
- **Session hijacking**: session timer + re-verification

We do **not** currently defend against:

- **Root access**: root can read process memory, attach debugger, etc.
- **Same-user attackers**: another process running as the same user can connect to the socket (this is by design, same as ssh-agent)
- **Physical access with unlocked session**: no screen-lock integration yet

## Memory Protection

### What's implemented

- **Linux**: `mlockall(MCL_CURRENT | MCL_FUTURE)` at service startup — prevents pages from being swapped to disk. `prctl(PR_SET_DUMPABLE, 0)` — prevents core dumps and ptrace from non-root. Both are **fatal on failure** — the service refuses to start without memory protection.
- **macOS**: `ptrace(PT_DENY_ATTACH)` — prevents debugger attachment (same mechanism used by Apple's security daemon). Fatal on failure.

### What's delegated to the SDK

- `bitwarden-crypto` uses `ZeroizingAllocator` and `KeyStore` internally for key material
- We never extract raw keys from the SDK — all crypto ops go through `PasswordManagerClient`

### Password and PIN zeroization

All password and PIN fields use `zeroize::Zeroizing<String>` — memory is zeroed on drop. This covers:
- `LoginParams.password` and `UnlockParams.password` in protocol types
- `LoginCredentials.password` in the SDK wrapper
- `Session.pin` held in service state (`Option<Zeroizing<String>>`)
- `SetPinParams.pin` in protocol types
- `PromptResponse.credential` from prompt subprocess
- Local variables from `rpassword::prompt_password()` in the CLI
- `ServiceState.unlock()` and `verify_password()` accept `&Zeroizing<String>`
- `AuthClient.unlock()` and `verify_password()` accept `&Zeroizing<String>`
- SSH Ed25519 raw key bytes zeroized after signing (`ssh.rs`)

The SDK uses `ZeroizingAllocator` internally for key material. Between Grimoire's zeroization of passwords and the SDK's zeroization of keys, the sensitive-data lifecycle is covered.

### Known gaps

- **No macOS swap protection.** macOS has no `mlockall` equivalent. `PT_DENY_ATTACH` prevents debugger attachment but does not prevent pages from being swapped to disk. macOS processes may swap sensitive pages.
- **SSH private key zeroization is partial.** Ed25519 raw key bytes are zeroized after signing, but `ssh_key::PrivateKey` and `ed25519_dalek::SigningKey` do not implement `Zeroize` in their current versions. The `rsa::RsaPrivateKey` is consumed by the signing key constructor (not leaked). See `grimoire-sdk/src/ssh.rs`.
- **Password `String` copy at SDK boundary.** `unlock()` and `verify_password()` accept `&Zeroizing<String>`, but the SDK's `InitUserCryptoRequest` requires a plain `String`. The copy is documented and minimized but not zeroized by us — the SDK's `ZeroizingAllocator` handles it.

### Future improvements

- Investigate macOS `mlock` per-page support for key material
- Consider `seccomp` filtering on Linux to restrict syscalls

## IPC Security

### Socket permissions

- Runtime directory: `$XDG_RUNTIME_DIR/grimoire/` (mode `0700`) or `/tmp/grimoire-<id>/` fallback
- Socket file: mode `0600` (owner read/write only)
- Stale sockets removed before binding

### Peer credential validation

- **Main socket (Linux/macOS)**: `SO_PEERCRED` / `getpeereid()` check on every connection — peer UID must match service UID. Connections from other users are rejected.
- **SSH agent socket**: Same UID peer verification inside `SshAgentHandler::new_session()`. Rejected sessions return empty identities and refuse signing.

### Encrypted IPC

- Every connection performs an **X25519 key exchange** followed by **ChaCha20-Poly1305 AEAD** encryption
- Wire format per message: `[4-byte length][8-byte nonce counter][ciphertext + 16-byte tag]`
- Ephemeral keypairs generated per connection — no key reuse across sessions
- Nonce counter prevents replay within a connection
- Socket permissions (`0600` + UID check) remain the primary trust boundary; encryption provides defense-in-depth against local eavesdropping or socket path attacks

### Connection limits and timeouts

- **Max 64 concurrent connections** — enforced by a `tokio::sync::Semaphore`. Excess connections are rejected immediately.
- **10-second handshake timeout** — the X25519 key exchange must complete within 10 seconds or the connection is dropped.
- **60-second idle timeout** — clients that don't send a message within 60 seconds are disconnected.
- **1 MiB message size limit** — prevents memory exhaustion from oversized payloads.

### Known gaps

- **Fallback socket path** uses `/tmp/grimoire-<uid>/` (real UID via `libc::getuid()`). `$XDG_RUNTIME_DIR` is preferred when available (user-owned, `0700`, managed by systemd).

## Authentication & Lockout

### Master password backoff

- Exponential backoff on failed login/unlock: 0s, 1s, 2s, 4s, 8s, 16s, 30s (capped)
- Enforced server-side — the service rejects attempts before the backoff window expires (error code 1009)
- Counter resets on successful authentication
- **Persisted to disk** (`~/.local/share/grimoire/backoff.json`, mode `0600`) — service restart does not reset the counter. Prevents restart-based brute force bypass.

### PIN

- 3 attempts, no delay between them
- After 3 failures: vault locks automatically (keys scrubbed, need master password)
- PIN stored as `Option<Zeroizing<String>>` in service memory, never on disk
- Constant-time comparison via XOR fold — **leaks length** due to early return on length mismatch. Acceptable for short PINs (4-6 digits).

### Session re-verification

- After unlock, a session timer starts (default 300s)
- Expired session gates vault operations behind re-verification
- Re-verify order: biometric → PIN → master password fallback
- Session is per-service, not per-client — all connected clients share one session

## Prompt Agent Security

### Binary discovery

- Service looks for `grimoire-prompt-{platform}` then `grimoire-prompt` **only adjacent to `current_exe()`**
- **No PATH fallback** — if the prompt binary is not found next to the service, the service returns a clear error. This prevents PATH-based interception of master passwords.
- Install both binaries in the same directory

### Platform-specific concerns

- **macOS biometric**: Uses inline Swift via `swift -e` with the `reason` parameter interpolated into a string literal. The `reason` is currently hardcoded in our code, but the interpolation does not escape special characters — a latent injection vector if `reason` ever comes from untrusted input.
- **macOS password dialog**: Uses `osascript` — the prompt message is interpolated into AppleScript. Same escaping concern as biometric.
- **Linux GUI**: Uses `zenity`/`kdialog` with arguments — lower injection risk since arguments are not shell-interpreted.
- **Terminal**: Uses `rpassword` — no injection risk.

### Communication

- Prompt agent writes one JSON line to stdout, exits with 0/1/2
- Service reads and parses the JSON response
- No signature or integrity check on the prompt binary's output — service trusts whatever is in stdout

## Lock & Key Lifecycle

### How lock works

The SDK does not expose an explicit "clear keys" operation. Lock is implemented by:
1. Dropping the `GrimoireClient` (which drops the inner `PasswordManagerClient`)
2. Creating a fresh `GrimoireClient` for the same server URL
3. Preserving `LoginState` so re-unlock doesn't require re-login

### Concerns

- **Key erasure depends on SDK Drop impl.** We assume `bitwarden-crypto`'s `KeyStore` zeros keys on drop (it uses `ZeroizingAllocator`), but this is not verified at the Grimoire layer.
- **LoginState persists across lock.** The `LoginState` contains `MasterPasswordUnlockData` (encrypted user key, KDF params) and `WrappedAccountCryptographicState` (encrypted private key). These are encrypted — holding them in memory while locked is equivalent to what the official Bitwarden client does.

### Client-managed state repositories

The SDK requires the consuming application to provide repositories for certain state types. We register in-memory `HashMap`-backed repositories (`grimoire-sdk/src/state.rs`) for:

- `LocalUserDataKeyState` — holds the user's data key wrapped by the user key (`EncString`)
- `EphemeralPinEnvelopeState` — PIN envelope for ephemeral PIN unlock
- `UserKeyState` — decrypted user key (as base64)
- `Cipher` — encrypted cipher objects from sync
- `Folder` — encrypted folder objects from sync

**Security layering:**
- `LocalUserDataKeyState` and `EphemeralPinEnvelopeState` hold *encrypted* (wrapped) values — the actual decryption keys never leave the SDK's `KeyStore` which uses `ZeroizingAllocator`
- `UserKeyState` holds a *decrypted* user key as base64 in a plain `String` inside our `HashMap` — this is the most sensitive item and is **not zeroized** on drop
- `Cipher` and `Folder` hold server-encrypted objects that require the user key to decrypt

**Future improvement:** Replace the `HashMap<String, V>` backing with a zeroizing-on-drop container, particularly for `UserKeyState`. Consider whether `Cipher`/`Folder` repositories should be backed by the SQLite database (SDK-managed) instead of in-memory, to support offline access and reduce memory footprint for large vaults.

## Persistent Login State

After successful login, the service saves encrypted credentials to `~/.local/share/grimoire/login.json` (mode `0600`) so subsequent service restarts only require `grimoire unlock`, not a full re-login.

**What's persisted** (all encrypted or non-sensitive):
- Email and server URL
- User ID (from JWT)
- KDF configuration (type, iterations, memory, parallelism)
- Master-key-wrapped user key (`EncString` — encrypted with master password)
- Encrypted private key (`EncString` — encrypted with user key)

**What's NOT persisted:**
- Master password (never stored)
- Decrypted user key or private key
- Session tokens (re-obtained on each unlock via the SDK)

**Lifecycle:**
- Created on `grimoire login`
- Read on service startup → starts in `Locked` state if present
- Deleted on `grimoire logout`

**Security notes:**
- The persisted file contains the same encrypted material that the Bitwarden server returns on login — equivalent to what official Bitwarden clients cache locally
- File permissions are set to `0600` immediately after write
- An attacker with read access to this file still needs the master password to derive keys

## Configuration Security

- Security parameters (auto-lock timeout, approval duration, PIN max attempts, approval scope, approval requirement) are **hardcoded constants** — not configurable via config file. This prevents config-based downgrade attacks.
- Only operational settings are configurable: server URL, prompt method (auto/gui/terminal/none), SSH agent enabled/disabled.
- Config file at `~/.config/grimoire/config.toml` — **refuses to start if group/world-writable** (`mode & 0o022`). While security parameters are hardcoded, `server.url` is security-relevant (malicious URL redirects password hash). No fallback, no override.
- Config is loaded once at startup — runtime changes require restart.

## Dependency Security

### Bitwarden SDK

- Git dependency pinned to a specific revision — no published crate, no semver guarantees
- Uses pre-release RustCrypto crates (`argon2 =0.6.0-rc.2`, etc.)
- Transitive deps must be manually pinned after updates (see `UPGRADING.md`)
- **`digest 0.11.1` is yanked on crates.io** but required for compatibility

### Known advisories in transitive dependencies

- **RUSTSEC-2023-0071** (rsa 0.9.x and 0.10.0-rc.x) — Marvin Attack timing sidechannel. No fixed version available. Pulled in transitively by the SDK via `bitwarden-crypto` and `ssh-key`. Our RSA usage is SSH signing over a local Unix socket where the timing attack is not exploitable. Ignored in `cargo audit`.
- **RUSTSEC-2026-0049** (rustls-webpki 0.103.x) — CRL Distribution Point matching logic bug. No fixed version available. Transitive dep from the SDK's `reqwest` chain. Ignored in `cargo audit`.
- **Yanked crates**: `digest 0.11.1` and `crypto-bigint 0.7.1` are yanked but required by the SDK's pre-release RustCrypto stack. Builds work from the committed `Cargo.lock`; a clean `cargo update` would fail to resolve these.

### CI security scanning

- `cargo audit` runs on every push/PR with explicit `--ignore` flags for the unfixable advisories above
- All advisories are re-evaluated on each SDK revision bump

### Other notable dependencies

- `rpassword` — terminal password input, well-maintained
- `tokio` — async runtime, `features = ["full"]` (narrowing to explicit features is a medium-term goal)
- `serde_json` — JSON parsing, no known vulnerabilities
- `libc` — FFI for mlockall/prctl/ptrace/getuid/getsid, Unix only

## Release Pipeline & Supply Chain

### Artifact integrity

- Every release tarball is SHA256-checksummed — checksums file uploaded as a release asset
- Checksums file is signed with **cosign keyless** (GitHub OIDC identity) — verifiers confirm the signature came from the release workflow, not just someone with a key
- Install script (`contrib/install.sh`) verifies SHA256 before extracting

### Quality gate

- Release workflow re-runs the full CI gate (fmt, clippy, tests) before building — `needs: [gate]` dependency on all build jobs
- No release ships without passing checks, regardless of how the tag was created

### Nix flake

- `flake.lock` is committed — all input revisions are pinned, changes visible in PR diffs
- NixOS module only exposes operational settings (server URL, prompt method, SSH agent toggle) — security parameters are hardcoded constants in the binary
- systemd service includes sandboxing directives (`NoNewPrivileges`, `MemoryDenyWriteExecute`, etc.)

### Prerequisites (not enforced by the pipeline)

- **Branch protection** on `main` — workflow file changes require PR review
- **Tag protection rules** — prevent deletion/overwrite of `v*` tags

## Known Issues Prioritized

| Priority | Issue | Status |
|----------|-------|--------|
| ~~High~~ | ~~No secret zeroization in Grimoire code~~ | **Fixed** — all password/PIN fields use `Zeroizing<String>` |
| ~~High~~ | ~~macOS Swift string injection~~ | **Fixed** — `escape_swift()` and `escape_applescript()` sanitize all interpolated strings |
| ~~High~~ | ~~No macOS peer credential check~~ | **Fixed** — UID check now uses `#[cfg(unix)]` (tokio's `peer_cred()` works on both Linux and macOS) |
| ~~Medium~~ | ~~Socket fallback path uses PID not UID~~ | **Fixed** — uses `libc::getuid()` on Unix |
| ~~Medium~~ | ~~Prompt binary PATH fallback~~ | **Fixed** — PATH fallback removed, only checks adjacent to `current_exe()` |
| ~~Medium~~ | ~~Backoff counter resets on service restart~~ | **Fixed** — persisted to `backoff.json` |
| ~~Medium~~ | ~~Inactivity timer not reset on vault ops~~ | **Fixed** — `touch()` called in `dispatch()` for every session-guarded operation |
| ~~Medium~~ | ~~No connection limits or timeouts~~ | **Fixed** — 64 max connections, 10s handshake timeout, 60s idle timeout, 1 MiB message limit |
| ~~Medium~~ | ~~mlockall failure is non-fatal~~ | **Fixed** — all memory hardening failures are fatal, no fallback |
| ~~Medium~~ | ~~SSH agent socket lacks UID check~~ | **Fixed** — UID peer verification added in `SshAgentHandler::new_session()` |
| ~~Medium~~ | ~~No cargo audit in CI~~ | **Fixed** — `cargo audit` runs on every push/PR |
| ~~Low~~ | ~~Config file permissions not checked~~ | **Fixed** — refuses to start with group/world-writable config |
| ~~Low~~ | ~~KDF parameters unbounded from server~~ | **Fixed** — PBKDF2 max 2M iter, Argon2 max 4096 MiB / 16 threads |
| Medium | Password `String` copy at SDK boundary | Mitigated — `Zeroizing<String>` passed to SDK boundary, but SDK requires plain `String` internally |
| Medium | SSH key zeroization partial | Mitigated — Ed25519 raw bytes zeroized, but `PrivateKey`/`SigningKey` types lack `Zeroize` impl |
| Medium | `UserKeyState` holds decrypted key in plain HashMap | Open — SDK-managed state, needs upstream zeroizing container |
| Medium | No macOS swap protection | Open — `PT_DENY_ATTACH` prevents debugger but no `mlockall` equivalent |
| Medium | Sync holds read lock during HTTP call | Open — blocks state mutations during server requests |
| Medium | `login.json` has no integrity protection | Open — same-user attacker can redirect `server_url` |
| Medium | CI actions not pinned to commit SHAs | Open — tag-based references are a supply chain risk |
| Medium | `tokio` uses `features = ["full"]` | Open — wider attack surface than needed |
| Low | PIN length leaked via timing | Accepted — acceptable for 4-6 digit PINs per design decision |
| Medium | Offline vault cache on disk (`vault_cache.bin`) | Mitigated — envelope-encrypted with platform-bound CEK (macOS Keychain / Linux Secret Service). Fallback (no credential store) relies on master password KDF only. See ADR 016. |
| Low | macOS CEK lacks biometric gate | Open — Keychain item stored without `kSecAccessControlUserPresence`; same-user processes can read silently. Device-binding still applies. |
| Low | Background sync cannot update cache HMAC | Open — cache reflects vault state at last unlock; background sync detects changes but cannot re-sign without password hash |
| Low | Error messages leak vault item names/counts | Open — `resolve_single_ref` includes names in errors |
| Low | RUSTSEC-2023-0071 (RSA Marvin Attack) | Accepted — SDK transitive dep, no fix available, not exploitable over local socket |
| Low | RUSTSEC-2026-0049 (rustls-webpki CRL) | Accepted — SDK transitive dep, no fix available |
