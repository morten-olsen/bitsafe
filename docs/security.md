# Security

This document covers how BitSafe protects sensitive data, known gaps, and planned improvements. It is a living document — update it when security-relevant code changes.

## Threat Model

BitSafe is a single-user daemon holding decrypted vault keys in memory. The trust boundary is the Unix socket — same model as `ssh-agent`. We defend against:

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

- `mlockall(MCL_CURRENT | MCL_FUTURE)` at service startup — prevents pages from being swapped to disk
- `prctl(PR_SET_DUMPABLE, 0)` — prevents core dumps and ptrace from non-root
- Both are **Linux-only** (`#[cfg(target_os = "linux")]` in `bitsafe-service/src/main.rs`)
- Both **log a warning and continue** if they fail (e.g. memlock rlimit exhausted)

### What's delegated to the SDK

- `bitwarden-crypto` uses `ZeroizingAllocator` and `KeyStore` internally for key material
- We never extract raw keys from the SDK — all crypto ops go through `PasswordManagerClient`

### Known gaps

- **No zeroization of passwords/PINs in BitSafe code.** Passwords flow as plain `String` through: CLI → JSON → socket → service → SDK. Each intermediate `String` is not zeroized after use. This includes:
  - `LoginParams.password` and `UnlockParams.password` in protocol types
  - `LoginCredentials.password` in the SDK wrapper
  - `Session.pin` held in service state as `Option<String>`
  - Local `String` variables from `rpassword::prompt_password()` in the CLI
- **No macOS memory hardening.** `mlockall` and `PR_SET_DUMPABLE` have no macOS equivalents in the current code. macOS processes may swap sensitive pages.

### Future improvements

- Use `zeroize::Zeroizing<String>` for all password/PIN fields
- Investigate macOS `mlock` support (per-page, not process-wide)
- Consider `seccomp` filtering on Linux to restrict syscalls

## IPC Security

### Socket permissions

- Runtime directory: `$XDG_RUNTIME_DIR/bitsafe/` (mode `0700`) or `/tmp/bitsafe-<id>/` fallback
- Socket file: mode `0600` (owner read/write only)
- Stale sockets removed before binding

### Peer credential validation

- **Linux**: `SO_PEERCRED` check on every connection — peer UID must match service UID. Connections from other users are rejected.
- **macOS**: `getpeereid()` check (via tokio's `peer_cred()`) — same UID validation as Linux.

### No IPC encryption

- `PlainCodec` only — messages are length-prefixed JSON in cleartext
- Passwords transit the socket as plaintext JSON strings
- Socket permissions are the trust boundary (same as ssh-agent)
- The `Codec` trait is designed for a future `EncryptedCodec` (NaCl boxes or similar)

### Known gaps

- **Fallback socket path** uses `/tmp/bitsafe-<uid>/` (real UID via `libc::getuid()`). `$XDG_RUNTIME_DIR` is preferred when available (user-owned, `0700`, managed by systemd).

## Authentication & Lockout

### Master password backoff

- Exponential backoff on failed login/unlock: 0s, 1s, 2s, 4s, 8s, 16s, 30s (capped)
- Enforced server-side — the service rejects attempts before the backoff window expires (error code 1009)
- Counter resets on successful authentication
- **Not persisted to disk** — service restart resets the counter

### PIN

- 3 attempts, no delay between them
- After 3 failures: vault locks automatically (keys scrubbed, need master password)
- PIN stored as `Option<String>` in service memory, never on disk
- Constant-time comparison via XOR fold — **leaks length** due to early return on length mismatch. Acceptable for short PINs (4-6 digits).

### Session re-verification

- After unlock, a session timer starts (default 300s)
- Expired session gates vault operations behind re-verification
- Re-verify order: biometric → PIN → master password fallback
- Session is per-service, not per-client — all connected clients share one session

## Prompt Agent Security

### Binary discovery

- Service looks for `bitsafe-prompt` next to its own binary (`current_exe()`), then falls back to `PATH`
- **PATH fallback is a risk** — an attacker who can place a binary earlier in PATH could intercept password prompts
- Mitigation: install both binaries in the same directory

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
1. Dropping the `BitsafeClient` (which drops the inner `PasswordManagerClient`)
2. Creating a fresh `BitsafeClient` for the same server URL
3. Preserving `LoginState` so re-unlock doesn't require re-login

### Concerns

- **Key erasure depends on SDK Drop impl.** We assume `bitwarden-crypto`'s `KeyStore` zeros keys on drop (it uses `ZeroizingAllocator`), but this is not verified at the BitSafe layer.
- **LoginState persists across lock.** The `LoginState` contains `MasterPasswordUnlockData` (encrypted user key, KDF params) and `WrappedAccountCryptographicState` (encrypted private key). These are encrypted — holding them in memory while locked is equivalent to what the official Bitwarden client does.

### Client-managed state repositories

The SDK requires the consuming application to provide repositories for certain state types. We register in-memory `HashMap`-backed repositories (`bitsafe-sdk/src/state.rs`) for:

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

After successful login, the service saves encrypted credentials to `~/.local/share/bitsafe/login.json` (mode `0600`) so subsequent service restarts only require `bitsafe unlock`, not a full re-login.

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
- Created on `bitsafe login`
- Read on service startup → starts in `Locked` state if present
- Deleted on `bitsafe logout`

**Security notes:**
- The persisted file contains the same encrypted material that the Bitwarden server returns on login — equivalent to what official Bitwarden clients cache locally
- File permissions are set to `0600` immediately after write
- An attacker with read access to this file still needs the master password to derive keys

## Configuration Security

- Config file at `~/.config/bitsafe/config.toml` — file permissions are not verified by the service
- No input validation on config values (e.g. negative durations, zero PIN attempts)
- Config is loaded once at startup — runtime changes require restart
- Default values are security-reasonable (300s session, 900s auto-lock, 3 PIN attempts)

## Dependency Security

### Bitwarden SDK

- Git dependency pinned to a specific revision — no published crate, no semver guarantees
- Uses pre-release RustCrypto crates (`argon2 =0.6.0-rc.2`, etc.)
- Transitive deps must be manually pinned after updates (see `UPGRADING.md`)
- **`digest 0.11.1` is yanked on crates.io** but required for compatibility

### Other notable dependencies

- `rpassword` — terminal password input, well-maintained
- `tokio` — async runtime, full features enabled
- `serde_json` — JSON parsing, no known vulnerabilities
- `libc` — FFI for mlockall/prctl, Linux-only

## Known Issues Prioritized

| Priority | Issue | Status |
|----------|-------|--------|
| High | No secret zeroization in BitSafe code | Open — use `zeroize::Zeroizing<String>` for passwords and PINs |
| ~~High~~ | ~~macOS Swift string injection~~ | **Fixed** — `escape_swift()` and `escape_applescript()` sanitize all interpolated strings |
| ~~High~~ | ~~No macOS peer credential check~~ | **Fixed** — UID check now uses `#[cfg(unix)]` (tokio's `peer_cred()` works on both Linux and macOS) |
| ~~Medium~~ | ~~Socket fallback path uses PID not UID~~ | **Fixed** — uses `libc::getuid()` on Unix |
| Medium | Prompt binary PATH fallback | Open — restrict to absolute path or same-directory-as-service only |
| Medium | Backoff counter resets on service restart | Open — consider persisting attempt count |
| ~~Medium~~ | ~~Inactivity timer not reset on vault ops~~ | **Fixed** — `touch()` called in `dispatch()` for every session-guarded operation |
| Medium | `UserKeyState` holds decrypted key in plain HashMap | Open — back with zeroizing container |
| Low | Config file permissions not checked | Open — warn if config is world-readable |
| Low | PIN length leaked via timing | Accepted — acceptable for 4-6 digit PINs per design decision |
| Low | mlockall failure is non-fatal | Open — consider failing hard if memory hardening is configured as required |
