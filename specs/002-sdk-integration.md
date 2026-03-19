# ADR 002: SDK Integration

## Status

Accepted

## Context

Bitwarden publishes `sdk-internal` — a Rust workspace containing crates for crypto, vault operations, auth, sync, and more. This is the same code that powers their official clients. It is not published to crates.io and has no stability guarantees, but it is battle-tested and regularly audited.

We need to consume this SDK without tightly coupling our entire codebase to its internal API surface.

## Decision

### Git Dependency Pinned to a Specific Revision

```toml
[workspace.dependencies]
bitwarden-core = { git = "https://github.com/bitwarden/sdk-internal", rev = "<pinned>" }
bitwarden-crypto = { git = "https://github.com/bitwarden/sdk-internal", rev = "<pinned>" }
bitwarden-vault = { git = "https://github.com/bitwarden/sdk-internal", rev = "<pinned>" }
bitwarden-pm = { git = "https://github.com/bitwarden/sdk-internal", rev = "<pinned>" }
bitwarden-ssh = { git = "https://github.com/bitwarden/sdk-internal", rev = "<pinned>" }
bitwarden-auth = { git = "https://github.com/bitwarden/sdk-internal", rev = "<pinned>" }
bitwarden-sync = { git = "https://github.com/bitwarden/sdk-internal", rev = "<pinned>" }
```

We pin to a specific git revision rather than tracking a branch. Updates are deliberate: bump the rev, fix any breakage in `bitsafe-sdk`, test, commit.

### Isolation via `bitsafe-sdk` Wrapper Crate

All BitSafe code depends on `bitsafe-sdk`, never on `bitwarden-*` crates directly.

**Strategy: Newtypes + selective own types**

- Where the SDK type is stable and useful, wrap it in a newtype: `struct BsCipher(sdk::CipherView)`
- Where we need a different shape or the SDK type is volatile, define our own type and convert
- The wrapper exposes a clean, stable API that the rest of BitSafe depends on
- When updating the pinned SDK rev, only `bitsafe-sdk` needs changes

### Crates We Consume

| Crate | Purpose |
|-------|---------|
| `bitwarden-pm` | Top-level `PasswordManagerClient` — the main entry point |
| `bitwarden-core` | `Client`, settings, platform configuration |
| `bitwarden-crypto` | Secure key storage, zeroizing allocator |
| `bitwarden-vault` | Cipher types, TOTP, folders, collections |
| `bitwarden-auth` | Login flows (password, SSO) |
| `bitwarden-sync` | Vault sync operations |
| `bitwarden-ssh` | SSH key operations |

### SDK Entry Point

`PasswordManagerClient` from `bitwarden-pm` is the top-level client:

```rust
let client = PasswordManagerClient::new(/* settings */);
client.auth().login(/* ... */);     // authenticate
client.crypto();                     // key management / unlock
client.vault().ciphers();           // cipher CRUD
client.sync().sync();               // vault sync
```

## Consequences

### Positive

- **Isolation**: SDK API changes only affect `bitsafe-sdk`
- **No FFI overhead**: Direct Rust dependency, no serialization boundary
- **Crypto safety**: We inherit `bitwarden-crypto`'s secure memory handling
- **Deliberate updates**: Pinned rev means no surprise breakage

### Negative

- **Build time**: The SDK pulls in many transitive dependencies
- **No semver**: We must manually verify compatibility on each rev bump
- **Wrapper maintenance**: The `bitsafe-sdk` crate must be kept in sync

### Upgrade Process

1. Update the pinned rev in workspace `Cargo.toml`
2. Fix any compilation errors in `bitsafe-sdk`
3. Run tests
4. Document changes in `UPGRADING.md`
