# SDK Upgrade Guide

BitSafe depends on [bitwarden/sdk-internal](https://github.com/bitwarden/sdk-internal) pinned to a specific git revision.

## Current Pin

- **Revision**: `9e3be8abbe71319620e964a90d79539bf9d19d9c`
- **Date**: 2026-03-12
- **Notable**: Last rev before breaking API binding update (prelogin path change + sync response changes). The official Bitwarden clients use WASM build `0.2.0-main.617` which is compatible with this rev.

## Why This Rev

Commit `7dc0d60d` (2026-03-13) updated the Identity API bindings, changing:
- `/accounts/prelogin` → `/accounts/prelogin/password` (Vaultwarden doesn't support the new path)
- `SyncResponseModel` field types changed (Vaultwarden responses can't be deserialized)

We pin to `9e3be8ab` (one commit before) to stay compatible with Vaultwarden and match what the official Bitwarden clients ship.

## Upgrade Process

1. Check the [sdk-internal commit log](https://github.com/bitwarden/sdk-internal/commits/main) for changes since the current pin.
2. **Check Vaultwarden compatibility** — look for API binding updates that may change endpoint paths or response models.
3. Update the `rev` in `Cargo.toml` workspace dependencies (root + `crates/bitsafe-sdk/Cargo.toml`).
4. Run `cargo update` to refresh the lockfile.
5. **Check transitive dependency versions** — compare against the SDK's `Cargo.lock` and pin if needed:
   ```bash
   cargo update -p <crate>@<resolved> --precise <sdk-lockfile-version>
   ```
6. Run `cargo build` — fix any compilation errors in `crates/bitsafe-sdk/`.
7. Test against your Vaultwarden instance: login, unlock, sync, list.
8. Update this file with the new revision and any API changes encountered.

## Known Transitive Dependency Pins

These may need re-checking after a rev bump:

| Crate | SDK Version | Notes |
|-------|------------|-------|
| `digest` | `0.11.1` | Yanked on crates.io but needed for hmac/pbkdf2 compat |
| `reqwest-middleware` | `0.4.2` | SDK API uses `.query()` not present in 0.5.x |

## API Changes Log

| From Rev | To Rev | Changes |
|----------|--------|---------|
| (initial) | `9e3be8a` | Initial pin — pre-API-binding-update, Vaultwarden compatible |
| `9e3be8a` | `7dc0d60` | **BREAKING**: prelogin path changed, sync response model changed |
