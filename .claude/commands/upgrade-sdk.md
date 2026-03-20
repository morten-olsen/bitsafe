Upgrade the Bitwarden SDK dependency to a new revision.

Arguments: $ARGUMENTS

## Process (follow UPGRADING.md exactly)

1. Read `UPGRADING.md` for the current pin and known issues
2. If a target revision was provided in arguments, use that. Otherwise, check the sdk-internal commit log to identify a safe target.
3. **Before changing anything**, check Vaultwarden compatibility:
   - Look for changes to API binding paths (`/accounts/prelogin`, `/identity/connect/token`, `/api/sync`)
   - Look for changes to response model types (`SyncResponseModel`, `CipherDetailsResponseModel`)
   - If incompatible changes exist, stop and explain — do NOT proceed
4. Update the `rev` in root `Cargo.toml` workspace dependencies (all `bitwarden-*` entries)
5. Run `cargo update`
6. Compare transitive dependency versions against the SDK's `Cargo.lock`:
   - Check `digest`, `reqwest-middleware`, and any RustCrypto crates
   - Pin mismatches: `cargo update -p <crate>@<wrong> --precise <sdk-version>`
7. Run `cargo build --workspace` — fix any compilation errors in `grimoire-sdk`
8. Run `cargo test --workspace`
9. Update `UPGRADING.md` with the new revision, date, and any changes encountered
10. Update `CLAUDE.md` if any SDK gotchas changed

This is a high-risk operation. Do not skip steps. Report every issue encountered.
