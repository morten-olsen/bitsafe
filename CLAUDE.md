# CLAUDE.md

This file is the entrypoint for agents. Keep it current — if you discover something wrong or missing, fix it. Same for `specs/` and `docs/`.

## Principles

This is a security product. Code quality, auditability, and simplicity are not nice-to-haves — they are security properties.

- **Simplicity IS security.** If a reviewer can't follow the logic, it's a bug. Prefer straightforward code over clever abstractions.
- **Minimal surface area.** Every public API, every dependency, every feature is attack surface. Add only what's needed.
- **No `.unwrap()` on fallible operations** in non-test code. Use typed errors (`thiserror`), propagate with `?`.
- **No `unsafe`** without a spec-level justification and a `// SAFETY:` comment.
- **Secrets are toxic.** Never log them, never put them in error messages, never hold them longer than needed.
- **Specs before code.** Design changes go through `specs/` before implementation. See Spec Lifecycle below.

## Maintenance Rules

- **This file**: Update when gotchas change, conventions shift, or you discover undocumented traps. Don't document the obvious — only what would surprise an agent reading the code for the first time.
- **`specs/`**: ADR-style decision records. Immutable once implemented — see Spec Lifecycle below.
- **`docs/`**: Living documentation of the current system. Always reflects reality. Update when code changes.
- **`UPGRADING.md`**: SDK revision tracking and transitive dep pinning. Update on every rev bump.

## Spec Lifecycle

Full process documented in `docs/development.md`. Quick reference:

Specs live in `specs/` as numbered ADR-style documents (`NNN-slug.md`). Every spec has a Status field.

| Status | Meaning | Mutable? |
|--------|---------|----------|
| **Proposed** | Under discussion, not yet approved | Yes — freely edit |
| **Accepted** | Approved for implementation | Yes — refine details |
| **Implemented** | Code exists matching this spec | **No** — frozen as historical record |
| **Superseded** | Replaced by a newer spec | **No** — add "Superseded by: NNN" |

**Key rules:**
- Changing behavior described by an Implemented spec requires a **new spec** that supersedes the old one
- Every spec must include a **Security Analysis** section with: Threat Model Impact, Attack Vectors (table with severity), Planned Mitigations (table with mechanism), Residual Risk, and Implementation Security Notes (filled during finalization)
- Use `/spec <description>` to create new specs, `/implement specs/NNN-slug.md` to implement them
- `docs/` reflects current reality; `specs/` preserves decision history. Don't duplicate between them.

## Commits

Atomic conventional commits. Each commit is one logical change.

- Format: `type(scope): description` — lowercase, imperative mood, no period
- Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `security`
- Scopes: crate names (`cli`, `service`, `sdk`, `protocol`, `prompt`, `common`) or feature areas (`ssh`, `auth`, `sync`, `ipc`)
- Spec-only: `docs(specs): add ADR NNN - title`
- Breaking changes: `feat(scope)!: description` with body explaining the break
- Don't mix unrelated changes in one commit. A feature touching multiple crates for one purpose is fine as one commit.

## Feature Development Lifecycle

Full process documented in `docs/development.md`. Quick reference:

New features follow a six-phase lifecycle via `/feature <description>`:

1. **Brainstorm & Threat Analysis** — understand the feature, map security surface, identify attack vectors
2. **Spec** — write the ADR with Security Analysis section capturing all vectors and planned mitigations
3. **Implement** — code the spec, pass quality gates (fmt, clippy, tests)
4. **Test** — add tests targeting the threat analysis, cover every attack vector
5. **Security Audit** — adversarial review verifying every planned mitigation is actually implemented
6. **Finalize** — fill in spec's Implementation Security Notes, update spec status + docs, commit

Each phase pauses for user review. The audit in Phase 5 checks that every attack vector from Phase 1 has a working mitigation. Critical/High findings loop back to Phase 3. The spec's Security Analysis section evolves: Planned Mitigations are written in Phase 2, Implementation Security Notes are filled in Phase 6.

Bug fixes follow a lighter three-phase workflow via `/fix <description>`: Diagnose (root cause + security triage) → Fix & Test (minimal fix + regression test) → Verify & Commit. Security bugs get extra scrutiny: similar-pattern search, threat model update, and `security(scope):` commit type.

Individual phases are also available standalone: `/spec`, `/implement`, `/refactor`, `/test`, `/security-review`, `/audit`, `/sync-docs`, `/check`, `/upgrade-sdk`.

## Build

- **Recommended**: `task build` — builds everything for the current platform
- `task test` — all tests. `task install` — install to `~/.cargo/bin`
- **Rust workspace**: `cargo check --workspace` / `cargo test --workspace`
- **Native prompts** (outside workspace, optional):
  - macOS: `cd native/macos && swift build -c release` → `grimoire-prompt-macos`
  - Linux: `cd native/linux && cargo build --release` (needs `libgtk-4-dev`, `libadwaita-1-dev`) → `grimoire-prompt-linux`
- Binaries: `grimoire` (CLI), `grimoire-service` (daemon + SSH agent), `grimoire-prompt` (fallback), `grimoire-prompt-{macos,linux}` (native UI)
- **Prompt binary discovery order**: `grimoire-prompt-{platform}` next to service → `grimoire-prompt` next to service → PATH lookup → terminal fallback

## Auth Architecture — Matching the Official CLI

The official Bitwarden CLI does **not** use the SDK for prelogin, login, or sync. It does its own HTTP calls and only uses the SDK for crypto. We follow the same pattern:

- **Prelogin**: our HTTP POST to `/identity/accounts/prelogin` — gets KDF params
- **Key derivation**: SDK's `MasterPasswordAuthenticationData::derive()` — derives master key hash
- **Login**: our HTTP POST to `/identity/connect/token` (form-encoded) — gets access token + encrypted keys
- **Token management**: stored in our `TokenStore`, SDK reads via `ClientManagedTokens` for any API calls it makes internally
- **Crypto init**: SDK's `initialize_user_crypto()` — decrypts vault keys using the login response data
- **Sync**: our HTTP GET to `/api/sync` — parses ciphers from JSON, stores in cipher repository
- **Vault ops**: SDK's `vault().ciphers().list()` / `.get()` / `.totp()` — reads from the cipher repository we populated

This avoids all Vaultwarden compatibility issues with the SDK's generated API bindings.

## SDK Dependency — The Big Gotcha

- `bitwarden/sdk-internal` is a **git dep pinned to a rev**, not a published crate
- The SDK uses **pre-release RustCrypto crates** (`argon2 =0.6.0-rc.2`, etc.) — Cargo resolves transitive deps from crates.io independently from the SDK's own lockfile
- After any `cargo update` or rev bump, you **must** compare transitive dep versions against the SDK's `Cargo.lock` and pin mismatches manually:
  ```
  cargo update -p <crate>@<wrong-version> --precise <sdk-lockfile-version>
  ```
- Currently pinned: `digest 0.11.1` (yanked but required), `reqwest-middleware 0.4.2` (0.5.x breaks SDK)
- See `UPGRADING.md` for the full process

## SDK Wrapper (`grimoire-sdk`)

Full investigation documented in `docs/sdk-integration.md`.

- `GrimoireClient` wraps `PasswordManagerClient` behind `Arc<Mutex<>>` — all sub-clients share the lock
- All other crates depend on `grimoire-sdk`, never on `bitwarden-*` directly
- **Do NOT use the SDK for HTTP** — the SDK's generated API bindings (`bitwarden-api-identity`, `bitwarden-api-api`) are incompatible with Vaultwarden in multiple ways. The official Bitwarden CLI doesn't use them either. See `docs/sdk-integration.md` for the full investigation.
- **SDK is crypto-only** — we use `MasterPasswordAuthenticationData::derive()`, `initialize_user_crypto()`, and `vault().ciphers().list()/get()/totp()`. Everything else is our own HTTP calls.
- **Token management**: `PasswordManagerClient::new_with_client_tokens()` + our `TokenStore` implementing `ClientManagedTokens`. We set the access token after our own login HTTP call.
- **Cipher repository population**: sync is our own HTTP GET to `/api/sync`. We parse the JSON, deserialize individual `CipherDetailsResponseModel` entries, and store them in our in-memory repository. The SDK then decrypts from that repository.
- **State database**: SDK needs `platform().state().initialize_database()` with SQLite config + `get_sdk_managed_migrations()` before any crypto ops. Also needs client-managed in-memory repos for `Cipher`, `Folder`, `LocalUserDataKeyState`, `UserKeyState`, `EphemeralPinEnvelopeState`.
- **Lock = drop + recreate client** — the SDK has no explicit lock/clear-crypto. We recreate `GrimoireClient` on lock but preserve `LoginState` so unlock doesn't require re-login.
- **Login state persists to disk** — saved to `~/.local/share/grimoire/login.json` (mode `0600`) after login. Service starts in `Locked` state if this file exists. Deleted on logout. Contains only email + server_url.
- **V1 account assumption**: We construct `WrappedAccountCryptographicState::V1` from the login response's `PrivateKey` field. V2 accounts (COSE) need the full `PrivateKeysResponseModel` from sync — not yet handled.
- **`grimoire run` uses exec** — after resolving `grimoire:<id>/<field>` references in env vars, the process is replaced via `execvp()`. No wrapper process, no TTY breakage. All resolution errors must happen before exec. See `docs/secret-injection.md` and `specs/007-secret-injection.md`.
- **Vaultwarden SSH key requirement**: Vaultwarden must have `EXPERIMENTAL_CLIENT_FEATURE_FLAGS=fido2-vault-credentials,ssh-key-vault-item,ssh-agent` set — without this, SSH key ciphers (type 5) are filtered from the sync response entirely
- SSH signing currently supports Ed25519 only; RSA/ECDSA can be added
- **SSH agent enforces access approval** — the embedded agent extracts the SSH client's peer PID via `SO_PEERCRED` and checks the approval cache before signing. If not approved, it tries GUI prompt (biometric/PIN/password); if no GUI, signing fails. Users pre-approve from headless sessions via `grimoire approve`. See `docs/ssh-agent.md`.
- **`grimoire approve`** — CLI command for headless/SSH sessions. Prompts for master password in terminal, verifies against the server (prelogin + derive + token request), then refreshes session + grants scoped access approval. Same backoff rules as login/unlock.
- **CLI auto-unlock** — vault commands (`list`, `get`, `totp`, `sync`, `run`) automatically request unlock via the service's GUI prompt when the vault is locked (error 1000). If no GUI is available (error 1008), the CLI tells the user to run `grimoire approve` first. Access approval is handled by the service's own GUI flow (biometric → PIN → password), not by the CLI.
- **Unlock always grants approval** — `handle_unlock` grants scoped access approval on successful unlock regardless of whether the password came from CLI, GUI prompt, or `grimoire approve`. One password entry handles both unlock and approval.

### Specific SDK incompatibilities with Vaultwarden (discovered the hard way)

- **Prelogin endpoint**: SDK hits `/accounts/prelogin/password`, Vaultwarden only supports `/accounts/prelogin`. Path changed in SDK commit `0d52f617` (Dec 2025). The official Bitwarden clients bypass this by doing their own HTTP call.
- **Login error responses**: SDK expects `{"error":"invalid_grant","error_description":"..."}`, Vaultwarden returns `{"error":"","message":"..."}`. SDK's `LoginErrorApiResponse` untagged enum can't deserialize it.
- **Sync response model**: SDK's `SyncResponseModel` has field type mismatches with Vaultwarden's response. Deserialization fails with "invalid type: map, expected a string".
- **`set_tokens` is pub(crate)**: Can't call it from outside `bitwarden_core`. Must use `ClientManagedTokens` trait instead.
- **Cipher `data` field**: SDK expects `Option<String>`, Vaultwarden sends a JSON object. We stringify it before deserialization in `sync.rs`. The field is a legacy duplicate — the SDK reads from the typed `login`/`card`/`identity` fields instead.

## Protocol (`grimoire-protocol`)

- `RequestParams` is `#[serde(untagged)]` — deserialization tries variants in declaration order. Structs with all-optional fields (like `UnlockParams`, `VaultListParams`) will greedily match any input. Use `#[serde(deny_unknown_fields)]` on every variant struct to prevent false matches.
- `LoginParams.password` and `UnlockParams.password` are both `Option<String>` — `None` means "service should spawn the GUI prompt agent"
- **Login** prompts in the terminal (one-time setup). **Unlock and approval** go through the service's GUI prompt (defense against RCE — attacker with shell access can trigger unlock but can't complete it without interacting with the GUI dialog on the user's display). For headless/SSH sessions, `grimoire approve` provides a terminal-based pre-approval path.
- Responses use `skip_serializing_if = "Option::is_none"` — clients must handle both `null` and missing-key as equivalent

## Service State Machine

- Three states: `LoggedOut → Locked → Unlocked`
- Within Unlocked: all vault operations gated by scoped access approval (biometric → PIN → password prompt). See `docs/lifecycle.md`.
- PIN: 3 attempts, no backoff, then auto-lock (vault locks, keys scrubbed, need master password)
- Master password: exponential backoff (1s, 2s, 4s... capped 30s), enforced server-side
- State is behind `Arc<RwLock<ServiceState>>` — read lock for queries, write lock for mutations
- Auto-lock worker checks every 30s with TOCTOU double-check pattern (read check, then write-lock + re-check)
- **Config is loaded once at startup** — changes to `~/.config/grimoire/config.toml` require service restart

## Prompt Agent (`grimoire-prompt`)

- Spawned by the service as a subprocess, not linked as a library
- Binary discovery: checks next to `current_exe()`, then `PATH`
- Writes one JSON line to stdout, exits with 0/1/2
- Platform detection at runtime, not compile time — `zenity`/`kdialog`/`osascript` checked via `which`
- Biometric on Linux needs `fprintd-verify` in PATH; on macOS uses inline Swift via `swift -e` (requires Xcode CLI tools)
- Terminal fallback always available but no biometric support

## Security Notes

Full security analysis in `docs/security.md` — read it before touching auth, crypto, IPC, or prompt code.

Key gotchas not obvious from the code:

- `mlockall` + `PR_SET_DUMPABLE` at startup on Linux only — **logs warning and continues** if either fails. macOS has no equivalent.
- Socket: `0600` perms + UID peer check on all Unix (`SO_PEERCRED` on Linux, `getpeereid` on macOS)
- **Secret zeroization** — all password and PIN fields use `zeroize::Zeroizing<String>` (zeroed on drop). The SDK uses `ZeroizingAllocator` internally for key material. The `UserKeyState` repository still holds a decrypted user key as base64 in a plain `String` — this is SDK-managed state and needs an upstream fix.
- **Scoped access approval** — all vault operations (`vault.list`, `vault.get`, `vault.totp`, `vault.resolve_refs`, `ssh.list_keys`, `ssh.sign`, `sync.trigger`) require per-session approval via biometric/PIN even when vault is unlocked. Same gate for CLI commands and SSH agent signing. Scoped to terminal session leader PID via `/proc/<pid>/stat` (Linux) or `getsid` (macOS). **Always on, not configurable.** Hardcoded: 300s approval duration, session scope, 3 PIN attempts. See `docs/lifecycle.md`.
- **Security parameters are hardcoded constants** — auto-lock (900s), sync interval (300s), approval duration (300s), approval scope (session), PIN max attempts (3), approval required (always). Config file only controls: server URL, prompt method, SSH agent enabled. This prevents config-based downgrade attacks.
- **Encrypted IPC** — every connection performs X25519 key exchange + ChaCha20-Poly1305 AEAD. Socket permissions remain the primary trust boundary; encryption provides defense-in-depth.
- PIN constant-time comparison leaks length (early return on length mismatch) — acceptable for short PINs
- Socket fallback path uses `libc::getuid()` (real UID). `$XDG_RUNTIME_DIR` preferred when available.
- Prompt binary discovered via PATH fallback — binary replacement risk if attacker controls PATH
