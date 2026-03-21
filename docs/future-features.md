# Future Feature Ideas

Ideas for features that leverage Grimoire's existing approval system and secret management infrastructure. These are brainstorm-stage — each would need a proper spec before implementation.

## Third-Party Integration: Identity & Secret Broker

### PAM Module (`pam_grimoire`)

A PAM authentication module that delegates `sudo`, SSH login, or screen unlock to Grimoire's approval gate. Instead of typing a system password, the native biometric/PIN dialog pops up. Reuses the existing scoped approval + prompt agent infrastructure directly.

### Docker/Podman Credential Helper (`docker-credential-grimoire`)

A credentials helper that supplies container registry credentials from the vault. Docker already supports pluggable credential stores — Grimoire would be a drop-in backend, with the approval gate protecting `docker pull` from private registries without ever writing credentials to `~/.docker/config.json`.

### Kubernetes Secret Injection

Grimoire could serve as a secret store for k8s workloads — either as a CSI secrets driver or a sidecar/init container that resolves `grimoire://` references into mounted secret files. The `vault.resolve_refs` RPC already does batch resolution.

### Database Proxy with Just-in-Time Credentials

A lightweight TCP proxy (e.g., for Postgres) that intercepts the auth handshake and injects the password from the vault. The DBA connects to `localhost:5433`, Grimoire prompts for approval, then proxies to the real server with the vault-stored password. Credentials never touch `~/.pgpass` or environment variables.

## Developer Tooling

### Git Credential Helper (`git-credential-grimoire`)

Git supports pluggable credential helpers. Grimoire could serve HTTPS credentials for GitHub/GitLab/Gitea with biometric approval on each `git push`. Combined with the existing SSH agent for SSH-based auth, this covers both Git transport protocols.

### `.env.grimoire` Manifest Files

Extend `grimoire run` to support a declarative manifest file:

```
# .env.grimoire
DATABASE_URL=grimoire://Production DB/password
API_KEY=grimoire://Stripe/notes
```

Teams check in the manifest (no actual secrets) and `grimoire run` resolves them all. Already 90% there with `grimoire run`'s existing env var scanning — this just adds file-based input.

### HTTP Credential Provider

Automatically supply HTTP credentials from the vault for tools like `curl`, `wget`, and `httpie` — eliminating plaintext `.netrc` files and manual token copy-paste during API testing.

The simplest form would be a virtual `.netrc` generator:

```bash
curl --netrc-file <(grimoire netrc) https://api.example.com/endpoint
```

However, this is a deceptively hard problem with multiple layers of complexity:

**1. Item-to-host mapping** — which vault item serves which service?
- Bitwarden's URI matching (exact, host, starts-with, regex) is a starting point, but many API credentials don't have URIs set
- Multiple items may match the same host (personal vs. team token, staging vs. prod)
- Fallback options (naming conventions, explicit mapping config, tags) each add friction or fragility

**2. Credential type** — the password field is just a string; how should it be used?
- **Basic auth**: username + password → `Authorization: Basic <base64>`
- **Bearer token**: password is a static API key → `Authorization: Bearer <token>`
- **API key in header**: password goes in a custom header like `X-API-Key`
- **API key in query param**: password goes in `?api_key=<token>` (some legacy APIs)
- **OAuth2 client credentials**: username is client_id, password is client_secret → must call a token endpoint to exchange for a short-lived access token
- **OAuth2 refresh token**: password is a refresh token → exchange at token endpoint, cache the access token until expiry
- **Mutual TLS**: credential is a client certificate, not a password at all

**3. Token exchange flows** — some credentials aren't directly usable:
- OAuth2 client credentials grant requires knowing the token endpoint URL
- Some APIs need a two-step flow (get session token, then use it)
- Token caching and refresh logic to avoid hitting the auth server on every request

**4. `.netrc` limitations** — even for basic auth, `.netrc` only supports machine/login/password. No path scoping, no port distinction, no auth type selection. More capable alternatives exist (e.g., `git-credential` protocol, `curl --config`) but none handle the full problem space.

This needs significant design work. A proper spec should consider whether Grimoire should:
- Stay minimal (virtual `.netrc` for basic auth only, explicit `grimoire://` references for everything else)
- Support auth type metadata (via Bitwarden custom fields or a local config overlay)
- Act as an HTTP credential proxy that intercepts and injects headers transparently
- Implement OAuth2 flows internally or delegate to existing tools

The `grimoire run` env var injection already handles the "explicit reference" case well. The open question is whether implicit, URL-based credential injection is worth the complexity.

### OAuth2 Token Broker (`grimoire token`)

Turn Grimoire into a token vending machine for OAuth2-based services. Store client credentials (client ID + secret) in a vault item, and Grimoire handles the full lifecycle — token exchange, caching, and refresh — behind the approval gate.

```bash
# Get a valid bearer token (exchanges or refreshes automatically)
curl -H "Authorization: Bearer $(grimoire token "GitHub App")" https://api.github.com/repos

# Or inject via grimoire run
GITHUB_TOKEN="grimoire-token://GitHub App" grimoire run -- ./deploy.sh
```

**What Grimoire manages:**
- **Client credentials grant**: POST to the token endpoint with client_id + client_secret, return the access token
- **Token caching**: keep the access token in memory (not on disk), reuse until expiry
- **Automatic refresh**: if a refresh token was issued, use it transparently when the access token expires
- **Token endpoint discovery**: stored as a custom field or URI on the vault item, or via OpenID Connect discovery (`.well-known/openid-configuration`)

**Vault item structure** (using Bitwarden's existing fields):
- **Username**: client ID
- **Password**: client secret
- **URI**: token endpoint (or base URL for discovery)
- **Custom fields**: scopes, audience, grant type overrides

**Service-side components:**
- New RPC method `oauth.token(item_id, scopes?)` — returns a valid access token, exchanging or refreshing as needed
- In-memory token cache keyed by (item_id, scopes) — tokens never written to disk
- Cache cleared on vault lock (same as all decrypted material)

**Design considerations:**
- Should only support confidential client flows (client credentials, refresh token) — authorization code flow requires a browser redirect and is a much larger scope
- Token endpoint TLS verification must be strict (no `--insecure` equivalent)
- Rate limiting on token exchange to avoid hammering auth servers
- Whether to support non-standard token endpoints (some services deviate from RFC 6749)
- Scopes may vary per invocation for the same client — cache key must include requested scopes

This pairs well with the HTTP credential provider (which could delegate to the token broker for OAuth2 items) and with `grimoire run` (via a `grimoire-token://` reference scheme).

### Password/Passphrase Generation (`grimoire generate`)

Integrated password and passphrase generator:

```bash
# Random password
grimoire generate --length 32 --charset alphanumeric+symbols

# Diceware-style passphrase
grimoire generate --type passphrase --words 6

# Generate and store directly (requires vault write ops)
grimoire generate --length 24 --save "New API Key"
```

Basic utility, but important for a security tool — users should be able to generate and store credentials in one flow without reaching for another tool.

### Clipboard with Auto-Clear (`grimoire clip`)

Copy a secret to the system clipboard and automatically clear it after a timeout:

```bash
# Copy password to clipboard, clear after 15 seconds
grimoire clip <id>

# Copy a specific field
grimoire clip <id> -f totp
```

Table-stakes for password managers. Requires platform-specific clipboard access (`pbcopy`/`pbpaste` on macOS, `xclip`/`wl-copy` on Linux). The auto-clear timer should survive even if Grimoire exits (spawn a background clearer or use platform clipboard expiry where available).

### IDE/Editor Plugin (VS Code, JetBrains)

A language server or extension that detects `grimoire://` references in config files, validates they resolve, and offers code actions to insert references. Could also provide a secret picker UI.

## Platform Integration

### Secret Service D-Bus / macOS Keychain Bridge

Expose vault items through the platform's native secret API — `org.freedesktop.secrets` (Secret Service) on Linux, Keychain Services on macOS. Any application that already uses the system keychain — browsers, email clients, network managers, GUI apps — would transparently read from Grimoire with approval gating.

**How it works:**
- On Linux: Grimoire implements the Secret Service D-Bus interface, replacing or supplementing `gnome-keyring` / `kwallet`
- On macOS: a Keychain Services provider backed by the vault (more constrained, may require a helper binary)
- Lookups map to `vault.get` with the same approval gate — no secrets exposed without biometric/PIN/password

**Design considerations:**
- The Secret Service spec supports collections, items, and search attributes — mapping these to Bitwarden's folder/item/field model needs careful design
- Some apps store secrets frequently (e.g., Wi-Fi passwords on every connect) — approval fatigue is a real risk; may need "always allow" rules for specific apps or attribute patterns
- Replacing `gnome-keyring` entirely vs. running alongside it (some system components may depend on specific keyring behaviors)
- Must handle the chicken-and-egg problem: if the display manager uses the keyring for auto-login, Grimoire can't replace that part

### PKCS#11 Module (`grimoire-pkcs11.so`)

A shared library implementing the PKCS#11 cryptographic token interface. PKCS#11 is the industry standard for making keys available to applications without exposing the key material:

- **Firefox/Chrome**: TLS client certificate authentication
- **OpenVPN**: client certificate auth without key files on disk
- **OpenSSL/GnuTLS**: any application using these libraries can use vault keys via `engine`/`provider`
- **Smart card tools**: `pkcs11-tool`, `p11-kit`

The module would proxy crypto operations to Grimoire's service over the existing IPC socket, with each operation gated by access approval. Keys never leave the service process — the PKCS#11 module forwards sign/decrypt requests and returns results.

### Systemd Credential Integration

Systemd supports `LoadCredential=` and `ImportCredential=` directives for injecting secrets into service units. A Grimoire credential provider would let systemd services load secrets at startup without environment variables or files on disk:

```ini
# /etc/systemd/system/myapp.service
[Service]
LoadCredential=db-password:grimoire://Production DB/password
ExecStart=/usr/bin/myapp --db-password-file %d/db-password
```

The service reads the secret from a file descriptor that systemd provides, and Grimoire resolves the reference at unit start time. Requires the vault to be unlocked (service units start after login, so this typically works for user-level units via `systemctl --user`).

### WireGuard/VPN Key Injection

Store WireGuard private keys and OpenVPN certificates in the vault, inject them at connection time:

```bash
# WireGuard: inject private key into config
PRIVATE_KEY="grimoire://WireGuard Home/notes" grimoire run -- wg-quick up wg0

# Or as a PostUp hook in wg0.conf
PostUp = grimoire get "WireGuard Home" -f notes | wg set %i private-key /dev/stdin
```

Network credentials are exactly the kind of long-lived, high-value secret that shouldn't sit in `/etc/wireguard/` as a plaintext file. The approval gate ensures VPN connections require explicit user presence.

### FIDO2/WebAuthn Authenticator

Grimoire could act as a platform authenticator for WebAuthn challenges. The Vaultwarden feature flags already include `fido2-vault-credentials`, suggesting the vault can store FIDO2 credential keys. Grimoire's approval gate serves as the "user presence" and "user verification" checks that the WebAuthn spec requires.

**How it works:**
- A browser extension or platform integration registers Grimoire as an authenticator
- When a site requests WebAuthn authentication, the challenge is forwarded to Grimoire's service
- Grimoire prompts for approval (biometric = UV, any approval = UP), signs the challenge with the stored credential key, and returns the assertion
- Registration (creating new credentials) would store the key pair in the vault

**Design considerations:**
- Requires browser integration (extension or platform authenticator API)
- Must implement the full CTAP2/WebAuthn attestation and assertion flow
- Resident keys (discoverable credentials) need the vault to be unlocked before the browser can enumerate them
- Backup eligibility flags: since keys are synced via Vaultwarden, they are technically multi-device — this affects relying party risk assessments

## Runtime Encryption for Third-Party Apps

### Application Encryption Key Broker (`vault.derive_key`)

Expose a new RPC method that returns a deterministic encryption key derived from a vault item + application-specific context (HKDF). Third-party apps call Grimoire's socket to get their encryption key on startup, use it for at-rest encryption, and never persist the key. When Grimoire locks, the key is gone.

Example flow:

```
App -> grimoire socket -> vault.derive_key(item_id, context="myapp-db-encryption")
                       -> approval prompt (biometric)
                       -> HKDF(vault_item_secret, context) -> 256-bit key
```

This transforms Grimoire from a password manager into a local keychain that other applications build on.

### Cryptographic Operations (`grimoire sign` / `grimoire decrypt`)

Expose the vault's keys for general-purpose signing and decryption — not just SSH authentication challenges but arbitrary data. The SSH agent already proves this works for signing; this generalizes it.

**Signing:**

```bash
# Sign a file with an SSH key from the vault
grimoire sign --key "Deploy Key" < release.tar.gz > release.tar.gz.sig

# Sign a git tag (alternative to git's built-in SSH signing)
echo "v1.0.0 release" | grimoire sign --key "Signing Key" --armor

# Pipe-friendly for verification workflows
sha256sum build/* | grimoire sign --key "CI Key" > manifest.sig
```

**Decryption:**

```bash
# Decrypt a file encrypted to one of your vault keys
grimoire decrypt --key "Team Key" < secrets.enc > secrets.json

# Decrypt inline for piping
curl -s https://internal/config.enc | grimoire decrypt --key "Config Key" | jq .
```

**What already exists vs. what's new:**
- `ssh.sign` already signs arbitrary data with Ed25519/RSA keys — but only via the SSH agent protocol, which expects SSH-formatted challenges
- New: sign raw data (not wrapped in SSH protocol framing), output detached signatures in standard formats
- New: decryption of data encrypted to the public half of a vault key (e.g., age, OpenPGP, or raw asymmetric decryption)

**Key types and formats:**
- **Ed25519**: signing (already supported in SSH agent), decryption via X25519 conversion (well-established, libsodium does this)
- **RSA**: signing with PKCS#1 v1.5 or PSS, decryption with OAEP
- **Output formats**: raw bytes, PEM/armor, SSH signature format (for `ssh-keygen -Y verify` compatibility)

**Design considerations:**
- All operations gated by the same scoped access approval as SSH signing
- Private keys never leave the service process — data flows in, signatures/plaintext flows out
- Should support both item-ID and name-based key selection (like `grimoire get`)
- Streaming vs. buffered: large files need streaming sign/decrypt, but the IPC protocol is message-based — may need a size limit or a file-path mode
- Whether to support symmetric encryption/decryption using vault-stored passwords (simpler use case, different trust model)
- Compatibility: should `grimoire sign` output be verifiable with standard tools (`ssh-keygen -Y verify`, `openssl dgst -verify`, `age -d`)?

This pairs naturally with the SOPS/age integration (Grimoire becomes the key backend) and the attestation token feature (sign attestations with vault keys).

### SOPS/age Integration

Grimoire could act as a key source for [SOPS](https://github.com/getsops/sops) or `age` encrypted files. Store the age identity in the vault, and a `grimoire-age-plugin` retrieves it on demand with approval. Encrypted config files live in git, decrypted only when Grimoire approves.

## SSH Certificate Authority

### Ephemeral SSH Certificates (`grimoire ssh cert`)

Turn Grimoire into a lightweight SSH certificate authority. A CA key is stored in the vault and added to target machines as a `TrustedUserCAKeys`. When a user wants to connect, Grimoire mints a short-lived SSH certificate on demand — no static keys in `authorized_keys`, no key distribution, no revocation lists.

Similar to how HashiCorp Vault's SSH secrets engine works, but local and personal rather than requiring a central server.

```bash
# Grimoire mints a certificate, SSH agent presents it automatically
ssh production-server

# Or explicitly request a certificate for a specific principal
grimoire ssh cert --principal deploy --ttl 5m

# Certificate is cached in-memory for its lifetime, then discarded
```

**How it works:**
1. A CA key pair lives in the vault (Ed25519 or RSA)
2. Servers are configured to trust the CA's public key via `TrustedUserCAKeys` in `sshd_config`
3. When the SSH agent receives an auth challenge for a configured host, Grimoire signs the user's ephemeral public key with the CA key, producing a short-lived certificate
4. The certificate is presented to the server, which validates it against the trusted CA
5. Certificate expires (e.g., 5 minutes), no cleanup needed

**Server-side setup (one-time):**
```bash
# Add Grimoire's CA public key to the server
echo "ssh-ed25519 AAAA... grimoire-ca" >> /etc/ssh/trusted_user_ca_keys
# In sshd_config:
# TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys
```

**Certificate contents:**
- **Key ID**: `grimoire:<email>:<timestamp>` (for audit trails in server auth logs)
- **Principals**: configurable per-host or per-group (e.g., `deploy`, `admin`, `readonly`)
- **Validity**: short-lived, default 5 minutes, configurable per-profile
- **Extensions**: `permit-pty`, `permit-port-forwarding`, etc. — lockable per-profile

**Configuration:**
```toml
# ~/.config/grimoire/config.toml
[ssh_ca]
ca_key = "item-id-or-name"      # vault item holding the CA key
default_ttl = "5m"
default_principals = ["deploy"]

[[ssh_ca.profiles]]
name = "production"
hosts = ["prod-*", "*.prod.internal"]
principals = ["deploy"]
ttl = "2m"
extensions = ["permit-pty"]

[[ssh_ca.profiles]]
name = "staging"
hosts = ["staging-*"]
principals = ["deploy", "admin"]
ttl = "15m"
extensions = ["permit-pty", "permit-port-forwarding"]
```

**Integration with existing SSH agent:**
- The embedded SSH agent already handles key listing and signing
- Certificate minting extends this: when the agent sees a host matching a CA profile, it generates an ephemeral key pair, signs it with the CA key to produce a certificate, and presents the certificate
- If no profile matches, falls back to regular key-based auth (existing behavior)

**Design considerations:**
- **Principal mapping**: who decides which principals a user can claim? In a personal setup, the user controls everything. In a team setup, this becomes an authorization policy problem — Grimoire would need to enforce principal restrictions
- **CA key protection**: the CA key is the crown jewel — signing with it should always require the highest approval level (biometric or master password, never just PIN)
- **Ephemeral vs. user keys**: the certificate can sign the user's existing SSH key (simpler, key already in vault) or a freshly generated ephemeral key pair (more secure, no long-lived key to compromise)
- **Host certificates**: the reverse direction — Grimoire could also sign host keys so clients can verify servers without TOFU. Lower priority but uses the same machinery
- **Audit**: every certificate issued should be logged (key ID, principal, TTL, target host) — ties into the audit log feature
- **Offline operation**: certificates can only be minted when the vault is unlocked and approved. No caching of the CA private key outside the service process

**Why this matters:**
- Eliminates `authorized_keys` management entirely
- Certificates are self-expiring — no revocation infrastructure needed
- Server auth logs show the key ID (`grimoire:<email>:<timestamp>`), providing attribution
- Compromised user key is useless without the CA — attacker can't mint new certificates
- Natural fit for `grimoire approve` in headless sessions: approve once, mint certificates for the session duration

## Operational Security

### Signed Attestation Tokens (`auth.attest`)

A new RPC method that returns a short-lived signed JWT: "user X proved their identity at time T via method M (biometric/PIN/password)." Third-party services on the same machine (CI runners, deploy scripts, internal tools) could require this token before performing sensitive operations. The approval system already tracks method and time — this serializes it into a verifiable token.

### Ephemeral Session Tokens for Scripts

`grimoire session --ttl 60 --scope vault.get` would return a bearer token granting limited access for automation. The script uses the token instead of calling the socket directly. Approval happens once at token creation; subsequent uses within TTL skip the prompt. Useful for CI/CD pipelines that need multiple secret lookups in a batch.

### Audit Log

Record every approval event (who, when, what method, what was accessed, which PID/session) to a local append-only log. Security teams can review what secrets were accessed and when. The approval system already has all this data — it just isn't persisted today.

### Infrastructure-as-Code Provider (Terraform / Ansible)

A Terraform provider and/or Ansible lookup plugin that reads secrets from Grimoire's IPC socket. IaC is a major source of secrets sprawl (`terraform.tfvars`, Ansible vault files, `.env` files checked into repos).

**Terraform:**
```hcl
data "grimoire_secret" "db_password" {
  name  = "Production DB"
  field = "password"
}

resource "aws_db_instance" "main" {
  password = data.grimoire_secret.db_password.value
}
```

**Ansible:**
```yaml
- name: Deploy app
  template:
    src: config.j2
  vars:
    db_password: "{{ lookup('grimoire', 'Production DB', field='password') }}"
```

Both would communicate over Grimoire's Unix socket, with each lookup gated by the standard approval flow. The Terraform provider would need to be written in Go (Terraform plugin protocol requirement); the Ansible plugin is Python.

## Delivery Model

Each feature falls into one of three categories based on where it should live architecturally:

- **Core** — built into the grimoire workspace (service, CLI, or both). These features need access to service internals (private keys, crypto state, approval cache), are fundamental to the user experience, or would be awkward as a separate install.
- **External** — a separate binary, plugin, or library in its own repository. Communicates with Grimoire over the existing IPC socket. May require new RPC methods to be added to the service first, but the feature itself lives outside. Often forced external by the consuming tool's plugin architecture (PAM `.so`, PKCS#11 `.so`, Terraform Go binary, browser extension).
- **Either** — could reasonably go either way. Trade-offs noted.

### Core (built into grimoire)

| Feature | Why core | Service changes | CLI changes |
|---------|----------|-----------------|-------------|
| **`.env.grimoire` manifest** | Extension of existing `grimoire run` — adding file input to an existing command | None — `vault.resolve_refs` already exists | Parse manifest file, merge into env before exec |
| **Password generation** | Fundamental utility; no external dependency; expected in a security tool | None (pure generation) or new RPC if `--save` needs vault write | `grimoire generate` subcommand |
| **Clipboard with auto-clear** | Core UX convenience; tightly coupled to `vault.get` flow | None — uses existing `vault.get` | `grimoire clip` subcommand + platform clipboard code |
| **Application key derivation** | Needs access to decrypted vault secrets + HKDF inside the service process; key material must never cross the socket as a raw secret | New RPC: `vault.derive_key` — performs HKDF inside the service | `grimoire derive-key` subcommand (optional) |
| **Crypto operations (sign/decrypt)** | Private keys must stay in the service process; signing/decryption happens inside the trust boundary | New RPCs: `crypto.sign`, `crypto.decrypt` — raw data in, signature/plaintext out | `grimoire sign`, `grimoire decrypt` subcommands |
| **OAuth2 token broker** | Token cache should live in the service (survives CLI exits, shared across invocations); client secrets are vault items that should never leave the service | New RPC: `oauth.token` — handles exchange, caching, refresh internally | `grimoire token` subcommand |
| **SSH certificate authority** | Must integrate with the embedded SSH agent — when the agent receives an auth challenge for a CA-profiled host, it auto-mints a certificate. This logic runs inside `grimoire-service` | CA signing logic + ephemeral key generation + cert caching inside the SSH agent handler | `grimoire ssh cert` for explicit minting; config in `config.toml` |
| **Signed attestation tokens** | Needs access to approval state (who proved identity, when, how) which is service-internal; signs with service-held keys | New RPC: `auth.attest` — reads approval cache, signs JWT | `grimoire attest` subcommand |
| **Ephemeral session tokens** | Token issuance is a service-side authorization decision; scoped access control is service-internal | New RPC: `auth.session` — issues scoped bearer token, tracks in approval cache | `grimoire session` subcommand |
| **Audit log** | Logging happens at the point of operation inside the service; must capture every approval event | Append-only log writer in the service process | `grimoire audit` to query the log |
| **HTTP credential provider** | If implemented as a `grimoire netrc` subcommand, it's a CLI formatter on top of existing RPCs. If implemented as a proxy, see "Either" | Possibly new RPCs for URI-based item matching | `grimoire netrc` or `grimoire proxy` subcommand |

### External (separate project/binary)

| Feature | Why external | Language | Grimoire interface |
|---------|-------------|----------|-------------------|
| **PAM module** | Must be a `.so` loaded by the PAM stack into `sudo`/`sshd`/`login`. Cannot be part of grimoire's Rust binary — PAM has its own C ABI and module loading conventions | C or Rust (with `cdylib`) | Connects to Grimoire's socket, calls `auth.attest` or a new `auth.verify` RPC |
| **PKCS#11 module** | Must be a `.so` loaded by applications (Firefox, OpenVPN, OpenSSL). PKCS#11 has a C ABI that the consuming application `dlopen()`s | C or Rust (`cdylib`) | Proxies `C_Sign`/`C_Decrypt`/`C_GetAttributeValue` calls to Grimoire's socket via `crypto.sign`/`crypto.decrypt` RPCs |
| **Docker credential helper** | Docker requires a binary named `docker-credential-<name>` that speaks a specific JSON stdin/stdout protocol | Rust (small, standalone) | Calls `vault.get` over socket |
| **Git credential helper** | Git requires a binary (or `grimoire credential-helper` subcommand) that speaks the `git-credential` protocol on stdin/stdout. See "Either" | Rust | Calls `vault.get` over socket with URI matching |
| **SOPS/age plugin** | `age` has a defined plugin interface (`age-plugin-<name>` binary). SOPS delegates to `age`. Must be a separate binary | Rust | Calls `crypto.decrypt` (or `vault.get` for the age identity) over socket |
| **IDE plugins** | VS Code (TypeScript), JetBrains (Kotlin/Java). Completely different ecosystems | TypeScript / Kotlin | Calls Grimoire socket or CLI as subprocess |
| **IaC providers** | Terraform providers must be Go binaries (gRPC plugin protocol). Ansible lookup plugins must be Python | Go / Python | Calls Grimoire socket or CLI as subprocess |
| **Kubernetes secret injection** | CSI driver (Go, runs in k8s), or sidecar container. Different deployment model entirely | Go | Calls Grimoire socket (if local) or would need a network-accessible API (different threat model) |
| **Secret Service D-Bus bridge** | Implements the `org.freedesktop.secrets` D-Bus interface. Adding D-Bus as a dependency to `grimoire-service` would be a heavy pull; cleaner as a separate bridge daemon (`grimoire-secret-service`) that translates D-Bus ↔ Grimoire IPC | Rust (separate binary) | Calls `vault.list`, `vault.get`, `vault.create` etc. over socket |
| **Systemd credential provider** | Helper binary invoked by systemd's `LoadCredential=` mechanism | Rust (small, standalone) | Calls `vault.get` or `vault.resolve_refs` over socket |
| **Database proxy** | Standalone TCP proxy with significant independent logic (protocol parsing, connection pooling). Would bloat the service | Rust (separate binary) | Calls `vault.get` over socket for credentials at connection time |

### Either (could go either way)

| Feature | Built-in case | External case | Recommendation |
|---------|--------------|---------------|----------------|
| **Git credential helper** | `grimoire credential-helper` subcommand — git calls `grimoire credential-helper get`. Zero additional install, ships with the CLI. Simple enough (~100 LOC) to not bloat the codebase | Separate `git-credential-grimoire` binary — cleaner separation, independently versioned | **Built-in** — too small to justify a separate project; users shouldn't need to install a second binary for basic git HTTPS auth |
| **SSH certificate authority** | CA signing + cert caching in the service; SSH agent auto-mints certs. Tightest integration, best UX (transparent to user) | Separate `grimoire-ssh-ca` that requests signing via `crypto.sign` RPC, manages cert generation externally, and injects certs into the user's SSH agent | **Built-in** — the killer feature is transparent cert minting inside the SSH agent. An external tool can't intercept agent auth challenges |
| **FIDO2/WebAuthn authenticator** | Add CTAP2 handler to `grimoire-service` (new socket or virtual USB HID). Keeps credential keys inside the trust boundary | Separate `grimoire-webauthn` binary or browser extension that calls `crypto.sign` for assertions. Credential management via new vault RPCs | **External** — CTAP2/WebAuthn is a large spec surface; browser integration requires a platform-specific extension regardless. The service just needs `crypto.sign` which is already planned |
| **WireGuard/VPN key injection** | Not really a feature — it's documentation/examples for using existing `grimoire run` and `grimoire get` with WireGuard/OpenVPN configs | A helper script (`grimoire-wg`) that wraps `wg-quick` with automatic secret injection | **Neither** — just document the pattern. Existing `grimoire run` already handles this |
| **macOS Keychain bridge** | Unlike D-Bus (which is a protocol bridge), macOS Keychain integration requires a system extension or helper with Apple entitlements. Very different from the Linux D-Bus case | Separate signed helper binary with Apple Keychain entitlements | **External** — Apple's security model requires separate signing/entitlements |
| **OAuth2 token broker** | Service-side token caching is the main value (shared across CLI invocations, survives process exits). New RPC `oauth.token` | Separate `grimoire-oauth` binary that manages its own token cache (e.g., in-memory daemon or temp file) and calls `vault.get` for client secrets | **Built-in** — the whole point is that tokens live in the service's memory alongside vault secrets, cleared on lock. External caching defeats the security model |

## Priority Assessment

| Feature | Delivery | Effort | Impact | Rationale |
|---------|----------|--------|--------|-----------|
| Clipboard with auto-clear | Core | Low | High | Table-stakes for password managers; small platform-specific code |
| Git credential helper | Core | Low | High | ~100 LOC subcommand, covers HTTPS Git auth alongside existing SSH agent |
| `.env.grimoire` manifest | Core | Low | High | Small extension to `grimoire run`, large DX improvement for teams |
| Password generation | Core | Low | Medium | Basic utility; expected of any security tool |
| WireGuard/VPN key injection | Docs | Low | Medium | Already works with `grimoire run`; just needs documentation |
| Docker credential helper | External | Low | Medium | Drop-in, well-defined protocol, narrow scope |
| SOPS/age integration | External | Low | Medium | Plugin interface already defined by age, small adapter |
| Application key derivation | Core | Medium | Very High | Unique differentiator — positions Grimoire as a local secrets platform |
| SSH certificate authority | Core | High | Very High | Eliminates authorized_keys management; must integrate with embedded SSH agent |
| Crypto operations (sign/decrypt) | Core | Medium | High | Generalizes existing SSH signing; private keys never leave the service |
| OAuth2 token broker | Core | Medium | High | Token vending machine with service-side caching; cleared on lock |
| Signed attestation tokens | Core | Medium | High | Needs access to service-internal approval state |
| Audit log | Core | Medium | High | Service-side logging at point of operation |
| PAM module | External | Medium | High | Must be a `.so` loaded by the PAM stack; C ABI requirement |
| PKCS#11 module | External | High | High | Must be a `.so` loaded by applications; C ABI requirement |
| Secret Service D-Bus bridge | External | High | High | Separate bridge daemon avoids D-Bus dependency in grimoire-service |
| macOS Keychain bridge | External | High | High | Requires separate signed binary with Apple entitlements |
| FIDO2/WebAuthn authenticator | External | High | High | Large spec surface; browser extension required regardless |
| IaC provider (Terraform/Ansible) | External | Medium | Medium | Go (Terraform) + Python (Ansible); different ecosystems |
| Systemd credential provider | External | Medium | Medium | Helper binary for systemd's `LoadCredential=` |
| HTTP credential provider | Core | High | Medium | Deep design challenges around credential type detection |
| Database proxy | External | High | Medium | Standalone TCP proxy; too much independent logic for the service |
| Kubernetes secret injection | External | High | Medium | Different deployment model (k8s); needs network API |
| IDE plugin | External | Medium | Medium | VS Code (TypeScript), JetBrains (Kotlin); different ecosystems |
| Ephemeral session tokens | Core | Medium | Medium | Service-side authorization decision |
