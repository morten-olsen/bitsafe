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

### IDE/Editor Plugin (VS Code, JetBrains)

A language server or extension that detects `grimoire://` references in config files, validates they resolve, and offers code actions to insert references. Could also provide a secret picker UI.

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

### SOPS/age Integration

Grimoire could act as a key source for [SOPS](https://github.com/getsops/sops) or `age` encrypted files. Store the age identity in the vault, and a `grimoire-age-plugin` retrieves it on demand with approval. Encrypted config files live in git, decrypted only when Grimoire approves.

## Operational Security

### Signed Attestation Tokens (`auth.attest`)

A new RPC method that returns a short-lived signed JWT: "user X proved their identity at time T via method M (biometric/PIN/password)." Third-party services on the same machine (CI runners, deploy scripts, internal tools) could require this token before performing sensitive operations. The approval system already tracks method and time — this serializes it into a verifiable token.

### Ephemeral Session Tokens for Scripts

`grimoire session --ttl 60 --scope vault.get` would return a bearer token granting limited access for automation. The script uses the token instead of calling the socket directly. Approval happens once at token creation; subsequent uses within TTL skip the prompt. Useful for CI/CD pipelines that need multiple secret lookups in a batch.

### Audit Log

Record every approval event (who, when, what method, what was accessed, which PID/session) to a local append-only log. Security teams can review what secrets were accessed and when. The approval system already has all this data — it just isn't persisted today.

## Priority Assessment

| Feature | Effort | Impact | Rationale |
|---------|--------|--------|-----------|
| Git credential helper | Low | High | ~200 LOC, reuses `vault.get`, covers HTTPS Git auth alongside existing SSH agent |
| `.env.grimoire` manifest | Low | High | Small extension to `grimoire run`, large DX improvement for teams |
| Application key derivation | Medium | Very High | Unique differentiator — positions Grimoire as a local secrets platform |
| Signed attestation tokens | Medium | High | Enables an ecosystem of tools that trust Grimoire's identity proof |
| PAM module | Medium | High | Replaces system password with biometric for `sudo`, major UX win |
| Audit log | Medium | High | Table-stakes for security products, data already exists internally |
| Docker credential helper | Low | Medium | Drop-in, well-defined protocol, narrow scope |
| SOPS/age integration | Low | Medium | Plugin interface already defined by age, small adapter |
| Database proxy | High | Medium | Niche but powerful; significant new code surface |
| Kubernetes secret injection | High | Medium | Deployment complexity, but reuses `vault.resolve_refs` |
| IDE plugin | Medium | Medium | Developer convenience, not a security boundary |
| Ephemeral session tokens | Medium | Medium | Useful for CI/CD, overlaps with `grimoire approve` |
