# ADR 015: `.env.grimoire` Manifest Files

## Status

Implemented

## Context

`grimoire run` (ADR 007) injects vault secrets into environment variables by scanning for `grimoire:<id>/<field>` references in the current environment. This works well for individual use, but teams need a declarative way to specify which secrets a project requires without exposing the actual secret values.

Currently, teams must either:
- Document the required env vars and their vault references in a README (error-prone, goes stale)
- Share `.env` files with actual secrets (insecure)
- Have each developer manually set `VAR=grimoire://name/field` in their shell (tedious, inconsistent)

A `.env.grimoire` manifest file solves this: a checked-in file that maps environment variable names to vault references. No secrets in the file — just pointers. `grimoire run --manifest .env.grimoire -- ./app` resolves them all.

### Prior Art

- Docker Compose `.env` files — declarative env var mapping
- `direnv` `.envrc` — shell-evaluated env setup
- AWS Parameter Store references in ECS task definitions — pointer-based secret injection
- HashiCorp Vault Agent templates — reference-based secret rendering

### What Exists Today

- `grimoire run` scans `std::env::vars()` for `grimoire:` references and resolves them via `vault.resolve_refs` RPC
- `vault.resolve_refs` handles batch resolution (ID prefix match and `//name` lookup)
- `grimoire run` uses `exec()` semantics — no wrapper process
- All resolution errors are reported before exec

## Decision

### Manifest Format

```
# .env.grimoire
# Lines starting with # are comments
# Empty lines are ignored
# Format: KEY=grimoire://name/field

DATABASE_URL=grimoire://Production DB/password
API_KEY=grimoire://Stripe/notes
GITHUB_TOKEN=grimoire://GitHub PAT/password
SSH_PASSPHRASE=grimoire://Deploy Key/password
```

Rules:
- One mapping per line: `KEY=grimoire://name/field` or `KEY=grimoire:id/field`
- Lines starting with `#` (optionally preceded by whitespace) are comments
- Empty lines and whitespace-only lines are ignored
- Key must be a valid environment variable name: `[A-Za-z_][A-Za-z0-9_]*`
- Value must be a valid grimoire reference (same syntax as `grimoire run` env var scanning)
- No quoting, no escaping, no multiline values, no variable interpolation — this is not a `.env` parser
- Non-grimoire values are rejected with an error (this is a grimoire manifest, not a generic env file)

### CLI Interface

```bash
# Explicit manifest file
grimoire run --manifest .env.grimoire -- ./app

# Multiple manifests (merged left to right)
grimoire run --manifest base.env.grimoire --manifest local.env.grimoire -- ./app

# Manifest + existing env var references (both are resolved)
DATABASE_URL=grimoire://Staging DB/password grimoire run --manifest .env.grimoire -- ./app
```

`--manifest` is the only way to specify a manifest. No auto-discovery of `.env.grimoire` files in the current directory — explicit is safer.

### Precedence

When the same env var is defined in multiple places:

1. **Existing environment variables** (highest priority) — `DATABASE_URL=local grimoire run --manifest .env.grimoire -- ./app` uses `local`, not the manifest value
2. **Later manifest files** override earlier ones — `--manifest base --manifest override` uses values from `override`
3. **Manifest file entries** (lowest priority for a given key)

This means:
- Env vars already set in the shell are never overridden by the manifest
- Developers can override specific values for local development without editing the manifest
- Only env vars whose values are grimoire references (from manifest or environment) are resolved — plain values pass through unchanged

### Resolution Flow

1. **Parse manifest file(s)**: read each `--manifest` file, parse into `Vec<(String, String)>` of (key, grimoire_reference) pairs
2. **Apply precedence**: for each manifest entry, only set the env var if it's not already set in the environment
3. **Scan environment**: the existing `grimoire run` logic scans all env vars for `grimoire:` prefixed values (this now includes manifest-injected vars)
4. **Batch resolve**: all grimoire references are resolved in a single `vault.resolve_refs` RPC call (existing behavior)
5. **Error check**: all resolution errors reported before exec (existing behavior)
6. **Exec**: replace process with the command (existing behavior)

The manifest is purely a way to inject grimoire references into the environment before the existing resolution logic runs. Minimal change to the existing `grimoire run` flow.

### File Permission Check

When reading a manifest file, check its permissions:
- **Warn to stderr** if the file is group-writable or world-writable (`mode & 0o022 != 0`)
- **Do not refuse to read** — the file contains vault item names (not secrets), and it's designed to be checked into git (which doesn't preserve Unix permissions). A warning is sufficient.

### Error Handling

| Condition | Behavior |
|-----------|----------|
| Manifest file not found | Error: "Manifest file not found: <path>" |
| Manifest file not readable | Error with OS error message |
| Invalid line format | Error: "<path>:<line>: invalid format — expected KEY=grimoire://name/field" |
| Non-grimoire value | Error: "<path>:<line>: value must be a grimoire:// reference, not a plain value" |
| Invalid env var name | Error: "<path>:<line>: invalid environment variable name '<key>'" |
| Duplicate key in same file | Last wins (consistent with `.env` convention) |
| Resolution failure | Existing `grimoire run` error handling (lists all failures before exit) |

### Protocol Changes

None. Uses existing `vault.resolve_refs` RPC.

### File Convention

The recommended filename is `.env.grimoire` — the `.env` prefix signals "environment configuration" to developers, and `.grimoire` suffix clarifies it's not a regular `.env` file. But the `--manifest` flag accepts any path.

## Consequences

### Positive

- Teams can declaratively specify required secrets without sharing actual values
- Manifest files are safe to check into version control (contain only vault item names)
- Minimal implementation: manifest parsing feeds into existing `grimoire run` resolution flow
- Precedence rules allow local overrides without editing shared manifests
- Multiple `--manifest` flags support base/override patterns (dev/staging/prod)

### Negative

- Another file format to understand (though intentionally minimal — no quoting, escaping, or interpolation)
- Grimoire-refs only — teams still need a separate `.env` for non-secret config. This is by design (separation of concerns) but adds one more file to manage.
- No auto-discovery means developers must type `--manifest .env.grimoire` every time. Shell aliases or project-level Makefiles/Taskfiles mitigate this.

## Security Analysis

### Threat Model Impact

No change to the threat model. The manifest file is a convenience layer on top of existing `grimoire run` behavior. The same RPCs, approval gates, and exec semantics apply. The manifest itself contains vault item names (not secrets) and is designed to be public.

### Attack Vectors

| # | Vector | Severity | Description |
|---|--------|----------|-------------|
| 1 | Manifest file tampering | Medium | Attacker modifies manifest to add entries that exfiltrate secrets into env vars read by a malicious subprocess |
| 2 | Env var override | Low | Manifest could set env vars like `LD_PRELOAD` to vault secrets, causing unexpected behavior |
| 3 | Manifest reveals vault item names | Low | Checked-in manifest exposes which vault items a project uses |
| 4 | Symlink following | Low | `--manifest` path follows symlinks to unexpected files |

### Planned Mitigations

| Vector | Mitigation | Mechanism |
|--------|-----------|-----------|
| 1 | Permission warning | Warn on stderr if manifest is group/world-writable. The approval gate still requires user interaction for resolution — attacker can't silently exfiltrate. |
| 2 | Accept (user responsibility) | Resolved values are vault secrets, not attacker-controlled. User is responsible for env var names in the manifest. Document the risk. |
| 3 | Accept (by design) | Manifest is designed to be checked in. Vault item names are not secrets. |
| 4 | Accept (standard behavior) | Consistent with how all tools handle file arguments. |

### Residual Risk

Manifest file tampering is mitigated by the approval gate — even if an attacker adds entries, the user must approve the vault access. The attacker gains knowledge of which secrets were resolved (via the subprocess's environment) but cannot access the secret values without user approval.

### Implementation Security Notes

- All planned mitigations implemented as designed. No deviations.
- **Audit finding (Medium):** Resolved secret values in `handle_run` were held as plain `String` in the `ResolvedRef` vector without zeroization. Fixed — values are explicitly zeroized after env var injection, before exec. (This was a pre-existing issue in `handle_run`, not introduced by manifest support, but fixed as part of this work.)
- Manifest parsing is strict: rejects non-grimoire values, validates env var names, warns on insecure file permissions.
- **Regression tests:** Vector 1 (manifest tampering) mitigated by approval gate + permission warning. Precedence (Vector 2) covered by `apply_manifest_does_not_override_existing_env` and `apply_manifest_sets_missing_env`. Parsing edge cases covered by 15 tests.
