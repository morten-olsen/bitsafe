# ADR 010: Rename Project from BitSafe to Grimoire

## Status

Implemented

## Context

The project is currently named "BitSafe" — a name that sounds corporate and generic, poorly reflecting the tool's personality as a security-focused, developer-centric secrets manager and SSH agent. The project is pre-release with no public users, making this the ideal time for a rebrand.

**Grimoire** — a medieval book of secrets and spells — captures the project's essence: a locked book of secrets that only the owner can read, with invocations (`grimoire run`) and sigils (SSH signing). The CLI alias `grim` is short and fast to type.

### Scope of the rename

The name "bitsafe" / "BitSafe" appears in:

- **Cargo workspace**: root `Cargo.toml` (members, deps, metadata)
- **6 crates**: `bitsafe-cli`, `bitsafe-common`, `bitsafe-prompt`, `bitsafe-protocol`, `bitsafe-sdk`, `bitsafe-service`
- **Crate directories**: `crates/bitsafe-*`
- **Native packages**: `native/linux/Cargo.toml` (`bitsafe-prompt-linux`), `native/macos/Package.swift` (`bitsafe-prompt-macos`), `native/macos/Sources/main.swift`
- **~19 Rust source files**: binary names, config paths, socket paths, data dirs, service identifiers, user-facing strings
- **Config/data paths**: `~/.config/bitsafe/`, `~/.local/share/bitsafe/`, `bitsafe.sock`
- **CI pipelines**: `.github/workflows/ci.yml`, `.github/workflows/release.yml`
- **Task runner**: `Taskfile.yml`
- **Documentation**: `CLAUDE.md`, `README.md`, `UPGRADING.md`, all `docs/*.md` (including `security-report.md`)
- **All specs** (001–009): all are Accepted or Proposed (none frozen), so all get renamed
- **Contrib files**: `contrib/systemd/bitsafe.service`, `contrib/systemd/bitsafe-ssh-auth-sock.sh`, `contrib/launchd/com.bitsafe.service.plist`
- **Claude commands**: `.claude/commands/feature.md`, `.claude/commands/fix.md`, `.claude/commands/upgrade-sdk.md`
- **Repository metadata**: `Cargo.toml` repository URL
- **Cargo.lock**: regenerated automatically after crate renames

### What this does NOT touch

- **Bitwarden SDK dependencies** — these remain `bitwarden-*`
- **Git history** — commits reference the old name, that's fine
- **Agent memory files** — `.claude/projects/` memory content updated separately as needed

## Decision

### Naming scheme

| Current | New | Notes |
|---------|-----|-------|
| `bitsafe` (binary) | `grimoire` | Primary CLI binary |
| — | `grim` | Symlink to `grimoire`, installed alongside |
| `bitsafe-service` | `grimoire-service` | Daemon + SSH agent |
| `bitsafe-prompt` | `grimoire-prompt` | Fallback prompt binary |
| `bitsafe-prompt-linux` | `grimoire-prompt-linux` | Native Linux prompt |
| `bitsafe-prompt-macos` | `grimoire-prompt-macos` | Native macOS prompt |
| `bitsafe-cli` (crate) | `grimoire-cli` | CLI crate |
| `bitsafe-common` (crate) | `grimoire-common` | Shared utilities crate |
| `bitsafe-prompt` (crate) | `grimoire-prompt` | Prompt crate |
| `bitsafe-protocol` (crate) | `grimoire-protocol` | IPC protocol crate |
| `bitsafe-sdk` (crate) | `grimoire-sdk` | SDK wrapper crate |
| `bitsafe-service` (crate) | `grimoire-service` | Service crate |
| `~/.config/bitsafe/` | `~/.config/grimoire/` | Config directory |
| `~/.local/share/bitsafe/` | `~/.local/share/grimoire/` | Data directory (login state, DB) |
| `bitsafe.sock` | `grimoire.sock` | IPC socket |
| `BitSafe` (display name) | `Grimoire` | User-facing name in docs, prompts, errors |
| `bitsafe:<id>/<field>` | `grimoire:<id>/<field>` | Secret reference format in `grimoire run` |
| `bitsafe.service` (systemd) | `grimoire.service` | Systemd unit file |
| `bitsafe-ssh-auth-sock.sh` | `grimoire-ssh-auth-sock.sh` | SSH auth sock helper |
| `com.bitsafe.service.plist` | `com.grimoire.service.plist` | macOS launchd plist |

### `grim` symlink

The `task install` target creates a symlink `grim → grimoire` in `~/.cargo/bin/`. The binary itself is always `grimoire` — `grim` is a convenience alias, not a separate binary. No code changes needed to support this; it's purely an install-time artifact.

### Implementation order

The rename is mechanical — find-and-replace across the codebase. Execute in this order to keep the build working at each step:

1. **Rename crate directories**: `crates/bitsafe-* → crates/grimoire-*`
2. **Update Cargo.toml files**: workspace members, package names, binary names, internal dependency references
3. **Update Rust source**: all `use bitsafe_*` imports become `use grimoire_*`, string literals with paths/names/binary references
4. **Update native packages**: `native/linux/Cargo.toml`, `native/macos/Package.swift`, `native/macos/Sources/main.swift`
5. **Update Taskfile.yml**: binary references, install paths, add `grim` symlink step
6. **Update CI pipelines**: `.github/workflows/ci.yml`, `.github/workflows/release.yml`
7. **Rename contrib files**: `contrib/systemd/bitsafe.service` → `grimoire.service`, `bitsafe-ssh-auth-sock.sh` → `grimoire-ssh-auth-sock.sh`, `contrib/launchd/com.bitsafe.service.plist` → `com.grimoire.service.plist` (plus content updates)
8. **Update documentation**: `CLAUDE.md`, `README.md`, `UPGRADING.md`, all `docs/*.md`
9. **Update all specs** (001–009): all are Accepted/Proposed, none frozen
10. **Update Claude commands**: `.claude/commands/feature.md`, `.claude/commands/fix.md`, `.claude/commands/upgrade-sdk.md`
11. **Post-rename audit**: `grep -r bitsafe` across all non-target, non-.git directories to catch stragglers

### Migration

None. The project is pre-release. Users must re-configure from scratch. Old config/data directories are ignored, not migrated.

### Secret reference format

The `grimoire run` command resolves `grimoire:<id>/<field>` references in environment variables. This replaces the `bitsafe:<id>/<field>` format. The prefix is a simple string constant in the resolution code.

## Consequences

### Positive

- Name reflects the project's personality — memorable, distinctive, not corporate
- `grim` is 4 characters — faster to type than `bitsafe` (7)
- Clean break while the project has zero users
- No migration complexity

### Negative

- Every file in the project changes — large diff, noisy git blame
- Frozen specs still reference "BitSafe" / "bitsafe" — minor inconsistency (acceptable: they're historical records)
- `grimoire` is 8 characters (one more than `bitsafe`) — but `grim` alias compensates
- Existing dev muscle memory needs adjustment

## Security Analysis

### Threat Model Impact

This is a cosmetic rename with no changes to security architecture, trust boundaries, crypto, or access control. The threat model in `docs/security.md` is unchanged in substance — only the names change.

One subtle area: file paths for config, data, and socket change. The same permission model applies (`0600` socket, `0600` login state file, directory permissions). No new trust boundaries are introduced.

### Attack Vectors

| # | Vector | Severity | Description |
|---|--------|----------|-------------|
| 1 | Stale socket/config path | Low | If old `bitsafe.sock` or `~/.config/bitsafe/` persists from a dev install, a separate `bitsafe` binary could impersonate the service via the old socket. Only affects developers who had the old name installed. |
| 2 | Symlink confusion (`grim`) | Low | If an attacker places a `grim` binary earlier in PATH, it could intercept commands. Identical to the existing prompt-binary-in-PATH risk already documented in `docs/security.md`. |
| 3 | Incomplete rename | Low | If some code path still references `bitsafe` paths/socket, it could create files with wrong names in unexpected locations. Build-time detection (won't compile if crate names are wrong) mitigates most of this. |

### Planned Mitigations

| Vector | Mitigation | Mechanism |
|--------|-----------|-----------|
| 1 | Documentation note | README/install guide tells developers to clean up old `~/.config/bitsafe/` and `~/.local/share/bitsafe/` if they had the old name installed |
| 2 | No change needed | Existing PATH risk is documented; `grim` symlink doesn't change the threat model |
| 3 | Grep audit | Post-rename `grep -r bitsafe` across all non-target, non-.git directories to catch stragglers. CI build confirms all crate references resolve. |

### Residual Risk

A developer with an old install could have stale `bitsafe.sock` or config files. This is a dev-only risk with no impact on end users (project is pre-release). Documenting the cleanup is sufficient.

### Implementation Security Notes

- **No deviations** from planned mitigations.
- **Vector 3 (incomplete rename) verified**: Post-rename `grep -r bitsafe` across all source files found only `specs/010-rename-to-grimoire.md` (this spec) and `native/linux/Cargo.lock` (stale build artifact, regenerated on next build). All crate references resolve; workspace compiles and all 61 tests pass.
- **`GrimoireClient` struct renamed** from `BitsafeClient` — all references updated in service, session, and state code.
- **Secret reference prefix** updated from `bitsafe:` to `grimoire:` — test suite confirms parsing works (`parse_grimoire_ref` tests pass).
- **Env var `BITSAFE_PROMPT_TERMINAL`** renamed to `GRIMOIRE_PROMPT_TERMINAL` in service prompt code.
- **Device identifier** in token request changed from `"bitsafe"` / `"BitSafe"` to `"grimoire"` / `"Grimoire"` — cosmetic, no security impact.
- **User agent** changed from `"BitSafe/0.1"` to `"Grimoire/0.1"`.
- **`grim` symlink** added to `task install` via `ln -sf grimoire ~/.cargo/bin/grim`.
- **Pre-existing clippy warnings** remain unchanged — all are from before the rename, none introduced by it.
