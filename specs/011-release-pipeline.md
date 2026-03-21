# ADR 011: Release Pipeline

## Status

Implemented

## Context

Grimoire is a security product distributed as prebuilt binaries. Users trust that the binaries they download are the ones we built, from the code they can audit. The release pipeline is a critical part of the supply chain — a compromised or misconfigured pipeline can ship tampered binaries.

### What exists today

Two GitHub Actions workflows:

- **`ci.yml`** — runs on push/PR to main: format check, clippy with `-D warnings`, tests (Linux + macOS), release builds with artifact upload.
- **`release.yml`** — runs on `v*` tag push: builds a 4-target matrix (x86_64-linux, aarch64-linux, x86_64-macos, aarch64-macos), packages tarballs, creates a GitHub Release.

### Problems

1. **No quality gate on release.** The release workflow skips fmt/clippy/tests — a tag on a broken commit ships broken binaries.
2. **No artifact integrity.** No checksums file, no signatures. Users can't verify that a downloaded tarball matches what CI built.
3. **No changelog.** GitHub's auto-generated release notes are commit-title dumps — not useful for users deciding whether to upgrade.
4. **aarch64-linux native prompt doesn't build.** The `cross` tool can't compile the GTK4/libadwaita native prompt. The aarch64-linux tarball silently ships without it.
5. **No install script.** Users must manually download, extract, and place binaries.
6. **No package manager distribution.** No Homebrew tap, no AUR, no `cargo install`.

## Decision

### 1. Workflow structure

Consolidate into two workflows with a clear separation:

```
ci.yml        — every push/PR: quality gate (fmt, clippy, test)
release.yml   — on v* tag: quality gate → build → sign → publish
```

The release workflow **re-runs the full quality gate** as its first job. Build jobs depend on the gate passing. This ensures no release ships without passing checks, regardless of how the tag was created.

### 2. Quality gate job (shared)

A single `gate` job runs in both workflows:

```yaml
gate:
  steps:
    - cargo fmt --all -- --check
    - cargo clippy --workspace -- -D warnings
    - cargo test --workspace
```

In `ci.yml`, this is the primary purpose. In `release.yml`, all build jobs have `needs: [gate]`.

### 3. Build matrix

Four targets, using native runners (no `cross`):

| Target | Runner | Native prompt |
|--------|--------|---------------|
| `x86_64-unknown-linux-gnu` | `ubuntu-latest` | `grimoire-prompt-linux` (GTK4) |
| `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` | `grimoire-prompt-linux` (GTK4) |
| `x86_64-apple-darwin` | `macos-13` | `grimoire-prompt-macos` (Swift) |
| `aarch64-apple-darwin` | `macos-latest` | `grimoire-prompt-macos` (Swift) |

Using native ARM64 runners for aarch64-linux eliminates the `cross` dependency and allows the GTK4 native prompt to build. `macos-13` is used for x86_64 since `macos-latest` is now ARM64.

### 4. Package format

Each target produces a tarball: `grimoire-{VERSION}-{TARGET}.tar.gz`

Contents:
```
grimoire-v0.2.0-x86_64-unknown-linux-gnu/
├── grimoire                    # CLI
├── grimoire-service            # daemon + SSH agent
├── grimoire-prompt             # fallback prompt (zenity/kdialog/osascript)
├── grimoire-prompt-linux       # native GTK4 prompt (Linux only)
├── grimoire-prompt-macos       # native Swift prompt (macOS only)
├── contrib/
│   ├── systemd/                # Linux service files
│   └── launchd/                # macOS service files
└── install.sh                  # Per-platform installer (see §6)
```

### 5. Artifact integrity

#### Checksums

After all build jobs complete, a `sign` job:

1. Downloads all tarballs
2. Generates `grimoire-{VERSION}-checksums.sha256` containing SHA256 hashes of every tarball
3. Signs the checksums file with cosign (keyless, using GitHub OIDC identity)
4. Uploads checksums + signature + certificate as release assets

Verification flow for users:
```bash
# Download tarball + checksums + signature + certificate
sha256sum -c grimoire-v0.2.0-checksums.sha256 --ignore-missing
cosign verify-blob \
  --certificate grimoire-v0.2.0-checksums.sha256.cert \
  --signature grimoire-v0.2.0-checksums.sha256.sig \
  --certificate-identity-regexp 'https://github\.com/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  grimoire-v0.2.0-checksums.sha256
```

#### Why cosign keyless

- No signing key to manage, rotate, or protect
- Identity is tied to the GitHub Actions workflow via OIDC — verifiers can confirm the signature came from our CI, not just from someone with a key
- Standard tooling (`cosign`) with broad adoption

### 6. Install script

A `install.sh` script in the repository (`contrib/install.sh`) that:

1. Detects OS and architecture
2. Fetches the latest release (or a specified version) from GitHub Releases
3. Verifies the SHA256 checksum against the checksums file
4. Extracts binaries to `~/.local/bin` (or a user-specified prefix)
5. Prints post-install instructions (PATH, systemd/launchd setup)

Usage:
```bash
curl -fsSL https://raw.githubusercontent.com/<org>/grimoire/main/contrib/install.sh | sh
# or with a specific version:
curl -fsSL ... | sh -s -- --version v0.2.0
```

The script does **not** verify cosign signatures — that requires cosign to be installed. Checksum verification is sufficient for most users; the cosign verification is documented for high-assurance environments.

### 7. Changelog

Use `git-cliff` to generate changelogs from conventional commits. Configuration in `cliff.toml` at the repo root.

Sections mapped from commit types:
- `feat` → Features
- `fix` → Bug Fixes
- `security` → Security
- `refactor`, `chore`, `docs`, `test` → Other (collapsed)

The release workflow runs `git-cliff` to generate the changelog body for the GitHub Release, replacing `--generate-notes`.

### 8. Nix flake

A `flake.nix` at the repository root provides:

- `packages.{system}.default` — builds `grimoire`, `grimoire-service`, and `grimoire-prompt` from source using `rustPlatform.buildRustPackage`
- `packages.{system}.grimoire-prompt-linux` — builds the native GTK4 prompt (Linux only, with `gtk4` and `libadwaita` in `buildInputs`)
- `overlays.default` — overlay adding `grimoire` to nixpkgs for use in NixOS configurations
- `nixosModules.default` — a NixOS module that provides:
  - `services.grimoire.enable` — systemd user service for `grimoire-service`
  - `services.grimoire.settings` — typed config mapped to `~/.config/grimoire/config.toml`
  - `services.grimoire.ssh-agent.enable` — sets `SSH_AUTH_SOCK` to the grimoire socket

The flake uses `crane` for incremental Rust builds and caches dependencies separately from source. The `cargoLock` configuration must handle the SDK's git dependency and pinned transitive deps (see `UPGRADING.md`).

Usage:
```nix
# flake.nix (consumer)
{
  inputs.grimoire.url = "github:<org>/grimoire";

  outputs = { self, nixpkgs, grimoire, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        grimoire.nixosModules.default
        {
          services.grimoire = {
            enable = true;
            ssh-agent.enable = true;
            settings.server_url = "https://vault.example.com";
          };
        }
      ];
    };
  };
}
```

Standalone install:
```bash
nix profile install github:<org>/grimoire
```

The flake is maintained in-repo and tested in CI via `nix build` and `nix flake check` (added as an optional CI job on `ubuntu-latest` with Nix installed via `DeterminateSystems/nix-installer-action`).

### 9. Homebrew tap (future)

Not in scope for this ADR. Document as a follow-up: create a `homebrew-grimoire` repository with a formula that downloads the macOS tarball and verifies checksums. This is a separate concern from the release pipeline itself.

### 10. Release process

To cut a release:

1. Update version in workspace `Cargo.toml`
2. Run `git-cliff --unreleased` to preview the changelog
3. Commit: `chore: release v0.2.0`
4. Tag: `git tag v0.2.0`
5. Push: `git push && git push --tags`
6. Release workflow runs automatically

This is deliberately manual — no release-please or automation. The version bump commit is an explicit decision point.

## Consequences

### Positive

- Every release passes the full quality gate — no shipping broken builds
- Users can verify artifact integrity via checksums and cosign signatures
- aarch64-linux gets a native prompt build (native ARM64 runners)
- Install script lowers the barrier to adoption
- Nix flake provides reproducible builds, NixOS module integration, and declarative configuration
- Conventional commit changelog gives users meaningful upgrade guidance
- Manual release process keeps version bumps as deliberate decisions

### Negative

- Native ARM64 runners may have different availability/pricing than x86_64 runners
- Cosign keyless requires `id-token: write` permission in the workflow — broader than current `contents: write`
- Install script is another artifact to maintain and test
- Nix flake adds complexity: `crane` configuration, SDK git dep handling in `cargoLock`, GTK4/libadwaita native deps
- `git-cliff` is a new CI dependency
- Nix CI job requires Nix installer action and adds build time

## Security Analysis

### Threat Model Impact

This ADR adds a new trust boundary: **the release pipeline itself**. Users trust that binaries on GitHub Releases correspond to the source code in the repository. The pipeline is the mechanism that establishes this trust.

New attack surface:
- GitHub Actions workflow manipulation
- Artifact tampering between build and publish
- Install script as a distribution vector
- Cosign OIDC identity scope
- Nix flake as an additional build/distribution vector

### Attack Vectors

| # | Vector | Severity | Description |
|---|--------|----------|-------------|
| 1 | Workflow file tampering | Critical | Attacker modifies `.github/workflows/release.yml` to inject malicious code into the build. Requires write access to the repository. |
| 2 | Artifact tampering in transit | High | Man-in-the-middle between GitHub's artifact storage and the release publish step. Unlikely but checksums without signatures don't fully prevent. |
| 3 | Install script hijacking | High | Attacker compromises the install script (via repo access or CDN cache poisoning) to serve malicious binaries or skip verification. |
| 4 | Dependency confusion in build | Medium | A compromised crate dependency injects malicious code during the build. Applies to all Rust builds, not specific to this pipeline. |
| 5 | Tag reuse / force-push | Medium | Attacker with write access deletes and re-creates a tag pointing to a different (malicious) commit. |
| 6 | Cosign identity scope too broad | Low | If the certificate identity regex is too permissive, a different workflow in the same org could produce valid signatures. |
| 7 | Install script argument injection | Low | Malicious version string passed to install script could inject shell commands. |
| 8 | Nix flake.lock manipulation | Medium | Attacker modifies `flake.lock` to point nixpkgs or crane inputs to a compromised revision. Requires repo write access. Same class as vector 1 but specific to Nix. |
| 9 | NixOS module config injection | Low | Malicious `settings` values in the NixOS module could produce a config file that alters service behavior (e.g., setting `prompt_method = "none"` to disable prompts). Only exploitable if the attacker controls the NixOS configuration, which implies root access. |

### Planned Mitigations

| Vector | Mitigation | Mechanism |
|--------|-----------|-----------|
| 1 | Branch protection + required reviews | GitHub branch protection rules on `main` — workflow changes require PR review. Not enforced by this ADR but documented as a prerequisite. |
| 2 | Cosign signatures on checksums | Checksums are signed with GitHub OIDC identity via cosign. Tampering is detectable by verifying the signature chain back to GitHub's OIDC provider. |
| 3 | Checksum verification in install script | Install script verifies SHA256 of downloaded tarball against the checksums file fetched from the same release. Script itself is auditable in the repo. |
| 4 | Pinned dependencies + lockfile | Cargo.lock is committed; SDK is pinned to a specific git rev. `cargo audit` can be added as a CI step (future). |
| 5 | Tag protection rules | GitHub tag protection rules prevent deletion/overwrite of `v*` tags. Documented as a prerequisite. |
| 6 | Specific certificate identity | Cosign verification uses `--certificate-identity` with the exact workflow file path, not a broad regex. |
| 7 | Input sanitization in install script | Version argument is validated against `^v[0-9]+\.[0-9]+\.[0-9]+` before use. All variables are quoted. |
| 8 | Pinned flake inputs + lock review | `flake.lock` is committed and changes are visible in PR diffs. Input revisions are pinned — no floating references. Branch protection ensures lock changes are reviewed. |
| 9 | Security parameters are hardcoded | NixOS module only exposes operational settings (server URL, prompt method, SSH agent toggle). Security parameters (auto-lock, approval duration, PIN attempts) are hardcoded constants in the binary — not configurable via the module. |

### Residual Risk

- **GitHub Actions as root of trust.** We trust that GitHub correctly maps OIDC tokens to workflow identities. A compromise of GitHub's OIDC provider would break the signature chain. This is acceptable — the same trust is implicit in hosting source code on GitHub.
- **Dependency supply chain.** A compromised upstream crate could inject code at build time. Mitigated by lockfile and rev pinning, but not eliminated. `cargo audit` in CI would catch known CVEs but not zero-days.
- **curl-pipe-sh.** The install script pattern is inherently trust-on-first-use. Users who want higher assurance should download and inspect the script, or verify cosign signatures manually.
- **Nix build reproducibility.** Nix builds from source, so the binary may differ from GitHub Release artifacts due to different toolchain versions or flags. This is expected — Nix users trust the Nix build, not the GitHub Release. The two distribution channels are independent trust paths.

### Implementation Security Notes

- **Vector 2 (artifact tampering):** Implemented as planned — cosign keyless signing of checksums file via `sigstore/cosign-installer@v3` in the `sign` job. Certificate identity is scoped to the exact `release.yml` workflow path in the verification instructions.
- **Vector 3 (install script hijacking):** `contrib/install.sh` fetches checksums from the same GitHub Release and verifies SHA256 before extracting. Supports both `sha256sum` (Linux) and `shasum -a 256` (macOS).
- **Vector 7 (install script argument injection):** Version argument validated against `^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$` regex. All shell variables are quoted throughout the script.
- **Vector 8 (flake.lock manipulation):** `flake.lock` is committed to the repo. All inputs use pinned URLs (nixpkgs on `nixos-unstable`, crane on default branch). Changes are visible in PR diffs.
- **Vector 9 (NixOS module config injection):** Module only exposes `server_url` (string), `prompt_method` (enum of 4 values), and `ssh-agent.enable` (bool). Security parameters remain hardcoded in the binary. The `prompt_method` option uses `lib.types.enum` to restrict values.
- **Quality gate:** Both `ci.yml` and `release.yml` run fmt + clippy + test. Release build jobs have `needs: [gate]`.
- **Build matrix:** Removed `cross` dependency entirely. aarch64-linux uses `ubuntu-24.04-arm` native runner. macOS x86_64 uses `macos-13` (last Intel runner). All targets build native prompts.
- **NixOS module hardening:** systemd service config includes `NoNewPrivileges`, `MemoryDenyWriteExecute`, `LockPersonality`, and other sandboxing directives beyond what the spec required.
- **Deviation:** The spec mentioned the cosign `--certificate-identity-regexp` could be too broad (vector 6). The release notes template uses the exact workflow path pattern `https://github\.com/.*/.*/\.github/workflows/release\.yml@.*` rather than a blanket org match. Users should further narrow this to their specific org/repo.
