# CI & Release

How code goes from commit to published release. See ADR 011 for the design rationale.

## Pipeline Overview

```
commit to main
      │
      ├── ci.yml ─────────── Quality gate (fmt, clippy, test)
      │                      Build artifacts (Linux + macOS)
      │                      Nix flake check + build
      │
      └── release-please ─── Opens/updates a Release PR
                             (version bump + changelog)
                                    │
                              merge PR (human decision)
                                    │
                              creates v* tag
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
              release.yml    flakehub.yml    release-please
                    │               │         updates manifest
                    ▼               ▼
              gate → build    publish flake
              → sign → upload
              → homebrew tap
```

## Workflows

### CI (`ci.yml`)

Runs on every push to `main` and every PR.

| Job | Runner | Purpose |
|-----|--------|---------|
| `gate` | ubuntu-latest | Format check, clippy with `-D warnings`, all tests |
| `test-macos` | macos-latest | Tests on macOS (parallel with gate) |
| `build` | ubuntu + macOS | Release builds + native prompts. Depends on `gate` |
| `nix` | ubuntu-latest | `nix flake check` + `nix build` |

### Release Please (`release-please.yml`)

Runs on every push to `main`. Watches conventional commits and maintains a Release PR.

- `feat` commits → patch bump (pre-1.0), minor bump (post-1.0)
- `fix` commits → patch bump
- Breaking changes (`!`) → minor bump (pre-1.0), major bump (post-1.0)
- Changelog generated from commit messages

When you merge the Release PR, release-please creates the tag and GitHub Release with the changelog.

### Release (`release.yml`)

Triggered by `v*` tag push (from release-please or manual).

| Job | Purpose |
|-----|---------|
| `gate` | Re-runs full quality gate — no release ships without passing |
| `build` | 4-target matrix build (see below) |
| `sign` | SHA256 checksums + cosign keyless signing + upload to release |
| `homebrew` | Generates formula and pushes to `morten-olsen/homebrew-tap` |

### FlakeHub (`flakehub.yml`)

Triggered by `v*` tag push. Publishes the Nix flake to FlakeHub.

### Build Matrix

All targets use native runners — no cross-compilation.

| Target | Runner | Native Prompt |
|--------|--------|---------------|
| `x86_64-unknown-linux-gnu` | `ubuntu-latest` | GTK4/libadwaita |
| `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` | GTK4/libadwaita |
| `x86_64-apple-darwin` | `macos-13` | Swift |
| `aarch64-apple-darwin` | `macos-latest` | Swift |

## Cutting a Release

Releases are semi-automated via release-please:

1. Merge feature/fix commits to `main` using conventional commit format
2. Release-please opens (or updates) a Release PR with version bump + changelog
3. Review the PR — adjust changelog if needed
4. Merge the PR
5. Release-please creates the `v*` tag and GitHub Release
6. Release pipeline runs automatically: build → sign → publish → homebrew → flakehub

### Manual Release (bypass release-please)

If you need to tag manually:

```bash
# Update version in Cargo.toml
vim Cargo.toml

# Commit and tag
git commit -am "chore: release v0.2.0"
git tag v0.2.0
git push && git push --tags
```

## Verifying Release Artifacts

Every release includes a SHA256 checksums file signed with cosign (keyless, GitHub OIDC).

### Checksum verification

```bash
# Download the tarball and checksums file from the release
sha256sum -c grimoire-v0.2.0-checksums.sha256 --ignore-missing
```

### Signature verification (requires cosign)

```bash
cosign verify-blob \
  --certificate grimoire-v0.2.0-checksums.sha256.cert \
  --signature grimoire-v0.2.0-checksums.sha256.sig \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github\.com/morten-olsen/grimoire/\.github/workflows/release\.yml@.*' \
  grimoire-v0.2.0-checksums.sha256
```

This verifies that the checksums file was produced by the release workflow in this repository, not by someone with a stolen key.

## Distribution Channels

| Channel | How to install | Updated |
|---------|---------------|---------|
| GitHub Releases | Download tarball | Every tag |
| Install script | `curl -fsSL .../install.sh \| sh` | Uses GitHub Releases |
| Homebrew | `brew tap morten-olsen/tap && brew install grimoire` | Auto-updated by release workflow |
| Nix flake | `nix profile install github:morten-olsen/grimoire` | Every commit (builds from source) |
| FlakeHub | `inputs.grimoire.url = "https://flakehub.com/f/morten-olsen/grimoire/*.tar.gz"` | Every tag |

## NixOS Module

The flake provides a NixOS module for declarative configuration:

```nix
{
  inputs.grimoire.url = "github:morten-olsen/grimoire";

  outputs = { self, nixpkgs, grimoire, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        grimoire.nixosModules.default
        {
          services.grimoire = {
            enable = true;
            ssh-agent.enable = true;
            settings = {
              server_url = "https://vault.example.com";
              prompt_method = "auto";  # auto | gui | terminal | none
            };
          };
        }
      ];
    };
  };
}
```

The module creates a systemd user service with hardening directives (`NoNewPrivileges`, `MemoryDenyWriteExecute`, etc.). Only operational settings are exposed — security parameters are hardcoded in the binary.

## Required Secrets

| Secret | Where | Purpose |
|--------|-------|---------|
| `HOMEBREW_TAP_TOKEN` | Repository → Settings → Secrets | PAT with write access to `morten-olsen/homebrew-tap` |

Cosign signing and FlakeHub publishing use GitHub OIDC — no secrets needed.
