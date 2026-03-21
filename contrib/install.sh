#!/bin/sh
# Grimoire installer — downloads and installs prebuilt binaries from GitHub Releases.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/<org>/grimoire/main/contrib/install.sh | sh
#   curl -fsSL ... | sh -s -- --version v0.2.0 --prefix ~/.local
#
# Environment variables:
#   GRIMOIRE_VERSION   — override version (e.g., v0.2.0)
#   GRIMOIRE_PREFIX    — override install prefix (default: ~/.local)

set -eu

REPO="user/grimoire"
DEFAULT_PREFIX="${HOME}/.local"

# --- Helpers ---

die() {
    printf 'error: %s\n' "$1" >&2
    exit 1
}

info() {
    printf '  %s\n' "$1"
}

need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1; then
        die "need '$1' (command not found)"
    fi
}

# --- Platform detection ---

detect_target() {
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux)  os_part="unknown-linux-gnu" ;;
        Darwin) os_part="apple-darwin" ;;
        *)      die "unsupported OS: $os" ;;
    esac

    case "$arch" in
        x86_64|amd64)   arch_part="x86_64" ;;
        aarch64|arm64)  arch_part="aarch64" ;;
        *)              die "unsupported architecture: $arch" ;;
    esac

    printf '%s-%s' "$arch_part" "$os_part"
}

# --- Argument parsing ---

parse_args() {
    VERSION="${GRIMOIRE_VERSION:-}"
    PREFIX="${GRIMOIRE_PREFIX:-${DEFAULT_PREFIX}}"

    while [ $# -gt 0 ]; do
        case "$1" in
            --version)
                shift
                VERSION="${1:-}"
                ;;
            --prefix)
                shift
                PREFIX="${1:-}"
                ;;
            --help)
                printf 'Usage: install.sh [--version VERSION] [--prefix PATH]\n'
                exit 0
                ;;
            *)
                die "unknown argument: $1"
                ;;
        esac
        shift
    done

    # Validate version format if specified (mitigation: attack vector 7)
    if [ -n "$VERSION" ]; then
        case "$VERSION" in
            v[0-9]*)
                # Basic check passed, do stricter regex if grep -E is available
                if command -v grep > /dev/null 2>&1; then
                    if ! printf '%s' "$VERSION" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$'; then
                        die "invalid version format: $VERSION (expected vX.Y.Z)"
                    fi
                fi
                ;;
            *)
                die "invalid version format: $VERSION (expected vX.Y.Z)"
                ;;
        esac
    fi
}

# --- Latest version detection ---

get_latest_version() {
    need_cmd curl

    url="https://api.github.com/repos/${REPO}/releases/latest"
    version="$(curl -fsSL "$url" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"

    if [ -z "$version" ]; then
        die "could not determine latest version from GitHub"
    fi

    printf '%s' "$version"
}

# --- Download and verify ---

download_and_install() {
    version="$1"
    target="$2"
    prefix="$3"
    bindir="${prefix}/bin"

    tarball="grimoire-${version}-${target}.tar.gz"
    checksums="grimoire-${version}-checksums.sha256"
    base_url="https://github.com/${REPO}/releases/download/${version}"

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    info "Downloading ${tarball}..."
    curl -fsSL -o "${tmpdir}/${tarball}" "${base_url}/${tarball}" ||
        die "failed to download ${tarball} — does this version/target exist?"

    info "Downloading checksums..."
    curl -fsSL -o "${tmpdir}/${checksums}" "${base_url}/${checksums}" ||
        die "failed to download checksums file"

    info "Verifying checksum..."
    expected="$(grep "  ${tarball}$" "${tmpdir}/${checksums}" | cut -d' ' -f1)"
    if [ -z "$expected" ]; then
        die "tarball ${tarball} not found in checksums file"
    fi

    if command -v sha256sum > /dev/null 2>&1; then
        actual="$(sha256sum "${tmpdir}/${tarball}" | cut -d' ' -f1)"
    elif command -v shasum > /dev/null 2>&1; then
        actual="$(shasum -a 256 "${tmpdir}/${tarball}" | cut -d' ' -f1)"
    else
        die "need 'sha256sum' or 'shasum' for checksum verification"
    fi

    if [ "$expected" != "$actual" ]; then
        die "checksum mismatch!\n  expected: ${expected}\n  actual:   ${actual}"
    fi
    info "Checksum verified."

    info "Extracting to ${bindir}..."
    mkdir -p "$bindir"
    tar xzf "${tmpdir}/${tarball}" -C "$tmpdir"
    extracted="${tmpdir}/grimoire-${version}-${target}"

    # Install binaries
    for bin in grimoire grimoire-service grimoire-prompt grimoire-prompt-linux grimoire-prompt-macos; do
        if [ -f "${extracted}/${bin}" ]; then
            install -m 755 "${extracted}/${bin}" "${bindir}/${bin}"
            info "  installed ${bin}"
        fi
    done

    info ""
    info "Grimoire ${version} installed to ${bindir}"
    info ""

    # Post-install guidance
    case ":${PATH}:" in
        *":${bindir}:"*) ;;
        *)
            info "Add to your PATH:"
            info "  export PATH=\"${bindir}:\$PATH\""
            info ""
            ;;
    esac

    case "$(uname -s)" in
        Linux)
            info "To run as a systemd user service:"
            info "  mkdir -p ~/.config/systemd/user"
            info "  cp ${extracted}/contrib/systemd/grimoire.service ~/.config/systemd/user/"
            info "  systemctl --user enable --now grimoire"
            ;;
        Darwin)
            info "To run as a launchd service:"
            info "  cp ${extracted}/contrib/launchd/com.grimoire.service.plist ~/Library/LaunchAgents/"
            info "  launchctl load ~/Library/LaunchAgents/com.grimoire.service.plist"
            ;;
    esac
}

# --- Main ---

main() {
    parse_args "$@"

    need_cmd curl
    need_cmd tar
    need_cmd mktemp

    target="$(detect_target)"

    if [ -z "$VERSION" ]; then
        info "Detecting latest version..."
        VERSION="$(get_latest_version)"
    fi

    info "Installing Grimoire ${VERSION} for ${target}..."
    info ""
    download_and_install "$VERSION" "$target" "$PREFIX"
}

main "$@"
