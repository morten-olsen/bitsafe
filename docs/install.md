# Installation Guide

Grimoire runs on Linux and macOS, with experimental support for Android via Termux. This guide covers every way to get it running.

## Install Script (Recommended)

The quickest way to install — detects your platform, downloads the release, and verifies checksums:

```bash
curl -fsSL https://raw.githubusercontent.com/morten-olsen/grimoire/main/contrib/install.sh | sh
```

Installs to `~/.local/bin` by default. Options:

```bash
# Specific version
curl -fsSL ... | sh -s -- --version v0.2.0

# Custom prefix
curl -fsSL ... | sh -s -- --prefix /usr/local
```

## Homebrew (macOS / Linux)

```bash
brew tap morten-olsen/tap
brew install grimoire
```

## Nix

```bash
# Standalone install
nix profile install github:morten-olsen/grimoire

# Or in a flake
inputs.grimoire.url = "github:morten-olsen/grimoire";
```

A NixOS module is available — see [CI & Release](release.md) for details.

## From Prebuilt Binaries (Manual)

Download the latest release for your platform from [GitHub Releases](../../releases).

Each release is signed — see [Verifying Release Artifacts](release.md#verifying-release-artifacts) for checksum and cosign verification instructions.

Each release archive contains:
- `grimoire` — the CLI client
- `grimoire-service` — the background daemon
- `grimoire-prompt` — the generic GUI/terminal prompt agent
- `grimoire-prompt-linux` or `grimoire-prompt-macos` — the native prompt (when available)
- `contrib/` — systemd and launchd service files

### Linux (x86_64 / aarch64)

```bash
# Download and extract
tar xzf grimoire-v*.tar.gz
cd grimoire-v*

# Install binaries
sudo install -m 755 grimoire grimoire-service grimoire-prompt /usr/local/bin/

# Install native prompt if present
[ -f grimoire-prompt-linux ] && sudo install -m 755 grimoire-prompt-linux /usr/local/bin/

# Set up the service (auto-start on login)
grimoire service install
```

### macOS (Apple Silicon / Intel)

```bash
# Download and extract
tar xzf grimoire-v*.tar.gz
cd grimoire-v*

# Install binaries
sudo install -m 755 grimoire grimoire-service grimoire-prompt /usr/local/bin/

# Install native prompt if present
[ -f grimoire-prompt-macos ] && sudo install -m 755 grimoire-prompt-macos /usr/local/bin/

# Set up the service (auto-start on login)
grimoire service install
```

## From Source

### Prerequisites

| Dependency | Required | Purpose |
|------------|----------|---------|
| Rust 1.88+ | Yes | Core build toolchain |
| `libgtk-4-dev` | Linux, optional | Native GTK4 prompt UI |
| `libadwaita-1-dev` | Linux, optional | Native libadwaita prompt UI |
| Xcode CLI Tools | macOS, optional | Native Swift prompt |
| `zenity` or `kdialog` | Linux, optional | Fallback GUI prompt (usually pre-installed) |

Install Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Build Everything

If you have [go-task](https://taskfile.dev/) installed:

```bash
task build    # builds workspace + native prompts for your platform
task install  # installs all binaries to ~/.cargo/bin
```

Or manually:

```bash
# Core workspace
cargo build --workspace --release

# Install core binaries
cargo install --path crates/grimoire-cli
cargo install --path crates/grimoire-service
cargo install --path crates/grimoire-prompt
```

### Native Prompts (Optional but Recommended)

The native prompts provide proper system-integrated password dialogs instead of generic zenity/kdialog.

**Linux (GTK4/libadwaita):**

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt install libgtk-4-dev libadwaita-1-dev

# Fedora
sudo dnf install gtk4-devel libadwaita-devel

# Arch
sudo pacman -S gtk4 libadwaita

# Build and install
cd native/linux && cargo build --release
cp target/release/grimoire-prompt-linux ~/.cargo/bin/
```

**macOS (Swift):**

```bash
# Requires Xcode Command Line Tools
xcode-select --install

# Build and install
cd native/macos && swift build -c release
cp .build/release/grimoire-prompt-macos ~/.cargo/bin/
```

The service discovers prompt binaries in this order:
1. `grimoire-prompt-{platform}` next to the service binary
2. `grimoire-prompt` next to the service binary
3. PATH lookup
4. Terminal fallback (always available)

## Service Setup

### Auto-Start on Login

The easiest way:

```bash
grimoire service install
```

This creates a systemd user unit (Linux) or launchd LaunchAgent (macOS) and starts the service immediately.

To stop and remove:

```bash
grimoire service uninstall
```

### Manual Start

If you prefer to run the service yourself:

```bash
grimoire-service
```

It runs in the foreground and logs to stderr. You can background it, wrap it in a tmux session, or manage it however you like.

### Verify

```bash
grimoire status
```

Should show `Service is running` and the current vault state.

## Shell Completions

```bash
# Bash — add to ~/.bashrc
grimoire completions bash >> ~/.bashrc

# Zsh — create completion file
grimoire completions zsh > ~/.zfunc/_grimoire

# Fish
grimoire completions fish > ~/.config/fish/completions/grimoire.fish
```

## Android (Termux)

Grimoire works in Termux with terminal-only prompts (no native GUI). This is experimental.

### Prerequisites

```bash
# Install Rust in Termux
pkg install rust binutils

# OpenSSL for the SDK's HTTP
pkg install openssl
```

### Build

```bash
git clone https://github.com/user/grimoire.git
cd grimoire
cargo install --path crates/grimoire-cli
cargo install --path crates/grimoire-service
cargo install --path crates/grimoire-prompt
```

### Configuration

Since Termux has no GUI environment, configure the prompt to always use terminal mode:

```toml
# ~/.config/grimoire/config.toml
[server]
url = "https://vault.example.com"

[prompt]
method = "terminal"
```

Access approval is always required. On Termux, use `grimoire authorize` to grant approval for your terminal session (prompts for master password).

### Running

Start the service manually:

```bash
grimoire-service &
```

For auto-start on boot, you can use [Termux:Boot](https://wiki.termux.com/wiki/Termux:Boot):

```bash
mkdir -p ~/.termux/boot
cat > ~/.termux/boot/grimoire.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/sh
grimoire-service &
EOF
chmod +x ~/.termux/boot/grimoire.sh
```

### Limitations on Termux

- No biometric or GUI prompts — terminal password entry only
- No `mlockall` or `PR_SET_DUMPABLE` — Android's security model is different
- SSH agent works if you set `SSH_AUTH_SOCK` correctly
- Access approval works via `grimoire authorize` (master password in terminal)

## Configuration

Create `~/.config/grimoire/config.toml`:

```toml
[server]
url = "https://vault.example.com"    # your Vaultwarden/Bitwarden server

[prompt]
method = "auto"                      # auto | gui | terminal | none

[ssh_agent]
enabled = true                       # embedded SSH agent (default: true)
```

All settings are optional — sensible defaults are used when omitted.

Security parameters are hardcoded constants — not configurable. This is deliberate: configurability in security-critical paths is attack surface. An attacker who can modify your config file could weaken your security posture.

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Auto-lock timeout | 900s (15 min) | Vault locks after inactivity |
| Background sync | 300s (5 min) | Periodic vault sync |
| Approval duration | 300s (5 min) | How long a session approval lasts |
| Approval scope | Terminal session | Scoped to session leader PID |
| PIN max attempts | 3 | Auto-lock after 3 wrong PINs |
| Access approval | Always required | Cannot be disabled |

## Vaultwarden Server Requirements

If you use SSH keys in your vault, your Vaultwarden instance needs this environment variable:

```
EXPERIMENTAL_CLIENT_FEATURE_FLAGS=fido2-vault-credentials,ssh-key-vault-item,ssh-agent
```

Without it, SSH key ciphers (type 5) are silently filtered from sync responses. Restart Vaultwarden after adding it.

## Uninstalling

```bash
# Remove service auto-start
grimoire service uninstall

# Remove binaries
rm ~/.cargo/bin/grimoire ~/.cargo/bin/grimoire-service ~/.cargo/bin/grimoire-prompt
rm -f ~/.cargo/bin/grimoire-prompt-linux ~/.cargo/bin/grimoire-prompt-macos

# Remove data (login state, logs)
rm -rf ~/.local/share/grimoire

# Remove config
rm -rf ~/.config/grimoire
```

## Next Steps

- **[Tutorial: Getting Started](tutorials/01-getting-started.md)** — first login and basic usage
- **[Tutorial: SSH Agent](tutorials/02-ssh-agent.md)** — set up SSH authentication with vault keys
- **[Quick Reference](quickstart.md)** — command cheat sheet
