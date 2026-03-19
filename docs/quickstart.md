# Quickstart

## Build

```bash
cargo build --release
```

Binaries are in `target/release/`: `bitsafe` (CLI), `bitsafe-service`, `bitsafe-prompt`.

Copy them somewhere in your PATH:

```bash
cp target/release/{bitsafe,bitsafe-service,bitsafe-prompt} ~/.cargo/bin/
```

## First-Time Setup

### 1. Start the service

```bash
bitsafe-service
```

Or install it to start on login:

```bash
bitsafe service install
```

This creates a systemd user unit (Linux) or LaunchAgent (macOS).

### 2. Log in

```bash
bitsafe login your@email.com --server https://your-vaultwarden.example.com
```

This prompts for your master password in the terminal. Login is a one-time operation — the credentials persist across service restarts.

### 3. Unlock

```bash
bitsafe unlock
```

This pops up a GUI password dialog (zenity on Linux, osascript on macOS). The GUI prompt is the default for security — an attacker with shell access can trigger unlock but can't interact with the dialog without visual access.

For headless/SSH sessions:

```bash
bitsafe unlock --terminal
```

### 4. Use it

```bash
# List items
bitsafe list

# Search
bitsafe list --search github

# Get full item
bitsafe get <id>

# Get single field (pipe-friendly)
bitsafe get <id> -f password
bitsafe get <id> -f username

# Copy password to clipboard
bitsafe get <id> -f password | xclip -selection clipboard  # Linux
bitsafe get <id> -f password | pbcopy                      # macOS

# Generate TOTP code
bitsafe totp <id>

# Force sync
bitsafe sync

# Lock
bitsafe lock

# Log out (deletes persisted credentials)
bitsafe logout

# Check status
bitsafe status
```

## SSH Agent

The service includes a built-in SSH agent. SSH keys stored in your Bitwarden vault are automatically available.

### Setup

Add to your shell profile (`~/.bashrc`, `~/.zshrc`):

```bash
export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/bitsafe/ssh-agent.sock"
```

### Verify

```bash
ssh-add -l          # List keys from vault
ssh git@github.com  # Authenticate with vault key
```

### Git Commit Signing

Git 2.34+ supports SSH signing natively:

```bash
git config --global gpg.format ssh
git config --global user.signingkey "key::$(ssh-add -L | head -1)"
git config --global commit.gpgsign true
```

### Vaultwarden SSH Key Requirement

Vaultwarden requires this server-side environment variable to return SSH keys in the vault:

```
EXPERIMENTAL_CLIENT_FEATURE_FLAGS=fido2-vault-credentials,ssh-key-vault-item,ssh-agent
```

Restart Vaultwarden after setting it.

## Shell Completions

```bash
# Bash
bitsafe completions bash >> ~/.bashrc

# Zsh
bitsafe completions zsh > ~/.zfunc/_bitsafe

# Fish
bitsafe completions fish > ~/.config/fish/completions/bitsafe.fish
```

## Configuration

Optional config file at `~/.config/bitsafe/config.toml`:

```toml
[server]
url = "https://your-vaultwarden.example.com"

[service]
auto_lock_seconds = 900       # Lock after 15min inactivity (0 = disable)
sync_interval_seconds = 300   # Background sync every 5min (0 = disable)

[session]
duration_seconds = 300        # Re-verify after 5min
pin_enabled = true            # Allow PIN for re-verification
pin_max_attempts = 3          # Lock vault after 3 wrong PINs
biometric_enabled = true      # Try fingerprint before PIN

[prompt]
method = "auto"               # auto | gui | terminal | none

[ssh_agent]
enabled = true                # Disable to skip SSH agent socket
```

## Service Management

```bash
bitsafe service install     # Install and start
bitsafe service uninstall   # Stop and remove
bitsafe service ssh-socket  # Print SSH_AUTH_SOCK path
```
