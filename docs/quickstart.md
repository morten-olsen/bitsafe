# Quickstart

## Build

```bash
cargo build --release
```

Binaries are in `target/release/`: `grimoire` (CLI), `grimoire-service`, `grimoire-prompt`.

Copy them somewhere in your PATH:

```bash
cp target/release/{grimoire,grimoire-service,grimoire-prompt} ~/.cargo/bin/
```

## First-Time Setup

### 1. Start the service

```bash
grimoire-service
```

Or install it to start on login:

```bash
grimoire service install
```

This creates a systemd user unit (Linux) or LaunchAgent (macOS).

### 2. Log in

```bash
grimoire login your@email.com --server https://your-vaultwarden.example.com
```

This prompts for your master password in the terminal. Login is a one-time operation — the credentials persist across service restarts.

### 3. Unlock

```bash
grimoire unlock
```

This pops up a GUI password dialog (zenity on Linux, osascript on macOS). The GUI prompt is the default for security — an attacker with shell access can trigger unlock but can't interact with the dialog without visual access.

For headless/SSH sessions:

```bash
grimoire unlock --terminal
```

### 4. Use it

```bash
# List items
grimoire list

# Search
grimoire list --search github

# Get full item
grimoire get <id>

# Get single field (pipe-friendly)
grimoire get <id> -f password
grimoire get <id> -f username

# Copy password to clipboard
grimoire get <id> -f password | xclip -selection clipboard  # Linux
grimoire get <id> -f password | pbcopy                      # macOS

# Generate TOTP code
grimoire totp <id>

# Force sync
grimoire sync

# Lock
grimoire lock

# Log out (deletes persisted credentials)
grimoire logout

# Check status
grimoire status
```

## SSH Agent

The service includes a built-in SSH agent. SSH keys stored in your Bitwarden vault are automatically available.

### Setup

Add to your shell profile (`~/.bashrc`, `~/.zshrc`):

```bash
export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/grimoire/ssh-agent.sock"
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
grimoire completions bash >> ~/.bashrc

# Zsh
grimoire completions zsh > ~/.zfunc/_grimoire

# Fish
grimoire completions fish > ~/.config/fish/completions/grimoire.fish
```

## Configuration

Optional config file at `~/.config/grimoire/config.toml`:

```toml
[server]
url = "https://your-vaultwarden.example.com"

[prompt]
method = "auto"               # auto | gui | terminal | none

[ssh_agent]
enabled = true                # Disable to skip SSH agent socket
```

Security parameters are hardcoded and not configurable:

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Auto-lock | 900s (15 min) | Lock vault after inactivity |
| Sync interval | 300s (5 min) | Background vault sync |
| Approval duration | 300s (5 min) | Session approval timeout |
| Approval scope | Session | Tied to terminal session leader PID |
| PIN max attempts | 3 | Auto-lock after 3 wrong PINs |
| Access approval | Always on | Cannot be disabled |

## Service Management

```bash
grimoire service install     # Install and start
grimoire service uninstall   # Stop and remove
grimoire service ssh-socket  # Print SSH_AUTH_SOCK path
```
