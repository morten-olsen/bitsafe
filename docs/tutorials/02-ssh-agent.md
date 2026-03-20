# Tutorial: SSH Agent

Grimoire includes an embedded SSH agent that serves keys stored in your Bitwarden vault. No private key files on disk. No `~/.ssh/id_ed25519` for someone to steal. The keys exist only in your vault and in memory while the service is unlocked.

This tutorial covers setup, daily usage, git commit signing, and what to do when things go wrong.

## Prerequisites

- Grimoire [installed](../install.md) and service running
- Logged in and vault unlocked (`grimoire status` shows `Unlocked`)
- SSH keys stored in your Bitwarden/Vaultwarden vault as SSH key items
- **Vaultwarden users**: your server must have the following flag set, otherwise SSH keys are silently filtered from sync:

```
EXPERIMENTAL_CLIENT_FEATURE_FLAGS=fido2-vault-credentials,ssh-key-vault-item,ssh-agent
```

Restart Vaultwarden after adding it.

## Step 1: Point SSH at Grimoire

Add to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR}/grimoire/ssh-agent.sock"
```

Or use the helper command:

```bash
export SSH_AUTH_SOCK="$(grimoire service ssh-socket)"
```

Reload your shell or source the profile:

```bash
source ~/.bashrc  # or ~/.zshrc
```

## Step 2: Verify Keys

```bash
ssh-add -l
```

You should see your vault's SSH keys listed. If you see "The agent has no identities":

1. Check the vault is unlocked: `grimoire status`
2. Check you have SSH keys in your vault: `grimoire list --search ssh`
3. Check Vaultwarden has the feature flags set (see prerequisites)
4. Force a sync: `grimoire sync`

## Step 3: Use SSH

```bash
ssh user@server
```

On the first use, you'll see a GUI approval prompt (biometric/PIN/password). This is the access approval system — the same one that protects CLI vault operations. Once approved, subsequent SSH operations in the same terminal session proceed silently until the approval expires (default: 5 minutes).

### On Headless / SSH Sessions

If you're already connected to a machine via SSH (no display), pre-authorize before using SSH keys:

```bash
grimoire authorize          # prompts for master password in terminal
ssh git@github.com         # works — approval cached for this session
```

See the [Headless Tutorial](04-headless.md) for the full story.

## Git Commit Signing

Git 2.34+ can sign commits with SSH keys. This is arguably the best reason to use Grimoire's SSH agent — your signing key never touches disk.

### Setup

```bash
# Tell git to use SSH signing
git config --global gpg.format ssh

# Use your vault key (grab the first one)
git config --global user.signingkey "key::$(ssh-add -L | head -1)"

# Enable signing for all commits
git config --global commit.gpgsign true
```

### How It Works

When you run `git commit`, git asks Grimoire's SSH agent to sign the commit hash. The agent checks your access approval, prompts if needed, and returns the signature. The private key never leaves the service process.

### Verifying Signatures

To verify signatures from your key, you need an allowed signers file:

```bash
# Create allowed signers file
echo "$(git config user.email) $(ssh-add -L | head -1)" > ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers

# Verify a commit
git log --show-signature -1
```

## Configuration

The SSH agent is enabled by default:

```toml
# ~/.config/grimoire/config.toml
[ssh_agent]
enabled = true              # disable to skip the SSH agent socket entirely
```

Security parameters are hardcoded:
- Approval is **always required** for signing operations
- Approval lasts **5 minutes** per terminal session
- Approval is scoped to the **terminal session leader PID** — all processes in the same terminal session share one approval grant

Run `grimoire authorize` once, and all `ssh` / `git` commands in that terminal work for 5 minutes.

## Auto-Lock Gotcha

The vault auto-locks after inactivity (default: 15 minutes). **SSH agent requests do not reset the inactivity timer** — only CLI commands do.

This means if you're only using SSH (no `grimoire list`, `grimoire status`, etc.), the vault will auto-lock and your SSH keys will disappear from `ssh-add -l`.

Workarounds:
- Run `grimoire status` periodically (resets the timer)
- Any vault CLI command resets the timer

## Supported Key Types

- **Ed25519**: fully supported
- **RSA / ECDSA**: not yet supported (planned)

If you have RSA or ECDSA keys in your vault, they'll be listed by `ssh-add -l` (the public key is visible) but signing will fail.

## Troubleshooting

### `ssh-add -l` shows nothing

```bash
# Is the service running?
grimoire status

# Is the vault unlocked?
grimoire unlock --terminal   # or just grimoire list (auto-prompts)

# Is SSH_AUTH_SOCK correct?
echo $SSH_AUTH_SOCK
ls -la $SSH_AUTH_SOCK

# Do you have SSH keys in your vault?
grimoire list --search ssh

# Has the vault synced recently?
grimoire sync
```

### `ssh` says "permission denied" or "signing failed"

Most likely cause: access approval not granted.

```bash
grimoire authorize    # grants approval for this terminal session
ssh git@github.com   # retry
```

### Keys appear but signing fails for a specific key

- Check the key type — only Ed25519 is supported
- The key's private key data may be corrupt or in an unexpected format
- Check service logs: `journalctl --user -u grimoire -f` (Linux) or `/tmp/grimoire-service.log` (macOS)

### Everything was working, now it's not

The vault probably auto-locked. Run `grimoire status` to check, then unlock.

## What's Next

- **[Secret Injection Tutorial](03-secret-injection.md)** — inject vault secrets into process environments
- **[Headless Servers Tutorial](04-headless.md)** — full guide for remote/CI usage
- **[SSH Agent Reference](../ssh-agent.md)** — protocol details, signing lifecycle, security analysis
