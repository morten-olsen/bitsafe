# Tutorial: Headless Servers

Grimoire works on machines without a display — remote servers, CI runners, SSH sessions. The experience is different from desktop usage because there's no GUI prompt, but the core functionality is the same.

## The Difference: No GUI

On a desktop, Grimoire uses GUI prompts for:
- Unlocking the vault
- Access approval (biometric/PIN/password verification)

On a headless machine, there's no display for these prompts. You have two options:
1. Use **terminal prompts** — type your password in the terminal
2. Use **`grimoire authorize`** — pre-approve access for your terminal session

The security model shifts: on desktop, the GUI prompt is the defense against blind RCE (attacker has shell but can't interact with the dialog). On headless, that defense isn't available — the terminal is the only authentication boundary.

## Setup for Headless

### Configuration

```toml
# ~/.config/grimoire/config.toml
[server]
url = "https://vault.example.com"

[prompt]
method = "terminal"       # skip GUI prompt discovery, go straight to terminal
```

For fully automated CI environments:

```toml
[prompt]
method = "none"           # never prompt — caller must provide password in RPC params
```

Access approval is always required and cannot be disabled. In automated environments, use `grimoire authorize` with the master password piped to stdin.

### Service

On a server with systemd:

```bash
grimoire service install
```

Without systemd (tmux, screen, or background):

```bash
grimoire-service &
```

## Daily Usage: SSH Sessions

### First Connection

```bash
# SSH into the server
ssh user@server

# Log in (first time only)
grimoire login you@example.com

# Unlock and authorize in one step
grimoire unlock --terminal
# or just run a vault command — it auto-prompts:
grimoire list
```

When you unlock with a direct password (terminal mode), access approval is automatically granted for your terminal session. You don't need a separate `grimoire authorize` step.

### Subsequent Connections

If the service is still running and the vault is unlocked (hasn't auto-locked):

```bash
ssh user@server
grimoire authorize         # re-authorize this new session
grimoire list              # works
```

If the vault has auto-locked:

```bash
ssh user@server
grimoire list              # auto-prompts for password, unlocks, shows list
```

### Multiple Terminal Sessions

Each SSH connection is a different terminal session. Approval is scoped per session by default, so you need to authorize each one:

```bash
# Terminal 1
grimoire authorize         # approved

# Terminal 2 (separate SSH connection)
grimoire authorize         # need to authorize again
```

This is intentional — it prevents a background process from riding on your interactive session's approval.

## CI / Automated Pipelines

For fully automated usage, you need to provide the password programmatically and disable interactive approval.

### Script Usage

```bash
#!/bin/bash
set -euo pipefail

# Start service if not running
pgrep -x grimoire-service >/dev/null || grimoire-service &
sleep 1

# Login (if not already logged in)
if ! grimoire status 2>/dev/null | grep -q "Unlocked\|Locked"; then
  echo "$GRIMOIRE_PASSWORD" | grimoire login "$GRIMOIRE_EMAIL" --server "$GRIMOIRE_SERVER"
fi

# Unlock (if locked) — also grants approval for this session
if grimoire status 2>/dev/null | grep -q "Locked"; then
  echo "$GRIMOIRE_PASSWORD" | grimoire unlock --terminal
fi

# Re-authorize if approval expired (approval lasts 5 min)
echo "$GRIMOIRE_PASSWORD" | grimoire authorize

# Use secrets
DB_PASS="grimoire:prod-db/password" grimoire run -- ./deploy.sh
```

### Security Notes for CI

- The master password must be available to the CI runner — store it as a CI secret (GitHub Actions secret, GitLab CI variable, etc.)
- Access approval is always required — CI scripts must use `grimoire authorize` to grant it
- Approval lasts 5 minutes — long-running jobs may need periodic re-authorization
- Consider whether you actually need Grimoire in CI, or whether your CI platform's native secret management is sufficient
- The vault should be locked/logged out at the end of the job

## Using SSH Agent on Headless

The SSH agent works on headless machines. Pre-authorize before using it:

```bash
# Set the socket
export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR}/grimoire/ssh-agent.sock"

# Authorize for this session
grimoire authorize

# Now SSH agent signing works
ssh-add -l               # lists keys
ssh git@github.com       # signs successfully
git push                 # commit signing works too
```

Without `grimoire authorize`, the agent will attempt a GUI prompt, fail (no display), and reject the signing request. The SSH client sees "signing failed."

## Troubleshooting

### "No display available" or prompt hangs

The service is trying to launch a GUI prompt on a machine with no display.

Fix: set `method = "terminal"` in config, or use `grimoire unlock --terminal`.

### Auto-lock keeps locking the vault during long jobs

The auto-lock timeout is hardcoded at 15 minutes and cannot be changed. For long-running jobs, have your script periodically run a vault command (e.g. `grimoire status`) to reset the timer, or re-unlock when needed.

### SSH agent says "no identities" after a while

The vault auto-locked. SSH agent requests don't reset the inactivity timer. Either:
- Increase `auto_lock_seconds`
- Have your script run `grimoire status` periodically
- Re-unlock when needed

### `grimoire authorize` says "already authorized"

Your session is already approved. The approval might have been granted by a previous `grimoire unlock --terminal` in the same session.

### Scripts fail with "vault is locked" but password piping doesn't work

Make sure you're piping to stdin correctly:

```bash
echo "$PASSWORD" | grimoire unlock --terminal
```

Not:

```bash
grimoire unlock --terminal <<< "$PASSWORD"  # this also works
```

## What's Next

- **[Quick Reference](../quickstart.md)** — all commands and config options
- **[Security Model](../security.md)** — understand what headless mode gives up
- **[SSH Agent Reference](../ssh-agent.md)** — detailed agent protocol and troubleshooting
