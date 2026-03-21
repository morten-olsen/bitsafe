# Tutorial: Getting Started

This tutorial walks you through your first session with Grimoire — from login to retrieving your first secret. It assumes you've already [installed Grimoire](../install.md) and have a running Vaultwarden (or Bitwarden-compatible) server.

## Before We Start: What You're Getting Into

Grimoire is a daemon. When you interact with `grimoire` on the command line, you're not talking to your server directly — you're talking to a local service (`grimoire-service`) that holds your decrypted vault keys in memory and mediates all access to them.

This means:
- You log in **once** — the service remembers your credentials across restarts
- You unlock the vault — the service holds decrypted keys until it locks (auto-lock or manual)
- Every vault operation goes through the service — the CLI is just a thin JSON-RPC client

It also means the service is the thing keeping your secrets safe. If it's compromised, your vault is compromised. Read the [security model](../security.md) when you get a chance. We'll wait.

## Step 1: Start the Service

If you ran `grimoire service install` during setup, the service is already running. Check with:

```bash
grimoire status
```

If it's not running, start it:

```bash
grimoire-service &
```

Or, for a one-time test without backgrounding:

```bash
grimoire-service
# (runs in foreground, Ctrl+C to stop)
```

## Step 2: Log In

Login is a one-time operation. It authenticates you against your server and saves encrypted credentials so you only need to unlock (not re-login) in the future.

```bash
grimoire login you@example.com --server https://vault.example.com
```

You'll be prompted for your master password in the terminal. This is the only time Grimoire asks for your password in the terminal by design — all subsequent password entries go through the GUI prompt, which requires physical access to your display.

If your server URL is in your config file, you can omit `--server`:

```toml
# ~/.config/grimoire/config.toml
[server]
url = "https://vault.example.com"
```

```bash
grimoire login you@example.com
```

### What Just Happened

The service:
1. Fetched your KDF parameters from the server (prelogin)
2. Derived your master key hash using the Bitwarden SDK
3. Authenticated against the server and received encrypted vault keys
4. Initialized the SDK's crypto with your keys
5. Synced your vault from the server
6. Saved encrypted login state to `~/.local/share/grimoire/login.json`

Your master password was used to derive keys and then... well, it's still somewhere in heap memory as a `String`. We're working on that. The SDK zeroizes its own internal key material, but our wrapper layer doesn't yet. See? Honest.

## Step 3: Explore Your Vault

List everything:

```bash
grimoire list
```

Search for something specific:

```bash
grimoire list --search github
```

Get the full details of an item (use the ID from the list output):

```bash
grimoire get <id>
```

### Getting Specific Fields

The `-f` flag extracts a single field, which is useful for piping:

```bash
# Get just the password
grimoire get <id> -f password

# Get the username
grimoire get <id> -f username

# Get TOTP code
grimoire get <id> -f totp
# or equivalently:
grimoire totp <id>
```

### Copying to Clipboard

```bash
# Linux (X11)
grimoire get <id> -f password | xclip -selection clipboard

# Linux (Wayland)
grimoire get <id> -f password | wl-copy

# macOS
grimoire get <id> -f password | pbcopy
```

## Step 4: Understanding Access Approval

Here's where Grimoire differs from most CLI password managers. By default, every vault operation requires **access approval** — a check that the person requesting access is actually you, sitting at the machine, right now.

The first time you run a vault command after unlock, you'll see a GUI prompt asking for biometric verification (fingerprint), a PIN, or your master password. Once you approve, the approval is cached for your terminal session (default: 5 minutes).

```bash
grimoire list          # GUI prompt appears on first access
grimoire get <id>      # no prompt — same session, still approved
# ... 5 minutes pass ...
grimoire list          # GUI prompt again
```

This is the defense against blind RCE: if an attacker gets shell access to your machine, they can run `grimoire list`, but they can't interact with the GUI prompt that appears on your display. They'd need physical access (or a display server exploit) to approve the operation.

### Setting Up a PIN

After the first biometric or password verification, you can set a PIN for faster re-verification:

```bash
# PIN is set during the first GUI prompt interaction
# Subsequent prompts will offer: biometric → PIN → password
```

### Headless Environments

Access approval cannot be disabled — it's a hardcoded security invariant. On headless machines without a GUI, use `grimoire approve` to pre-approve access via master password in the terminal:

```bash
grimoire approve     # prompts for master password
grimoire list         # approved for this terminal session (5 min)
```

See the [Headless Tutorial](04-headless.md) for the full story.

## Step 5: Locking and Unlocking

Lock the vault manually:

```bash
grimoire lock
```

Or let it auto-lock after inactivity (default: 15 minutes). When locked, vault operations prompt you to unlock:

```bash
grimoire list
# "Vault is locked" → GUI prompt appears → enter password → list shows
```

Grimoire auto-prompts on locked vault. You don't need a separate `unlock` step — just use it, and it'll ask for your password when needed.

To unlock explicitly:

```bash
grimoire unlock              # GUI prompt (default — requires display access)
grimoire unlock --terminal   # terminal prompt (for SSH sessions)
```

### Why GUI Unlock by Default?

Because terminal unlock means any process that can send keystrokes to your terminal can unlock your vault. GUI unlock requires interacting with a separate window on your display, which is a stronger authentication boundary.

## Step 6: Syncing

Grimoire syncs your vault automatically in the background (default: every 5 minutes). To force a sync:

```bash
grimoire sync
```

## Step 7: Logging Out

When you're done (or want to clear all saved state):

```bash
grimoire logout
```

This deletes the persistent login state (`~/.local/share/grimoire/login.json`). You'll need to `grimoire login` again next time.

Versus locking:
- **Lock**: keys scrubbed from memory, need password to unlock. Login state preserved.
- **Logout**: everything cleared, need full login next time.

## What's Next

- **[SSH Agent Tutorial](02-ssh-agent.md)** — use your vault's SSH keys for authentication and git signing
- **[Secret Injection Tutorial](03-secret-injection.md)** — inject secrets into process environments
- **[Headless Servers Tutorial](04-headless.md)** — run Grimoire on machines without a display
- **[Quick Reference](../quickstart.md)** — all commands at a glance
