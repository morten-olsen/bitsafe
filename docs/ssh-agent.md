# SSH Agent

BitSafe includes an SSH agent that serves keys stored in your Bitwarden vault. SSH clients connect to the agent socket, and the agent uses the vault's decrypted keys to sign authentication challenges — no private key files on disk.

## Architecture

The SSH agent runs embedded inside `bitsafe-service` as a second socket listener. It accesses vault state directly — no JSON-RPC round-trip.

```
┌──────────┐        SSH protocol        ┌──────────────────────────────┐
│ ssh, git │ ──────────────────────────▸ │ bitsafe-service              │
│          │ ◂────────────────────────── │   ├─ main socket (RPC)       │
└──────────┘       (unix socket)        │   └─ ssh-agent socket        │
                                        │        peer_cred() → PID     │
                                        │        check approval cache  │
                                        │        sdk.ssh().sign()      │
                                        └──────────────────────────────┘
```

- Socket: `$XDG_RUNTIME_DIR/bitsafe/ssh-agent.sock` (mode `0600`)
- Enabled by default (`ssh_agent.enabled = true` in config)
- Peer PID extracted via `SO_PEERCRED` on each connection for approval scoping

## Setup

### 1. Enable the SSH agent

The agent is enabled by default. To disable it:

```toml
# ~/.config/bitsafe/config.toml
[ssh_agent]
enabled = false
```

### 2. Set SSH_AUTH_SOCK

Add to your shell profile (`~/.bashrc`, `~/.zshrc`):

```sh
export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR}/bitsafe/ssh-agent.sock"
```

Or use the helper:

```sh
export SSH_AUTH_SOCK="$(bitsafe service ssh-socket)"
```

### 3. Store SSH keys in Bitwarden

SSH keys must be stored as SSH key items (cipher type 5) in your Bitwarden/Vaultwarden vault.

**Vaultwarden requirement**: the server must have the following flag set, otherwise SSH key ciphers are filtered from sync responses entirely:

```
EXPERIMENTAL_CLIENT_FEATURE_FLAGS=fido2-vault-credentials,ssh-key-vault-item,ssh-agent
```

### 4. Verify

```sh
ssh-add -l              # List available keys
ssh -T git@github.com   # Test signing
```

## Signing Lifecycle

### What happens when `ssh` requests a signature

1. SSH client connects to the agent socket
2. Agent extracts the client's PID via `SO_PEERCRED`
3. Client sends `SSH_AGENTC_REQUEST_IDENTITIES` — agent returns public keys from the vault (no approval required for listing)
4. Client sends `SSH_AGENTC_SIGN_REQUEST` with the key and challenge data
5. Agent checks access approval for the client's scope (see below)
6. If approved: signs with `sdk.ssh().sign()` and returns the signature
7. If not approved and GUI is available: prompts via biometric/PIN/password dialog
8. If not approved and no GUI: rejects the request (SSH client sees a signing failure)

### Prerequisites

- The vault must be **unlocked** — if locked, the agent returns an empty key list and signing is impossible
- The caller must have **access approval** — either pre-authorized via `bitsafe authorize`, granted by a GUI prompt, or approval disabled in config

## Access Approval

SSH signing uses the same scoped access approval system as CLI vault commands (`vault.get`, `vault.totp`, etc.).

### How it works

1. When a signing request arrives, the agent resolves the SSH client's PID to a **scope key**
2. The scope key depends on the `approval_for` config:
   - **`session`** (default): scope key = terminal session leader PID. All processes in the same terminal session share one approval grant
   - **`pid`**: scope key = the SSH client's exact PID
   - **`connection`**: scope key = 0 (every connection requires fresh approval)
3. If the scope key has a cached approval that hasn't expired, signing proceeds immediately
4. If not, the agent attempts a GUI prompt (biometric → PIN → password dialog)
5. If GUI is unavailable (headless/SSH session), signing is rejected

### Interactive sessions (GUI available)

On a machine with a display, the first signing request triggers a GUI prompt:

```
ssh git@github.com    # GUI dialog appears: "BitSafe: approve SSH signing"
                      # approve via fingerprint/PIN/password
                      # signing proceeds, approval cached for 5 minutes
```

Subsequent signing requests within the approval window proceed silently.

### Headless / SSH sessions (no GUI)

Pre-authorize before using SSH keys:

```sh
bitsafe authorize      # prompts for master password in terminal
ssh git@github.com     # signing works — approval is cached
```

The `authorize` command grants approval scoped to your terminal session. Any SSH command from the same terminal session will be approved until `approval_seconds` expires (default: 300s / 5 minutes).

Unlocking the vault with a direct password also grants approval:

```sh
bitsafe unlock --terminal   # or just run any vault command (auto-prompts)
ssh git@github.com          # already approved from the unlock
```

### Disabling approval

For CI/headless environments where interactive approval is impractical:

```toml
[access]
require_approval = false
```

With approval disabled, any process that can connect to the agent socket can sign.

## Timeouts and Auto-lock

The vault auto-locks after a period of inactivity (default: 900 seconds / 15 minutes). Inactivity is measured by calls to the main RPC socket — `touch()` is called on every vault/sync operation.

**Important**: SSH agent requests do **not** reset the inactivity timer. This means:

- If you only use SSH (no CLI vault commands), the vault will auto-lock after 15 minutes
- After auto-lock, `ssh-add -l` returns an empty list and signing fails silently
- To keep the vault alive, any RPC operation (e.g. `bitsafe status`) resets the timer

The auto-lock timeout is configurable:

```toml
[service]
auto_lock_seconds = 3600  # 1 hour
```

## Security Considerations

### Socket permissions

Both sockets (main RPC and SSH agent) are created with mode `0600`. Only the owner can connect. The main socket also validates peer UID via `SO_PEERCRED` (Linux) or `getpeereid` (macOS).

### Scope isolation

Access approval is scoped to the caller's terminal session by default. A process in one terminal session cannot use another session's approval grant. This prevents a background process or cron job from silently using approval that was granted in an interactive session (unless they share the same session leader PID, which they wouldn't).

### GUI prompt as RCE defense

The GUI prompt requirement for SSH signing serves the same purpose as for CLI vault operations: defense against blind RCE. An attacker with command execution but no display access cannot approve signing without physical interaction with the GUI dialog.

In headless environments, `bitsafe authorize` provides an equivalent: the attacker would need to know the master password.

### Ed25519 only

SSH signing currently supports Ed25519 keys only. RSA and ECDSA support can be added.

### Key material

Private keys are decrypted by the SDK and held in memory for the duration of the unlocked session. The SDK uses `ZeroizingAllocator` internally. Keys are scrubbed when the vault locks (the SDK client is dropped and recreated).

## Configuration Reference

```toml
# ~/.config/bitsafe/config.toml

[ssh_agent]
enabled = true              # Enable the embedded SSH agent (default: true)

[service]
auto_lock_seconds = 900     # Auto-lock after inactivity (default: 900)

[session]
duration_seconds = 300      # Session duration before re-verification (default: 300)
biometric_enabled = true    # Try biometric for approval prompts (default: true)
pin_enabled = true          # Allow PIN for approval (default: true)
pin_max_attempts = 3        # PIN attempts before requiring master password (default: 3)

[access]
require_approval = true     # Require approval for signing (default: true)
approval_seconds = 300      # How long an approval lasts (default: 300)
approval_for = "session"    # Scope: session | pid | connection (default: session)
```

## Troubleshooting

### `ssh-add -l` returns "The agent has no identities"

- **Vault is locked**: run `bitsafe unlock --terminal` or `bitsafe list` (auto-prompts)
- **No SSH keys in vault**: check Vaultwarden has `EXPERIMENTAL_CLIENT_FEATURE_FLAGS` set, then `bitsafe sync`
- **Wrong socket**: verify `SSH_AUTH_SOCK` points to the correct path
- **Service not running**: check `systemctl --user status bitsafe`

### `ssh` fails with "permission denied" or "signing failed"

- **Not approved**: run `bitsafe authorize` in the same terminal session, then retry
- **Approval expired**: approvals last `approval_seconds` (default: 5 min). Re-authorize
- **Auto-locked**: the vault locked due to inactivity. Run `bitsafe status` to check, then unlock
- **Key type**: only Ed25519 is supported. Check your vault key type

### Keys appear in `ssh-add -l` but signing fails

- **Access approval**: most likely cause. Run `bitsafe authorize` and retry
- Check service logs: `journalctl --user -u bitsafe -f`
- The key's private key data may be corrupted or in an unsupported format
