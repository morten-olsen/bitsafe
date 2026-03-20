# ADR 005: Client Designs

## Status

Accepted

## Context

Multiple client programs connect to `grimoire-service` to perform password management operations. Each client is thin and stateless — all crypto and state management live in the service.

## Decision

### CLI Client (`grimoire`)

The primary human interface. Stateless: connect, send request, print result, exit.

**Commands:**

```
grimoire status                         # Show service state, email, server
grimoire login <email>                  # Log in (prompts for password)
grimoire unlock                         # Unlock vault (prompts for password)
grimoire list [--type TYPE] [--search QUERY]  # List vault items
grimoire get <id> [--field FIELD]       # Get item (field: password, username, totp, uri, notes)
grimoire sync                           # Force sync
grimoire lock                           # Lock vault
grimoire logout                         # Log out
```

**Design choices:**
- `clap` derive API for argument parsing
- Password prompts via `rpassword` — transmitted over Unix socket, never stored by CLI
- Default output is human-readable; `--json` flag for machine-readable output
- Exit codes: 0 success, 1 error, 2 vault locked, 3 not logged in

### SSH Agent (embedded in `grimoire-service`)

The SSH agent runs as a second socket listener inside the service process. No separate binary needed.

- Listens on `$XDG_RUNTIME_DIR/grimoire/ssh-agent.sock`
- Speaks the SSH agent protocol (RFC draft) to SSH clients
- Accesses vault state directly (no IPC round-trip)
- Supports Ed25519 and RSA key signing
- Also supports Git commit signing (`git config --global gpg.format ssh`)
- A standalone `grimoire-ssh-agent` binary also exists for users who prefer a separate process

**Protocol translation:**

| SSH Agent Message | Grimoire RPC |
|---|---|
| `SSH_AGENTC_REQUEST_IDENTITIES` | `ssh.list_keys` |
| `SSH_AGENTC_SIGN_REQUEST` | `ssh.sign` |
| Other | `SSH_AGENT_FAILURE` |

**Usage:**
```bash
# Start the agent
grimoire-ssh-agent &

# Point SSH at it
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/grimoire/ssh-agent.sock

# SSH keys from your vault are now available
ssh git@github.com
```

### Future Clients

The JSON-RPC protocol is designed so that additional clients can be built independently:

- **GUI (Tauri/egui)**: Desktop application, long-lived connection with server-push notifications
- **rofi/dmenu integration**: Script that calls `grimoire list --json`, pipes through rofi, then `grimoire get <id> --field password | xclip`
- **Browser extension**: Native messaging host that bridges browser requests to the service

These are separate projects that speak the same IPC protocol.

## Consequences

### Positive

- **Thin clients**: No crypto, no state, no network — easy to implement and maintain
- **Scriptable**: CLI output + exit codes work well in shell scripts
- **Composable**: Pipe-friendly output enables integration with system tools
- **Independent**: Each client can be developed and released separately

### Negative

- **Service dependency**: All clients require the service to be running
- **Two sockets**: SSH agent needs its own socket (SSH protocol is not JSON-RPC)
- **Password transit**: Master password travels over the Unix socket (mitigated by socket permissions and SO_PEERCRED)
