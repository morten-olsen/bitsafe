# Tutorial: Secret Injection

Grimoire can inject secrets from your vault directly into a process's environment variables. No temp files, no shell history, no clipboard. The process sees real values; everything else sees references.

## How It Works

`grimoire run` scans a command's environment variables for `grimoire:<id>/<field>` references, resolves them against your vault, and then **replaces the current process** (via `execvp`) with the target command. There is no wrapper process — your command runs directly with the resolved environment.

```bash
DB_PASSWORD="grimoire:abc123/password" grimoire run -- psql -h db.example.com
```

What happens:
1. Grimoire sees `DB_PASSWORD=grimoire:abc123/password`
2. It connects to the service and fetches the `password` field of vault item `abc123`
3. It sets `DB_PASSWORD=the-actual-password` in the environment
4. It `exec`s `psql -h db.example.com` — Grimoire is gone, `psql` is now the process

The `exec` semantics matter: there's no parent process holding secrets, no TTY forwarding issues, no signal handling complexity. `psql` *is* the process, as if you'd typed `DB_PASSWORD=hunter2 psql -h db.example.com` directly.

## Basic Usage

### Reference Format

```
grimoire:<vault-item-id>/<field>
```

Fields: `password`, `username`, `totp`, `notes`, `uri`

### Finding Item IDs

```bash
grimoire list --search "database"
# Shows item IDs you can use in references
```

### Simple Example

```bash
export API_KEY="grimoire:item-id-here/password"
grimoire run -- curl -H "Authorization: Bearer $API_KEY" https://api.example.com
```

### Multiple Secrets

```bash
export DB_USER="grimoire:db-item/username"
export DB_PASS="grimoire:db-item/password"
export API_TOKEN="grimoire:api-item/password"
grimoire run -- ./deploy.sh
```

All references are resolved before exec. If any reference fails (item not found, vault locked, field doesn't exist), Grimoire exits with an error *before* launching the command. Your script never runs with partial secrets.

## With Scripts

### Wrapper Script

```bash
#!/bin/bash
# deploy.sh — secrets are already resolved when this runs
echo "Deploying as ${DB_USER}..."
psql -h db.example.com -U "$DB_USER" -c "SELECT 1"
```

```bash
DB_USER="grimoire:prod-db/username" \
DB_PASS="grimoire:prod-db/password" \
grimoire run -- ./deploy.sh
```

### With Docker

```bash
DB_PASSWORD="grimoire:prod-db/password" \
grimoire run -- docker run -e DB_PASSWORD myapp:latest
```

The secret is resolved on the host. Docker sees the real value in its environment. The `grimoire:` reference never reaches the container.

### With .env Files

If your tool reads `.env` files, you can keep references in them:

```bash
# .env.grimoire
DB_URL=postgres://grimoire:db/username:grimoire:db/password@db.example.com/mydb
API_KEY=grimoire:api/password
```

```bash
export $(cat .env.grimoire | xargs)
grimoire run -- ./my-app
```

Note: this puts `grimoire:` references in your shell's environment temporarily. They're resolved by `grimoire run` before exec.

## Error Handling

All errors happen before the target command runs:

| Error | What Happens |
|-------|-------------|
| Vault is locked | Auto-prompts for unlock (GUI or terminal), then resolves |
| Item not found | Exit with error, command never runs |
| Field not found | Exit with error, command never runs |
| Service not running | Exit with error, command never runs |
| Access not approved | Prompts for approval, then resolves |

This is deliberate: you never end up in a state where your command is running with some secrets resolved and others still as `grimoire:` references.

## Security Considerations

### What's Good

- No secrets in shell history (the `grimoire:` reference is what's recorded, not the value)
- No temp files — resolution happens in memory
- `exec` semantics — no wrapper process holding secrets
- Access approval is checked during resolution — scoped to your session

### What's Not Great

- The resolved secret exists as an environment variable in the target process. Any child process inherits it. `/proc/<pid>/environ` is readable by the same user (Linux).
- If the target process logs its environment (many frameworks do on crash), the secret is in the logs.
- The resolution happens once at startup. If the secret rotates in your vault, the running process keeps the old value.

These are inherent to environment variable injection and not specific to Grimoire. They're the same tradeoffs as Vault Agent, 1Password CLI, or any other secret injector.

### Versus Alternatives

| Approach | Shell History | Disk | Process Env | Runtime |
|----------|:---:|:---:|:---:|:---:|
| Hardcoded in script | Visible | Visible | Visible | Static |
| `.env` file | Clean | Visible | Visible | Static |
| `grimoire run` | Clean | Clean | Visible | Static |
| Runtime API call | Clean | Clean | Depends | Dynamic |

`grimoire run` removes secrets from disk and history. The remaining exposure is the process environment, which is the minimum possible for environment-variable-based injection.

## What's Next

- **[Headless Servers Tutorial](04-headless.md)** — using `grimoire run` on remote machines and CI
- **[Quick Reference](../quickstart.md)** — all commands and options
