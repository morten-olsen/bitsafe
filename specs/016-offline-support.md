# ADR 016: Offline Vault Access

## Status

Implemented

## Context

When the Bitwarden/Vaultwarden server is unreachable (offline, server down, network issues), Grimoire cannot:

1. **Unlock the vault** — unlock calls `prelogin` (HTTP) to get KDF params, then `login_token_request` (HTTP) to verify the master password and retrieve encrypted vault keys. Both require the server.
2. **Populate ciphers after a service restart** — the cipher repository is in-memory only. If the service restarts while offline, the vault is empty even if the user could unlock.

Once unlocked with a populated cipher repository, vault operations (list, get, totp, SSH signing, `grimoire run`) already work fully offline — they read from the in-memory repo with no network calls. Background sync failures are already handled gracefully (warn + retry in 300s).

**The gap is narrow but critical:** if the service auto-locks (900s timeout) or restarts while the user is offline, they lose all access until the server returns.

### How Bitwarden desktop/mobile handles this

The official Bitwarden clients cache the entire encrypted vault to a local SQLite database. On unlock:

1. KDF params are cached locally (they rarely change)
2. The master password is derived locally using the cached KDF params
3. The derived key is used to decrypt the locally cached user key
4. If decryption succeeds, the password was correct — no server round-trip needed
5. The decrypted user key unlocks the cached encrypted ciphers

The server is only needed for sync (fetching changes). The encrypted vault on disk *is* the password verifier — if the derived key can decrypt the `user_key` field, the password is correct. There is no separate hash or verifier stored.

### Security trade-off

Today, Grimoire stores almost nothing on disk — just `login.json` (email + server URL) and `backoff.json`. An attacker with disk access finds nothing to brute-force. Adding an encrypted local cache means:

- **Offline brute-force becomes theoretically possible** — but mitigated by platform-bound encryption. The cache is envelope-encrypted with a CEK stored in the OS credential store (macOS Keychain with biometric gate, Linux Secret Service, or TPM). A copied cache file is useless without the machine-bound CEK. On systems without a credential store, the fallback is master-password-only protection (same as Bitwarden desktop).
- **This is strictly stronger than Bitwarden desktop**, which stores its encrypted vault in a SQLite database without OS-level key wrapping.
- **We do NOT weaken online protections** — exponential backoff for server-verified attempts remains unchanged.

## Decision

### Encrypted local vault cache

After each successful sync, persist the encrypted vault data to disk. This cache contains only data that is already encrypted server-side — we never write plaintext secrets to disk.

#### Cache file: `~/.local/share/grimoire/vault_cache.bin`

The cache stores everything needed to unlock and operate offline:

```rust
struct VaultCache {
    /// Schema version for forward compatibility
    version: u32,
    /// KDF parameters (from prelogin response)
    kdf: KdfParams,
    /// Encrypted user key (from login token response, already encrypted by master key)
    encrypted_user_key: String,
    /// Encrypted private key (from login token response, already encrypted by user key)
    encrypted_private_key: String,
    /// User ID (from JWT claims)
    user_id: String,
    /// Email (salt for key derivation)
    email: String,
    /// Server URL
    server_url: String,
    /// Encrypted cipher objects (exactly as received from sync, server-encrypted)
    ciphers: Vec<serde_json::Value>,
    /// Timestamp of the sync that produced this cache
    last_sync: DateTime<Utc>,
    /// HMAC-SHA256 over all above fields, keyed by the derived master key
    /// Serves dual purpose: integrity check + password verification
    integrity_hmac: [u8; 32],
}
```

File permissions: `0600` (owner read/write only), same as existing state files.

#### How fields are populated

**On login** (server reachable): The token response contains `key` (encrypted user key) and `private_key` (encrypted private key). These are already encrypted by the user's master key — they are the same blobs that Bitwarden stores server-side. We save them to the cache alongside the KDF params from prelogin.

**On sync** (server reachable): The sync response contains encrypted cipher objects. We save the raw JSON values to the cache. These are server-encrypted — we never serialize decrypted vault data.

**On unlock** (offline or online): We read the cache, derive the master key from the password + cached KDF params, compute the HMAC over the cached fields, and compare to `integrity_hmac`. If it matches, the password is correct and the cached data is intact. We then pass the encrypted keys and ciphers to the SDK for decryption.

#### HMAC as password verifier

Rather than attempting trial decryption of the user key (which requires matching SDK internal formats), we compute an HMAC-SHA256 over the cache contents keyed by a value derived from the master key:

```
cache_hmac_key = HKDF-SHA256(ikm=master_key, salt="grimoire-vault-cache", info="hmac-v1")
integrity_hmac = HMAC-SHA256(cache_hmac_key, canonical_cache_bytes)
```

This gives us:
- **Password verification** — wrong password → wrong master key → wrong HMAC key → mismatch
- **Integrity** — any tampering with cached data (ciphers, KDF params, keys) is detected
- **Domain separation** — HKDF info string prevents cross-protocol key reuse

The `canonical_cache_bytes` is the serialized cache struct with the `integrity_hmac` field zeroed — a deterministic canonical form.

### Unified unlock flow (cache-first)

Rather than branching between "online" and "offline" code paths, unlock always uses the local cache when one exists. Background sync handles freshness. This reduces implementation complexity to a single unlock path.

```
User provides master password
        │
        ▼
   Cache exists?
        │
        ├── NO ──► Server reachable? ──► NO ──► Error: "Cannot reach server
        │                  │                      and no local cache available.
        │                  │                      Run 'grimoire login' when online."
        │                  ▼ YES
        │             Online bootstrap: prelogin + token request
        │                  │
        │             ├── Auth fails ──► "Wrong master password"
        │             │
        │             └── Auth succeeds ──► Generate CEK, init crypto,
        │                                   sync, build cache, unlock
        │
        └── YES ──► Read CEK from OS credential store
                         │
                    ├── CEK unavailable ──► Error: "Credential store
                    │                        unavailable — cannot decrypt
                    │                        vault cache"
                    │
                    └── CEK available ──► Decrypt outer layer (ChaCha20-Poly1305)
                                              │
                                         Derive master key from password + cached KDF
                                              │
                                         Verify HMAC
                                              │
                                         ├── Mismatch ──► "Wrong master password"
                                         │
                                         └── Match ──► Init SDK crypto with cached keys
                                                            │
                                                       Populate cipher repo from
                                                       cached ciphers
                                                            │
                                                       Vault unlocked ✓
                                                            │
                                                       Kick off background sync
                                                       (updates cache if vault hash
                                                       changes)
```

#### HMAC mismatch is always "wrong password"

HMAC mismatch has exactly one meaning: the provided password does not match the master key that built this cache. No recovery path, no server fallback.

If the user changed their master password on another device, the cache is stale — the old HMAC was computed with the old master key. The user must `grimoire logout` + `grimoire login` with the new password. This is deliberate:

- **Password changes are rare and intentional** — requiring logout + login is expected and reasonable
- **Eliminates the only complex branching** — no "is the server reachable?" check, no recovery path, no ambiguity
- **Simple to audit** — HMAC mismatch → wrong password → exponential backoff. One path.

#### Why cache-first is equivalent in security

| Concern | Cache-first | How it's handled |
|---------|-------------|-----------------|
| Wrong password | HMAC mismatch → reject | Same UX as server rejection |
| Password change | Requires logout + login | Rebuilds cache from scratch |
| Account revocation | Sync fails with 401 → lock + delete cache | Within seconds of connectivity |
| KDF param updates | Sync fetches new params → cache rebuilt on next write | Async, same outcome |
| Stale vault data | Fresh after background sync | Sync runs immediately after unlock + every 300s |

**What we eliminate:**
- Two parallel unlock code paths (online vs offline)
- "Is the server reachable?" check at unlock time (with its own timeout/retry logic)
- HMAC mismatch recovery logic
- `UnlockSource` enum — every unlock is the same

### Cache age indicator

Since every unlock now uses the cache, the `status` RPC response includes the cache age (time since last successful sync). The CLI displays this when relevant:

```
Vault unlocked (last synced 2h ago)
```

If the background sync is failing (server unreachable), the age grows and serves as a natural staleness warning. No special "offline mode" — just a sync timestamp that tells the user how fresh their data is.

### Cache lifecycle

| Event | Cache action |
|-------|-------------|
| Login (success) | Generate CEK, sync, build + encrypt cache |
| Unlock (success) | Read-only — decrypt cache, init crypto, populate repo |
| Sync (success) | Compare vault hash — skip write if unchanged (see below) |
| Lock | No change — cache persists |
| Logout | **Delete** cache file + delete CEK from credential store |
| Password change (on another device) | Old cache remains valid with old password. User must `grimoire logout` + `grimoire login` to rebuild cache with new password. |

### Vault hash: skip cache writes when nothing changed

The cache file header (outside the encrypted envelope) includes a **vault hash** — the SHA-256 of the serialized encrypted cipher array from the last sync. This hash is not secret (it's a hash of already-encrypted data) and reveals only whether the vault has changed, not what changed.

On each sync:

1. Compute SHA-256 of the fresh encrypted cipher array
2. Compare to the stored `vault_hash` in the cache header
3. **Match** → vault is unchanged, skip cache re-encryption entirely (no CEK read, no Touch ID prompt, no disk write)
4. **Mismatch** → vault changed, read CEK from credential store, re-encrypt cache, update hash

This is critical for UX on macOS: since the CEK read triggers Touch ID via `kSecAccessControlUserPresence`, we only prompt the user when vault content has actually changed. For most users whose vault is relatively stable, background syncs will almost never trigger Touch ID.

The hash also covers the KDF params and encrypted keys — if any of these change server-side (password change, KDF param update), the hash mismatches and forces a cache rebuild.

### Backoff enforcement for offline unlock

Offline unlock still enforces the same exponential backoff as online unlock. The backoff state is already persisted to `backoff.json` and survives service restarts. An attacker who restarts the service to reset the backoff would need to also delete `backoff.json`, but they already have disk access in that scenario — the backoff is defense-in-depth against casual brute-force, not a hard guarantee against a disk-level attacker.

### What this does NOT include

- **Offline login** — first-time login always requires the server. The cache is only populated after a successful login + sync.
- **Offline write operations** — vault modifications are not supported offline. Grimoire is read-only regardless of online status (no create/edit/delete cipher support).
- **Offline `grimoire approve`** — password verification for headless pre-approval still requires the server. This is deliberate: `approve` is a security-sensitive operation that should not bypass server-side revocation checks.
- **Configurable cache location** — hardcoded to `~/.local/share/grimoire/vault_cache.bin`. Following the principle that security parameters are not configurable.
- **Selective caching** — all ciphers from the last sync are cached. No filtering by type, folder, or collection.

### Platform-bound cache encryption (CEK wrapping)

The vault cache is not just protected by the master-password-derived HMAC — it is **envelope-encrypted** with a random 256-bit Cache Encryption Key (CEK) stored in the OS credential store. This means an attacker who copies `vault_cache.bin` to another machine cannot brute-force it — they need both the master password AND the machine-bound CEK.

#### Cache encryption layers

```
┌─────────────────────────────────────────────────────┐
│ vault_cache.bin                                     │
│                                                     │
│  ┌─────────────────────────────────────────────┐    │
│  │ Outer layer: ChaCha20-Poly1305              │    │
│  │ Key: CEK (stored in OS credential store)    │    │
│  │                                             │    │
│  │  ┌─────────────────────────────────────┐    │    │
│  │  │ Inner layer: Bitwarden encryption   │    │    │
│  │  │ Key: user key (encrypted by master  │    │    │
│  │  │      password via KDF)              │    │    │
│  │  │                                     │    │    │
│  │  │ encrypted_user_key                  │    │    │
│  │  │ encrypted_private_key               │    │    │
│  │  │ encrypted ciphers                   │    │    │
│  │  └─────────────────────────────────────┘    │    │
│  │                                             │    │
│  │ integrity_hmac (master-password-derived)    │    │
│  └─────────────────────────────────────────────┘    │
│                                                     │
│ CEK nonce (24 bytes, stored in the clear)           │
│ CEK version tag (for key rotation)                  │
│ vault_hash: SHA-256 of encrypted ciphers (clear)    │
└─────────────────────────────────────────────────────┘
```

The outer ChaCha20-Poly1305 layer encrypts the entire serialized `VaultCache` struct. The inner layer is the existing Bitwarden server-side encryption. An attacker needs to strip both layers to reach plaintext secrets.

#### CEK storage: platform-specific

**macOS — Keychain with biometric gate:**

The CEK is stored as a `kSecClassGenericPassword` item in the macOS Keychain with:

- `kSecAttrService`: `"com.grimoire.vault-cache"`
- `kSecAttrAccount`: `"cek-v1"`
- `kSecAttrSynchronizable`: `false` — excluded from iCloud Keychain
- `kSecAttrAccessible`: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — item is:
  - Only accessible when the Mac is unlocked (logged in)
  - **Excluded from backups** (Time Machine, Migration Assistant)
  - **Bound to the device** via the Secure Enclave's UID key — copying the keychain DB to another Mac yields gibberish
- `SecAccessControl`: `kSecAccessControlUserPresence` — every read requires Touch ID or the system login password

This means:
- Stolen disk image → CEK is unreadable (bound to Secure Enclave hardware)
- Malware as same user → triggers visible Touch ID / password prompt that the user can deny
- Backup copy → CEK excluded from backup (`ThisDeviceOnly` flag)

Uses the `security-framework` Rust crate for Keychain access, with `security-framework-sys` for `SecAccessControl` flags.

**Linux desktop (GNOME/KDE) — Secret Service API:**

The CEK is stored via the freedesktop Secret Service D-Bus API (`org.freedesktop.secrets`), implemented by GNOME Keyring or KDE KWallet:

- Service: `"grimoire"`
- Attribute: `"cache-encryption-key"`
- Collection: default (login keyring)

The login keyring is encrypted with the user's login password and automatically unlocked at login via PAM. This provides:
- Stolen disk image → CEK is encrypted by the login keyring's master key (derived from the user's login password via PBKDF2)
- Same-user malware → can access (same trust boundary as file access — but this matches the existing threat model)

Uses the `keyring` Rust crate (which wraps `libsecret` on Linux).

**Linux headless / no desktop environment — TPM 2.0 (if available):**

When no Secret Service provider is available but a TPM 2.0 is present (`/dev/tpmrm0` exists):

- The CEK is **sealed** to the TPM under the Storage Root Key (SRK) hierarchy
- An authorization password (derived from a stable machine identity) is set on the sealed object
- The sealed blob is stored alongside the cache file as `~/.local/share/grimoire/cek.tpm2`
- Unsealing requires physical access to the same TPM chip — the blob is useless on any other machine

No PCR binding (avoids breakage on kernel/firmware updates). The TPM binding alone ensures the CEK cannot be extracted to another machine.

Uses `tss-esapi` Rust crate (requires `libtss2-esys` system library). TPM support is **optional** — detected at runtime.

**Fallback — no OS credential store available:**

When no Keychain, Secret Service, or TPM is available (minimal Linux, containers, WSL):

- The CEK is **not used** — the cache relies solely on the master-password-derived HMAC and Bitwarden's own encryption
- This is the same security level as Bitwarden's desktop client (which does not use OS-level key wrapping either)
- The service logs a warning at startup: `"No OS credential store available — vault cache is protected by master password only"`

#### CEK lifecycle

| Event | CEK action |
|-------|-----------|
| Login (first time, no CEK exists) | Generate random 256-bit CEK via `OsRng`, store in OS credential store |
| Cache write (vault hash mismatch) | Read CEK from credential store (may trigger biometric), encrypt cache, write to disk |
| Cache write (vault hash match) | **No CEK read** — skip entirely, no biometric prompt |
| Cache read (offline unlock) | Read CEK from credential store (triggers biometric on macOS), decrypt cache, verify HMAC |
| Logout | Delete CEK from credential store (and delete cache file) |
| CEK read fails (credential store locked/unavailable) | Fall back to online-only unlock; warn user |
| Migration to new machine | CEK is absent → first online unlock generates a new CEK and rebuilds cache |

#### When CEK biometric prompts occur (macOS)

The CEK read from Keychain triggers Touch ID via `kSecAccessControlUserPresence`. With the unified cache-first flow, prompts occur at:

- **Every unlock**: CEK needed to decrypt the cache — Touch ID + master password = two factors
- **Background sync when vault changed**: vault hash mismatch → CEK needed to re-encrypt cache
- **Background sync when vault unchanged**: **no Touch ID** — hash matches, no cache write needed

Day-to-day for a user with a stable vault: Touch ID on unlock only. Subsequent syncs are silent. Vault operations while unlocked use the existing approval flow (separate Touch ID via GUI prompt), with no CEK involvement.

## Consequences

### Positive

- **Resilient to server outages** — laptop on a plane, server maintenance, network issues no longer lock users out
- **Service restart doesn't lose vault** — the main pain point (auto-lock timeout + slow server = re-enter password + wait for sync) is eliminated
- **Stronger than Bitwarden desktop** — the CEK wrapping means a copied cache file is useless without the OS credential store, unlike Bitwarden's SQLite vault which can be brute-forced from any machine
- **macOS biometric gate** — offline unlock on macOS requires Touch ID or system password in addition to the master password, providing genuine two-factor offline protection
- **Matches user expectations** — Bitwarden desktop/mobile already works this way (minus the CEK wrapping, which is a security improvement)
- **No protocol changes** — the unlock RPC stays the same; cache logic is internal to the service
- **Graceful degradation** — works on every platform, with increasing security on platforms that offer credential stores
- **Single code path** — cache-first unified flow eliminates online/offline branching, reducing implementation complexity and testing surface

### Negative

- **Encrypted vault data on disk** — expands attack surface for disk-level attackers, even with CEK wrapping (fallback path has no CEK)
- **Platform dependencies** — `security-framework` (macOS), `keyring`/`libsecret` (Linux), optionally `tss-esapi` (TPM). These are well-maintained crates but add to the dependency surface.
- **Stale data risk** — offline vault may be missing recently added/modified entries. The `last_sync` age indicator mitigates confusion but doesn't prevent it.
- **Cache coherency** — password changes, account deactivation, and org policy changes don't propagate until the next successful online unlock/sync.
- **Credential store failures** — if the macOS Keychain or Linux keyring is broken/locked, offline unlock fails. Users must understand this dependency. Fallback to online-only is safe but may surprise.
- **Disk I/O on sync when vault changes** — writing the full encrypted cache adds latency, though the vault hash check skips writes when nothing changed. For large vaults (1000+ ciphers), writes could be noticeable. Mitigated by writing asynchronously after the in-memory repo is populated.

## Security Analysis

### Threat Model Impact

This changes Grimoire's threat model by putting encrypted vault data on disk. However, the CEK wrapping via OS credential stores **significantly** limits the impact compared to a naive local cache:

- **With CEK (macOS Keychain / Linux Secret Service / TPM):** Disk access alone yields an encrypted blob that requires both the master password AND the platform-bound CEK to decrypt. An attacker who copies the file to another machine gets nothing — the CEK is non-exportable. On-machine attacks require unlocking the OS credential store (biometric/login password on macOS, login keyring on Linux).
- **Without CEK (fallback):** Same as Bitwarden desktop — brute-forceable with master password only. This only applies when no OS credential store is available.

The trust boundary remains the same (Unix user account). The CEK wrapping adds a second trust boundary (OS credential store / hardware) that is strictly stronger.

### Attack Vectors

| # | Vector | Severity | Description |
|---|--------|----------|-------------|
| 1 | Offline brute-force (copied file) | High→**Low with CEK** | Attacker copies `vault_cache.bin` to another machine. Without CEK: brute-force master password against HMAC. **With CEK: cache is double-encrypted; CEK is hardware/OS-bound and absent on the attacker's machine. Attack requires brute-forcing ChaCha20-Poly1305 (infeasible).** |
| 2 | Offline brute-force (same machine) | Medium | Attacker has persistent access to the same machine. Must still unlock the OS credential store to read CEK (Touch ID/login password on macOS, login keyring password on Linux). Without credential store access, same as Vector 1. |
| 3 | Stale cache after password change | Medium | User changes master password on another device. Old password still unlocks the local cache until user does `grimoire logout` + `grimoire login`. |
| 4 | Stale cache after account revocation | Medium | Admin deactivates account or removes org access. Cached ciphers remain accessible offline until next online unlock attempt fails and cache is not used. |
| 5 | Cache file tampering | Medium | Attacker modifies cached ciphers to inject malicious data (e.g., altered URIs in credential-helper responses). |
| 6 | Cache file theft via backup/sync | Low | `vault_cache.bin` included in cloud backup or rsync. **macOS Keychain `ThisDeviceOnly` items are excluded from Time Machine. The copied cache is useless without the CEK.** On Linux, backup copies are encrypted by CEK if credential store was used. |
| 7 | KDF param downgrade via cache poisoning | High | Attacker replaces cache file with one using weak KDF params (PBKDF2 iterations=1), then observes/captures the HMAC to brute-force trivially. **CEK mitigates: attacker cannot construct a valid outer ChaCha20-Poly1305 layer without the CEK, so a poisoned cache is rejected at decryption before KDF params are even read.** |
| 8 | Vault hash as oracle | Low | The vault hash is stored in the clear (outside the encrypted envelope). It reveals whether the vault changed between syncs but not what changed (SHA-256 of already-encrypted data). Minimal information leakage. |
| 9 | Swap/tmpfs leak of cache contents | Low | Cache file contents may be paged to swap during read. Existing `mlockall` on Linux mitigates for process memory but not for filesystem buffer cache. |
| 10 | CEK extraction from credential store | Medium | Same-user malware attempts to read the CEK. On macOS: triggers visible Touch ID prompt (user can deny). On Linux with Secret Service: accessible to same-user processes (same trust boundary). On Linux with TPM: requires the TPM device. |

### Planned Mitigations

| Vector | Mitigation | Mechanism |
|--------|-----------|-----------|
| 1 | CEK wrapping makes copied-file attacks infeasible | Cache is encrypted with CEK (ChaCha20-Poly1305) before being written to disk. CEK is stored in OS credential store with `ThisDeviceOnly` (macOS) or bound to TPM/login keyring (Linux). Without CEK, attacker faces AES-256 + ChaCha20 — not brute-forceable. Fallback (no credential store) still has KDF as defense. |
| 2 | OS credential store authentication | macOS: `kSecAccessControlUserPresence` requires Touch ID or system password to read CEK — visible prompt that user can deny. Linux: login keyring requires login password. TPM: requires physical machine access. |
| 3 | Password change requires logout + login | After password change on another device, cached HMAC won't match new password. User must `grimoire logout` + `grimoire login` to rebuild cache. Old password continues to work against the local cache until then — acceptable because the user holds both passwords and the action is deliberate. |
| 4 | Sync failure clears cache on revocation | Background sync runs immediately after unlock and every 300s. If sync returns HTTP 401/403 (account deactivated, access revoked), delete `vault_cache.bin` and CEK, then lock the vault. Revocation takes effect within seconds of connectivity. |
| 5 | HMAC integrity check + CEK AEAD | Two layers of integrity: ChaCha20-Poly1305 AEAD rejects any modification to the outer ciphertext, and the HMAC covers all inner fields. Attacker cannot forge either without the respective keys. |
| 6 | CEK hardware binding | macOS: `ThisDeviceOnly` flag excludes from backups and binds to Secure Enclave UID key. Linux TPM: sealed to physical TPM chip. Backup copies of the cache file are inert without the CEK. Document in `docs/security.md`. |
| 7 | CEK AEAD rejects poisoned caches + KDF param floor | The ChaCha20-Poly1305 layer is verified before any cache parsing. A poisoned cache (crafted by attacker without CEK) fails AEAD and is rejected before KDF params are read. As defense-in-depth, also enforce KDF param floor on cache read: PBKDF2 ≥ 100,000 iterations, Argon2id ≥ 3 iterations / 64 MiB / 1 parallelism. |
| 8 | Accepted | Hash of encrypted data reveals only change/no-change. No plaintext or structural information leakage. Acceptable trade-off for the UX benefit of avoiding unnecessary biometric prompts. |
| 9 | Accepted | Existing `mlockall` covers process memory. Filesystem buffer cache is kernel-managed and transient. Same exposure as reading any encrypted file. |
| 10 | Biometric gating (macOS) + documentation (Linux) | macOS: `kSecAccessControlUserPresence` means malware triggers a visible prompt. Linux Secret Service: same trust boundary as file access (documented trade-off). Linux TPM: physical access required. |

### Residual Risk

- **Same-machine, same-user attack** (Vector 2) — if an attacker has persistent same-user access AND can satisfy the credential store authentication (e.g., trick the user into Touch ID, or on Linux where Secret Service is same-user accessible), they can read the CEK and decrypt the cache. This is inherent to the same-user trust boundary and matches the existing threat model (same-user attacker can already read process memory, attach debuggers, etc.).
- **Fallback path without CEK** — on systems with no OS credential store, the cache is protected only by the master password KDF. This is equivalent to Bitwarden desktop's security level. Users on such systems should ensure full-disk encryption.
- **Revocation window** (Vectors 3, 4) — between a server-side change and the next successful sync, cached access persists. Bounded by sync interval (300s) when online, or indefinitely when offline. A deliberately-offline attacker could maintain access indefinitely, but they need the master password + CEK.
- **Backup copies on Linux** (Vector 6) — without `ThisDeviceOnly` equivalent, Linux backup copies of the cache are encrypted by CEK from the login keyring. If the attacker also obtains the login keyring DB and knows the login password, they can extract the CEK. Full-disk encryption is the recommended mitigation.

### Implementation Security Notes

**Deviations from planned mitigations:**

- **macOS biometric gate (kSecAccessControlUserPresence) not yet implemented.** The macOS keystore uses `security-framework`'s `set_generic_password` / `get_generic_password` which stores items in the Keychain but without `SecAccessControl` biometric flags. Items are still device-bound (Keychain encryption) but same-user processes can read without biometric prompt. This is a v2 enhancement requiring lower-level `SecItem*` API usage. The CEK is still hardware-bound and excluded from backups by default Keychain behavior.
- **Background sync cache updates deferred.** The vault cache is built at login/unlock time when the password hash is available for HMAC computation. Background syncs detect vault hash changes but cannot re-sign the cache without the password hash (which is zeroed after unlock). The cache reflects the vault state at last unlock + first sync. A future enhancement could persist a cache-signing key in memory.
- **TPM 2.0 support deferred.** The spec describes optional TPM sealing for headless Linux. This is not implemented in v1 — headless Linux without Secret Service falls back to no-CEK mode. The `tss-esapi` dependency and runtime detection can be added without architecture changes.

**Additional mitigations discovered during implementation:**

- **SDK client recreation on cache unlock failure.** If cache-first unlock fails (e.g., corrupted cache, wrong password), the SDK client is recreated before falling through to online bootstrap. This prevents a failed `initialize_user_crypto()` from leaving the SDK in a bad state.
- **3-second timeout on post-cache token refresh.** After cache-first unlock, a best-effort token refresh is attempted with a 3-second timeout. This avoids blocking unlock when offline while still acquiring an access token for background sync when online.

**Attack vector test coverage:**

- Vector 1 (offline brute-force): `seal_open_wrong_cek_fails` — wrong CEK fails AEAD decryption
- Vector 5 (cache tampering): `vault_cache_tamper_detection` — field modification detected by HMAC
- Vector 7 (KDF downgrade): `kdf_floor_validation` — weak KDF params rejected
- Vector 8 (vault hash oracle): `vault_hash_deterministic`, `vault_hash_changes_on_different_data` — hash behavior verified
- HMAC correctness: `vault_cache_hmac_roundtrip` — correct password verifies, wrong password rejects
- CEK encryption: `seal_open_roundtrip_with_cek`, `seal_open_roundtrip_no_cek` — both paths work
- File format: `envelope_serialization_roundtrip` — binary format parse/serialize roundtrip

**Post-review hardening (security review findings):**

- **H1/H2: Secret zeroization.** `UnlockCacheData.password_hash` wrapped in `Zeroizing<String>`. HMAC derivation key wrapped in `Zeroizing<[u8; 32]>`. CEK from `KeyStore::load_cek()` and `generate_cek()` wrapped in `Zeroizing<[u8; 32]>`. All cleared on drop.
- **M1: Max body size.** Cache body limited to 256 MiB (`MAX_BODY_SIZE`). Prevents OOM from crafted `body_len` in malformed cache files.
- **M2: Upgrade warning.** When an unencrypted cache is read but a credential store is now available, a warning is logged advising re-login to encrypt with CEK.
- **M3: Debug redaction.** Manual `Debug` impl on `VaultCache` redacts `encrypted_user_key`, `encrypted_private_key`, `integrity_hmac`, and `ciphers` to prevent accidental logging of brute-force target material.
- **M4: Fixed-length HMAC comparison.** `constant_time_eq_hmac` asserts both inputs are exactly 64 bytes (HMAC-SHA256 hex), eliminating the length-based timing leak.
- **M5: Vault hash error handling.** `compute_vault_hash` logs and hashes error messages on serialization failure instead of silently producing a constant hash.
- **L3: deny_unknown_fields.** Added `#[serde(deny_unknown_fields)]` on `VaultCache` and `CachedKdf` for defense-in-depth against deserialization of unexpected fields.

**Residual risk from implementation:**

- Without macOS biometric gate, same-user malware on macOS can silently read the CEK from Keychain. This matches the existing same-user trust boundary (malware can also read process memory).
- Background sync cannot update the cache — staleness window is unlock-to-unlock rather than sync-to-sync. Mitigated by the token refresh ensuring sync works immediately after cache unlock.
- Cache file write is not atomic (write-to-temp + rename). Consistent with existing `persist.rs` pattern. A crash during write could leave a truncated file, which is detected by the magic/length checks on next read.
