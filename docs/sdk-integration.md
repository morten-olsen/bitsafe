# SDK Integration

How Grimoire consumes `bitwarden/sdk-internal` and why.

## What the SDK Is and Isn't Used For

After extensive investigation of the [official Bitwarden CLI](https://github.com/bitwarden/clients/tree/web-v2026.3.0/apps/cli), we discovered that **the official clients do not use the SDK for HTTP operations**. The SDK is only used for crypto — key derivation, vault encryption/decryption. All HTTP calls (prelogin, login, sync, token refresh) are done by the clients' own `ApiService` layer.

We follow the same pattern.

### What the SDK does for us

| Operation | SDK API |
|-----------|---------|
| Key derivation | `MasterPasswordAuthenticationData::derive()` |
| Crypto initialization | `CryptoClient::initialize_user_crypto()` |
| Cipher decryption | `VaultClient::ciphers().list()`, `.get()` |
| TOTP generation | `VaultClient::totp().generate_totp()` |
| Key store management | Internal `KeyStore` with `ZeroizingAllocator` |

### What we do ourselves

| Operation | Implementation |
|-----------|---------------|
| Prelogin (get KDF params) | HTTP POST to `/identity/accounts/prelogin` |
| Login (get tokens) | HTTP POST to `/identity/connect/token` (form-encoded) |
| Sync (get vault data) | HTTP GET to `/api/sync` with Bearer token |
| Token storage | Our `TokenStore` implementing `ClientManagedTokens` trait |
| Cipher repository population | Parse sync JSON, convert to SDK `Cipher` type, store in repository |

## Why Not Use the SDK's Built-in Login/Sync?

We tried three approaches before settling on the current one:

### Attempt 1: SDK's `LoginClient` + `PasswordPreloginResponse`
- The SDK's `LoginClient` (from `bitwarden-auth`) lets you supply your own prelogin response
- **Problem**: The SDK's login response parser (`LoginErrorApiResponse`) is an untagged enum that can't deserialize Vaultwarden's error format (`{"error":"","message":"..."}` vs the expected `{"error":"invalid_grant","error_description":"..."}`)
- **Problem**: Token management — `LoginClient` is separate from the main `PasswordManagerClient`. Tokens from login don't transfer to the main client.

### Attempt 2: Core client's `login_password()`
- The core `Client` has `auth().login_password()` which does prelogin + login + set_tokens + init_crypto in one call
- **Problem**: It calls `prelogin()` internally, which uses the SDK's generated API bindings that hit `/accounts/prelogin/password` — a new endpoint that Vaultwarden doesn't support (404). The old endpoint is `/accounts/prelogin`.
- This path has been in the SDK since December 2025 (`0d52f617`). It's not a recent change.

### Attempt 3: SDK's `SyncClient::sync()`
- The SDK's sync client calls `/sync` through generated API bindings
- **Problem**: `SyncResponseModel` deserialization fails on Vaultwarden responses ("invalid type: map, expected a string at line 1 column 115") — field type mismatch between what Vaultwarden returns and what the SDK expects.

### Current approach: Own HTTP calls + SDK crypto
- Matches how the official Bitwarden CLI works
- No dependency on the SDK's generated API bindings for HTTP
- Uses the SDK only for crypto operations where it's battle-tested
- Full compatibility with Vaultwarden without workarounds

## SDK API Surface We Actually Use

From `bitwarden-core`:
- `ClientSettings` — server URL configuration (used for SDK's internal `identity_url`/`api_url` even though we don't use them for HTTP)
- `MasterPasswordAuthenticationData::derive(password, kdf, email)` — derives the master key hash sent to the server
- `CryptoClient::initialize_user_crypto(InitUserCryptoRequest)` — initializes the key store with decrypted vault keys
- `InitUserCryptoMethod::MasterPasswordUnlock` — unlock method using master password + encrypted user key
- `WrappedAccountCryptographicState::V1 { private_key }` — encrypted private key from login response
- `MasterPasswordUnlockData { kdf, master_key_wrapped_user_key, salt }` — KDF config + encrypted user key
- `ClientManagedTokens` trait — we implement this to provide the access token to the SDK
- `PasswordManagerClient::new_with_client_tokens(settings, token_store)` — creates client with our token store

From `bitwarden-vault`:
- `VaultClient::ciphers().list()` → `DecryptCipherListResult` — decrypts all ciphers from repository
- `VaultClient::ciphers().get(id)` → `CipherView` — decrypts a single cipher
- `VaultClient::totp().generate_totp(key, time)` — generates TOTP codes
- `Cipher`, `CipherId`, `CipherView`, `CipherListView`, `CipherListViewType` — vault types
- `FolderSyncHandler` — we register this to handle folder population on sync

From `bitwarden-state`:
- `Repository<T>` trait — we implement in-memory repositories for state types
- `DatabaseConfiguration::Sqlite` — for initializing the SDK's state database

## Token Flow

```
Login:
  1. POST /identity/connect/token → access_token
  2. Store in TokenStore (Arc<RwLock<Option<String>>>)
  3. SDK reads via ClientManagedTokens::get_access_token()
     (used if SDK ever makes internal API calls)

Sync/Vault:
  4. We read from TokenStore for our own HTTP calls
  5. SDK decrypts using keys initialized in step (crypto init)
```

## Client-Managed Repositories

The SDK expects the consuming application to provide repositories for certain state types. We register in-memory `HashMap`-backed implementations for:

- `Cipher` — encrypted cipher objects populated by our sync
- `Folder` — encrypted folder objects populated by SDK's `FolderSyncHandler`
- `LocalUserDataKeyState` — local user data key (wrapped by user key)
- `UserKeyState` — decrypted user key state
- `EphemeralPinEnvelopeState` — PIN envelope for ephemeral PIN unlock

## Server URL Convention

For Vaultwarden (and self-hosted Bitwarden):
- Base URL: `https://vault.example.com`
- Identity: `{base}/identity` (prelogin at `/identity/accounts/prelogin`, tokens at `/identity/connect/token`)
- API: `{base}/api` (sync at `/api/sync`)

Official Bitwarden cloud uses separate subdomains (`identity.bitwarden.com`, `api.bitwarden.com`) but the path structure is the same.
