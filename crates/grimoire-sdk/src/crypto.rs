// Crypto-related utilities that wrap bitwarden-crypto.
//
// For now this is a placeholder. The main crypto operations (key derivation,
// unlock) are handled through the auth module which delegates to the SDK's
// PasswordManagerClient.crypto() sub-client.
//
// This module will hold any additional crypto helpers we need beyond what
// the SDK provides directly.
