use crate::error::SdkError;
use bitwarden_pm::PasswordManagerClient;
use std::sync::Arc;
use tokio::sync::Mutex;
use zeroize::Zeroize;

/// Summary of an SSH key stored in the vault.
pub struct SshKeyInfo {
    pub id: String,
    pub name: String,
    /// Public key in OpenSSH authorized_keys format
    pub public_key: String,
    pub fingerprint: String,
}

pub struct SshClient {
    pub(crate) client: Arc<Mutex<PasswordManagerClient>>,
}

impl SshClient {
    /// List SSH keys stored in the vault.
    pub async fn list_keys(&self) -> Result<Vec<SshKeyInfo>, SdkError> {
        let pm = self.client.lock().await;

        let result = pm
            .vault()
            .ciphers()
            .get_all()
            .await
            .map_err(|e| SdkError::Internal(format!("Failed to list ciphers: {e}")))?;

        let keys: Vec<SshKeyInfo> = result
            .successes
            .into_iter()
            .filter(|c| c.r#type == bitwarden_vault::CipherType::SshKey)
            .filter_map(|c| {
                let ssh = c.ssh_key.as_ref()?;
                Some(SshKeyInfo {
                    id: c.id.map(|id| id.to_string()).unwrap_or_default(),
                    name: c.name.clone(),
                    public_key: ssh.public_key.clone(),
                    fingerprint: ssh.fingerprint.clone(),
                })
            })
            .collect();

        Ok(keys)
    }

    /// Sign data with an SSH key from the vault.
    pub async fn sign(&self, key_id: &str, data: &[u8], flags: u32) -> Result<Vec<u8>, SdkError> {
        let pm = self.client.lock().await;

        let view = pm
            .vault()
            .ciphers()
            .get(key_id)
            .await
            .map_err(|e| SdkError::NotFound(format!("SSH key not found: {e}")))?;

        let ssh_key_view = view
            .ssh_key
            .as_ref()
            .ok_or_else(|| SdkError::Internal("Cipher is not an SSH key".into()))?;

        let private_key = ssh_key::PrivateKey::from_openssh(&ssh_key_view.private_key)
            .map_err(|e| SdkError::Internal(format!("Failed to parse SSH private key: {e}")))?;

        // Sign then immediately drop the parsed key. The Ed25519/RSA signing keys
        // inside sign_with_key are zeroized explicitly. ssh_key::PrivateKey does not
        // implement Zeroize, so we drop it and rely on the SDK's ZeroizingAllocator
        // for the underlying allocation.
        sign_with_key(&private_key, data, flags)
    }
}

/// Sign data with a parsed SSH private key, returning the signature in SSH wire format.
///
/// SSH agent protocol flag constants
const _SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;

/// SSH wire format: u32_be(algo_len) + algo_name + u32_be(sig_len) + sig_bytes
fn sign_with_key(key: &ssh_key::PrivateKey, data: &[u8], flags: u32) -> Result<Vec<u8>, SdkError> {
    use ssh_key::private::KeypairData;

    match key.key_data() {
        KeypairData::Ed25519(kp) => {
            use ed25519_dalek::{Signer, SigningKey};
            let mut key_bytes = kp.private.to_bytes();
            let signing_key = SigningKey::from_bytes(&key_bytes);
            let sig = signing_key.sign(data);
            // Zeroize the raw key bytes we extracted. The SigningKey itself
            // doesn't implement Zeroize, but we ensure the extracted copy is wiped.
            key_bytes.zeroize();
            Ok(encode_ssh_signature(b"ssh-ed25519", &sig.to_bytes()))
        }
        KeypairData::Rsa(kp) => {
            use rsa::pkcs1v15::SigningKey as RsaSigningKey;
            use rsa::signature::SignatureEncoding;
            use rsa::signature::Signer;
            use rsa::BigUint;

            // Construct rsa::RsaPrivateKey from ssh-key's components
            let n = BigUint::from_bytes_be(kp.public().n().as_bytes());
            let e = BigUint::from_bytes_be(kp.public().e().as_bytes());
            let d = BigUint::from_bytes_be(kp.private().d().as_bytes());
            let p = BigUint::from_bytes_be(kp.private().p().as_bytes());
            let q = BigUint::from_bytes_be(kp.private().q().as_bytes());

            let private_key = rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q])
                .map_err(|e| SdkError::Internal(format!("RSA key error: {e}")))?;

            // RsaSigningKey takes ownership — it implements Drop which zeroizes
            // the inner RsaPrivateKey when the signing key goes out of scope.
            if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                let signing_key = RsaSigningKey::<sha2::Sha512>::new(private_key);
                let sig = signing_key.sign(data);
                Ok(encode_ssh_signature(b"rsa-sha2-512", &sig.to_bytes()))
            } else {
                // Default to SHA-256 (rsa-sha2-256) — modern SSH standard
                let signing_key = RsaSigningKey::<sha2::Sha256>::new(private_key);
                let sig = signing_key.sign(data);
                Ok(encode_ssh_signature(b"rsa-sha2-256", &sig.to_bytes()))
            }
        }
        other => Err(SdkError::Internal(format!(
            "Unsupported SSH key type for signing: {other:?}"
        ))),
    }
}

/// Encode a signature in SSH wire format: string algorithm + string signature_blob
fn encode_ssh_signature(algorithm: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + algorithm.len() + 4 + signature.len());
    buf.extend_from_slice(&(algorithm.len() as u32).to_be_bytes());
    buf.extend_from_slice(algorithm);
    buf.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    buf.extend_from_slice(signature);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_ssh_signature_ed25519() {
        let sig = encode_ssh_signature(b"ssh-ed25519", &[0xAA; 64]);
        // 4 + 11 + 4 + 64 = 83 bytes
        assert_eq!(sig.len(), 83);

        // Parse it back
        let algo_len = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]) as usize;
        assert_eq!(algo_len, 11);
        assert_eq!(&sig[4..15], b"ssh-ed25519");

        let sig_len = u32::from_be_bytes([sig[15], sig[16], sig[17], sig[18]]) as usize;
        assert_eq!(sig_len, 64);
        assert_eq!(&sig[19..], &[0xAA; 64]);
    }

    #[test]
    fn encode_ssh_signature_rsa() {
        let sig = encode_ssh_signature(b"rsa-sha2-256", &[0xBB; 256]);
        let algo_len = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]) as usize;
        assert_eq!(algo_len, 12);
        assert_eq!(&sig[4..16], b"rsa-sha2-256");

        let sig_offset = 4 + algo_len;
        let sig_len = u32::from_be_bytes([
            sig[sig_offset],
            sig[sig_offset + 1],
            sig[sig_offset + 2],
            sig[sig_offset + 3],
        ]) as usize;
        assert_eq!(sig_len, 256);
    }

    #[test]
    fn encode_ssh_signature_empty() {
        let sig = encode_ssh_signature(b"", &[]);
        assert_eq!(sig.len(), 8); // 4 + 0 + 4 + 0
        let algo_len = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]);
        assert_eq!(algo_len, 0);
    }

    #[test]
    fn encode_ssh_signature_roundtrip_parseable() {
        let algo = b"ssh-ed25519";
        let raw_sig = [0x42; 64];
        let encoded = encode_ssh_signature(algo, &raw_sig);

        // Parse back using the same logic as ssh_agent.rs
        let alen = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;
        let parsed_algo = std::str::from_utf8(&encoded[4..4 + alen]).unwrap();
        assert_eq!(parsed_algo, "ssh-ed25519");

        let soff = 4 + alen;
        let slen = u32::from_be_bytes([
            encoded[soff],
            encoded[soff + 1],
            encoded[soff + 2],
            encoded[soff + 3],
        ]) as usize;
        let parsed_sig = &encoded[soff + 4..soff + 4 + slen];
        assert_eq!(parsed_sig, &raw_sig);
    }
}
