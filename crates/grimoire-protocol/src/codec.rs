use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Message too large: {0} bytes (max {MAX_MESSAGE_SIZE})")]
    TooLarge(u32),
    #[error("Connection closed")]
    ConnectionClosed,
    #[error("Crypto error: {0}")]
    Crypto(String),
}

/// Maximum message size: 16 MiB (generous for vault payloads).
const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

/// Codec trait for message framing. Allows swapping in encrypted codecs later.
pub trait Codec: Send + Sync {
    fn encode<T: Serialize>(&self, msg: &T) -> Result<Vec<u8>, CodecError>;
    fn decode<T: DeserializeOwned>(&self, bytes: &[u8]) -> Result<T, CodecError>;
}

/// Length-prefixed JSON codec (no encryption).
#[derive(Debug, Clone, Default)]
pub struct PlainCodec;

impl Codec for PlainCodec {
    fn encode<T: Serialize>(&self, msg: &T) -> Result<Vec<u8>, CodecError> {
        let json = serde_json::to_vec(msg)?;
        let len = json.len() as u32;
        let mut buf = Vec::with_capacity(4 + json.len());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&json);
        Ok(buf)
    }

    fn decode<T: DeserializeOwned>(&self, bytes: &[u8]) -> Result<T, CodecError> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

/// Encrypted codec using ChaCha20-Poly1305 AEAD.
///
/// Wire format per message: `[4-byte length][8-byte nonce counter][ciphertext + 16-byte tag]`
///
/// The length prefix covers `nonce_counter + ciphertext + tag`. The 12-byte AEAD nonce
/// is constructed as `[0u8; 4] ++ [counter as u64 LE]`, ensuring uniqueness as long as
/// the counter doesn't wrap (2^64 messages per direction per connection).
pub struct EncryptedCodec {
    cipher: chacha20poly1305::ChaCha20Poly1305,
    send_counter: std::sync::atomic::AtomicU64,
}

impl EncryptedCodec {
    /// Create a new encrypted codec from a 32-byte shared secret.
    pub fn new(shared_secret: [u8; 32]) -> Self {
        use chacha20poly1305::KeyInit;
        Self {
            cipher: chacha20poly1305::ChaCha20Poly1305::new(
                chacha20poly1305::Key::from_slice(&shared_secret),
            ),
            send_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn next_nonce(&self) -> chacha20poly1305::Nonce {
        let counter = self
            .send_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&counter.to_le_bytes());
        *chacha20poly1305::Nonce::from_slice(&nonce_bytes)
    }

    fn nonce_from_counter(counter: u64) -> chacha20poly1305::Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&counter.to_le_bytes());
        *chacha20poly1305::Nonce::from_slice(&nonce_bytes)
    }
}

impl Codec for EncryptedCodec {
    fn encode<T: Serialize>(&self, msg: &T) -> Result<Vec<u8>, CodecError> {
        use chacha20poly1305::aead::Aead;

        let plaintext = serde_json::to_vec(msg)?;
        let nonce = self.next_nonce();

        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| CodecError::Crypto(format!("Encrypt failed: {e}")))?;

        // Wire format: [length][8-byte counter][ciphertext (includes tag)]
        let counter_bytes = &nonce.as_slice()[4..]; // 8 bytes of counter
        let payload_len = (8 + ciphertext.len()) as u32;

        let mut buf = Vec::with_capacity(4 + 8 + ciphertext.len());
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(counter_bytes);
        buf.extend_from_slice(&ciphertext);
        Ok(buf)
    }

    fn decode<T: DeserializeOwned>(&self, bytes: &[u8]) -> Result<T, CodecError> {
        use chacha20poly1305::aead::Aead;

        if bytes.len() < 8 + 16 {
            return Err(CodecError::Crypto("Message too short for decryption".into()));
        }

        // Parse counter from first 8 bytes
        let counter = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let nonce = Self::nonce_from_counter(counter);

        let ciphertext = &bytes[8..];

        let plaintext = self
            .cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| CodecError::Crypto("Decryption failed — wrong key or tampered".into()))?;

        serde_json::from_slice(&plaintext).map_err(Into::into)
    }
}

/// Perform the client side of an X25519 key exchange.
///
/// 1. Generate ephemeral keypair
/// 2. Send our public key (32 bytes)
/// 3. Receive server's public key (32 bytes)
/// 4. Compute shared secret
/// 5. Return `EncryptedCodec` ready for use
pub async fn handshake_client<R, W>(
    reader: &mut R,
    writer: &mut W,
) -> Result<EncryptedCodec, CodecError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use x25519_dalek::{EphemeralSecret, PublicKey};

    let client_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let client_public = PublicKey::from(&client_secret);

    // Send our public key
    writer.write_all(client_public.as_bytes()).await?;
    writer.flush().await?;

    // Receive server's public key
    let mut server_pub_bytes = [0u8; 32];
    reader.read_exact(&mut server_pub_bytes).await?;
    let server_public = PublicKey::from(server_pub_bytes);

    // Derive shared secret
    let shared = client_secret.diffie_hellman(&server_public);

    Ok(EncryptedCodec::new(shared.to_bytes()))
}

/// Perform the server side of an X25519 key exchange.
///
/// 1. Receive client's public key (32 bytes)
/// 2. Generate ephemeral keypair
/// 3. Send our public key (32 bytes)
/// 4. Compute shared secret
/// 5. Return `EncryptedCodec` ready for use
pub async fn handshake_server<R, W>(
    reader: &mut R,
    writer: &mut W,
) -> Result<EncryptedCodec, CodecError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use x25519_dalek::{EphemeralSecret, PublicKey};

    // Receive client's public key
    let mut client_pub_bytes = [0u8; 32];
    match reader.read_exact(&mut client_pub_bytes).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(CodecError::ConnectionClosed);
        }
        Err(e) => return Err(CodecError::Io(e)),
    }
    let client_public = PublicKey::from(client_pub_bytes);

    let server_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let server_public = PublicKey::from(&server_secret);

    // Send our public key
    writer.write_all(server_public.as_bytes()).await?;
    writer.flush().await?;

    // Derive shared secret
    let shared = server_secret.diffie_hellman(&client_public);

    Ok(EncryptedCodec::new(shared.to_bytes()))
}

/// Write a length-prefixed message to an async writer.
pub async fn write_message<W, T>(writer: &mut W, codec: &impl Codec, msg: &T) -> Result<(), CodecError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let data = codec.encode(msg)?;
    writer.write_all(&data).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a length-prefixed message from an async reader.
pub async fn read_message<R, T>(reader: &mut R, codec: &impl Codec) -> Result<T, CodecError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(CodecError::ConnectionClosed);
        }
        Err(e) => return Err(CodecError::Io(e)),
    }

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MESSAGE_SIZE {
        return Err(CodecError::TooLarge(len));
    }

    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;

    codec.decode(&payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestMsg {
        text: String,
        num: i32,
    }

    #[test]
    fn plain_codec_encode_decode_roundtrip() {
        let codec = PlainCodec;
        let msg = TestMsg {
            text: "hello".into(),
            num: 42,
        };
        let encoded = codec.encode(&msg).unwrap();
        // First 4 bytes are the length prefix
        let len = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(len as usize, encoded.len() - 4);
        // Decode the payload (without length prefix)
        let decoded: TestMsg = codec.decode(&encoded[4..]).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn plain_codec_encode_length_prefix_is_big_endian() {
        let codec = PlainCodec;
        let msg = serde_json::json!({"a": 1});
        let encoded = codec.encode(&msg).unwrap();
        let expected_len = (encoded.len() - 4) as u32;
        let actual_len = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(actual_len, expected_len);
    }

    #[test]
    fn plain_codec_decode_invalid_json() {
        let codec = PlainCodec;
        let result = codec.decode::<TestMsg>(b"not json");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn write_read_message_roundtrip() {
        let codec = PlainCodec;
        let msg = TestMsg {
            text: "roundtrip".into(),
            num: 99,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &codec, &msg).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let decoded: TestMsg = read_message(&mut cursor, &codec).await.unwrap();
        assert_eq!(decoded, msg);
    }

    #[tokio::test]
    async fn read_message_too_large() {
        // Craft a length prefix that exceeds MAX_MESSAGE_SIZE
        let fake_len: u32 = MAX_MESSAGE_SIZE + 1;
        let mut buf = Vec::new();
        buf.extend_from_slice(&fake_len.to_be_bytes());
        buf.extend_from_slice(&[0u8; 10]); // dummy payload

        let mut cursor = std::io::Cursor::new(buf);
        let result = read_message::<_, serde_json::Value>(&mut cursor, &PlainCodec).await;
        assert!(matches!(result, Err(CodecError::TooLarge(_))));
    }

    #[tokio::test]
    async fn read_message_connection_closed() {
        let mut cursor = std::io::Cursor::new(Vec::new()); // empty = EOF
        let result = read_message::<_, serde_json::Value>(&mut cursor, &PlainCodec).await;
        assert!(matches!(result, Err(CodecError::ConnectionClosed)));
    }

    // --- Encrypted codec tests ---

    #[test]
    fn encrypted_codec_roundtrip() {
        let key = [42u8; 32];
        let codec = EncryptedCodec::new(key);
        let msg = TestMsg {
            text: "secret".into(),
            num: 7,
        };
        let encoded = codec.encode(&msg).unwrap();
        // Encoded should be longer than plain (nonce counter + tag overhead)
        assert!(encoded.len() > 4 + 8);
        // Decode: skip the 4-byte length prefix
        let decoded: TestMsg = codec.decode(&encoded[4..]).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn encrypted_codec_tamper_detection() {
        let key = [42u8; 32];
        let codec = EncryptedCodec::new(key);
        let msg = TestMsg {
            text: "tamper test".into(),
            num: 1,
        };
        let mut encoded = codec.encode(&msg).unwrap();
        // Flip a byte in the ciphertext (after length prefix + counter)
        if encoded.len() > 14 {
            encoded[14] ^= 0xff;
        }
        let result = codec.decode::<TestMsg>(&encoded[4..]);
        assert!(result.is_err());
    }

    #[test]
    fn encrypted_codec_wrong_key_fails() {
        let codec1 = EncryptedCodec::new([1u8; 32]);
        let codec2 = EncryptedCodec::new([2u8; 32]);
        let msg = TestMsg {
            text: "wrong key".into(),
            num: 0,
        };
        let encoded = codec1.encode(&msg).unwrap();
        let result = codec2.decode::<TestMsg>(&encoded[4..]);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn encrypted_write_read_roundtrip() {
        let key = [99u8; 32];
        let codec = EncryptedCodec::new(key);
        let msg = TestMsg {
            text: "encrypted roundtrip".into(),
            num: 42,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &codec, &msg).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let decoded: TestMsg = read_message(&mut cursor, &codec).await.unwrap();
        assert_eq!(decoded, msg);
    }

    #[tokio::test]
    async fn handshake_and_communicate() {
        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let (mut client_read, mut client_write) = tokio::io::split(client_stream);
        let (mut server_read, mut server_write) = tokio::io::split(server_stream);

        // Perform handshake concurrently
        let (client_codec, server_codec) = tokio::join!(
            handshake_client(&mut client_read, &mut client_write),
            handshake_server(&mut server_read, &mut server_write),
        );
        let client_codec = client_codec.unwrap();
        let server_codec = server_codec.unwrap();

        // Client sends, server receives
        let msg = TestMsg {
            text: "hello encrypted".into(),
            num: 123,
        };
        write_message(&mut client_write, &client_codec, &msg)
            .await
            .unwrap();
        let received: TestMsg = read_message(&mut server_read, &server_codec)
            .await
            .unwrap();
        assert_eq!(received, msg);

        // Server sends, client receives
        let reply = TestMsg {
            text: "reply".into(),
            num: 456,
        };
        write_message(&mut server_write, &server_codec, &reply)
            .await
            .unwrap();
        let received: TestMsg = read_message(&mut client_read, &client_codec)
            .await
            .unwrap();
        assert_eq!(received, reply);
    }
}
