//! 加密模块。
//! 使用 HKDF-SHA256 派生密钥，并使用 ChaCha20-Poly1305 AEAD 加密/解密 payload。

use crate::app::error::{FSpeedError, Result};
use crate::protocol::packet::Header;
use bytes::{BufMut, Bytes, BytesMut};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload as AeadPayload},
};
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

/// ChaCha20-Poly1305 使用 12 字节 Nonce。
pub const NONCE_LEN: usize = 12;

/// 使用 HKDF-SHA256 从 CLI 的 shared secret 派生 32 字节的 AEAD 密钥。
///
/// `Salt` 固定为 `fspeed-rs-v1`。
/// `Info` 固定为 `fspeed-rs tunnel aead v1`。
pub fn derive_key(secret: &str) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(b"fspeed-rs-v1"), secret.as_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(b"fspeed-rs tunnel aead v1", &mut key)
        .expect("HKDF expand failed");
    key
}

/// 从 Packet Header 构建 AAD (附加认证数据)。
/// 包含 magic, version, packet_type, flags, connection_id, sequence, ack, window。
/// 为了保持处理简单，因为加密会增加 Payload 长度，`payload_len` 不纳入 AAD 计算。
pub fn build_aad(header: &Header) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(20);
    buf.put_u16(header.magic);
    buf.put_u8(header.version);
    buf.put_u8(header.packet_type.clone() as u8);
    buf.put_u16(header.flags);
    buf.put_u32(header.connection_id.0);
    buf.put_u32(header.sequence);
    buf.put_u32(header.ack);
    buf.put_u16(header.window);
    buf.to_vec()
}

/// Encrypts the payload using ChaCha20-Poly1305.
/// Returns: nonce (12 bytes) || ciphertext_and_tag
/// 对有效载荷进行加密。
/// 采用 ChaCha20-Poly1305 算法。生成的随机 Nonce 会直接附加在密文前端。
/// 返回的格式为：`[nonce(12 bytes)] || [ciphertext_and_tag]`。
pub fn encrypt_payload(plaintext: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Bytes> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aead_payload = AeadPayload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, aead_payload)
        .map_err(|_| FSpeedError::CryptoError)?;

    let mut result = BytesMut::with_capacity(NONCE_LEN + ciphertext.len());
    result.put_slice(&nonce_bytes);
    result.put_slice(&ciphertext);

    Ok(result.freeze())
}

/// Decrypts the payload using ChaCha20-Poly1305.
/// Expects encrypted_payload: nonce (12 bytes) || ciphertext_and_tag
/// 对有效载荷进行解密。
/// 输入必须是 `[nonce(12 bytes)] || [ciphertext_and_tag]` 格式。
/// 如果完整性校验失败或长度不够，则返回错误。
pub fn decrypt_payload(encrypted_payload: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Bytes> {
    if encrypted_payload.len() < NONCE_LEN {
        return Err(FSpeedError::EncryptedPayloadTooShort);
    }

    let nonce = Nonce::from_slice(&encrypted_payload[..NONCE_LEN]);
    let ciphertext = &encrypted_payload[NONCE_LEN..];

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    let aead_payload = AeadPayload {
        msg: ciphertext,
        aad,
    };

    let plaintext = cipher
        .decrypt(nonce, aead_payload)
        .map_err(|_| FSpeedError::DecryptFailed)?;

    Ok(Bytes::from(plaintext))
}

/// 获取当前的 Unix 时间戳（毫秒）。
pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Validates that the given timestamp is within ±300 seconds (300,000 ms) of the current time.
/// 校验时间戳是否在允许的偏差窗口内（当前硬编码为前后 300 秒）。
/// 用于 OpenConnection 防止重放攻击的初步防护。
pub fn validate_timestamp_ms(timestamp_ms: u64) -> Result<()> {
    let current = current_timestamp_ms();
    let diff = current.abs_diff(timestamp_ms);

    if diff > 300_000 {
        return Err(FSpeedError::TimestampExpired);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::packet::PacketType;
    use crate::tunnel::session::ConnectionId;

    fn dummy_header() -> Header {
        Header {
            magic: crate::protocol::packet::MAGIC_BYTES,
            version: crate::protocol::packet::VERSION,
            packet_type: PacketType::Data,
            flags: 0x0001,
            connection_id: ConnectionId(1),
            sequence: 42,
            ack: 10,
            window: 1024,
            payload_len: 0, // Ignored in AAD
        }
    }

    #[test]
    fn test_derive_key_deterministic() {
        let key1 = derive_key("test123_secret");
        let key2 = derive_key("test123_secret");
        assert_eq!(key1, key2);

        let key3 = derive_key("different_secret");
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_encrypt_decrypt_success() {
        let key = derive_key("test123_secret");
        let header = dummy_header();
        let aad = build_aad(&header);
        let plaintext = b"hello fspeed data";

        let encrypted = encrypt_payload(plaintext, &key, &aad).unwrap();
        assert_ne!(encrypted.as_ref(), plaintext);
        assert!(encrypted.len() >= NONCE_LEN + plaintext.len());

        let decrypted = decrypt_payload(&encrypted, &key, &aad).unwrap();
        assert_eq!(decrypted.as_ref(), plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1 = derive_key("test123_secret");
        let key2 = derive_key("wrong_secret");
        let header = dummy_header();
        let aad = build_aad(&header);
        let plaintext = b"hello";

        let encrypted = encrypt_payload(plaintext, &key1, &aad).unwrap();
        let result = decrypt_payload(&encrypted, &key2, &aad);
        assert!(matches!(result, Err(FSpeedError::DecryptFailed)));
    }

    #[test]
    fn test_decrypt_wrong_aad() {
        let key = derive_key("test123_secret");
        let header1 = dummy_header();
        let mut header2 = dummy_header();
        header2.sequence = 99; // Different sequence

        let aad1 = build_aad(&header1);
        let aad2 = build_aad(&header2);
        let plaintext = b"hello";

        let encrypted = encrypt_payload(plaintext, &key, &aad1).unwrap();
        let result = decrypt_payload(&encrypted, &key, &aad2);
        assert!(matches!(result, Err(FSpeedError::DecryptFailed)));
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let key = derive_key("test123_secret");
        let header = dummy_header();
        let aad = build_aad(&header);
        let plaintext = b"hello";

        let mut encrypted = encrypt_payload(plaintext, &key, &aad).unwrap().to_vec();

        // Tamper with ciphertext
        let len = encrypted.len();
        encrypted[len - 1] ^= 0x01;

        let result = decrypt_payload(&encrypted, &key, &aad);
        assert!(matches!(result, Err(FSpeedError::DecryptFailed)));
    }

    #[test]
    fn test_decrypt_payload_too_short() {
        let key = derive_key("test123_secret");
        let header = dummy_header();
        let aad = build_aad(&header);

        let too_short = vec![0u8; NONCE_LEN - 1];
        let result = decrypt_payload(&too_short, &key, &aad);
        assert!(matches!(result, Err(FSpeedError::EncryptedPayloadTooShort)));
    }

    #[test]
    fn test_timestamp_validation() {
        let now = current_timestamp_ms();
        assert!(validate_timestamp_ms(now).is_ok());

        let old = now - 301_000;
        assert!(matches!(
            validate_timestamp_ms(old),
            Err(FSpeedError::TimestampExpired)
        ));

        let future = now + 301_000;
        assert!(matches!(
            validate_timestamp_ms(future),
            Err(FSpeedError::TimestampExpired)
        ));
    }
}
