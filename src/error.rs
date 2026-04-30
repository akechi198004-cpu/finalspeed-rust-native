use thiserror::Error;

#[derive(Debug, Error)]
pub enum FSpeedError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Packet decode error: {0}")]
    Decode(String),

    #[error("Invalid magic number")]
    InvalidMagic,

    #[error("Invalid protocol version")]
    InvalidVersion,

    #[error("Invalid packet type")]
    InvalidPacketType,

    #[error("Truncated packet")]
    TruncatedPacket,

    #[error("Payload length mismatch: expected exact match, found extra/trailing bytes")]
    PayloadLengthMismatch,

    #[error("Payload too large: exceeds maximum allowed size for u16")]
    PayloadTooLarge,

    #[error("Invalid payload format")]
    InvalidPayloadFormat,

    #[error("Missing secret in payload")]
    MissingSecret,

    #[error("Missing target in payload")]
    MissingTarget,

    #[error("Unknown key in payload: {0}")]
    UnknownKey(String),

    #[error("Duplicate key in payload: {0}")]
    DuplicateKey(String),

    #[error("Invalid target address: {0}")]
    InvalidTargetAddr(String),

    #[error("Crypto error: failed to encrypt/decrypt payload")]
    CryptoError,

    #[error("Decryption failed: authentication tag mismatch or malformed ciphertext")]
    DecryptFailed,

    #[error("Encrypted payload is too short to contain a nonce")]
    EncryptedPayloadTooShort,

    #[error("Missing FLAG_ENCRYPTED on payload requiring encryption")]
    MissingEncryptedFlag,

    #[error("Timestamp expired or drifted too far")]
    TimestampExpired,

    #[error("Invalid timestamp format")]
    InvalidTimestamp,
}

pub type Result<T> = std::result::Result<T, FSpeedError>;
