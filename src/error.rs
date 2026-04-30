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
}

pub type Result<T> = std::result::Result<T, FSpeedError>;
