//! 错误定义模块。
//! 包含 FSpeedError 枚举，定义了各类协议、加密及网络 IO 的错误类型。

use thiserror::Error;

/// 核心错误枚举。
#[derive(Debug, Error)]
pub enum FSpeedError {
    /// 包装 std::io::Error。
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// 数据包解码错误（包括截断等）。
    #[error("Packet decode error: {0}")]
    Decode(String),

    /// 数据包 Magic 标识不合法。
    #[error("Invalid magic number")]
    InvalidMagic,

    /// 协议版本不匹配。
    #[error("Invalid protocol version")]
    InvalidVersion,

    /// 遇到不支持的 Packet Type。
    #[error("Invalid packet type")]
    InvalidPacketType,

    /// 接收到的数据包不完整。
    #[error("Truncated packet")]
    TruncatedPacket,

    /// Payload 长度不一致（包含 trailing bytes 等情况）。
    #[error("Payload length mismatch: expected exact match, found extra/trailing bytes")]
    PayloadLengthMismatch,

    /// Payload 长度超出了最大允许值。
    #[error("Payload too large: exceeds maximum allowed size for u16")]
    PayloadTooLarge,

    /// 明文 Payload 格式（通常是 `key=value`）解析错误。
    #[error("Invalid payload format")]
    InvalidPayloadFormat,

    /// （保留/历史）缺少 secret。
    #[error("Missing secret in payload")]
    MissingSecret,

    /// OpenConnection 的 payload 缺少 target 字段。
    #[error("Missing target in payload")]
    MissingTarget,

    /// Payload 中存在未知的 `key`。
    #[error("Unknown key in payload: {0}")]
    UnknownKey(String),

    /// Payload 中存在重复的 `key`。
    #[error("Duplicate key in payload: {0}")]
    DuplicateKey(String),

    /// 非法的目标地址（无法解析为 `SocketAddr`，或者域名格式错误等）。
    #[error("Invalid target address: {0}")]
    InvalidTargetAddr(String),

    /// 底层加密/解密失败的通用错误。
    #[error("Crypto error: failed to encrypt/decrypt payload")]
    CryptoError,

    /// 解密失败：标签不匹配或密文损坏。
    #[error("Decryption failed: authentication tag mismatch or malformed ciphertext")]
    DecryptFailed,

    /// 加密 payload 长度太短，不包含有效的 12 字节 nonce。
    #[error("Encrypted payload is too short to contain a nonce")]
    EncryptedPayloadTooShort,

    /// 需要加密的 Packet 缺少 `FLAG_ENCRYPTED` 标志。
    #[error("Missing FLAG_ENCRYPTED on payload requiring encryption")]
    MissingEncryptedFlag,

    /// 时间戳校验失败（通常为防重放时间窗校验不通过）。
    #[error("Timestamp expired or drifted too far")]
    TimestampExpired,

    /// 时间戳格式非法。
    #[error("Invalid timestamp format")]
    InvalidTimestamp,
}

/// 通用 Result 类型。
pub type Result<T> = std::result::Result<T, FSpeedError>;
