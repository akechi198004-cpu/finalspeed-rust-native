//! Packet 数据结构定义模块。
//! 定义 Packet Header 以及支持的 Packet 类型，对应 `docs/protocol.md`。

use crate::error::{FSpeedError, Result};
use crate::session::ConnectionId;
use bytes::Bytes;

/// 固定的 Magic 字节，对应 ASCII "FS"。
pub const MAGIC_BYTES: u16 = 0x4653; // "FS"
/// 协议版本号。
pub const VERSION: u8 = 1;
/// Header 固定长度。
/// 包含: magic(2) + ver(1) + type(1) + flags(2) + conn(4) + seq(4) + ack(4) + window(2) + len(2) = 22 bytes。
pub const HEADER_LEN: usize = 22;

/// 表示 payload 是否已被加密的标志。
pub const FLAG_ENCRYPTED: u16 = 0x0001;

/// 定义支持的数据包类型。
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// 开启连接，携带加密的目标地址和时间戳。
    OpenConnection = 1,
    /// 传输 TCP 数据片段，payload 已加密。
    Data = 2,
    /// 累计确认包，确认已收到的序列号。
    Ack = 3,
    /// 关闭会话包。
    Close = 4,
    /// 错误包，携带失败原因。
    Error = 5,
    /// 保持活跃包，更新 `last_activity` 以避免连接被意外关闭。
    KeepAlive = 6,
}

impl TryFrom<u8> for PacketType {
    type Error = FSpeedError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(PacketType::OpenConnection),
            2 => Ok(PacketType::Data),
            3 => Ok(PacketType::Ack),
            4 => Ok(PacketType::Close),
            5 => Ok(PacketType::Error),
            6 => Ok(PacketType::KeepAlive),
            _ => Err(FSpeedError::InvalidPacketType),
        }
    }
}

/// 数据包头部。
/// 所有字段按 big-endian 顺序在网络中传输，并且除 `payload_len` 外，均作为 AEAD 的 AAD（附加认证数据）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub magic: u16,
    pub version: u8,
    pub packet_type: PacketType,
    pub flags: u16,
    pub connection_id: ConnectionId,
    /// 发送的序列号，Data 数据包从 1 开始计数。
    pub sequence: u32,
    /// 累计确认（ACK）的序列号。
    pub ack: u32,
    /// 接收窗口大小，当前通常在 Data packet 发送 `0` 或固定值。
    pub window: u16,
    /// 后续 payload 的字节数，由于加密会改变长度，因此该字段不计入 AAD。
    pub payload_len: u16,
}

/// 完整的协议数据包。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub header: Header,
    /// 实际的有效载荷，当前实现中通常是 ChaCha20-Poly1305 加密后的数据。
    pub payload: Bytes,
}

impl Packet {
    /// 构造一个新的数据包，并自动根据 payload 长度设置 `payload_len` 字段。
    pub fn try_new(
        packet_type: PacketType,
        flags: u16,
        connection_id: ConnectionId,
        sequence: u32,
        ack: u32,
        window: u16,
        payload: Bytes,
    ) -> Result<Self> {
        if payload.len() > u16::MAX as usize {
            return Err(FSpeedError::PayloadTooLarge);
        }

        Ok(Self {
            header: Header {
                magic: MAGIC_BYTES,
                version: VERSION,
                packet_type,
                flags,
                connection_id,
                sequence,
                ack,
                window,
                payload_len: payload.len() as u16,
            },
            payload,
        })
    }
}
