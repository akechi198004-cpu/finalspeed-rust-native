use crate::error::{FSpeedError, Result};
use crate::session::ConnectionId;
use bytes::Bytes;

pub const MAGIC_BYTES: u16 = 0x4653; // "FS"
pub const VERSION: u8 = 1;
// magic(2) + ver(1) + type(1) + flags(2) + conn(4) + seq(4) + ack(4) + window(2) + len(2)
pub const HEADER_LEN: usize = 22;

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    OpenConnection = 1,
    Data = 2,
    Ack = 3,
    Close = 4,
    Error = 5,
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
            _ => Err(FSpeedError::InvalidPacketType),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub magic: u16,
    pub version: u8,
    pub packet_type: PacketType,
    pub flags: u16,
    pub connection_id: ConnectionId,
    pub sequence: u32,
    pub ack: u32,
    pub window: u16,
    pub payload_len: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub header: Header,
    pub payload: Bytes,
}

impl Packet {
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
