use crate::error::{FSpeedError, Result};
use crate::packet::{HEADER_LEN, Header, MAGIC_BYTES, Packet, PacketType, VERSION};
use crate::session::ConnectionId;
use bytes::{Buf, BufMut, BytesMut};

pub fn encode_packet(packet: &Packet) -> Result<BytesMut> {
    if packet.header.payload_len as usize != packet.payload.len() {
        return Err(FSpeedError::PayloadLengthMismatch);
    }

    let mut buf = BytesMut::with_capacity(HEADER_LEN + packet.payload.len());

    // Write header (Big-Endian)
    buf.put_u16(packet.header.magic);
    buf.put_u8(packet.header.version);
    buf.put_u8(packet.header.packet_type.clone() as u8);
    buf.put_u16(packet.header.flags);
    buf.put_u32(packet.header.connection_id.0);
    buf.put_u32(packet.header.sequence);
    buf.put_u32(packet.header.ack);
    buf.put_u16(packet.header.window);
    buf.put_u16(packet.header.payload_len);

    // Write payload
    buf.put_slice(&packet.payload);

    Ok(buf)
}

pub fn decode_packet(buf: &mut BytesMut) -> Result<Option<Packet>> {
    if buf.len() < HEADER_LEN {
        // UDP datagram is too short to even contain the header.
        return Err(FSpeedError::TruncatedPacket);
    }

    // Peek the header without consuming the buffer
    let magic = u16::from_be_bytes(buf[0..2].try_into().unwrap());
    if magic != MAGIC_BYTES {
        return Err(FSpeedError::InvalidMagic);
    }

    let version = buf[2];
    if version != VERSION {
        return Err(FSpeedError::InvalidVersion);
    }

    let packet_type_raw = buf[3];
    let packet_type = PacketType::try_from(packet_type_raw)?;

    let flags = u16::from_be_bytes(buf[4..6].try_into().unwrap());
    let conn_id_raw = u32::from_be_bytes(buf[6..10].try_into().unwrap());
    let sequence = u32::from_be_bytes(buf[10..14].try_into().unwrap());
    let ack = u32::from_be_bytes(buf[14..18].try_into().unwrap());
    let window = u16::from_be_bytes(buf[18..20].try_into().unwrap());
    let payload_len = u16::from_be_bytes(buf[20..22].try_into().unwrap());

    let total_len = HEADER_LEN + payload_len as usize;

    if buf.len() < total_len {
        // Not enough data for the full payload, although this is UDP,
        // it means the UDP packet itself was truncated or malformed.
        return Err(FSpeedError::TruncatedPacket);
    }

    // Strict UDP parsing: reject trailing bytes
    if buf.len() > total_len {
        return Err(FSpeedError::PayloadLengthMismatch);
    }

    // We have exactly the full packet, consume it from the buffer
    buf.advance(HEADER_LEN);
    let payload = buf.split_to(payload_len as usize).freeze();

    let header = Header {
        magic,
        version,
        packet_type,
        flags,
        connection_id: ConnectionId(conn_id_raw),
        sequence,
        ack,
        window,
        payload_len,
    };

    Ok(Some(Packet { header, payload }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::FSpeedError;
    use crate::packet::{HEADER_LEN, MAGIC_BYTES, Packet, PacketType, VERSION};
    use crate::session::ConnectionId;
    use bytes::Bytes;

    #[test]
    fn test_valid_encode_decode() {
        let conn_id = ConnectionId(12345);
        let payload = Bytes::from_static(b"Hello, World!");

        let packet = Packet::try_new(
            PacketType::Data,
            0x01,
            conn_id,
            42,
            10,
            1024,
            payload.clone(),
        )
        .unwrap();

        let mut encoded = encode_packet(&packet).unwrap();
        let decoded = decode_packet(&mut encoded).unwrap().unwrap();

        assert_eq!(decoded.header.magic, MAGIC_BYTES);
        assert_eq!(decoded.header.version, VERSION);
        assert_eq!(decoded.header.packet_type, PacketType::Data);
        assert_eq!(decoded.header.flags, 0x01);
        assert_eq!(decoded.header.connection_id.0, 12345);
        assert_eq!(decoded.header.sequence, 42);
        assert_eq!(decoded.header.ack, 10);
        assert_eq!(decoded.header.window, 1024);
        assert_eq!(decoded.header.payload_len, 13);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_encode_payload_length_mismatch() {
        let conn_id = ConnectionId(1);
        let payload = Bytes::from_static(b"test");
        let mut packet = Packet::try_new(PacketType::Data, 0, conn_id, 0, 0, 0, payload).unwrap();

        // Corrupt the header length
        packet.header.payload_len = 99;

        let result = encode_packet(&packet);
        assert!(matches!(result, Err(FSpeedError::PayloadLengthMismatch)));
    }

    #[test]
    fn test_invalid_magic() {
        let conn_id = ConnectionId(1);
        let payload = Bytes::from_static(b"test");
        let packet = Packet::try_new(PacketType::Data, 0, conn_id, 0, 0, 0, payload).unwrap();

        let mut encoded = encode_packet(&packet).unwrap();
        encoded[0] = 0x00;
        encoded[1] = 0x00;

        let result = decode_packet(&mut encoded);
        assert!(matches!(result, Err(FSpeedError::InvalidMagic)));
    }

    #[test]
    fn test_invalid_version() {
        let conn_id = ConnectionId(1);
        let payload = Bytes::from_static(b"test");
        let packet = Packet::try_new(PacketType::Data, 0, conn_id, 0, 0, 0, payload).unwrap();

        let mut encoded = encode_packet(&packet).unwrap();
        encoded[2] = 99;

        let result = decode_packet(&mut encoded);
        assert!(matches!(result, Err(FSpeedError::InvalidVersion)));
    }

    #[test]
    fn test_invalid_packet_type() {
        let conn_id = ConnectionId(1);
        let payload = Bytes::from_static(b"test");
        let packet = Packet::try_new(PacketType::Data, 0, conn_id, 0, 0, 0, payload).unwrap();

        let mut encoded = encode_packet(&packet).unwrap();
        encoded[3] = 99; // Invalid type

        let result = decode_packet(&mut encoded);
        assert!(matches!(result, Err(FSpeedError::InvalidPacketType)));
    }

    #[test]
    fn test_truncated_packet() {
        let conn_id = ConnectionId(1);
        let payload = Bytes::from_static(b"this is a longer payload");
        let packet = Packet::try_new(PacketType::Data, 0, conn_id, 0, 0, 0, payload).unwrap();

        let encoded = encode_packet(&packet).unwrap();

        // Truncate the payload by slicing the buffer
        let mut truncated = encoded.clone();
        truncated.truncate(HEADER_LEN + 5);

        let result = decode_packet(&mut truncated);
        assert!(matches!(result, Err(FSpeedError::TruncatedPacket)));

        // Truncate even the header
        let mut short_header = encoded.clone();
        short_header.truncate(5);
        let result = decode_packet(&mut short_header);
        // UDP datagram is incomplete, this is a truncated packet
        assert!(matches!(result, Err(FSpeedError::TruncatedPacket)));
    }

    #[test]
    fn test_trailing_bytes() {
        let conn_id = ConnectionId(1);
        let payload = Bytes::from_static(b"test");
        let packet = Packet::try_new(PacketType::Data, 0, conn_id, 0, 0, 0, payload).unwrap();

        let mut encoded = encode_packet(&packet).unwrap();

        // Add trailing bytes
        encoded.put_slice(b"trailing_data_from_network");

        let result = decode_packet(&mut encoded);
        assert!(matches!(result, Err(FSpeedError::PayloadLengthMismatch)));
    }

    #[test]
    fn test_oversized_payload() {
        let conn_id = ConnectionId(1);
        // Create a payload larger than u16::MAX
        let payload_len = (u16::MAX as usize) + 1;
        let payload = Bytes::from(vec![0; payload_len]);

        let result = Packet::try_new(PacketType::Data, 0, conn_id, 0, 0, 0, payload);
        assert!(matches!(result, Err(FSpeedError::PayloadTooLarge)));
    }
}
