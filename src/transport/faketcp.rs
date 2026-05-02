//! Experimental fake-TCP packet wrapper.
//!
//! fake-TCP is not `TcpListener` / `TcpStream` and does not create real OS TCP
//! connections. It carries one existing fspeed-rs encoded packet in each TCP
//! payload and is intended to be sent/received by a Linux raw-packet backend.

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::app::error::{FSpeedError, Result};

pub const TCP_FLAG_FIN: u16 = 0x01;
pub const TCP_FLAG_SYN: u16 = 0x02;
pub const TCP_FLAG_RST: u16 = 0x04;
pub const TCP_FLAG_PSH: u16 = 0x08;
pub const TCP_FLAG_ACK: u16 = 0x10;

const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
const IPV4_TCP_PROTO: u8 = 6;
const DEFAULT_TTL: u8 = 64;

/// A single fake-TCP carrier frame.
///
/// The payload is one complete fspeed-rs encoded packet produced by
/// `crate::protocol::encode_packet`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeTcpFrame {
    pub src_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_addr: Ipv4Addr,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u16,
    pub payload: Vec<u8>,
}

impl FakeTcpFrame {
    pub fn peer_addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.src_addr, self.src_port)
    }

    pub fn reply_to(&self, payload: Vec<u8>) -> Self {
        Self {
            src_addr: self.dst_addr,
            src_port: self.dst_port,
            dst_addr: self.src_addr,
            dst_port: self.src_port,
            seq: self.ack,
            ack: self.seq.wrapping_add(self.payload.len() as u32),
            flags: TCP_FLAG_PSH | TCP_FLAG_ACK,
            payload,
        }
    }
}

/// Build an IPv4 packet containing a minimal TCP header and fake-TCP payload.
pub fn build_ipv4_tcp_packet(frame: &FakeTcpFrame) -> Result<Vec<u8>> {
    let total_len = IPV4_HEADER_LEN
        .checked_add(TCP_HEADER_LEN)
        .and_then(|len| len.checked_add(frame.payload.len()))
        .ok_or_else(|| {
            FSpeedError::FakeTcpPacketBuildFailed("packet length overflow".to_string())
        })?;

    if total_len > u16::MAX as usize {
        return Err(FSpeedError::FakeTcpPacketBuildFailed(format!(
            "IPv4 packet too large: {} bytes",
            total_len
        )));
    }

    let mut packet = vec![0_u8; total_len];

    packet[0] = 0x45;
    packet[1] = 0;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&0_u16.to_be_bytes());
    packet[6..8].copy_from_slice(&0_u16.to_be_bytes());
    packet[8] = DEFAULT_TTL;
    packet[9] = IPV4_TCP_PROTO;
    packet[12..16].copy_from_slice(&frame.src_addr.octets());
    packet[16..20].copy_from_slice(&frame.dst_addr.octets());

    let ip_checksum = ipv4_checksum(&packet[..IPV4_HEADER_LEN]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let tcp_offset = IPV4_HEADER_LEN;
    packet[tcp_offset..tcp_offset + 2].copy_from_slice(&frame.src_port.to_be_bytes());
    packet[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&frame.dst_port.to_be_bytes());
    packet[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&frame.seq.to_be_bytes());
    packet[tcp_offset + 8..tcp_offset + 12].copy_from_slice(&frame.ack.to_be_bytes());
    packet[tcp_offset + 12] = (5_u8) << 4;
    packet[tcp_offset + 13] = (frame.flags & 0x3f) as u8;
    packet[tcp_offset + 14..tcp_offset + 16].copy_from_slice(&u16::MAX.to_be_bytes());
    packet[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&0_u16.to_be_bytes());
    packet[tcp_offset + 18..tcp_offset + 20].copy_from_slice(&0_u16.to_be_bytes());
    packet[tcp_offset + TCP_HEADER_LEN..].copy_from_slice(&frame.payload);

    let tcp_checksum = tcp_ipv4_checksum(
        frame.src_addr,
        frame.dst_addr,
        &packet[tcp_offset..tcp_offset + TCP_HEADER_LEN + frame.payload.len()],
    );
    packet[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

    Ok(packet)
}

/// Parse an IPv4/TCP packet and return its fake-TCP frame when it matches.
///
/// `local_port` filters the packet's destination port. `expected_peer`, when
/// present, also filters source address and source port.
pub fn parse_ipv4_tcp_payload(
    packet: &[u8],
    local_port: u16,
    expected_peer: Option<SocketAddrV4>,
) -> Result<Option<FakeTcpFrame>> {
    if packet.len() < IPV4_HEADER_LEN {
        return Err(FSpeedError::FakeTcpPacketParseFailed(
            "packet shorter than IPv4 header".to_string(),
        ));
    }

    let version = packet[0] >> 4;
    if version != 4 {
        return Err(FSpeedError::FakeTcpUnsupportedAddressFamily);
    }

    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < IPV4_HEADER_LEN || packet.len() < ihl {
        return Err(FSpeedError::FakeTcpPacketParseFailed(
            "invalid IPv4 header length".to_string(),
        ));
    }

    if packet[9] != IPV4_TCP_PROTO {
        return Ok(None);
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < ihl + TCP_HEADER_LEN || total_len > packet.len() {
        return Err(FSpeedError::FakeTcpPacketParseFailed(
            "invalid IPv4 total length".to_string(),
        ));
    }

    if ipv4_checksum(&packet[..ihl]) != 0 {
        return Err(FSpeedError::FakeTcpPacketParseFailed(
            "invalid IPv4 checksum".to_string(),
        ));
    }

    let src_addr = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_addr = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let tcp = &packet[ihl..total_len];
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);

    if dst_port != local_port {
        return Ok(None);
    }

    if let Some(peer) = expected_peer
        && (*peer.ip() != src_addr || peer.port() != src_port)
    {
        return Ok(None);
    }

    let tcp_data_offset = ((tcp[12] >> 4) as usize) * 4;
    if tcp_data_offset < TCP_HEADER_LEN || tcp.len() < tcp_data_offset {
        return Err(FSpeedError::FakeTcpPacketParseFailed(
            "invalid TCP data offset".to_string(),
        ));
    }

    if tcp_ipv4_checksum(src_addr, dst_addr, tcp) != 0 {
        return Err(FSpeedError::FakeTcpPacketParseFailed(
            "invalid TCP checksum".to_string(),
        ));
    }

    let payload = tcp[tcp_data_offset..].to_vec();
    Ok(Some(FakeTcpFrame {
        src_addr,
        src_port,
        dst_addr,
        dst_port,
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        flags: (tcp[13] & 0x3f) as u16,
        payload,
    }))
}

pub fn ipv4_checksum(header: &[u8]) -> u16 {
    internet_checksum(header)
}

pub fn tcp_ipv4_checksum(src_addr: Ipv4Addr, dst_addr: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp_segment.len() + 1);
    pseudo.extend_from_slice(&src_addr.octets());
    pseudo.extend_from_slice(&dst_addr.octets());
    pseudo.push(0);
    pseudo.push(IPV4_TCP_PROTO);
    pseudo.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp_segment);
    internet_checksum(&pseudo)
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = bytes.chunks_exact(2);

    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

#[cfg(target_os = "linux")]
pub mod linux_impl {
    use std::net::SocketAddr;

    use crate::app::error::{FSpeedError, Result};

    pub const RUNTIME_UNAVAILABLE: &str = "fake-TCP raw socket transport is experimental and the raw packet send/receive backend is not implemented in this build";

    #[derive(Debug)]
    pub struct FakeTcpTransport;

    impl FakeTcpTransport {
        pub async fn bind(_local_addr: SocketAddr) -> Result<Self> {
            Err(FSpeedError::FakeTcpIoError(RUNTIME_UNAVAILABLE.to_string()))
        }

        pub async fn recv_packet(&self) -> Result<(Vec<u8>, SocketAddr)> {
            Err(FSpeedError::FakeTcpIoError(RUNTIME_UNAVAILABLE.to_string()))
        }

        pub async fn send_packet(&self, _peer: SocketAddr, _encoded_packet: &[u8]) -> Result<()> {
            Err(FSpeedError::FakeTcpIoError(RUNTIME_UNAVAILABLE.to_string()))
        }
    }

    pub fn runtime_error() -> FSpeedError {
        FSpeedError::FakeTcpIoError(RUNTIME_UNAVAILABLE.to_string())
    }
}

#[cfg(not(target_os = "linux"))]
pub mod linux_impl {
    use std::net::SocketAddr;

    use crate::app::error::{FSpeedError, Result};

    pub const UNSUPPORTED_PLATFORM: &str = "fake-TCP transport is only supported on Linux";

    #[derive(Debug)]
    pub struct FakeTcpTransport;

    impl FakeTcpTransport {
        pub async fn bind(_local_addr: SocketAddr) -> Result<Self> {
            Err(runtime_error())
        }

        pub async fn recv_packet(&self) -> Result<(Vec<u8>, SocketAddr)> {
            Err(runtime_error())
        }

        pub async fn send_packet(&self, _peer: SocketAddr, _encoded_packet: &[u8]) -> Result<()> {
            Err(runtime_error())
        }
    }

    pub fn runtime_error() -> FSpeedError {
        FSpeedError::UnsupportedPlatform(UNSUPPORTED_PLATFORM.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame() -> FakeTcpFrame {
        FakeTcpFrame {
            src_addr: Ipv4Addr::new(192, 0, 2, 10),
            src_port: 54000,
            dst_addr: Ipv4Addr::new(198, 51, 100, 20),
            dst_port: 443,
            seq: 100,
            ack: 200,
            flags: TCP_FLAG_PSH | TCP_FLAG_ACK,
            payload: b"encoded fspeed packet".to_vec(),
        }
    }

    #[test]
    fn build_and_parse_ipv4_tcp_packet() {
        let frame = frame();
        let packet = build_ipv4_tcp_packet(&frame).unwrap();
        let parsed = parse_ipv4_tcp_payload(&packet, 443, None).unwrap().unwrap();

        assert_eq!(parsed, frame);
    }

    #[test]
    fn parse_ignores_wrong_port() {
        let packet = build_ipv4_tcp_packet(&frame()).unwrap();
        let parsed = parse_ipv4_tcp_payload(&packet, 444, None).unwrap();

        assert_eq!(parsed, None);
    }

    #[test]
    fn parse_ignores_wrong_peer() {
        let packet = build_ipv4_tcp_packet(&frame()).unwrap();
        let peer = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 11), 54000);
        let parsed = parse_ipv4_tcp_payload(&packet, 443, Some(peer)).unwrap();

        assert_eq!(parsed, None);
    }

    #[test]
    fn malformed_packet_returns_error() {
        let err = parse_ipv4_tcp_payload(&[0x45, 0x00], 443, None).unwrap_err();

        assert!(matches!(err, FSpeedError::FakeTcpPacketParseFailed(_)));
    }

    #[test]
    fn checksum_verifies_built_packet() {
        let packet = build_ipv4_tcp_packet(&frame()).unwrap();
        assert_eq!(ipv4_checksum(&packet[..IPV4_HEADER_LEN]), 0);

        let tcp = &packet[IPV4_HEADER_LEN..];
        assert_eq!(
            tcp_ipv4_checksum(
                Ipv4Addr::new(192, 0, 2, 10),
                Ipv4Addr::new(198, 51, 100, 20),
                tcp
            ),
            0
        );
    }
}
