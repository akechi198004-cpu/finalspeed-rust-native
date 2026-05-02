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
    use std::collections::HashMap;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use pnet::datalink::{self, Channel, Config, DataLinkSender, MacAddr, NetworkInterface};
    use pnet::ipnetwork::IpNetwork;
    use tokio::sync::Mutex as AsyncMutex;
    use tokio::sync::mpsc;

    use super::{
        FakeTcpFrame, TCP_FLAG_ACK, TCP_FLAG_PSH, build_ipv4_tcp_packet, parse_ipv4_tcp_payload,
    };
    use crate::app::error::{FSpeedError, Result};
    use crate::transport::{PacketIo, PacketIoFuture};

    const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
    const ETHERNET_HEADER_LEN: usize = 14;
    const INCOMING_QUEUE: usize = 2048;

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct FakeTcpPeer {
        pub addr: SocketAddrV4,
    }

    #[derive(Debug, Clone)]
    pub struct FakeTcpConfig {
        pub local_addr: SocketAddr,
        pub peer_addr: Option<SocketAddr>,
    }

    #[derive(Debug, Clone)]
    struct PeerRoute {
        dst_mac: MacAddr,
        local_ip: Ipv4Addr,
    }

    struct OutboundFrame {
        peer: SocketAddrV4,
        payload: Vec<u8>,
    }

    struct RawLoopContext {
        routes: Arc<Mutex<HashMap<SocketAddrV4, PeerRoute>>>,
        local_addr: SocketAddrV4,
        interface_mac: MacAddr,
        default_dst_mac: MacAddr,
    }

    #[derive(Debug)]
    pub struct FakeTcpEndpoint {
        local_addr: SocketAddrV4,
        rx: AsyncMutex<mpsc::Receiver<(Vec<u8>, FakeTcpPeer)>>,
        tx: std::sync::mpsc::Sender<OutboundFrame>,
    }

    pub type FakeTcpTransport = FakeTcpEndpoint;

    impl FakeTcpEndpoint {
        pub async fn bind_server(listen_addr: SocketAddr) -> Result<Self> {
            warn_rst(listen_addr.port());
            Self::new(FakeTcpConfig {
                local_addr: listen_addr,
                peer_addr: None,
            })
        }

        pub async fn connect_client(server_addr: SocketAddr) -> Result<Self> {
            warn_rst(server_addr.port());
            Self::new(FakeTcpConfig {
                local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), ephemeral_port()),
                peer_addr: Some(server_addr),
            })
        }

        pub async fn bind(local_addr: SocketAddr) -> Result<Self> {
            Self::bind_server(local_addr).await
        }

        pub async fn recv_packet(&self) -> Result<(Vec<u8>, FakeTcpPeer)> {
            let mut rx = self.rx.lock().await;
            rx.recv()
                .await
                .ok_or_else(|| FSpeedError::FakeTcpIoError("fake-TCP receive loop stopped".into()))
        }

        pub async fn send_packet(&self, peer: FakeTcpPeer, encoded_packet: &[u8]) -> Result<()> {
            self.tx
                .send(OutboundFrame {
                    peer: peer.addr,
                    payload: encoded_packet.to_vec(),
                })
                .map_err(|e| FSpeedError::FakeTcpIoError(e.to_string()))
        }

        fn new(config: FakeTcpConfig) -> Result<Self> {
            ensure_raw_socket_permission()?;

            let requested_local_ip = match config.local_addr.ip() {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => return Err(FSpeedError::FakeTcpUnsupportedAddressFamily),
            };
            if let Some(peer) = config.peer_addr
                && !peer.is_ipv4()
            {
                return Err(FSpeedError::FakeTcpUnsupportedAddressFamily);
            }

            let interface = select_interface(requested_local_ip, config.peer_addr)?;
            let interface_mac = interface.mac.ok_or_else(|| {
                FSpeedError::FakeTcpIoError(format!(
                    "interface {} has no MAC address",
                    interface.name
                ))
            })?;
            let interface_ip = interface_ipv4(&interface, requested_local_ip).ok_or_else(|| {
                FSpeedError::FakeTcpIoError(format!(
                    "interface {} has no usable IPv4 address",
                    interface.name
                ))
            })?;
            let local_ip = if requested_local_ip.is_unspecified() {
                interface_ip
            } else {
                requested_local_ip
            };
            let local_addr = SocketAddrV4::new(local_ip, config.local_addr.port());
            let default_dst_mac =
                default_destination_mac(&interface).unwrap_or(MacAddr::broadcast());

            let (mut tx_raw, mut rx_raw) = match datalink::channel(
                &interface,
                Config {
                    read_timeout: Some(Duration::from_millis(50)),
                    write_buffer_size: 4096,
                    read_buffer_size: 4096,
                    ..Config::default()
                },
            ) {
                Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => {
                    return Err(FSpeedError::FakeTcpIoError(
                        "unsupported datalink channel type".to_string(),
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    return Err(FSpeedError::RawSocketPermissionDenied);
                }
                Err(e) => return Err(FSpeedError::FakeTcpIoError(e.to_string())),
            };

            let routes = Arc::new(Mutex::new(HashMap::new()));
            let thread_routes = Arc::clone(&routes);
            let (incoming_tx, incoming_rx) = mpsc::channel(INCOMING_QUEUE);
            let (outgoing_tx, outgoing_rx) = std::sync::mpsc::channel::<OutboundFrame>();
            let thread_interface_name = interface.name.clone();

            thread::Builder::new()
                .name(format!("faketcp-{}", thread_interface_name))
                .spawn(move || {
                    raw_io_loop(
                        &mut tx_raw,
                        &mut rx_raw,
                        outgoing_rx,
                        incoming_tx,
                        RawLoopContext {
                            routes: thread_routes,
                            local_addr,
                            interface_mac,
                            default_dst_mac,
                        },
                    );
                })
                .map_err(|e| FSpeedError::FakeTcpIoError(e.to_string()))?;

            tracing::info!(
                "fake-TCP endpoint bound on {} via interface {} ({})",
                local_addr,
                interface.name,
                interface_mac
            );

            Ok(Self {
                local_addr,
                rx: AsyncMutex::new(incoming_rx),
                tx: outgoing_tx,
            })
        }
    }

    impl PacketIo for FakeTcpEndpoint {
        fn recv_from<'a>(
            &'a self,
            buf: &'a mut [u8],
        ) -> PacketIoFuture<'a, anyhow::Result<(usize, SocketAddr)>> {
            Box::pin(async move {
                let (packet, peer) = self.recv_packet().await?;
                if packet.len() > buf.len() {
                    anyhow::bail!(
                        "fake-TCP received packet too large for buffer: {} > {}",
                        packet.len(),
                        buf.len()
                    );
                }
                buf[..packet.len()].copy_from_slice(&packet);
                Ok((packet.len(), SocketAddr::V4(peer.addr)))
            })
        }

        fn send_to<'a>(
            &'a self,
            buf: &'a [u8],
            peer: SocketAddr,
        ) -> PacketIoFuture<'a, anyhow::Result<usize>> {
            Box::pin(async move {
                let SocketAddr::V4(peer) = peer else {
                    return Err(FSpeedError::FakeTcpUnsupportedAddressFamily.into());
                };
                self.tx
                    .send(OutboundFrame {
                        peer,
                        payload: buf.to_vec(),
                    })
                    .map_err(|e| FSpeedError::FakeTcpIoError(e.to_string()))?;
                Ok(buf.len())
            })
        }

        fn local_addr(&self) -> anyhow::Result<SocketAddr> {
            Ok(SocketAddr::V4(self.local_addr))
        }
    }

    fn raw_io_loop(
        tx_raw: &mut Box<dyn DataLinkSender>,
        rx_raw: &mut Box<dyn datalink::DataLinkReceiver>,
        outgoing_rx: std::sync::mpsc::Receiver<OutboundFrame>,
        incoming_tx: mpsc::Sender<(Vec<u8>, FakeTcpPeer)>,
        context: RawLoopContext,
    ) {
        loop {
            while let Ok(outbound) = outgoing_rx.try_recv() {
                if let Err(e) = send_raw_packet(
                    tx_raw,
                    &context.routes,
                    context.local_addr,
                    context.interface_mac,
                    context.default_dst_mac,
                    outbound,
                ) {
                    tracing::warn!("fake-TCP send failed: {}", e);
                }
            }

            match rx_raw.next() {
                Ok(ethernet) => {
                    if let Some((encoded, peer)) =
                        parse_ethernet_frame(ethernet, context.local_addr.port(), &context.routes)
                        && incoming_tx
                            .blocking_send((encoded, FakeTcpPeer { addr: peer }))
                            .is_err()
                    {
                        break;
                    }
                }
                Err(e)
                    if e.kind() == io::ErrorKind::TimedOut
                        || e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    tracing::warn!("fake-TCP receive failed: {}", e);
                }
            }
        }
    }

    fn send_raw_packet(
        tx_raw: &mut Box<dyn DataLinkSender>,
        routes: &Arc<Mutex<HashMap<SocketAddrV4, PeerRoute>>>,
        local_addr: SocketAddrV4,
        interface_mac: MacAddr,
        default_dst_mac: MacAddr,
        outbound: OutboundFrame,
    ) -> Result<()> {
        let route = routes
            .lock()
            .map_err(|_| FSpeedError::FakeTcpIoError("peer route lock poisoned".into()))?
            .get(&outbound.peer)
            .cloned();
        let local_ip = route
            .as_ref()
            .map(|route| route.local_ip)
            .unwrap_or(*local_addr.ip());
        let dst_mac = route.map(|route| route.dst_mac).unwrap_or(default_dst_mac);
        let frame = FakeTcpFrame {
            src_addr: local_ip,
            src_port: local_addr.port(),
            dst_addr: *outbound.peer.ip(),
            dst_port: outbound.peer.port(),
            seq: initial_seq(),
            ack: 0,
            flags: TCP_FLAG_PSH | TCP_FLAG_ACK,
            payload: outbound.payload,
        };
        let ip_packet = build_ipv4_tcp_packet(&frame)?;
        let mut ethernet = Vec::with_capacity(ETHERNET_HEADER_LEN + ip_packet.len());
        ethernet.extend_from_slice(&mac_octets(dst_mac));
        ethernet.extend_from_slice(&mac_octets(interface_mac));
        ethernet.extend_from_slice(&ETHERTYPE_IPV4);
        ethernet.extend_from_slice(&ip_packet);

        match tx_raw.send_to(&ethernet, None) {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(FSpeedError::FakeTcpIoError(e.to_string())),
            None => Err(FSpeedError::FakeTcpIoError(
                "datalink sender refused packet".to_string(),
            )),
        }
    }

    fn parse_ethernet_frame(
        ethernet: &[u8],
        local_port: u16,
        routes: &Arc<Mutex<HashMap<SocketAddrV4, PeerRoute>>>,
    ) -> Option<(Vec<u8>, SocketAddrV4)> {
        if ethernet.len() <= ETHERNET_HEADER_LEN || ethernet[12..14] != ETHERTYPE_IPV4 {
            return None;
        }

        let src_mac = MacAddr::new(
            ethernet[6],
            ethernet[7],
            ethernet[8],
            ethernet[9],
            ethernet[10],
            ethernet[11],
        );
        let ip_packet = &ethernet[ETHERNET_HEADER_LEN..];
        match parse_ipv4_tcp_payload(ip_packet, local_port, None) {
            Ok(Some(frame)) if !frame.payload.is_empty() => {
                let peer = frame.peer_addr();
                if let Ok(mut routes) = routes.lock() {
                    routes.insert(
                        peer,
                        PeerRoute {
                            dst_mac: src_mac,
                            local_ip: frame.dst_addr,
                        },
                    );
                }
                Some((frame.payload, peer))
            }
            Ok(_) => None,
            Err(e) => {
                tracing::debug!("Ignoring non fake-TCP packet: {}", e);
                None
            }
        }
    }

    fn select_interface(
        requested_local_ip: Ipv4Addr,
        peer_addr: Option<SocketAddr>,
    ) -> Result<NetworkInterface> {
        let interfaces = datalink::interfaces();

        if !requested_local_ip.is_unspecified()
            && let Some(interface) = interfaces.iter().find(|iface| {
                iface.is_up()
                    && !iface.is_loopback()
                    && iface.ips.iter().any(|ip| match ip {
                        IpNetwork::V4(v4) => v4.ip() == requested_local_ip,
                        IpNetwork::V6(_) => false,
                    })
            })
        {
            return Ok(interface.clone());
        }

        if let Some(SocketAddr::V4(peer)) = peer_addr
            && peer.ip().is_loopback()
            && let Some(interface) = interfaces.iter().find(|iface| {
                iface.is_up()
                    && iface.is_loopback()
                    && interface_ipv4(iface, Ipv4Addr::UNSPECIFIED).is_some()
            })
        {
            return Ok(interface.clone());
        }

        interfaces
            .into_iter()
            .find(|iface| {
                iface.is_up()
                    && !iface.is_loopback()
                    && iface.mac.is_some()
                    && interface_ipv4(iface, Ipv4Addr::UNSPECIFIED).is_some()
            })
            .ok_or_else(|| {
                FSpeedError::FakeTcpIoError(
                    "failed to select a usable IPv4 interface for fake-TCP; explicit --interface is not implemented yet".to_string(),
                )
            })
    }

    fn interface_ipv4(interface: &NetworkInterface, preferred: Ipv4Addr) -> Option<Ipv4Addr> {
        interface.ips.iter().find_map(|ip| match ip {
            IpNetwork::V4(v4) if preferred.is_unspecified() || v4.ip() == preferred => {
                Some(v4.ip())
            }
            IpNetwork::V4(_) | IpNetwork::V6(_) => None,
        })
    }

    fn default_destination_mac(interface: &NetworkInterface) -> Option<MacAddr> {
        let gateway = default_gateway_ipv4(interface)?;
        arp_mac_for_ip(gateway)
    }

    fn default_gateway_ipv4(interface: &NetworkInterface) -> Option<Ipv4Addr> {
        let routes = std::fs::read_to_string("/proc/net/route").ok()?;
        for line in routes.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 3 || fields[0] != interface.name || fields[1] != "00000000" {
                continue;
            }
            let raw = u32::from_str_radix(fields[2], 16).ok()?;
            let bytes = raw.to_le_bytes();
            return Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]));
        }
        None
    }

    fn arp_mac_for_ip(ip: Ipv4Addr) -> Option<MacAddr> {
        let arp = std::fs::read_to_string("/proc/net/arp").ok()?;
        for line in arp.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 || fields[0] != ip.to_string() {
                continue;
            }
            return MacAddr::from_str(fields[3]).ok();
        }
        None
    }

    fn ensure_raw_socket_permission() -> Result<()> {
        if unsafe { libc::geteuid() } == 0 {
            return Ok(());
        }
        Err(FSpeedError::RawSocketPermissionDenied)
    }

    fn warn_rst(port: u16) {
        tracing::warn!(
            "fake-TCP may require dropping kernel TCP RST packets for the selected port. Example: sudo iptables -A OUTPUT -p tcp --sport {} --tcp-flags RST RST -j DROP",
            port
        );
    }

    fn ephemeral_port() -> u16 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.subsec_nanos())
            .unwrap_or(0);
        49152 + (nanos % 16384) as u16
    }

    fn initial_seq() -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.subsec_nanos())
            .unwrap_or(1)
    }

    fn mac_octets(mac: MacAddr) -> [u8; 6] {
        [mac.0, mac.1, mac.2, mac.3, mac.4, mac.5]
    }

    pub fn runtime_error() -> FSpeedError {
        FSpeedError::FakeTcpIoError("fake-TCP runtime initialization failed".to_string())
    }
}

#[cfg(not(target_os = "linux"))]
pub mod linux_impl {
    use std::net::SocketAddr;

    use crate::app::error::{FSpeedError, Result};
    use crate::transport::{PacketIo, PacketIoFuture};

    pub const UNSUPPORTED_PLATFORM: &str = "fake-TCP transport is only supported on Linux";

    #[derive(Debug)]
    pub struct FakeTcpEndpoint;

    pub type FakeTcpTransport = FakeTcpEndpoint;

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct FakeTcpPeer {
        pub addr: std::net::SocketAddrV4,
    }

    impl FakeTcpEndpoint {
        pub async fn bind_server(_local_addr: SocketAddr) -> Result<Self> {
            Err(runtime_error())
        }

        pub async fn connect_client(_server_addr: SocketAddr) -> Result<Self> {
            Err(runtime_error())
        }

        pub async fn bind(_local_addr: SocketAddr) -> Result<Self> {
            Err(runtime_error())
        }

        pub async fn recv_packet(&self) -> Result<(Vec<u8>, FakeTcpPeer)> {
            Err(runtime_error())
        }

        pub async fn send_packet(&self, _peer: FakeTcpPeer, _encoded_packet: &[u8]) -> Result<()> {
            Err(runtime_error())
        }
    }

    impl PacketIo for FakeTcpEndpoint {
        fn recv_from<'a>(
            &'a self,
            _buf: &'a mut [u8],
        ) -> PacketIoFuture<'a, anyhow::Result<(usize, SocketAddr)>> {
            Box::pin(async move { Err(runtime_error().into()) })
        }

        fn send_to<'a>(
            &'a self,
            _buf: &'a [u8],
            _peer: SocketAddr,
        ) -> PacketIoFuture<'a, anyhow::Result<usize>> {
            Box::pin(async move { Err(runtime_error().into()) })
        }

        fn local_addr(&self) -> anyhow::Result<SocketAddr> {
            Err(runtime_error().into())
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
    fn malformed_tcp_packet_returns_error() {
        let mut packet = build_ipv4_tcp_packet(&frame()).unwrap();
        packet[IPV4_HEADER_LEN + 12] = 0;
        let err = parse_ipv4_tcp_payload(&packet, 443, None).unwrap_err();

        assert!(matches!(err, FSpeedError::FakeTcpPacketParseFailed(_)));
    }

    #[test]
    fn payload_roundtrip_preserves_encoded_packet_bytes() {
        use bytes::Bytes;

        let packet = crate::protocol::packet::Packet::try_new(
            crate::protocol::packet::PacketType::Data,
            0,
            crate::tunnel::session::ConnectionId(7),
            1,
            0,
            0,
            Bytes::from_static(b"hello"),
        )
        .unwrap();
        let encoded = crate::protocol::encode_packet(&packet).unwrap();
        let mut frame = frame();
        frame.payload = encoded.to_vec();

        let raw = build_ipv4_tcp_packet(&frame).unwrap();
        let parsed = parse_ipv4_tcp_payload(&raw, 443, None).unwrap().unwrap();

        assert_eq!(parsed.payload, encoded.to_vec());
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
