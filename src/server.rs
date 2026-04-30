use bytes::BytesMut;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::packet::PacketType;
use crate::protocol::decode_packet;
use crate::transport::ConnectionTable;

pub async fn run(
    listen: SocketAddr,
    _secret: String,
    _allow: Option<Vec<SocketAddr>>,
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(listen).await?;
    tracing::info!("Server UDP socket bound to {}", listen);

    let connection_table = Arc::new(RwLock::new(ConnectionTable::new()));

    let mut buf = vec![0u8; 65536];

    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(e) => {
                tracing::warn!("Failed to receive UDP datagram: {}", e);
                continue;
            }
        };

        let mut data = BytesMut::from(&buf[..len]);
        match decode_packet(&mut data) {
            Ok(Some(packet)) => {
                tracing::info!(
                    peer_address = %peer,
                    packet_type = ?packet.header.packet_type,
                    connection_id = packet.header.connection_id.0,
                    sequence = packet.header.sequence,
                    ack = packet.header.ack,
                    window = packet.header.window,
                    payload_len = packet.header.payload_len,
                    "Received valid packet"
                );

                if packet.header.packet_type == PacketType::OpenConnection {
                    if let Ok(payload_str) = std::str::from_utf8(&packet.payload) {
                        tracing::info!("OpenConnection payload:\n{}", payload_str);
                        let mut table = connection_table.write().await;
                        table.insert(packet.header.connection_id, peer);
                        tracing::debug!(
                            "Updated route for ConnectionId({}) -> {}",
                            packet.header.connection_id.0,
                            peer
                        );
                    } else {
                        tracing::warn!("OpenConnection payload is not valid UTF-8");
                    }
                }
            }
            Ok(None) => {
                tracing::warn!(peer_address = %peer, "Decoded packet was None (unexpected)");
            }
            Err(e) => {
                tracing::warn!(peer_address = %peer, error = %e, "Malformed packet received");
            }
        }
    }
}
