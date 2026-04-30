use bytes::BytesMut;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::RwLock;

use crate::packet::{Packet, PacketType};
use crate::payload::parse_open_connection_payload;
use crate::protocol::decode_packet;
use crate::session::ServerSession;
use crate::transport::{ConnectionRoute, ConnectionTable};

#[allow(clippy::collapsible_if)]
pub async fn handle_open_connection_packet(
    packet: &Packet,
    peer_addr: SocketAddr,
    secret: &str,
    allowlist: Option<&[SocketAddr]>,
    connection_table: &mut ConnectionTable,
) -> Result<ServerSession, String> {
    let payload = parse_open_connection_payload(&packet.payload).map_err(|e| e.to_string())?;

    if payload.secret != secret {
        tracing::warn!(
            peer_addr = %peer_addr,
            "OpenConnection secret mismatch"
        );
        return Err("Secret mismatch".to_string());
    }

    if let Some(allowed) = allowlist {
        if !allowed.contains(&payload.target) {
            tracing::warn!(
                peer_addr = %peer_addr,
                target = %payload.target,
                "Target not in allowlist"
            );
            return Err("Target not allowed".to_string());
        }
    }

    let route = ConnectionRoute {
        peer_addr,
        target_addr: payload.target,
    };
    connection_table.insert(packet.header.connection_id, route.clone());

    tracing::debug!(
        "Updated route for ConnectionId({}) -> peer: {}, target: {}",
        packet.header.connection_id.0,
        peer_addr,
        payload.target
    );

    // Phase 4.1: Attempt to establish TCP connection
    tracing::info!("Attempting TCP connection to target: {}", payload.target);
    match TcpStream::connect(payload.target).await {
        Ok(tcp_stream) => {
            tracing::info!("Successfully connected to target: {}", payload.target);
            let session = ServerSession {
                connection_id: packet.header.connection_id,
                peer_addr,
                target_addr: payload.target,
                target_tcp: tcp_stream,
            };
            Ok(session)
        }
        Err(e) => {
            tracing::error!("Failed to connect to target {}: {}", payload.target, e);
            Err(format!("TCP connection failed: {}", e))
        }
    }
}

#[allow(clippy::collapsible_if)]
pub async fn run(
    listen: SocketAddr,
    secret: String,
    allow: Option<Vec<SocketAddr>>,
) -> anyhow::Result<()> {
    if let Some(ref allowed) = allow {
        if allowed.is_empty() {
            return Err(anyhow::anyhow!(
                "Allowlist is provided but empty, this is an invalid configuration."
            ));
        }
    }

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
                    let mut table = connection_table.write().await;
                    let allow_ref = allow.as_deref();
                    match handle_open_connection_packet(
                        &packet, peer, &secret, allow_ref, &mut table,
                    )
                    .await
                    {
                        Ok(_session) => {
                            tracing::info!("ServerSession created for {}", _session.connection_id);
                            // Future: start async loops using _session
                        }
                        Err(e) => {
                            tracing::warn!("Failed to handle OpenConnection from {}: {}", peer, e);
                            // Future: remove from connection_table and send Error packet
                        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::ConnectionId;
    use bytes::Bytes;

    fn create_test_packet(payload_str: &str) -> Packet {
        Packet::try_new(
            PacketType::OpenConnection,
            0,
            ConnectionId(1),
            0,
            0,
            0,
            Bytes::from(payload_str.to_string()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_handle_open_connection_success() {
        // To test success, we need a mock TCP server to connect to
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = listener.local_addr().unwrap();

        let payload_str = format!("secret=test123\ntarget={}", target_addr);
        let mut table = ConnectionTable::new();
        let packet = create_test_packet(&payload_str);
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let result =
            handle_open_connection_packet(&packet, peer_addr, "test123", None, &mut table).await;

        assert!(result.is_ok());
        let session = result.unwrap();
        assert_eq!(session.target_addr, target_addr);

        let route = table.lookup(&ConnectionId(1)).unwrap();
        assert_eq!(route.peer_addr, peer_addr);
        assert_eq!(route.target_addr, target_addr);
    }

    #[tokio::test]
    async fn test_handle_open_connection_secret_mismatch() {
        let mut table = ConnectionTable::new();
        let packet = create_test_packet("secret=wrong\ntarget=192.168.1.1:80");
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let result =
            handle_open_connection_packet(&packet, peer_addr, "test123", None, &mut table).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Secret mismatch");
        assert!(table.lookup(&ConnectionId(1)).is_none());
    }

    #[tokio::test]
    async fn test_handle_open_connection_allowlist_success() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = listener.local_addr().unwrap();

        let payload_str = format!("secret=test123\ntarget={}", target_addr);
        let mut table = ConnectionTable::new();
        let packet = create_test_packet(&payload_str);
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let result = handle_open_connection_packet(
            &packet,
            peer_addr,
            "test123",
            Some(&[target_addr]),
            &mut table,
        )
        .await;

        assert!(result.is_ok());
        let route = table.lookup(&ConnectionId(1)).unwrap();
        assert_eq!(route.target_addr, target_addr);
    }

    #[tokio::test]
    async fn test_handle_open_connection_allowlist_reject() {
        let mut table = ConnectionTable::new();
        let allowed_addr: SocketAddr = "192.168.1.1:80".parse().unwrap();
        // Requesting a different target
        let packet = create_test_packet("secret=test123\ntarget=10.0.0.1:22");
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let result = handle_open_connection_packet(
            &packet,
            peer_addr,
            "test123",
            Some(&[allowed_addr]),
            &mut table,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Target not allowed");
        assert!(table.lookup(&ConnectionId(1)).is_none());
    }
}
