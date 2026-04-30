use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{RwLock, mpsc};

use crate::packet::{Packet, PacketType};
use crate::payload::parse_open_connection_payload;
use crate::protocol::{decode_packet, encode_packet};
use crate::session::{ServerSessionManager, SessionHandle};
use crate::transport::{ConnectionRoute, ConnectionTable};

#[allow(clippy::collapsible_if)]
pub async fn validate_open_connection_packet(
    packet: &Packet,
    peer_addr: SocketAddr,
    secret: &str,
    allowlist: Option<&[SocketAddr]>,
) -> Result<SocketAddr, String> {
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

    Ok(payload.target)
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

    let socket = Arc::new(UdpSocket::bind(listen).await?);
    tracing::info!("Server UDP socket bound to {}", listen);

    let connection_table = Arc::new(RwLock::new(ConnectionTable::new()));
    let session_manager = ServerSessionManager::new();

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
                tracing::debug!(
                    peer_address = %peer,
                    packet_type = ?packet.header.packet_type,
                    connection_id = packet.header.connection_id.0,
                    sequence = packet.header.sequence,
                    "Received valid packet"
                );

                let allow_clone = allow.clone();
                let secret_ref = secret.clone();
                let socket_clone = Arc::clone(&socket);
                let conn_table_clone = Arc::clone(&connection_table);
                let session_mgr_clone = session_manager.clone();
                let packet_type = packet.header.packet_type.clone();
                let conn_id = packet.header.connection_id;

                match packet_type {
                    PacketType::OpenConnection => {
                        // Spawn task to handle OpenConnection asynchronously, to avoid blocking the UDP loop
                        // while TCP connect is performed.
                        let packet_clone = packet.clone();
                        tokio::spawn(async move {
                            match validate_open_connection_packet(
                                &packet_clone,
                                peer,
                                &secret_ref,
                                allow_clone.as_deref(),
                            )
                            .await
                            {
                                Ok(target_addr) => {
                                    tracing::info!(
                                        "Attempting TCP connection to target: {}",
                                        target_addr
                                    );
                                    match TcpStream::connect(target_addr).await {
                                        Ok(tcp_stream) => {
                                            tracing::info!(
                                                "Successfully connected to target: {}",
                                                target_addr
                                            );

                                            // Insert into connection table
                                            let route = ConnectionRoute {
                                                peer_addr: peer,
                                                target_addr,
                                            };
                                            {
                                                let mut table = conn_table_clone.write().await;
                                                table.insert(conn_id, route);
                                            }

                                            let (mut read_half, mut write_half) =
                                                tcp_stream.into_split();
                                            let (tx, mut rx) = mpsc::channel::<Bytes>(1024);

                                            // Register session
                                            session_mgr_clone
                                                .insert(conn_id, SessionHandle { sender: tx })
                                                .await;

                                            // Spawn TCP -> UDP reader task
                                            let read_socket = Arc::clone(&socket_clone);
                                            let read_table = Arc::clone(&conn_table_clone);
                                            let read_session_mgr = session_mgr_clone.clone();
                                            tokio::spawn(async move {
                                                let mut tcp_buf = vec![0u8; 1200];
                                                let mut seq: u32 = 0; // TODO: integrate SendState::next_seq()
                                                loop {
                                                    match read_half.read(&mut tcp_buf).await {
                                                        Ok(0) => {
                                                            // EOF
                                                            tracing::info!(
                                                                "Server target TCP EOF for {}",
                                                                conn_id
                                                            );
                                                            break;
                                                        }
                                                        Ok(n) => {
                                                            let payload = Bytes::copy_from_slice(
                                                                &tcp_buf[..n],
                                                            );
                                                            seq = seq.wrapping_add(1);

                                                            // Send Data packet
                                                            if let Ok(data_packet) = Packet::try_new(
                                                                PacketType::Data,
                                                                0,
                                                                conn_id,
                                                                seq,
                                                                0,
                                                                0,
                                                                payload,
                                                            ) {
                                                                if let Ok(encoded) =
                                                                    encode_packet(&data_packet)
                                                                {
                                                                    // We use the peer_addr from the connection table in case it changed (e.g. client roaming)
                                                                    // For now we just use `peer` from OpenConnection
                                                                    if let Err(e) = read_socket
                                                                        .send_to(&encoded, peer)
                                                                        .await
                                                                    {
                                                                        tracing::warn!(
                                                                            "Failed to send Data packet to client: {}",
                                                                            e
                                                                        );
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        Err(e) => {
                                                            tracing::error!(
                                                                "Failed to read from target TCP for {}: {}",
                                                                conn_id,
                                                                e
                                                            );
                                                            break;
                                                        }
                                                    }
                                                }
                                                // Cleanup
                                                read_session_mgr.remove(&conn_id).await;
                                                {
                                                    let mut table = read_table.write().await;
                                                    table.remove(&conn_id);
                                                }
                                                // Send Close packet
                                                if let Ok(close_packet) = Packet::try_new(
                                                    PacketType::Close,
                                                    0,
                                                    conn_id,
                                                    seq.wrapping_add(1),
                                                    0,
                                                    0,
                                                    Bytes::new(),
                                                ) {
                                                    if let Ok(encoded) =
                                                        encode_packet(&close_packet)
                                                    {
                                                        let _ = read_socket
                                                            .send_to(&encoded, peer)
                                                            .await;
                                                    }
                                                }
                                            });

                                            // Spawn UDP -> TCP writer task
                                            tokio::spawn(async move {
                                                while let Some(data) = rx.recv().await {
                                                    if let Err(e) =
                                                        write_half.write_all(&data).await
                                                    {
                                                        tracing::error!(
                                                            "Failed to write to target TCP for {}: {}",
                                                            conn_id,
                                                            e
                                                        );
                                                        break;
                                                    }
                                                }
                                                let _ = write_half.shutdown().await;
                                                tracing::debug!(
                                                    "Target TCP writer task exiting for {}",
                                                    conn_id
                                                );
                                            });
                                        }
                                        Err(e) => {
                                            tracing::error!(
                                                "Failed to connect to target {}: {}",
                                                target_addr,
                                                e
                                            );
                                            // Do NOT insert into connection_table
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to handle OpenConnection from {}: {}",
                                        peer,
                                        e
                                    );
                                }
                            }
                        });
                    }
                    PacketType::Data => {
                        let payload = packet.payload.clone();
                        tokio::spawn(async move {
                            if let Some(session) = session_mgr_clone.lookup(&conn_id).await {
                                if let Err(e) = session.sender.send(payload).await {
                                    tracing::warn!(
                                        "Failed to forward data to session writer task: {}",
                                        e
                                    );
                                }
                            } else {
                                tracing::warn!(
                                    "Received Data packet for unknown ConnectionId: {}",
                                    conn_id
                                );
                            }
                        });
                    }
                    PacketType::Close => {
                        tokio::spawn(async move {
                            tracing::info!("Received Close packet for ConnectionId: {}", conn_id);
                            session_mgr_clone.remove(&conn_id).await;
                            {
                                let mut table = conn_table_clone.write().await;
                                table.remove(&conn_id);
                            }
                        });
                    }
                    _ => {
                        tracing::warn!("Unhandled packet type: {:?}", packet_type);
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
    async fn test_validate_open_connection_success() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = listener.local_addr().unwrap();

        let payload_str = format!("secret=test123\ntarget={}", target_addr);
        let packet = create_test_packet(&payload_str);
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let result = validate_open_connection_packet(&packet, peer_addr, "test123", None).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), target_addr);
    }

    #[tokio::test]
    async fn test_validate_open_connection_secret_mismatch() {
        let packet = create_test_packet("secret=wrong\ntarget=192.168.1.1:80");
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let result = validate_open_connection_packet(&packet, peer_addr, "test123", None).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Secret mismatch");
    }

    #[tokio::test]
    async fn test_validate_open_connection_allowlist_success() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = listener.local_addr().unwrap();

        let payload_str = format!("secret=test123\ntarget={}", target_addr);
        let packet = create_test_packet(&payload_str);
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let result =
            validate_open_connection_packet(&packet, peer_addr, "test123", Some(&[target_addr]))
                .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), target_addr);
    }

    #[tokio::test]
    async fn test_validate_open_connection_allowlist_reject() {
        let allowed_addr: SocketAddr = "192.168.1.1:80".parse().unwrap();
        let packet = create_test_packet("secret=test123\ntarget=10.0.0.1:22");
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let result =
            validate_open_connection_packet(&packet, peer_addr, "test123", Some(&[allowed_addr]))
                .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Target not allowed");
    }
}
