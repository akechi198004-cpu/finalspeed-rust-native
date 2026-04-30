use crate::config::PortMap;
use crate::packet::{Packet, PacketType};
use crate::protocol::{decode_packet, encode_packet};
use crate::session::{ClientSessionManager, SessionHandle};
use crate::transport::ConnectionIdGenerator;

use bytes::{Bytes, BytesMut};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket, lookup_host};
use tokio::sync::mpsc;

pub async fn run(server: String, secret: String, map: Vec<PortMap>) -> anyhow::Result<()> {
    tracing::info!("Initializing client, mapping {} ports", map.len());

    // Resolve server address
    let mut addrs = lookup_host(&server).await?;
    let server_addr = addrs
        .next()
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve server address: {}", server))?;
    tracing::info!("Resolved server address to {}", server_addr);

    // Bind local UDP socket
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    tracing::info!("Client UDP socket bound to {}", socket.local_addr()?);

    let id_generator = Arc::new(ConnectionIdGenerator::new());
    let secret_arc = Arc::new(secret);
    let session_manager = ClientSessionManager::new();

    let mut tasks = vec![];

    // Spawn central UDP receive loop
    let socket_recv_clone = Arc::clone(&socket);
    let session_mgr_recv = session_manager.clone();
    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match socket_recv_clone.recv_from(&mut buf).await {
                Ok((len, peer)) => {
                    let mut data = BytesMut::from(&buf[..len]);
                    match decode_packet(&mut data) {
                        Ok(Some(packet)) => {
                            let conn_id = packet.header.connection_id;
                            match packet.header.packet_type {
                                PacketType::Data => {
                                    let payload = packet.payload.clone();
                                    let session_mgr = session_mgr_recv.clone();
                                    tokio::spawn(async move {
                                        if let Some(session) = session_mgr.lookup(&conn_id).await {
                                            if let Err(e) = session.sender.send(payload).await {
                                                tracing::warn!(
                                                    "Failed to forward data to local TCP writer task: {}",
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
                                    tracing::info!(
                                        "Received Close packet for ConnectionId: {}",
                                        conn_id
                                    );
                                    let session_mgr = session_mgr_recv.clone();
                                    tokio::spawn(async move {
                                        session_mgr.remove(&conn_id).await;
                                    });
                                }
                                _ => {
                                    tracing::debug!(
                                        "Unhandled packet type from server: {:?}",
                                        packet.header.packet_type
                                    );
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::warn!(peer_address = %peer, error = %e, "Malformed packet received");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to receive UDP datagram: {}", e);
                }
            }
        }
    });
    tasks.push(recv_task);

    for mapping in map {
        tracing::info!(
            "Setting up TCP listener for {} -> {}",
            mapping.local,
            mapping.target
        );

        let listener = TcpListener::bind(&mapping.local).await?;
        let socket_clone = Arc::clone(&socket);
        let id_gen_clone = Arc::clone(&id_generator);
        let secret_clone = Arc::clone(&secret_arc);
        let session_mgr_clone = session_manager.clone();

        // Spawn task to handle incoming local TCP connections
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((tcp_stream, peer_addr)) => {
                        let conn_id = id_gen_clone.next();
                        tracing::info!(
                            "Accepted TCP connection from {} (ConnId: {}), targeting {}",
                            peer_addr,
                            conn_id,
                            mapping.target
                        );

                        let payload_str =
                            format!("secret={}\ntarget={}", secret_clone, mapping.target);
                        let payload = Bytes::from(payload_str);

                        match Packet::try_new(
                            PacketType::OpenConnection,
                            0,
                            conn_id,
                            0,
                            0,
                            1024,
                            payload,
                        ) {
                            Ok(packet) => {
                                match encode_packet(&packet) {
                                    Ok(encoded) => {
                                        if let Err(e) =
                                            socket_clone.send_to(&encoded, server_addr).await
                                        {
                                            tracing::error!("Failed to send UDP packet: {}", e);
                                        } else {
                                            tracing::info!(
                                                "Sent OpenConnection packet for {} to server",
                                                conn_id
                                            );

                                            let (mut read_half, mut write_half) =
                                                tcp_stream.into_split();
                                            let (tx, mut rx) = mpsc::channel::<Bytes>(1024);

                                            // Register session
                                            session_mgr_clone
                                                .insert(conn_id, SessionHandle { sender: tx })
                                                .await;

                                            // Spawn Local TCP -> UDP reader task
                                            let read_socket = Arc::clone(&socket_clone);
                                            let read_session_mgr = session_mgr_clone.clone();
                                            tokio::spawn(async move {
                                                let mut tcp_buf = vec![0u8; 1200];
                                                let mut seq: u32 = 0; // TODO: integrate SendState::next_seq()
                                                // TODO: Wait for Server response / OpenConnectionAccepted or Handshake
                                                //       before sending data. Phase 4.2 currently just sends immediately.
                                                loop {
                                                    match read_half.read(&mut tcp_buf).await {
                                                        Ok(0) => {
                                                            // EOF
                                                            tracing::info!(
                                                                "Local TCP EOF for {}",
                                                                conn_id
                                                            );
                                                            break;
                                                        }
                                                        Ok(n) => {
                                                            let payload = Bytes::copy_from_slice(
                                                                &tcp_buf[..n],
                                                            );
                                                            seq = seq.wrapping_add(1);

                                                            if let Ok(data_packet) = Packet::try_new(
                                                                PacketType::Data,
                                                                0,
                                                                conn_id,
                                                                seq,
                                                                0,
                                                                0,
                                                                payload,
                                                            ) && let Ok(encoded) =
                                                                encode_packet(&data_packet)
                                                                && let Err(e) = read_socket
                                                                    .send_to(&encoded, server_addr)
                                                                    .await
                                                            {
                                                                tracing::warn!(
                                                                    "Failed to send Data packet to server: {}",
                                                                    e
                                                                );
                                                            }
                                                        }
                                                        Err(e) => {
                                                            tracing::error!(
                                                                "Failed to read from local TCP for {}: {}",
                                                                conn_id,
                                                                e
                                                            );
                                                            break;
                                                        }
                                                    }
                                                }

                                                // Cleanup and Send Close packet
                                                read_session_mgr.remove(&conn_id).await;
                                                if let Ok(close_packet) = Packet::try_new(
                                                    PacketType::Close,
                                                    0,
                                                    conn_id,
                                                    seq.wrapping_add(1),
                                                    0,
                                                    0,
                                                    Bytes::new(),
                                                ) && let Ok(encoded) =
                                                    encode_packet(&close_packet)
                                                {
                                                    let _ = read_socket
                                                        .send_to(&encoded, server_addr)
                                                        .await;
                                                }
                                            });

                                            // Spawn UDP -> Local TCP writer task
                                            tokio::spawn(async move {
                                                while let Some(data) = rx.recv().await {
                                                    if let Err(e) =
                                                        write_half.write_all(&data).await
                                                    {
                                                        tracing::error!(
                                                            "Failed to write to local TCP for {}: {}",
                                                            conn_id,
                                                            e
                                                        );
                                                        break;
                                                    }
                                                }
                                                let _ = write_half.shutdown().await;
                                                tracing::debug!(
                                                    "Local TCP writer task exiting for {}",
                                                    conn_id
                                                );
                                            });
                                        }
                                    }
                                    Err(e) => tracing::error!("Failed to encode packet: {}", e),
                                }
                            }
                            Err(e) => tracing::error!("Failed to construct packet: {}", e),
                        }
                    }
                    Err(e) => tracing::error!("Error accepting TCP connection: {}", e),
                }
            }
        });

        tasks.push(handle);
    }

    // Keep the client running as tasks are backgrounded
    for handle in tasks {
        let _ = handle.await;
    }

    Ok(())
}
