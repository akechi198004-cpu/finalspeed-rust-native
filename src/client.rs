use crate::config::PortMap;
use crate::crypto::{
    build_aad, current_timestamp_ms, decrypt_payload, derive_key, encrypt_payload,
};
use crate::packet::{FLAG_ENCRYPTED, Packet, PacketType};
use crate::payload::parse_error_payload;
use crate::protocol::{decode_packet, encode_packet};
use crate::session::{ClientSessionManager, SessionHandle, SessionState};
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
    let secret_recv_clone = Arc::clone(&secret_arc);
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
                                    if packet.header.flags & FLAG_ENCRYPTED == 0 {
                                        tracing::warn!(
                                            "Data packet missing FLAG_ENCRYPTED, dropping"
                                        );
                                        continue;
                                    }
                                    let payload = packet.payload.clone();
                                    let session_mgr = session_mgr_recv.clone();
                                    let read_key = derive_key(&secret_recv_clone);
                                    let aad = build_aad(&packet.header);

                                    tokio::spawn(async move {
                                        match decrypt_payload(&payload, &read_key, &aad) {
                                            Ok(plaintext) => {
                                                if let Some(session) =
                                                    session_mgr.lookup(&conn_id).await
                                                {
                                                    if let Err(e) =
                                                        session.sender.send(plaintext).await
                                                    {
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
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    "Failed to decrypt Data payload: {}",
                                                    e
                                                );
                                            }
                                        }
                                    });
                                }
                                PacketType::Ack => {
                                    if packet.header.flags & FLAG_ENCRYPTED == 0 {
                                        tracing::warn!(
                                            "Ack packet missing FLAG_ENCRYPTED, dropping"
                                        );
                                        continue;
                                    }
                                    let payload = packet.payload.clone();
                                    let session_mgr = session_mgr_recv.clone();
                                    let read_key = derive_key(&secret_recv_clone);
                                    let aad = build_aad(&packet.header);

                                    tokio::spawn(async move {
                                        if let Err(e) = decrypt_payload(&payload, &read_key, &aad) {
                                            tracing::warn!("Failed to decrypt Ack payload: {}", e);
                                            return;
                                        }
                                        tracing::info!(
                                            "Received Ack packet for ConnectionId: {}",
                                            conn_id
                                        );
                                        session_mgr.complete_handshake(&conn_id, true).await;
                                    });
                                }
                                PacketType::Error => {
                                    if packet.header.flags & FLAG_ENCRYPTED == 0 {
                                        tracing::warn!(
                                            "Error packet missing FLAG_ENCRYPTED, dropping"
                                        );
                                        continue;
                                    }
                                    let payload = packet.payload.clone();
                                    let session_mgr = session_mgr_recv.clone();
                                    let read_key = derive_key(&secret_recv_clone);
                                    let aad = build_aad(&packet.header);

                                    tokio::spawn(async move {
                                        match decrypt_payload(&payload, &read_key, &aad) {
                                            Ok(plaintext) => {
                                                let reason = if let Ok(error_response) =
                                                    parse_error_payload(&plaintext)
                                                {
                                                    error_response.reason
                                                } else {
                                                    "unknown".to_string()
                                                };
                                                tracing::warn!(
                                                    "Received Error packet for ConnectionId: {} with reason: {}",
                                                    conn_id,
                                                    reason
                                                );
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    "Failed to decrypt Error payload: {}",
                                                    e
                                                );
                                            }
                                        }
                                        session_mgr.complete_handshake(&conn_id, false).await;
                                    });
                                }
                                PacketType::Close => {
                                    if packet.header.flags & FLAG_ENCRYPTED == 0 {
                                        tracing::warn!(
                                            "Close packet missing FLAG_ENCRYPTED, dropping"
                                        );
                                        continue;
                                    }
                                    let payload = packet.payload.clone();
                                    let session_mgr = session_mgr_recv.clone();
                                    let read_key = derive_key(&secret_recv_clone);
                                    let aad = build_aad(&packet.header);

                                    tokio::spawn(async move {
                                        if let Err(e) = decrypt_payload(&payload, &read_key, &aad) {
                                            tracing::warn!(
                                                "Failed to decrypt Close payload: {}",
                                                e
                                            );
                                            return;
                                        }
                                        tracing::info!(
                                            "Received Close packet for ConnectionId: {}",
                                            conn_id
                                        );
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

                        let payload_str = format!(
                            "target={}\ntimestamp_ms={}",
                            mapping.target,
                            current_timestamp_ms()
                        );
                        let payload = Bytes::from(payload_str);

                        match Packet::try_new(
                            PacketType::OpenConnection,
                            FLAG_ENCRYPTED,
                            conn_id,
                            0,
                            0,
                            1024,
                            Bytes::new(),
                        ) {
                            Ok(mut packet) => {
                                let key = derive_key(&secret_clone);
                                let aad = build_aad(&packet.header);

                                match encrypt_payload(&payload, &key, &aad) {
                                    Ok(encrypted_payload) => {
                                        packet.payload = encrypted_payload.clone();
                                        packet.header.payload_len = encrypted_payload.len() as u16;

                                        let (mut read_half, mut write_half) =
                                            tcp_stream.into_split();
                                        let (tx, mut rx) = mpsc::channel::<Bytes>(1024);

                                        let (hs_tx, hs_rx) = tokio::sync::oneshot::channel();

                                        // Register session as Pending BEFORE sending the packet
                                        // This prevents a race condition where the server replies with Ack
                                        // before the client has registered the pending handshake.
                                        session_mgr_clone
                                            .insert_pending(
                                                conn_id,
                                                SessionHandle {
                                                    sender: tx,
                                                    state: SessionState::Pending,
                                                },
                                                hs_tx,
                                            )
                                            .await;

                                        match encode_packet(&packet) {
                                            Ok(encoded) => {
                                                if let Err(e) = socket_clone
                                                    .send_to(&encoded, server_addr)
                                                    .await
                                                {
                                                    tracing::error!(
                                                        "Failed to send UDP packet: {}",
                                                        e
                                                    );
                                                    session_mgr_clone.remove(&conn_id).await;
                                                } else {
                                                    tracing::info!(
                                                        "Sent OpenConnection packet for {} to server",
                                                        conn_id
                                                    );

                                                    // Wait for handshake with a 5-second timeout
                                                    let handshake_result = tokio::time::timeout(
                                                        std::time::Duration::from_secs(5),
                                                        hs_rx,
                                                    )
                                                    .await;

                                                    match handshake_result {
                                                        Ok(Ok(true)) => {
                                                            tracing::info!(
                                                                "Handshake successful for ConnectionId: {}",
                                                                conn_id
                                                            );
                                                            session_mgr_clone
                                                                .establish(&conn_id)
                                                                .await;
                                                        }
                                                        Ok(Ok(false)) => {
                                                            tracing::warn!(
                                                                "Handshake failed (Error packet) for ConnectionId: {}",
                                                                conn_id
                                                            );
                                                            session_mgr_clone
                                                                .remove(&conn_id)
                                                                .await;
                                                            return;
                                                        }
                                                        Ok(Err(_)) => {
                                                            tracing::warn!(
                                                                "Handshake channel dropped for ConnectionId: {}",
                                                                conn_id
                                                            );
                                                            session_mgr_clone
                                                                .remove(&conn_id)
                                                                .await;
                                                            return;
                                                        }
                                                        Err(_) => {
                                                            tracing::warn!(
                                                                "Handshake timeout for ConnectionId: {}",
                                                                conn_id
                                                            );
                                                            session_mgr_clone
                                                                .remove(&conn_id)
                                                                .await;
                                                            return;
                                                        }
                                                    }

                                                    // Spawn Local TCP -> UDP reader task
                                                    let read_socket = Arc::clone(&socket_clone);
                                                    let read_session_mgr =
                                                        session_mgr_clone.clone();
                                                    let read_secret_clone = secret_clone.clone();
                                                    tokio::spawn(async move {
                                                        let mut tcp_buf = vec![0u8; 1200];
                                                        let mut seq: u32 = 0; // TODO: integrate SendState::next_seq()
                                                        let read_key =
                                                            derive_key(&read_secret_clone);
                                                        loop {
                                                            match read_half.read(&mut tcp_buf).await
                                                            {
                                                                Ok(0) => {
                                                                    // EOF
                                                                    tracing::info!(
                                                                        "Local TCP EOF for {}",
                                                                        conn_id
                                                                    );
                                                                    break;
                                                                }
                                                                Ok(n) => {
                                                                    let plaintext = &tcp_buf[..n];
                                                                    seq = seq.wrapping_add(1);

                                                                    if let Ok(mut data_packet) =
                                                                        Packet::try_new(
                                                                            PacketType::Data,
                                                                            FLAG_ENCRYPTED,
                                                                            conn_id,
                                                                            seq,
                                                                            0,
                                                                            0,
                                                                            Bytes::new(),
                                                                        )
                                                                    {
                                                                        let data_aad = build_aad(
                                                                            &data_packet.header,
                                                                        );
                                                                        if let Ok(encrypted_data) =
                                                                            encrypt_payload(
                                                                                plaintext,
                                                                                &read_key,
                                                                                &data_aad,
                                                                            )
                                                                        {
                                                                            data_packet.payload =
                                                                                encrypted_data
                                                                                    .clone();
                                                                            data_packet
                                                                                .header
                                                                                .payload_len =
                                                                                encrypted_data.len()
                                                                                    as u16;

                                                                            if let Ok(encoded) =
                                                                                encode_packet(
                                                                                    &data_packet,
                                                                                )
                                                                                && let Err(e) = read_socket.send_to(&encoded, server_addr).await {
                                                                                    tracing::warn!(
                                                                                        "Failed to send Data packet to server: {}",
                                                                                        e
                                                                                    );
                                                                                }
                                                                        }
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
                                                        if let Ok(mut close_packet) =
                                                            Packet::try_new(
                                                                PacketType::Close,
                                                                FLAG_ENCRYPTED,
                                                                conn_id,
                                                                seq.wrapping_add(1),
                                                                0,
                                                                0,
                                                                Bytes::new(),
                                                            )
                                                        {
                                                            let close_aad =
                                                                build_aad(&close_packet.header);
                                                            if let Ok(encrypted_close) =
                                                                encrypt_payload(
                                                                    b"", &read_key, &close_aad,
                                                                )
                                                            {
                                                                close_packet.payload =
                                                                    encrypted_close.clone();
                                                                close_packet.header.payload_len =
                                                                    encrypted_close.len() as u16;
                                                                if let Ok(encoded) =
                                                                    encode_packet(&close_packet)
                                                                {
                                                                    let _ = read_socket
                                                                        .send_to(
                                                                            &encoded,
                                                                            server_addr,
                                                                        )
                                                                        .await;
                                                                }
                                                            }
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
                                            Err(e) => {
                                                tracing::error!("Failed to encode packet: {}", e)
                                            }
                                        }
                                    }
                                    Err(e) => tracing::error!(
                                        "Failed to encrypt OpenConnection payload: {}",
                                        e
                                    ),
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
