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
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket, lookup_host};
use tokio::sync::mpsc;

use crate::cli::TransportMode;
use crate::framing::{read_frame, write_frame};

pub async fn run(
    server: String,
    secret: String,
    map: Vec<PortMap>,
    socks5: Option<SocketAddr>,
    transport: TransportMode,
) -> anyhow::Result<()> {
    match transport {
        TransportMode::Udp => run_udp(server, secret, map, socks5).await,
        TransportMode::Tcp => run_tcp(server, secret, map, socks5).await,
    }
}

pub async fn run_udp(
    server: String,
    secret: String,
    map: Vec<PortMap>,
    socks5: Option<SocketAddr>,
) -> anyhow::Result<()> {
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

                                    let socket_ack = Arc::clone(&socket_recv_clone);
                                    tokio::spawn(async move {
                                        match decrypt_payload(&payload, &read_key, &aad) {
                                            Ok(plaintext) => {
                                                if let Some(session) =
                                                    session_mgr.lookup(&conn_id).await
                                                {
                                                    let sequence = packet.header.sequence;

                                                    // Pass to ReceiveState
                                                    let delivered_payloads = {
                                                        let mut state =
                                                            session.receive_state.lock().await;
                                                        state.receive_packet(sequence, plaintext)
                                                    };

                                                    for payload in delivered_payloads {
                                                        if let Err(e) =
                                                            session.sender.send(payload).await
                                                        {
                                                            tracing::warn!(
                                                                "Failed to forward data to local TCP writer task: {}",
                                                                e
                                                            );
                                                        }
                                                    }

                                                    // Generate and send Ack
                                                    let ack_num = {
                                                        let state =
                                                            session.receive_state.lock().await;
                                                        state.generate_ack()
                                                    };

                                                    if let Ok(mut ack_packet) = Packet::try_new(
                                                        PacketType::Ack,
                                                        FLAG_ENCRYPTED,
                                                        conn_id,
                                                        0, // Ack sequence is typically 0
                                                        ack_num,
                                                        0, // Window size (TODO)
                                                        Bytes::new(),
                                                    ) {
                                                        let ack_aad = build_aad(&ack_packet.header);
                                                        let ack_payload =
                                                            crate::payload::build_ack_payload(); // or empty
                                                        if let Ok(encrypted_ack) = encrypt_payload(
                                                            ack_payload.as_bytes(),
                                                            &read_key,
                                                            &ack_aad,
                                                        ) {
                                                            ack_packet.payload =
                                                                encrypted_ack.clone();
                                                            ack_packet.header.payload_len =
                                                                encrypted_ack.len() as u16;
                                                            if let Ok(encoded) =
                                                                encode_packet(&ack_packet)
                                                            {
                                                                let _ = socket_ack
                                                                    .send_to(
                                                                        &encoded,
                                                                        session.peer_addr,
                                                                    )
                                                                    .await;
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    use crate::session::UnknownState;
                                                    match session_mgr.check_unknown(&conn_id).await
                                                    {
                                                        UnknownState::RecentlyClosed => {
                                                            tracing::debug!(
                                                                "Dropping late Data packet for recently closed ConnectionId: {}",
                                                                conn_id
                                                            );
                                                        }
                                                        UnknownState::RateLimited => {
                                                            tracing::debug!(
                                                                "Dropping repeated Data packet for unknown ConnectionId: {}",
                                                                conn_id
                                                            );
                                                        }
                                                        UnknownState::WarnFirstTime => {
                                                            tracing::warn!(
                                                                "Received Data packet for unknown ConnectionId: {}",
                                                                conn_id
                                                            );
                                                        }
                                                    }
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
                                        tracing::debug!(
                                            "Received Ack packet for ConnectionId: {}, ack={}",
                                            conn_id,
                                            packet.header.ack
                                        );

                                        if let Some(session) = session_mgr.lookup(&conn_id).await {
                                            {
                                                let mut state = session.send_state.lock().await;
                                                state.handle_ack(packet.header.ack);
                                            }
                                            session.window_notify.notify_waiters();

                                            // Only complete handshake if session was pending
                                            if session.state == SessionState::Pending {
                                                session_mgr
                                                    .complete_handshake(&conn_id, true)
                                                    .await;
                                            }
                                        } else {
                                            use crate::session::UnknownState;
                                            match session_mgr.check_unknown(&conn_id).await {
                                                UnknownState::RecentlyClosed => {
                                                    tracing::debug!(
                                                        "Dropping late Ack packet for recently closed ConnectionId: {}",
                                                        conn_id
                                                    );
                                                }
                                                UnknownState::RateLimited => {
                                                    tracing::debug!(
                                                        "Dropping repeated Ack packet for unknown ConnectionId: {}",
                                                        conn_id
                                                    );
                                                }
                                                UnknownState::WarnFirstTime => {
                                                    tracing::warn!(
                                                        "Received Ack packet for unknown ConnectionId: {}",
                                                        conn_id
                                                    );
                                                }
                                            }
                                        }
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

                                        if session_mgr.lookup(&conn_id).await.is_some() {
                                            tracing::info!(
                                                "Received Close packet for ConnectionId: {}",
                                                conn_id
                                            );
                                            session_mgr.remove(&conn_id).await;
                                        } else {
                                            use crate::session::UnknownState;
                                            match session_mgr.check_unknown(&conn_id).await {
                                                UnknownState::RecentlyClosed => {
                                                    tracing::debug!(
                                                        "Dropping late Close packet for recently closed ConnectionId: {}",
                                                        conn_id
                                                    );
                                                }
                                                UnknownState::RateLimited => {
                                                    tracing::debug!(
                                                        "Dropping repeated Close packet for unknown ConnectionId: {}",
                                                        conn_id
                                                    );
                                                }
                                                UnknownState::WarnFirstTime => {
                                                    tracing::warn!(
                                                        "Received Close packet for unknown ConnectionId: {}",
                                                        conn_id
                                                    );
                                                }
                                            }
                                        }
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
                                        use crate::reliability::{ReceiveState, SendState};
                                        use tokio::sync::{Mutex, Notify};

                                        session_mgr_clone
                                            .insert_pending(
                                                conn_id,
                                                SessionHandle {
                                                    sender: tx,
                                                    state: SessionState::Pending,
                                                    send_state: Arc::new(Mutex::new(
                                                        SendState::new(1024),
                                                    )),
                                                    receive_state: Arc::new(Mutex::new(
                                                        ReceiveState::new(1024),
                                                    )),
                                                    window_notify: Arc::new(Notify::new()),
                                                    close_notify: Arc::new(Notify::new()),
                                                    peer_addr: server_addr,
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

                                                            // Spawn retransmission task
                                                            if let Some(session) = session_mgr_clone
                                                                .lookup(&conn_id)
                                                                .await
                                                            {
                                                                let send_state_arc =
                                                                    session.send_state.clone();
                                                                let close_notify =
                                                                    session.close_notify.clone();
                                                                let peer_addr = session.peer_addr;
                                                                let socket_retx =
                                                                    Arc::clone(&socket_clone);
                                                                let session_mgr_retx =
                                                                    session_mgr_clone.clone();

                                                                tokio::spawn(async move {
                                                                    loop {
                                                                        tokio::select! {
                                                                            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                                                                                let now = std::time::Instant::now();
                                                                                let mut to_retransmit = Vec::new();
                                                                                let mut failed = false;

                                                                                {
                                                                                    let mut state = send_state_arc.lock().await;
                                                                                    match state.get_timed_out_packets(now) {
                                                                                        Ok(pkts) => to_retransmit = pkts,
                                                                                        Err(_) => failed = true,
                                                                                    }
                                                                                }

                                                                                if failed {
                                                                                    tracing::warn!("Max retransmissions exceeded for {}. Closing session.", conn_id);
                                                                                    close_notify.notify_waiters();
                                                                                    session_mgr_retx.remove(&conn_id).await;
                                                                                    break;
                                                                                }

                                                                                for pkt in to_retransmit {
                                                                                    if let Ok(encoded) = crate::protocol::encode_packet(&pkt) {
                                                                                        let _ = socket_retx.send_to(&encoded, peer_addr).await;
                                                                                    }
                                                                                }
                                                                            }
                                                                            _ = close_notify.notified() => {
                                                                                break;
                                                                            }
                                                                        }
                                                                    }
                                                                });
                                                            }
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
                                                        let session_handle_opt =
                                                            read_session_mgr.lookup(&conn_id).await;
                                                        if session_handle_opt.is_none() {
                                                            return;
                                                        }
                                                        let session_handle =
                                                            session_handle_opt.unwrap();
                                                        let send_state_arc =
                                                            session_handle.send_state;
                                                        let receive_state_arc =
                                                            session_handle.receive_state;
                                                        let window_notify =
                                                            session_handle.window_notify;
                                                        let close_notify =
                                                            session_handle.close_notify;

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

                                                                    // Wait for window space
                                                                    loop {
                                                                        let can_send = {
                                                                            let state =
                                                                                send_state_arc
                                                                                    .lock()
                                                                                    .await;
                                                                            state.can_send()
                                                                        };
                                                                        if can_send {
                                                                            break;
                                                                        }

                                                                        tokio::select! {
                                                                            _ = window_notify.notified() => {},
                                                                            _ = close_notify.notified() => {
                                                                                tracing::info!("Session closed, stopping local TCP reader for {}", conn_id);
                                                                                return;
                                                                            }
                                                                        }
                                                                    }

                                                                    let seq = {
                                                                        let mut state =
                                                                            send_state_arc
                                                                                .lock()
                                                                                .await;
                                                                        state.next_seq()
                                                                    };

                                                                    let current_ack = {
                                                                        let state =
                                                                            receive_state_arc
                                                                                .lock()
                                                                                .await;
                                                                        state.generate_ack()
                                                                    };

                                                                    if let Ok(mut data_packet) =
                                                                        Packet::try_new(
                                                                            PacketType::Data,
                                                                            FLAG_ENCRYPTED,
                                                                            conn_id,
                                                                            seq,
                                                                            current_ack,
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

                                                                            {
                                                                                let mut state =
                                                                                    send_state_arc
                                                                                        .lock()
                                                                                        .await;
                                                                                state.save_unacked(
                                                                                    seq,
                                                                                    data_packet
                                                                                        .clone(),
                                                                                );
                                                                            }

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
                                                        let next_seq = {
                                                            let mut state =
                                                                send_state_arc.lock().await;
                                                            state.next_seq()
                                                        };
                                                        if let Ok(mut close_packet) =
                                                            Packet::try_new(
                                                                PacketType::Close,
                                                                FLAG_ENCRYPTED,
                                                                conn_id,
                                                                next_seq,
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

    if let Some(socks5_addr) = socks5 {
        tracing::info!("Setting up SOCKS5 listener on {}", socks5_addr);
        let listener = TcpListener::bind(&socks5_addr).await?;
        let socket_clone = Arc::clone(&socket);
        let id_gen_clone = Arc::clone(&id_generator);
        let secret_clone = Arc::clone(&secret_arc);
        let session_mgr_clone = session_manager.clone();
        let server_addr_clone = server_addr;

        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut tcp_stream, peer_addr)) => {
                        let conn_id = id_gen_clone.next();
                        tracing::info!(
                            "Accepted SOCKS5 connection from {} (ConnId: {})",
                            peer_addr,
                            conn_id
                        );

                        let socket_inner = Arc::clone(&socket_clone);
                        let secret_inner = Arc::clone(&secret_clone);
                        let session_mgr_inner = session_mgr_clone.clone();

                        tokio::spawn(async move {
                            use crate::socks5::{
                                handle_socks5_greeting, handle_socks5_request, send_socks5_failure,
                                send_socks5_success,
                            };

                            if let Err(e) = handle_socks5_greeting(&mut tcp_stream).await {
                                tracing::warn!("SOCKS5 greeting failed: {}", e);
                                return;
                            }

                            let target = match handle_socks5_request(&mut tcp_stream).await {
                                Ok(t) => t,
                                Err(e) => {
                                    tracing::warn!("SOCKS5 request failed: {}", e);
                                    return;
                                }
                            };

                            let target_str = target.to_string();
                            tracing::info!("SOCKS5 routing ConnId: {} to {}", conn_id, target_str);

                            let payload_str = format!(
                                "target={}\ntimestamp_ms={}",
                                target_str,
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
                                    let key = derive_key(&secret_inner);
                                    let aad = build_aad(&packet.header);

                                    match encrypt_payload(&payload, &key, &aad) {
                                        Ok(encrypted_payload) => {
                                            packet.payload = encrypted_payload.clone();
                                            packet.header.payload_len =
                                                encrypted_payload.len() as u16;

                                            let (mut read_half, mut write_half) =
                                                tcp_stream.into_split();
                                            let (tx, mut rx) = mpsc::channel::<Bytes>(1024);
                                            let (hs_tx, hs_rx) = tokio::sync::oneshot::channel();

                                            use crate::reliability::{ReceiveState, SendState};
                                            use tokio::sync::{Mutex, Notify};

                                            session_mgr_inner
                                                .insert_pending(
                                                    conn_id,
                                                    SessionHandle {
                                                        sender: tx,
                                                        state: SessionState::Pending,
                                                        send_state: Arc::new(Mutex::new(
                                                            SendState::new(1024),
                                                        )),
                                                        receive_state: Arc::new(Mutex::new(
                                                            ReceiveState::new(1024),
                                                        )),
                                                        window_notify: Arc::new(Notify::new()),
                                                        close_notify: Arc::new(Notify::new()),
                                                        peer_addr: server_addr_clone,
                                                    },
                                                    hs_tx,
                                                )
                                                .await;

                                            match encode_packet(&packet) {
                                                Ok(encoded) => {
                                                    if let Err(e) = socket_inner
                                                        .send_to(&encoded, server_addr_clone)
                                                        .await
                                                    {
                                                        tracing::error!(
                                                            "Failed to send UDP packet: {}",
                                                            e
                                                        );
                                                        session_mgr_inner.remove(&conn_id).await;
                                                        let _ = send_socks5_failure(&mut write_half, crate::socks5::REP_COMMAND_NOT_SUPPORTED).await;
                                                    } else {
                                                        tracing::info!(
                                                            "Sent OpenConnection packet for SOCKS5 {} to server",
                                                            conn_id
                                                        );

                                                        let handshake_result =
                                                            tokio::time::timeout(
                                                                std::time::Duration::from_secs(5),
                                                                hs_rx,
                                                            )
                                                            .await;

                                                        match handshake_result {
                                                            Ok(Ok(true)) => {
                                                                tracing::info!(
                                                                    "SOCKS5 Handshake successful for {}",
                                                                    conn_id
                                                                );
                                                                session_mgr_inner
                                                                    .establish(&conn_id)
                                                                    .await;

                                                                // Spawn retransmission task for SOCKS5
                                                                if let Some(session) =
                                                                    session_mgr_inner
                                                                        .lookup(&conn_id)
                                                                        .await
                                                                {
                                                                    let send_state_arc =
                                                                        session.send_state.clone();
                                                                    let close_notify = session
                                                                        .close_notify
                                                                        .clone();
                                                                    let peer_addr =
                                                                        session.peer_addr;
                                                                    let socket_retx =
                                                                        Arc::clone(&socket_inner);
                                                                    let session_mgr_retx =
                                                                        session_mgr_inner.clone();

                                                                    tokio::spawn(async move {
                                                                        loop {
                                                                            tokio::select! {
                                                                                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                                                                                    let now = std::time::Instant::now();
                                                                                    let mut to_retransmit = Vec::new();
                                                                                    let mut failed = false;

                                                                                    {
                                                                                        let mut state = send_state_arc.lock().await;
                                                                                        match state.get_timed_out_packets(now) {
                                                                                            Ok(pkts) => to_retransmit = pkts,
                                                                                            Err(_) => failed = true,
                                                                                        }
                                                                                    }

                                                                                    if failed {
                                                                                        tracing::warn!("Max retransmissions exceeded for SOCKS5 {}. Closing session.", conn_id);
                                                                                        close_notify.notify_waiters();
                                                                                        session_mgr_retx.remove(&conn_id).await;
                                                                                        break;
                                                                                    }

                                                                                    for pkt in to_retransmit {
                                                                                        if let Ok(encoded) = crate::protocol::encode_packet(&pkt) {
                                                                                            let _ = socket_retx.send_to(&encoded, peer_addr).await;
                                                                                        }
                                                                                    }
                                                                                }
                                                                                _ = close_notify.notified() => {
                                                                                    break;
                                                                                }
                                                                            }
                                                                        }
                                                                    });
                                                                }

                                                                if let Err(e) = send_socks5_success(
                                                                    &mut write_half,
                                                                )
                                                                .await
                                                                {
                                                                    tracing::warn!(
                                                                        "Failed to send SOCKS5 success: {}",
                                                                        e
                                                                    );
                                                                    session_mgr_inner
                                                                        .remove(&conn_id)
                                                                        .await;
                                                                    return;
                                                                }
                                                            }
                                                            _ => {
                                                                tracing::warn!(
                                                                    "SOCKS5 Handshake failed/timeout for {}",
                                                                    conn_id
                                                                );
                                                                session_mgr_inner
                                                                    .remove(&conn_id)
                                                                    .await;
                                                                let _ = send_socks5_failure(&mut write_half, crate::socks5::REP_COMMAND_NOT_SUPPORTED).await;
                                                                return;
                                                            }
                                                        }

                                                        let read_socket = Arc::clone(&socket_inner);
                                                        let read_session_mgr =
                                                            session_mgr_inner.clone();
                                                        let read_secret_clone =
                                                            secret_inner.clone();

                                                        tokio::spawn(async move {
                                                            let mut tcp_buf = vec![0u8; 1200];

                                                            let session_handle_opt =
                                                                read_session_mgr
                                                                    .lookup(&conn_id)
                                                                    .await;
                                                            if session_handle_opt.is_none() {
                                                                return;
                                                            }
                                                            let session_handle =
                                                                session_handle_opt.unwrap();
                                                            let send_state_arc =
                                                                session_handle.send_state;
                                                            let receive_state_arc =
                                                                session_handle.receive_state;
                                                            let window_notify =
                                                                session_handle.window_notify;
                                                            let close_notify =
                                                                session_handle.close_notify;

                                                            let read_key =
                                                                derive_key(&read_secret_clone);

                                                            loop {
                                                                match read_half
                                                                    .read(&mut tcp_buf)
                                                                    .await
                                                                {
                                                                    Ok(0) => {
                                                                        tracing::info!(
                                                                            "Local SOCKS5 TCP EOF for {}",
                                                                            conn_id
                                                                        );
                                                                        break;
                                                                    }
                                                                    Ok(n) => {
                                                                        let plaintext =
                                                                            &tcp_buf[..n];

                                                                        loop {
                                                                            let can_send = {
                                                                                let state =
                                                                                    send_state_arc
                                                                                        .lock()
                                                                                        .await;
                                                                                state.can_send()
                                                                            };
                                                                            if can_send {
                                                                                break;
                                                                            }

                                                                            tokio::select! {
                                                                                _ = window_notify.notified() => {},
                                                                                _ = close_notify.notified() => {
                                                                                    tracing::info!("Session closed, stopping local SOCKS5 TCP reader for {}", conn_id);
                                                                                    return;
                                                                                }
                                                                            }
                                                                        }

                                                                        let seq = {
                                                                            let mut state =
                                                                                send_state_arc
                                                                                    .lock()
                                                                                    .await;
                                                                            state.next_seq()
                                                                        };

                                                                        let current_ack = {
                                                                            let state =
                                                                                receive_state_arc
                                                                                    .lock()
                                                                                    .await;
                                                                            state.generate_ack()
                                                                        };

                                                                        if let Ok(mut data_packet) =
                                                                            Packet::try_new(
                                                                                PacketType::Data,
                                                                                FLAG_ENCRYPTED,
                                                                                conn_id,
                                                                                seq,
                                                                                current_ack,
                                                                                0,
                                                                                Bytes::new(),
                                                                            )
                                                                        {
                                                                            let data_aad =
                                                                                build_aad(
                                                                                    &data_packet
                                                                                        .header,
                                                                                );
                                                                            if let Ok(
                                                                                encrypted_data,
                                                                            ) = encrypt_payload(
                                                                                plaintext,
                                                                                &read_key,
                                                                                &data_aad,
                                                                            ) {
                                                                                data_packet
                                                                                    .payload =
                                                                                    encrypted_data
                                                                                        .clone();
                                                                                data_packet
                                                                                    .header
                                                                                    .payload_len =
                                                                                    encrypted_data
                                                                                        .len()
                                                                                        as u16;

                                                                                {
                                                                                    let mut state = send_state_arc.lock().await;
                                                                                    state.save_unacked(seq, data_packet.clone());
                                                                                }

                                                                                if let Ok(encoded) = encode_packet(&data_packet)
                                                                                    && let Err(e) = read_socket.send_to(&encoded, server_addr_clone).await {
                                                                                        tracing::warn!("Failed to send SOCKS5 Data packet: {}", e);
                                                                                    }
                                                                            }
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        tracing::error!(
                                                                            "Failed to read from local SOCKS5 TCP: {}",
                                                                            e
                                                                        );
                                                                        break;
                                                                    }
                                                                }
                                                            }

                                                            read_session_mgr.remove(&conn_id).await;
                                                            let next_seq = {
                                                                let mut state =
                                                                    send_state_arc.lock().await;
                                                                state.next_seq()
                                                            };
                                                            if let Ok(mut close_packet) =
                                                                Packet::try_new(
                                                                    PacketType::Close,
                                                                    FLAG_ENCRYPTED,
                                                                    conn_id,
                                                                    next_seq,
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
                                                                    close_packet
                                                                        .header
                                                                        .payload_len =
                                                                        encrypted_close.len()
                                                                            as u16;
                                                                    if let Ok(encoded) =
                                                                        encode_packet(&close_packet)
                                                                    {
                                                                        let _ = read_socket
                                                                            .send_to(
                                                                                &encoded,
                                                                                server_addr_clone,
                                                                            )
                                                                            .await;
                                                                    }
                                                                }
                                                            }
                                                        });

                                                        tokio::spawn(async move {
                                                            while let Some(data) = rx.recv().await {
                                                                if let Err(e) = write_half
                                                                    .write_all(&data)
                                                                    .await
                                                                {
                                                                    tracing::error!(
                                                                        "Failed to write to local SOCKS5 TCP: {}",
                                                                        e
                                                                    );
                                                                    break;
                                                                }
                                                            }
                                                            let _ = write_half.shutdown().await;
                                                            tracing::debug!(
                                                                "Local SOCKS5 TCP writer task exiting for {}",
                                                                conn_id
                                                            );
                                                        });
                                                    }
                                                }
                                                Err(e) => {
                                                    tracing::error!(
                                                        "Failed to encode SOCKS5 packet: {}",
                                                        e
                                                    );
                                                    session_mgr_inner.remove(&conn_id).await;
                                                }
                                            }
                                        }
                                        Err(e) => tracing::error!(
                                            "Failed to encrypt SOCKS5 OpenConnection payload: {}",
                                            e
                                        ),
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("Failed to construct SOCKS5 packet: {}", e)
                                }
                            }
                        });
                    }
                    Err(e) => tracing::error!("Error accepting SOCKS5 connection: {}", e),
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
#[allow(clippy::collapsible_if)]
pub async fn run_tcp(
    server: String,
    secret: String,
    map: Vec<PortMap>,
    socks5: Option<SocketAddr>,
) -> anyhow::Result<()> {
    tracing::info!("Initializing TCP client, mapping {} ports", map.len());

    let mut addrs = lookup_host(&server).await?;
    let server_addr = addrs
        .next()
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve server address: {}", server))?;
    tracing::info!("Resolved server address to {}", server_addr);

    // Connect to server TCP
    let tcp_stream = TcpStream::connect(server_addr).await?;
    let (mut read_half, mut write_half) = tcp_stream.into_split();

    let id_generator = Arc::new(ConnectionIdGenerator::new());
    let secret_arc = Arc::new(secret);
    let session_manager = ClientSessionManager::new();

    let mut tasks = vec![];

    // Central TCP transport MPSC channel
    let (tx_out, mut rx_out) = mpsc::channel::<Bytes>(1024);

    // Spawn central TCP writer task
    let writer_task = tokio::spawn(async move {
        while let Some(data) = rx_out.recv().await {
            if let Err(e) = write_frame(&mut write_half, &data).await {
                tracing::error!("Failed to write to TCP server: {}", e);
                break;
            }
        }
        let _ = write_half.shutdown().await;
        tracing::debug!("TCP client writer task exiting");
    });
    tasks.push(writer_task);

    // Spawn central TCP reader task
    let session_mgr_recv = session_manager.clone();
    let secret_recv_clone = Arc::clone(&secret_arc);
    let tx_out_recv = tx_out.clone();
    let recv_task = tokio::spawn(async move {
        loop {
            match read_frame(&mut read_half).await {
                Ok(frame_data) => {
                    let mut data = BytesMut::from(&frame_data[..]);
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
                                    let tx_out_ack = tx_out_recv.clone();

                                    tokio::spawn(async move {
                                        match decrypt_payload(&payload, &read_key, &aad) {
                                            Ok(plaintext) => {
                                                if let Some(session) =
                                                    session_mgr.lookup(&conn_id).await
                                                {
                                                    let sequence = packet.header.sequence;

                                                    let delivered_payloads = {
                                                        let mut state =
                                                            session.receive_state.lock().await;
                                                        state.receive_packet(sequence, plaintext)
                                                    };

                                                    for payload in delivered_payloads {
                                                        if let Err(e) =
                                                            session.sender.send(payload).await
                                                        {
                                                            tracing::warn!(
                                                                "Failed to forward data to local TCP writer task: {}",
                                                                e
                                                            );
                                                        }
                                                    }

                                                    let ack_num = {
                                                        let state =
                                                            session.receive_state.lock().await;
                                                        state.generate_ack()
                                                    };

                                                    if let Ok(mut ack_packet) = Packet::try_new(
                                                        PacketType::Ack,
                                                        FLAG_ENCRYPTED,
                                                        conn_id,
                                                        0,
                                                        ack_num,
                                                        0,
                                                        Bytes::new(),
                                                    ) {
                                                        let ack_aad = build_aad(&ack_packet.header);
                                                        let ack_payload =
                                                            crate::payload::build_ack_payload();
                                                        if let Ok(encrypted_ack) = encrypt_payload(
                                                            ack_payload.as_bytes(),
                                                            &read_key,
                                                            &ack_aad,
                                                        ) {
                                                            ack_packet.payload =
                                                                encrypted_ack.clone();
                                                            ack_packet.header.payload_len =
                                                                encrypted_ack.len() as u16;
                                                            if let Ok(encoded) =
                                                                encode_packet(&ack_packet)
                                                            {
                                                                let _ = tx_out_ack
                                                                    .send(Bytes::from(encoded))
                                                                    .await;
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    use crate::session::UnknownState;
                                                    match session_mgr.check_unknown(&conn_id).await
                                                    {
                                                        UnknownState::RecentlyClosed => {
                                                            tracing::debug!(
                                                                "Dropping late Data packet for recently closed ConnectionId: {}",
                                                                conn_id
                                                            );
                                                        }
                                                        UnknownState::RateLimited => {
                                                            tracing::debug!(
                                                                "Dropping repeated Data packet for unknown ConnectionId: {}",
                                                                conn_id
                                                            );
                                                        }
                                                        UnknownState::WarnFirstTime => {
                                                            tracing::warn!(
                                                                "Received Data packet for unknown ConnectionId: {}",
                                                                conn_id
                                                            );
                                                        }
                                                    }
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
                                        tracing::debug!(
                                            "Received Ack packet for ConnectionId: {}, ack={}",
                                            conn_id,
                                            packet.header.ack
                                        );

                                        if let Some(session) = session_mgr.lookup(&conn_id).await {
                                            {
                                                let mut state = session.send_state.lock().await;
                                                state.handle_ack(packet.header.ack);
                                            }
                                            session.window_notify.notify_waiters();

                                            if session.state == SessionState::Pending {
                                                session_mgr
                                                    .complete_handshake(&conn_id, true)
                                                    .await;
                                            }
                                        } else {
                                            use crate::session::UnknownState;
                                            match session_mgr.check_unknown(&conn_id).await {
                                                UnknownState::RecentlyClosed => {
                                                    tracing::debug!(
                                                        "Dropping late Ack packet for recently closed ConnectionId: {}",
                                                        conn_id
                                                    );
                                                }
                                                UnknownState::RateLimited => {
                                                    tracing::debug!(
                                                        "Dropping repeated Ack packet for unknown ConnectionId: {}",
                                                        conn_id
                                                    );
                                                }
                                                UnknownState::WarnFirstTime => {
                                                    tracing::warn!(
                                                        "Received Ack packet for unknown ConnectionId: {}",
                                                        conn_id
                                                    );
                                                }
                                            }
                                        }
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
                                        if session_mgr.lookup(&conn_id).await.is_some() {
                                            tracing::info!(
                                                "Received Close packet for ConnectionId: {}",
                                                conn_id
                                            );
                                            session_mgr.remove(&conn_id).await;
                                        } else {
                                            use crate::session::UnknownState;
                                            match session_mgr.check_unknown(&conn_id).await {
                                                UnknownState::RecentlyClosed => {
                                                    tracing::debug!(
                                                        "Dropping late Close packet for recently closed ConnectionId: {}",
                                                        conn_id
                                                    );
                                                }
                                                UnknownState::RateLimited => {
                                                    tracing::debug!(
                                                        "Dropping repeated Close packet for unknown ConnectionId: {}",
                                                        conn_id
                                                    );
                                                }
                                                UnknownState::WarnFirstTime => {
                                                    tracing::warn!(
                                                        "Received Close packet for unknown ConnectionId: {}",
                                                        conn_id
                                                    );
                                                }
                                            }
                                        }
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
                            tracing::warn!(error = %e, "Malformed packet received");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("TCP connection read error: {}", e);
                    break;
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
        let tx_out_clone = tx_out.clone();
        let id_gen_clone = Arc::clone(&id_generator);
        let secret_clone = Arc::clone(&secret_arc);
        let session_mgr_clone = session_manager.clone();

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
                                        let (s_tx, mut s_rx) = mpsc::channel::<Bytes>(1024);
                                        let (hs_tx, hs_rx) = tokio::sync::oneshot::channel();

                                        use crate::reliability::{ReceiveState, SendState};
                                        use tokio::sync::{Mutex, Notify};

                                        session_mgr_clone
                                            .insert_pending(
                                                conn_id,
                                                SessionHandle {
                                                    sender: s_tx,
                                                    state: SessionState::Pending,
                                                    send_state: Arc::new(Mutex::new(
                                                        SendState::new(1024),
                                                    )),
                                                    receive_state: Arc::new(Mutex::new(
                                                        ReceiveState::new(1024),
                                                    )),
                                                    window_notify: Arc::new(Notify::new()),
                                                    close_notify: Arc::new(Notify::new()),
                                                    peer_addr: server_addr,
                                                },
                                                hs_tx,
                                            )
                                            .await;

                                        match encode_packet(&packet) {
                                            Ok(encoded) => {
                                                if let Err(e) =
                                                    tx_out_clone.send(Bytes::from(encoded)).await
                                                {
                                                    tracing::error!(
                                                        "Failed to send OpenConnection to writer: {}",
                                                        e
                                                    );
                                                    session_mgr_clone.remove(&conn_id).await;
                                                } else {
                                                    tracing::info!(
                                                        "Sent OpenConnection packet for {} to server",
                                                        conn_id
                                                    );

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

                                                            if let Some(session) = session_mgr_clone
                                                                .lookup(&conn_id)
                                                                .await
                                                            {
                                                                let send_state_arc =
                                                                    session.send_state.clone();
                                                                let close_notify =
                                                                    session.close_notify.clone();
                                                                let tx_out_retx =
                                                                    tx_out_clone.clone();
                                                                let session_mgr_retx =
                                                                    session_mgr_clone.clone();

                                                                tokio::spawn(async move {
                                                                    loop {
                                                                        tokio::select! {
                                                                            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                                                                                let now = std::time::Instant::now();
                                                                                let mut to_retransmit = Vec::new();
                                                                                let mut failed = false;

                                                                                {
                                                                                    let mut state = send_state_arc.lock().await;
                                                                                    match state.get_timed_out_packets(now) {
                                                                                        Ok(pkts) => to_retransmit = pkts,
                                                                                        Err(_) => failed = true,
                                                                                    }
                                                                                }

                                                                                if failed {
                                                                                    tracing::warn!("Max retransmissions exceeded for {}. Closing session.", conn_id);
                                                                                    close_notify.notify_waiters();
                                                                                    session_mgr_retx.remove(&conn_id).await;
                                                                                    break;
                                                                                }

                                                                                for pkt in to_retransmit {
                                                                                    if let Ok(encoded) = crate::protocol::encode_packet(&pkt) {
                                                                                        let _ = tx_out_retx.send(Bytes::from(encoded)).await;
                                                                                    }
                                                                                }
                                                                            }
                                                                            _ = close_notify.notified() => {
                                                                                break;
                                                                            }
                                                                        }
                                                                    }
                                                                });
                                                            }
                                                        }
                                                        _ => {
                                                            tracing::warn!(
                                                                "Handshake failed/timeout for ConnectionId: {}",
                                                                conn_id
                                                            );
                                                            session_mgr_clone
                                                                .remove(&conn_id)
                                                                .await;
                                                            return;
                                                        }
                                                    }

                                                    let read_tx_out = tx_out_clone.clone();
                                                    let read_session_mgr =
                                                        session_mgr_clone.clone();
                                                    let read_secret_clone = secret_clone.clone();

                                                    tokio::spawn(async move {
                                                        let mut tcp_buf = vec![0u8; 1200];
                                                        let session_handle_opt =
                                                            read_session_mgr.lookup(&conn_id).await;
                                                        if session_handle_opt.is_none() {
                                                            return;
                                                        }
                                                        let session_handle =
                                                            session_handle_opt.unwrap();
                                                        let send_state_arc =
                                                            session_handle.send_state;
                                                        let receive_state_arc =
                                                            session_handle.receive_state;
                                                        let window_notify =
                                                            session_handle.window_notify;
                                                        let close_notify =
                                                            session_handle.close_notify;

                                                        let read_key =
                                                            derive_key(&read_secret_clone);

                                                        loop {
                                                            match read_half.read(&mut tcp_buf).await
                                                            {
                                                                Ok(0) => {
                                                                    tracing::info!(
                                                                        "Local TCP EOF for {}",
                                                                        conn_id
                                                                    );
                                                                    break;
                                                                }
                                                                Ok(n) => {
                                                                    let plaintext = &tcp_buf[..n];

                                                                    loop {
                                                                        let can_send = {
                                                                            let state =
                                                                                send_state_arc
                                                                                    .lock()
                                                                                    .await;
                                                                            state.can_send()
                                                                        };
                                                                        if can_send {
                                                                            break;
                                                                        }
                                                                        tokio::select! {
                                                                            _ = window_notify.notified() => {},
                                                                            _ = close_notify.notified() => {
                                                                                tracing::info!("Session closed, stopping local TCP reader for {}", conn_id);
                                                                                return;
                                                                            }
                                                                        }
                                                                    }

                                                                    let seq = {
                                                                        let mut state =
                                                                            send_state_arc
                                                                                .lock()
                                                                                .await;
                                                                        state.next_seq()
                                                                    };

                                                                    let current_ack = {
                                                                        let state =
                                                                            receive_state_arc
                                                                                .lock()
                                                                                .await;
                                                                        state.generate_ack()
                                                                    };

                                                                    if let Ok(mut data_packet) =
                                                                        Packet::try_new(
                                                                            PacketType::Data,
                                                                            FLAG_ENCRYPTED,
                                                                            conn_id,
                                                                            seq,
                                                                            current_ack,
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

                                                                            {
                                                                                let mut state =
                                                                                    send_state_arc
                                                                                        .lock()
                                                                                        .await;
                                                                                state.save_unacked(
                                                                                    seq,
                                                                                    data_packet
                                                                                        .clone(),
                                                                                );
                                                                            }

                                                                            if let Ok(encoded) =
                                                                                encode_packet(
                                                                                    &data_packet,
                                                                                )
                                                                            {
                                                                                if let Err(e) = read_tx_out.send(Bytes::from(encoded)).await {
                                                                                    tracing::warn!("Failed to send Data packet to server: {}", e);
                                                                                }
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

                                                        read_session_mgr.remove(&conn_id).await;
                                                        let next_seq = {
                                                            let mut state =
                                                                send_state_arc.lock().await;
                                                            state.next_seq()
                                                        };
                                                        if let Ok(mut close_packet) =
                                                            Packet::try_new(
                                                                PacketType::Close,
                                                                FLAG_ENCRYPTED,
                                                                conn_id,
                                                                next_seq,
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
                                                                    let _ = read_tx_out
                                                                        .send(Bytes::from(encoded))
                                                                        .await;
                                                                }
                                                            }
                                                        }
                                                    });

                                                    tokio::spawn(async move {
                                                        while let Some(data) = s_rx.recv().await {
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

    if let Some(socks5_addr) = socks5 {
        tracing::info!("Setting up SOCKS5 listener on {}", socks5_addr);
        let listener = TcpListener::bind(&socks5_addr).await?;
        let tx_out_clone = tx_out.clone();
        let id_gen_clone = Arc::clone(&id_generator);
        let secret_clone = Arc::clone(&secret_arc);
        let session_mgr_clone = session_manager.clone();

        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut tcp_stream, peer_addr)) => {
                        let conn_id = id_gen_clone.next();
                        tracing::info!(
                            "Accepted SOCKS5 connection from {} (ConnId: {})",
                            peer_addr,
                            conn_id
                        );

                        let tx_out_inner = tx_out_clone.clone();
                        let secret_inner = Arc::clone(&secret_clone);
                        let session_mgr_inner = session_mgr_clone.clone();

                        tokio::spawn(async move {
                            use crate::socks5::{
                                handle_socks5_greeting, handle_socks5_request, send_socks5_failure,
                                send_socks5_success,
                            };

                            if let Err(e) = handle_socks5_greeting(&mut tcp_stream).await {
                                tracing::warn!("SOCKS5 greeting failed: {}", e);
                                return;
                            }

                            let target = match handle_socks5_request(&mut tcp_stream).await {
                                Ok(t) => t,
                                Err(e) => {
                                    tracing::warn!("SOCKS5 request failed: {}", e);
                                    return;
                                }
                            };

                            let target_str = target.to_string();
                            tracing::info!("SOCKS5 routing ConnId: {} to {}", conn_id, target_str);

                            let payload_str = format!(
                                "target={}\ntimestamp_ms={}",
                                target_str,
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
                                    let key = derive_key(&secret_inner);
                                    let aad = build_aad(&packet.header);

                                    match encrypt_payload(&payload, &key, &aad) {
                                        Ok(encrypted_payload) => {
                                            packet.payload = encrypted_payload.clone();
                                            packet.header.payload_len =
                                                encrypted_payload.len() as u16;

                                            let (mut read_half, mut write_half) =
                                                tcp_stream.into_split();
                                            let (s_tx, mut s_rx) = mpsc::channel::<Bytes>(1024);
                                            let (hs_tx, hs_rx) = tokio::sync::oneshot::channel();

                                            use crate::reliability::{ReceiveState, SendState};
                                            use tokio::sync::{Mutex, Notify};

                                            session_mgr_inner
                                                .insert_pending(
                                                    conn_id,
                                                    SessionHandle {
                                                        sender: s_tx,
                                                        state: SessionState::Pending,
                                                        send_state: Arc::new(Mutex::new(
                                                            SendState::new(1024),
                                                        )),
                                                        receive_state: Arc::new(Mutex::new(
                                                            ReceiveState::new(1024),
                                                        )),
                                                        window_notify: Arc::new(Notify::new()),
                                                        close_notify: Arc::new(Notify::new()),
                                                        peer_addr: server_addr, // The peer_addr in session_mgr isn't strictly used for TCP since we route by channel, but required
                                                    },
                                                    hs_tx,
                                                )
                                                .await;

                                            match encode_packet(&packet) {
                                                Ok(encoded) => {
                                                    if let Err(e) = tx_out_inner
                                                        .send(Bytes::from(encoded))
                                                        .await
                                                    {
                                                        tracing::error!(
                                                            "Failed to send UDP packet: {}",
                                                            e
                                                        );
                                                        session_mgr_inner.remove(&conn_id).await;
                                                        let _ = send_socks5_failure(&mut write_half, crate::socks5::REP_COMMAND_NOT_SUPPORTED).await;
                                                    } else {
                                                        tracing::info!(
                                                            "Sent OpenConnection packet for SOCKS5 {} to server",
                                                            conn_id
                                                        );

                                                        let handshake_result =
                                                            tokio::time::timeout(
                                                                std::time::Duration::from_secs(5),
                                                                hs_rx,
                                                            )
                                                            .await;

                                                        match handshake_result {
                                                            Ok(Ok(true)) => {
                                                                tracing::info!(
                                                                    "SOCKS5 Handshake successful for {}",
                                                                    conn_id
                                                                );
                                                                session_mgr_inner
                                                                    .establish(&conn_id)
                                                                    .await;

                                                                if let Some(session) =
                                                                    session_mgr_inner
                                                                        .lookup(&conn_id)
                                                                        .await
                                                                {
                                                                    let send_state_arc =
                                                                        session.send_state.clone();
                                                                    let close_notify = session
                                                                        .close_notify
                                                                        .clone();
                                                                    let tx_out_retx =
                                                                        tx_out_inner.clone();
                                                                    let session_mgr_retx =
                                                                        session_mgr_inner.clone();

                                                                    tokio::spawn(async move {
                                                                        loop {
                                                                            tokio::select! {
                                                                                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                                                                                    let now = std::time::Instant::now();
                                                                                    let mut to_retransmit = Vec::new();
                                                                                    let mut failed = false;

                                                                                    {
                                                                                        let mut state = send_state_arc.lock().await;
                                                                                        match state.get_timed_out_packets(now) {
                                                                                            Ok(pkts) => to_retransmit = pkts,
                                                                                            Err(_) => failed = true,
                                                                                        }
                                                                                    }

                                                                                    if failed {
                                                                                        tracing::warn!("Max retransmissions exceeded for SOCKS5 {}. Closing session.", conn_id);
                                                                                        close_notify.notify_waiters();
                                                                                        session_mgr_retx.remove(&conn_id).await;
                                                                                        break;
                                                                                    }

                                                                                    for pkt in to_retransmit {
                                                                                        if let Ok(encoded) = crate::protocol::encode_packet(&pkt) {
                                                                                            let _ = tx_out_retx.send(Bytes::from(encoded)).await;
                                                                                        }
                                                                                    }
                                                                                }
                                                                                _ = close_notify.notified() => {
                                                                                    break;
                                                                                }
                                                                            }
                                                                        }
                                                                    });
                                                                }

                                                                if let Err(e) = send_socks5_success(
                                                                    &mut write_half,
                                                                )
                                                                .await
                                                                {
                                                                    tracing::warn!(
                                                                        "Failed to send SOCKS5 success: {}",
                                                                        e
                                                                    );
                                                                    session_mgr_inner
                                                                        .remove(&conn_id)
                                                                        .await;
                                                                    return;
                                                                }
                                                            }
                                                            _ => {
                                                                tracing::warn!(
                                                                    "SOCKS5 Handshake failed/timeout for {}",
                                                                    conn_id
                                                                );
                                                                session_mgr_inner
                                                                    .remove(&conn_id)
                                                                    .await;
                                                                let _ = send_socks5_failure(&mut write_half, crate::socks5::REP_COMMAND_NOT_SUPPORTED).await;
                                                                return;
                                                            }
                                                        }

                                                        let read_tx_out = tx_out_inner.clone();
                                                        let read_session_mgr =
                                                            session_mgr_inner.clone();
                                                        let read_secret_clone =
                                                            secret_inner.clone();

                                                        tokio::spawn(async move {
                                                            let mut tcp_buf = vec![0u8; 1200];

                                                            let session_handle_opt =
                                                                read_session_mgr
                                                                    .lookup(&conn_id)
                                                                    .await;
                                                            if session_handle_opt.is_none() {
                                                                return;
                                                            }
                                                            let session_handle =
                                                                session_handle_opt.unwrap();
                                                            let send_state_arc =
                                                                session_handle.send_state;
                                                            let receive_state_arc =
                                                                session_handle.receive_state;
                                                            let window_notify =
                                                                session_handle.window_notify;
                                                            let close_notify =
                                                                session_handle.close_notify;

                                                            let read_key =
                                                                derive_key(&read_secret_clone);

                                                            loop {
                                                                match read_half
                                                                    .read(&mut tcp_buf)
                                                                    .await
                                                                {
                                                                    Ok(0) => {
                                                                        tracing::info!(
                                                                            "Local SOCKS5 TCP EOF for {}",
                                                                            conn_id
                                                                        );
                                                                        break;
                                                                    }
                                                                    Ok(n) => {
                                                                        let plaintext =
                                                                            &tcp_buf[..n];

                                                                        loop {
                                                                            let can_send = {
                                                                                let state =
                                                                                    send_state_arc
                                                                                        .lock()
                                                                                        .await;
                                                                                state.can_send()
                                                                            };
                                                                            if can_send {
                                                                                break;
                                                                            }

                                                                            tokio::select! {
                                                                                _ = window_notify.notified() => {},
                                                                                _ = close_notify.notified() => {
                                                                                    tracing::info!("Session closed, stopping local SOCKS5 TCP reader for {}", conn_id);
                                                                                    return;
                                                                                }
                                                                            }
                                                                        }

                                                                        let seq = {
                                                                            let mut state =
                                                                                send_state_arc
                                                                                    .lock()
                                                                                    .await;
                                                                            state.next_seq()
                                                                        };

                                                                        let current_ack = {
                                                                            let state =
                                                                                receive_state_arc
                                                                                    .lock()
                                                                                    .await;
                                                                            state.generate_ack()
                                                                        };

                                                                        if let Ok(mut data_packet) =
                                                                            Packet::try_new(
                                                                                PacketType::Data,
                                                                                FLAG_ENCRYPTED,
                                                                                conn_id,
                                                                                seq,
                                                                                current_ack,
                                                                                0,
                                                                                Bytes::new(),
                                                                            )
                                                                        {
                                                                            let data_aad =
                                                                                build_aad(
                                                                                    &data_packet
                                                                                        .header,
                                                                                );
                                                                            if let Ok(
                                                                                encrypted_data,
                                                                            ) = encrypt_payload(
                                                                                plaintext,
                                                                                &read_key,
                                                                                &data_aad,
                                                                            ) {
                                                                                data_packet
                                                                                    .payload =
                                                                                    encrypted_data
                                                                                        .clone();
                                                                                data_packet
                                                                                    .header
                                                                                    .payload_len =
                                                                                    encrypted_data
                                                                                        .len()
                                                                                        as u16;

                                                                                {
                                                                                    let mut state = send_state_arc.lock().await;
                                                                                    state.save_unacked(seq, data_packet.clone());
                                                                                }

                                                                                if let Ok(encoded) = encode_packet(&data_packet) {
                                                                                    if let Err(e) = read_tx_out.send(Bytes::from(encoded)).await {
                                                                                        tracing::warn!("Failed to send SOCKS5 Data packet: {}", e);
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        tracing::error!(
                                                                            "Failed to read from local SOCKS5 TCP: {}",
                                                                            e
                                                                        );
                                                                        break;
                                                                    }
                                                                }
                                                            }

                                                            read_session_mgr.remove(&conn_id).await;
                                                            let next_seq = {
                                                                let mut state =
                                                                    send_state_arc.lock().await;
                                                                state.next_seq()
                                                            };
                                                            if let Ok(mut close_packet) =
                                                                Packet::try_new(
                                                                    PacketType::Close,
                                                                    FLAG_ENCRYPTED,
                                                                    conn_id,
                                                                    next_seq,
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
                                                                    close_packet
                                                                        .header
                                                                        .payload_len =
                                                                        encrypted_close.len()
                                                                            as u16;
                                                                    if let Ok(encoded) =
                                                                        encode_packet(&close_packet)
                                                                    {
                                                                        let _ = read_tx_out
                                                                            .send(Bytes::from(
                                                                                encoded,
                                                                            ))
                                                                            .await;
                                                                    }
                                                                }
                                                            }
                                                        });

                                                        tokio::spawn(async move {
                                                            while let Some(data) = s_rx.recv().await
                                                            {
                                                                if let Err(e) = write_half
                                                                    .write_all(&data)
                                                                    .await
                                                                {
                                                                    tracing::error!(
                                                                        "Failed to write to local SOCKS5 TCP: {}",
                                                                        e
                                                                    );
                                                                    break;
                                                                }
                                                            }
                                                            let _ = write_half.shutdown().await;
                                                            tracing::debug!(
                                                                "Local SOCKS5 TCP writer task exiting for {}",
                                                                conn_id
                                                            );
                                                        });
                                                    }
                                                }
                                                Err(e) => {
                                                    tracing::error!(
                                                        "Failed to encode SOCKS5 packet: {}",
                                                        e
                                                    );
                                                    session_mgr_inner.remove(&conn_id).await;
                                                }
                                            }
                                        }
                                        Err(e) => tracing::error!(
                                            "Failed to encrypt SOCKS5 OpenConnection payload: {}",
                                            e
                                        ),
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("Failed to construct SOCKS5 packet: {}", e)
                                }
                            }
                        });
                    }
                    Err(e) => tracing::error!("Error accepting SOCKS5 connection: {}", e),
                }
            }
        });
        tasks.push(handle);
    }

    for handle in tasks {
        let _ = handle.await;
    }

    Ok(())
}
