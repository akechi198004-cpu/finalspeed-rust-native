use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{RwLock, mpsc};

use crate::cli::TransportMode;
use crate::crypto::{
    build_aad, decrypt_payload, derive_key, encrypt_payload, validate_timestamp_ms,
};
use crate::framing::{read_frame, write_frame};
use crate::packet::{FLAG_ENCRYPTED, Packet, PacketType};
use crate::payload::{build_ack_payload, build_error_payload, parse_open_connection_payload};
use crate::protocol::{decode_packet, encode_packet};
use crate::session::{ServerSessionManager, SessionHandle, SessionState};
use crate::transport::{ConnectionRoute, ConnectionTable};

#[allow(clippy::collapsible_if)]
pub async fn validate_open_connection_packet(
    packet: &Packet,
    peer_addr: SocketAddr,
    secret: &str,
    allowlist: Option<&[SocketAddr]>,
) -> Result<String, String> {
    if packet.header.flags & FLAG_ENCRYPTED == 0 {
        tracing::warn!(peer_addr = %peer_addr, "OpenConnection missing FLAG_ENCRYPTED");
        return Err("Missing FLAG_ENCRYPTED".to_string());
    }

    let key = derive_key(secret);
    let aad = build_aad(&packet.header);
    let decrypted = decrypt_payload(&packet.payload, &key, &aad).map_err(|e| e.to_string())?;

    let payload = parse_open_connection_payload(&decrypted).map_err(|e| e.to_string())?;

    validate_timestamp_ms(payload.timestamp_ms).map_err(|e| {
        tracing::warn!(peer_addr = %peer_addr, "OpenConnection timestamp validation failed");
        e.to_string()
    })?;

    if let Some(allowed) = allowlist {
        let is_allowed = match payload.target.parse::<SocketAddr>() {
            Ok(addr) => allowed.contains(&addr),
            Err(_) => false, // Reject domain targets if an allowlist is configured
        };

        if !is_allowed {
            tracing::warn!(
                peer_addr = %peer_addr,
                target = %payload.target,
                "Target not in allowlist or domain target rejected by allowlist policy"
            );
            return Err("Target not allowed".to_string());
        }
    }

    Ok(payload.target)
}

pub async fn run(
    listen: SocketAddr,
    secret: String,
    allow: Option<Vec<SocketAddr>>,
    transport: TransportMode,
) -> anyhow::Result<()> {
    match transport {
        TransportMode::Udp => run_udp(listen, secret, allow).await,
        TransportMode::Tcp => run_tcp(listen, secret, allow).await,
    }
}

#[allow(clippy::collapsible_if)]
pub async fn run_udp(
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
                                    match TcpStream::connect(target_addr.clone()).await {
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

                                            use crate::reliability::{ReceiveState, SendState};
                                            use tokio::sync::{Mutex, Notify};

                                            // Register session
                                            session_mgr_clone
                                                .insert(
                                                    conn_id,
                                                    SessionHandle {
                                                        sender: tx,
                                                        state: SessionState::Established,
                                                        send_state: Arc::new(Mutex::new(
                                                            SendState::new(1024),
                                                        )),
                                                        receive_state: Arc::new(Mutex::new(
                                                            ReceiveState::new(1024),
                                                        )),
                                                        window_notify: Arc::new(Notify::new()),
                                                        close_notify: Arc::new(Notify::new()),
                                                        peer_addr: peer,
                                                    },
                                                )
                                                .await;

                                            // Spawn retransmission task for Server
                                            if let Some(session) =
                                                session_mgr_clone.lookup(&conn_id).await
                                            {
                                                let send_state_arc = session.send_state.clone();
                                                let close_notify = session.close_notify.clone();
                                                let peer_addr = session.peer_addr;
                                                let socket_retx = Arc::clone(&socket_clone);
                                                let session_mgr_retx = session_mgr_clone.clone();

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
                                                                    tracing::warn!("Max retransmissions exceeded for Server {}. Closing session.", conn_id);
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

                                            // Send Ack payload
                                            let key = derive_key(&secret_ref);
                                            if let Ok(mut ack_packet) = Packet::try_new(
                                                PacketType::Ack,
                                                FLAG_ENCRYPTED,
                                                conn_id,
                                                0,
                                                0,
                                                0,
                                                Bytes::new(),
                                            ) {
                                                let ack_payload = build_ack_payload();
                                                let aad = build_aad(&ack_packet.header);
                                                if let Ok(encrypted_ack) = encrypt_payload(
                                                    ack_payload.as_bytes(),
                                                    &key,
                                                    &aad,
                                                ) {
                                                    ack_packet.payload = encrypted_ack.clone();
                                                    ack_packet.header.payload_len =
                                                        encrypted_ack.len() as u16;

                                                    if let Ok(encoded) = encode_packet(&ack_packet)
                                                    {
                                                        let _ = socket_clone
                                                            .send_to(&encoded, peer)
                                                            .await;
                                                    }
                                                }
                                            }

                                            // Spawn TCP -> UDP reader task
                                            let read_socket = Arc::clone(&socket_clone);
                                            let read_table = Arc::clone(&conn_table_clone);
                                            let read_session_mgr = session_mgr_clone.clone();
                                            let read_key = derive_key(&secret_ref);
                                            tokio::spawn(async move {
                                                let mut tcp_buf = vec![0u8; 1200];

                                                let session_handle_opt =
                                                    read_session_mgr.lookup(&conn_id).await;
                                                if session_handle_opt.is_none() {
                                                    return;
                                                }
                                                let session_handle = session_handle_opt.unwrap();
                                                let send_state_arc = session_handle.send_state;
                                                let receive_state_arc =
                                                    session_handle.receive_state;
                                                let window_notify = session_handle.window_notify;
                                                let close_notify = session_handle.close_notify;

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
                                                            let plaintext = &tcp_buf[..n];

                                                            // Wait for window space
                                                            loop {
                                                                let can_send = {
                                                                    let state =
                                                                        send_state_arc.lock().await;
                                                                    state.can_send()
                                                                };
                                                                if can_send {
                                                                    break;
                                                                }

                                                                tokio::select! {
                                                                    _ = window_notify.notified() => {},
                                                                    _ = close_notify.notified() => {
                                                                        tracing::info!("Session closed, stopping server TCP reader for {}", conn_id);
                                                                        return;
                                                                    }
                                                                }
                                                            }

                                                            let seq = {
                                                                let mut state =
                                                                    send_state_arc.lock().await;
                                                                state.next_seq()
                                                            };

                                                            let current_ack = {
                                                                let state =
                                                                    receive_state_arc.lock().await;
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
                                                                let aad =
                                                                    build_aad(&data_packet.header);
                                                                if let Ok(encrypted_payload) =
                                                                    encrypt_payload(
                                                                        plaintext, &read_key, &aad,
                                                                    )
                                                                {
                                                                    data_packet.payload =
                                                                        encrypted_payload.clone();
                                                                    data_packet
                                                                        .header
                                                                        .payload_len =
                                                                        encrypted_payload.len()
                                                                            as u16;

                                                                    {
                                                                        let mut state =
                                                                            send_state_arc
                                                                                .lock()
                                                                                .await;
                                                                        state.save_unacked(
                                                                            seq,
                                                                            data_packet.clone(),
                                                                        );
                                                                    }

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
                                                                } else {
                                                                    tracing::error!(
                                                                        "Failed to encrypt Data payload"
                                                                    );
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
                                                let next_seq = {
                                                    let mut state = send_state_arc.lock().await;
                                                    state.next_seq()
                                                };
                                                if let Ok(mut close_packet) = Packet::try_new(
                                                    PacketType::Close,
                                                    FLAG_ENCRYPTED,
                                                    conn_id,
                                                    next_seq,
                                                    0,
                                                    0,
                                                    Bytes::new(),
                                                ) {
                                                    let aad = build_aad(&close_packet.header);
                                                    if let Ok(encrypted_payload) =
                                                        encrypt_payload(b"", &read_key, &aad)
                                                    {
                                                        close_packet.payload =
                                                            encrypted_payload.clone();
                                                        close_packet.header.payload_len =
                                                            encrypted_payload.len() as u16;
                                                        if let Ok(encoded) =
                                                            encode_packet(&close_packet)
                                                        {
                                                            let _ = read_socket
                                                                .send_to(&encoded, peer)
                                                                .await;
                                                        }
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
                                            // Send encrypted Error payload
                                            let key = derive_key(&secret_ref);
                                            if let Ok(mut err_packet) = Packet::try_new(
                                                PacketType::Error,
                                                FLAG_ENCRYPTED,
                                                conn_id,
                                                0,
                                                0,
                                                0,
                                                Bytes::new(),
                                            ) {
                                                let err_payload =
                                                    build_error_payload("Target connect failed");
                                                let aad = build_aad(&err_packet.header);
                                                if let Ok(encrypted_err) = encrypt_payload(
                                                    err_payload.as_bytes(),
                                                    &key,
                                                    &aad,
                                                ) {
                                                    err_packet.payload = encrypted_err.clone();
                                                    err_packet.header.payload_len =
                                                        encrypted_err.len() as u16;

                                                    if let Ok(encoded) = encode_packet(&err_packet)
                                                    {
                                                        let _ = socket_clone
                                                            .send_to(&encoded, peer)
                                                            .await;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to handle OpenConnection from {}: {}",
                                        peer,
                                        e
                                    );
                                    // Send encrypted Error payload
                                    let key = derive_key(&secret_ref);
                                    if let Ok(mut err_packet) = Packet::try_new(
                                        PacketType::Error,
                                        FLAG_ENCRYPTED,
                                        conn_id,
                                        0,
                                        0,
                                        0,
                                        Bytes::new(),
                                    ) {
                                        let err_payload = build_error_payload(&e);
                                        let aad = build_aad(&err_packet.header);
                                        if let Ok(encrypted_err) =
                                            encrypt_payload(err_payload.as_bytes(), &key, &aad)
                                        {
                                            err_packet.payload = encrypted_err.clone();
                                            err_packet.header.payload_len =
                                                encrypted_err.len() as u16;

                                            if let Ok(encoded) = encode_packet(&err_packet) {
                                                let _ = socket_clone.send_to(&encoded, peer).await;
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    }
                    PacketType::Ack => {
                        if packet.header.flags & FLAG_ENCRYPTED == 0 {
                            tracing::warn!(peer_address = %peer, "Ack packet missing FLAG_ENCRYPTED, dropping");
                            continue;
                        }

                        let read_key = derive_key(&secret_ref);
                        let aad = build_aad(&packet.header);
                        let payload_encrypted = packet.payload.clone();

                        tokio::spawn(async move {
                            if let Err(e) = decrypt_payload(&payload_encrypted, &read_key, &aad) {
                                tracing::warn!(
                                    peer_address = %peer,
                                    error = %e,
                                    "Failed to decrypt Ack payload"
                                );
                                return;
                            }

                            tracing::debug!(
                                "Received Ack packet for ConnectionId: {}, ack={}",
                                conn_id,
                                packet.header.ack
                            );

                            if let Some(session) = session_mgr_clone.lookup(&conn_id).await {
                                {
                                    let mut state = session.send_state.lock().await;
                                    state.handle_ack(packet.header.ack);
                                }
                                session.window_notify.notify_waiters();
                            } else {
                                tracing::warn!(
                                    "Received Ack for unknown ConnectionId: {}",
                                    conn_id
                                );
                            }
                        });
                    }
                    PacketType::Data => {
                        if packet.header.flags & FLAG_ENCRYPTED == 0 {
                            tracing::warn!(peer_address = %peer, "Data packet missing FLAG_ENCRYPTED, dropping");
                            continue;
                        }

                        let read_key = derive_key(&secret_ref);
                        let aad = build_aad(&packet.header);
                        let payload_encrypted = packet.payload.clone();

                        let socket_ack = Arc::clone(&socket);
                        tokio::spawn(async move {
                            match decrypt_payload(&payload_encrypted, &read_key, &aad) {
                                Ok(plaintext) => {
                                    if let Some(session) = session_mgr_clone.lookup(&conn_id).await
                                    {
                                        let sequence = packet.header.sequence;

                                        // Pass to ReceiveState
                                        let delivered_payloads = {
                                            let mut state = session.receive_state.lock().await;
                                            state.receive_packet(sequence, plaintext)
                                        };

                                        for payload in delivered_payloads {
                                            if let Err(e) = session.sender.send(payload).await {
                                                tracing::warn!(
                                                    "Failed to forward data to session writer task: {}",
                                                    e
                                                );
                                            }
                                        }

                                        // Generate and send Ack
                                        let ack_num = {
                                            let state = session.receive_state.lock().await;
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
                                            let ack_payload = crate::payload::build_ack_payload();
                                            if let Ok(encrypted_ack) = encrypt_payload(
                                                ack_payload.as_bytes(),
                                                &read_key,
                                                &ack_aad,
                                            ) {
                                                ack_packet.payload = encrypted_ack.clone();
                                                ack_packet.header.payload_len =
                                                    encrypted_ack.len() as u16;
                                                if let Ok(encoded) = encode_packet(&ack_packet) {
                                                    let _ = socket_ack
                                                        .send_to(&encoded, session.peer_addr)
                                                        .await;
                                                }
                                            }
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
                                        peer_address = %peer,
                                        error = %e,
                                        "Failed to decrypt Data payload"
                                    );
                                }
                            }
                        });
                    }
                    PacketType::Close => {
                        if packet.header.flags & FLAG_ENCRYPTED == 0 {
                            tracing::warn!(peer_address = %peer, "Close packet missing FLAG_ENCRYPTED, dropping");
                            continue;
                        }

                        let read_key = derive_key(&secret_ref);
                        let aad = build_aad(&packet.header);
                        let payload_encrypted = packet.payload.clone();

                        tokio::spawn(async move {
                            if let Err(e) = decrypt_payload(&payload_encrypted, &read_key, &aad) {
                                tracing::warn!(
                                    peer_address = %peer,
                                    error = %e,
                                    "Failed to decrypt Close payload"
                                );
                                return;
                            }

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

    use crate::crypto::{build_aad, current_timestamp_ms, derive_key, encrypt_payload};

    fn create_encrypted_open_packet(target_addr: &str, secret: &str, valid_ts: bool) -> Packet {
        let ts = if valid_ts {
            current_timestamp_ms()
        } else {
            current_timestamp_ms() - 600_000 // Expired
        };
        let payload_str = format!("target={}\ntimestamp_ms={}", target_addr, ts);

        let mut packet = Packet::try_new(
            PacketType::OpenConnection,
            FLAG_ENCRYPTED,
            ConnectionId(1),
            0,
            0,
            0,
            Bytes::new(),
        )
        .unwrap();

        let key = derive_key(secret);
        let aad = build_aad(&packet.header);
        let encrypted = encrypt_payload(payload_str.as_bytes(), &key, &aad).unwrap();

        packet.payload = encrypted.clone();
        packet.header.payload_len = encrypted.len() as u16;
        packet
    }

    #[tokio::test]
    async fn test_validate_open_connection_success() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = listener.local_addr().unwrap();

        let packet = create_encrypted_open_packet(&target_addr.to_string(), "test123", true);
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let result = validate_open_connection_packet(&packet, peer_addr, "test123", None).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), target_addr.to_string());
    }

    #[tokio::test]
    async fn test_validate_open_connection_missing_flag() {
        let mut packet = create_encrypted_open_packet("127.0.0.1:80", "test123", true);
        packet.header.flags = 0; // Remove flag
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let result = validate_open_connection_packet(&packet, peer_addr, "test123", None).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Missing FLAG_ENCRYPTED");
    }

    #[tokio::test]
    async fn test_validate_open_connection_secret_mismatch() {
        // Encrypt with wrong secret
        let packet = create_encrypted_open_packet("192.168.1.1:80", "wrong_secret", true);
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let result = validate_open_connection_packet(&packet, peer_addr, "test123", None).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_open_connection_timestamp_expired() {
        let packet = create_encrypted_open_packet("192.168.1.1:80", "test123", false); // false = expired
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let result = validate_open_connection_packet(&packet, peer_addr, "test123", None).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_open_connection_allowlist_success() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = listener.local_addr().unwrap();

        let packet = create_encrypted_open_packet(&target_addr.to_string(), "test123", true);
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let result =
            validate_open_connection_packet(&packet, peer_addr, "test123", Some(&[target_addr]))
                .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), target_addr.to_string());
    }

    #[tokio::test]
    async fn test_validate_open_connection_allowlist_reject() {
        let allowed_addr: SocketAddr = "192.168.1.1:80".parse().unwrap();
        let packet = create_encrypted_open_packet("10.0.0.1:22", "test123", true);
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let result =
            validate_open_connection_packet(&packet, peer_addr, "test123", Some(&[allowed_addr]))
                .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Target not allowed");
    }
}
#[allow(clippy::collapsible_if)]
pub async fn run_tcp(
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

    let listener = TcpListener::bind(listen).await?;
    tracing::info!("Server TCP listener bound to {}", listen);

    let connection_table = Arc::new(RwLock::new(ConnectionTable::new()));
    let session_manager = ServerSessionManager::new();

    loop {
        match listener.accept().await {
            Ok((tcp_stream, peer)) => {
                tracing::info!("Accepted TCP connection from {}", peer);

                let allow_clone = allow.clone();
                let secret_ref = secret.clone();
                let conn_table_clone = Arc::clone(&connection_table);
                let session_mgr_clone = session_manager.clone();

                // We split the TCP stream. The read_half is passed to the reader loop,
                // and the write_half is moved to a dedicated writer task.
                let (mut read_half, mut write_half) = tcp_stream.into_split();

                // MPSC channel for sending frames back to this specific client connection.
                let (tx_out, mut rx_out) = mpsc::channel::<Bytes>(1024);

                // Spawn writer task for this TCP connection
                tokio::spawn(async move {
                    while let Some(data) = rx_out.recv().await {
                        if let Err(e) = write_frame(&mut write_half, &data).await {
                            tracing::error!("Failed to write frame to TCP client {}: {}", peer, e);
                            break;
                        }
                    }
                    let _ = write_half.shutdown().await;
                    tracing::debug!("TCP client writer task exiting for {}", peer);
                });

                // Spawn reader task for this TCP connection
                tokio::spawn(async move {
                    loop {
                        match read_frame(&mut read_half).await {
                            Ok(frame_data) => {
                                let mut data = BytesMut::from(&frame_data[..]);
                                match decode_packet(&mut data) {
                                    Ok(Some(packet)) => {
                                        tracing::debug!(
                                            peer_address = %peer,
                                            packet_type = ?packet.header.packet_type,
                                            connection_id = packet.header.connection_id.0,
                                            sequence = packet.header.sequence,
                                            "Received valid packet over TCP"
                                        );

                                        let allow_c = allow_clone.clone();
                                        let secret_c = secret_ref.clone();
                                        let tx_out_c = tx_out.clone();
                                        let conn_table_c = Arc::clone(&conn_table_clone);
                                        let session_mgr_c = session_mgr_clone.clone();
                                        let packet_type = packet.header.packet_type.clone();
                                        let conn_id = packet.header.connection_id;

                                        match packet_type {
                                            PacketType::OpenConnection => {
                                                let packet_clone = packet.clone();
                                                tokio::spawn(async move {
                                                    match validate_open_connection_packet(
                                                        &packet_clone,
                                                        peer,
                                                        &secret_c,
                                                        allow_c.as_deref(),
                                                    )
                                                    .await
                                                    {
                                                        Ok(target_addr) => {
                                                            tracing::info!(
                                                                "Attempting TCP connection to target: {}",
                                                                target_addr
                                                            );
                                                            match TcpStream::connect(
                                                                target_addr.clone(),
                                                            )
                                                            .await
                                                            {
                                                                Ok(target_stream) => {
                                                                    tracing::info!(
                                                                        "Successfully connected to target: {}",
                                                                        target_addr
                                                                    );

                                                                    let route = ConnectionRoute {
                                                                        peer_addr: peer,
                                                                        target_addr,
                                                                    };
                                                                    {
                                                                        let mut table =
                                                                            conn_table_c
                                                                                .write()
                                                                                .await;
                                                                        table
                                                                            .insert(conn_id, route);
                                                                    }

                                                                    let (
                                                                        mut t_read_half,
                                                                        mut t_write_half,
                                                                    ) = target_stream.into_split();
                                                                    let (s_tx, mut s_rx) =
                                                                        mpsc::channel::<Bytes>(
                                                                            1024,
                                                                        );

                                                                    use crate::reliability::{
                                                                        ReceiveState, SendState,
                                                                    };
                                                                    use tokio::sync::{
                                                                        Mutex, Notify,
                                                                    };

                                                                    session_mgr_c.insert(
                                                                        conn_id,
                                                                        SessionHandle {
                                                                            sender: s_tx,
                                                                            state: SessionState::Established,
                                                                            send_state: Arc::new(Mutex::new(SendState::new(1024))),
                                                                            receive_state: Arc::new(Mutex::new(ReceiveState::new(1024))),
                                                                            window_notify: Arc::new(Notify::new()),
                                                                            close_notify: Arc::new(Notify::new()),
                                                                            peer_addr: peer,
                                                                        },
                                                                    ).await;

                                                                    // For TCP transport, we still spawn the retransmission task to keep code minimally changed,
                                                                    // but it sends frames instead of datagrams.
                                                                    if let Some(session) =
                                                                        session_mgr_c
                                                                            .lookup(&conn_id)
                                                                            .await
                                                                    {
                                                                        let send_state_arc =
                                                                            session
                                                                                .send_state
                                                                                .clone();
                                                                        let close_notify = session
                                                                            .close_notify
                                                                            .clone();
                                                                        let session_mgr_retx =
                                                                            session_mgr_c.clone();
                                                                        let tx_out_retx =
                                                                            tx_out_c.clone();

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
                                                                                            tracing::warn!("Max retransmissions exceeded for Server TCP {}. Closing session.", conn_id);
                                                                                            close_notify.notify_waiters();
                                                                                            session_mgr_retx.remove(&conn_id).await;
                                                                                            break;
                                                                                        }

                                                                                        for pkt in to_retransmit {
                                                                                            if let Ok(encoded) = encode_packet(&pkt) {
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

                                                                    // Send Ack payload
                                                                    let key = derive_key(&secret_c);
                                                                    if let Ok(mut ack_packet) =
                                                                        Packet::try_new(
                                                                            PacketType::Ack,
                                                                            FLAG_ENCRYPTED,
                                                                            conn_id,
                                                                            0,
                                                                            0,
                                                                            0,
                                                                            Bytes::new(),
                                                                        )
                                                                    {
                                                                        let ack_payload =
                                                                            build_ack_payload();
                                                                        let aad = build_aad(
                                                                            &ack_packet.header,
                                                                        );
                                                                        if let Ok(encrypted_ack) =
                                                                            encrypt_payload(
                                                                                ack_payload
                                                                                    .as_bytes(),
                                                                                &key,
                                                                                &aad,
                                                                            )
                                                                        {
                                                                            ack_packet.payload =
                                                                                encrypted_ack
                                                                                    .clone();
                                                                            ack_packet
                                                                                .header
                                                                                .payload_len =
                                                                                encrypted_ack.len()
                                                                                    as u16;

                                                                            if let Ok(encoded) =
                                                                                encode_packet(
                                                                                    &ack_packet,
                                                                                )
                                                                            {
                                                                                let _ = tx_out_c
                                                                                    .send(
                                                                                        Bytes::from(
                                                                                            encoded,
                                                                                        ),
                                                                                    )
                                                                                    .await;
                                                                            }
                                                                        }
                                                                    }

                                                                    // Spawn Target TCP -> Transport TCP reader task
                                                                    let read_tx_out =
                                                                        tx_out_c.clone();
                                                                    let read_table =
                                                                        Arc::clone(&conn_table_c);
                                                                    let read_session_mgr =
                                                                        session_mgr_c.clone();
                                                                    let read_key =
                                                                        derive_key(&secret_c);

                                                                    tokio::spawn(async move {
                                                                        let mut tcp_buf =
                                                                            vec![0u8; 1200];

                                                                        let session_handle_opt =
                                                                            read_session_mgr
                                                                                .lookup(&conn_id)
                                                                                .await;
                                                                        if session_handle_opt
                                                                            .is_none()
                                                                        {
                                                                            return;
                                                                        }
                                                                        let session_handle =
                                                                            session_handle_opt
                                                                                .unwrap();
                                                                        let send_state_arc =
                                                                            session_handle
                                                                                .send_state;
                                                                        let receive_state_arc =
                                                                            session_handle
                                                                                .receive_state;
                                                                        let window_notify =
                                                                            session_handle
                                                                                .window_notify;
                                                                        let close_notify =
                                                                            session_handle
                                                                                .close_notify;

                                                                        loop {
                                                                            match t_read_half
                                                                                .read(&mut tcp_buf)
                                                                                .await
                                                                            {
                                                                                Ok(0) => {
                                                                                    tracing::info!(
                                                                                        "Server target TCP EOF for {}",
                                                                                        conn_id
                                                                                    );
                                                                                    break;
                                                                                }
                                                                                Ok(n) => {
                                                                                    let plaintext =
                                                                                        &tcp_buf
                                                                                            [..n];

                                                                                    loop {
                                                                                        let can_send = {
                                                                                            let state = send_state_arc.lock().await;
                                                                                            state.can_send()
                                                                                        };
                                                                                        if can_send
                                                                                        {
                                                                                            break;
                                                                                        }
                                                                                        tokio::select! {
                                                                                            _ = window_notify.notified() => {},
                                                                                            _ = close_notify.notified() => {
                                                                                                tracing::info!("Session closed, stopping server TCP reader for {}", conn_id);
                                                                                                return;
                                                                                            }
                                                                                        }
                                                                                    }

                                                                                    let seq = {
                                                                                        let mut state = send_state_arc.lock().await;
                                                                                        state.next_seq()
                                                                                    };

                                                                                    let current_ack = {
                                                                                        let state = receive_state_arc.lock().await;
                                                                                        state.generate_ack()
                                                                                    };

                                                                                    if let Ok(mut data_packet) = Packet::try_new(PacketType::Data, FLAG_ENCRYPTED, conn_id, seq, current_ack, 0, Bytes::new()) {
                                                                                        let aad = build_aad(&data_packet.header);
                                                                                        if let Ok(encrypted_payload) = encrypt_payload(plaintext, &read_key, &aad) {
                                                                                            data_packet.payload = encrypted_payload.clone();
                                                                                            data_packet.header.payload_len = encrypted_payload.len() as u16;

                                                                                            {
                                                                                                let mut state = send_state_arc.lock().await;
                                                                                                state.save_unacked(seq, data_packet.clone());
                                                                                            }

                                                                                            if let Ok(encoded) = encode_packet(&data_packet) {
                                                                                                if let Err(e) = read_tx_out.send(Bytes::from(encoded)).await {
                                                                                                    tracing::warn!("Failed to send Data packet to TCP client: {}", e);
                                                                                                }
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

                                                                        read_session_mgr
                                                                            .remove(&conn_id)
                                                                            .await;
                                                                        {
                                                                            let mut table =
                                                                                read_table
                                                                                    .write()
                                                                                    .await;
                                                                            table.remove(&conn_id);
                                                                        }

                                                                        let next_seq = {
                                                                            let mut state =
                                                                                send_state_arc
                                                                                    .lock()
                                                                                    .await;
                                                                            state.next_seq()
                                                                        };
                                                                        if let Ok(
                                                                            mut close_packet,
                                                                        ) = Packet::try_new(
                                                                            PacketType::Close,
                                                                            FLAG_ENCRYPTED,
                                                                            conn_id,
                                                                            next_seq,
                                                                            0,
                                                                            0,
                                                                            Bytes::new(),
                                                                        ) {
                                                                            let aad = build_aad(
                                                                                &close_packet
                                                                                    .header,
                                                                            );
                                                                            if let Ok(
                                                                                encrypted_payload,
                                                                            ) = encrypt_payload(
                                                                                b"", &read_key,
                                                                                &aad,
                                                                            ) {
                                                                                close_packet.payload = encrypted_payload.clone();
                                                                                close_packet.header.payload_len = encrypted_payload.len() as u16;
                                                                                if let Ok(encoded) = encode_packet(&close_packet) {
                                                                                    let _ = read_tx_out.send(Bytes::from(encoded)).await;
                                                                                }
                                                                            }
                                                                        }
                                                                    });

                                                                    // Spawn Transport TCP -> Target TCP writer task
                                                                    tokio::spawn(async move {
                                                                        while let Some(data) =
                                                                            s_rx.recv().await
                                                                        {
                                                                            if let Err(e) =
                                                                                t_write_half
                                                                                    .write_all(
                                                                                        &data,
                                                                                    )
                                                                                    .await
                                                                            {
                                                                                tracing::error!(
                                                                                    "Failed to write to target TCP for {}: {}",
                                                                                    conn_id,
                                                                                    e
                                                                                );
                                                                                break;
                                                                            }
                                                                        }
                                                                        let _ = t_write_half
                                                                            .shutdown()
                                                                            .await;
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
                                                                    let key = derive_key(&secret_c);
                                                                    if let Ok(mut err_packet) =
                                                                        Packet::try_new(
                                                                            PacketType::Error,
                                                                            FLAG_ENCRYPTED,
                                                                            conn_id,
                                                                            0,
                                                                            0,
                                                                            0,
                                                                            Bytes::new(),
                                                                        )
                                                                    {
                                                                        let err_payload =
                                                                            build_error_payload(
                                                                                "Target connect failed",
                                                                            );
                                                                        let aad = build_aad(
                                                                            &err_packet.header,
                                                                        );
                                                                        if let Ok(encrypted_err) =
                                                                            encrypt_payload(
                                                                                err_payload
                                                                                    .as_bytes(),
                                                                                &key,
                                                                                &aad,
                                                                            )
                                                                        {
                                                                            err_packet.payload =
                                                                                encrypted_err
                                                                                    .clone();
                                                                            err_packet
                                                                                .header
                                                                                .payload_len =
                                                                                encrypted_err.len()
                                                                                    as u16;

                                                                            if let Ok(encoded) =
                                                                                encode_packet(
                                                                                    &err_packet,
                                                                                )
                                                                            {
                                                                                let _ = tx_out_c
                                                                                    .send(
                                                                                        Bytes::from(
                                                                                            encoded,
                                                                                        ),
                                                                                    )
                                                                                    .await;
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        Err(e) => {
                                                            tracing::warn!(
                                                                "Failed to handle OpenConnection from {}: {}",
                                                                peer,
                                                                e
                                                            );
                                                            let key = derive_key(&secret_c);
                                                            if let Ok(mut err_packet) =
                                                                Packet::try_new(
                                                                    PacketType::Error,
                                                                    FLAG_ENCRYPTED,
                                                                    conn_id,
                                                                    0,
                                                                    0,
                                                                    0,
                                                                    Bytes::new(),
                                                                )
                                                            {
                                                                let err_payload =
                                                                    build_error_payload(&e);
                                                                let aad =
                                                                    build_aad(&err_packet.header);
                                                                if let Ok(encrypted_err) =
                                                                    encrypt_payload(
                                                                        err_payload.as_bytes(),
                                                                        &key,
                                                                        &aad,
                                                                    )
                                                                {
                                                                    err_packet.payload =
                                                                        encrypted_err.clone();
                                                                    err_packet.header.payload_len =
                                                                        encrypted_err.len() as u16;

                                                                    if let Ok(encoded) =
                                                                        encode_packet(&err_packet)
                                                                    {
                                                                        let _ = tx_out_c
                                                                            .send(Bytes::from(
                                                                                encoded,
                                                                            ))
                                                                            .await;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                });
                                            }
                                            PacketType::Ack => {
                                                if packet.header.flags & FLAG_ENCRYPTED == 0 {
                                                    tracing::warn!(peer_address = %peer, "Ack packet missing FLAG_ENCRYPTED, dropping");
                                                    continue;
                                                }

                                                let read_key = derive_key(&secret_c);
                                                let aad = build_aad(&packet.header);
                                                let payload_encrypted = packet.payload.clone();

                                                tokio::spawn(async move {
                                                    if let Err(e) = decrypt_payload(
                                                        &payload_encrypted,
                                                        &read_key,
                                                        &aad,
                                                    ) {
                                                        tracing::warn!(peer_address = %peer, error = %e, "Failed to decrypt Ack payload");
                                                        return;
                                                    }

                                                    tracing::debug!(
                                                        "Received Ack packet for ConnectionId: {}, ack={}",
                                                        conn_id,
                                                        packet.header.ack
                                                    );

                                                    if let Some(session) =
                                                        session_mgr_c.lookup(&conn_id).await
                                                    {
                                                        {
                                                            let mut state =
                                                                session.send_state.lock().await;
                                                            state.handle_ack(packet.header.ack);
                                                        }
                                                        session.window_notify.notify_waiters();
                                                    } else {
                                                        tracing::warn!(
                                                            "Received Ack for unknown ConnectionId: {}",
                                                            conn_id
                                                        );
                                                    }
                                                });
                                            }
                                            PacketType::Data => {
                                                if packet.header.flags & FLAG_ENCRYPTED == 0 {
                                                    tracing::warn!(peer_address = %peer, "Data packet missing FLAG_ENCRYPTED, dropping");
                                                    continue;
                                                }

                                                let read_key = derive_key(&secret_c);
                                                let aad = build_aad(&packet.header);
                                                let payload_encrypted = packet.payload.clone();
                                                let tx_out_ack = tx_out_c.clone();

                                                tokio::spawn(async move {
                                                    match decrypt_payload(
                                                        &payload_encrypted,
                                                        &read_key,
                                                        &aad,
                                                    ) {
                                                        Ok(plaintext) => {
                                                            if let Some(session) =
                                                                session_mgr_c.lookup(&conn_id).await
                                                            {
                                                                let sequence =
                                                                    packet.header.sequence;

                                                                let delivered_payloads = {
                                                                    let mut state = session
                                                                        .receive_state
                                                                        .lock()
                                                                        .await;
                                                                    state.receive_packet(
                                                                        sequence, plaintext,
                                                                    )
                                                                };

                                                                for payload in delivered_payloads {
                                                                    if let Err(e) = session
                                                                        .sender
                                                                        .send(payload)
                                                                        .await
                                                                    {
                                                                        tracing::warn!(
                                                                            "Failed to forward data to session writer task: {}",
                                                                            e
                                                                        );
                                                                    }
                                                                }

                                                                let ack_num = {
                                                                    let state = session
                                                                        .receive_state
                                                                        .lock()
                                                                        .await;
                                                                    state.generate_ack()
                                                                };

                                                                if let Ok(mut ack_packet) =
                                                                    Packet::try_new(
                                                                        PacketType::Ack,
                                                                        FLAG_ENCRYPTED,
                                                                        conn_id,
                                                                        0,
                                                                        ack_num,
                                                                        0,
                                                                        Bytes::new(),
                                                                    )
                                                                {
                                                                    let ack_aad = build_aad(
                                                                        &ack_packet.header,
                                                                    );
                                                                    let ack_payload = crate::payload::build_ack_payload();
                                                                    if let Ok(encrypted_ack) =
                                                                        encrypt_payload(
                                                                            ack_payload.as_bytes(),
                                                                            &read_key,
                                                                            &ack_aad,
                                                                        )
                                                                    {
                                                                        ack_packet.payload =
                                                                            encrypted_ack.clone();
                                                                        ack_packet
                                                                            .header
                                                                            .payload_len =
                                                                            encrypted_ack.len()
                                                                                as u16;
                                                                        if let Ok(encoded) =
                                                                            encode_packet(
                                                                                &ack_packet,
                                                                            )
                                                                        {
                                                                            let _ = tx_out_ack
                                                                                .send(Bytes::from(
                                                                                    encoded,
                                                                                ))
                                                                                .await;
                                                                        }
                                                                    }
                                                                }
                                                            } else {
                                                                tracing::warn!(
                                                                    "Received Data packet for unknown ConnectionId: {}",
                                                                    conn_id
                                                                );
                                                            }
                                                        }
                                                        Err(e) => {
                                                            tracing::warn!(peer_address = %peer, error = %e, "Failed to decrypt Data payload");
                                                        }
                                                    }
                                                });
                                            }
                                            PacketType::Close => {
                                                if packet.header.flags & FLAG_ENCRYPTED == 0 {
                                                    tracing::warn!(peer_address = %peer, "Close packet missing FLAG_ENCRYPTED, dropping");
                                                    continue;
                                                }

                                                let read_key = derive_key(&secret_c);
                                                let aad = build_aad(&packet.header);
                                                let payload_encrypted = packet.payload.clone();

                                                tokio::spawn(async move {
                                                    if let Err(e) = decrypt_payload(
                                                        &payload_encrypted,
                                                        &read_key,
                                                        &aad,
                                                    ) {
                                                        tracing::warn!(peer_address = %peer, error = %e, "Failed to decrypt Close payload");
                                                        return;
                                                    }

                                                    tracing::info!(
                                                        "Received Close packet for ConnectionId: {}",
                                                        conn_id
                                                    );
                                                    session_mgr_c.remove(&conn_id).await;
                                                    {
                                                        let mut table = conn_table_c.write().await;
                                                        table.remove(&conn_id);
                                                    }
                                                });
                                            }
                                            _ => {
                                                tracing::warn!(
                                                    "Unhandled packet type: {:?}",
                                                    packet_type
                                                );
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
                            Err(e) => {
                                tracing::warn!("TCP connection read error from {}: {}", peer, e);
                                break;
                            }
                        }
                    }
                });
            }
            Err(e) => {
                tracing::warn!("Failed to accept TCP connection: {}", e);
            }
        }
    }
}
