use crate::config::PortMap;
use crate::packet::{Packet, PacketType};
use crate::protocol::encode_packet;
use crate::session::ClientSession;
use crate::transport::ConnectionIdGenerator;

use bytes::Bytes;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket, lookup_host};

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

    let mut listeners = vec![];

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

                                            // Create the client session context (Phase 4.1 basis)
                                            let _session = ClientSession {
                                                connection_id: conn_id,
                                                local_tcp: tcp_stream,
                                                target_addr: mapping.target,
                                            };
                                            // Future: start async loops for TCP->UDP and UDP->TCP using _session
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

        listeners.push(handle);
    }

    // Keep the client running as tasks are backgrounded
    for handle in listeners {
        let _ = handle.await;
    }

    Ok(())
}
