use crate::config::PortMap;
use crate::packet::{Packet, PacketType};
use crate::protocol::encode_packet;
use crate::transport::ConnectionIdGenerator;

use bytes::Bytes;
use tokio::net::{UdpSocket, lookup_host};

pub async fn run(server: String, secret: String, map: Vec<PortMap>) -> anyhow::Result<()> {
    tracing::info!("Initializing client, mapping {} ports", map.len());

    // Resolve server address
    let mut addrs = lookup_host(&server).await?;
    let server_addr = addrs
        .next()
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve server address: {}", server))?;
    tracing::info!("Resolved server address to {}", server_addr);

    // Bind local UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    tracing::info!("Client UDP socket bound to {}", socket.local_addr()?);

    let id_generator = ConnectionIdGenerator::new();

    for mapping in map {
        let conn_id = id_generator.next();
        tracing::info!(
            "Generated {} for mapping {} -> {}",
            conn_id,
            mapping.local,
            mapping.target
        );

        // Phase 2 temporary payload format
        let payload_str = format!("secret={}\ntarget={}", secret, mapping.target);
        let payload = Bytes::from(payload_str);

        let packet = Packet::try_new(PacketType::OpenConnection, 0, conn_id, 0, 0, 1024, payload)?;

        let encoded = encode_packet(&packet)?;

        // Send OpenConnection packet
        match socket.send_to(&encoded, server_addr).await {
            Ok(bytes_sent) => {
                tracing::info!(
                    "Sent OpenConnection test packet for {} ({} bytes)",
                    conn_id,
                    bytes_sent
                );
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to send UDP packet: {}", e));
            }
        }
    }

    // Since this is Phase 2 and we are only sending OpenConnection packets,
    // we don't start the TCP listeners yet. We just exit for now (or wait if needed).
    tracing::info!("Client sent all OpenConnection test packets. Exiting Phase 2 stub.");
    Ok(())
}
