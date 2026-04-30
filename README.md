# fspeed-rs

A Rust-native reliable UDP tunnel for accelerating TCP services.

## Current MVP Status (Phase 4.2)

This phase implements a basic session manager and full-duplex TCP <-> UDP Data packet forwarding.

### What is implemented:
- Full `tokio`-based async binary skeleton.
- CLI argument parsing via `clap` supporting `client` and `server` subcommands.
- Custom Big-Endian binary packet layout for the UDP transport (`magic`, `version`, `packet_type`, `flags`, `connection_id`, `sequence`, `ack`, `window`, `payload_len`).
- Codec logic for encoding/decoding UDP datagrams with strict error checking.
- UDP socket transport skeleton is implemented.
- **Session Management:** Built `ClientSessionManager` and `ServerSessionManager` managing lock-free background access to independent connections via internal `mpsc` channels.
- **Client Session Forwarding:** Client accepts multiple local TCP connections concurrently. Each splits into concurrent Reader/Writer tasks, forwarding raw bytes securely via UDP using monotonically increasing sequence numbers inside `PacketType::Data` datagrams.
- **Server Session Forwarding:** Server strictly validates endpoint payloads before initiating target TCP connections autonomously. Concurrent target Read/Write tasks are spawned, maintaining duplex traffic back through the dynamic UDP port tracked by `ConnectionTable`.
- **Connection Teardown:** Handling of EOF/shutdowns propagating through `PacketType::Close` over UDP to cleanup routes on peer components appropriately.

### What is NOT implemented yet:
- **Full Reliable Runtime:** Basic forwarding transmits packets effectively but does not integrate full retransmission (`SendState` & `ReceiveState`) mechanisms yet.
- OpenConnection Acknowledgement / Initial Handshake sequence synchronization.
- QUIC
- Java wire-compatibility (This project intentionally defines a custom Rust-native protocol).

## Build Instructions

```bash
cargo build
cargo test
```

## CLI Examples

### Server Mode
Listen for incoming UDP tunnel traffic on port 150, allowing connections only to port 22 and 80 on localhost.
```bash
cargo run -- server --listen 0.0.0.0:150 --secret test123 --allow 127.0.0.1:22,127.0.0.1:80
```

### Client Mode
Forward local port 2222 to the target server's port 22 over the tunnel.
```bash
cargo run -- client --server 127.0.0.1:150 --secret test123 --map 127.0.0.1:2222=127.0.0.1:22
```
