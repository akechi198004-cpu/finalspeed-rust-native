# fspeed-rs

A Rust-native reliable UDP tunnel for accelerating TCP services.

## Current MVP Status (Phase 4.1)

This phase implements TCP port mapping endpoint establishment.

### What is implemented:
- Full `tokio`-based async binary skeleton.
- CLI argument parsing via `clap` supporting `client` and `server` subcommands.
- Custom Big-Endian binary packet layout for the UDP transport (`magic`, `version`, `packet_type`, `flags`, `connection_id`, `sequence`, `ack`, `window`, `payload_len`).
- Codec logic for encoding/decoding UDP datagrams with strict error checking.
- UDP socket transport skeleton is implemented.
- **Client Session Establishment:** Client binds a `TcpListener` per port mapping and successfully allocates per-connection `ClientSession` structures mapped to standard `OpenConnection` packets over UDP.
- **Server Session Establishment:** Server parses `OpenConnection` packets, validates the secret and optional allowlist limits, actively initiates connection to target TCP via `TcpStream::connect`, and successfully binds `ServerSession` instances.
- `ConnectionTable` dynamically tracks UDP endpoints.
- **Reliability State Machine Basis:** Core structs (sliding windows, send buffers, retransmission queues, cumulative ACKs) are implemented and successfully unit tested.

### What is NOT implemented yet:
- Reliable runtime loop: Binding the `ServerSession`/`ClientSession` to the UDP stream loops for full end-to-end TCP forwarding.
- QUIC
- Java wire-compatibility (This project defines a new Rust-native protocol).

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
