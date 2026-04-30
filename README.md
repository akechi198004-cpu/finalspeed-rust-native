# fspeed-rs

A Rust-native reliable UDP tunnel for accelerating TCP services.

## Current MVP Status (Phase 3)

This phase implements the reliability runtime primitives based on `docs/rust-design.md`.

### What is implemented:
- Full `tokio`-based async binary skeleton.
- CLI argument parsing via `clap` supporting `client` and `server` subcommands.
- Custom Big-Endian binary packet layout for the UDP transport (`magic`, `version`, `packet_type`, `flags`, `connection_id`, `sequence`, `ack`, `window`, `payload_len`).
- Codec logic for encoding/decoding UDP datagrams with strict error checking.
- UDP socket transport skeleton is implemented.
- Client can send `OpenConnection` test packets.
- Server already parses `OpenConnection` temporary payload properly.
- Server successfully validates the shared secret.
- Server supports `--allow` target address allowlisting.
- `ConnectionTable` records both `peer_addr` and `target_addr` for accurate routing.
- **Reliability State Machine Basis**: implemented core structs and state transitions for sliding windows, send buffers, receive buffers (out-of-order handling), retransmission queues, and cumulative ACKs. Unit tests are provided for all these pieces.

### What is NOT implemented yet:
- Still no TCP port forwarding.
- Still no end-to-end tunnel tying the UDP packets to real TCP streams.
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
