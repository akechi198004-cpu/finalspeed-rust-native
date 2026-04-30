# fspeed-rs

A Rust-native reliable UDP tunnel for accelerating TCP services.

## Current MVP Status (Phase 1)

This phase establishes the foundational project structure, the custom binary packet codec, and the command-line interface based on `docs/rust-design.md`.

### What is implemented:
- Full `tokio`-based async binary skeleton.
- CLI argument parsing via `clap` supporting `client` and `server` subcommands.
    - Includes static TCP port mapping via `--map Local=Target`.
    - Includes `--allow` server flag which accepts a comma-separated list of `SocketAddr` targets.
- A clean, custom Big-Endian binary packet layout for the UDP transport (`magic`, `version`, `packet_type`, `flags`, `connection_id`, `sequence`, `ack`, `window`, `payload_len`).
- Codec logic for encoding/decoding UDP datagrams with **strict** error checking (exact length bounds, magic bytes verification, payload size limits, valid types).
- Unit tests for the codec and CLI parsing logic.

### What is NOT implemented yet:
- Actual UDP socket transport
- TCP port forwarding
- Reliability (ARQ) mechanisms like retransmission loops or sliding windows
- Connection lifecycles and secret validation logic
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
