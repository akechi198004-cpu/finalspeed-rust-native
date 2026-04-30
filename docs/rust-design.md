# fspeed-rs Design Document

This document outlines the design for `fspeed-rs`, a Rust-native network application that accelerates TCP services over a reliable UDP tunnel. This application is designed to be self-compatible (Rust client ↔ Rust server) and uses the original Java FinalSpeed model only as a conceptual behavioral reference.

## 1. Overall Architecture

The application is built entirely in Rust, heavily leveraging the `tokio` asynchronous runtime.

*   **Transport Layer:** Standard UDP sockets. No raw sockets, `libpcap`, or fake-TCP are used.
*   **Concurrency Model:**
    *   One central async task manages the UDP socket for reading and writing packets to the network.
    *   Separate async tasks handle individual TCP listener streams on the client.
    *   Separate async tasks handle individual TCP outgoing streams on the server.
    *   Channels (e.g., `tokio::sync::mpsc`) are used to route packets between the UDP multiplexer and the individual logical connections.
*   **Observability:** The `tracing` crate is used for logging and diagnostics.
*   **Security Context:** No full TLS or QUIC implementation. A simple shared-secret mechanism prevents unauthorized usage.

## 2. CLI Commands

The application acts as a single binary with two subcommands: `client` and `server`.

### Server Mode
Starts the UDP listener to accept incoming tunnel connections.
```bash
fspeed-rs server \
  --listen 0.0.0.0:150 \
  --secret test123 \
  --allow 127.0.0.1:22,127.0.0.1:80 # Optional: only allow forwarding to these targets
```

### Client Mode
Listens on local TCP ports and forwards connections to the remote server over UDP.
```bash
fspeed-rs client \
  --server example.com:150 \
  --secret test123 \
  --map 127.0.0.1:2222=127.0.0.1:22 \
  --map 127.0.0.1:8080=127.0.0.1:80
```

## 3. Client Behavior

1.  Parses the `--map` arguments to determine which local TCP ports to listen on and what target address they correspond to.
2.  Starts a `tokio::net::TcpListener` for each local mapping.
3.  When a local TCP client connects, the `fspeed-rs` client:
    *   Generates a new unique `connection_id`.
    *   Sends an `OpenConnection` packet over UDP to the server, containing the `connection_id`, the shared secret, and the target address (e.g., `127.0.0.1:22`).
    *   Spawns two async tasks:
        *   **TCP → UDP:** Reads from the TCP stream, chunks into payloads, wraps in `Data` packets with sequence numbers, and pushes to the UDP sender channel.
        *   **UDP → TCP:** Receives ordered `Data` packets from the UDP receiver channel and writes the payload to the TCP stream.

## 4. Server Behavior

1.  Starts a single `tokio::net::UdpSocket` listening on the configured port.
2.  Maintains a routing table (`HashMap<u32, mpsc::Sender>`) mapping `connection_id` to active connection tasks.
3.  Upon receiving an `OpenConnection` packet:
    *   Validates the shared secret. If invalid, drops the packet (or sends an Error packet).
    *   Checks the requested target address against the optional `--allow` list.
    *   If valid, initiates a `tokio::net::TcpStream` connection to the target address.
    *   Spawns two async tasks mirroring the client (TCP → UDP and UDP → TCP).
4.  Subsequent UDP packets for that `connection_id` are routed via channels to the respective connection task.

## 5. Port Mapping Model

Configuration is entirely static. The client operator must specify mappings via the CLI or a config file.

*   **Client:** Knows it is listening on `LocalAddr` and needs to reach `TargetAddr`.
*   **Wire:** The `OpenConnection` packet explicitly dictates the `TargetAddr`.
*   **Server:** Blindly attempts to connect to `TargetAddr` upon receiving a valid `OpenConnection` request (restricted by an optional server-side allowlist for security).

## 6. Rust-native UDP Packet Format

The wire format uses a custom, explicit binary layout using **Big-Endian** byte order.

### Common Header (22 bytes)

| Offset | Field Name | Size | Type | Description |
| :--- | :--- | :--- | :--- | :--- |
| 0 | `magic` | 2 | `u16` | Magic bytes identifier (e.g., `0x4653` 'FS'). |
| 2 | `version` | 1 | `u8` | Protocol version (currently `1`). |
| 3 | `packet_type` | 1 | `u8` | E.g., `1`=Open, `2`=Data, `3`=Ack, `4`=Close, `5`=Error. |
| 4 | `flags` | 2 | `u16` | Bitmask for future use (e.g., compression, auth type). |
| 6 | `connection_id` | 4 | `u32` | Unique ID representing the logical TCP stream. |
| 10 | `sequence` | 4 | `u32` | Packet sequence number (for Data/Ack). |
| 14 | `ack` | 4 | `u32` | Cumulative ACK for received packets. |
| 18 | `window` | 2 | `u16` | Current sliding window size. |
| 20 | `payload_len`| 2 | `u16` | Length of the payload following the header. |

### Packet Types & Payloads

*   **OpenConnection (Type 1):**
    *   `payload`: Contains the fixed-length/padded shared secret hash, followed by the UTF-8 string of the target address (e.g., `127.0.0.1:22`).
*   **Data (Type 2):**
    *   `payload`: Raw byte chunk read from the TCP socket.
*   **Ack (Type 3):**
    *   `sequence` field in header acts as the cumulative ACK (acknowledging all packets up to this sequence).
    *   `payload`: (Optional) Can contain a list of `u32` representing Selective ACKs (SACK) for out-of-order packets.
*   **Close (Type 4):**
    *   Signals graceful or forceful termination of the `connection_id`.
    *   `payload`: Reason code (`u8`).
*   **Error (Type 5):**
    *   `payload`: Error code and message (e.g., "Auth Failed", "Target Unreachable").

## 7. Connection/Session Model

A connection represents a single proxied TCP stream.

1.  **Init:** Client sends `OpenConnection` (retry on timeout).
2.  **Established:** Server connects to TCP target and responds with an `Ack` for the Open packet, or begins sending `Data` packets.
3.  **Transfer:** Bi-directional flow of `Data` and `Ack` packets.
4.  **Close:** Initiated when either local or remote TCP stream EOFs. A `Close` packet is sent and must be ACKed.

## 8. Sequence and ACK Model

*   **Sequence Numbers:** Increment by 1 for each new `Data` packet sent per `connection_id` (packet-based, not byte-based). Starts at 0.
*   **Cumulative ACK:** The `ack` packet header field tells the sender: "I have received and processed all packets up to sequence X".
*   **Selective ACK (SACK):** If packets arrive out of order, the receiver buffers them and sends an `Ack` with the highest continuous sequence, plus a payload list of newer sequence numbers that were received.

## 9. Retransmission Strategy

*   **Sender Table:** The sender maintains a map of un-ACKed packets along with their transmission timestamps.
*   **RTO (Retransmission TimeOut):** Initially set to a static value (e.g., 200ms) or calculated via a simple RTT (Round Trip Time) estimator.
*   **Timer Task:** An async task (or a `tokio::time::Interval`) periodically scans the sender table. If `CurrentTime - SendTime > RTO`, the packet is pushed back onto the UDP send queue.
*   **Max Retries:** If a packet is retransmitted N times (e.g., 10) without an ACK, the connection is deemed dead and forcefully closed.

## 10. Sliding Window Strategy

*   **Window Size:** Limits how many un-ACKed packets can be in flight simultaneously (e.g., 1024 packets).
*   **Flow Control:** The sender will halt pulling new data from the TCP stream if the number of un-ACKed packets reaches the window limit.
*   **Window Advancement:** When a cumulative ACK arrives, it removes acknowledged packets from the sender table, freeing up window slots, which resumes reading from the TCP socket.

## 11. Stream Close Behavior

*   **Graceful Close (FIN):** When the local TCP socket reads EOF (0 bytes), the application sends a `Close` packet (Reason: EOF). The peer receives this, writes pending ordered data to its TCP socket, and then shuts down the write half of the TCP stream.
*   **Forceful Close (RST):** If maximum retransmissions are hit, or an internal error occurs, a `Close` packet (Reason: Error) is sent, and all state for `connection_id` is immediately dropped.

## 12. Error Handling

*   **Invalid Packets:** Packets with a bad `magic` number, unknown `version`, or mismatched lengths are silently dropped to avoid abuse/amplification.
*   **Auth Failures:** Triggers a specific `Error` packet response and immediate drop.
*   **TCP Failures:** If the server cannot reach the TargetAddr, it sends an `Error` packet back to the client, causing the client to drop the local TCP connection.

## 13. Minimal MVP Scope

The Minimum Viable Product will focus strictly on:
1.  Hardcoded or simple static CLI configuration.
2.  Clear binary packet serialization/deserialization.
3.  Basic `connection_id` routing over a single UDP socket.
4.  Simple Stop-and-Wait or small fixed-size sliding window without complex SACK (retransmit un-ACKed packets after a fixed timeout).
5.  Basic shared secret validation.
6.  Successful proxying of a standard TCP application (like SSH or HTTP) over the Rust UDP tunnel.

## 14. Implementation Phases

1.  **Phase 1: Project Setup & Codec:** Initialize the Cargo workspace. Implement the binary packet layout (`encode`/`decode` traits) and comprehensive unit tests for serialization.
2.  **Phase 2: Core Transport & Routing:** Implement the UDP socket multiplexer. Create the connection table and routing logic to pass packets to specific connection channels.
3.  **Phase 3: Connection Lifecycle:** Implement the `OpenConnection`, `Close`, and basic authentication flows.
4.  **Phase 4: Reliability (ARQ):** Implement sequence numbering, the sender table, ACK processing, and the retransmission timer.
5.  **Phase 5: CLI & TCP Integration:** Add the `clap` CLI parser. Tie the reliable UDP logical connections to physical `tokio::net::TcpStream` sockets.
6.  **Phase 6: Tuning:** Implement sliding windows, SACKs, dynamic RTO calculation, and rate limiting.
