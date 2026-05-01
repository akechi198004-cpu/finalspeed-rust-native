# Current Status

This document describes the current implementation as observed in the codebase.
It is not a future design document.

## Implemented Features

- `server` and `client` CLI subcommands.
- Transport selection with `--transport udp|tcp`; default is `udp`.
- Server options: `--listen`, `--secret`, optional `--allow`, optional `--transport`.
- Client options: `--server`, `--secret`, repeated `--map`, optional `--socks5`, optional `--transport`.
- UDP transport: one UDP datagram carries one encoded packet.
- TCP transport fallback: one long-lived client-to-server TCP connection carries length-prefixed encoded packets.
- TCP framing: `u32` big-endian frame length followed by the encoded packet bytes.
- Static TCP port mappings via `--map local_addr:local_port=target_host:target_port`.
- Client-side SOCKS5 listener via `--socks5`.
- SOCKS5 no-auth greeting and `CONNECT` command.
- SOCKS5 target address parsing for IPv4, domain names, and IPv6.
- ChaCha20-Poly1305 AEAD payload encryption.
- HKDF-SHA256 key derivation from the shared `--secret`.
- Encrypted payloads for `OpenConnection`, `Data`, `Ack`, `Error`, and `Close`.
- Plaintext packet headers authenticated through AEAD AAD.
- OpenConnection timestamp validation with a 300 second clock skew window.
- Server-side target allowlist for socket-address targets.
- Per-session send and receive state with cumulative ACKs, ordered delivery, duplicate dropping, and out-of-order buffering.
- Retransmission tasks for both UDP and TCP transport paths.
- Session tombstones, unknown-connection warning rate limiting, last activity tracking, and idle sweeping on both client and server.
- Linux and Windows GitHub Actions builds with release artifacts.

## Not Implemented

- Fake TCP, raw sockets, pcap, TUN/TAP, or firewall manipulation.
- UDP ASSOCIATE or UDP application proxying.
- SOCKS5 BIND.
- SOCKS5 username/password authentication.
- SACK.
- Congestion control.
- Adaptive RTO.
- Replay cache.
- Per-session salt or key rotation.
- Traffic padding or traffic shape hiding.
- Production-grade hardening.

## Experimental Features

- The custom reliability runtime is active, but still simple: fixed RTO, fixed packet-count window, cumulative ACK only.
- TCP transport fallback reuses the same packet, crypto, ACK, and retransmission logic over a TCP stream. This can help when UDP is blocked, but it is not an acceleration mode.
- SOCKS5 is useful for browser and curl testing, but it creates many short tunnel sessions and should be treated as an experimental convenience layer.

## Transport Comparison

| Transport | Status | Framing | Default | Notes |
|---|---:|---|---:|---|
| `udp` | Implemented | One datagram equals one encoded packet | Yes | Primary transport. Uses `UdpSocket::send_to` / `recv_from`. |
| `tcp` | Implemented | `u32` big-endian length + encoded packet | No | Fallback for UDP-blocked networks. Uses one client-to-server TCP connection and framed packets. |

## Security Model

- The shared `--secret` is not sent as a plaintext payload.
- `derive_key(secret)` uses HKDF-SHA256 with salt `fspeed-rs-v1` and info `fspeed-rs tunnel aead v1`.
- Payload encryption uses ChaCha20-Poly1305.
- Encrypted payload bytes are `nonce(12 bytes) || ciphertext_and_tag`.
- The packet header remains plaintext so the runtime can route by type and connection ID.
- AAD includes `magic`, `version`, `packet_type`, `flags`, `connection_id`, `sequence`, `ack`, and `window`.
- AAD does not include `payload_len`.
- Packets carrying `OpenConnection`, `Data`, `Ack`, `Error`, or `Close` are expected to set `FLAG_ENCRYPTED = 0x0001`.
- OpenConnection plaintext, after decryption, is:

```text
target=<host-or-ip>:<port>
timestamp_ms=<unix_epoch_milliseconds>
```

- Timestamp validation allows up to 300 seconds of skew.
- Current limits: no replay cache, no per-session salt, no key rotation, no traffic padding.

## Reliability Model

- `SendState` tracks `next_sequence`, unacknowledged packets, retransmit timestamps, retransmit counts, and a fixed send window.
- `ReceiveState` tracks the next expected sequence, out-of-order payloads, and a fixed receive window.
- Data packets use packet-based sequence numbers starting at `1`.
- ACKs are cumulative: an ACK value of `N` means all packet sequences `<= N` have been continuously received.
- Receivers send encrypted ACK packets after encrypted Data packets are accepted.
- Senders remove unacknowledged packets up to the cumulative ACK number.
- Retransmission scans run every `200 ms`.
- Initial and fixed RTO is `1000 ms`.
- Maximum retransmissions is `20`.
- Default send/receive window is `1024` packets.
- There is no SACK, congestion control, adaptive RTO, or byte-based stream ACK.

## SOCKS5 Support

- SOCKS5 is implemented only on the client side.
- No-auth (`0x00`) is supported.
- `CONNECT` (`0x01`) is supported.
- IPv4, domain, and IPv6 address types are parsed.
- BIND, UDP ASSOCIATE, and username/password authentication are not supported.
- On successful tunnel handshake, the client sends a SOCKS5 success reply with a zero IPv4 bind address.

## Test Coverage

- Integration tests:
  - `tests/basic_tunnel.rs`
  - `tests/socks5_tunnel.rs`
  - `tests/tcp_transport_tunnel.rs`
  - `tests/reliable_tunnel.rs`
- Unit tests cover:
  - CLI parsing.
  - Packet encoding/decoding.
  - Protocol validation errors.
  - TCP frame read/write behavior.
  - Crypto key derivation, AEAD decrypt failures, tamper detection, and timestamp validation.
  - OpenConnection payload parsing and error payload parsing.
  - SOCKS5 greeting and request parsing.
  - Reliability send/receive state, cumulative ACKs, retransmission timeout, max retransmission failure, duplicate handling, and out-of-order buffering.
  - Session tombstones, unknown-connection rate limiting, and idle sweep behavior.
- GitHub Actions:
  - Linux x64 job runs `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, and `cargo build --release`.
  - Windows x64 job runs the same checks and uploads a Windows executable artifact.

## Known Limitations

- This is an experimental tunnel, not a production-grade proxy.
- The server can become an open TCP forwarder if `--allow` is omitted. Use `--allow` whenever possible.
- If `--allow` is configured, domain targets are rejected by current policy because allowlist entries are parsed as `SocketAddr`.
- UDP mode requires UDP reachability through cloud security groups, local firewalls, and NAT paths.
- TCP fallback may work through UDP-blocked networks, but it does not provide the same performance properties as UDP.
- Reliability uses packet-count sequencing and fixed timers; it is not a full TCP replacement.
- The header exposes packet type, connection ID, sequence, ACK, window, and payload length.
- OpenConnection replay protection is timestamp-only.
- IPv6 SOCKS5 targets are formatted as bracketed host strings such as `[::1]:443`.

## Recommended Next Steps

- Add a replay cache for OpenConnection requests.
- Add per-session salt or a stronger handshake-derived key schedule.
- Decide whether TCP transport should keep retransmission semantics or use a transport-specific reliability policy.
- Add clearer operational logging around allowlist rejections and SOCKS5 target failures.
- Consider structured config files for repeated deployment setups.
- Add tests for IPv6 SOCKS5 tunnel behavior and allowlist/domain interactions.
