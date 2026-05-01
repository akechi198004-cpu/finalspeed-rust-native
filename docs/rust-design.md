# fspeed-rs Design Notes

This document contains earlier design notes. For current implementation status,
see [docs/current-status.md](current-status.md) and [docs/protocol.md](protocol.md).

The notes below have been lightly corrected where they conflicted with the
current code, but they should not be treated as the authoritative protocol
reference.

## Current Architecture Summary

`fspeed-rs` is a Rust-native client/server TCP tunnel built on Tokio.

- Server listens with either UDP transport or TCP transport fallback.
- Client accepts local TCP connections from `--map` listeners and/or a local SOCKS5 listener.
- UDP transport sends one encoded packet per datagram.
- TCP transport sends framed encoded packets over a client-to-server TCP stream.
- Payloads are encrypted with ChaCha20-Poly1305 using an HKDF-SHA256 key derived from `--secret`.
- Headers are plaintext but authenticated as AEAD AAD.
- The protocol is self-compatible between Rust client and Rust server only.

## CLI Shape

Server:

```bash
fspeed-rs server \
  --listen 0.0.0.0:15000 \
  --secret test123_secure \
  --allow 127.0.0.1:22 \
  --transport udp
```

Client with mapping:

```bash
fspeed-rs client \
  --server example.com:15000 \
  --secret test123_secure \
  --map 127.0.0.1:2222=127.0.0.1:22 \
  --transport udp
```

Client with SOCKS5:

```bash
fspeed-rs client \
  --server example.com:15000 \
  --secret test123_secure \
  --socks5 127.0.0.1:1080 \
  --transport tcp
```

## Packet Model

The current common header is 22 bytes, big-endian:

| Offset | Field | Size |
|---:|---|---:|
| 0 | `magic` | 2 |
| 2 | `version` | 1 |
| 3 | `packet_type` | 1 |
| 4 | `flags` | 2 |
| 6 | `connection_id` | 4 |
| 10 | `sequence` | 4 |
| 14 | `ack` | 4 |
| 18 | `window` | 2 |
| 20 | `payload_len` | 2 |

Packet types are `OpenConnection = 1`, `Data = 2`, `Ack = 3`, `Close = 4`, and
`Error = 5`.

## OpenConnection

OpenConnection payloads are encrypted. The current plaintext format after
decryption is:

```text
target=127.0.0.1:22
timestamp_ms=1682390884000
```

The shared secret is not sent as a plaintext payload. Old keys such as `secret`,
`auth`, and `nonce` are rejected by the parser.

## Reliability Notes

The current reliability runtime is implemented and connected to the data plane:

- `SendState` and `ReceiveState` exist.
- Sequence numbers start at `1`.
- ACKs are cumulative and use the header `ack` field.
- Retransmission uses a fixed `1000 ms` RTO.
- Retransmission scanning runs every `200 ms`.
- Maximum retransmissions is `20`.
- Default send/receive window is `1024` packets.
- TCP and UDP transport paths both start retransmission tasks.

Current reliability limits:

- No SACK.
- No congestion control.
- No adaptive RTO.
- No byte-based TCP-style ACK semantics.

## Session Lifecycle Notes

Both client and server managers implement:

- active session maps,
- `last_activity`,
- idle sweep every `30 s`,
- idle timeout after `300 s`,
- closed-session tombstones with `60 s` TTL,
- unknown connection warning rate limit of `10 s`.

## Security Notes

- ChaCha20-Poly1305 is used for payload encryption.
- HKDF-SHA256 derives the AEAD key from `--secret`.
- AAD covers header fields except `payload_len`.
- Timestamp validation gives basic freshness checking for OpenConnection.
- There is no replay cache, per-session salt, key rotation, or traffic padding.

## Historical Design Ideas Not Currently Implemented

The following ideas may appear in older discussions but are not present in the
current implementation:

- Plaintext shared-secret payloads.
- Adaptive RTO.
- Congestion control.
- Config-file driven mappings.
- UDP ASSOCIATE support for SOCKS5.
