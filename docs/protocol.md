# Protocol

This document describes the packet, crypto, and transport behavior currently
implemented by `fspeed-rs`.

## Packet Header

Every encoded packet starts with a fixed 22-byte header. All integer fields are
big-endian.

| Offset | Field | Size | Type | Current meaning |
|---:|---|---:|---|---|
| 0 | `magic` | 2 | `u16` | `0x4653` (`FS`) |
| 2 | `version` | 1 | `u8` | `1` |
| 3 | `packet_type` | 1 | `u8` | See Packet Types |
| 4 | `flags` | 2 | `u16` | `FLAG_ENCRYPTED = 0x0001` |
| 6 | `connection_id` | 4 | `u32` | Logical tunnel session ID |
| 10 | `sequence` | 4 | `u32` | Packet sequence for data/close send state |
| 14 | `ack` | 4 | `u32` | Cumulative ACK value |
| 18 | `window` | 2 | `u16` | Header field exists; current data packets usually send `0` after open |
| 20 | `payload_len` | 2 | `u16` | Length of payload bytes after the header |

`HEADER_LEN` is `22`. Encoded packet size is `22 + payload_len`.

The decoder rejects invalid magic, invalid version, unknown packet types,
truncated packets, oversized payloads, and trailing bytes after the declared
payload length.

## Packet Types

| Value | Type |
|---:|---|
| `1` | `OpenConnection` |
| `2` | `Data` |
| `3` | `Ack` |
| `4` | `Close` |
| `5` | `Error` |

## Transport Framing

UDP transport:

```text
one UDP datagram = one encoded packet
```

TCP transport fallback:

```text
u32_be length || encoded_packet
```

The TCP frame length is the encoded packet size, not including the four-byte
length prefix. The current maximum frame size is `2 MiB`.

## Encryption

Payload encryption uses ChaCha20-Poly1305. Keys are derived from the CLI shared
secret using HKDF-SHA256:

- Salt: `fspeed-rs-v1`
- Info: `fspeed-rs tunnel aead v1`
- Output key length: 32 bytes

Encrypted payload bytes are:

```text
nonce(12 bytes) || ciphertext_and_tag
```

The packet header remains plaintext. The encrypted packet sets
`FLAG_ENCRYPTED = 0x0001`.

AAD is built from these header fields, in big-endian order:

```text
magic || version || packet_type || flags || connection_id || sequence || ack || window
```

`payload_len` is intentionally not included in AAD because encryption changes
the payload length.

## OpenConnection

`OpenConnection` payloads are encrypted. After decryption, the current plaintext
format is UTF-8 key/value lines:

```text
target=<host-or-ip>:<port>
timestamp_ms=<unix_epoch_milliseconds>
```

The payload parser rejects missing `target`, missing or invalid `timestamp_ms`,
duplicate keys, unknown keys, and old keys such as `secret`, `auth`, and
`nonce`.

The server validates `timestamp_ms` with a 300 second allowed skew. If `--allow`
is configured, the target must parse as a `SocketAddr` and be present in the
allowlist. Domain targets are rejected when `--allow` is active.

## Data

`Data` payloads are encrypted TCP byte chunks. Data packets use per-session
packet sequence numbers from `SendState`, starting at `1`.

On receive, `ReceiveState`:

- drops duplicate sequence numbers below `next_expected`,
- buffers out-of-order packets inside the receive window,
- delivers only contiguous payloads in order,
- generates a cumulative ACK equal to the last contiguous sequence received.

## Ack

`Ack` packets are encrypted and currently carry the text payload:

```text
status=ok
```

The meaningful ACK value is the header `ack` field. It is cumulative: `ack = N`
means all packet sequences `<= N` have been continuously received for that
session. ACK packets use `sequence = 0`.

The initial successful OpenConnection response is also an encrypted `Ack`, with
`ack = 0`.

## Error

`Error` packets are encrypted. The current plaintext format is:

```text
status=error
reason=<reason text>
```

Clients parse the reason when possible and fail pending handshakes after an
Error response.

## Close

`Close` packets are encrypted. Current close payloads are empty before
encryption. A received valid close removes local session state and records a
short tombstone.

## Reliability

The current runtime is a simple packet-based reliability layer:

- `SendState` stores unacknowledged packets and retransmit counters.
- `ReceiveState` stores next expected sequence and out-of-order payloads.
- Default window is `1024` packets.
- Sequence numbers start at `1`; `0` is skipped after wrap.
- ACKs are cumulative only.
- Retransmission scan interval is `200 ms`.
- RTO is fixed at `1000 ms`.
- Maximum retransmissions is `20`.
- UDP and TCP transport paths both start retransmission tasks for established sessions.

## Session Lifecycle

Both client and server managers implement:

- active session lookup and removal,
- `last_activity` updates,
- idle sweeping every `30 s`,
- idle timeout after `300 s`,
- tombstones for recently closed connection IDs with `60 s` TTL,
- unknown connection warning rate limiting with a `10 s` window.

## Not Supported

The current protocol does not implement:

- SACK,
- congestion control,
- adaptive RTO,
- replay cache,
- per-session salt,
- key rotation,
- traffic padding,
- UDP application proxying,
