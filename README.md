# fspeed-rs

`fspeed-rs` is a Rust-native experimental TCP tunnel. It runs as a `server`
and `client`: the client accepts local TCP connections through static port
mappings or a local SOCKS5 listener, then forwards them to targets reachable
from the server.

The project uses a custom packet format, ChaCha20-Poly1305 payload encryption,
and a simple reliability runtime over UDP. It also has a TCP transport fallback
for networks where UDP is blocked.

## Current Status

- UDP transport is implemented and is the default.
- TCP transport fallback is implemented with length-prefixed packet framing.
- Static `--map` TCP forwarding is implemented.
- Client-side SOCKS5 no-auth `CONNECT` is implemented.
- Payloads for `OpenConnection`, `Data`, `Ack`, `Error`, and `Close` are encrypted.
- Data packets use sequence numbers, cumulative ACKs, a fixed window, and retransmission.
- This is still experimental. It does not implement SACK, congestion control, adaptive RTO, replay cache, per-session salts, or production-grade hardening.

For a more detailed implementation snapshot, see [docs/current-status.md](docs/current-status.md).

## Build

Install a stable Rust toolchain, then run:

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo build --release
```

The binary is written to:

- Linux/macOS: `target/release/fspeed-rs`
- Windows: `target\release\fspeed-rs.exe`

## UDP Mode

UDP is the default transport, so `--transport udp` is optional.

Server:

```bash
./target/release/fspeed-rs server \
  --listen 0.0.0.0:15000 \
  --secret test123_secure \
  --allow 127.0.0.1:22 \
  --transport udp
```

Client:

```bash
./target/release/fspeed-rs client \
  --server SERVER_IP:15000 \
  --secret test123_secure \
  --map 127.0.0.1:2222=127.0.0.1:22 \
  --transport udp
```

Test:

```bash
ssh -p 2222 user@127.0.0.1
```

## TCP Fallback Mode

Use TCP transport when UDP cannot reach the server. Both sides must use
`--transport tcp`.

Server:

```bash
./target/release/fspeed-rs server \
  --listen 0.0.0.0:15000 \
  --secret test123_secure \
  --allow 127.0.0.1:22 \
  --transport tcp
```

Client:

```bash
./target/release/fspeed-rs client \
  --server SERVER_IP:15000 \
  --secret test123_secure \
  --map 127.0.0.1:2222=127.0.0.1:22 \
  --transport tcp
```

TCP fallback uses:

```text
u32 big-endian length || encoded_packet
```

## SOCKS5 Example

SOCKS5 runs on the client side only.

Server:

```bash
./target/release/fspeed-rs server \
  --listen 0.0.0.0:15000 \
  --secret test123_secure
```

Client:

```bash
./target/release/fspeed-rs client \
  --server SERVER_IP:15000 \
  --secret test123_secure \
  --socks5 127.0.0.1:1080
```

Test with curl:

```bash
curl --socks5-hostname 127.0.0.1:1080 http://example.com
```

TCP fallback with SOCKS5:

```bash
./target/release/fspeed-rs client \
  --server SERVER_IP:15000 \
  --secret test123_secure \
  --socks5 127.0.0.1:1080 \
  --transport tcp
```

## Map Example

Forward local port `2222` to the server machine's `127.0.0.1:22`:

```bash
./target/release/fspeed-rs client \
  --server SERVER_IP:15000 \
  --secret test123_secure \
  --map 127.0.0.1:2222=127.0.0.1:22
```

Multiple mappings can be passed by repeating `--map`.

## GitHub Actions Artifacts

The build workflow runs on Linux and Windows. Each job runs formatting checks,
clippy with warnings denied, tests, and a release build.

Successful workflow runs upload:

- `fspeed-rs-linux-x64`
- `fspeed-rs-windows-x64`

Download them from the Artifacts section of the GitHub Actions run page.

## Security Notes

- The shared `--secret` is used locally to derive a 32-byte AEAD key with HKDF-SHA256.
- The shared secret is not sent as a plaintext packet payload.
- Packet payloads are encrypted with ChaCha20-Poly1305.
- Packet headers are plaintext for routing, but selected header fields are authenticated as AEAD AAD.
- `OpenConnection` contains an encrypted target address and timestamp.
- Current replay protection is timestamp-only. There is no replay cache or per-session salt yet.
- Running a server without `--allow` can expose it as an arbitrary TCP forwarder. Use `--allow` for controlled deployments.

## Known Limitations

- Experimental project; not a production-grade proxy.
- No SACK, congestion control, or adaptive RTO.
- No replay cache, per-session salt, key rotation, or traffic padding.
- No UDP ASSOCIATE, BIND, or username/password SOCKS5 auth.
- UDP transport requires firewall, NAT, and cloud security group UDP reachability.
- TCP fallback is for reachability, not acceleration.
- With `--allow`, domain targets are rejected by current server policy because allowlist entries are socket addresses.

## Roadmap

- Add replay cache and stronger handshake/key scheduling.
- Add per-session salt support.
- Improve close/half-close behavior.
- Add structured configuration files.
- Clarify transport-specific reliability behavior.
- Expand integration tests for IPv6 SOCKS5 and allowlist edge cases.
