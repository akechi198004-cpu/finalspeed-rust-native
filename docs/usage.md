# Usage

This guide shows commands that match the current CLI and implementation.

## Build

Linux:

```bash
cargo build --release
./target/release/fspeed-rs --help
```

Windows PowerShell:

```powershell
cargo build --release
.\target\release\fspeed-rs.exe --help
```

## Linux Server

UDP mode, allowing only SSH on the server host:

```bash
./target/release/fspeed-rs server \
  --listen 0.0.0.0:15000 \
  --secret test123_secure \
  --allow 127.0.0.1:22 \
  --transport udp
```

TCP fallback mode:

```bash
./target/release/fspeed-rs server \
  --listen 0.0.0.0:15000 \
  --secret test123_secure \
  --allow 127.0.0.1:22 \
  --transport tcp
```

`--allow` is optional, but strongly recommended. Without it, authenticated
clients can ask the server to connect to arbitrary TCP targets.

## Windows Client

UDP mode with SSH mapping:

```powershell
.\target\release\fspeed-rs.exe client `
  --server SERVER_IP:15000 `
  --secret test123_secure `
  --map 127.0.0.1:2222=127.0.0.1:22 `
  --transport udp
```

TCP fallback with the same mapping:

```powershell
.\target\release\fspeed-rs.exe client `
  --server SERVER_IP:15000 `
  --secret test123_secure `
  --map 127.0.0.1:2222=127.0.0.1:22 `
  --transport tcp
```

Test SSH from the client machine:

```powershell
ssh -p 2222 user@127.0.0.1
```

## UDP Transport

UDP is the default. These two commands are equivalent:

```bash
./target/release/fspeed-rs client --server SERVER_IP:15000 --secret test123_secure --map 127.0.0.1:2222=127.0.0.1:22
./target/release/fspeed-rs client --server SERVER_IP:15000 --secret test123_secure --map 127.0.0.1:2222=127.0.0.1:22 --transport udp
```

Each UDP datagram carries one encoded packet.

## TCP Transport Fallback

Use TCP fallback when UDP cannot reach the server. The server and client must
both use `--transport tcp`.

```bash
./target/release/fspeed-rs server --listen 0.0.0.0:15000 --secret test123_secure --transport tcp
./target/release/fspeed-rs client --server SERVER_IP:15000 --secret test123_secure --socks5 127.0.0.1:1080 --transport tcp
```

TCP fallback frames each encoded packet as `u32` big-endian length followed by
the packet bytes.

## SOCKS5 Curl Test

Start the server:

```bash
./target/release/fspeed-rs server \
  --listen 0.0.0.0:15000 \
  --secret test123_secure
```

Start the client-side SOCKS5 listener:

```bash
./target/release/fspeed-rs client \
  --server SERVER_IP:15000 \
  --secret test123_secure \
  --socks5 127.0.0.1:1080
```

Test through the tunnel:

```bash
curl --socks5-hostname 127.0.0.1:1080 http://example.com
```

Use `--socks5-hostname` when you want the SOCKS5 request to carry the domain
name instead of resolving it locally.

## Browser SOCKS5 Setup

Configure the browser or system proxy to use:

```text
SOCKS host: 127.0.0.1
SOCKS port: 1080
SOCKS version: SOCKS5
Authentication: none
```

For browser traffic, prefer remote DNS through SOCKS5 when the browser exposes
that option. Browsers open many short connections, so more session lifecycle log
entries are expected.

## SSH Map Example

Server:

```bash
./target/release/fspeed-rs server \
  --listen 0.0.0.0:15000 \
  --secret test123_secure \
  --allow 127.0.0.1:22
```

Client:

```bash
./target/release/fspeed-rs client \
  --server SERVER_IP:15000 \
  --secret test123_secure \
  --map 127.0.0.1:2222=127.0.0.1:22
```

SSH:

```bash
ssh -p 2222 user@127.0.0.1
```

## GitHub Actions Artifacts

The GitHub Actions build workflow runs on Linux and Windows. Successful runs
upload `fspeed-rs-linux-x64` and `fspeed-rs-windows-x64` artifacts from the run
page.

## FAQ

### UDP cannot reach the server

Check cloud security groups, VPS firewall rules, local firewall rules, NAT, and
whether the server is listening on the expected UDP port. If UDP is blocked by
the network path, use TCP fallback on both sides.

### How do I use TCP fallback?

Add `--transport tcp` to both server and client. Do not mix UDP on one side and
TCP on the other.

### Secret mismatch

Both sides derive the AEAD key from `--secret`. If the values differ,
decryption fails and handshakes do not complete. Use exactly the same string on
both sides.

### Target not allowed

The server rejected the requested target because it is not in `--allow`. Add the
exact `SocketAddr`, such as `127.0.0.1:22`, to the server allowlist. Domain
names are rejected when `--allow` is configured.

### Windows firewall

Allow `fspeed-rs.exe` through Windows Defender Firewall, or create an inbound
rule for the chosen server port when running the server on Windows.

### Linux firewall or cloud security group

Open the selected UDP or TCP port in both the cloud provider security group and
the host firewall. For UDP mode, opening only TCP is not enough.

### Browser SOCKS5 creates many logs

Browsers open many short connections. It is normal to see many connection IDs,
Close packets, and occasional debug logs for late packets belonging to recently
closed sessions.

### What does unknown ConnectionId mean?

A packet arrived for a connection ID that is not currently active. The runtime
keeps tombstones for recently closed sessions and rate-limits repeated unknown
warnings, so late retransmits or delayed packets do not flood logs.

### Is this production-grade?

No. It is an experimental tunnel. It has encryption and a basic reliability
runtime, but no SACK, congestion control, adaptive RTO, replay cache, or
per-session key separation.
