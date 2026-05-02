# fspeed-rs

`fspeed-rs` 是一个使用 Rust 实现的实验性 TCP 隧道项目。程序分为 `server` 与 `client` 两端：`client` 通过静态端口映射或本地 SOCKS5 监听接收连接，再将流量转发到 `server` 可达的目标地址。

项目使用自定义 packet 格式、ChaCha20-Poly1305 payload 加密，以及基于 UDP 的简化可靠性运行时；当 UDP 不可达时，也支持 TCP transport fallback。

## 当前状态

- 已实现 UDP transport（默认模式）。
- 已实现 TCP transport fallback（基于长度前缀 framing）。
- 已新增 Linux-only experimental `--transport faketcp` raw backend，使用 pnet datalink/AF_PACKET 收发 IPv4 fake TCP packet。
- 已实现静态 `--map` TCP 转发。
- 已实现客户端 SOCKS5 无认证 `CONNECT`。
- `OpenConnection`、`Data`、`Ack`、`Error`、`Close`、`KeepAlive` 的 payload 均已加密。
- `Data` packet 使用 sequence number、累计 ACK、固定窗口与重传机制。
- 已实现加密 keepalive：默认每 30 秒发送一次，用于减少 TCP fallback + SOCKS5 浏览器长连接闲置后失效。
- 目前仍是实验阶段，尚未实现 SACK、拥塞控制、自适应 RTO、replay cache、per-session salt、生产级加固等能力。

更详细的实现快照见 [docs/current-status.md](docs/current-status.md)。

## 构建

先安装稳定版 Rust toolchain，然后执行：

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo build --release
```

可执行文件输出位置：

- Linux/macOS: `target/release/fspeed-rs`
- Windows: `target\release\fspeed-rs.exe`

## UDP 模式

UDP 是默认 transport，因此 `--transport udp` 可省略。

Server：

```bash
./target/release/fspeed-rs server \
  --listen 0.0.0.0:15000 \
  --secret test123_secure \
  --allow 127.0.0.1:22 \
  --transport udp
```

Client：

```bash
./target/release/fspeed-rs client \
  --server SERVER_IP:15000 \
  --secret test123_secure \
  --map 127.0.0.1:2222=127.0.0.1:22 \
  --transport udp
```

测试：

```bash
ssh -p 2222 user@127.0.0.1
```

## TCP Fallback 模式

当 UDP 无法到达 server 时可使用 TCP transport。两端都必须显式设置 `--transport tcp`。

Server：

```bash
./target/release/fspeed-rs server \
  --listen 0.0.0.0:15000 \
  --secret test123_secure \
  --allow 127.0.0.1:22 \
  --transport tcp
```

Client：

```bash
./target/release/fspeed-rs client \
  --server SERVER_IP:15000 \
  --secret test123_secure \
  --map 127.0.0.1:2222=127.0.0.1:22 \
  --transport tcp
```

TCP fallback 使用如下 framing：

```text
u32 big-endian length || encoded_packet
```

已建立会话会发送 encrypted keepalive，默认间隔 30 秒；keepalive timeout 为 120 秒，session idle timeout 仍为 300 秒。

## fake-TCP 模式（Linux-only experimental）

`--transport faketcp` 是实验性的 Linux-only fake TCP packet carrier。它从网络外观看是 TCP 端口，因此云防火墙/安全组应放行所选 TCP 端口；程序内部不是 `TcpListener` / `TcpStream`，也不是真实 TCP 连接。

fake-TCP payload 仍承载现有 encoded packet，不修改 packet header 格式，不修改 ChaCha20-Poly1305 AEAD 加密逻辑。当前 Linux backend 使用 pnet datalink/AF_PACKET 在二层收发 IPv4 fake TCP packet，并复用现有 server/client packet handling。不建议生产使用。

运行真实 fake-TCP 需要 root 或 `CAP_NET_RAW` / `CAP_NET_ADMIN`。Linux 内核可能对 fake-TCP 端口发送 RST，server 机器可能需要手动阻止，例如：

```bash
sudo iptables -A OUTPUT -p tcp --sport 443 --tcp-flags RST RST -j DROP
```

程序不会自动执行 sudo，也不会自动修改 iptables/nftables。Windows 可以解析 `--transport faketcp`，但运行时会返回 `fake-TCP transport is only supported on Linux`。

MVP 限制：仅 IPv4；不实现完整 TCP 三次握手、拥塞控制或真实 stream；使用 PSH/ACK packet 承载一个 encoded packet；自动选择可用 IPv4 网卡，复杂多网卡环境可能失败；部分 NAT/防火墙可能丢弃无握手 TCP payload。

示例：

```bash
./target/release/fspeed-rs server --listen 0.0.0.0:443 --secret test123 --transport faketcp
./target/release/fspeed-rs client --server SERVER_IP:443 --secret test123 --transport faketcp --socks5 127.0.0.1:1080
```

## SOCKS5 示例

SOCKS5 仅运行在 client 侧。

Server：

```bash
./target/release/fspeed-rs server \
  --listen 0.0.0.0:15000 \
  --secret test123_secure
```

Client：

```bash
./target/release/fspeed-rs client \
  --server SERVER_IP:15000 \
  --secret test123_secure \
  --socks5 127.0.0.1:1080
```

用 curl 测试：

```bash
curl --socks5-hostname 127.0.0.1:1080 http://example.com
```

SOCKS5 + TCP fallback：

```bash
./target/release/fspeed-rs client \
  --server SERVER_IP:15000 \
  --secret test123_secure \
  --socks5 127.0.0.1:1080 \
  --transport tcp
```

## 端口映射示例

将本地端口 `2222` 转发到 server 机器的 `127.0.0.1:22`：

```bash
./target/release/fspeed-rs client \
  --server SERVER_IP:15000 \
  --secret test123_secure \
  --map 127.0.0.1:2222=127.0.0.1:22
```

可通过重复 `--map` 传入多条映射规则。

## GitHub Actions Artifacts

构建 workflow 在 Linux 与 Windows 上运行。每个 job 都会执行格式检查、`clippy`（warnings 视为错误）、测试与 release 构建。

成功运行后会上传：

- `fspeed-rs-linux-x64`
- `fspeed-rs-windows-x64`

可在对应 GitHub Actions 运行页面的 Artifacts 区域下载。

## 安全说明

- 共享 `--secret` 在本地通过 HKDF-SHA256 派生 32-byte AEAD key。
- 共享 secret 不会以明文 payload 形式发送。
- packet payload 使用 ChaCha20-Poly1305 加密。
- packet header 为明文（用于路由），但关键 header 字段会作为 AEAD AAD 参与认证。
- `OpenConnection` 包含加密后的目标地址与时间戳。
- 当前 replay 防护仅基于时间戳；暂未实现 replay cache 与 per-session salt。
- 若 server 不配置 `--allow`，可能成为任意 TCP 转发器。建议在受控部署中始终使用 `--allow`。

## 已知限制

- 项目处于实验阶段，不是生产级代理。
- 暂无 SACK、拥塞控制、自适应 RTO。
- 暂无 replay cache、per-session salt、key rotation、traffic padding。
- 暂不支持 SOCKS5 `UDP ASSOCIATE`、`BIND`、用户名/密码认证。
- UDP 模式依赖防火墙、NAT、云安全组对 UDP 的可达性。
- TCP fallback 解决的是可达性，不是加速能力。
- fake-TCP 是 Linux-only experimental，当前支持 pnet datalink/AF_PACKET raw backend；尚未实现 IPv6 或完整 handshake/state-machine hardening。
- 开启 `--allow` 时，domain target 会被当前 server 策略拒绝（allowlist 仅接受 `SocketAddr`）。

## 路线图

- 增加 replay cache 与更强的 handshake/key scheduling。
- 增加 per-session salt 支持。
- 改进 close/half-close 行为。
- 增加结构化配置文件。
- 明确不同 transport 下的可靠性策略。
- 扩展 IPv6 SOCKS5 与 allowlist 边界场景的集成测试。
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
- Linux-only experimental `--transport faketcp` now has a pnet datalink/AF_PACKET raw backend for IPv4 fake TCP packets.
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

## fake-TCP Mode (Linux-only experimental)

`--transport faketcp` is an experimental Linux-only fake TCP packet carrier. It looks like TCP on the network, so cloud firewalls and security groups should allow the selected TCP port. Internally it is not `TcpListener` / `TcpStream`, and it is not a real TCP connection.

fake-TCP still carries one existing encoded packet per payload. It does not change the packet header format or the ChaCha20-Poly1305 AEAD payload encryption. The Linux backend uses pnet datalink/AF_PACKET to send and receive IPv4 fake TCP packets and reuses the existing server/client packet handling. This is not recommended for production.

Real fake-TCP raw packet I/O requires root or `CAP_NET_RAW` / `CAP_NET_ADMIN`. Linux may emit kernel RST packets for fake-TCP ports, so the server host may need a manual rule such as:

```bash
sudo iptables -A OUTPUT -p tcp --sport 443 --tcp-flags RST RST -j DROP
```

The program does not run sudo and does not modify iptables/nftables automatically. Windows can parse `--transport faketcp`, but runtime returns `fake-TCP transport is only supported on Linux`.

MVP limitations: IPv4 only; no full TCP three-way handshake, congestion control, or real stream; PSH/ACK packets carry one encoded packet each; interface selection is automatic and can fail on complex hosts; some NATs/firewalls may drop TCP payload without a prior handshake.

Example:

```bash
./target/release/fspeed-rs server --listen 0.0.0.0:443 --secret test123 --transport faketcp
./target/release/fspeed-rs client --server SERVER_IP:443 --secret test123 --transport faketcp --socks5 127.0.0.1:1080
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
- Packet payloads, including keepalive payloads, are encrypted with ChaCha20-Poly1305.
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
- fake-TCP is Linux-only experimental and currently uses a pnet datalink/AF_PACKET raw backend; IPv6 and handshake/state-machine hardening are not implemented.
- With `--allow`, domain targets are rejected by current server policy because allowlist entries are socket addresses.

## Roadmap

- Add replay cache and stronger handshake/key scheduling.
- Add per-session salt support.
- Improve close/half-close behavior.
- Add structured configuration files.
- Clarify transport-specific reliability behavior.
- Expand integration tests for IPv6 SOCKS5 and allowlist edge cases.
