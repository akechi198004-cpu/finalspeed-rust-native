# fspeed-rs

`fspeed-rs` 是一个使用 Rust 实现的实验性 TCP 隧道项目。程序分为 `server` 与 `client` 两端：`client` 通过静态端口映射或本地 SOCKS5 监听接收连接，再将流量转发到 `server` 可达的目标地址。

项目使用自定义 packet 格式、ChaCha20-Poly1305 payload 加密，以及基于 UDP 的简化可靠性运行时；当 UDP 不可达时，也支持 TCP transport fallback。

## 当前状态

- 已实现 UDP transport（默认模式）。
- 已实现 TCP transport fallback（基于长度前缀 framing）。
- 已实现静态 `--map` TCP 转发。
- 已实现客户端 SOCKS5 无认证 `CONNECT`。
- `OpenConnection`、`Data`、`Ack`、`Error`、`Close` 的 payload 均已加密。
- `Data` packet 使用 sequence number、累计 ACK、固定窗口与重传机制。
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
