# 当前实现状态（Current Status）

本文档描述代码库中已经实现的行为，不是未来设计文档。

## 已实现功能

- 提供 `server` 与 `client` CLI 子命令。
- 支持 `--transport udp|tcp|faketcp`，默认 `udp`。
- Server 参数：`--listen`、`--secret`、可选 `--allow`、可选 `--transport`。
- Client 参数：`--server`、`--secret`、可重复 `--map`、可选 `--socks5`、可选 `--transport`。
- UDP transport：一个 UDP datagram 对应一个 encoded packet。
- TCP fallback：单条 client->server 长连接承载带长度前缀的 encoded packet。
- TCP framing：`u32` big-endian frame length + packet bytes。
- fake-TCP：Linux-only experimental raw backend 已接入，使用 pnet datalink/AF_PACKET 收发 IPv4 fake TCP packet。
- 支持通过 `--map local_addr:local_port=target_host:target_port` 做静态 TCP 映射。
- 支持 client 侧 `--socks5` 监听。
- 已实现 SOCKS5 no-auth greeting 与 `CONNECT`。
- 已实现 SOCKS5 目标地址解析（IPv4/domain/IPv6）。
- 已实现 ChaCha20-Poly1305 AEAD payload 加密。
- 已实现从共享 `--secret` 派生 HKDF-SHA256 key。
- `OpenConnection`、`Data`、`Ack`、`Error`、`Close`、`KeepAlive` payload 均加密。
- 明文 header 字段通过 AEAD AAD 认证。
- `OpenConnection` 的 timestamp 校验窗口为 300 秒。
- Server 侧支持基于 socket address 的 target allowlist。
- 会话级收发状态支持累计 ACK、有序交付、重复包丢弃、乱序缓冲。
- UDP 路径已接入重传任务；TCP transport 不启动重传任务，且业务 Data fast path 不使用 RUDP send window、unacked buffer、ReceiveState 重排或 Data Ack。
- Client/Server 均支持 encrypted keepalive、tombstone、未知连接告警限速、`last_activity` 跟踪与 idle sweep。
- GitHub Actions 在 Linux/Windows 构建并上传 release artifacts。

## 未实现能力

- fake-TCP IPv6、完整 TCP handshake/state-machine、pcap、TUN/TAP、防火墙自动操控。
- UDP ASSOCIATE 或 UDP 应用代理。
- SOCKS5 BIND。
- SOCKS5 用户名/密码认证。
- SACK。
- 拥塞控制。
- 自适应 RTO。
- Replay cache。
- Per-session salt 或 key rotation。
- Traffic padding/流量特征隐藏。
- 生产级安全加固。

## 实验性特征

- 当前可靠性运行时已启用，但较简化：固定 RTO、固定 packet 窗口、仅累计 ACK。
- TCP fallback 使用 `u32` big-endian length-prefixed frame，在 TCP stream 上承载同一套 encoded packet 与 AEAD payload。它依赖 OS TCP 的可靠性和有序性，可用于 UDP 被屏蔽的场景，但不是加速模式；TCP transport 不启动重传任务，不等待 RUDP send window，不保存 Data unacked buffer，不发送业务 Data Ack。`Ack` 仍用于 `OpenConnection` handshake。
- fake-TCP transport 使用 `--transport faketcp`，仅面向 Linux，是 raw packet carrier MVP：网络外观看是 TCP 端口，但程序内部不是 `TcpListener` / `TcpStream`，也不是真实 TCP 连接。它需要 root 或 `CAP_NET_RAW` / `CAP_NET_ADMIN`，云防火墙/安全组应放行所选 TCP 端口；Windows 会返回 `fake-TCP transport is only supported on Linux`。Linux 内核可能对 fake-TCP 端口发送 RST，运行 server 时可能需要手动阻止，例如 `sudo iptables -A OUTPUT -p tcp --sport <PORT> --tcp-flags RST RST -j DROP`。当前未自动执行 sudo、iptables 或 nftables。
- fake-TCP 当前使用 pnet datalink/AF_PACKET，支持 IPv4 TCP header build/parse、checksum、端口/peer 过滤和 encoded packet payload carrier；尚未实现完整 SYN/SYN-ACK/ACK 状态机，可能需要 handshake/state-machine hardening，不建议生产使用。
- SOCKS5 适合浏览器与 curl 测试，但会产生大量短会话，应视为实验性便利层。

## Transport 对比

| Transport | 状态 | Framing | 默认 | 说明 |
|---|---:|---|---:|---|
| `udp` | 已实现 | 一个 datagram = 一个 encoded packet | 是 | 主路径，使用 `UdpSocket::send_to` / `recv_from`。 |
| `tcp` | 已实现 | `u32` big-endian length + encoded packet | 否 | UDP 不可达时的 fallback，使用单条 client->server TCP 连接。 |
| `faketcp` | Linux 实验性 MVP | IPv4/TCP payload = 一个 encoded packet | 否 | Linux-only pnet datalink/AF_PACKET fake TCP packet carrier；需要 raw packet 权限。 |

## 安全模型

- 共享 `--secret` 不会以明文 payload 传输。
- `derive_key(secret)` 使用 HKDF-SHA256（salt=`fspeed-rs-v1`，info=`fspeed-rs tunnel aead v1`）。
- payload 使用 ChaCha20-Poly1305 加密。
- 加密后 payload 为 `nonce(12 bytes) || ciphertext_and_tag`。
- packet header 保持明文，便于按 type/connection ID 路由。
- AAD 覆盖 `magic`、`version`、`packet_type`、`flags`、`connection_id`、`sequence`、`ack`、`window`。
- AAD 不包含 `payload_len`。
- 携带 `OpenConnection`、`Data`、`Ack`、`Error`、`Close`、`KeepAlive` 的 packet 应设置 `FLAG_ENCRYPTED = 0x0001`。
- KeepAlive payload 同样使用 ChaCha20-Poly1305 AEAD 加密，默认每 30 秒发送一次。
- `OpenConnection` 解密后明文格式为：

```text
target=<host-or-ip>:<port>
timestamp_ms=<unix_epoch_milliseconds>
```

- 时间戳校验允许最多 300 秒偏差。
- 当前限制：无 replay cache、无 per-session salt、无 key rotation、无 traffic padding。

## 可靠性模型

- `SendState` 跟踪 `next_sequence`、未确认 packet、重传时间戳、重传计数与固定发送窗口。
- `ReceiveState` 跟踪下一期望序号、乱序 payload 与固定接收窗口。
- Data packet 的 sequence number 从 `1` 开始，按 packet 计数。
- ACK 为累计确认：`ack = N` 表示序号 `<= N` 已连续收到。
- 接收端接受到加密 `Data` 后会回加密 `Ack`。
- 发送端收到累计 ACK 后移除对应未确认 packet。
- 以上 RUDP 可靠性规则仅适用于 UDP/fake-TCP packet data path；TCP transport 的业务 Data 到达后直接解密并按 TCP frame 顺序交付。
- UDP 重传扫描间隔：`200 ms`。
- 初始/固定 RTO：`1000 ms`。
- 最大重传次数：`20`。
- 默认收发窗口：`1024` packets。
- KeepAlive interval：`30 s`；KeepAlive timeout：`120 s`；Session idle timeout：`300 s`。
- 不支持 SACK、拥塞控制、自适应 RTO、按字节 ACK。

## SOCKS5 支持

- 仅在 client 侧实现 SOCKS5。
- 支持 no-auth（`0x00`）。
- 支持 `CONNECT`（`0x01`）。
- 支持 IPv4、domain、IPv6 地址类型解析。
- 不支持 BIND、UDP ASSOCIATE、用户名/密码认证。
- 隧道握手成功后，client 返回 SOCKS5 success reply（IPv4 绑定地址为全零）。

## 测试覆盖

- 集成测试：
  - `tests/basic_tunnel.rs`
  - `tests/socks5_tunnel.rs`
  - `tests/tcp_transport_tunnel.rs`
  - `tests/reliable_tunnel.rs`
- 单元测试覆盖：
  - CLI 解析；
  - packet 编解码；
  - protocol 校验错误路径；
  - TCP frame 读写行为；
  - crypto key 派生、AEAD 解密失败、篡改检测、timestamp 校验；
  - OpenConnection payload 解析与 Error payload 解析；
  - SOCKS5 greeting 与 request 解析；
  - reliability 收发状态、累计 ACK、重传超时、最大重传失败、重复包与乱序缓冲；
  - keepalive packet 编解码、payload 加密、last_activity 更新、idle sweep 保活行为；
  - session tombstone、未知连接限速与 idle sweep。
- GitHub Actions：
  - Linux x64 job：`cargo fmt --check`、`cargo clippy -- -D warnings`、`cargo test`、`cargo build --release`；
  - Windows x64 job：同样检查并上传 Windows 可执行文件 artifact。

## 已知限制

- 项目仍属实验性，不是生产级代理。
- 若省略 `--allow`，server 可能成为开放 TCP 转发器；建议尽量开启。
- 若配置 `--allow`，当前策略会拒绝 domain target（allowlist 按 `SocketAddr` 匹配）。
- UDP 模式依赖云安全组、本机防火墙与 NAT 路径的 UDP 可达性。
- TCP fallback 可提升可达性，但不具备 UDP 模式的同类性能特征。
- 可靠性层采用 packet 计数与固定计时器，不是完整 TCP 替代。
- header 会暴露 packet type、connection ID、sequence、ACK、window、payload length。
- `OpenConnection` 仅有基于 timestamp 的 replay 防护。
- IPv6 SOCKS5 target 使用括号格式，如 `[::1]:443`。

## 建议下一步

- 为 `OpenConnection` 增加 replay cache。
- 增加 per-session salt，或采用更强的 handshake 派生 key 方案。
- 增强 allowlist 拒绝与 SOCKS5 target 失败场景的可观测日志。
- 为重复部署场景提供结构化配置文件。
- 补充 IPv6 SOCKS5 与 allowlist/domain 交互场景测试。
