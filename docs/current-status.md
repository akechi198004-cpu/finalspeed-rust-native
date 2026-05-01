# 当前实现状态（Current Status）

本文档描述代码库中已经实现的行为，不是未来设计文档。

## 已实现功能

- 提供 `server` 与 `client` CLI 子命令。
- 支持 `--transport udp|tcp`，默认 `udp`。
- Server 参数：`--listen`、`--secret`、可选 `--allow`、可选 `--transport`。
- Client 参数：`--server`、`--secret`、可重复 `--map`、可选 `--socks5`、可选 `--transport`。
- UDP transport：一个 UDP datagram 对应一个 encoded packet。
- TCP fallback：单条 client->server 长连接承载带长度前缀的 encoded packet。
- TCP framing：`u32` big-endian frame length + packet bytes。
- 支持通过 `--map local_addr:local_port=target_host:target_port` 做静态 TCP 映射。
- 支持 client 侧 `--socks5` 监听。
- 已实现 SOCKS5 no-auth greeting 与 `CONNECT`。
- 已实现 SOCKS5 目标地址解析（IPv4/domain/IPv6）。
- 已实现 ChaCha20-Poly1305 AEAD payload 加密。
- 已实现从共享 `--secret` 派生 HKDF-SHA256 key。
- `OpenConnection`、`Data`、`Ack`、`Error`、`Close` payload 均加密。
- 明文 header 字段通过 AEAD AAD 认证。
- `OpenConnection` 的 timestamp 校验窗口为 300 秒。
- Server 侧支持基于 socket address 的 target allowlist。
- 会话级收发状态支持累计 ACK、有序交付、重复包丢弃、乱序缓冲。
- UDP 与 TCP 路径均已接入重传任务。
- Client/Server 均支持 tombstone、未知连接告警限速、`last_activity` 跟踪与 idle sweep。
- GitHub Actions 在 Linux/Windows 构建并上传 release artifacts。

## 未实现能力

- Fake TCP、raw socket、pcap、TUN/TAP、防火墙自动操控。
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
- TCP fallback 在 TCP stream 上复用同一套 packet/crypto/ACK/重传逻辑，可用于 UDP 被屏蔽的场景，但不是加速模式。
- SOCKS5 适合浏览器与 curl 测试，但会产生大量短会话，应视为实验性便利层。

## Transport 对比

| Transport | 状态 | Framing | 默认 | 说明 |
|---|---:|---|---:|---|
| `udp` | 已实现 | 一个 datagram = 一个 encoded packet | 是 | 主路径，使用 `UdpSocket::send_to` / `recv_from`。 |
| `tcp` | 已实现 | `u32` big-endian length + encoded packet | 否 | UDP 不可达时的 fallback，使用单条 client->server TCP 连接。 |

## 安全模型

- 共享 `--secret` 不会以明文 payload 传输。
- `derive_key(secret)` 使用 HKDF-SHA256（salt=`fspeed-rs-v1`，info=`fspeed-rs tunnel aead v1`）。
- payload 使用 ChaCha20-Poly1305 加密。
- 加密后 payload 为 `nonce(12 bytes) || ciphertext_and_tag`。
- packet header 保持明文，便于按 type/connection ID 路由。
- AAD 覆盖 `magic`、`version`、`packet_type`、`flags`、`connection_id`、`sequence`、`ack`、`window`。
- AAD 不包含 `payload_len`。
- 携带 `OpenConnection`、`Data`、`Ack`、`Error`、`Close` 的 packet 应设置 `FLAG_ENCRYPTED = 0x0001`。
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
- 重传扫描间隔：`200 ms`。
- 初始/固定 RTO：`1000 ms`。
- 最大重传次数：`20`。
- 默认收发窗口：`1024` packets。
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
- 明确 TCP transport 是否应继续复用重传语义，或改为 transport-specific reliability 策略。
- 增强 allowlist 拒绝与 SOCKS5 target 失败场景的可观测日志。
- 为重复部署场景提供结构化配置文件。
- 补充 IPv6 SOCKS5 与 allowlist/domain 交互场景测试。
