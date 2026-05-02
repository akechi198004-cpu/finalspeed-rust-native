# fspeed-rs 设计笔记（Design Notes）

本文档是较早期的设计记录。当前实现状态请优先参考 [docs/current-status.md](current-status.md) 与 [docs/protocol.md](protocol.md)。

下文已对与当前代码冲突的部分做了轻量修正，但不应视为权威协议规范。

## 当前架构摘要

`fspeed-rs` 是基于 Tokio 的 Rust 原生 client/server TCP 隧道。

- Server 支持 UDP transport、TCP fallback，以及 Linux-only experimental fake-TCP 边界。
- Client 通过 `--map` 本地监听和/或本地 SOCKS5 监听接收连接。
- UDP 路径中一个 datagram 对应一个 encoded packet。
- TCP 路径中通过 client->server TCP stream 发送 framed packet。
- fake-TCP 路径从网络外观看是 TCP packet，但程序内部不是 `TcpListener` / `TcpStream`，也不是真实 TCP connection；当前只实现 IPv4/TCP packet wrapper helper 与 runtime 边界。
- payload 使用 ChaCha20-Poly1305 加密，key 由 `--secret` 经 HKDF-SHA256 派生。
- header 保持明文，但通过 AEAD AAD 做完整性认证。
- 协议当前仅保证 Rust client 与 Rust server 之间自兼容。

## CLI 形态

Server：

```bash
fspeed-rs server \
  --listen 0.0.0.0:15000 \
  --secret test123_secure \
  --allow 127.0.0.1:22 \
  --transport udp
```

Client（端口映射）：

```bash
fspeed-rs client \
  --server example.com:15000 \
  --secret test123_secure \
  --map 127.0.0.1:2222=127.0.0.1:22 \
  --transport udp
```

Client（SOCKS5）：

```bash
fspeed-rs client \
  --server example.com:15000 \
  --secret test123_secure \
  --socks5 127.0.0.1:1080 \
  --transport tcp
```

Client（SOCKS5 + experimental fake-TCP，仅 Linux）：

```bash
fspeed-rs client \
  --server example.com:443 \
  --secret test123_secure \
  --socks5 127.0.0.1:1080 \
  --transport faketcp
```

## Packet 模型

当前通用 header 为 22 bytes（big-endian）：

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

packet type 定义为 `OpenConnection = 1`、`Data = 2`、`Ack = 3`、`Close = 4`、`Error = 5`。

## Transport 模型

- UDP：一个 UDP datagram 对应一个 encoded packet。
- TCP fallback：`u32` big-endian length-prefixed frame + encoded packet，使用 OS `TcpListener` / `TcpStream`。
- fake-TCP：`IPv4 header || TCP header || encoded_packet`，网络外观看是 TCP 端口，但 payload 是现有 encoded packet。packet header 格式不变，payload 仍使用 ChaCha20-Poly1305 AEAD 加密。

fake-TCP 是 Linux-only experimental 功能。真实收发需要 raw packet injection/capture、root 或 `CAP_NET_RAW` / `CAP_NET_ADMIN`，云防火墙/安全组应放行所选 TCP 端口，并且可能需要手动阻止 Linux kernel RST，例如 `sudo iptables -A OUTPUT -p tcp --sport <PORT> --tcp-flags RST RST -j DROP`。当前实现尚未接入 raw socket 后端，也未实现完整 TCP 三次握手状态机；Windows 运行时会返回 `fake-TCP transport is only supported on Linux`。

## OpenConnection

`OpenConnection` payload 为加密内容。解密后当前明文格式：

```text
target=127.0.0.1:22
timestamp_ms=1682390884000
```

共享 secret 不会以明文 payload 发送。parser 会拒绝旧字段 `secret`、`auth`、`nonce`。

## 可靠性说明

当前可靠性运行时已实现并接入 data plane：

- 已实现 `SendState` 与 `ReceiveState`；
- sequence number 从 `1` 开始；
- ACK 为累计确认，使用 header `ack` 字段；
- 重传使用固定 `1000 ms` RTO；
- 重传扫描周期为 `200 ms`；
- 最大重传次数为 `20`；
- 默认收发窗口为 `1024` packets；
- TCP 与 UDP 路径都会启动重传任务。

当前可靠性限制：

- 无 SACK；
- 无拥塞控制；
- 无自适应 RTO；
- 无 TCP 式按字节 ACK 语义。

## Session 生命周期说明

client 与 server manager 均支持：

- active session map；
- `last_activity` 更新时间；
- 每 `30 s` idle sweep；
- `300 s` idle timeout；
- 关闭会话 tombstone（TTL `60 s`）；
- 未知连接告警限速（`10 s` 窗口）。

## 安全说明

- payload 使用 ChaCha20-Poly1305。
- AEAD key 由 `--secret` 通过 HKDF-SHA256 派生。
- AAD 覆盖 header 字段（不含 `payload_len`）。
- timestamp 校验为 OpenConnection 提供基础新鲜度保护。
- 当前无 replay cache、per-session salt、key rotation、traffic padding。

## 历史设计想法（当前未实现）

以下想法可能出现在早期讨论中，但当前代码未实现：

- 明文 shared-secret payload；
- 自适应 RTO；
- 拥塞控制；
- 配置文件驱动的映射管理；
- SOCKS5 `UDP ASSOCIATE` 支持。
- 生产级 fake-TCP raw socket 收发、IPv6、RST 管理与握手/state-machine hardening。
