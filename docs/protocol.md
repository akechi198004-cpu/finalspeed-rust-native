# 协议说明（Protocol）

本文档描述 `fspeed-rs` 当前已经实现的 packet、加密与 transport 行为。

## Packet Header

每个编码后的 packet 都以固定 22-byte header 开头，所有整数均为 big-endian。

| Offset | Field | Size | Type | 当前含义 |
|---:|---|---:|---|---|
| 0 | `magic` | 2 | `u16` | `0x4653` (`FS`) |
| 2 | `version` | 1 | `u8` | `1` |
| 3 | `packet_type` | 1 | `u8` | 见 Packet Types |
| 4 | `flags` | 2 | `u16` | `FLAG_ENCRYPTED = 0x0001` |
| 6 | `connection_id` | 4 | `u32` | 逻辑隧道会话 ID |
| 10 | `sequence` | 4 | `u32` | data/close 发送状态的序号 |
| 14 | `ack` | 4 | `u32` | 累计 ACK 值 |
| 18 | `window` | 2 | `u16` | header 字段已保留；当前 data packet 在 open 后通常发送 `0` |
| 20 | `payload_len` | 2 | `u16` | header 后 payload 字节长度 |

`HEADER_LEN` 为 `22`，编码后的 packet 总长度为 `22 + payload_len`。

decoder 会拒绝以下情况：magic/version 非法、未知 packet_type、截断 packet、超大 payload、声明长度后的 trailing bytes。

## Packet Types

| Value | Type |
|---:|---|
| `1` | `OpenConnection` |
| `2` | `Data` |
| `3` | `Ack` |
| `4` | `Close` |
| `5` | `Error` |
| `6` | `KeepAlive` |

## Transport Framing

UDP transport：

```text
one UDP datagram = one encoded packet
```

TCP transport fallback：

```text
u32_be length || encoded_packet
```

TCP frame length 指编码后 packet 长度，不包含前置 4-byte length。当前最大 frame size 为 `2 MiB`。

fake-TCP transport（experimental / Linux-only）：

```text
IPv4 header || TCP header || encoded_packet
```

fake-TCP 从网络外观看是 TCP packet，云防火墙/安全组应放行所选 TCP 端口，但程序内部不是 `TcpListener` / `TcpStream`，也不是真实 TCP connection。每个 fake-TCP payload 承载一个现有 `encoded_packet`，packet header 格式不变，payload 仍使用 ChaCha20-Poly1305 AEAD 加密，明文 header 仍参与 AAD 认证。当前 helper 仅支持 IPv4，已实现 IPv4 checksum 与 TCP pseudo-header checksum 的构造/校验，以及目标端口/源 peer 过滤。

当前 fake-TCP Linux backend 使用 pnet datalink/AF_PACKET 收发二层 Ethernet frame，并已接入 client/server data path。运行需要 Linux raw packet send/receive 权限（root 或 `CAP_NET_RAW` / `CAP_NET_ADMIN`），且可能需要手动阻止 Linux kernel RST，例如：

```bash
sudo iptables -A OUTPUT -p tcp --sport <PORT> --tcp-flags RST RST -j DROP
```

程序不会自动执行 sudo，也不会自动修改 iptables/nftables。Windows 不支持 fake-TCP，并返回 `fake-TCP transport is only supported on Linux`。

MVP 限制：仅 IPv4；不实现完整 TCP 三次握手、拥塞控制或真实 stream；当前使用 PSH/ACK packet 承载一个 encoded packet；自动选择可用 IPv4 网卡，复杂路由或多网卡环境可能失败；部分 NAT/防火墙可能丢弃无握手 TCP payload。

## 加密（Encryption）

payload 加密算法为 ChaCha20-Poly1305。key 由 CLI shared secret 通过 HKDF-SHA256 派生：

- Salt: `fspeed-rs-v1`
- Info: `fspeed-rs tunnel aead v1`
- 输出 key 长度：32 bytes

加密后 payload 格式：

```text
nonce(12 bytes) || ciphertext_and_tag
```

packet header 保持明文。加密 packet 会设置 `FLAG_ENCRYPTED = 0x0001`。

AAD 由以下 header 字段按 big-endian 顺序拼接：

```text
magic || version || packet_type || flags || connection_id || sequence || ack || window
```

`payload_len` 故意不纳入 AAD，因为加密会改变 payload 长度。

## OpenConnection

`OpenConnection` payload 为加密内容。解密后的当前明文格式是 UTF-8 key/value 行：

```text
target=<host-or-ip>:<port>
timestamp_ms=<unix_epoch_milliseconds>
```

payload parser 会拒绝：缺失 `target`、缺失或非法 `timestamp_ms`、重复 key、未知 key、旧字段（如 `secret`、`auth`、`nonce`）。

server 使用 300 秒时间偏差窗口校验 `timestamp_ms`。若配置了 `--allow`，目标地址必须能解析为 `SocketAddr` 且位于 allowlist。开启 `--allow` 时，domain target 会被拒绝。

## Data

`Data` payload 为加密后的 TCP 字节片段。Data packet 使用会话级 sequence number（来自 `SendState`），从 `1` 开始。

接收端 `ReceiveState` 行为：

- 丢弃低于 `next_expected` 的重复序号；
- 在接收窗口内缓存乱序 packet；
- 仅按顺序交付连续 payload；
- 生成累计 ACK（值为最近连续接收的最大 sequence）。

## Ack

`Ack` packet 为加密内容，当前 text payload 为：

```text
status=ok
```

真正有意义的 ACK 值在 header 的 `ack` 字段中。它是累计确认：`ack = N` 表示该会话中 `<= N` 的 packet 序号已连续收到。ACK packet 使用 `sequence = 0`。

初次 `OpenConnection` 成功响应也是加密 `Ack`，其 `ack = 0`。

## Error

`Error` packet 为加密内容。当前明文格式：

```text
status=error
reason=<reason text>
```

client 在可能时会解析 reason，并在收到 Error 后让待定握手失败。

## Close

`Close` packet 为加密内容。当前 close payload 在加密前为空。收到合法 close 后会删除本地 session 状态，并记录短期 tombstone。

## KeepAlive

`KeepAlive` packet 为加密内容，packet type value 为 `6`，必须设置 `FLAG_ENCRYPTED`。header 格式不变，header 仍为明文并参与 AAD 认证。

当前 keepalive 明文 payload 在加密前为：

```text
type=keepalive
timestamp_ms=<unix_epoch_milliseconds>
```

收到合法 KeepAlive 后只更新对应 session 的 `last_activity`，不会写入 TCP stream，也不会生成业务数据。若 connection ID 未知，则复用现有 tombstone 与 unknown rate-limit 逻辑。

## 可靠性（Reliability）

当前运行时是简化的 packet 级可靠性层：

- `SendState` 保存未确认 packet 与重传计数；
- `ReceiveState` 保存下一个期望序号与乱序 payload；
- 默认窗口为 `1024` packets；
- sequence 从 `1` 开始，回绕后跳过 `0`；
- ACK 仅支持累计确认；
- 重传扫描间隔：`200 ms`；
- RTO 固定：`1000 ms`；
- 最大重传次数：`20`；
- UDP 路径在会话建立后启动重传任务；TCP transport 不启动重传任务。

## Session 生命周期

client 与 server 的 session manager 均实现：

- active session 查询与删除；
- `last_activity` 更新时间；
- 每 `30 s` 执行 idle sweep；
- keepalive 发送间隔：`30 s`；
- keepalive timeout：`120 s`；
- `300 s` idle timeout；
- 最近关闭连接的 tombstone（TTL `60 s`）；
- 对未知连接告警进行 `10 s` 窗口限速。

## 暂不支持

当前协议尚未实现：

- SACK
- 拥塞控制
- 自适应 RTO
- replay cache
- per-session salt
- key rotation
- traffic padding
- UDP 应用代理转发
