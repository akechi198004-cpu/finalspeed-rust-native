# 使用指南（Usage）

本文给出与当前 CLI 和实现一致的常用命令。

## 构建

Linux：

```bash
cargo build --release
./target/release/fspeed-rs --help
```

Windows PowerShell：

```powershell
cargo build --release
.\target\release\fspeed-rs.exe --help
```

## Linux Server

UDP 模式，仅允许访问 server 主机上的 SSH：

```bash
./target/release/fspeed-rs server \
  --listen 0.0.0.0:15000 \
  --secret test123_secure \
  --allow 127.0.0.1:22 \
  --transport udp
```

TCP fallback 模式：

```bash
./target/release/fspeed-rs server \
  --listen 0.0.0.0:15000 \
  --secret test123_secure \
  --allow 127.0.0.1:22 \
  --transport tcp
```

`--allow` 是可选参数，但强烈建议开启。若不设置，认证通过的 client 可能要求 server 连接任意 TCP 目标。

## Windows Client

UDP 模式（SSH 映射）：

```powershell
.\target\release\fspeed-rs.exe client `
  --server SERVER_IP:15000 `
  --secret test123_secure `
  --map 127.0.0.1:2222=127.0.0.1:22 `
  --transport udp
```

同样映射下的 TCP fallback：

```powershell
.\target\release\fspeed-rs.exe client `
  --server SERVER_IP:15000 `
  --secret test123_secure `
  --map 127.0.0.1:2222=127.0.0.1:22 `
  --transport tcp
```

在 client 机器测试 SSH：

```powershell
ssh -p 2222 user@127.0.0.1
```

## UDP Transport

UDP 是默认值，以下两条命令等价：

```bash
./target/release/fspeed-rs client --server SERVER_IP:15000 --secret test123_secure --map 127.0.0.1:2222=127.0.0.1:22
./target/release/fspeed-rs client --server SERVER_IP:15000 --secret test123_secure --map 127.0.0.1:2222=127.0.0.1:22 --transport udp
```

每个 UDP datagram 承载一个 encoded packet。

## TCP Transport Fallback

当 UDP 无法到达 server 时使用 TCP fallback。server 与 client 必须同时设置 `--transport tcp`。

```bash
./target/release/fspeed-rs server --listen 0.0.0.0:15000 --secret test123_secure --transport tcp
./target/release/fspeed-rs client --server SERVER_IP:15000 --secret test123_secure --socks5 127.0.0.1:1080 --transport tcp
```

TCP fallback 的 framing 为：`u32` big-endian length + packet bytes。已建立会话会发送 encrypted keepalive，默认每 30 秒一次，用于减少浏览器/SOCKS5 长连接闲置后失效。


## KeepAlive

已建立 session 会发送 encrypted keepalive packet：

- 默认发送间隔：30 秒；
- keepalive timeout：120 秒；
- session idle timeout：300 秒；
- keepalive payload 使用 ChaCha20-Poly1305 AEAD 加密；
- packet header 仍保持明文，用于路由和 AAD 认证。

这个机制主要用于减少 TCP fallback + SOCKS5 浏览器长连接在闲置后被本程序 idle sweep 或中间网络过早清理导致的页面加载失败。

## SOCKS5 Curl 测试

启动 server：

```bash
./target/release/fspeed-rs server \
  --listen 0.0.0.0:15000 \
  --secret test123_secure
```

启动 client 侧 SOCKS5 监听：

```bash
./target/release/fspeed-rs client \
  --server SERVER_IP:15000 \
  --secret test123_secure \
  --socks5 127.0.0.1:1080
```

通过隧道测试：

```bash
curl --socks5-hostname 127.0.0.1:1080 http://example.com
```

当你希望 SOCKS5 请求携带 domain 名（而非本地解析）时，请使用 `--socks5-hostname`。

## 浏览器 SOCKS5 配置

将浏览器或系统代理配置为：

```text
SOCKS host: 127.0.0.1
SOCKS port: 1080
SOCKS version: SOCKS5
Authentication: none
```

浏览器流量建议开启“通过 SOCKS5 远程 DNS 解析”（如果浏览器提供该选项）。浏览器通常产生大量短连接，因此会看到更多 session 生命周期日志。

## SSH 映射示例

Server：

```bash
./target/release/fspeed-rs server \
  --listen 0.0.0.0:15000 \
  --secret test123_secure \
  --allow 127.0.0.1:22
```

Client：

```bash
./target/release/fspeed-rs client \
  --server SERVER_IP:15000 \
  --secret test123_secure \
  --map 127.0.0.1:2222=127.0.0.1:22
```

SSH：

```bash
ssh -p 2222 user@127.0.0.1
```

## GitHub Actions Artifacts

GitHub Actions 构建 workflow 在 Linux 与 Windows 上运行。成功运行后，会在 run 页面上传 `fspeed-rs-linux-x64` 与 `fspeed-rs-windows-x64` artifacts。

## FAQ

### UDP 无法连接到 server

请检查云安全组、VPS 防火墙、本机防火墙、NAT 路径，以及 server 是否监听了预期 UDP 端口。若网络路径屏蔽 UDP，请在两端改用 TCP fallback。

### 如何使用 TCP fallback？

在 server 与 client 两端都加上 `--transport tcp`。不要一端 UDP、一端 TCP 混用。

### Secret 不一致

双方都会从 `--secret` 派生 AEAD key。若值不一致，解密会失败，握手也无法完成。请确保两端字符串完全一致。

### Target not allowed

server 拒绝了请求目标，因为该地址不在 `--allow` 中。请将精确 `SocketAddr`（如 `127.0.0.1:22`）加入 allowlist。开启 `--allow` 时，domain 名会被拒绝。

### Windows 防火墙

在 Windows 上允许 `fspeed-rs.exe` 通过 Defender Firewall，或为 server 监听端口新增 inbound rule。

### Linux 防火墙或云安全组

请同时在云安全组与主机防火墙放行所选 UDP/TCP 端口。UDP 模式下仅放行 TCP 不足以通信。

### 浏览器 SOCKS5 日志很多

浏览器会打开大量短连接。出现大量 connection ID、Close packet，以及偶发“已关闭会话迟到 packet”的 debug 日志是正常现象。

### unknown ConnectionId 是什么？

表示收到一个不属于当前活跃会话的 packet。运行时会为最近关闭会话保留 tombstone，并对重复未知连接告警限速，以避免迟到重传刷屏。

### 是否可用于生产？

暂不建议。当前是实验性隧道，虽有加密和基础可靠性机制，但没有 SACK、拥塞控制、自适应 RTO、replay cache 或 per-session key 隔离等生产级能力。
