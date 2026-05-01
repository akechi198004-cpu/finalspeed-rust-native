# fspeed-rs

## 1. 项目简介 (Project Introduction)

**fspeed-rs** 是一款基于 Rust-native 构建的可靠 UDP 隧道（reliable UDP-style tunnel）工具，旨在为 TCP 服务加速实验提供底层承载支持。

- 采用 **client/server 双端转发** 结构，允许客户端通过隧道将本地 TCP 流量映射至远端服务端所指向的目标 TCP 端口。
- 采用 **自定义可靠协议结构**，专注于轻量化传输。
- **不兼容** 原始 Java FinalSpeed 协议。
- **支持 SOCKS5 代理** 客户端内置可选 SOCKS5 (无鉴权) 服务，支持动态建立隧道代理网络请求。
- **不使用** QUIC。
- **不使用** fake-TCP 或基于 pcap 的发包拦截机制。

---

## 2. 当前状态 (Current Status)

目前项目已经完成了基础数据面（basic data plane）转发：

- **基础隧道**：具备完整的 TCP 监听、TCP/UDP 流拆分、UDP 数据封装和连接表的生命周期管理。并支持 TCP Transport Fallback (`--transport tcp`) 模式。
- **控制原语**：实现了 `OpenConnection` 带有显式握手的双端握手机制解析。支持针对时间戳的安全验证、`allowlist` 服务端目标白名单限制，并具备对端同步回传加密的 Ack/Error 同步机制以阻塞 Client 不发送无用 Data。这为后续支持 SOCKS5 CONNECT 的双向结果传导奠定了基础。
- **数据加密层**：隧道内部的所有 Payload（包含 OpenConnection、Data、Ack、Error、Close）均已通过基于 `HKDF-SHA256` 衍生的 `ChaCha20-Poly1305` AEAD 算法进行对称加密和认证（AAD 包含 Header）。抓包将无法获得明文目标地址、响应状态以及被承载的 TCP 内容。
- **传输层构建**：UDP datagram 能够完整进行封包与解包，并验证 Magic、Version 等协议报头及 `FLAG_ENCRYPTED` 安全标志。在使用 `--transport tcp` 时，提供长度前缀的 Framing 帧协议支持。
- **自动验证**：具备基于本地 loopback 的自动集成测试和通过 GitHub Actions (Linux x64 / Windows x64) 运行的 CI 工作流。
- ⚠️ **当前状态警告**：目前项目已将基础的滑动窗口（Sliding Window）、累计确认（Cumulative Ack）、重传列队（Retransmission）**完整接入**真实的 Data Plane 收发平面。在弱网环境下已具备基本的丢包容忍与乱序重排能力。但需要注意的是，**本协议仍处在实验阶段**，**暂不支持** 高级拥塞控制（Congestion Control）、自适应超时计算（Adaptive RTO）及选择性确认（SACK），在极端环境下可能引发阻塞堆积。**因此依旧不建议应用于任何重资产的生产环境中。**

---

## 3. 构建方法 (Build Instructions)

本项目推荐使用 Rust 官方 stable toolchain 编译：

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo build --release
```

---

## 4. 运行示例 (Usage Examples)

以下给出了在开发环境下使用的最小化测试方式。**请注意：这些测试示例假设目标机器上存在真实的运行服务（如 SSH 或 HTTP 服务）。**

### SSH 加速映射
*场景：本地通过 2222 端口，连接被加速服务端的 22 端口。*

**Server (服务端运行):**
```bash
cargo run --release -- server --listen 127.0.0.1:15000 --secret test123 --allow 127.0.0.1:22
```

**Client (客户端运行):**
```bash
cargo run --release -- client --server 127.0.0.1:15000 --secret test123 --map 127.0.0.1:2222=127.0.0.1:22
```

测试连接：
```bash
ssh -p 2222 user@127.0.0.1
```

### TCP Fallback 模式 (TCP 传输后备)
*场景：当目标 VPS 无法接受 UDP 流量时，可强制通过 TCP Transport 传输原有协议。该模式使用 Length-prefixed framing，且不破坏现有 SOCKS5/加密及可靠层，但可能失去加速效果。*

**Server (服务端运行):**
```bash
cargo run --release -- server --listen 0.0.0.0:15000 --secret test123 --transport tcp
```

**Client (客户端使用 SOCKS5 代理):**
```bash
cargo run --release -- client --server SERVER_IP:15000 --secret test123 --transport tcp --socks5 127.0.0.1:1080
```

### SOCKS5 动态代理映射
*场景：将本地所有的代理流量通过隧道安全传输到服务端并动态请求对应互联网资源。*

**Server (服务端运行):**
*(注意: 提供 SOCKS5 代理往往意味着服务器成为跳板，请在安全可控环境或严格配合 --allow 参数使用)*
```bash
cargo run --release -- server --listen 0.0.0.0:15000 --secret test123
```

**Client (客户端内建 SOCKS5 监听):**
```bash
cargo run --release -- client --server SERVER_IP:15000 --secret test123 --socks5 127.0.0.1:1080
```

测试代理连接：
```bash
curl --socks5-hostname 127.0.0.1:1080 http://example.com
```

---

## 5. 参数说明 (CLI Parameters)

### Server 参数
- `--listen`: 监听的本地地址和端口。例如 `0.0.0.0:150`。
- `--secret`: 隧道接入密码。客户端必须提供一致的密码才能接入建立连接。
- `--allow`: Server-side target allowlist。限制客户端允许请求连接的白名单目标地址列表。如 `--allow 127.0.0.1:22,127.0.0.1:80`。
- `--transport`: 指定隧道传输层协议，可选 `udp` 或 `tcp`，默认 `udp`。

### Client 参数
- `--server`: 隧道远程服务端的地址和端口。例如 `198.51.100.1:150`。
- `--secret`: 隧道接入密码。需要与服务端配置匹配。
- `--map`: 静态端口映射规则，格式为 `local_addr:local_port=target_addr:target_port`。
  - 例如 `127.0.0.1:2222=127.0.0.1:22`，表示把本地 TCP 2222 端口的流量隧道转发到目标远端服务 22 端口。支持传入多条规则映射。
- `--socks5`: 动态代理绑定地址。例如 `127.0.0.1:1080`。支持解析远端 IPv4 及 Domain 域名，SOCKS5 入口仅在客户端有效。
  - *注意：Client 启动至少需要提供一个 `--map` 或 一个 `--socks5` 监听，两者支持组合同时使用。*
- `--transport`: 指定隧道传输层协议，可选 `udp` 或 `tcp`，默认 `udp`。

---

## 6. GitHub Actions 自动构建 (CI Artifacts)

本项目通过 GitHub Actions 实现了跨平台的自动化构建与校验。

- 触发条件：对 `main` 分支的 **push** 以及 **pull_request**。
- 执行流程：每次触发均自动运行 `fmt` 格式化校验、`clippy` 静态错误检测、单元和集成 `test` 测试，以及 `release build` 发布编译。
- 编译构件 (Artifacts)：
  编译好的 release 级二进制执行文件会作为 Artifacts 挂载到工作流执行结果中，供下载：
  - `fspeed-rs-linux-x64`
  - `fspeed-rs-windows-x64`

*(下载方式：在 Github Actions 的目标 workflow run 页面底部，即可点击下载构建产物 Artifacts)。*

---

## 7. 安全说明 (Security Notice)

- 项目采用基于共享 `secret` 配合 `HKDF-SHA256` 派生的密钥机制，使用 `ChaCha20-Poly1305` AEAD 进行 payload 的全程加密。
- 数据包中的 Header 部分（包括 connection_id 等流信息）目前仍为**明文**传输，仅供内部路由器处理。但是 AEAD 的 AAD 机制确保了明文头部防篡改。
- 虽然协议实现了包含 Unix timestamp ms 的鉴权原语机制来防备基础重放，但当前代码尚未接入**重放缓存 (replay cache)**、**动态 per-session salt**、**按时密钥轮换 (key rotation)** 以及**流量混淆 (traffic padding)**。所以针对复杂的流量侧写分析（Traffic Analysis）仍存在特征识别风险。
- ⚠️ **强烈建议**在启动 Server 时明确配置 `--allow` 目标地址白名单，以防服务端被恶意用作全网开放的任意 TCP 转发代理。特别是开放客户端 SOCKS5 功能时，服务端的远端路由请求可能不可控。

---

## 8. Roadmap (发展路线图)

- **Phase 5**：将当前的 ACK 确认、数据包重传（Retransmission）与滑动窗口（Sliding Window）实现代码完整对接并应用于真实的数据流平面 (Data Plane)。
- **Phase 6**：完善更鲁棒和干净的连接关闭（Connection Teardown）流程和 Half-Close 处理（已部分实现 Session Tombstone 与 Close 自动清理）。
- **Phase 7**：引入更加结构化、可复用的持久化外部配置文件系统。
- **Phase 8**：安全协议层增强完善：全面接管 per-session salt / replay cache 防护矩阵。
