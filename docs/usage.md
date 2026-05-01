# fspeed-rs 使用指南 (Usage Documentation)

本指南面向最终使用者，详细描述如何在不同环境下构建、测试及部署 **fspeed-rs**。

## 1. Linux 构建和运行

建议在具有完整 Rust 开发环境的主机（如 Ubuntu/Debian/Arch 等）下进行编译构建：

1. **环境准备:**
   如果尚未安装 Rust，请运行以下官方脚本安装 stable toolchain：
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```
2. **下载与编译:**
   ```bash
   git clone <repository_url>
   cd fspeed-rs
   cargo build --release
   ```
3. **运行:**
   编译好的二进制文件位于 `target/release/fspeed-rs`。
   ```bash
   # 查看帮助菜单
   ./target/release/fspeed-rs --help
   ```

## 2. Windows 构建和运行

对于 Windows 用户，建议安装包含 C++ 负载的 [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) 以及 `rustup` 环境。

1. **环境准备:**
   下载并运行 [rustup-init.exe](https://win.rs/rustup-init.exe)。
2. **下载与编译:**
   使用 Git CMD / PowerShell 下载仓库：
   ```powershell
   git clone <repository_url>
   cd fspeed-rs
   cargo build --release
   ```
3. **运行:**
   产物位于 `target\release\fspeed-rs.exe`。
   ```powershell
   .\target\release\fspeed-rs.exe --help
   ```

## 3. 从 GitHub Actions 下载 Artifacts

如果不想在本地编译，可直接通过 GitHub 获取最新构建的执行程序。

1. 打开项目 GitHub 主页。
2. 进入顶部的 **Actions** 标签栏。
3. 选中最近成功的一个 **"build"** workflow run 记录。
4. 在页面底部的 **Artifacts** 区域，直接点击下载目标系统的压缩包：
   - `fspeed-rs-linux-x64`
   - `fspeed-rs-windows-x64`
5. 解压后赋予执行权限（针对 Linux: `chmod +x fspeed-rs`）。

## 4. 本机 Loopback 快速测试

本机回环（loopback）测试是验证基础逻辑的最快方式，假定我们在本地进行 `echo` 服务等简单路由验证。

**启动 Server:**
```bash
./fspeed-rs server --listen 127.0.0.1:15000 --secret dev_test --allow 127.0.0.1:22
```

**启动 Client:**
将本地 TCP 2222 端口转发至服务端所在机器的本地（即 127.0.0.1）22 端口：
```bash
./fspeed-rs client --server 127.0.0.1:15000 --secret dev_test --map 127.0.0.1:2222=127.0.0.1:22
```

## 5. 远程 VPS 部署测试方式

这是最常见的生产或实验场景，将 **fspeed-rs** 用于跨地域的网络优化。

**在境外/目标 VPS 运行服务端:**
*(假设公网 IP 为 `198.51.100.1`，想要加速其上的本地 ssh 22 端口服务)*
```bash
# 绑定在 VPS 的所有网卡 UDP 15000 端口
./fspeed-rs server --listen 0.0.0.0:15000 --secret your_secure_pass --allow 127.0.0.1:22
```

**在本地/个人电脑运行客户端:**
```bash
# 指向 VPS 远端，将本机 2222 端口进行映射穿透
./fspeed-rs client --server 198.51.100.1:15000 --secret your_secure_pass --map 127.0.0.1:2222=127.0.0.1:22
```

## 6. SSH 映射示例

成功执行上述步骤后，便可通过本地连接间接访问 VPS：
```bash
# 通过 2222 端口，隧道将流量转给远端的 22 端口
ssh -p 2222 root@127.0.0.1
```

## 7. HTTP 映射示例 与 SOCKS5 代理模式

如果您在 VPS `8080` 端口搭建了一个内部测试 Web 服务。

**服务端白名单许可:**
```bash
./fspeed-rs server --listen 0.0.0.0:15000 --secret your_secure_pass --allow 127.0.0.1:8080
```

**客户端静态端口映射:**
```bash
./fspeed-rs client --server 198.51.100.1:15000 --secret your_secure_pass --map 127.0.0.1:18080=127.0.0.1:8080
```

**静态映射访问验证:**
```bash
curl http://127.0.0.1:18080
```

如果您不想配置复杂的静态 Map 列表，希望利用浏览器等原生代理功能直接利用远端服务端去触达公网/内网，也可以使用 **SOCKS5** 动态代理模式。

**注意：SOCKS5 入口服务只应开启在 Client（客户端本地计算机）侧，请不要将它暴露。这有助于保护远端 Server 不被任意人拿作跳板。**

**客户端动态 SOCKS5 监听配置:**
```bash
./fspeed-rs client --server 198.51.100.1:15000 --secret your_secure_pass --socks5 127.0.0.1:1080
```
**动态代理访问验证:**
```bash
curl --socks5-hostname 127.0.0.1:1080 http://example.com
```

## 8. 常见问题 (FAQ)

**Q: Client 连不上 Server 怎么办？**
- 检查您的客户端指定的 `--server` IP 地址与端口是否正确。
- 检查是否存在网络隔离，可尝试在服务端运行 `tcpdump udp port 15000` 观测服务端是否确实接收到了包。

**Q: Server 日志提示收到 `Malformed packet received`？**
- 此提示意味着收到了不符合本系统自定义报头格式的 UDP 数据包。由于 UDP 端口长期对外暴露，可能受到来自外网扫描工具的探测报文干扰。本项目不建议暴露在外网，如遇该提示且源 IP 非您的 Client IP，可暂时忽略。

**Q: 日志提示 `DecryptFailed` / `Invalid shared secret` 等认证错位提示？**
- 此时代表用于衍生密钥匹配的 Client `--secret` 和 Server 的 `--secret` 不相符。请确保两端传入的鉴权字符串一模一样，否则 Server 将拒绝回送握手 Ack 并直接通过加密流回绝错误终止请求。

**Q: 日志提示 `Target not allowed`？**
- 这是出于安全考量。Client 请求将流量映射到的 `target`（如 `--map ...=192.168.1.100:80`），但是该 `target` 不在 Server 启动时传入的 `--allow` 列表里。请将需要的 IP 及端口加入服务端白名单参数中。Server 会回发加密的 `Error` packet 并在 Client 输出警告断言。

**Q: 启动提示端口已被占用 (Address already in use)？**
- 这是因为您设置监听的 TCP 或 UDP 端口当前正被其他应用程序使用。您可以选择修改绑定的本地端口，或通过 `netstat` / `lsof` 排查占用该端口的进程并关闭它。

**Q: Windows 环境下无法连接？**
- **Windows Defender 防火墙阻止** 是常见原因。当您首次启动 `fspeed-rs.exe` 时，若弹出网络许可请求，请允许应用程序通过专用/公用网络。也可通过防火墙高级设置手动入站 UDP 和 TCP 端口放行。

**Q: Linux 环境下无法连接？**
- 您的 VPS 厂商（如 AWS、Alibaba Cloud）通常具有外部安全组，且默认情况下可能仅仅放通了 TCP。请前往云平台控制台页面，显式放通 **UDP** 协议和对应的服务端监听端口（如 UDP 15000）。
- 系统内部 `iptables` / `ufw` 可能拦截了 UDP 流量。通过 `sudo ufw allow 15000/udp` 开放端口。

**Q: 传输速度慢 / 存在严重丢包，这套协议完全稳定吗？**
- **重要提醒**：当前版本（Phase 4.3）依然属于前期的基础数据面与加密面（AEAD）验证阶段。**当前版本还不是完整可靠 UDP**。
- 尽管我们编写了握手同步并前置了核心的 ACK/Retransmission 及 Sliding Window 框架，但尚未被完整耦合到真实连续双发 TCP->UDP 通信逻辑中。当前的 Data 发送是 UDP 不保序单发，若网络剧烈颠簸丢失即丢失，无法进行高级弱网恢复与纠错补偿。未来的版本（Phase 5 及后续）才会实装完整的可靠性加速特性。

## Transport Modes

`fspeed-rs` supports two transport modes for sending packets between the client and server: UDP and TCP. You can choose the transport mode using the `--transport` flag on both the client and server.

- **UDP (Default)**: A pure UDP transport mode where each packet corresponds to a single UDP datagram. This is the primary target for `fspeed-rs` and provides the best performance for accelerating TCP streams.
- **TCP (Fallback)**: A TCP transport mode where packets are encoded into length-prefixed frames and sent over a TCP connection. Use this mode if your network environment or VPS restricts UDP traffic. Note that TCP transport maintains the reliable runtime and encryption features but does not guarantee the same acceleration effects as UDP transport, as TCP already provides reliable stream transmission.

**Q: Server/Client 日志为什么有时候会有 `Dropping late packet for recently closed ConnectionId` 或 `Dropping repeated packet for unknown ConnectionId` 的 debug 提示？**
- 浏览器或其他应用使用 SOCKS5 时通常会创建大量的短连接。当这些连接在程序内部被正常释放关闭后，网络上由于延迟或重传，仍有可能收到属于这些已关闭连接的迟到数据包（如 Data、Ack 或 Close）。程序内置了 Tombstone (墓碑) 和 Rate-Limit 机制，会静默丢弃这些已失效连接的遗留报文，从而避免大量的无效 Warning 警告刷屏。
