# FinalSpeed 分析

## 1. 项目结构概览

主要目录结构如下：

- `src/net/fs/client/`: 客户端逻辑。包含配置读取、端口映射管理、无 UI 与有 UI 两种客户端的实现。
  - `FSClient.java`: 客户端启动类。
  - `ClientNoUI.java` / `ClientUI.java`: 客户端实现（区分是否带 GUI）。
  - `PortMapManager.java`: 端口映射配置加载和监听建立。
  - `PortMapProcess.java`: 处理具体的一条端口映射链路上的数据中转。
- `src/net/fs/server/`: 服务端逻辑。
  - `FSServer.java`: 服务端启动类。
  - `MapTunnelProcessor.java`: 服务端处理端口映射数据中转，将收到的请求转发到目标服务。
- `src/net/fs/rudp/`: RUDP (Reliable UDP) 协议层的核心实现。负责基于 UDP （或伪造的 TCP）上实现可靠传输。
  - `Route.java`: 路由管理，负责监听、分发数据包，和连接管理。
  - `ConnectionUDP.java`: RUDP 核心连接类。
  - `Sender.java`: 发送端逻辑（滑动窗口、发送队列）。
  - `Receiver.java`: 接收端逻辑。
  - `ClientControl.java`: 客户端控制，包括限速、心跳管理等。
- `src/net/fs/rudp/message/`: 定义了所有的自定义协议消息，如 `DataMessage`, `AckListMessage`, `PingMessage` 等。
- `src/net/fs/cap/`: libpcap/WinPcap 抓包实现，用于伪装 TCP 流量。
  - `CapEnv.java`: 封装了 pcap 的环境变量与监听操作。
  - `TCPTun.java`: 伪造 TCP 包头、构造类似 TCP 握手和 ACK 的逻辑。

## 2. 程序入口

- **Client 侧入口**: `src/net/fs/client/FSClient.java`
  - 使用 `main` 函数启动 `ClientUI` 或 `ClientNoUI`。默认无参数情况下可能启动带有 UI 的客户端。
- **Server 侧入口**: `src/net/fs/server/FSServer.java`
  - 使用 `main` 函数启动。根据操作系统不同，会自动调用系统防火墙命令（如 iptables、netsh）来拦截特定端口的流量。

## 3. Client 侧行为

1. **读取配置**: `ClientNoUI.java` 会调用 `loadConfig()` 读取 `client_config.json`（服务器地址、端口、速率限制）。
2. **建立本地监听**: `PortMapManager.java` 会读取 `port_map.json`，为每一条映射规则（`MapRule`）在本地开启一个 `ServerSocket`，并在该端口进行 accept() 监听。
3. **接收本地 TCP 连接**: 本地端口有连接时，`PortMapManager` 的监听线程调用 `serverSocket.accept()` 建立 Socket，然后创建 `PortMapProcess`。
4. **将 TCP 数据交给 FinalSpeed 协议层**: `PortMapProcess` 会将对应的源 Socket (`srcSocket`) 的输入输出流与 `ConnectionUDP` 提供的假输入流 (`tis` / `UDPInputStream`) 和输出流 (`tos` / `UDPOutputStream`) 用 `Pipe` 进行双向 pipe：
   - 客户端在连接建立前发送一段 JSON: `{"dst_address":"...","dst_port":...,"password_proxy_md5":"..."}` 告诉 Server 目标去向。
   - 然后分别启动两个线程，将 `srcIs` 的数据 pipe 到 `tos` (发往 RUDP 层)，将 `tis` 的数据 pipe 到 `srcOs` (写回本地客户端)。
5. **与 Server 通信**: 流量经过 `UDPOutputStream` 到达 RUDP 层，由 `Sender.java` 切片打包成 `DataMessage`，发往底层 `Route` 传送到服务器。

## 4. Server 侧行为

1. **启动监听**: `FSServer.java` 启动并初始化 `Route`。它不仅能监听 UDP，还能借助 pcap 和 iptables 开启 TCP fake-tun 监听。
2. **接收 client 数据**: `Route.java` 中有一个专门的线程监听端口或 pcap 数据包。当有包进来时，根据包头解析出这是数据、心跳等消息，并交给对应的 `ConnectionUDP` 的 `Receiver` 处理。
3. **还原 TCP 连接**: 对于具体的映射连接，`MapTunnelProcessor.java` 会读取最初发来的 JSON：获取目标服务端口（`dst_port`）。
4. **连接目标服务**: `MapTunnelProcessor` 通过 `new Socket("127.0.0.1", dst_port)` 在服务端本地连接真正的目标服务。
5. **将目标服务返回数据发回 client**: 同样使用 `Pipe` 进行双向流拷贝。RUDP 层的 `UDPInputStream` 收到的数据发给 `Socket`的 output，`Socket` 的 input 收到的数据交给 `UDPOutputStream`，由 `Sender` 送回客户端。

## 5. 端口映射模型

配置主要在 `port_map.json`，在 `ClientConfig` 与 `PortMapManager` 层面进行解析。
格式：
```json
{
    "map_list": [
        {
            "dst_port": 12345,
            "listen_port": 1099,
            "name": "ss"
        }
    ]
}
```
- **listen_port (local port)**: 客户端本地启动监听的端口。
- **dst_port (target port)**: 服务端最终需要连接的端口号。因为 FinalSpeed 一般用作代理到服务端本机的流量（常见是 ss/ssh 端口），因此 `target host` 在代码里默认是 `"127.0.0.1"`（见 `MapTunnelProcessor.java` 第 56 行）。
- **remote/server port**: Client 与 Server 通信的主控制/传输端口，在 `client_config.json` 中的 `server_port` 指定。

## 6. 原始网络模型判定

- **加速对象**: FinalSpeed 加速的是 **TCP 服务**（通过将客户端 TCP 数据流接管并转发）。应用层并未支持 UDP 代理转发（代码中没有相关 `DatagramSocket` 接管目标逻辑）。
- **承载方式**:
  - 支持 **UDP 承载**（直接发送 DatagramPacket）。
  - 支持 **伪造的 TCP 承载**（TCP Fake-Tun）。
- **libpcap / WinPcap 的使用**:
  - **是**的，使用了。在 `src/net/fs/cap/` 包下，包括 `CapEnv.java` 和 `TCPTun.java`。
  - **用途**: 当客户端配置为 `"protocal": "tcp"` 时，系统为了能利用防火墙/QoS策略，会将数据封装进伪造的 TCP 报文。
    - 服务端通过 `iptables` 丢弃真实内核对该监听端口（例如150）的 TCP 包 (`iptables -j DROP`，见 `FSServer.java` )，防止系统内核发送 RST。
    - 然后利用 libpcap (`PcapHandle`) 在链路层抓取该端口的以太网帧，并在应用层手动解析 IPv4/TCP 报头（如三次握手），并将 RUDP 数据附带在伪造的 TCP Payload 中。

## 7. 原始协议分析

FinalSpeed 自定义了一套基于消息的 RUDP（Reliable UDP）协议。所有消息基础类为 `Message.java`。

**包格式 (通用 Header)** (推导自 `Message.java`, `DataMessage.java`, `AckListMessage.java` 等):
*不确定字段字节大小的部分由 `ByteShortConvert` 和 `ByteIntConvert` 确认。*
- **ver** (`short`, 2 bytes): 协议版本号, 偏移 0。
- **sType** (`short`, 2 bytes): Message/Packet type, 偏移 2。例如 `80` 为 `DataMessage`，`60` 为 `AckListMessage`，`301`/`302` 为 `Ping`。
- **connectId** (`int`, 4 bytes): 连接ID (Session ID), 偏移 4。
- **clientId** (`int`, 4 bytes): 客户端ID, 偏移 8。

以 **DataMessage** (sType=80) 为例 (见 `DataMessage.java`):
- `sequence` (`int`, 4 bytes): RUDP层的 Sequence Number, 偏移 12。
- `length` (`short`, 2 bytes): Data 的长度, 偏移 16。
- `timeId` (`int`, 4 bytes): 供限速与丢包统计使用的时间窗口ID, 偏移 18。
- `data`: 偏移 22，实际的载荷。

以 **AckListMessage** (sType=60) 为例 (见 `AckListMessage.java`):
- `lastRead` (`int`, 4 bytes): 连续收到并读取的最大 Sequence, 偏移 12。
- `ackList.size()` (`short`, 2 bytes): 确认散列包数量，偏移 16。
- 后跟一系列散列的 `sequence` (每个 4 bytes)。
- 尾部还附带了近期 `timeId` 的传输统计量（用于流量控制和判断丢包）。

**机制分析**:
- **Connection ID**: 用于标识具体的业务连接 (`ConnectionUDP`)。
- **Sequence**: 发送的包序号，单位是 **包数量** (从 0 开始递增)，而不是像标准 TCP 那样的字节数（见 `Sender.java:94`）。
- **ACK机制**: 使用 `AckListMessage`。不仅确认 `lastRead` (即累积确认)，还在后面带上乱序到达的 `ackList` (SACK机制)。
- **重传机制**:
  - `ResendManage.java`: 延迟队列。发送端通过 RTT (来自 ping 的估算) 动态设置定时器，定时器到期后重发未被 ACK 的包。
- **窗口机制**:
  - 在 `Receiver.java` 中定义了 `availWin`（最大窗口，默认 5120 即 `5 * 1024` 包），当收发相差过大时通过 `checkWin()` 判断，如果超过窗口 Sender 则 `wait()` 阻塞。
- **限速机制**:
  - 在 `ClientControl.java` 的 `sendSleep()` 中实现。按时间窗口 `timeId` 计算已发数据，如果发送过快则调用 `Thread.sleep()` 在当前线程中阻塞。
- **心跳/Keepalive**:
  - `PingMessage` 和 `PingMessage2`。定期发送以测量延迟并交换双端设置的最大下载/上传速度。
- **连接关闭流程**:
  - 拥有 `CloseMessage_Stream` (sType=75) 和 `CloseMessage_Conn` (sType=76)。
  - `CloseMessage_Stream` 带一个 `closeOffset`（即最后一个包的 Sequence），等接收端收到了这个序号之前的所有数据后才真正 close。

## 8. Rust 重写应保留的部分

1. **TCP 服务加速模型**: 保持将本地 TCP 转封装为 UDP/Fake-TCP 进行传输的核心逻辑。
2. **Client/Server 双端结构**: 维持端到端体系，方便跨环境部署。
3. **端口映射模型**: 兼容 `port_map.json` 形式，读取 `dst_port` 与 `listen_port`。
4. **底层传输逻辑兼容**: 如果一阶段要和 Java 交互，那整个 Message 的打包拆包（2字节ver, 2字节type, 4字节connId等）机制都需 1:1 保留。
5. **CLI 化运行**: 移除任何多余东西，通过命令行启动。
6. **Ping/RTT 机制**: 需保留以用于 RTT 的计算。
7. **拥塞/重传控制**: RUDP 的重发定时器逻辑（基于发送窗口和未确认队列的重传机制）。

## 9. Rust 重写应放弃的部分

1. **GUI 及其相关代码**: `ClientUI.java`、`AddMapFrame.java` 等一切 `javax.swing.*` 代码。
2. **Java 特有的打包/过时依赖**: 不要使用 fastjson，而应在 Rust 中使用 `serde_json`。
3. **平台特定的脚本与过时命令行调用**:
   - 不在应用层写死 `netsh` 或 `ipseccmd.exe` 等防火墙规则代码。应当在文档里要求用户手动配置，或提供专门的 Shell 脚本而非内置于 Rust。
   - 代码中诸如检测网卡并强制重启网卡的 Hack（如 `CapEnv.java` 里的 `systemSleepScanThread`）应去掉。
4. **WinPcap/libpcap (如果不追求 tcp fake-tun 兼容)**:
   - 如果一阶段只是为了分析和核心重构，建议暂时放弃 pcap 模式（TCP承载），只实现纯 UDP。若必须实现 TCP tun，推荐使用跨平台的 `smoltcp` 或者直接通过 TUN 设备，而不是强依赖于 pcap 抓包抓以太网帧的方式。

## 10. Rust 重写建议

- **是否应该复刻原始协议 / Wire-Compatible**
  - 理论上 **可以做到 Wire-Compatible**。因为协议包结构都是定长偏移量的二进制序列，不存在无法翻译的 Java 序列化特征。
  - **Rust client 连接 Java server** 与 **Java client 连接 Rust server** 理论上完全可行。
  - **需要复刻的细节**: `Message` 的所有 `sType`（80，60，301等），`DataMessage`，`AckListMessage` 的精确序列化格式，以及最初端口映射时发的 JSON Auth Payload。
  - **兼容困难的部分**:
    1. Java 的 `Thread.sleep` 限速非常粗糙而且耦合度高，Rust 使用 Tokio 异步改写时如果不小心，可能会与 Java 的发包节奏不一致导致另一端重传激增。
    2. TCP 伪装。如果要写出和 Java `PacketUtils.java` 中一模一样的以太网帧、IPv4、TCP 校验和，容易踩坑。建议阶段一仅做 UDP 模式互通。

- **第一阶段最小可行路线 (MVP)**
  1. 放弃 pcap/TCP Fake-Tun，强制仅实现 UDP RUDP 协议互通。
  2. 实现 `Message` 的 parse 和 serialize。
  3. 实现本地 Listener，监听 TCP，并将流转换为 `DataMessage`。
  4. 实现滑动窗口接收，根据收到的 Sequence Number 重组 TCP 字节流，并处理 `AckListMessage`。
  5. 进行 Rust Client 和 Java Server 在局域网内的单 TCP 流量测试。

---

## 附录：特殊行为与兼容风险

1. **协议层强依赖时间窗口 (TimeId)**
   `timeId` 是基于开始运行的 Epoch (`(current - startSendTime) / 1000`) 来计算的。服务端与客户端各自以自身启动为基准计算 timeId。在 `AckListMessage` 里，客户端强行回传最近 3 秒 (`timeId`, `timeId-1`, `timeId-2`) 的流量统计。这部分逻辑极其容易在异构重写时因时钟同步偏差或统计不准而引起逻辑崩溃。
2. **连接初始化时的 JSON**
   代码使用 `{ "dst_address": "...", "dst_port": ..., "password_proxy_md5": "..." }` 进行初始化通信。这部分是以 raw bytes 混合进传输流的最开头，由于没有长标识符界定，很容易产生边界问题。
3. **TCP 伪造使用 pcap**
   Java 版中 `FSServer` 依赖外部命令 `iptables -j DROP` 丢弃内核的 TCP 控制。这是严重的 Hack，直接导致同一台机器上其他服务的干扰以及极度不稳定的兼容性。如果可能，后续重写应当放弃这种在应用层用 pcap 造 TCP 的设计，改用标准的 TUN 设备。
