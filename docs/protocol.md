# fspeed-rs 协议设计说明 (Protocol Documentation)

本指南针对协议设计本身进行解构阐释。注意：这是 **fspeed-rs** 项目自定义建立的 **Rust-native** 协议体系说明，它不遵循、且有意拒绝 Java 版 FinalSpeed 格式兼容性。

## 1. 协议目标 (Goals)

- **封装承载**：在不可靠的 UDP Datagram 上透明且安全地承载纯粹的 TCP Byte Stream（面向连接的字节流）。
- **双端转发**：原生支持 `client` 与 `server` 跨网映射架构下的双向解包与发包。
- **并发标识**：支持 `connection_id` 特性以对多条并发路由进行有效区分，防止混淆串包。
- **状态追踪**：内置 `sequence`（序列号）、`ack`（确认号）、`window`（滑动窗口）基础字段位。
- **演进铺垫**：此报头形态为后续迭代升级入栈 ARQ 重传机制（retransmission）及流量控制（sliding window）提供不可或缺的基础数据结构基石。

## 2. 非目标 (Non-Goals)

为了保证实现的聚焦和系统轻巧性，本项目排除了以下方向：
- **不兼容 Java FinalSpeed**：未对原版本作 Wire-compatibility 支持，不继承其庞杂机制。
- **不使用 QUIC**：虽然同样是基于 UDP 的可靠协议，但引入 `quinn` 等三方框架违背了本自研加速协议实验的初衷。
- **不实现 UDP 应用代理**：当前专职隧道化代理 TCP 层面的负载，不处理应用级 UDP 的封装转发。
- **不实现 Fake-TCP / Pcap**：坚决摒弃拦截底层网卡伪造链路报文的方式，保证本工具的纯属应用层实现（跨平台高）。
- **当前没有加密**：此阶段属于加速原型验证期，尚不涵盖 Payload 解密验证相关的加密保护。

## 3. Packet Header 格式 (Format)

所有封装的 UDP Datagram 都遵循下表所述的全局统一包头格式规范。

| Offset | Field | Size | Type | Description |
|---|---|---|---|---|
| 0 | `magic` | 2 bytes | `u16` | 魔数验证字 (Magic Bytes)，必须为固定合法值标识报文 |
| 2 | `version` | 1 byte | `u8` | 协议版本号，当前版本默认有效字段值为 `0x01` |
| 3 | `packet_type` | 1 byte | `u8` | 指示该包具体生命周期类型 (枚举：详见后续章节) |
| 4 | `flags` | 2 bytes | `u16` | 扩展标记位（当前保留为 0x00 或简单位域扩展） |
| 6 | `connection_id`| 4 bytes | `u32` | 每个隧道会话对应的逻辑链接唯一表示 |
| 10 | `sequence` | 4 bytes | `u32` | 此报文发送序号（单调递增，供保序和重传比对） |
| 14 | `ack` | 4 bytes | `u32` | 累计确认序号（累计收到对端的报文数位） |
| 18 | `window` | 2 bytes | `u16` | 宣告的接收端滑动窗口剩余可用大小阈值 |
| 20 | `payload_len` | 2 bytes | `u16` | 紧随 Header 后携带负载 Payload 数据长度 |

**核心校验说明:**
- Header 固定长度：`HEADER_LEN` = 22 bytes。
- 字节序设定：全部统一使用 **Big-Endian (大端序/网络字节序)**。
- 定位约束：承载的业务负载 (`payload`) 必须严格、紧凑地拼接到头部最后。
- UDP 严格大小映射：整个接受到的网络 UDP Datagram 长度**必须精确等于** `HEADER_LEN + payload_len`。
- 多余尾部数据 (trailing bytes) 将判定为错误报文直接丢弃。
- 总长度短于标称甚至截断表头的报文 (truncated packet) 将直接拦截并抛弃异常。

## 4. PacketType

根据上述表的 Offset 3 所在 `packet_type` 字段数值定义：

- `OpenConnection` (`0x01`): 建立虚拟 UDP 隧道的握手原语，携带关键验证与建立请求体。
- `Data` (`0x02`): 隧道处于 ESTABLISHED 态后承载真实双向 TCP `Payload` 的数据分组。
- `Ack` (`0x03`): 纯应答机制包，负责传达控制状态（即将实装，当前处于占位规划）。
- `Close` (`0x04`): TCP 层触发 `EOF` 后用于清理双端映射路由、主动宣告优雅终止隧道资源释放的分组。
- `Error` (`0x05`): 指示非标准状态失败响应，如服务端驳回非法连接（当前在底层结构体中作为基础变体）。

## 5. OpenConnection Payload

对于 `OpenConnection`（建立连接）报文，内部存在特定的明文鉴权 Payload 要求。目前使用的是兼容早期（Phase 2/4）设计的临时 Payload 结构。格式采用行协议。

**基础示例如下：**
```
secret=test123
target=127.0.0.1:22
```

**解析校验与要求:**
- 采用 **UTF-8** 编码格式传输。
- 行分割支持 `\n` 或 `\r\n`。
- Key-Value 字典键的顺序是无须固定的。
- 如果存在未定义的 key（Unknown key），则服务端触发阻断。
- 如果同一个 key 被重复定义（Duplicate key），则服务端触发阻断。
- 服务端会提取 `secret` 值并比对其启动时存储的密钥以完成验证。
- 服务端会提取 `target` 地址，比对配置开启时的 `--allow` 白名单校验放行权限。

## 6. Data Packet

**当前 Phase 4 基础数据面状态下的工作方式：**
- `Data` 类型包确实正有效地承载被拆分的 TCP payload。
- 报文中诸如 `sequence`、`ack`、`window` 等控制字段的写入流程确实已在代码层进行了映射与装载。
- **重要提醒**：当前的可靠传输基础运行时（Reliable Runtime）**尚未真正耦合介入**真实的 Data Plane 操作流程。目前数据发送仍然为快速单调发包循环。

## 7. Ack / Retransmission / Window 当前状态

项目内部文件（如 `src/reliability.rs`）虽实现了滑动控制流框架体系：
- 存在被独立测试验证过的 `SendState` 和 `ReceiveState` 状态机。它们被设计用来支持 ARQ RTO（重传超时测算）处理、失序丢包缓存及 Duplicate-Drop（重复丢弃）判定。
- **但截止当前版本**，这套可靠网络状态机**没有**对接/融合到实际的 `UDP -> TCP` 接收管道与 `TCP -> UDP` 写入循环当中。相关核心重传逻辑仍归于未来的开发阶段（Future Work）。在此声明旨在杜绝对当前实际投产的性能容错率产生夸大的误解。

## 8. Connection Lifecycle

简易的数据隧道传输的完整生命周期管理：
1. **启动与建立:** Client 根据启动指令传递的 `--map` 配置按序随机生成一个唯一 `connection_id` 字典键。
2. **连接声明:** Client 向目标服务器发送携带目标指向和鉴权的 `OpenConnection` Payload 原语。
3. **验证与挂载:** Server 对接收到的报文解开 Payload 并依次做 `secret`、`target` 格式验证以及白名单匹配，一切合法后由 Server 记录内部映射路由（将该请求 UDP IP/端口 与 `connection_id` 与目标 TCP 挂钩）。
4. **透明中转:** 后续交互将仅依据 UDP Header 里的 `connection_id` 标志来进行 `Data` 包双端路由派发映射。
5. **正常关闭:** 当由于网络或者进程导致任意一端的 TCP socket 发生阻塞报错或触发 `EOF` 半关闭后，触发端发送 `Close` UDP 指令包，双端同步清理维护表中挂载的内存。

## 9. 错误处理

本项目通过健壮的二进制解析 `BytesMut` 包进行严酷的数据处理。任何如下匹配异常都将产生静默警告或者错误降级，保障服务长期稳定运行：
- **Invalid Magic**: 前置魔数（通常设定 `0x5F53`）验证未通过，大概率外围杂包。
- **Invalid Version**: 版本字段不对称。
- **Invalid Packet Type**: 读取到了超过 Enum 枚举上限的定义字。
- **Truncated Packet**: Datagram 短于 Header 固定字长（22 字节），或者 Datagram 长于所标称的总承载长度。
- **Payload Length Mismatch**: 实际 UDP 数据体积长出所附带 `payload_len` 加上表头所需长度（即网络包含有 Trailing 游离拖尾数据）。
- **Malformed OpenConnection Payload**: KV 构建失败，或者缺失了必要的验证项属性键值。
- **Secret Mismatch**: Tunnel 接入安全凭证检验出错。
- **Target Not Allowed**: 试图利用 Server 作为代理去直连不被许可的目标主机（不在 Allow 列表）。

## 10. 未来协议增强 (Future Protocol Enhancements)

此版本为加速方案的基础底座实现阶段，未来拟开展以下扩展维度：
- **HMAC Authentication**: 全局替换基础明文的 Secret。
- **Encryption**: 实装对称隧道加密模型体系以保证负载传输层不可见。
- **Replay Protection**: 接入强防御体系防止抓包回放攻击导致 Server 瘫痪或误建。
- **SACK (Selective Acknowledgment)**: 提供对于高丢包弱网跨网段环境更优的选择重传，优化队列占用。
- **Adaptive RTO**: 将超时重发延迟从常量固定值升级为通过网络抖动计算估量。
- **Congestion Control**: 标准的拥塞控制避碰和控制避免网络雪崩。
- **MTU Handling**: 实现 MTU 的自适应拆包控制。