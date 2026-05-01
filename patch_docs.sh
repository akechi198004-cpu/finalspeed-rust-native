#!/bin/bash

# Update README.md
sed -i 's/- **Phase 6**：完善更鲁棒和干净的连接关闭（Connection Teardown）流程和 Half-Close 处理。/- **Phase 6**：完善更鲁棒和干净的连接关闭（Connection Teardown）流程和 Half-Close 处理（已实现 Session Tombstone 与 Close 自动清理）。/g' README.md

# Update docs/usage.md
cat << 'APPENDEOF' >> docs/usage.md

**Q: Server/Client 日志为什么有时候会有 `Dropping late packet for recently closed ConnectionId` 或 `Dropping repeated packet for unknown ConnectionId` 的 debug 提示？**
- 浏览器或其他应用使用 SOCKS5 时通常会创建大量的短连接。当这些连接在程序内部被正常释放关闭后，网络上由于延迟或重传，仍有可能收到属于这些已关闭连接的迟到数据包（如 Data、Ack 或 Close）。程序内置了 Tombstone (墓碑) 和 Rate-Limit 机制，会静默丢弃这些已失效连接的遗留报文，从而避免大量的无效 Warning 警告刷屏。
APPENDEOF

# Update docs/rust-design.md
sed -i 's/## 11. Stream Close Behavior/## 11. Stream Close Behavior\n\n- **Session Tombstoning (墓碑机制):** 尤其是通过浏览器 SOCKS5 代理产生的海量短连接，即使连接已经关闭或失败移除，网络中仍可能有迟到或重传的报文到达。为了避免打印大量的 "unknown ConnectionId" 警告日志，SessionManager 引入了 `closed_connections` Tombstone 机制和未知连接的警告限流机制（Rate Limit）。移除的 session 会在一段时间内进入墓碑状态，遇到属于它的迟到包仅作 debug 级忽略处理。/g' docs/rust-design.md
