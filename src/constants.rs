//! 常量定义模块。
//! 集中管理协议超时、间隔、重传参数以及缓冲区大小等配置常量。

use std::time::Duration;

/// 握手超时时间。
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// 初始重传超时（RTO），目前协议采用固定 RTO，不支持自适应 RTO。
pub const INITIAL_RTO: Duration = Duration::from_millis(1000);
/// UDP 重传扫描的时间间隔。
pub const RETRANSMIT_SCAN_INTERVAL: Duration = Duration::from_millis(200);
/// 最大重传次数。
pub const MAX_RETRANSMISSIONS: u32 = 20;
/// KeepAlive 默认发送间隔。
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// KeepAlive 超时时间，如果在该时间内没有收到 KeepAlive 会认为远端无响应（具体处理视逻辑而定）。
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(120);
/// Session 空闲超时时间，超过该时间没有活动更新 `last_activity` 的会话将被清理。
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// 清理空闲 Session 的后台任务执行间隔。
pub const SESSION_IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// Session 关闭后 Tombstone 的存活时间（TTL），用于临时过滤近期已关闭会话的迟到数据包。
pub const TOMBSTONE_TTL: Duration = Duration::from_secs(60);
/// 未知 Connection ID 警告日志的速率限制时间窗口。
pub const UNKNOWN_WARN_RATE_LIMIT: Duration = Duration::from_secs(10);
/// 默认的发送与接收窗口大小（单位：packets）。当前使用固定大小的滑动窗口。
pub const DEFAULT_SEND_WINDOW: u16 = 1024;
/// TCP 数据负载的最大限制。
pub const TCP_MAX_DATA_PAYLOAD: usize = 16 * 1024;
/// TCP 读取缓冲区大小。
pub const TCP_READ_BUFFER_SIZE: usize = TCP_MAX_DATA_PAYLOAD;
