//! 配置模块。
//! 包含解析端口映射相关的配置结构。

use std::net::SocketAddr;

/// 端口映射配置。
///
/// 用于在 Client 端将本地端口映射到目标的地址。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMap {
    /// 本地监听地址。
    pub local: SocketAddr,
    /// 目标地址，保留为字符串格式（如 `host:port` 或 `ip:port`），支持域名。
    pub target: String,
}
