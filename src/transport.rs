//! 传输层通用状态定义。
//! 主要包含 ConnectionIdGenerator 用于自增连接 ID。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::session::ConnectionId;

/// 线程安全的 Connection ID 生成器。
/// 在客户端用于为每一条建立的 TCP 连接分配唯一的逻辑会话 ID。
pub struct ConnectionIdGenerator {
    next_id: AtomicU32,
}

impl Default for ConnectionIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionIdGenerator {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU32::new(1), // Start at 1
        }
    }

    /// 自增并获取下一个逻辑 Connection ID。
    pub fn next(&self) -> ConnectionId {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        ConnectionId(id)
    }
}

/// 用于记录每个 Connection ID 映射的对端和目标地址。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRoute {
    pub peer_addr: SocketAddr,
    pub target_addr: String,
}

/// 连接的路由表，主要记录已建立逻辑隧道的路由信息。
pub struct ConnectionTable {
    routes: HashMap<ConnectionId, ConnectionRoute>,
}

impl Default for ConnectionTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionTable {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    /// Insert or update a route
    pub fn insert(&mut self, id: ConnectionId, route: ConnectionRoute) {
        self.routes.insert(id, route);
    }

    /// Lookup a route by ConnectionId
    pub fn lookup(&self, id: &ConnectionId) -> Option<ConnectionRoute> {
        self.routes.get(id).cloned()
    }

    /// Remove a route
    pub fn remove(&mut self, id: &ConnectionId) -> Option<ConnectionRoute> {
        self.routes.remove(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_id_generation() {
        let generator = ConnectionIdGenerator::new();
        assert_eq!(generator.next(), ConnectionId(1));
        assert_eq!(generator.next(), ConnectionId(2));
        assert_eq!(generator.next(), ConnectionId(3));
    }

    #[test]
    fn test_connection_table() {
        let mut table = ConnectionTable::new();
        let id = ConnectionId(42);
        let peer1: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let route1 = ConnectionRoute {
            peer_addr: peer1,
            target_addr: "127.0.0.1:22".to_string(),
        };

        let peer2: SocketAddr = "127.0.0.1:9090".parse().unwrap();
        let route2 = ConnectionRoute {
            peer_addr: peer2,
            target_addr: "example.com:80".to_string(),
        };

        // Should be empty initially
        assert_eq!(table.lookup(&id), None);

        // Insert
        table.insert(id, route1.clone());
        assert_eq!(table.lookup(&id), Some(route1.clone()));

        // Update
        table.insert(id, route2.clone());
        assert_eq!(table.lookup(&id), Some(route2.clone()));

        // Remove
        let removed = table.remove(&id);
        assert_eq!(removed, Some(route2.clone()));
        assert_eq!(table.lookup(&id), None);
    }
}
