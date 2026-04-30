use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::session::ConnectionId;

/// Thread-safe Connection ID generator
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

    pub fn next(&self) -> ConnectionId {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        ConnectionId(id)
    }
}

/// Routing table for logical connections
pub struct ConnectionTable {
    routes: HashMap<ConnectionId, SocketAddr>,
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
    pub fn insert(&mut self, id: ConnectionId, addr: SocketAddr) {
        self.routes.insert(id, addr);
    }

    /// Lookup a route by ConnectionId
    pub fn lookup(&self, id: &ConnectionId) -> Option<SocketAddr> {
        self.routes.get(id).copied()
    }

    /// Remove a route
    pub fn remove(&mut self, id: &ConnectionId) -> Option<SocketAddr> {
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
        let addr1: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:9090".parse().unwrap();

        // Should be empty initially
        assert_eq!(table.lookup(&id), None);

        // Insert
        table.insert(id, addr1);
        assert_eq!(table.lookup(&id), Some(addr1));

        // Update
        table.insert(id, addr2);
        assert_eq!(table.lookup(&id), Some(addr2));

        // Remove
        let removed = table.remove(&id);
        assert_eq!(removed, Some(addr2));
        assert_eq!(table.lookup(&id), None);
    }
}
