use std::fmt;

/// A unique identifier for a logical connection/session over the UDP tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub u32);

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Conn({})", self.0)
    }
}

use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Context for a client-side established logical session.
#[derive(Debug)]
pub struct ClientSession {
    pub connection_id: ConnectionId,
    pub local_tcp: TcpStream,
    pub target_addr: SocketAddr,
}

/// Context for a server-side established logical session.
#[derive(Debug)]
pub struct ServerSession {
    pub connection_id: ConnectionId,
    pub peer_addr: SocketAddr,
    pub target_addr: SocketAddr,
    pub target_tcp: TcpStream,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_id_display() {
        let id = ConnectionId(42);
        assert_eq!(id.to_string(), "Conn(42)");
    }
}
