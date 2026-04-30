use std::fmt;

/// A unique identifier for a logical connection/session over the UDP tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub u32);

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Conn({})", self.0)
    }
}

use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc, oneshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Pending,
    Established,
}

/// Handle to a logical session, used to send data to the TCP writer task.
#[derive(Debug, Clone)]
pub struct SessionHandle {
    pub sender: mpsc::Sender<Bytes>,
    pub state: SessionState,
}

/// Used during connection establishment to await Ack/Error Handshakes
pub struct HandshakeNotifier {
    pub tx: oneshot::Sender<bool>,
}

/// Manages client-side sessions.
#[derive(Debug, Clone)]
pub struct ClientSessionManager {
    sessions: Arc<RwLock<HashMap<ConnectionId, SessionHandle>>>,
    handshakes: Arc<RwLock<HashMap<ConnectionId, oneshot::Sender<bool>>>>,
}

impl Default for ClientSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            handshakes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn insert_pending(
        &self,
        id: ConnectionId,
        handle: SessionHandle,
        handshake_tx: oneshot::Sender<bool>,
    ) {
        {
            let mut map = self.sessions.write().await;
            map.insert(id, handle);
        }
        {
            let mut hs_map = self.handshakes.write().await;
            hs_map.insert(id, handshake_tx);
        }
        tracing::debug!("ClientSessionManager inserted pending connection: {}", id);
    }

    pub async fn establish(&self, id: &ConnectionId) {
        let mut map = self.sessions.write().await;
        if let Some(handle) = map.get_mut(id) {
            handle.state = SessionState::Established;
        }
    }

    pub async fn complete_handshake(&self, id: &ConnectionId, success: bool) {
        let mut hs_map = self.handshakes.write().await;
        if let Some(tx) = hs_map.remove(id) {
            let _ = tx.send(success);
        }
    }

    pub async fn lookup(&self, id: &ConnectionId) -> Option<SessionHandle> {
        let map = self.sessions.read().await;
        map.get(id).cloned()
    }

    pub async fn remove(&self, id: &ConnectionId) -> Option<SessionHandle> {
        {
            let mut hs_map = self.handshakes.write().await;
            hs_map.remove(id);
        }
        let mut map = self.sessions.write().await;
        let handle = map.remove(id);
        if handle.is_some() {
            tracing::debug!("ClientSessionManager removed connection: {}", id);
        }
        handle
    }
}

/// Manages server-side sessions.
#[derive(Debug, Clone)]
pub struct ServerSessionManager {
    sessions: Arc<RwLock<HashMap<ConnectionId, SessionHandle>>>,
}

impl Default for ServerSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn insert(&self, id: ConnectionId, handle: SessionHandle) {
        let mut map = self.sessions.write().await;
        map.insert(id, handle);
        tracing::debug!("ServerSessionManager inserted connection: {}", id);
    }

    pub async fn lookup(&self, id: &ConnectionId) -> Option<SessionHandle> {
        let map = self.sessions.read().await;
        map.get(id).cloned()
    }

    pub async fn remove(&self, id: &ConnectionId) -> Option<SessionHandle> {
        let mut map = self.sessions.write().await;
        let handle = map.remove(id);
        if handle.is_some() {
            tracing::debug!("ServerSessionManager removed connection: {}", id);
        }
        handle
    }
}

/// Context for a client-side established logical session (used during initialization).
#[derive(Debug)]
pub struct ClientSession {
    pub connection_id: ConnectionId,
    pub target_addr: SocketAddr,
}

/// Context for a server-side established logical session (used during initialization).
#[derive(Debug)]
pub struct ServerSession {
    pub connection_id: ConnectionId,
    pub peer_addr: SocketAddr,
    pub target_addr: SocketAddr,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_id_display() {
        let id = ConnectionId(42);
        assert_eq!(id.to_string(), "Conn(42)");
    }

    #[tokio::test]
    async fn test_client_session_manager() {
        let manager = ClientSessionManager::new();
        let (tx, _) = mpsc::channel(1);
        let (hs_tx, hs_rx) = oneshot::channel();
        let id = ConnectionId(1);
        let handle = SessionHandle {
            sender: tx,
            state: SessionState::Pending,
        };

        manager.insert_pending(id, handle.clone(), hs_tx).await;

        let lookup = manager.lookup(&id).await;
        assert!(lookup.is_some());
        assert_eq!(lookup.unwrap().state, SessionState::Pending);

        manager.establish(&id).await;
        let lookup2 = manager.lookup(&id).await;
        assert_eq!(lookup2.unwrap().state, SessionState::Established);

        manager.complete_handshake(&id, true).await;
        let success = hs_rx.await.unwrap();
        assert!(success);

        let remove = manager.remove(&id).await;
        assert!(remove.is_some());

        let lookup_after = manager.lookup(&id).await;
        assert!(lookup_after.is_none());
    }

    #[tokio::test]
    async fn test_server_session_manager() {
        let manager = ServerSessionManager::new();
        let (tx, _) = mpsc::channel(1);
        let id = ConnectionId(2);
        let handle = SessionHandle {
            sender: tx,
            state: SessionState::Established,
        };

        manager.insert(id, handle.clone()).await;

        let lookup = manager.lookup(&id).await;
        assert!(lookup.is_some());

        let remove = manager.remove(&id).await;
        assert!(remove.is_some());

        let lookup_after = manager.lookup(&id).await;
        assert!(lookup_after.is_none());
    }
}
