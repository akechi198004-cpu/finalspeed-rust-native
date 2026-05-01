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
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc, oneshot};

const TOMBSTONE_TTL: Duration = Duration::from_secs(60);
const WARNING_RATE_LIMIT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownState {
    RecentlyClosed,
    RateLimited,
    WarnFirstTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Pending,
    Established,
}

use crate::reliability::{ReceiveState, SendState};
use tokio::sync::{Mutex, Notify};

/// Handle to a logical session, used to send data to the TCP writer task.
#[derive(Debug, Clone)]
pub struct SessionHandle {
    pub sender: mpsc::Sender<Bytes>,
    pub state: SessionState,
    pub send_state: Arc<Mutex<SendState>>,
    pub receive_state: Arc<Mutex<ReceiveState>>,
    pub window_notify: Arc<Notify>,
    pub close_notify: Arc<Notify>,
    pub peer_addr: SocketAddr,
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
    closed_connections: Arc<RwLock<HashMap<ConnectionId, Instant>>>,
    unknown_seen: Arc<RwLock<HashMap<ConnectionId, Instant>>>,
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
            closed_connections: Arc::new(RwLock::new(HashMap::new())),
            unknown_seen: Arc::new(RwLock::new(HashMap::new())),
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
        if let Some(ref h) = handle {
            tracing::debug!("ClientSessionManager removed connection: {}", id);
            h.close_notify.notify_waiters();

            let mut closed_map = self.closed_connections.write().await;
            closed_map.insert(*id, Instant::now());
        }
        handle
    }

    pub async fn check_unknown(&self, id: &ConnectionId) -> UnknownState {
        let now = Instant::now();

        {
            let mut closed_map = self.closed_connections.write().await;
            closed_map.retain(|_, v| now.duration_since(*v) < TOMBSTONE_TTL);
            if closed_map.contains_key(id) {
                return UnknownState::RecentlyClosed;
            }
        }

        let mut unknown_map = self.unknown_seen.write().await;
        unknown_map.retain(|_, v| now.duration_since(*v) < WARNING_RATE_LIMIT);

        if unknown_map.contains_key(id) {
            UnknownState::RateLimited
        } else {
            unknown_map.insert(*id, now);
            UnknownState::WarnFirstTime
        }
    }
}

/// Manages server-side sessions.
#[derive(Debug, Clone)]
pub struct ServerSessionManager {
    sessions: Arc<RwLock<HashMap<ConnectionId, SessionHandle>>>,
    closed_connections: Arc<RwLock<HashMap<ConnectionId, Instant>>>,
    unknown_seen: Arc<RwLock<HashMap<ConnectionId, Instant>>>,
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
            closed_connections: Arc::new(RwLock::new(HashMap::new())),
            unknown_seen: Arc::new(RwLock::new(HashMap::new())),
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
        if let Some(ref h) = handle {
            tracing::debug!("ServerSessionManager removed connection: {}", id);
            h.close_notify.notify_waiters();

            let mut closed_map = self.closed_connections.write().await;
            closed_map.insert(*id, Instant::now());
        }
        handle
    }

    pub async fn check_unknown(&self, id: &ConnectionId) -> UnknownState {
        let now = Instant::now();

        {
            let mut closed_map = self.closed_connections.write().await;
            closed_map.retain(|_, v| now.duration_since(*v) < TOMBSTONE_TTL);
            if closed_map.contains_key(id) {
                return UnknownState::RecentlyClosed;
            }
        }

        let mut unknown_map = self.unknown_seen.write().await;
        unknown_map.retain(|_, v| now.duration_since(*v) < WARNING_RATE_LIMIT);

        if unknown_map.contains_key(id) {
            UnknownState::RateLimited
        } else {
            unknown_map.insert(*id, now);
            UnknownState::WarnFirstTime
        }
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
    async fn test_check_unknown_tombstone_and_rate_limit() {
        let manager = ClientSessionManager::new();
        let id = ConnectionId(99);

        // Initially unknown
        let state1 = manager.check_unknown(&id).await;
        assert_eq!(state1, UnknownState::WarnFirstTime);

        // Immediately again -> RateLimited
        let state2 = manager.check_unknown(&id).await;
        assert_eq!(state2, UnknownState::RateLimited);

        // Add to manager and remove it -> RecentlyClosed
        let (tx, _) = mpsc::channel(1);
        let (hs_tx, _) = oneshot::channel();
        let handle = SessionHandle {
            sender: tx,
            state: SessionState::Established,
            send_state: Arc::new(Mutex::new(SendState::new(1024))),
            receive_state: Arc::new(Mutex::new(ReceiveState::new(1024))),
            window_notify: Arc::new(Notify::new()),
            close_notify: Arc::new(Notify::new()),
            peer_addr: "127.0.0.1:8080".parse().unwrap(),
        };

        manager.insert_pending(id, handle, hs_tx).await;
        manager.remove(&id).await;

        let state3 = manager.check_unknown(&id).await;
        assert_eq!(state3, UnknownState::RecentlyClosed);
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
            send_state: Arc::new(Mutex::new(SendState::new(1024))),
            receive_state: Arc::new(Mutex::new(ReceiveState::new(1024))),
            window_notify: Arc::new(Notify::new()),
            close_notify: Arc::new(Notify::new()),
            peer_addr: "127.0.0.1:8080".parse().unwrap(),
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
            send_state: Arc::new(Mutex::new(SendState::new(1024))),
            receive_state: Arc::new(Mutex::new(ReceiveState::new(1024))),
            window_notify: Arc::new(Notify::new()),
            close_notify: Arc::new(Notify::new()),
            peer_addr: "127.0.0.1:8080".parse().unwrap(),
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
