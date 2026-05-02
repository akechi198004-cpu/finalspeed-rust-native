//! 会话 (Session) 管理模块。
//! 包含 Session 的生命周期、Idle Sweep、Tombstone 及速率限制过滤等机制。

use std::fmt;

/// 逻辑隧道的会话 ID。
/// 客户端发起的每一个 TCP 连接都会对应一个自增的 ConnectionId。
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
use std::time::Instant;
use tokio::sync::{RwLock, mpsc, oneshot};

/// 未知连接包的处理状态。用于减少错误重传造成的日志刷屏。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownState {
    /// 命中了 Tombstone，连接近期已关闭。
    RecentlyClosed,
    /// 未知且处于限速警告期内。
    RateLimited,
    /// 第一次遇到未知 ConnectionId，允许记录 Warn 日志。
    WarnFirstTime,
}

/// 逻辑 Session 的当前状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// 正在握手等待目标地址等。
    Pending,
    /// 已建立可以正常收发。
    Established,
}

use crate::reliability::{ReceiveState, SendState};
use tokio::sync::{Mutex, Notify};

/// SessionHandle 包装了处理逻辑连接相关的通道和状态。
/// 被 UDP Receive 循环使用，将会话的数据分发到对应的 TCP Writer task，
/// 同时也持有了滑动窗口的状态以便验证包。
#[derive(Debug, Clone)]
pub struct SessionHandle {
    pub sender: mpsc::Sender<Bytes>,
    pub state: SessionState,
    pub send_state: Arc<Mutex<SendState>>,
    pub receive_state: Arc<Mutex<ReceiveState>>,
    pub window_notify: Arc<Notify>,
    pub close_notify: Arc<Notify>,
    pub peer_addr: SocketAddr,
    last_activity: Arc<std::sync::Mutex<Instant>>,
}

impl SessionHandle {
    pub fn new(
        sender: mpsc::Sender<Bytes>,
        state: SessionState,
        send_state: Arc<Mutex<SendState>>,
        receive_state: Arc<Mutex<ReceiveState>>,
        window_notify: Arc<Notify>,
        close_notify: Arc<Notify>,
        peer_addr: SocketAddr,
    ) -> Self {
        Self {
            sender,
            state,
            send_state,
            receive_state,
            window_notify,
            close_notify,
            peer_addr,
            last_activity: Arc::new(std::sync::Mutex::new(Instant::now())),
        }
    }

    pub fn touch(&self) {
        if let Ok(mut lock) = self.last_activity.lock() {
            *lock = Instant::now();
        }
    }

    pub fn last_activity(&self) -> Instant {
        *self.last_activity.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn is_idle(&self, now: Instant, timeout: std::time::Duration) -> bool {
        now.duration_since(self.last_activity()) > timeout
    }
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
    pub async fn sweep_idle_sessions(&self, now: Instant, idle_timeout: std::time::Duration) {
        let mut to_remove = Vec::new();
        {
            let map = self.sessions.read().await;
            for (id, handle) in map.iter() {
                if handle.is_idle(now, idle_timeout) {
                    to_remove.push(*id);
                }
            }
        }

        for id in to_remove {
            if let Some(_handle) = self.remove(&id).await {
                tracing::debug!(
                    "ClientSessionManager sweep: session idle timeout exceeded, removing Conn({})",
                    id.0
                );
            }
        }
    }
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
            closed_map.retain(|_, v| now.duration_since(*v) < crate::constants::TOMBSTONE_TTL);
            if closed_map.contains_key(id) {
                return UnknownState::RecentlyClosed;
            }
        }

        let mut unknown_map = self.unknown_seen.write().await;
        unknown_map
            .retain(|_, v| now.duration_since(*v) < crate::constants::UNKNOWN_WARN_RATE_LIMIT);

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
    pub async fn sweep_idle_sessions(&self, now: Instant, idle_timeout: std::time::Duration) {
        let mut to_remove = Vec::new();
        {
            let map = self.sessions.read().await;
            for (id, handle) in map.iter() {
                if handle.is_idle(now, idle_timeout) {
                    to_remove.push(*id);
                }
            }
        }

        for id in to_remove {
            if let Some(_handle) = self.remove(&id).await {
                tracing::debug!(
                    "ServerSessionManager sweep: session idle timeout exceeded, removing Conn({})",
                    id.0
                );
            }
        }
    }
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
            closed_map.retain(|_, v| now.duration_since(*v) < crate::constants::TOMBSTONE_TTL);
            if closed_map.contains_key(id) {
                return UnknownState::RecentlyClosed;
            }
        }

        let mut unknown_map = self.unknown_seen.write().await;
        unknown_map
            .retain(|_, v| now.duration_since(*v) < crate::constants::UNKNOWN_WARN_RATE_LIMIT);

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
    use crate::constants::{DEFAULT_SEND_WINDOW, SESSION_IDLE_TIMEOUT};
    use crate::keepalive::record_received_keepalive;

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
        let handle = SessionHandle::new(
            tx,
            SessionState::Established,
            Arc::new(Mutex::new(SendState::new(1024))),
            Arc::new(Mutex::new(ReceiveState::new(1024))),
            Arc::new(Notify::new()),
            Arc::new(Notify::new()),
            "127.0.0.1:8080".parse().unwrap(),
        );

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
        let handle = SessionHandle::new(
            tx,
            SessionState::Pending,
            Arc::new(Mutex::new(SendState::new(1024))),
            Arc::new(Mutex::new(ReceiveState::new(1024))),
            Arc::new(Notify::new()),
            Arc::new(Notify::new()),
            "127.0.0.1:8080".parse().unwrap(),
        );

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
        let handle = SessionHandle::new(
            tx,
            SessionState::Established,
            Arc::new(Mutex::new(SendState::new(1024))),
            Arc::new(Mutex::new(ReceiveState::new(1024))),
            Arc::new(Notify::new()),
            Arc::new(Notify::new()),
            "127.0.0.1:8080".parse().unwrap(),
        );

        manager.insert(id, handle.clone()).await;

        let lookup = manager.lookup(&id).await;
        assert!(lookup.is_some());

        let remove = manager.remove(&id).await;
        assert!(remove.is_some());

        let lookup_after = manager.lookup(&id).await;
        assert!(lookup_after.is_none());
    }

    #[tokio::test]
    async fn test_keepalive_touch_prevents_idle_sweep() {
        let manager = ServerSessionManager::new();
        let (tx, _) = mpsc::channel(1);
        let id = ConnectionId(7);
        let handle = SessionHandle::new(
            tx,
            SessionState::Established,
            Arc::new(Mutex::new(SendState::new(DEFAULT_SEND_WINDOW))),
            Arc::new(Mutex::new(ReceiveState::new(DEFAULT_SEND_WINDOW))),
            Arc::new(Notify::new()),
            Arc::new(Notify::new()),
            "127.0.0.1:8080".parse().unwrap(),
        );

        let before = handle.last_activity();
        std::thread::sleep(std::time::Duration::from_millis(2));
        record_received_keepalive(&handle);
        let after = handle.last_activity();
        assert!(after > before);

        manager.insert(id, handle).await;
        manager
            .sweep_idle_sessions(after + SESSION_IDLE_TIMEOUT / 2, SESSION_IDLE_TIMEOUT)
            .await;

        assert!(manager.lookup(&id).await.is_some());
    }
}
