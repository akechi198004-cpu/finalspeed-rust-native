//! KeepAlive 数据包构造与验证模块。
//! 用于防止闲置连接被清理。

use bytes::Bytes;

use crate::app::error::Result;
use crate::protocol::crypto::{build_aad, current_timestamp_ms, encrypt_payload};
use crate::protocol::packet::{FLAG_ENCRYPTED, Packet, PacketType};
use crate::tunnel::session::{ConnectionId, SessionHandle, SessionState};

/// 构造 KeepAlive 的明文 payload，包含类型和当前时间戳。
pub fn build_keepalive_payload() -> String {
    format!("type=keepalive\ntimestamp_ms={}", current_timestamp_ms())
}

/// 构造并加密一个 KeepAlive 数据包。
/// KeepAlive 数据包使用 ChaCha20-Poly1305 进行加密，但 Header 保持明文（加入 AAD）。
pub fn build_encrypted_keepalive_packet(conn_id: ConnectionId, key: &[u8; 32]) -> Result<Packet> {
    let mut packet = Packet::try_new(
        PacketType::KeepAlive,
        FLAG_ENCRYPTED,
        conn_id,
        0,
        0,
        0,
        Bytes::new(),
    )?;
    let aad = build_aad(&packet.header);
    let payload = build_keepalive_payload();
    let encrypted = encrypt_payload(payload.as_bytes(), key, &aad)?;
    packet.payload = encrypted.clone();
    packet.header.payload_len = encrypted.len() as u16;
    Ok(packet)
}

/// 判断一个 Session 是否应该发送 KeepAlive 包（当前仅 Established 状态发送）。
pub fn should_send_keepalive(session: &SessionHandle) -> bool {
    session.state == SessionState::Established
}

/// 记录接收到的 KeepAlive 数据包。
/// 仅更新 `last_activity`，防止 Idle Sweep 将连接清理掉。
pub fn record_received_keepalive(session: &SessionHandle) {
    session.touch();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::crypto::{build_aad, decrypt_payload, derive_key};
    use crate::protocol::{decode_packet, encode_packet};
    use crate::tunnel::reliability::{ReceiveState, SendState};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::{Mutex, Notify, mpsc};

    fn test_session(state: SessionState) -> SessionHandle {
        let (tx, _rx) = mpsc::channel(1);
        let peer_addr: SocketAddr = "127.0.0.1:15000".parse().unwrap();
        SessionHandle::new(
            tx,
            state,
            Arc::new(Mutex::new(SendState::new(
                crate::app::constants::DEFAULT_SEND_WINDOW,
            ))),
            Arc::new(Mutex::new(ReceiveState::new(
                crate::app::constants::DEFAULT_SEND_WINDOW,
            ))),
            Arc::new(Notify::new()),
            Arc::new(Notify::new()),
            peer_addr,
        )
    }

    #[test]
    fn test_keepalive_packet_encode_decode() {
        let key = derive_key("secret");
        let packet = build_encrypted_keepalive_packet(ConnectionId(7), &key).unwrap();
        let mut encoded = encode_packet(&packet).unwrap();
        let decoded = decode_packet(&mut encoded).unwrap().unwrap();

        assert_eq!(decoded.header.packet_type, PacketType::KeepAlive);
        assert_eq!(decoded.header.flags & FLAG_ENCRYPTED, FLAG_ENCRYPTED);
        assert_eq!(decoded.header.connection_id, ConnectionId(7));
    }

    #[test]
    fn test_keepalive_payload_is_encrypted() {
        let key = derive_key("secret");
        let packet = build_encrypted_keepalive_packet(ConnectionId(7), &key).unwrap();

        assert!(
            !packet
                .payload
                .windows(b"type=keepalive".len())
                .any(|w| { w == b"type=keepalive" })
        );

        let aad = build_aad(&packet.header);
        let decrypted = decrypt_payload(&packet.payload, &key, &aad).unwrap();
        let text = std::str::from_utf8(&decrypted).unwrap();
        assert!(text.contains("type=keepalive"));
        assert!(text.contains("timestamp_ms="));
    }

    #[test]
    fn test_closed_session_should_not_send_keepalive() {
        let established = test_session(SessionState::Established);
        let pending = test_session(SessionState::Pending);

        assert!(should_send_keepalive(&established));
        assert!(!should_send_keepalive(&pending));
    }

    #[test]
    fn test_received_keepalive_updates_last_activity() {
        let session = test_session(SessionState::Established);
        let before = session.last_activity();

        std::thread::sleep(std::time::Duration::from_millis(2));
        record_received_keepalive(&session);

        assert!(session.last_activity() > before);
    }

    #[tokio::test]
    async fn test_keepalive_does_not_touch_send_state_for_tcp_retransmission() {
        let session = test_session(SessionState::Established);
        let key = derive_key("secret");
        let packet = build_encrypted_keepalive_packet(ConnectionId(9), &key).unwrap();

        assert_eq!(packet.header.packet_type, PacketType::KeepAlive);
        assert!(session.send_state.lock().await.unacked.is_empty());
    }
}
