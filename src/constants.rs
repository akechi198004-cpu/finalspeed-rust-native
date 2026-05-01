use std::time::Duration;

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
pub const INITIAL_RTO: Duration = Duration::from_millis(1000);
pub const RETRANSMIT_SCAN_INTERVAL: Duration = Duration::from_millis(200);
pub const MAX_RETRANSMISSIONS: u32 = 20;
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(120);
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const SESSION_IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
pub const TOMBSTONE_TTL: Duration = Duration::from_secs(60);
pub const UNKNOWN_WARN_RATE_LIMIT: Duration = Duration::from_secs(10);
pub const DEFAULT_SEND_WINDOW: u16 = 1024;
pub const TCP_MAX_DATA_PAYLOAD: usize = 16 * 1024;
pub const TCP_READ_BUFFER_SIZE: usize = TCP_MAX_DATA_PAYLOAD;
