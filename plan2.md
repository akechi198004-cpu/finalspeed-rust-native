1. **Create Constants Module**
   - Create `src/constants.rs` to hold configuration constants (`HANDSHAKE_TIMEOUT`, `INITIAL_RTO`, `RETRANSMIT_SCAN_INTERVAL`, `MAX_RETRANSMISSIONS`, `SESSION_IDLE_TIMEOUT`, `SESSION_IDLE_SWEEP_INTERVAL`, `TOMBSTONE_TTL`, `UNKNOWN_WARN_RATE_LIMIT`, `DEFAULT_SEND_WINDOW`).
   - Add `pub mod constants;` to `src/lib.rs`.
   - Update `src/session.rs` to use `TOMBSTONE_TTL` and `UNKNOWN_WARN_RATE_LIMIT` from `constants.rs`.
   - Update `src/reliability.rs` to use `INITIAL_RTO`, `MAX_RETRANSMISSIONS`, and `DEFAULT_SEND_WINDOW` (where appropriate, perhaps replace `SendState::new(1024)` default).

2. **Implement Session Idle Timeout**
   - Update `SessionHandle` in `src/session.rs` to include `last_activity: Arc<RwLock<Instant>>`.
   - Add a `sweep_idle_sessions(&self, timeout: Duration) -> Vec<ConnectionId>` method to both session managers. This method will check `last_activity`, remove idle sessions, call `notify_waiters()`, and add to `closed_connections` tombstone.
   - Spawn a background task in `client.rs` and `server.rs` that periodically calls `sweep_idle_sessions` every `SESSION_IDLE_SWEEP_INTERVAL`.
   - Update `client.rs` and `server.rs` to update `last_activity` whenever Data, Ack, OpenConnection, or Close is sent or received.

3. **Disable Retransmission Task for TCP Transport**
   - In `client.rs` and `server.rs`, find the `tokio::spawn` blocks for the retransmission loops (`// Spawn retransmission task`).
   - For `TransportMode::Tcp` (`run_tcp`), remove the code that spawns the retransmission task entirely. (Since TCP guarantees delivery).
   - For `TransportMode::Udp` (`run_udp`), update the sleep interval to `RETRANSMIT_SCAN_INTERVAL`.
   - Update handshake timeouts in `client.rs` to `HANDSHAKE_TIMEOUT`.

4. **Update Logs and Error Handling**
   - Ensure "max retransmissions exceeded" is a `warn!`.
   - Ensure handshake timeout and target connect failures are `warn!`.

5. **Update Tests**
   - Add/update a test in `src/session.rs` to verify `sweep_idle_sessions` works correctly.
   - Adjust reliability tests to use the new `MAX_RETRANSMISSIONS` constant.

6. **Documentation and Pre-commit Checks**
   - Update `README.md`, `docs/usage.md`, `docs/rust-design.md`, `docs/protocol.md` (if it exists) with the new parameter details and TCP transport behavior.
   - Run `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, `cargo build --release`.
   - Submit.
