1. *Refactor Session Managers for Tombstoning and Rate Limiting*
   - Update `ClientSessionManager` and `ServerSessionManager` in `src/session.rs` to include shared state for `closed_connections: HashMap<ConnectionId, Instant>` and `unknown_seen: HashMap<ConnectionId, Instant>`.
   - Add a `TOMBSTONE_TTL` (e.g., 60 seconds) and `WARNING_RATE_LIMIT` (e.g., 10 seconds).
   - In `remove` method of both managers, add the `ConnectionId` to `closed_connections` with `Instant::now()`.
   - Add a `cleanup` logic during `check_unknown` to remove old tombstone/rate limit entries to avoid unbounded memory growth.
   - Add an enum `UnknownState` (e.g., `RecentlyClosed`, `RateLimited`, `WarnFirstTime`) and a method `check_unknown(&self, id: &ConnectionId) -> UnknownState` to the managers.

2. *Update Client/Server to Handle Unknown Packets Correctly*
   - Replace the current hardcoded `tracing::warn!("Received ... for unknown ConnectionId: {}", conn_id)` logic in `src/client.rs` and `src/server.rs` with calls to `session_mgr.check_unknown(&conn_id)`.
   - Handle the `UnknownState`:
     - `RecentlyClosed`: `tracing::debug!("Dropping late packet for recently closed ConnectionId: {}", conn_id)`
     - `RateLimited`: `tracing::debug!("Dropping repeated packet for unknown ConnectionId: {}", conn_id)`
     - `WarnFirstTime`: `tracing::warn!("Received packet for unknown ConnectionId: {}", conn_id)`
   - Apply this for `Data`, `Ack`, and `Close` packets on both Client and Server UDP and TCP modes.

3. *Verify/Fix Session Close/Failure Paths*
   - Ensure `session.close_notify.notify_waiters();` is called on all teardown paths:
     - Update the `remove` methods in `ClientSessionManager` and `ServerSessionManager` to automatically call `close_notify.notify_waiters()` on the removed handle if it exists, ensuring the retransmission task and reader tasks exit cleanly when a session is removed.

4. *Add/Update Tests*
   - Update `tests` in `src/session.rs` to verify tombstone, rate limit, and cleanup logic.
   - Run existing integration tests to ensure all tunnel types still pass.

5. *Update Documentation*
   - Update `README.md`, `docs/usage.md`, and `docs/rust-design.md` to mention the new tombstone and rate limit mechanism for handling late packets after SOCKS5 short connection close.

6. *Complete pre commit steps*
   - Complete pre commit steps to make sure proper testing, verifications, reviews and reflections are done.

7. *Submit the change.*
   - Submit the change with a descriptive commit message.
