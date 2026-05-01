# We already updated `remove` methods in ClientSessionManager and ServerSessionManager
# to call `h.close_notify.notify_waiters();` inside step 1.
# Let's verify that's the case.
cat src/session.rs | grep -A 5 "pub async fn remove"
