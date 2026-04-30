use std::net::SocketAddr;

pub async fn run(
    listen: SocketAddr,
    _secret: String,
    allow: Option<Vec<SocketAddr>>,
) -> anyhow::Result<()> {
    tracing::info!(
        "(Stub) Initializing server listening on {} with allow list: {:?}",
        listen,
        allow
    );
    // UDP listener, connection tracking, etc. will go here in future phases.
    Ok(())
}
