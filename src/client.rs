use crate::config::PortMap;

pub async fn run(server: String, _secret: String, map: Vec<PortMap>) -> anyhow::Result<()> {
    tracing::info!(
        "(Stub) Initializing client connecting to {} with {} mappings",
        server,
        map.len()
    );
    // UDP transport, TCP listener, etc. will go here in future phases.
    Ok(())
}
