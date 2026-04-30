use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMap {
    pub local: SocketAddr,
    pub target: SocketAddr,
}
