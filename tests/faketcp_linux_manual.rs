#![cfg(target_os = "linux")]

use std::net::SocketAddr;

use fspeed_rs::transport::PacketIo;
use fspeed_rs::transport::faketcp::linux_impl::FakeTcpEndpoint;

#[tokio::test]
#[ignore = "requires Linux root or CAP_NET_RAW/CAP_NET_ADMIN and a usable IPv4 interface"]
async fn faketcp_endpoint_can_start_with_raw_socket_permissions() {
    let listen: SocketAddr = "0.0.0.0:443".parse().unwrap();
    let endpoint = FakeTcpEndpoint::bind_server(listen).await.unwrap();
    assert!(endpoint.local_addr().unwrap().is_ipv4());
}
