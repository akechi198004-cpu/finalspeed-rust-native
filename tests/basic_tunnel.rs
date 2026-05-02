use fspeed_rs::app::config::PortMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

async fn find_free_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

async fn find_free_udp_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.local_addr().unwrap().port()
}

#[tokio::test]
async fn test_basic_tunnel_loopback() {
    tracing_subscriber::fmt::try_init().ok();
    // We wrap everything in a timeout to prevent the test from hanging
    tokio::time::timeout(Duration::from_secs(5), async {
        // 1. Start echo server
        let echo_port = find_free_tcp_port().await;
        let echo_addr = format!("127.0.0.1:{}", echo_port);
        let echo_listener = TcpListener::bind(&echo_addr).await.unwrap();

        let echo_task = tokio::spawn(async move {
            if let Ok((mut stream, _)) = echo_listener.accept().await {
                let mut buf = vec![0; 1024];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break; // EOF
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        });

        // 2. Start fspeed-rs server
        let server_port = find_free_udp_port().await;
        let server_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
        let allowlist = vec![echo_addr.parse().unwrap()];
        let server_task = tokio::spawn(async move {
            fspeed_rs::tunnel::server::run(
                server_addr,
                "test123".to_string(),
                Some(allowlist),
                fspeed_rs::app::cli::TransportMode::Udp,
            )
            .await
            .unwrap();
        });

        // Give the server a tiny moment to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 3. Start fspeed-rs client
        let local_port = find_free_tcp_port().await;
        let map = PortMap {
            local: format!("127.0.0.1:{}", local_port).parse().unwrap(),
            target: echo_addr.clone(),
        };

        let client_task = tokio::spawn(async move {
            fspeed_rs::tunnel::client::run(
                server_addr.to_string(),
                "test123".to_string(),
                vec![map],
                None,
                fspeed_rs::app::cli::TransportMode::Udp,
            )
            .await
            .unwrap();
        });

        // Give the client a tiny moment to bind its TCP listener
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 4. Connect to local TCP listener
        let mut client_stream = TcpStream::connect(format!("127.0.0.1:{}", local_port))
            .await
            .unwrap();

        // 5. Wait a tiny bit for the OpenConnection to be accepted by the server
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 6. Write short data
        let message = b"hello fspeed";
        client_stream.write_all(message).await.unwrap();

        // 7. Read echo response
        let mut buf = vec![0; message.len()];
        client_stream.read_exact(&mut buf).await.unwrap();

        // 7. Assert response
        assert_eq!(&buf, message);

        // Cleanup: abort tasks so the test finishes cleanly
        echo_task.abort();
        server_task.abort();
        client_task.abort();
    })
    .await
    .expect("Test timed out");
}
