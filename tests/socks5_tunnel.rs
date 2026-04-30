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
async fn test_socks5_tunnel_loopback() {
    tracing_subscriber::fmt::try_init().ok();

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
                        break;
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
            fspeed_rs::server::run(server_addr, "test123".to_string(), Some(allowlist))
                .await
                .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // 3. Start fspeed-rs client with SOCKS5 only
        let socks5_port = find_free_tcp_port().await;
        let socks5_addr: SocketAddr = format!("127.0.0.1:{}", socks5_port).parse().unwrap();

        let client_task = tokio::spawn(async move {
            fspeed_rs::client::run(
                server_addr.to_string(),
                "test123".to_string(),
                vec![],
                Some(socks5_addr),
            )
            .await
            .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // 4. Test code mimics a SOCKS5 client
        let mut client_stream = TcpStream::connect(format!("127.0.0.1:{}", socks5_port))
            .await
            .unwrap();

        // Send greeting: VER 5, 1 method, method 0 (NO AUTH)
        client_stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greeting_resp = [0u8; 2];
        client_stream.read_exact(&mut greeting_resp).await.unwrap();
        assert_eq!(greeting_resp, [0x05, 0x00]);

        // Send Connect request to 127.0.0.1:echo_port
        let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        req.extend_from_slice(&echo_port.to_be_bytes());
        client_stream.write_all(&req).await.unwrap();

        // Wait for SOCKS5 response indicating handshake tunnel success
        let mut connect_resp = [0u8; 10];
        client_stream.read_exact(&mut connect_resp).await.unwrap();
        assert_eq!(connect_resp[1], 0x00); // SUCCESS

        // Send payload through tunnel
        let message = b"hello socks5";
        client_stream.write_all(message).await.unwrap();

        // Read echo returned
        let mut buf = vec![0; message.len()];
        client_stream.read_exact(&mut buf).await.unwrap();

        assert_eq!(&buf, message);

        echo_task.abort();
        server_task.abort();
        client_task.abort();
    })
    .await
    .expect("Test timed out");
}
