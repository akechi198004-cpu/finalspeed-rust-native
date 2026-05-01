use fspeed_rs::cli::TransportMode;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn find_free_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

#[tokio::test]
async fn test_tcp_transport_tunnel_loopback() {
    tracing_subscriber::fmt::try_init().ok();

    tokio::time::timeout(Duration::from_secs(10), async {
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
        let server_port = find_free_tcp_port().await;
        let server_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
        let allowlist = vec![echo_addr.parse().unwrap()];
        let server_task = tokio::spawn(async move {
            fspeed_rs::server::run(
                server_addr,
                "test123".to_string(),
                Some(allowlist),
                TransportMode::Tcp,
            )
            .await
            .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // 3. Start fspeed-rs client
        let socks_port = find_free_tcp_port().await;
        let socks_addr: SocketAddr = format!("127.0.0.1:{}", socks_port).parse().unwrap();

        let client_task = tokio::spawn(async move {
            fspeed_rs::client::run(
                server_addr.to_string(),
                "test123".to_string(),
                vec![],
                Some(socks_addr),
                TransportMode::Tcp,
            )
            .await
            .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // 4. Connect to local SOCKS5 listener
        let mut client_stream = TcpStream::connect(socks_addr).await.unwrap();

        // 5. Send SOCKS5 greeting
        client_stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut response = [0u8; 2];
        client_stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x05, 0x00]); // NO AUTH

        // 6. Send SOCKS5 CONNECT request to echo_addr
        client_stream
            .write_all(&[0x05, 0x01, 0x00, 0x01])
            .await
            .unwrap();
        client_stream.write_all(&[127, 0, 0, 1]).await.unwrap(); // IPv4
        client_stream
            .write_all(&echo_port.to_be_bytes())
            .await
            .unwrap(); // Port

        let mut response = [0u8; 10];
        client_stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response[0], 0x05); // Version 5
        assert_eq!(response[1], 0x00); // Success

        // 7. Write data
        let message = b"hello tcp transport";
        client_stream.write_all(message).await.unwrap();

        // 8. Read echo response
        let mut buf = vec![0; message.len()];
        client_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, message);

        // Cleanup
        echo_task.abort();
        server_task.abort();
        client_task.abort();
    })
    .await
    .expect("Test timed out");
}
