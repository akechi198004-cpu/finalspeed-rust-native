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
async fn test_reliable_tunnel() {
    tracing_subscriber::fmt::try_init().ok();

    tokio::time::timeout(Duration::from_secs(5), async {
        // We will start the echo server, start fspeed-rs server and client, and run data through it.
        // It's tricky to directly inject network loss here without proxying the UDP socket,
        // but we verify the sliding window and timeout components integrated don't block normal operations.

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

        let server_port = find_free_udp_port().await;
        let server_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
        let allowlist = vec![echo_addr.parse().unwrap()];
        let server_task = tokio::spawn(async move {
            fspeed_rs::server::run(server_addr, "test123".to_string(), Some(allowlist))
                .await
                .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let local_port = find_free_tcp_port().await;
        let map = fspeed_rs::config::PortMap {
            local: format!("127.0.0.1:{}", local_port).parse().unwrap(),
            target: echo_addr.clone(),
        };

        let client_task = tokio::spawn(async move {
            fspeed_rs::client::run(
                server_addr.to_string(),
                "test123".to_string(),
                vec![map],
                None,
            )
            .await
            .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client_stream = TcpStream::connect(format!("127.0.0.1:{}", local_port))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Send multiple messages to test reliable ordering sequence
        let message1 = b"hello part 1, ";
        let message2 = b"hello part 2";
        client_stream.write_all(message1).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await; // give time for first packet
        client_stream.write_all(message2).await.unwrap();

        let mut buf = vec![0; message1.len() + message2.len()];
        client_stream.read_exact(&mut buf).await.unwrap();

        let mut expected = message1.to_vec();
        expected.extend_from_slice(message2);

        assert_eq!(&buf, &expected);

        echo_task.abort();
        server_task.abort();
        client_task.abort();
    })
    .await
    .expect("Test timed out");
}
