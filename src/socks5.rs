use anyhow::{Result, anyhow};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const SOCKS5_VERSION: u8 = 0x05;

pub const AUTH_NO_AUTH: u8 = 0x00;
pub const AUTH_NO_ACCEPTABLE_METHODS: u8 = 0xFF;

pub const CMD_CONNECT: u8 = 0x01;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

pub const REP_SUCCESS: u8 = 0x00;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksTarget {
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for SocksTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

pub async fn handle_socks5_greeting(stream: &mut TcpStream) -> Result<()> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;

    let version = header[0];
    let nmethods = header[1];

    if version != SOCKS5_VERSION {
        return Err(anyhow!("Unsupported SOCKS version: {}", version));
    }

    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;

    if methods.contains(&AUTH_NO_AUTH) {
        stream.write_all(&[SOCKS5_VERSION, AUTH_NO_AUTH]).await?;
        Ok(())
    } else {
        stream
            .write_all(&[SOCKS5_VERSION, AUTH_NO_ACCEPTABLE_METHODS])
            .await?;
        Err(anyhow!("No acceptable authentication methods provided"))
    }
}

pub async fn handle_socks5_request(stream: &mut TcpStream) -> Result<SocksTarget> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;

    let version = header[0];
    let cmd = header[1];
    let atyp = header[3];

    if version != SOCKS5_VERSION {
        return Err(anyhow!("Unsupported SOCKS version in request"));
    }

    if cmd != CMD_CONNECT {
        send_socks5_failure(stream, REP_COMMAND_NOT_SUPPORTED).await?;
        return Err(anyhow!("Unsupported SOCKS5 command: {}", cmd));
    }

    let target = match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);
            SocksTarget {
                host: Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string(),
                port,
            }
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let domain_len = len[0] as usize;
            let mut domain_bytes = vec![0u8; domain_len];
            stream.read_exact(&mut domain_bytes).await?;
            let domain = String::from_utf8(domain_bytes)?;

            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);

            SocksTarget { host: domain, port }
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);

            let ipv6 = Ipv6Addr::from(addr);
            SocksTarget {
                host: format!("[{}]", ipv6),
                port,
            }
        }
        _ => {
            send_socks5_failure(stream, REP_ADDRESS_TYPE_NOT_SUPPORTED).await?;
            return Err(anyhow!("Unsupported SOCKS5 address type: {}", atyp));
        }
    };

    Ok(target)
}

pub async fn send_socks5_success<W: AsyncWriteExt + Unpin>(stream: &mut W) -> Result<()> {
    let response = [
        SOCKS5_VERSION,
        REP_SUCCESS,
        0x00,
        ATYP_IPV4,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ];
    stream.write_all(&response).await?;
    Ok(())
}

pub async fn send_socks5_failure<W: AsyncWriteExt + Unpin>(stream: &mut W, rep: u8) -> Result<()> {
    let response = [
        SOCKS5_VERSION,
        rep,
        0x00,
        ATYP_IPV4,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ];
    stream.write_all(&response).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    async fn spawn_test_server() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            if handle_socks5_greeting(&mut stream).await.is_ok() {
                let _ = handle_socks5_request(&mut stream).await;
            }
        });
        (port, handle)
    }

    fn is_connection_closed_error(err: &std::io::Error) -> bool {
        matches!(
            err.kind(),
            std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe
        )
    }

    #[tokio::test]
    async fn test_socks5_greeting_success() {
        tokio::time::timeout(crate::constants::HANDSHAKE_TIMEOUT, async {
            let (port, _) = spawn_test_server().await;
            let mut client = TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();

            // Send greeting: VER 5, 1 Method, Method 0 (No Auth)
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

            let mut response = [0u8; 2];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [0x05, 0x00]);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_socks5_greeting_unsupported_version() {
        tokio::time::timeout(crate::constants::HANDSHAKE_TIMEOUT, async {
            let (port, _) = spawn_test_server().await;
            let mut client = TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();

            // Send greeting: VER 4, 1 method, 0x00
            client.write_all(&[0x04, 0x01, 0x00]).await.unwrap();

            // Server should drop connection or error, no valid response
            let mut response = [0u8; 2];
            if let Err(e) = client.read_exact(&mut response).await {
                assert!(
                    is_connection_closed_error(&e) || e.kind() == std::io::ErrorKind::InvalidData
                );
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_socks5_greeting_unsupported_method() {
        tokio::time::timeout(crate::constants::HANDSHAKE_TIMEOUT, async {
            let (port, _) = spawn_test_server().await;
            let mut client = TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();

            // Send greeting: VER 5, 1 Method, Method 2 (Username/Password, not supported)
            client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();

            let mut response = [0u8; 2];
            match client.read_exact(&mut response).await {
                Ok(_) => {
                    assert_eq!(response, [0x05, 0xFF]);
                }
                Err(e) => {
                    assert!(is_connection_closed_error(&e));
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_socks5_request_ipv4() {
        tokio::time::timeout(crate::constants::HANDSHAKE_TIMEOUT, async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let handle = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let target = handle_socks5_request(&mut stream).await.unwrap();
                assert_eq!(target.host, "1.2.3.4");
                assert_eq!(target.port, 80);
                send_socks5_success(&mut stream).await.unwrap();
            });

            let mut client = TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();

            // Send Request: VER 5, CMD 1 (CONNECT), RSV 0, ATYP 1 (IPv4), IP 1.2.3.4, Port 80
            let req = [0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50];
            client.write_all(&req).await.unwrap();

            let mut response = [0u8; 10];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(response[1], 0x00); // REP_SUCCESS

            handle.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_socks5_request_domain() {
        tokio::time::timeout(crate::constants::HANDSHAKE_TIMEOUT, async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let handle = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let target = handle_socks5_request(&mut stream).await.unwrap();
                assert_eq!(target.host, "example.com");
                assert_eq!(target.port, 443);
            });

            let mut client = TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();

            let domain = b"example.com";
            let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
            req.extend_from_slice(domain);
            req.extend_from_slice(&[0x01, 0xBB]); // Port 443
            client.write_all(&req).await.unwrap();

            handle.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_socks5_request_unsupported_cmd() {
        tokio::time::timeout(crate::constants::HANDSHAKE_TIMEOUT, async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let handle = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                assert!(handle_socks5_request(&mut stream).await.is_err());
                // Wait a tiny bit so the failure packet is sent before dropping the connection
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            });

            let mut client = TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();

            // Send Request: VER 5, CMD 2 (BIND), RSV 0, ATYP 1 (IPv4), IP 1.2.3.4, Port 80
            let req = [0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50];
            client.write_all(&req).await.unwrap();

            let mut response = [0u8; 10];
            match client.read_exact(&mut response).await {
                Ok(_) => {
                    assert_eq!(response[1], REP_COMMAND_NOT_SUPPORTED);
                }
                Err(e) => {
                    assert!(is_connection_closed_error(&e));
                }
            }

            handle.await.unwrap();
        })
        .await
        .unwrap();
    }
}
