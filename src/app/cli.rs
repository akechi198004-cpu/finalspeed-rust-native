//! CLI 参数解析模块。
//! 提供 Server 和 Client 的命令结构定义。

use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::str::FromStr;

use crate::app::config::PortMap;

#[derive(Parser, Debug)]
#[command(
    name = "fspeed-rs",
    version,
    about = "A Rust-native reliable UDP tunnel"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// 传输层模式选项。
#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq, Default)]
pub enum TransportMode {
    /// 默认使用 UDP 传输。
    ///
    /// 开启 RUDP 级的重传任务，并在 UDP 数据报文基础上封装。
    #[default]
    Udp,
    /// 备用 TCP 传输。
    ///
    /// 使用 4 字节长度前缀 Framing，依赖 OS TCP 的可靠性，
    /// 不再启动自身的重传任务。
    Tcp,
}

/// 支持的命令行子命令，分别为 Server 和 Client。
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// 启动 Server 端接受客户端隧道的连接。
    Server {
        /// Address to listen on (e.g., 0.0.0.0:150)
        #[arg(long, default_value = "0.0.0.0:150")]
        listen: SocketAddr,

        /// 预共享的密码，通过 HKDF-SHA256 派生会话密钥。
        #[arg(long)]
        secret: String,

        /// 可选的目标地址白名单列表（逗号分隔）。开启时会拒绝不在此名单中的连接目标。
        #[arg(long, value_delimiter = ',')]
        allow: Option<Vec<SocketAddr>>,

        /// 指定底层使用的传输协议。
        #[arg(long, value_enum, default_value_t = TransportMode::Udp)]
        transport: TransportMode,
    },

    /// 启动 Client 端代理本地 TCP 连接至服务端。
    Client {
        /// Server address to connect to (e.g., example.com:150)
        #[arg(long)]
        server: String,

        /// 预共享的密码，必须与服务端保持一致。
        #[arg(long)]
        secret: String,

        /// 端口映射配置。格式为 `local_addr:local_port=target_addr:target_port`。
        #[arg(long, value_parser = parse_port_map, required = false)]
        map: Vec<PortMap>,

        /// 开启基于 SOCKS5 (no-auth) 的本地监听代理（如 `127.0.0.1:1080`）。
        #[arg(long, required = false)]
        socks5: Option<SocketAddr>,

        /// 指定底层使用的传输协议。必须与服务端配置相同。
        #[arg(long, value_enum, default_value_t = TransportMode::Udp)]
        transport: TransportMode,
    },
}

fn parse_port_map(s: &str) -> std::result::Result<PortMap, String> {
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid port map format. Expected 'local=target', got '{}'",
            s
        ));
    }

    let local = SocketAddr::from_str(parts[0])
        .map_err(|e| format!("Invalid local address '{}': {}", parts[0], e))?;
    let target = parts[1].to_string();

    if target.is_empty() {
        return Err(format!(
            "Invalid target address '{}': cannot be empty",
            parts[1]
        ));
    }

    Ok(PortMap { local, target })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_parse_single_map() {
        let args = vec![
            "fspeed-rs",
            "client",
            "--server",
            "127.0.0.1:150",
            "--secret",
            "test123",
            "--map",
            "127.0.0.1:2222=127.0.0.1:22",
        ];

        let cli = Cli::parse_from(args);

        match cli.command {
            Commands::Client { map, .. } => {
                assert_eq!(map.len(), 1);
                assert_eq!(map[0].local.to_string(), "127.0.0.1:2222");
                assert_eq!(map[0].target.to_string(), "127.0.0.1:22");
            }
            _ => panic!("Expected Client command"),
        }
    }

    #[test]
    fn test_parse_multiple_map() {
        let args = vec![
            "fspeed-rs",
            "client",
            "--server",
            "127.0.0.1:150",
            "--secret",
            "test123",
            "--map",
            "127.0.0.1:2222=127.0.0.1:22",
            "--map",
            "127.0.0.1:8080=127.0.0.1:80",
        ];

        let cli = Cli::parse_from(args);

        match cli.command {
            Commands::Client { map, .. } => {
                assert_eq!(map.len(), 2);
                assert_eq!(map[0].local.port(), 2222);
                assert_eq!(map[1].local.port(), 8080);
            }
            _ => panic!("Expected Client command"),
        }
    }

    #[test]
    fn test_parse_invalid_map() {
        assert!(parse_port_map("invalid-format").is_err());
        assert!(parse_port_map("127.0.0.1:22=").is_err());
        assert!(parse_port_map("=127.0.0.1:22").is_err());
    }

    #[test]
    fn test_client_socks5_only() {
        let args = vec![
            "fspeed-rs",
            "client",
            "--server",
            "127.0.0.1:150",
            "--secret",
            "test123",
            "--socks5",
            "127.0.0.1:1080",
        ];

        let cli = Cli::parse_from(args);

        match cli.command {
            Commands::Client { map, socks5, .. } => {
                assert!(map.is_empty());
                assert_eq!(socks5.unwrap().to_string(), "127.0.0.1:1080");
            }
            _ => panic!("Expected Client command"),
        }
    }

    #[test]
    fn test_client_map_and_socks5() {
        let args = vec![
            "fspeed-rs",
            "client",
            "--server",
            "127.0.0.1:150",
            "--secret",
            "test123",
            "--map",
            "127.0.0.1:2222=127.0.0.1:22",
            "--socks5",
            "127.0.0.1:1080",
        ];

        let cli = Cli::parse_from(args);

        match cli.command {
            Commands::Client { map, socks5, .. } => {
                assert_eq!(map.len(), 1);
                assert_eq!(socks5.unwrap().to_string(), "127.0.0.1:1080");
            }
            _ => panic!("Expected Client command"),
        }
    }
}
