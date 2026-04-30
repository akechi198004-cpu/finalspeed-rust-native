use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::str::FromStr;

use crate::config::PortMap;

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

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the server to accept incoming tunnel connections
    Server {
        /// Address to listen on (e.g., 0.0.0.0:150)
        #[arg(long, default_value = "0.0.0.0:150")]
        listen: SocketAddr,

        /// Shared secret for authentication
        #[arg(long)]
        secret: String,

        /// Optional comma-separated list of allowed target addresses (e.g., 127.0.0.1:22,127.0.0.1:80)
        #[arg(long, value_delimiter = ',')]
        allow: Option<Vec<SocketAddr>>,
    },

    /// Start the client to forward local TCP connections to the server
    Client {
        /// Server address to connect to (e.g., example.com:150)
        #[arg(long)]
        server: String,

        /// Shared secret for authentication
        #[arg(long)]
        secret: String,

        /// Port mappings in the format local_addr:local_port=target_addr:target_port
        /// (e.g., 127.0.0.1:2222=127.0.0.1:22 or 127.0.0.1:8080=example.com:80)
        #[arg(long, value_parser = parse_port_map, required = false)]
        map: Vec<PortMap>,

        /// Local SOCKS5 listener address (e.g., 127.0.0.1:1080)
        #[arg(long, required = false)]
        socks5: Option<SocketAddr>,
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
