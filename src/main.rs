//! FSpeed-RS 命令行入口。
//! 解析命令行参数并启动 Server 或 Client 模式。

use clap::Parser;
use fspeed_rs::app::cli::{Cli, Commands};
use fspeed_rs::tunnel::{client, server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Server {
            listen,
            secret,
            allow,
            transport,
        } => {
            tracing::info!("Starting server mode...");
            tracing::info!("Listening on {:?}: {}", transport, listen);
            tracing::info!("Auth Secret: <hidden>");
            if let Some(ref allowed) = allow {
                tracing::info!("Allowed targets: {:?}", allowed);
            }
            server::run(listen, secret, allow, transport).await?;
        }
        Commands::Client {
            server,
            secret,
            map,
            socks5,
            transport,
        } => {
            if map.is_empty() && socks5.is_none() {
                anyhow::bail!("Client requires at least one --map or --socks5 listener.");
            }

            tracing::info!("Starting client mode...");
            tracing::info!("Target Server {:?}: {}", transport, server);
            tracing::info!("Auth Secret: <hidden>");
            for mapping in &map {
                tracing::info!(
                    "Mapping local TCP {} to remote TCP {}",
                    mapping.local,
                    mapping.target
                );
            }
            if let Some(s5) = socks5 {
                tracing::info!("SOCKS5 listener active on {}", s5);
            }
            client::run(server, secret, map, socks5, transport).await?;
        }
    }

    Ok(())
}
