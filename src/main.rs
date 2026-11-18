use clap::{Parser, Subcommand};
use oauth2_mcp_gateway::config::GatewayConfig;
use oauth2_mcp_gateway::crypto::PasswordVerifier;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    name = "oauth2-mcp-gateway",
    version,
    about = "OAuth 2.1 sidecar gateway for MCP servers"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the sidecar gateway
    Serve {
        #[arg(
            short,
            long,
            default_value = "gateway.json",
            env = "OAUTH2_MCP_GATEWAY_CONFIG"
        )]
        config: PathBuf,
    },
    /// Validate configuration and exit
    Check {
        #[arg(
            short,
            long,
            default_value = "gateway.json",
            env = "OAUTH2_MCP_GATEWAY_CONFIG"
        )]
        config: PathBuf,
    },
    /// Read a password from stdin and print its PBKDF2-HMAC-SHA256 hash
    HashPassword,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Serve { config } => match GatewayConfig::from_file(&config) {
            Ok(cfg) => {
                let shutdown = CancellationToken::new();
                let signal_shutdown = shutdown.clone();
                tokio::spawn(async move {
                    wait_for_shutdown_signal().await;
                    signal_shutdown.cancel();
                });
                if let Err(err) = oauth2_mcp_gateway::server::run(Arc::new(cfg), shutdown).await {
                    eprintln!("oauth2-mcp-gateway: {err}");
                    return ExitCode::from(1);
                }
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("oauth2-mcp-gateway: {err}");
                ExitCode::from(1)
            }
        },
        Commands::Check { config } => match GatewayConfig::from_file(&config) {
            Ok(_) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("oauth2-mcp-gateway: {err}");
                ExitCode::from(1)
            }
        },
        Commands::HashPassword => {
            use std::io::Read;
            let mut buf = String::new();
            if let Err(err) = std::io::stdin().read_to_string(&mut buf) {
                eprintln!("oauth2-mcp-gateway: cannot read stdin: {err}");
                return ExitCode::from(1);
            }
            let secret = buf.trim_end_matches(['\r', '\n']);
            match PasswordVerifier::from_plaintext(secret) {
                Ok(v) => {
                    println!("{}", v.encode());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("oauth2-mcp-gateway: {err}");
                    ExitCode::from(1)
                }
            }
        }
    }
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
