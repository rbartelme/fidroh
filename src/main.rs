//! fidroh: private tunnels over iroh, unlocked by an enrolled device and a FIDO2 security key.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

/// Private tunnels over iroh, unlocked by an enrolled device and a FIDO2 security key.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Folder for this machine's identity (and, on a server, its database).
    /// Defaults to ~/.local/share/fidroh.
    #[arg(long, short = 'd', env = "FIDROH_DATA_DIR", global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print this machine's endpoint id.
    Id,
    /// Laptop: create a credential on your security key and print an enrollment token.
    #[cfg(feature = "hardware")]
    Register,
    /// Server console: allow a laptop to log in, using its enrollment token.
    Enroll { name: String, token: String },
    /// Server: accept enrolled laptops and forward them to an upstream service.
    Serve {
        /// Where to forward authenticated traffic, e.g. 127.0.0.1:4000
        #[arg(long)]
        upstream: SocketAddr,
    },
    /// Laptop: log in to a server and open the tunnel locally.
    #[cfg(feature = "hardware")]
    Connect {
        /// The server's endpoint id (from `fidroh id` on the server).
        server: iroh::EndpointId,
        /// Local address for the tunnel; keep it on 127.0.0.1.
        #[arg(long, default_value = "127.0.0.1:8443")]
        listen: SocketAddr,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let dir = match cli.data_dir {
        Some(dir) => dir,
        None => dirs::data_dir().context("no home data folder found; pass --data-dir")?.join("fidroh"),
    };
    match cli.cmd {
        Cmd::Id => {
            println!("{}", fidroh::node::id(&dir)?);
            Ok(())
        }
        #[cfg(feature = "hardware")]
        Cmd::Register => fidroh::client::register(&dir),
        Cmd::Enroll { name, token } => fidroh::server::enroll(&dir, &name, &token),
        Cmd::Serve { upstream } => fidroh::server::serve(&dir, upstream).await,
        #[cfg(feature = "hardware")]
        Cmd::Connect { server, listen } => fidroh::client::connect(&dir, server, listen).await,
    }
}