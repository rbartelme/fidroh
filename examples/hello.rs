use anyhow::{Context, Result};
use iroh::endpoint::{Connection, presets};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointId};
use tokio::io::AsyncReadExt;

const ALPN: &[u8] = b"fidroh/hello/0";

#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        println!("Accepted connection from {}", conn.remote_id());
        let (mut send, mut recv) = conn.accept_bi().await?;
        let mut msg = Vec::new();
        AsyncReadExt::read_to_end(&mut recv, &mut msg).await.map_err(AcceptError::from_err)?;
        println!("Got: {}", String::from_utf8_lossy(&msg));
        send.write_all(b"Hello from the server").await.map_err(AcceptError::from_err)?;
        send.finish()?;
        conn.closed().await;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") => {
            let ep = Endpoint::bind(presets::N0).await?;
            ep.online().await;
            println!("Serving on, endpoint id:\n {}", ep.id());
            let _router = Router::builder(ep).accept(ALPN, Echo).spawn();
            tokio::signal::ctrl_c().await?;
        }
        Some("dial") => {
            let id: EndpointId = args.get(2).context("Usage: dial <endpoint_id>")?.parse()?;
            let ep = Endpoint::bind(presets::N0).await?;
            println!("Dialing endpoint id {}", ep.id());
            let conn = ep.connect(id, ALPN).await?;
            let (mut send, mut recv) = conn.open_bi().await?;
            send.write_all(b"Hello from the client").await?;
            send.finish()?;
            let mut reply = Vec::new();
            AsyncReadExt::read_to_end(&mut recv, &mut reply).await?;
            println!("Got reply: {}", String::from_utf8_lossy(&reply));
            conn.close(0u32.into(), b"bye");
            ep.close().await;
        }
        _ => println!("Usage: hello serve | hello dial <endpoint_id>"),
    }
    Ok(())
}