//! Streams after login: one QUIC stream per TCP connection, with a named route.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Result};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::pipe::splice;
use crate::proto::{read_msg, write_msg, Msg};

/// Server side: each new stream on this connection is one browser TCP connection on the laptop.
pub async fn serve_streams(conn: Connection, upstream: SocketAddr, routes: Vec<String>) {
    let routes = Arc::new(routes);
    while let Ok((send, recv)) = conn.accept_bi().await {
        let routes = routes.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, upstream, &routes).await {
                warn!("stream error: {e:#}");
            }
        });
    }
    // accept_bi() failed: the laptop disconnected, so every stream is done too.
}

async fn handle_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    upstream: SocketAddr,
    routes: &[String],
) -> Result<()> {
    let Msg::OpenRoute { name } = read_msg(&mut recv).await? else {
        bail!("expected OpenRoute");
    };
    // Only "web" exists for now, and only for laptops enrolled with it.
    if name != "web" || !routes.contains(&name) {
        let reply = Msg::RouteResult { ok: false, reason: "no such route".into() };
        write_msg(&mut send, &reply).await?;
        send.finish()?;
        return Ok(());
    }
    let tcp = match TcpStream::connect(upstream).await {
        Ok(tcp) => tcp,
        Err(e) => {
            eprintln!("upstream {upstream}: {e}"); // the detail stays in the server log
            let reply = Msg::RouteResult { ok: false, reason: "upstream unavailable".into() };
            write_msg(&mut send, &reply).await?;
            send.finish()?;
            return Ok(());
        }
    };
    write_msg(&mut send, &Msg::RouteResult { ok: true, reason: String::new() }).await?;
    let (up, down) = splice(tcp, send, recv).await?; // from here on: raw bytes, no more frames
    debug!(up, down, "stream closed");
    Ok(())
}

/// Laptop side: one browser connection becomes one stream asking for the "web" route.
pub async fn forward_one(conn: Connection, tcp: TcpStream) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, &Msg::OpenRoute { name: "web".into() }).await?;
    let Msg::RouteResult { ok, reason } = read_msg(&mut recv).await? else {
        bail!("expected RouteResult");
    };
    if !ok {
        bail!("route refused: {reason}");
    }
    splice(tcp, send, recv).await?;
    Ok(())
}