//! Moves bytes between a TCP socket and one iroh QUIC stream.

use iroh::endpoint::{RecvStream, SendStream};
use tokio::net::TcpStream;

/// Copies bytes both ways until both sides have finished.
/// Returns (bytes sent into QUIC, bytes sent into TCP).
pub async fn splice(
    mut tcp: TcpStream,
    send: SendStream,
    recv: RecvStream,
) -> std::io::Result<(u64, u64)> {
    tcp.set_nodelay(true)?;
    let mut quic = tokio::io::join(recv, send);
    tokio::io::copy_bidirectional(&mut tcp, &mut quic).await
}
