use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const ALPN: &[u8] = b"fidroh/1";
pub const MAX_FRAME: u32 = 64 * 1024; // 64 KiB

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    Es256,
    EdDsa,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub auth_data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    Hello {
        version: u16,
    },
    Challenge {
        nonce: [u8; 32],
        allow_credentials: Vec<Vec<u8>>,
    },
    Assertion(Assertion),
    AuthResult {
        ok: bool,
    },
    OpenRoute {
        name: String,
    },
    RouteResult {
        ok: bool,
        reason: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("Peer closed the stream")]
    Closed,
    #[error("Frame too large: {0} bytes")]
    TooLarge(u32),
    #[error("Truncated frame")]
    Truncated,
    #[error("Malformed message: {0}")]
    Decode(#[from] postcard::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Sends one message: a 4-byte big-endian length, then the postcard bytes.
pub async fn write_msg<W: AsyncWrite + Unpin>(w: &mut W, msg: &Msg) -> Result<(), FrameError> {
    // turn `msg` into a Vec<u8> with postcard::to_stdvec
    let bytes = postcard::to_stdvec(msg)?;
    // if the length is over MAX_FRAME, return Err(FrameError::TooLarge(len))
    if bytes.len() > MAX_FRAME as usize {
        return Err(FrameError::TooLarge(bytes.len() as u32));
    }
    // write the length with w.write_u32(...), then the bytes with w.write_all(...)
    w.write_u32(bytes.len() as u32).await?;
    w.write_all(&bytes).await?;
    // flush then OK
    w.flush().await?;
    Ok(())
}

/// Reads one message: a 4-byte big-endian length, then the postcard bytes.
pub async fn read_msg<R: AsyncRead + Unpin>(r: &mut R) -> Result<Msg, FrameError> {
    let len = r
        .read_u32()
        .await
        .map_err(|e| eof_as(e, FrameError::Closed))?;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)
        .await
        .map_err(|e| eof_as(e, FrameError::Truncated))?;
    let msg: Msg = postcard::from_bytes(&buf)?;
    Ok(msg)
}

/// An early end of stream becomes `on_eof`; any other I/O error stays an I/O error.
fn eof_as(e: std::io::Error, on_eof: FrameError) -> FrameError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        on_eof
    } else {
        FrameError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_hello() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let sent = Msg::Hello { version: 1 };
        write_msg(&mut a, &sent).await.unwrap();
        let got = read_msg(&mut b).await.unwrap();
        assert_eq!(got, sent);
    }

    #[tokio::test]
    async fn clean_close() {
        let (a, mut b) = tokio::io::duplex(64 * 1024);
        drop(a); // hang up without writing anything
        let got = read_msg(&mut b).await;
        assert!(matches!(got, Err(FrameError::Closed)));
    }

    #[tokio::test]
    async fn rejects_oversized_frame() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        a.write_u32(MAX_FRAME + 1).await.unwrap(); // a length, and no body
        let got = read_msg(&mut b).await;
        assert!(matches!(got, Err(FrameError::TooLarge(_))));
    }

    #[tokio::test]
    async fn truncated_frame() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        a.write_u32(100).await.unwrap(); // promise 100 bytes...
        a.write_all(&[0u8; 10]).await.unwrap(); // ...deliver 10...
        drop(a); // ...then hang up
        let got = read_msg(&mut b).await;
        assert!(matches!(got, Err(FrameError::Truncated)));
    }

    #[tokio::test]
    async fn two_frames_back_to_back() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let first = Msg::Hello { version: 1 };
        let second = Msg::AuthResult { ok: true };
        write_msg(&mut a, &first).await.unwrap();
        write_msg(&mut a, &second).await.unwrap();
        assert_eq!(read_msg(&mut b).await.unwrap(), first);
        assert_eq!(read_msg(&mut b).await.unwrap(), second);
    }
}
