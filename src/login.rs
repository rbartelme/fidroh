//! The client half of the login handshake. It doesn't care what does the signing:
//! the real client passes the security key, tests pass a SoftKey.

use anyhow::{Context, Result, bail};
use iroh::EndpointId;
use iroh::endpoint::Connection;

use crate::fido::binding;
use crate::proto::{Assertion, Msg, read_msg, write_msg};

/// Run Hello -> Challenge -> Assertion -> AuthResult on `conn`.
/// `sign(challenge, credential_id)` runs on a blocking thread, so it may prompt or touch USB.
pub async fn login<F>(conn: &Connection, me: EndpointId, server: EndpointId, sign: F) -> Result<()>
where
    F: FnOnce(&[u8], &[u8]) -> Result<Assertion> + Send + 'static,
{
    let (mut send, mut recv) = conn.open_bi().await?;

    write_msg(&mut send, &Msg::Hello { version: 1 }).await?;
    let Msg::Challenge {
        nonce,
        allow_credentials,
    } = read_msg(&mut recv)
        .await
        .context("no challenge from server: is this laptop enrolled there?")?
    else {
        bail!("expected Challenge");
    };
    // The server lists the credentials enrolled for this laptop; use the first.
    let cred_id = allow_credentials
        .first()
        .context("server sent no credentials")?
        .clone();

    // Bind to the server id WE DIALED, so a different server can't reuse this signature.
    let challenge = binding(&nonce, me.as_bytes(), server.as_bytes());
    // Sign only now that a real challenge is waiting.
    let assertion = tokio::task::spawn_blocking(move || sign(&challenge, &cred_id)).await??;
    write_msg(&mut send, &Msg::Assertion(assertion)).await?;

    let Msg::AuthResult { ok } = read_msg(&mut recv).await? else {
        bail!("expected AuthResult");
    };
    if !ok {
        conn.close(0u32.into(), b"bye");
        bail!("login denied");
    }
    Ok(())
}