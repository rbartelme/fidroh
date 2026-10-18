//! Device key + FIDO2 login over iroh, using the fidroh library.
//!   cargo run --example handshake -- serve
//!   cargo run --example handshake -- dial <server-id>

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use fidroh::fido::{binding, verify, StoredCredential, RP_ID};
use fidroh::proto::{read_msg, write_msg, Msg, ALPN};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use ctap_hid_fido2::fidokey::{CredentialSupportedKeyType, GetAssertionArgsBuilder}; // same path as in spike_ed
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};
use fidroh::proto::{Alg, Assertion};
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointId};

/// INSECURE dev state: device endpoint id -> (credential id, stored credential).
/// TODO: replace with SQLite.
type Devices = Arc<Mutex<HashMap<[u8; 32], (Vec<u8>, StoredCredential)>>>;

#[derive(Debug, Clone)]
struct Gate { 
    server_id: [u8; 32],
    devices: Devices,
}

impl ProtocolHandler for Gate {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let who = conn.remote_id().to_string();
        let who = &who[..8]; // short id for logs

        match tokio::time::timeout(Duration::from_secs(90), self.login(&conn)).await {
            Ok(Ok(())) => {
                println!("{who}: logged in");
                conn.closed().await; //to be replaced with tunnel
                println!("{who}: disconnected");
            }
            Ok(Err(e)) => {
                println!("{who}: denied: {e:#}"); // the reason stays in the log
                let _ = tokio::time::timeout(Duration::from_secs(2), conn.closed()).await;
                conn.close(1u32.into(), b"denied");
            }
            Err(_) => {
                println!("{who}: timed out");
                conn.close(2u32.into(), b"timeout");
            }
        }
        Ok(())
    }
}

impl Gate {
     async fn login(&self, conn: &Connection) -> Result<()> {
        // QUIC already proved the peer holds the secret key for this id.
        let peer: [u8; 32] = *conn.remote_id().as_bytes();
        let (mut send, mut recv) = conn.accept_bi().await?;

        // INSECURE (to be replaced with sqlite): trust whatever the client registers.
        let Msg::DevRegister { alg, credential_id, public_key } = read_msg(&mut recv).await? else {
            bail!("expected DevRegister");
        };
        let cred = StoredCredential { alg, public_key, sign_count: 0 };
        self.devices.lock().unwrap().insert(peer, (credential_id, cred));

        let Msg::Hello { version: 1 } = read_msg(&mut recv).await? else {
            bail!("expected Hello version 1");
        };
        let (cred_id, cred) =
            self.devices.lock().unwrap().get(&peer).cloned().context("unknown device")?;

        let nonce: [u8; 32] = rand::random();
        let challenge_msg = Msg::Challenge { nonce, allow_credentials: vec![cred_id.clone()] };
        write_msg(&mut send, &challenge_msg).await?;

        let Msg::Assertion(a) = read_msg(&mut recv).await? else {
            bail!("expected Assertion");
        };
        if a.credential_id != cred_id {
            bail!("unknown credential");
        }

        // THE most important line in fidroh: the binding is built from what QUIC
        // proved (peer) and who WE are (server_id), never from bytes the client sent.
        let challenge = binding(&nonce, &peer, &self.server_id);
        let result = verify(&a, &cred, RP_ID, &challenge);

        // Reply BEFORE propagating the error, so a denied client gets an answer.
        write_msg(&mut send, &Msg::AuthResult { ok: result.is_ok() }).await?;
        send.finish()?;
        let new_count = result?;
        if let Some((_, c)) = self.devices.lock().unwrap().get_mut(&peer) {
            c.sign_count = new_count;
        }
        Ok(())
    }   
}

// LIB todo: src/yubikey.rs 
/// Registers a credential, preferring Ed25519 and falling back to ES256.
/// Blocks until the key is touched. Returns (alg, credential id, public key).
fn yk_register(pin: &str) -> Result<(Alg, Vec<u8>, Vec<u8>)> {
    let device = FidoKeyHidFactory::create(&Cfg::init()).context("no FIDO2 security key found")?;
    let info = device.get_info()?;
    let has_eddsa = info.algorithms.iter().any(|(k, v)| k == "alg" && v == "-8");
    let (alg, key_type) = if has_eddsa {
        (Alg::EdDsa, CredentialSupportedKeyType::Ed25519)
    } else {
        (Alg::Es256, CredentialSupportedKeyType::Ecdsa256) // check the variant name in rustdoc
    };
    let challenge: [u8; 32] = rand::random();
    eprintln!("Touch your security key to register ({alg:?})...");
    let att = device.make_credential_with_key_type(RP_ID, &challenge, Some(pin), Some(key_type))?;
    Ok((alg, att.credential_descriptor.id.clone(), att.credential_publickey.der.clone()))
}

// LIB todo: src/yubikey.rs
/// Signs `challenge` with one credential. Blocks until the key is touched.
fn yk_sign(pin: &str, challenge: &[u8], credential_id: &[u8]) -> Result<Assertion> {
    let device = FidoKeyHidFactory::create(&Cfg::init()).context("no FIDO2 security key found")?;
    let args = GetAssertionArgsBuilder::new(RP_ID, challenge)
        .pin(pin)
        .credential_id(credential_id)
        .build();
    eprintln!("Touch your security key to log in...");
    let a = device.get_assertion_with_args(&args)?.pop().context("no assertion returned")?;
    Ok(Assertion { credential_id: credential_id.to_vec(), auth_data: a.auth_data, signature: a.signature })
}

async fn dial(server: EndpointId) -> Result<()> {
    let pin = rpassword::prompt_password("FIDO2 PIN: ")?;

    // INSECURE: a fresh credential every run (so two touches). TODO lib state with sqlite registers once.
    let p = pin.clone();
    let (alg, cred_id, public_key) = tokio::task::spawn_blocking(move || yk_register(&p)).await??;

    let ep = Endpoint::bind(presets::N0).await?;
    let me: [u8; 32] = *ep.id().as_bytes();
    let conn = ep.connect(server, ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await?;

    write_msg(&mut send, &Msg::DevRegister { alg, credential_id: cred_id.clone(), public_key }).await?;
    write_msg(&mut send, &Msg::Hello { version: 1 }).await?;

    let Msg::Challenge { nonce, allow_credentials } = read_msg(&mut recv).await? else {
        bail!("expected Challenge");
    };
    if !allow_credentials.contains(&cred_id) {
        bail!("this laptop has no credential for that server");
    }

    // Bind to the server id WE DIALED, so a different server can't reuse this signature.
    let challenge = binding(&nonce, &me, server.as_bytes());
    let id = cred_id.clone();
    let assertion = tokio::task::spawn_blocking(move || yk_sign(&pin, &challenge, &id)).await??;
    write_msg(&mut send, &Msg::Assertion(assertion)).await?;

    let Msg::AuthResult { ok } = read_msg(&mut recv).await? else {
        bail!("expected AuthResult");
    };
    if !ok {
        conn.close(0u32.into(), b"bye");
        bail!("login denied");
    }
    println!("logged in to {}", &server.to_string()[..8]);

    // TODO lib replaces with tunnel here.
    conn.close(0u32.into(), b"bye");
    ep.close().await;
    Ok(())
}


async fn serve() -> Result<()> {
    let ep = Endpoint::bind(presets::N0).await?;
    ep.online().await;
    let gate = Gate { server_id: *ep.id().as_bytes(), devices: Devices::default() };
    println!("serving, endpoint id:\n{}", ep.id());
    let _router = Router::builder(ep).accept(ALPN, gate).spawn();
    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") => serve().await,
        Some("dial") => {
            let id: EndpointId = args.get(2).context("usage: handshake dial <server-id>")?.parse()?;
            dial(id).await
        }
        _ => {
            eprintln!("usage: handshake serve | handshake dial <server-id>");
            Ok(())
        }
    }
}