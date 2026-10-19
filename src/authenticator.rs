//! The laptop's FIDO2 security key, over USB HID. Only built with the `hardware` feature.

use anyhow::{Context, Result};
use ctap_hid_fido2::fidokey::{CredentialSupportedKeyType, GetAssertionArgsBuilder}; // same path as spike_ed
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};

use crate::fido::RP_ID;
use crate::proto::{Alg, Assertion};

/// Registers a credential, preferring Ed25519 and falling back to ES256.
/// Blocks until the key is touched. Returns (alg, credential id, public key).
pub fn register(pin: &str) -> Result<(Alg, Vec<u8>, Vec<u8>)> {
    let device = FidoKeyHidFactory::create(&Cfg::init()).context("no FIDO2 security key found")?;
    let info = device.get_info()?;
    let has_eddsa = info.algorithms.iter().any(|(k, v)| k == "alg" && v == "-8");
    let (alg, key_type) = if has_eddsa {
        (Alg::EdDsa, CredentialSupportedKeyType::Ed25519)
    } else {
        (Alg::Es256, CredentialSupportedKeyType::Ecdsa256)
    };
    let challenge: [u8; 32] = rand::random();
    eprintln!("Touch your security key to register ({alg:?})...");
    let att = device.make_credential_with_key_type(RP_ID, &challenge, Some(pin), Some(key_type))?;
    Ok((
        alg,
        att.credential_descriptor.id.clone(),
        att.credential_publickey.der.clone(),
    ))
}

/// Signs `challenge` with one credential. Blocks until the key is touched.
pub fn sign(pin: &str, challenge: &[u8], credential_id: &[u8]) -> Result<Assertion> {
    let device = FidoKeyHidFactory::create(&Cfg::init()).context("no FIDO2 security key found")?;
    let args = GetAssertionArgsBuilder::new(RP_ID, challenge)
        .pin(pin)
        .credential_id(credential_id)
        .build();
    eprintln!("Touch your security key to log in...");
    let a = device
        .get_assertion_with_args(&args)?
        .pop()
        .context("no assertion returned")?;
    Ok(Assertion {
        credential_id: credential_id.to_vec(),
        auth_data: a.auth_data,
        signature: a.signature,
    })
}
