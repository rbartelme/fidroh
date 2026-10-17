//! Example: does this FIDO2 key do Ed25519, verified through the fidroh library.
use anyhow::{bail, Context, Result};
use ctap_hid_fido2::fidokey::{CredentialSupportedKeyType, GetAssertionArgsBuilder};
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};
use fidroh::fido::{verify, StoredCredential, RP_ID as LIB_RP_ID};
use fidroh::proto::{Alg, Assertion};

fn main() -> Result<()> {
    let device = FidoKeyHidFactory::create(&Cfg::init()).context("No FIDO2 security key found")?;

    // real EdDSA check, in same shape of `algorithms` from src/proto.rs.
    let info = device.get_info()?;
    let has_eddsa = info.algorithms.iter().any(|(k, v)| k == "alg" && v == "-8");
    if !has_eddsa {
        bail!("this FIDO2 key does not list EdDSA (-8)");
    }

    // one prompt, named `pin`.
    let pin = rpassword::prompt_password("FIDO2 PIN: ")?;

    let reg_challenge: [u8; 32] = rand::random();
    println!("Touch FIDO2 key to register (Ed25519)...");
    let att = device.make_credential_with_key_type(
        LIB_RP_ID, // CHANGED: use the library's RP id everywhere
        &reg_challenge,
        Some(pin.as_str()),
        Some(CredentialSupportedKeyType::Ed25519),
    )?;
    let cred_id = att.credential_descriptor.id.clone();
    let pubkey = att.credential_publickey.der.clone();
    println!("Credential ID: {} bytes", cred_id.len());
    println!("Public key: {} bytes: {:02x?}", pubkey.len(), pubkey);

    let key_bytes: [u8; 32] = match pubkey.len() {
        32 => pubkey.as_slice().try_into()?,
        44 => pubkey[12..].try_into()?,
        n => bail!("Unexpected public key length: {}", n),
    };
    // Uses src/fido.rs now.

    let challenge: [u8; 32] = rand::random();
    let args = GetAssertionArgsBuilder::new(LIB_RP_ID, &challenge)
        .pin(&pin)
        .credential_id(&cred_id)
        .build();
    println!("Touch the key to sign...");
    let assertion = device.get_assertion_with_args(&args)?.pop().context("no assertion")?;
    let auth_data = &assertion.auth_data;
    println!(
        "flags: {:#04x}, counter: {:02x?}, signature: {} bytes",
        auth_data[32], &auth_data[33..37], assertion.signature.len()
    );

    let cred = StoredCredential { alg: Alg::EdDsa, public_key: key_bytes.to_vec(), sign_count: 0 };
    let a = Assertion {
        credential_id: cred_id.clone(),
        auth_data: assertion.auth_data.clone(),
        signature: assertion.signature.clone(),
    };
    let count = verify(&a, &cred, LIB_RP_ID, &challenge)?;
    println!("Verified by fidroh::fido::verify (counter {count})!");
    Ok(())
}