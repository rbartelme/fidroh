use anyhow::{Context, Result};
use ctap_hid_fido2::fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder};
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};

const RP_ID: &str = "fidroh.local";

fn main() -> Result<()> {
    let pin = rpassword::prompt_password("FIDO2 PIN: ")?;
    let device = FidoKeyHidFactory::create(&Cfg::init()).context("No FIDO2 security key found")?;

    //1. Register: create new keypair for RP_ID
    let reg_challenge: [u8; 32] = rand::random();
    let args = MakeCredentialArgsBuilder::new(RP_ID, &reg_challenge)
        .pin(&pin)
        .build();
    println!("Touch FIDO2 key to register...");
    let att = device.make_credential_with_args(&args)?;
    let cred_id = att.credential_descriptor.id.clone();
    let pubkey = att.credential_publickey.der.clone();
    println!("Credential ID: {} bytes, public key: {} bytes", cred_id.len(), pubkey.len());

    //2. login: trhe key will sign a fresh challenge
    let challenge: [u8; 32] = rand::random();
    let args = GetAssertionArgsBuilder::new(RP_ID, &challenge)
        .pin(&pin)
        .credential_id(&cred_id)
        .build();
    println!("Touch FIDO2 key to sign...");
    let assertion = device.get_assertion_with_args(&args)?.pop().context("No assertion returned")?;

    //3. Verify like a server would do: signature over authData || SHA-256(challenge)
    let auth_data = &assertion.auth_data;
    println!("flags: {:#04x}, counter bytes: {:02x?}", auth_data[32], &auth_data[33..37]);

    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(&challenge));
    let sig = Signature::from_der(&assertion.signature)?;
    let sig = sig.normalize_s();
    let key = VerifyingKey::from_sec1_bytes(&pubkey).context("Public key format")?;
    key.verify(&signed, &sig).context("Signature verification failed")?;

    println!("Signature verified successfully");
    Ok(())
}