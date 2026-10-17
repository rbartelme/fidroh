//! Does this FIDO2 key do Ed25519, and what bytelength is the signature?
use anyhow::{bail, Context, Result};
use ctap_hid_fido2::fidokey::{CredentialSupportedKeyType, GetAssertionArgsBuilder};
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

const RP_ID: &str = "fidroh.local";

fn main() -> Result<()> {
    // Check if the FIDO2 key supports Ed25519
    let pin = rpassword::prompt_password("FIDO2 PIN: ")?;
    let device = FidoKeyHidFactory::create(&Cfg::init()).context("No FIDO2 security key found")?;
    let info = device.get_info()?;
    println!("FIDO2 key info: {:#?}", info);
   /* if !info.supported_key_types.contains(&CredentialSupportedKeyType::Ed25519) {
        bail!("FIDO2 key does not support Ed25519");
    } */
    // Register if it does, and then sign a challenge and verify the signature
    let pin = rpassword::prompt_password("FIDO2 PIN: ")?;
    let reg_challenge: [u8; 32] = rand::random();
    println!("Touch FIDO2 key to register (Ed25519)...");
    let att = device.make_credential_with_key_type(
        RP_ID,
        &reg_challenge,
        Some(pin.as_str()),
        Some(CredentialSupportedKeyType::Ed25519),
    )?;
    let cred_id = att.credential_descriptor.id.clone();
    let pubkey = att.credential_publickey.der.clone();
    println!("Credential ID: {} bytes", cred_id.len());
    println!("Public key: {} bytes: {:02x?}", pubkey.len(), pubkey);
    // enforce 32bytes for key length
    let key_bytes: [u8; 32] = match pubkey.len() {
        32 => pubkey.as_slice().try_into()?,
        44 => pubkey[12..].try_into()?,
        n => bail!("Unexpected public key length: {}", n),
    };
    let key = VerifyingKey::from_bytes(&key_bytes).context("not a valid ed25519 key")?;
    
    // Sign and verify a challenge
    let challenge: [u8; 32] = rand::random();
    let args = GetAssertionArgsBuilder::new(RP_ID, &challenge)
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

    // LIB: src/fido.rs (verify, EdDSA arm)
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(challenge));
    let sig = Signature::from_slice(&assertion.signature).context("signature is not 64 bytes")?;
    key.verify_strict(&signed, &sig).context("signature did not verify")?;

    println!("Verified (Ed25519)!");
    Ok(())
}