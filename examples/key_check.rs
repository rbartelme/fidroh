//! Hardware check: register on the security key, sign a challenge, verify it with fidroh.
//! No network involved.   cargo run --example key_check
use anyhow::Result;
use fidroh::authenticator;
use fidroh::fido::{RP_ID, StoredCredential, verify};

fn main() -> Result<()> {
    let pin = rpassword::prompt_password("FIDO2 PIN: ")?;
    let (alg, cred_id, public_key) = authenticator::register(&pin)?;
    let challenge: [u8; 32] = rand::random();
    let a = authenticator::sign(&pin, &challenge, &cred_id)?;
    let cred = StoredCredential {
        alg,
        public_key,
        sign_count: 0,
    };
    let count = verify(&a, &cred, RP_ID, &challenge)?;
    println!("OK: {alg:?} credential works with this key (counter {count})");
    Ok(())
}
