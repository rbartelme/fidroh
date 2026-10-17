use sha2::{Digest, Sha256};

use crate::proto::{Alg, Assertion};

pub const RP_ID: &str = "fidroh.local";
pub const FLAG_UP: u8 = 0x01; // user present: the key was touched
pub const FLAG_UV: u8 = 0x04; // user verified: the PIN was entered

/// Every reason an assertion can be rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("authenticator data too short")]
    TooShort,
    #[error("rp id mismatch")]
    RpId,
    #[error("user not present")]
    NoTouch,
    #[error("user not verified")]
    NoPin,
    #[error("sign counter did not increase")]
    Counter,
    #[error("malformed public key")]
    BadKey,
    #[error("malformed signature")]
    BadSigFormat,
    #[error("signature does not verify")]
    BadSignature,
}

/// What the server remembers about one enrolled credential.
#[derive(Debug, Clone)]
pub struct StoredCredential {
    pub alg: Alg,
    pub public_key: Vec<u8>, // ES256: 65-byte SEC1 point; EdDSA: 32 raw bytes
    pub sign_count: u32,
}

/// The exact bytes the FIDO2 key signs over. Binding both endpoint ids
/// means a signature is only valid for this laptop talking to this server.
pub fn binding(nonce: &[u8; 32], client: &[u8; 32], server: &[u8; 32]) -> Vec<u8> {
    let mut b = Vec::with_capacity(8 + 32 * 3);
    b.extend_from_slice(b"fidroh/1");
    b.extend_from_slice(nonce);
    b.extend_from_slice(client);
    b.extend_from_slice(server);
    b
}

/// Checks one assertion against a stored credential.
/// Returns the new sign counter; the caller decides whether to store it.
pub fn verify(
    a: &Assertion,
    cred: &StoredCredential,
    rp_id: &str,
    challenge: &[u8],
) -> Result<u32, VerifyError> {
    let ad = &a.auth_data;
    // length checks
    if ad.len() < 37 {
        return Err(VerifyError::TooShort);
    }
    if ad[..32] != Sha256::digest(rp_id.as_bytes())[..] {
        return Err(VerifyError::RpId);
    }
    // flags and counter
    let flags = ad[32];
    if flags & FLAG_UP == 0 {
        return Err(VerifyError::NoTouch);
    }
    if flags & FLAG_UV == 0 {
        return Err(VerifyError::NoPin);
    }
    // counter is big-endian u32 at ad[33..37]; can't fail because we checked length above.
    // If the counter is 0, the key is counterless, which is allowed if the stored credential is also counterless.
    let count = u32::from_be_bytes(ad[33..37].try_into().unwrap());
    let counterless = count == 0 && cred.sign_count == 0;
    if !counterless && count <= cred.sign_count {
        return Err(VerifyError::Counter);
    }
    // msg is the auth_data plus the SHA256 of the challenge, which is what the signature covers
    let mut msg = ad.clone();
    msg.extend_from_slice(&Sha256::digest(challenge));

    match cred.alg {
        Alg::Es256 => verify_es256(&cred.public_key, &msg, &a.signature)?,
        Alg::EdDsa => verify_eddsa(&cred.public_key, &msg, &a.signature)?,
    }
    Ok(count)
}

fn verify_es256(public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| VerifyError::BadKey)?;
    let sig = Signature::from_der(signature)
        .map_err(|_| VerifyError::BadSigFormat)?
        .normalize_s();
    key.verify(msg, &sig).map_err(|_| VerifyError::BadSignature)
}

fn verify_eddsa(public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let bytes: [u8; 32] = public_key.try_into().map_err(|_| VerifyError::BadKey)?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| VerifyError::BadKey)?;
    let sig = Signature::from_slice(signature).map_err(|_| VerifyError::BadSigFormat)?;
    key.verify_strict(msg, &sig).map_err(|_| VerifyError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_is_104_bytes_and_ordered() {
        let b = binding(&[1; 32], &[2; 32], &[3; 32]);
        assert_eq!(b.len(), 104);
        assert_eq!(&b[..8], b"fidroh/1");
        assert_eq!(&b[8..40], &[1; 32]);
        assert_eq!(&b[40..72], &[2; 32]);
        assert_eq!(&b[72..], &[3; 32]);
    }
}