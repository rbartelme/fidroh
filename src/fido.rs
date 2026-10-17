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

    // ---- the fake authenticator ----

    /// Builds auth_data and signs it exactly like a YubiKey would.
    /// Each field can be changed to produce one specific kind of bad assertion.
    struct SoftKey {
        alg: Alg,
        seed: u8,          // different seed = different key pair
        flags: u8,
        counter: u32,
        rp_id: &'static str,
    }

    impl SoftKey {
        fn new(alg: Alg) -> Self {
            SoftKey { alg, seed: 7, flags: FLAG_UP | FLAG_UV, counter: 1, rp_id: RP_ID }
        }

        /// The public key, in the same format the store will keep.
        fn public_key(&self) -> Vec<u8> {
            match self.alg {
                Alg::Es256 => es_key(self.seed).verifying_key().to_sec1_point(false).as_bytes().to_vec(),
                Alg::EdDsa => ed_key(self.seed).verifying_key().to_bytes().to_vec(),
            }
        }

        /// What the server would have stored for this key.
        fn credential(&self, sign_count: u32) -> StoredCredential {
            StoredCredential { alg: self.alg, public_key: self.public_key(), sign_count }
        }

        /// Signs `challenge` the way a real authenticator does.
        fn sign(&self, challenge: &[u8]) -> Assertion {
            let mut auth_data = Sha256::digest(self.rp_id.as_bytes()).to_vec();
            auth_data.push(self.flags);
            auth_data.extend_from_slice(&self.counter.to_be_bytes());

            let mut msg = auth_data.clone();
            msg.extend_from_slice(&Sha256::digest(challenge));

            let signature = match self.alg {
                Alg::Es256 => {
                    let sig: p256::ecdsa::Signature =
                        p256::ecdsa::signature::Signer::sign(&es_key(self.seed), &msg);
                    sig.to_der().as_bytes().to_vec()
                }
                Alg::EdDsa => ed25519_dalek::Signer::sign(&ed_key(self.seed), &msg).to_bytes().to_vec(),
            };
            Assertion { credential_id: vec![1, 2, 3], auth_data, signature }
        }
    }

    // Fixed seeds instead of randomness: the same test always uses the same keys.
    fn es_key(seed: u8) -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap()
    }
    fn ed_key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    const ALGS: [Alg; 2] = [Alg::Es256, Alg::EdDsa];

    fn challenge() -> Vec<u8> {
        binding(&[1; 32], &[2; 32], &[3; 32])
    }

    // ---- tests ----

    #[test]
    fn binding_is_104_bytes_and_ordered() {
        let b = binding(&[1; 32], &[2; 32], &[3; 32]);
        assert_eq!(b.len(), 104);
        assert_eq!(&b[..8], b"fidroh/1");
        assert_eq!(&b[8..40], &[1; 32]);
        assert_eq!(&b[40..72], &[2; 32]);
        assert_eq!(&b[72..], &[3; 32]);
    }

    #[test]
    fn valid_assertion_passes() {
        for alg in ALGS {
            let key = SoftKey::new(alg);
            let a = key.sign(&challenge());
            assert_eq!(verify(&a, &key.credential(0), RP_ID, &challenge()), Ok(1));
        }
    }

    #[test]
    fn wrong_laptop_fails() {
        for alg in ALGS {
            let key = SoftKey::new(alg);
            let a = key.sign(&challenge());
            let other_laptop = binding(&[1; 32], &[9; 32], &[3; 32]);
            assert_eq!(
                verify(&a, &key.credential(0), RP_ID, &other_laptop),
                Err(VerifyError::BadSignature)
            );
        }
    }
    #[test]
    fn missing_pin_fails() {
        for alg in ALGS {
            let mut key = SoftKey::new(alg);
            key.flags &= !FLAG_UV;
            let a = key.sign(&challenge());
            assert_eq!(
                verify(&a, &key.credential(0), RP_ID, &challenge()),
                Err(VerifyError::NoPin)
            );
        }
    }
    #[test]
    fn missing_touch_fails() {
        for alg in ALGS {
            let mut key = SoftKey::new(alg);
            key.flags &= !FLAG_UP;
            let a = key.sign(&challenge());
            assert_eq!(
                verify(&a, &key.credential(0), RP_ID, &challenge()),
                Err(VerifyError::NoTouch)
            );
        }
    }
    #[test]
    fn replayed_counter_fails() {
        for alg in ALGS {
            let key = SoftKey::new(alg);
            let a = key.sign(&challenge());
            assert_eq!(
                verify(&a, &key.credential(1), RP_ID, &challenge()),
                Err(VerifyError::Counter)
            );
        }
    }
    #[test]
    fn counterless_key_passes() {
        for alg in ALGS {
            let mut key = SoftKey::new(alg);
            key.counter = 0;
            let a = key.sign(&challenge());
            assert_eq!(verify(&a, &key.credential(0), RP_ID, &challenge()), Ok(0));
        }
    }
    #[test]
    fn wrong_rp_fails() {
        for alg in ALGS {
            let key = SoftKey::new(alg);
            let a = key.sign(&challenge());
            assert_eq!(
                verify(&a, &key.credential(0), "wrong", &challenge()),
                Err(VerifyError::RpId)
            );
        }
    }
    #[test]
    fn wrong_key_fails() {
        for alg in ALGS {
            let key = SoftKey::new(alg); // seed 7 signs...
            let a = key.sign(&challenge());
            let mut other = SoftKey::new(alg);
            other.seed = 8; // ...but the server has seed 8's public key
            assert_eq!(
                verify(&a, &other.credential(0), RP_ID, &challenge()),
                Err(VerifyError::BadSignature)
            );
        }
    }

    #[test]
    fn corrupted_key_fails() {
        for alg in ALGS {
            let key = SoftKey::new(alg);
            let a = key.sign(&challenge());
            let mut cred = key.credential(0);
            cred.public_key.pop(); // one byte short: not a valid key in either format
            assert_eq!(verify(&a, &cred, RP_ID, &challenge()), Err(VerifyError::BadKey));
        }
    }
}