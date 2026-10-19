//! Enrollment tokens: how a device's public data reaches the server's console.
//! Text form: "fidroh1:" + hex of the postcard bytes. Contains only public data.

use serde::{Deserialize, Serialize};

use crate::proto::Alg;

const PREFIX: &str = "fidroh1:";

/// Everything the server needs to let one device + one security key log in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrollment {
    pub endpoint_id: [u8; 32],
    pub alg: Alg,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("not a fidroh enrollment token (it should start with fidroh1:)")]
    BadPrefix,
    #[error("token is not valid hex")]
    BadHex,
    #[error("token is corrupted: {0}")]
    Decode(#[from] postcard::Error),
}

impl Enrollment {
    /// The text form to print on the device.
    pub fn to_token(&self) -> String {
        let bytes = postcard::to_stdvec(self).expect("serializing to a Vec cannot fail");
        format!("{PREFIX}{}", hex::encode(bytes))
    }

    /// Parses a pasted token. Surrounding whitespace (like a trailing newline) is ignored.
    pub fn from_token(s: &str) -> Result<Self, TokenError> {
        let body = s.trim().strip_prefix(PREFIX).ok_or(TokenError::BadPrefix)?;
        let bytes = hex::decode(body).map_err(|_| TokenError::BadHex)?;
        Ok(postcard::from_bytes(&bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Enrollment {
        Enrollment {
            endpoint_id: [1; 32],
            alg: Alg::EdDsa,
            credential_id: vec![2; 128],
            public_key: vec![3; 32],
        }
    }

    #[test]
    fn token_roundtrip() {
        let token = sample().to_token();
        assert!(token.starts_with("fidroh1:"));
        assert_eq!(Enrollment::from_token(&token).unwrap(), sample());
    }

    #[test]
    fn pasted_with_newline_still_parses() {
        let token = format!("  {}\n", sample().to_token());
        assert_eq!(Enrollment::from_token(&token).unwrap(), sample());
    }

    #[test]
    fn wrong_prefix_rejected() {
        let token = sample().to_token().replace("fidroh1:", "fidroh2:");
        assert!(matches!(
            Enrollment::from_token(&token),
            Err(TokenError::BadPrefix)
        ));
    }

    #[test]
    fn bad_hex_rejected() {
        assert!(matches!(
            Enrollment::from_token("fidroh1:zz"),
            Err(TokenError::BadHex)
        ));
    }

    #[test]
    fn truncated_token_rejected() {
        let token = sample().to_token();
        let cut = &token[..token.len() - 2]; // lose the last byte (2 hex chars)
        assert!(matches!(
            Enrollment::from_token(cut),
            Err(TokenError::Decode(_))
        ));
    }
}
