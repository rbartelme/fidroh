//! The iroh identity for a given server: a 32-byte secret key in a file only this user can read.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use iroh::SecretKey;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("key file {path} must be 32 bytes, found {len}")]
    WrongLength { path: String, len: usize },
    #[error("key file {path} is readable by other users; fix with: chmod 600 {path}")]
    TooOpen { path: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Loads the secret key at `path`, or creates one if the file doesn't exist.
pub fn load_or_create(path: &Path) -> Result<SecretKey, KeyError> {
    let shown = path.display().to_string();

    if path.exists() {
        let mode = fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(KeyError::TooOpen {path: shown});
        }
        let bytes = fs::read(path)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| KeyError::WrongLength { path: shown, len: bytes.len() })?;
        return Ok(SecretKey::from_bytes(&arr))
        
    }

    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    } 
    let bytes: [u8; 32] = rand::random();
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.write_all(&bytes)?;
    Ok(SecretKey::from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_then_reloads_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.key");
        let first = load_or_create(&path).unwrap();
        let second = load_or_create(&path).unwrap();
        assert_eq!(first.public(), second.public());
    }

    #[test]
    fn new_file_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.key");
        load_or_create(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn refuses_readable_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.key");
        load_or_create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(load_or_create(&path), Err(KeyError::TooOpen { .. })));
    }

    #[test]
    fn refuses_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.key");
        fs::write(&path, [0u8; 31]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(load_or_create(&path), Err(KeyError::WrongLength { len: 31, .. })));
    }
}