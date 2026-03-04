use crate::error::{FenvoyError, Result};

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub fn derive(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm).map_err(|_| {
        FenvoyError::KeyDerivationFailed("HKDF expand failed (output too long?)".into())
    })?;
    Ok(Zeroizing::new(okm))
}

pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let okm = derive(ikm, salt, info, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    Ok(Zeroizing::new(key))
}

pub fn derive_nonce(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 12]> {
    let okm = derive(ikm, salt, info, 12)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&okm);
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_deterministic() {
        let ikm = b"test key material";
        let salt = b"test salt";
        let info = b"test info";

        let k1 = derive_key(ikm, salt, info).unwrap();
        let k2 = derive_key(ikm, salt, info).unwrap();

        assert_eq!(&*k1, &*k2, "same inputs must produce same output");
    }

    #[test]
    fn derive_different_info_gives_different_keys() {
        let ikm = b"test key material";
        let salt = b"test salt";

        let k1 = derive_key(ikm, salt, b"info-a").unwrap();
        let k2 = derive_key(ikm, salt, b"info-b").unwrap();

        assert_ne!(&*k1, &*k2);
    }

    #[test]
    fn derive_various_lengths() {
        let ikm = b"ikm";
        assert!(derive(ikm, b"", b"", 1).is_ok());
        assert!(derive(ikm, b"", b"", 32).is_ok());
        assert!(derive(ikm, b"", b"", 64).is_ok());
        assert!(derive(ikm, b"", b"", 255 * 32).is_ok());
    }

    #[test]
    fn derive_too_long_fails() {
        let ikm = b"ikm";
        assert!(derive(ikm, b"", b"", 255 * 32 + 1).is_err());
    }

    #[test]
    fn derive_nonce_length() {
        let n = derive_nonce(b"ikm", b"salt", b"info").unwrap();
        assert_eq!(n.len(), 12);
    }
}
