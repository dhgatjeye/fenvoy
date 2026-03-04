use crate::error::{FenvoyError, Result};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::Rng;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"FENV";
const VERSION: u8 = 0x01;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const CIPHERTEXT_LEN: usize = 32 + 16;
pub const ENVELOPE_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN + CIPHERTEXT_LEN;

const ARGON2_M_COST: u32 = 19456;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

pub fn is_encrypted(data: &[u8]) -> bool {
    data.len() >= 5 && data[..4] == *MAGIC && data[4] == VERSION
}

pub fn encrypt_key(signing_key: &[u8; 32], password: &[u8]) -> Result<Vec<u8>> {
    if password.is_empty() {
        return Err(FenvoyError::KeyDerivationFailed(
            "password cannot be empty".into(),
        ));
    }

    let mut rng = crate::crypto::csprng();

    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);

    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let derived_key = derive_key_from_password(password, &salt)?;

    let cipher = ChaCha20Poly1305::new(&Key::from(*derived_key));
    let nonce_ga = Nonce::from(nonce);
    let ciphertext = cipher
        .encrypt(&nonce_ga, signing_key.as_ref())
        .map_err(|_| FenvoyError::KeyDerivationFailed("AEAD encryption failed".into()))?;

    let mut envelope = Vec::with_capacity(ENVELOPE_LEN);
    envelope.extend_from_slice(MAGIC);
    envelope.push(VERSION);
    envelope.extend_from_slice(&salt);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);

    debug_assert_eq!(envelope.len(), ENVELOPE_LEN);
    Ok(envelope)
}

pub fn decrypt_key(envelope: &[u8], password: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if envelope.len() != ENVELOPE_LEN {
        return Err(FenvoyError::ConfigParseError(format!(
            "encrypted key file has invalid length: {} (expected {ENVELOPE_LEN})",
            envelope.len()
        )));
    }

    if envelope[..4] != *MAGIC {
        return Err(FenvoyError::ConfigParseError(
            "invalid key file magic".into(),
        ));
    }

    if envelope[4] != VERSION {
        return Err(FenvoyError::ConfigParseError(format!(
            "unsupported key file version: {} (expected {VERSION})",
            envelope[4]
        )));
    }

    let salt = &envelope[5..5 + SALT_LEN];
    let nonce = &envelope[5 + SALT_LEN..5 + SALT_LEN + NONCE_LEN];
    let ciphertext = &envelope[5 + SALT_LEN + NONCE_LEN..];

    let derived_key = derive_key_from_password(password, salt)?;

    let cipher = ChaCha20Poly1305::new(&Key::from(*derived_key));
    let nonce_arr: [u8; NONCE_LEN] = nonce.try_into().expect("nonce length");
    let nonce_ga = Nonce::from(nonce_arr);
    let plaintext = cipher.decrypt(&nonce_ga, ciphertext).map_err(|_| {
        FenvoyError::AuthenticationFailed("wrong password or corrupted key file".into())
    })?;

    let plaintext = Zeroizing::new(plaintext);

    if plaintext.len() != 32 {
        return Err(FenvoyError::ConfigParseError(
            "decrypted key has invalid length".into(),
        ));
    }

    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&plaintext);
    Ok(key)
}

fn derive_key_from_password(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| FenvoyError::KeyDerivationFailed(format!("invalid Argon2 params: {e}")))?;

    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password, salt, &mut *key)
        .map_err(|e| FenvoyError::KeyDerivationFailed(format!("Argon2id failed: {e}")))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let signing_key = [42u8; 32];
        let password = b"test-password-123";

        let envelope = encrypt_key(&signing_key, password).unwrap();
        assert_eq!(envelope.len(), ENVELOPE_LEN);
        assert!(is_encrypted(&envelope));

        let decrypted = decrypt_key(&envelope, password).unwrap();
        assert_eq!(&*decrypted, &signing_key);
    }

    #[test]
    fn wrong_password_fails() {
        let signing_key = [42u8; 32];
        let envelope = encrypt_key(&signing_key, b"correct").unwrap();

        let result = decrypt_key(&envelope, b"wrong");
        assert!(result.is_err());
    }

    #[test]
    fn empty_password_rejected() {
        let signing_key = [42u8; 32];
        let result = encrypt_key(&signing_key, b"");
        assert!(result.is_err(), "empty password must be rejected");
    }

    #[test]
    fn is_encrypted_detection() {
        let envelope = encrypt_key(&[0u8; 32], b"pw").unwrap();
        assert!(is_encrypted(&envelope));

        assert!(!is_encrypted(&[0u8; 32]));

        assert!(!is_encrypted(&[0u8; 3]));
    }

    #[test]
    fn invalid_envelope_length() {
        let result = decrypt_key(&[0u8; 50], b"pw");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_magic() {
        let mut bad = vec![0u8; ENVELOPE_LEN];
        bad[..4].copy_from_slice(b"XXXX");
        let result = decrypt_key(&bad, b"pw");
        assert!(result.is_err());
    }

    #[test]
    fn different_salts_produce_different_envelopes() {
        let key = [1u8; 32];
        let pw = b"same-password";
        let e1 = encrypt_key(&key, pw).unwrap();
        let e2 = encrypt_key(&key, pw).unwrap();

        assert_ne!(e1, e2);

        assert_eq!(
            &*decrypt_key(&e1, pw).unwrap(),
            &*decrypt_key(&e2, pw).unwrap()
        );
    }
}
