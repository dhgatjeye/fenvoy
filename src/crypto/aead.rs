use crate::error::{FenvoyError, Result};

use chacha20poly1305::aead::{Aead as AeadTrait, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const MAX_NONCE: u64 = u64::MAX;
pub const REKEY_INTERVAL: u64 = 1 << 32;

const _: () = assert!(
    REKEY_INTERVAL.is_power_of_two(),
    "REKEY_INTERVAL must be a power of two",
);

const _: () = assert!(
    size_of::<ChaCha20Poly1305>() <= 256,
    "Review zeroize_flat_type safety",
);

pub struct CipherState {
    cipher: ChaCha20Poly1305,
    key: Zeroizing<[u8; KEY_LEN]>,
    counter: u64,
}

impl CipherState {
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        let cipher = ChaCha20Poly1305::new(&Key::from(*key));

        Self {
            cipher,
            key: Zeroizing::new(*key),
            counter: 0,
        }
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }

    fn current_nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[4..].copy_from_slice(&self.counter.to_le_bytes());
        nonce
    }

    fn rekey(&mut self) {
        let counter_bytes = self.counter.to_le_bytes();
        let hk = Hkdf::<Sha256>::new(Some(&counter_bytes), &self.key[..]);
        let mut new_key = Zeroizing::new([0u8; KEY_LEN]);
        hk.expand(b"fenvoy-rekey", &mut *new_key)
            .expect("HKDF expand for 32 bytes cannot fail");

        unsafe { zeroize::zeroize_flat_type(&mut self.cipher) };

        self.cipher = ChaCha20Poly1305::new(&Key::from(*new_key));
        debug_assert_ne!(
            &self.key[..],
            &new_key[..],
            "rekey produced identical key material KDF failure"
        );

        self.key = new_key;
    }

    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if self.counter == MAX_NONCE {
            return Err(FenvoyError::NonceError("nonce counter exhausted".into()));
        }

        let nonce = self.current_nonce();
        let nonce_ga = Nonce::from(nonce);

        let payload = chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext = self
            .cipher
            .encrypt(&nonce_ga, payload)
            .map_err(|_| FenvoyError::EncryptionFailed("AEAD encryption failed".into()))?;

        self.counter = self
            .counter
            .checked_add(1)
            .expect("nonce counter overflow");

        if self.counter % REKEY_INTERVAL == 0 {
            self.rekey();
        }

        Ok(ciphertext)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if self.counter == MAX_NONCE {
            return Err(FenvoyError::NonceError("nonce counter exhausted".into()));
        }

        let nonce = self.current_nonce();
        let nonce_ga = Nonce::from(nonce);

        let payload = chacha20poly1305::aead::Payload {
            msg: ciphertext,
            aad,
        };

        let plaintext = self
            .cipher
            .decrypt(&nonce_ga, payload)
            .map_err(|_| FenvoyError::DecryptionFailed)?;

        self.counter = self
            .counter
            .checked_add(1)
            .expect("nonce counter overflow");

        if self.counter % REKEY_INTERVAL == 0 {
            self.rekey();
        }

        Ok(plaintext)
    }
}

#[cfg(test)]
impl CipherState {
    fn set_counter_for_test(&mut self, counter: u64) {
        self.counter = counter;
    }
}

impl Drop for CipherState {
    fn drop(&mut self) {
        self.counter = 0;

        unsafe { zeroize::zeroize_flat_type(&mut self.cipher) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; KEY_LEN] {
        let mut key = [0u8; KEY_LEN];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_key();
        let mut enc = CipherState::new(&key);
        let mut dec = CipherState::new(&key);

        let plaintext = b"Hello, fenvoy!";
        let aad = b"record-header";

        let ct = enc.encrypt(plaintext, aad).unwrap();
        let pt = dec.decrypt(&ct, aad).unwrap();

        assert_eq!(pt, plaintext);
    }

    #[test]
    fn counter_increments() {
        let key = test_key();
        let mut enc = CipherState::new(&key);

        assert_eq!(enc.counter(), 0);
        enc.encrypt(b"msg1", b"").unwrap();
        assert_eq!(enc.counter(), 1);
        enc.encrypt(b"msg2", b"").unwrap();
        assert_eq!(enc.counter(), 2);
    }

    #[test]
    fn wrong_aad_fails() {
        let key = test_key();
        let mut enc = CipherState::new(&key);
        let mut dec = CipherState::new(&key);

        let ct = enc.encrypt(b"data", b"correct-aad").unwrap();
        let result = dec.decrypt(&ct, b"wrong-aad");

        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = test_key();
        let mut enc = CipherState::new(&key);
        let mut dec = CipherState::new(&key);

        let mut ct = enc.encrypt(b"data", b"aad").unwrap();
        ct[0] ^= 0xFF;
        let result = dec.decrypt(&ct, b"aad");

        assert!(result.is_err());
    }

    #[test]
    fn different_keys_fail() {
        let key1 = test_key();
        let mut key2 = test_key();
        key2[0] = 0xFF;

        let mut enc = CipherState::new(&key1);
        let mut dec = CipherState::new(&key2);

        let ct = enc.encrypt(b"data", b"aad").unwrap();
        let result = dec.decrypt(&ct, b"aad");

        assert!(result.is_err());
    }

    #[test]
    fn multiple_messages_sequential() {
        let key = test_key();
        let mut enc = CipherState::new(&key);
        let mut dec = CipherState::new(&key);

        for i in 0..100 {
            let msg = format!("message {i}");
            let ct = enc.encrypt(msg.as_bytes(), b"").unwrap();
            let pt = dec.decrypt(&ct, b"").unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn rekey_at_interval_boundary() {
        let key = test_key();
        let mut enc = CipherState::new(&key);
        let mut dec = CipherState::new(&key);

        let before_boundary = REKEY_INTERVAL - 2;
        enc.set_counter_for_test(before_boundary);
        dec.set_counter_for_test(before_boundary);

        let mut messages = Vec::new();
        for i in 0..4 {
            let msg = format!("rekey-boundary-msg-{i}");
            let ct = enc.encrypt(msg.as_bytes(), b"aad").unwrap();
            messages.push((msg, ct));
        }

        for (expected, ct) in &messages {
            let pt = dec.decrypt(ct, b"aad").unwrap();
            assert_eq!(pt, expected.as_bytes());
        }

        assert_eq!(enc.counter(), REKEY_INTERVAL + 2);
        assert_eq!(dec.counter(), REKEY_INTERVAL + 2);
    }

    #[test]
    fn rekey_changes_internal_key() {
        let key = test_key();
        let mut cs = CipherState::new(&key);

        let key_before = *cs.key;

        cs.set_counter_for_test(REKEY_INTERVAL - 1);
        cs.encrypt(b"trigger-rekey", b"").unwrap();

        assert_ne!(&key_before[..], &cs.key[..]);
    }
}
