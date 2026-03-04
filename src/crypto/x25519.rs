use crate::error::{FenvoyError, Result};
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use zeroize::Zeroizing;

pub const PUBLIC_KEY_LEN: usize = 32;

const LOW_ORDER_POINTS: [[u8; 32]; 7] = [
    // u = 0  (neutral element)
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // u = 1  (order 4)
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // Order-8 point
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    // Order-8 point
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    // p − 1  (≡ −1 mod p, order 2)
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p  (≡ 0 mod p)
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p + 1  (≡ 1 mod p)
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

fn is_low_order_point(pk: &[u8; 32]) -> bool {
    let mut masked = *pk;
    masked[31] &= 0x7f;
    LOW_ORDER_POINTS.contains(&masked)
}

fn is_all_zero(bytes: &[u8; 32]) -> bool {
    bool::from(bytes.ct_eq(&[0u8; 32]))
}

pub struct X25519Keypair {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl X25519Keypair {
    pub fn generate() -> Self {
        let mut csprng = crate::crypto::csprng();
        let secret = EphemeralSecret::random_from_rng(&mut csprng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        *self.public.as_bytes()
    }

    pub fn diffie_hellman(
        self,
        remote_public: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<Zeroizing<[u8; 32]>> {
        if is_low_order_point(remote_public) {
            return Err(FenvoyError::KeyExchangeFailed(
                "rejected small-order X25519 public key".into(),
            ));
        }

        let remote_pk = PublicKey::from(*remote_public);
        let shared: SharedSecret = self.secret.diffie_hellman(&remote_pk);
        let bytes = *shared.as_bytes();

        if is_all_zero(&bytes) {
            return Err(FenvoyError::KeyExchangeFailed(
                "X25519 produced all-zero shared secret".into(),
            ));
        }

        Ok(Zeroizing::new(bytes))
    }
}

pub fn parse_public_key(bytes: &[u8]) -> Option<[u8; PUBLIC_KEY_LEN]> {
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_roundtrip() {
        let alice = X25519Keypair::generate();
        let bob = X25519Keypair::generate();

        let alice_pk = alice.public_key_bytes();
        let bob_pk = bob.public_key_bytes();

        let alice_ss = alice.diffie_hellman(&bob_pk).unwrap();
        let bob_ss = bob.diffie_hellman(&alice_pk).unwrap();

        assert_eq!(&*alice_ss, &*bob_ss, "shared secrets must match");
    }

    #[test]
    fn different_keypairs_produce_different_secrets() {
        let a = X25519Keypair::generate();
        let b = X25519Keypair::generate();
        let c = X25519Keypair::generate();

        let b_pk = b.public_key_bytes();

        let ss_ab = a.diffie_hellman(&b_pk).unwrap();
        let ss_cb = c.diffie_hellman(&b_pk).unwrap();

        assert_ne!(&*ss_ab, &*ss_cb);
    }

    #[test]
    fn reject_zero_point() {
        let kp = X25519Keypair::generate();
        let zero = [0u8; 32];
        assert!(kp.diffie_hellman(&zero).is_err());
    }

    #[test]
    fn reject_one_point() {
        let kp = X25519Keypair::generate();
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(kp.diffie_hellman(&one).is_err());
    }

    #[test]
    fn reject_order8_point() {
        let kp = X25519Keypair::generate();
        assert!(kp.diffie_hellman(&LOW_ORDER_POINTS[2]).is_err());
    }

    #[test]
    fn reject_p_minus_1() {
        let kp = X25519Keypair::generate();
        assert!(kp.diffie_hellman(&LOW_ORDER_POINTS[4]).is_err());
    }

    #[test]
    fn reject_p() {
        let kp = X25519Keypair::generate();
        assert!(kp.diffie_hellman(&LOW_ORDER_POINTS[5]).is_err());
    }

    #[test]
    fn reject_p_plus_1() {
        let kp = X25519Keypair::generate();
        assert!(kp.diffie_hellman(&LOW_ORDER_POINTS[6]).is_err());
    }

    #[test]
    fn reject_low_order_with_high_bit_set() {
        let kp = X25519Keypair::generate();
        let mut pk = [0u8; 32];
        pk[31] = 0x80;
        assert!(kp.diffie_hellman(&pk).is_err());
    }

    #[test]
    fn is_all_zero_true() {
        assert!(is_all_zero(&[0u8; 32]));
    }

    #[test]
    fn is_all_zero_false() {
        let mut buf = [0u8; 32];
        buf[15] = 1;
        assert!(!is_all_zero(&buf));
    }

    #[test]
    fn parse_public_key_valid() {
        let kp = X25519Keypair::generate();
        let bytes = kp.public_key_bytes();
        assert!(parse_public_key(&bytes).is_some());
    }

    #[test]
    fn parse_public_key_invalid_len() {
        let short = [0u8; 16];
        assert!(parse_public_key(&short).is_none());
    }
}
