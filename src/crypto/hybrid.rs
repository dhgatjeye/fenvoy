use crate::crypto::{kdf, kem, x25519};
use crate::error::Result;

use zeroize::Zeroizing;

pub struct InitiatorKeyMaterial {
    pub x25519_kp: x25519::X25519Keypair,
    pub kem_material: kem::KemKeyMaterial,
}

pub fn initiator_keygen() -> InitiatorKeyMaterial {
    InitiatorKeyMaterial {
        x25519_kp: x25519::X25519Keypair::generate(),
        kem_material: kem::generate(),
    }
}

pub fn combine_secrets(
    x25519_ss: &[u8; 32],
    kem_ss: &[u8; 32],
    transcript_hash: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(x25519_ss);
    ikm[32..].copy_from_slice(kem_ss);

    kdf::derive_key(&*ikm, transcript_hash, b"fenvoy-hybrid-v1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combine_secrets_deterministic() {
        let ss1 = [1u8; 32];
        let ss2 = [2u8; 32];
        let th = b"transcript";

        let c1 = combine_secrets(&ss1, &ss2, th).unwrap();
        let c2 = combine_secrets(&ss1, &ss2, th).unwrap();

        assert_eq!(&*c1, &*c2);
    }

    #[test]
    fn combine_secrets_different_inputs() {
        let ss1 = [1u8; 32];
        let ss2 = [2u8; 32];
        let ss3 = [3u8; 32];

        let c1 = combine_secrets(&ss1, &ss2, b"t").unwrap();
        let c2 = combine_secrets(&ss1, &ss3, b"t").unwrap();

        assert_ne!(&*c1, &*c2);
    }
}
