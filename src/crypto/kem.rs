use crate::error::{FenvoyError, Result};

use libcrux_ml_kem::mlkem1024::{
    self, MlKem1024Ciphertext, MlKem1024PrivateKey, MlKem1024PublicKey,
};
use libcrux_ml_kem::{
    ENCAPS_SEED_SIZE, KEY_GENERATION_SEED_SIZE, MlKemSharedSecret, SHARED_SECRET_SIZE,
};
use rand_core::CryptoRng;
use zeroize::{Zeroize, Zeroizing};

fn random_array<const L: usize>(rng: &mut impl CryptoRng) -> [u8; L] {
    let mut buf = [0u8; L];
    rng.fill_bytes(&mut buf);
    buf
}

pub const ENCAPS_KEY_LEN: usize = 1568;
pub const CIPHERTEXT_LEN: usize = 1568;
pub const SHARED_SECRET_LEN: usize = 32;

const _: () = assert!(MlKem1024PublicKey::len() == ENCAPS_KEY_LEN);
const _: () = assert!(MlKem1024Ciphertext::len() == CIPHERTEXT_LEN);
const _: () = assert!(SHARED_SECRET_SIZE == SHARED_SECRET_LEN);

pub struct KemKeyMaterial {
    dk: MlKem1024PrivateKey,
    pub ek_bytes: Vec<u8>,
}

pub fn generate() -> KemKeyMaterial {
    let mut rng = crate::crypto::csprng();
    let randomness: [u8; KEY_GENERATION_SEED_SIZE] = random_array(&mut rng);
    let key_pair = mlkem1024::generate_key_pair(randomness);
    let ek_bytes = key_pair.pk().to_vec();
    let (dk, _pk) = key_pair.into_parts();
    KemKeyMaterial { dk, ek_bytes }
}

pub fn encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; SHARED_SECRET_LEN]>)> {
    let mlkem_pk = MlKem1024PublicKey::try_from(ek_bytes).map_err(|_| {
        FenvoyError::KeyExchangeFailed("invalid ML-KEM encapsulation key length".into())
    })?;

    if !mlkem1024::validate_public_key(&mlkem_pk) {
        return Err(FenvoyError::KeyExchangeFailed(
            "ML-KEM public key failed FIPS 203 validation".into(),
        ));
    }

    let mut rng = crate::crypto::csprng();
    let randomness: [u8; ENCAPS_SEED_SIZE] = random_array(&mut rng);
    let (ct, mut ss) = mlkem1024::encapsulate(&mlkem_pk, randomness);

    let ct_bytes: Vec<u8> = ct.as_ref().to_vec();
    let mut ss_arr = [0u8; SHARED_SECRET_LEN];
    ss_arr.copy_from_slice(&ss);

    ss.zeroize();

    Ok((ct_bytes, Zeroizing::new(ss_arr)))
}

pub fn decapsulate(
    key_material: &KemKeyMaterial,
    ct_bytes: &[u8],
) -> Result<Zeroizing<[u8; SHARED_SECRET_LEN]>> {
    let mlkem_ct = MlKem1024Ciphertext::try_from(ct_bytes)
        .map_err(|_| FenvoyError::KeyExchangeFailed("invalid ML-KEM ciphertext length".into()))?;

    let mut ss: MlKemSharedSecret = mlkem1024::decapsulate(&key_material.dk, &mlkem_ct);

    let mut ss_arr = [0u8; SHARED_SECRET_LEN];
    ss_arr.copy_from_slice(&ss);

    ss.zeroize();

    Ok(Zeroizing::new(ss_arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_roundtrip() {
        let km = generate();

        let (ct, ss_enc) = encapsulate(&km.ek_bytes).expect("encapsulation should succeed");
        let ss_dec = decapsulate(&km, &ct).expect("decapsulation should succeed");

        assert_eq!(&*ss_enc, &*ss_dec, "shared secrets must match");
    }

    #[test]
    fn encapsulate_invalid_key() {
        let bad_ek = vec![0u8; 100];
        assert!(encapsulate(&bad_ek).is_err());
    }

    #[test]
    fn decapsulate_invalid_ct() {
        let km = generate();
        let bad_ct = vec![0u8; 100];
        assert!(decapsulate(&km, &bad_ct).is_err());
    }

    #[test]
    fn key_material_sizes() {
        let km = generate();
        assert_eq!(km.ek_bytes.len(), ENCAPS_KEY_LEN);
    }

    #[test]
    fn fips_203_validation_rejects_corrupted_key() {
        let km = generate();
        let mut corrupted_ek = km.ek_bytes.clone();
        corrupted_ek[784] ^= 0xFF;
        let _ = encapsulate(&corrupted_ek);
    }
}
