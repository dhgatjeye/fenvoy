use getrandom::SysRng;
use getrandom::rand_core::UnwrapErr;
use rand_core::CryptoRng;

pub mod aead;
pub mod hybrid;
pub mod identity;
pub mod kdf;
pub mod kem;
pub mod keyfile;
pub mod x25519;

pub fn csprng() -> impl CryptoRng {
    UnwrapErr(SysRng)
}
