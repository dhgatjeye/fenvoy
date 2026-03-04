use crate::crypto::keyfile;
use crate::error::{FenvoyError, Result};

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use std::fs;
use std::io::Write;
use std::path::Path;

pub const FINGERPRINT_LEN: usize = 8;
pub const SIGNATURE_LEN: usize = 64;

pub struct Identity {
    signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut csprng = crate::crypto::csprng();
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn fingerprint(&self) -> [u8; FINGERPRINT_LEN] {
        fingerprint_of(&self.public_key_bytes())
    }

    pub fn fingerprint_hex(&self) -> String {
        hex_encode(&self.fingerprint())
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        use ed25519_dalek::Signer;
        let sig: Signature = self.signing_key.sign(message);
        sig.to_bytes()
    }

    pub fn derive_resume_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        crate::crypto::kdf::derive_key(
            &self.signing_key.to_bytes(),
            b"fenvoy-resume-salt",
            b"fenvoy-resume-hmac-key-v1",
        )
    }

    pub fn derive_peers_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        crate::crypto::kdf::derive_key(
            &self.signing_key.to_bytes(),
            b"fenvoy-peers-salt",
            b"fenvoy-peers-hmac-key-v1",
        )
    }

    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let secret_bytes = self.signing_key.to_bytes();
        write_key_file(path, &secret_bytes)
    }

    pub fn save_encrypted(&self, path: &Path, password: &[u8]) -> Result<()> {
        let secret_bytes = self.signing_key.to_bytes();
        let envelope = keyfile::encrypt_key(&secret_bytes, password)?;
        write_key_file(path, &envelope)
    }

    pub fn load_from_file(path: &Path, password: Option<&[u8]>) -> Result<Self> {
        let bytes = fs::read(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => FenvoyError::ConfigNotFound(path.to_path_buf()),
            std::io::ErrorKind::PermissionDenied => {
                FenvoyError::PermissionDenied(path.to_path_buf())
            }
            _ => FenvoyError::Io(e),
        })?;

        let bytes = Zeroizing::new(bytes);

        if keyfile::is_encrypted(&bytes) {
            let pw = password.ok_or_else(|| {
                FenvoyError::AuthenticationFailed(
                    "identity key is encrypted; password required".into(),
                )
            })?;
            let secret = keyfile::decrypt_key(&bytes, pw)?;
            Ok(Self::from_secret_bytes(*secret))
        } else if bytes.len() == 32 {
            let mut secret_bytes = [0u8; 32];
            secret_bytes.copy_from_slice(&bytes);
            let identity = Self::from_secret_bytes(secret_bytes);
            let _ = Zeroizing::new(secret_bytes);
            Ok(identity)
        } else {
            Err(FenvoyError::ConfigParseError(format!(
                "identity key file has invalid length: {} (expected 32 or {})",
                bytes.len(),
                keyfile::ENVELOPE_LEN,
            )))
        }
    }

    pub fn is_encrypted_file(path: &Path) -> Result<bool> {
        let bytes = fs::read(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => FenvoyError::ConfigNotFound(path.to_path_buf()),
            _ => FenvoyError::Io(e),
        })?;
        Ok(keyfile::is_encrypted(&bytes))
    }

    pub fn load_or_generate(path: &Path, password: Option<&[u8]>) -> Result<Self> {
        if path.exists() {
            Self::load_from_file(path, password)
        } else {
            let id = Self::generate();
            if let Some(pw) = password {
                id.save_encrypted(path, pw)?;
            } else {
                id.save_to_file(path)?;
            }
            Ok(id)
        }
    }
}

pub fn verify_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<()> {
    let verifying_key = VerifyingKey::from_bytes(public_key).map_err(|e| {
        FenvoyError::AuthenticationFailed(format!("invalid Ed25519 public key: {e}"))
    })?;
    let sig = Signature::from_bytes(signature);
    verifying_key.verify_strict(message, &sig).map_err(|e| {
        FenvoyError::AuthenticationFailed(format!("Ed25519 signature verification failed: {e}"))
    })
}

pub fn fingerprint_of(public_key: &[u8; 32]) -> [u8; FINGERPRINT_LEN] {
    let hash = Sha256::digest(public_key);
    let mut fp = [0u8; FINGERPRINT_LEN];
    fp.copy_from_slice(&hash[..FINGERPRINT_LEN]);
    fp
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn write_key_file(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut f = fs::File::create(path)?;
    f.write_all(data)?;
    f.sync_all()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    #[cfg(windows)]
    {
        restrict_windows_acl(path);
    }

    Ok(())
}

#[cfg(windows)]
fn restrict_windows_acl(path: &Path) {
    let username = std::env::var("USERNAME").unwrap_or_default();
    if username.is_empty() {
        return;
    }

    let path_str = path.to_string_lossy();

    let _ = std::process::Command::new("icacls")
        .args([&*path_str, "/inheritance:r"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    let grant = format!("{username}:(F)");
    let _ = std::process::Command::new("icacls")
        .args([&*path_str, "/grant:r", &grant])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_identity() {
        let id = Identity::generate();
        let pk = id.public_key_bytes();
        assert_ne!(pk, [0u8; 32], "public key should not be all zeros");
    }

    #[test]
    fn fingerprint_deterministic() {
        let id = Identity::generate();
        let fp1 = id.fingerprint();
        let fp2 = id.fingerprint();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_hex_format() {
        let id = Identity::generate();
        let hex = id.fingerprint_hex();
        assert_eq!(hex.len(), FINGERPRINT_LEN * 2);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join("fenvoy_test_identity_ed25519");
        let path = dir.join("test_identity.key");

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);

        let id1 = Identity::generate();
        id1.save_to_file(&path).unwrap();

        let id2 = Identity::load_from_file(&path, None).unwrap();

        assert_eq!(id1.public_key_bytes(), id2.public_key_bytes());
        assert_eq!(id1.fingerprint(), id2.fingerprint());

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn save_encrypted_and_load_roundtrip() {
        let dir = std::env::temp_dir().join("fenvoy_test_identity_encrypted");
        let path = dir.join("test_identity_enc.key");

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);

        let password = b"strong-password-42";
        let id1 = Identity::generate();
        id1.save_encrypted(&path, password).unwrap();

        assert!(Identity::is_encrypted_file(&path).unwrap());

        let id2 = Identity::load_from_file(&path, Some(password)).unwrap();
        assert_eq!(id1.public_key_bytes(), id2.public_key_bytes());

        let result = Identity::load_from_file(&path, Some(b"wrong"));
        assert!(result.is_err());

        let result = Identity::load_from_file(&path, None);
        assert!(result.is_err());

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn load_or_generate_encrypted() {
        let dir = std::env::temp_dir().join("fenvoy_test_lor_encrypted");
        let path = dir.join("test_lor_enc.key");

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);

        let password = b"lor-password";

        let id1 = Identity::load_or_generate(&path, Some(password)).unwrap();
        assert!(path.exists());
        assert!(Identity::is_encrypted_file(&path).unwrap());

        let id2 = Identity::load_or_generate(&path, Some(password)).unwrap();
        assert_eq!(id1.public_key_bytes(), id2.public_key_bytes());

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn load_missing_file() {
        let result = Identity::load_from_file(Path::new("/nonexistent/path/key"), None);
        assert!(result.is_err());
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "deadbeef");
        let decoded = hex_decode(&hex).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn sign_and_verify() {
        let id = Identity::generate();
        let message = b"hello fenvoy";
        let sig = id.sign(message);

        verify_signature(&id.public_key_bytes(), message, &sig).unwrap();
    }

    #[test]
    fn verify_wrong_key_fails() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let message = b"hello fenvoy";
        let sig = id1.sign(message);

        let result = verify_signature(&id2.public_key_bytes(), message, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_wrong_message_fails() {
        let id = Identity::generate();
        let sig = id.sign(b"original message");

        let result = verify_signature(&id.public_key_bytes(), b"different message", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn from_secret_bytes_deterministic() {
        let bytes = [42u8; 32];
        let id1 = Identity::from_secret_bytes(bytes);
        let id2 = Identity::from_secret_bytes(bytes);
        assert_eq!(id1.public_key_bytes(), id2.public_key_bytes());

        let sig1 = id1.sign(b"test");
        let sig2 = id2.sign(b"test");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn hex_decode_invalid() {
        assert!(hex_decode("xyz").is_none());
        assert!(hex_decode("0").is_none());
    }
}
