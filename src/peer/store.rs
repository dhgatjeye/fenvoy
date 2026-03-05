use crate::crypto::identity::{fingerprint_of, hex_decode, hex_encode};
use crate::error::{FenvoyError, Result};
use subtle::ConstantTimeEq;

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

fn lock_path(store_path: &Path) -> PathBuf {
    let mut p = store_path.as_os_str().to_owned();
    p.push(".lock");
    PathBuf::from(p)
}

struct FileLockGuard {
    _file: std::fs::File,
}

impl FileLockGuard {
    fn exclusive(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)?;

        platform_lock_exclusive(&file)?;

        Ok(Self { _file: file })
    }
}

#[cfg(windows)]
fn platform_lock_exclusive(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LockFileEx};
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let handle = file.as_raw_handle();
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };

    let ok = unsafe { LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &mut overlapped) };

    if ok != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn platform_lock_exclusive(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let fd = file.as_raw_fd();

    let lock = libc::flock {
        l_type: libc::F_WRLCK as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };

    #[cfg(target_os = "linux")]
    let cmd = libc::F_OFD_SETLKW;
    #[cfg(not(target_os = "linux"))]
    let cmd = libc::F_SETLKW;

    let result = unsafe { libc::fcntl(fd, cmd, &lock) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(windows, unix)))]
fn platform_lock_exclusive(_file: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

fn compute_hmac(key: &[u8; 32], content: &str) -> String {
    blake3::keyed_hash(key, content.as_bytes())
        .to_hex()
        .to_string()
}

#[derive(Debug, Clone)]
pub struct KnownPeer {
    pub name: String,
    pub public_key: [u8; 32],
    pub fingerprint: [u8; 8],
    pub first_seen: u64,
    pub last_seen: u64,
    pub verified: bool,
    pub last_address: String,
}

pub struct PeerStore {
    peers: HashMap<[u8; 32], KnownPeer>,
    path: PathBuf,
    hmac_key: Option<[u8; 32]>,
}

impl PeerStore {
    pub fn new(path: PathBuf) -> Self {
        Self {
            peers: HashMap::new(),
            path,
            hmac_key: None,
        }
    }

    pub fn with_hmac_key(path: PathBuf, key: [u8; 32]) -> Self {
        Self {
            peers: HashMap::new(),
            path,
            hmac_key: Some(key),
        }
    }

    pub fn load(&mut self) -> Result<()> {
        if !self.path.exists() {
            return Ok(());
        }

        let full_content = std::fs::read_to_string(&self.path).map_err(FenvoyError::Io)?;

        let content = if let Some(ref key) = self.hmac_key {
            if let Some(hmac_line_start) = full_content.rfind("\nhmac = ") {
                let content_before_hmac = &full_content[..hmac_line_start + 1];
                let hmac_line = full_content[hmac_line_start + 1..].trim();
                let stored_hmac = hmac_line
                    .strip_prefix("hmac = ")
                    .ok_or_else(|| {
                        FenvoyError::ConfigParseError("malformed hmac line in peer store".into())
                    })?
                    .trim();

                let expected = compute_hmac(key, content_before_hmac);
                if bool::from(stored_hmac.as_bytes().ct_ne(expected.as_bytes())) {
                    return Err(FenvoyError::ConfigParseError(
                        "peer store integrity check failed (HMAC mismatch)".into(),
                    ));
                }
                content_before_hmac.to_string()
            } else {
                return Err(FenvoyError::ConfigParseError(
                    "peer store missing HMAC (possible tampering or legacy file)".into(),
                ));
            }
        } else {
            full_content
        };

        self.parse_peers(&content);
        Ok(())
    }

    fn parse_peers(&mut self, content: &str) {
        self.peers.clear();

        let mut current: Option<PartialPeer> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line == "[peer]" {
                if let Some(partial) = current.take() {
                    if let Some(peer) = partial.build() {
                        self.peers.insert(peer.public_key, peer);
                    }
                }
                current = Some(PartialPeer::default());
                continue;
            }

            if let Some(ref mut partial) = current {
                if let Some((key, value)) = line.split_once('=') {
                    let key = key.trim();
                    let value = value.trim();
                    match key {
                        "name" => partial.name = Some(value.to_string()),
                        "public_key" => partial.public_key_hex = Some(value.to_string()),
                        "fingerprint" => partial.fingerprint_hex = Some(value.to_string()),
                        "first_seen" => partial.first_seen = value.parse().ok(),
                        "last_seen" => partial.last_seen = value.parse().ok(),
                        "verified" => partial.verified = Some(value == "true"),
                        "last_address" => partial.last_address = Some(value.to_string()),
                        _ => {}
                    }
                }
            }
        }

        if let Some(partial) = current {
            if let Some(peer) = partial.build() {
                self.peers.insert(peer.public_key, peer);
            }
        }
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(FenvoyError::Io)?;
        }

        let _lock = FileLockGuard::exclusive(&lock_path(&self.path)).map_err(FenvoyError::Io)?;

        let mut content = String::from("# Fenvoy Known Peers Database\n\n");

        for peer in self.peers.values() {
            content.push_str("[peer]\n");
            content.push_str(&format!("name = {}\n", peer.name));
            content.push_str(&format!("public_key = {}\n", hex_encode(&peer.public_key)));
            content.push_str(&format!(
                "fingerprint = {}\n",
                hex_encode(&peer.fingerprint)
            ));
            content.push_str(&format!("first_seen = {}\n", peer.first_seen));
            content.push_str(&format!("last_seen = {}\n", peer.last_seen));
            content.push_str(&format!("verified = {}\n", peer.verified));
            content.push_str(&format!("last_address = {}\n", peer.last_address));
            content.push('\n');
        }

        if let Some(ref key) = self.hmac_key {
            let hmac_hex = compute_hmac(key, &content);
            content.push_str(&format!("hmac = {hmac_hex}\n"));
        }

        let tmp_path = self.path.with_extension("tmp");
        let mut f = std::fs::File::create(&tmp_path).map_err(FenvoyError::Io)?;
        f.write_all(content.as_bytes()).map_err(FenvoyError::Io)?;
        f.sync_all().map_err(FenvoyError::Io)?;
        drop(f);

        std::fs::rename(&tmp_path, &self.path).map_err(FenvoyError::Io)?;

        Ok(())
    }

    pub fn locked_update<F>(&mut self, f: F) -> Result<()>
    where
        F: FnOnce(&mut Self) -> Result<()>,
    {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(FenvoyError::Io)?;
        }

        let _lock = FileLockGuard::exclusive(&lock_path(&self.path)).map_err(FenvoyError::Io)?;

        self.load_inner()?;

        f(self)?;

        self.save_inner()
    }

    fn load_inner(&mut self) -> Result<()> {
        if !self.path.exists() {
            return Ok(());
        }

        let full_content = std::fs::read_to_string(&self.path).map_err(FenvoyError::Io)?;

        let content = if let Some(ref key) = self.hmac_key {
            if let Some(hmac_line_start) = full_content.rfind("\nhmac = ") {
                let content_before_hmac = &full_content[..hmac_line_start + 1];
                let hmac_line = full_content[hmac_line_start + 1..].trim();
                let stored_hmac = hmac_line
                    .strip_prefix("hmac = ")
                    .ok_or_else(|| {
                        FenvoyError::ConfigParseError("malformed hmac line in peer store".into())
                    })?
                    .trim();

                let expected = compute_hmac(key, content_before_hmac);
                if bool::from(stored_hmac.as_bytes().ct_ne(expected.as_bytes())) {
                    return Err(FenvoyError::ConfigParseError(
                        "peer store integrity check failed (HMAC mismatch)".into(),
                    ));
                }
                content_before_hmac.to_string()
            } else {
                return Err(FenvoyError::ConfigParseError(
                    "peer store missing HMAC (possible tampering or legacy file)".into(),
                ));
            }
        } else {
            full_content
        };

        self.parse_peers(&content);
        Ok(())
    }

    fn save_inner(&self) -> Result<()> {
        let mut content = String::from("# Fenvoy Known Peers Database\n\n");

        for peer in self.peers.values() {
            content.push_str("[peer]\n");
            content.push_str(&format!("name = {}\n", peer.name));
            content.push_str(&format!("public_key = {}\n", hex_encode(&peer.public_key)));
            content.push_str(&format!(
                "fingerprint = {}\n",
                hex_encode(&peer.fingerprint)
            ));
            content.push_str(&format!("first_seen = {}\n", peer.first_seen));
            content.push_str(&format!("last_seen = {}\n", peer.last_seen));
            content.push_str(&format!("verified = {}\n", peer.verified));
            content.push_str(&format!("last_address = {}\n", peer.last_address));
            content.push('\n');
        }

        if let Some(ref key) = self.hmac_key {
            let hmac_hex = compute_hmac(key, &content);
            content.push_str(&format!("hmac = {hmac_hex}\n"));
        }

        let tmp_path = self.path.with_extension("tmp");
        let mut f = std::fs::File::create(&tmp_path).map_err(FenvoyError::Io)?;
        f.write_all(content.as_bytes()).map_err(FenvoyError::Io)?;
        f.sync_all().map_err(FenvoyError::Io)?;
        drop(f);

        std::fs::rename(&tmp_path, &self.path).map_err(FenvoyError::Io)?;

        Ok(())
    }

    pub fn get_by_public_key(&self, pk: &[u8; 32]) -> Option<&KnownPeer> {
        self.peers.get(pk)
    }

    pub fn get_by_fingerprint(&self, fp: &[u8; 8]) -> Option<&KnownPeer> {
        self.peers.values().find(|p| &p.fingerprint == fp)
    }

    pub fn get_by_name(&self, name: &str) -> Option<&KnownPeer> {
        self.peers.values().find(|p| p.name == name)
    }

    pub fn upsert(
        &mut self,
        name: &str,
        public_key: &[u8; 32],
        address: &str,
        verified: bool,
    ) -> Result<()> {
        let fp = fingerprint_of(public_key);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Some(existing) = self.peers.get_mut(public_key) {
            existing.last_seen = now;
            existing.last_address = address.to_string();
            if verified && !existing.verified {
                existing.verified = true;
            }
        } else {
            if let Some(old) = self.peers.values().find(|p| p.name == name) {
                if old.public_key != *public_key {
                    return Err(FenvoyError::PeerKeyChanged {
                        name: name.to_string(),
                        expected_fingerprint: hex_encode(&old.fingerprint),
                        actual_fingerprint: hex_encode(&fp),
                    });
                }
            }

            self.peers.insert(
                *public_key,
                KnownPeer {
                    name: name.to_string(),
                    public_key: *public_key,
                    fingerprint: fp,
                    first_seen: now,
                    last_seen: now,
                    verified,
                    last_address: address.to_string(),
                },
            );
        }

        Ok(())
    }

    pub fn set_verified(&mut self, name: &str, verified: bool) -> bool {
        let pk = self
            .peers
            .iter()
            .find(|(_, p)| p.name == name)
            .map(|(pk, _)| *pk);

        if let Some(pk) = pk {
            if let Some(peer) = self.peers.get_mut(&pk) {
                peer.verified = verified;
                return true;
            }
        }
        false
    }

    pub fn remove(&mut self, name: &str) -> bool {
        let pk = self
            .peers
            .iter()
            .find(|(_, p)| p.name == name)
            .map(|(pk, _)| *pk);

        if let Some(pk) = pk {
            self.peers.remove(&pk);
            true
        } else {
            false
        }
    }

    pub fn list(&self) -> Vec<&KnownPeer> {
        self.peers.values().collect()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

#[derive(Default)]
struct PartialPeer {
    name: Option<String>,
    public_key_hex: Option<String>,
    fingerprint_hex: Option<String>,
    first_seen: Option<u64>,
    last_seen: Option<u64>,
    verified: Option<bool>,
    last_address: Option<String>,
}

impl PartialPeer {
    fn build(self) -> Option<KnownPeer> {
        let name = self.name?;
        let pk_hex = self.public_key_hex?;
        let pk_bytes = hex_decode(&pk_hex)?;
        if pk_bytes.len() != 32 {
            return None;
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&pk_bytes);

        let fingerprint = fingerprint_of(&public_key);

        Some(KnownPeer {
            name,
            public_key,
            fingerprint,
            first_seen: self.first_seen.unwrap_or(0),
            last_seen: self.last_seen.unwrap_or(0),
            verified: self.verified.unwrap_or(false),
            last_address: self.last_address.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_HMAC_KEY: [u8; 32] = [0x42u8; 32];

    #[test]
    fn add_and_lookup() {
        let dir = std::env::temp_dir();
        let path = dir.join("fenvoy_test_peers.conf");
        let mut store = PeerStore::new(path.clone());

        let pk = [42u8; 32];
        store
            .upsert("Alice", &pk, "192.168.1.1:19527", true)
            .unwrap();

        let fp = fingerprint_of(&pk);
        let peer = store.get_by_fingerprint(&fp).unwrap();
        assert_eq!(peer.name, "Alice");
        assert!(peer.verified);

        let peer2 = store.get_by_name("Alice").unwrap();
        assert_eq!(peer2.public_key, pk);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join("fenvoy_test_peers_rt.conf");
        let _ = std::fs::remove_file(&path);

        let mut store = PeerStore::new(path.clone());
        store
            .upsert("Bob", &[1u8; 32], "10.0.0.1:19527", false)
            .unwrap();
        store.save().unwrap();

        let mut store = PeerStore::new(path.clone());
        store.load().unwrap();
        assert_eq!(store.len(), 1);
        let peer = store.get_by_name("Bob").unwrap();
        assert_eq!(peer.public_key, [1u8; 32]);
        assert!(!peer.verified);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(lock_path(&path));
    }

    #[test]
    fn save_and_load_with_hmac() {
        let dir = std::env::temp_dir();
        let path = dir.join("fenvoy_test_peers_hmac.conf");
        let _ = std::fs::remove_file(&path);

        let mut store = PeerStore::with_hmac_key(path.clone(), TEST_HMAC_KEY);
        store
            .upsert("Carol", &[7u8; 32], "10.0.0.7:19527", true)
            .unwrap();
        store.save().unwrap();

        let mut store = PeerStore::with_hmac_key(path.clone(), TEST_HMAC_KEY);
        store.load().unwrap();
        assert_eq!(store.len(), 1);
        let peer = store.get_by_name("Carol").unwrap();
        assert!(peer.verified);

        let wrong_key = [0x99u8; 32];
        let mut store = PeerStore::with_hmac_key(path.clone(), wrong_key);
        assert!(store.load().is_err());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(lock_path(&path));
    }

    #[test]
    fn tampered_peer_store_rejected() {
        let dir = std::env::temp_dir();
        let path = dir.join("fenvoy_test_peers_tamper.conf");
        let _ = std::fs::remove_file(&path);

        let mut store = PeerStore::with_hmac_key(path.clone(), TEST_HMAC_KEY);
        store
            .upsert("Dave", &[88u8; 32], "10.0.0.88:19527", false)
            .unwrap();
        store.save().unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replace("verified = false", "verified = true");
        std::fs::write(&path, tampered).unwrap();

        let mut store = PeerStore::with_hmac_key(path.clone(), TEST_HMAC_KEY);
        assert!(store.load().is_err());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(lock_path(&path));
    }

    #[test]
    fn locked_update_roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join("fenvoy_test_peers_locked.conf");
        let _ = std::fs::remove_file(&path);

        let mut store = PeerStore::with_hmac_key(path.clone(), TEST_HMAC_KEY);
        store
            .upsert("Frank", &[55u8; 32], "10.0.0.55:19527", false)
            .unwrap();
        store.save().unwrap();

        let mut store = PeerStore::with_hmac_key(path.clone(), TEST_HMAC_KEY);
        store
            .locked_update(|s| s.upsert("Grace", &[66u8; 32], "10.0.0.66:19527", true))
            .unwrap();

        let mut store = PeerStore::with_hmac_key(path.clone(), TEST_HMAC_KEY);
        store.load().unwrap();
        assert_eq!(store.len(), 2);
        assert!(store.get_by_name("Frank").is_some());
        assert!(store.get_by_name("Grace").is_some());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(lock_path(&path));
    }

    #[test]
    fn remove_peer() {
        let dir = std::env::temp_dir();
        let path = dir.join("fenvoy_test_peers_rm.conf");

        let mut store = PeerStore::new(path.clone());
        store
            .upsert("Eve", &[99u8; 32], "1.2.3.4:19527", false)
            .unwrap();
        assert_eq!(store.len(), 1);

        assert!(store.remove("Eve"));
        assert_eq!(store.len(), 0);
        assert!(!store.remove("Eve"));

        let _ = std::fs::remove_file(&path);
    }
}
