pub mod paths;

use crate::protocol::DEFAULT_PORT;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub peer_name: String,
    pub listen_addr: SocketAddr,
    pub save_dir: PathBuf,
    pub identity_path: PathBuf,
    pub peers_path: PathBuf,
    pub chunk_size: u32,
    pub auto_accept: bool,
    pub discovery_enabled: bool,
    pub max_file_size: u64,
}

impl Default for Config {
    fn default() -> Self {
        let data_dir = paths::data_dir();
        let downloads_dir = paths::downloads_dir();

        Self {
            peer_name: whoami(),
            listen_addr: format!("0.0.0.0:{DEFAULT_PORT}").parse().unwrap(),
            save_dir: downloads_dir,
            identity_path: data_dir.join("identity.key"),
            peers_path: data_dir.join("known_peers.conf"),
            chunk_size: crate::protocol::DEFAULT_CHUNK_SIZE,
            auto_accept: false,
            discovery_enabled: true,
            max_file_size: 100 * 1024 * 1024 * 1024,
        }
    }
}

fn whoami() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "fenvoy-peer".to_string())
}

mod hostname {
    use std::ffi::OsString;

    pub fn get() -> std::io::Result<OsString> {
        #[cfg(windows)]
        {
            std::env::var_os("COMPUTERNAME")
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No Hostname"))
        }

        #[cfg(unix)]
        {
            let mut buf = vec![0u8; 256];
            let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut _, buf.len()) };
            if ret != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            Ok(OsString::from(
                String::from_utf8_lossy(&buf[..len]).into_owned(),
            ))
        }

        #[cfg(not(any(windows, unix)))]
        {
            Ok(OsString::from("fenvoy-peer"))
        }
    }
}
