use super::{identity_ops, output, sas, strings};
use crate::config::Config;
use crate::crypto::identity;
use crate::error::{FenvoyError, Result};
use crate::peer::store::PeerStore;
use crate::peer::verification;
use crate::protocol::handshake;
use crate::transfer::dir_sender;
use crate::transfer::progress::ProgressTracker;
use crate::transfer::sender;
use crate::transport::tcp;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub async fn run(args: &[String]) -> Result<()> {
    if args.len() < 2 {
        eprintln!("{}", strings::SEND_USAGE);
        return Err(FenvoyError::InvalidMessage(
            strings::SEND_MISSING_ARGS.into(),
        ));
    }

    let file_path = PathBuf::from(&args[0]);
    let target = &args[1];

    if !file_path.exists() {
        return Err(FenvoyError::FileNotFound(file_path));
    }

    let config = Config::default();
    let id = identity_ops::load_identity(&config)?;
    let peers_hmac_key = id.derive_peers_key()?;

    let addr = resolve_peer(target, &config.peers_path, &peers_hmac_key)?;

    println!("Connecting to {addr}...");
    let stream = tcp::connect(addr).await?;
    println!("Connected. Performing handshake...");

    let hs = handshake::initiate(stream, &config.peer_name, &id).await?;

    let sas_str = verification::format_sas(&hs.sas_bytes);
    let remote_fp = identity::fingerprint_of(&hs.remote_static_key);

    println!("{}", strings::HANDSHAKE_COMPLETE);
    println!("  Remote:      {}", hs.remote_name);
    println!("  Fingerprint: {}", identity::hex_encode(&remote_fp));
    println!("  SAS:         {sas_str}");
    println!();

    let already_verified =
        sas::is_tofu_verified(&config.peers_path, &peers_hmac_key, &hs.remote_static_key);
    let mut channel = hs.channel;

    if already_verified {
        println!("{}", strings::SEND_TOFU_SKIP);
    }

    let sas_ok = match sas::exchange(&mut channel, already_verified).await {
        Ok(v) => v,
        Err(e) => {
            return Err(e);
        }
    };

    if already_verified && !sas_ok {
        return Err(FenvoyError::SasRejected(
            strings::SEND_REMOTE_REJECTED_ERR.into(),
        ));
    }

    if !sas_ok {
        return Err(FenvoyError::SasRejected(strings::SEND_SAS_ABORT.into()));
    }

    let mut progress = ProgressTracker::new();

    if file_path.is_dir() {
        println!("Sending directory: {}", file_path.display());
        let result = dir_sender::send_directory(&mut channel, &file_path, &mut progress).await?;
        output::print_send_dir_result(
            &result.dir_name,
            result.files_transferred,
            result.total_bytes,
            result.elapsed.as_secs_f64(),
            result.all_verified,
        );
    } else {
        println!("Sending: {}", file_path.display());
        let result = sender::send_file(&mut channel, &file_path, &mut progress).await?;
        output::print_send_file_result(
            &result.file_name,
            result.total_bytes,
            result.elapsed.as_secs_f64(),
            result.verified,
        );
    }

    sas::save_verified_peer(
        &config.peers_path,
        &peers_hmac_key,
        &hs.remote_name,
        &hs.remote_static_key,
        &addr,
    );

    Ok(())
}

fn resolve_peer(target: &str, peers_path: &Path, peers_hmac_key: &[u8; 32]) -> Result<SocketAddr> {
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok(addr);
    }

    let mut store = PeerStore::with_hmac_key(peers_path.to_path_buf(), *peers_hmac_key);
    let _ = store.load();

    if let Some(peer) = store.get_by_name(target) {
        return peer
            .last_address
            .parse()
            .map_err(|_| FenvoyError::PeerNotFound(target.to_string()));
    }

    let with_port = if target.contains(':') {
        target.to_string()
    } else {
        format!("{target}:{}", crate::protocol::DEFAULT_PORT)
    };

    use std::net::ToSocketAddrs;
    with_port
        .to_socket_addrs()
        .map_err(|_| FenvoyError::PeerNotFound(target.to_string()))?
        .next()
        .ok_or_else(|| FenvoyError::PeerNotFound(target.to_string()))
}
