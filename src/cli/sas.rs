use super::strings;
use super::terminal;
use crate::error::{FenvoyError, Result};
use crate::peer::store::PeerStore;
use crate::protocol::messages::{Message, SasConfirm};
use crate::protocol::record::SecureChannel;

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

const SAS_TIMEOUT: Duration = Duration::from_secs(60);

pub fn is_tofu_verified(
    peers_path: &Path,
    peers_hmac_key: &[u8; 32],
    remote_static_key: &[u8; 32],
) -> bool {
    let mut store = PeerStore::with_hmac_key(peers_path.to_path_buf(), *peers_hmac_key);
    store.load().is_ok()
        && store
            .get_by_public_key(remote_static_key)
            .is_some_and(|p| p.verified)
}

pub fn save_verified_peer(
    peers_path: &Path,
    peers_hmac_key: &[u8; 32],
    remote_name: &str,
    remote_key: &[u8; 32],
    addr: &SocketAddr,
) {
    let mut store = PeerStore::with_hmac_key(peers_path.to_path_buf(), *peers_hmac_key);
    let _ = store.locked_update(|s| s.upsert(remote_name, remote_key, &addr.to_string(), true));
}

pub async fn exchange<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    channel: &mut SecureChannel<S>,
    already_verified: bool,
) -> Result<bool> {
    if already_verified {
        return exchange_auto_confirm(channel).await;
    }
    exchange_interactive(channel).await
}

async fn exchange_auto_confirm<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    channel: &mut SecureChannel<S>,
) -> Result<bool> {
    let msg = Message::SasConfirm(SasConfirm { confirmed: true });
    let (rt, payload) = msg.encode().expect("SasConfirm encoding is infallible");
    channel.send_record(rt, &payload).await?;

    let (remote_rt, remote_payload) = channel.recv_record_with_timeout(SAS_TIMEOUT).await?;
    match Message::decode(remote_rt, &remote_payload)? {
        Message::SasConfirm(sc) if sc.confirmed => Ok(true),
        Message::SasConfirm(_) => Ok(false),
        _ => Err(FenvoyError::InvalidMessage(
            strings::EXPECT_SAS_CONFIRM.into(),
        )),
    }
}

async fn exchange_interactive<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    channel: &mut SecureChannel<S>,
) -> Result<bool> {
    let local_confirmed = tokio::task::spawn_blocking(|| {
        use std::io::Write;
        print!("{}", strings::PROMPT_YES_NO);
        std::io::stdout().flush().ok();
        terminal::prompt_yes_no()
    })
    .await
    .unwrap_or(false);

    let msg = Message::SasConfirm(SasConfirm {
        confirmed: local_confirmed,
    });
    let (rt, payload) = msg.encode()?;
    channel.send_record(rt, &payload).await?;

    let (remote_rt, remote_payload) = channel.recv_record_with_timeout(SAS_TIMEOUT).await?;
    let remote_confirmed = match Message::decode(remote_rt, &remote_payload)? {
        Message::SasConfirm(sc) => sc.confirmed,
        _ => {
            return Err(FenvoyError::InvalidMessage(
                strings::EXPECT_SAS_CONFIRM.into(),
            ));
        }
    };

    if !local_confirmed {
        println!("{}", strings::SAS_REJECTED_LOCAL);
        return Ok(false);
    }
    if !remote_confirmed {
        println!("{}", strings::SAS_REJECTED_BY_REMOTE);
        return Ok(false);
    }

    println!("{}", strings::SAS_VERIFIED_BOTH);
    Ok(true)
}
