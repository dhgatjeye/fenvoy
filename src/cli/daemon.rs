use super::{identity_ops, output, sas, strings};
use crate::config::Config;
use crate::discovery::multicast::{DiscoveryConfig, DiscoveryService};
use crate::discovery::{DiscoveryEvent, capabilities};
use crate::error::{FenvoyError, Result};
use crate::peer::verification;
use crate::protocol::messages::Message;
use crate::protocol::record::SecureChannel;
use crate::transfer::AcceptFn;
use crate::transfer::dir_receiver;
use crate::transfer::progress::{ProgressTracker, format_bytes};
use crate::transfer::receiver;
use crate::transport::listener::{ConnectionListener, ListenerConfig};

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Semaphore;

const MAX_CONCURRENT_TRANSFERS: usize = 5;
const ACCEPT_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);

pub async fn run(args: &[String]) -> Result<()> {
    let mut config = Config::default();
    parse_args(args, &mut config)?;

    let identity = identity_ops::load_identity(&config)?;
    let fingerprint = identity.fingerprint();
    let resume_hmac_key = identity.derive_resume_key()?;
    let peers_hmac_key = identity.derive_peers_key()?;
    let identity = Arc::new(identity);

    output::print_banner(
        &config.peer_name,
        &fingerprint,
        config.listen_addr,
        &config.save_dir.display().to_string(),
    );
    output::print_wildcard_warning(config.listen_addr);
    println!();

    std::fs::create_dir_all(&config.save_dir).map_err(FenvoyError::Io)?;

    let _discovery = start_discovery(&config, &identity, &fingerprint)?;

    let listener = start_listener(&config, &identity).await?;
    let bound = listener.local_addr()?;
    println!("  Listening:   {bound}");
    println!();
    println!("{}", strings::WAITING_CONNECTIONS);
    println!();

    accept_loop(listener, config, *resume_hmac_key, *peers_hmac_key).await
}

fn parse_args(args: &[String], config: &mut Config) -> Result<()> {
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" | "-b" => {
                i += 1;
                let addr_str = args.get(i).ok_or_else(|| {
                    FenvoyError::InvalidMessage(strings::BIND_REQUIRES_ADDR.into())
                })?;
                config.listen_addr = addr_str.parse::<SocketAddr>().map_err(|e| {
                    FenvoyError::InvalidMessage(format!("invalid bind address '{addr_str}': {e}"))
                })?;
            }
            other => {
                return Err(FenvoyError::InvalidMessage(format!(
                    "unknown daemon flag: {other}"
                )));
            }
        }
        i += 1;
    }
    Ok(())
}

fn start_discovery(
    config: &Config,
    identity: &crate::crypto::identity::Identity,
    fingerprint: &[u8],
) -> Result<Option<DiscoveryService>> {
    if !config.discovery_enabled {
        println!("{}", strings::DISCOVERY_DISABLED);
        return Ok(None);
    }

    let disc_config = DiscoveryConfig {
        local_name: config.peer_name.clone(),
        tcp_port: config.listen_addr.port(),
        fingerprint: fingerprint.try_into().expect("fingerprint length"),
        capabilities: capabilities::BOTH,
        signing_key: identity.signing_key_bytes(),
        public_key: identity.public_key_bytes(),
    };

    let service = DiscoveryService::start(disc_config)?;
    let mut rx = service.subscribe();

    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(DiscoveryEvent::PeerDiscovered(peer)) => {
                    output::print_discovered(
                        &peer.name,
                        &peer.fingerprint,
                        &peer.addr.ip().to_string(),
                        peer.tcp_port,
                    );
                }
                Ok(DiscoveryEvent::PeerUpdated(_)) => {}
                Ok(DiscoveryEvent::PeerExpired { name, .. }) => {
                    output::print_expired(&name);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
            }
        }
    });

    println!("{}", strings::DISCOVERY_ENABLED);
    Ok(Some(service))
}

async fn start_listener(
    config: &Config,
    identity: &Arc<crate::crypto::identity::Identity>,
) -> Result<ConnectionListener> {
    let listener_config = ListenerConfig {
        bind_addr: config.listen_addr,
        local_name: config.peer_name.clone(),
        identity: identity.clone(),
    };
    ConnectionListener::bind(listener_config).await
}

fn is_fatal_accept_error(err: &FenvoyError) -> bool {
    if let FenvoyError::Io(io_err) = err {
        matches!(
            io_err.kind(),
            std::io::ErrorKind::OutOfMemory | std::io::ErrorKind::PermissionDenied
        ) || matches!(io_err.raw_os_error(), Some(24) | Some(23))
    } else {
        false
    }
}

async fn accept_loop(
    listener: ConnectionListener,
    config: Config,
    resume_hmac_key: [u8; 32],
    peers_hmac_key: [u8; 32],
) -> Result<()> {
    let transfer_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_TRANSFERS));

    loop {
        let accept = tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\n  Shutting down accept loop...");
                break;
            }
            result = listener.accept_one() => result,
        };

        match accept {
            Ok((hs_result, addr)) => {
                let sas = verification::format_sas(&hs_result.sas_bytes);
                let remote_fp =
                    crate::crypto::identity::fingerprint_of(&hs_result.remote_static_key);

                output::print_connection_header(addr, &hs_result.remote_name, &remote_fp, &sas);

                let already_verified = sas::is_tofu_verified(
                    &config.peers_path,
                    &peers_hmac_key,
                    &hs_result.remote_static_key,
                );

                let ctx = ConnectionContext {
                    save_dir: config.save_dir.clone(),
                    auto_accept: config.auto_accept,
                    max_file_size: config.max_file_size,
                    resume_hmac_key,
                    peers_hmac_key,
                    peers_path: config.peers_path.clone(),
                    remote_name: hs_result.remote_name.clone(),
                    remote_key: hs_result.remote_static_key,
                    addr,
                    already_verified,
                };

                let permit = transfer_semaphore
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| {
                        FenvoyError::HandshakeFailed("transfer semaphore closed".into())
                    })?;

                tokio::spawn(async move {
                    handle_connection(hs_result.channel, ctx).await;
                    drop(permit);
                });
            }
            Err(ref e) if is_fatal_accept_error(e) => {
                eprintln!("  Fatal accept error (resource exhaustion): {e}");
                eprintln!("  Backing off for {:?}…", ACCEPT_ERROR_BACKOFF);
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
            }
            Err(e) => {
                eprintln!("  Accept error: {e}");
            }
        }
    }

    Ok(())
}
struct ConnectionContext {
    save_dir: PathBuf,
    auto_accept: bool,
    max_file_size: u64,
    resume_hmac_key: [u8; 32],
    peers_hmac_key: [u8; 32],
    peers_path: PathBuf,
    remote_name: String,
    remote_key: [u8; 32],
    addr: SocketAddr,
    already_verified: bool,
}

async fn handle_connection<S>(mut channel: SecureChannel<S>, ctx: ConnectionContext)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if ctx.already_verified {
        output::print_box_msg(strings::TOFU_SKIP);
    }

    let sas_ok = match sas::exchange(&mut channel, ctx.already_verified).await {
        Ok(confirmed) => confirmed,
        Err(e) => {
            output::print_box_msg(&format!("SAS exchange error: {e}"));
            output::print_box_close();
            return;
        }
    };

    if ctx.already_verified && !sas_ok {
        output::print_box_msg(strings::SAS_REJECTED_REMOTE);
        output::print_box_close();
        return;
    }

    if !sas_ok {
        output::print_box_msg(strings::SAS_FAILED_ABORT);
        output::print_box_close();
        return;
    }

    sas::save_verified_peer(
        &ctx.peers_path,
        &ctx.peers_hmac_key,
        &ctx.remote_name,
        &ctx.remote_key,
        &ctx.addr,
    );

    let mut progress = ProgressTracker::new();

    let idle = std::time::Duration::from_secs(crate::protocol::IDLE_TIMEOUT_SECS);
    let (rt, payload) = match channel.recv_record_with_timeout(idle).await {
        Ok(v) => v,
        Err(e) => {
            output::print_box_msg(&format!("Transfer error: {e}"));
            output::print_box_close();
            return;
        }
    };

    let first_msg = match Message::decode(rt, &payload) {
        Ok(m) => m,
        Err(e) => {
            output::print_box_msg(&format!("Protocol error: {e}"));
            output::print_box_close();
            return;
        }
    };

    match first_msg {
        Message::FileRequest(request) => {
            handle_file_transfer(&mut channel, &ctx, &mut progress, request).await;
        }
        Message::BatchBegin(batch_begin) => {
            handle_dir_transfer(&mut channel, &ctx, &mut progress, batch_begin).await;
        }
        _ => {
            output::print_box_msg(strings::UNEXPECTED_MESSAGE);
            output::print_box_close();
        }
    }
}

async fn handle_file_transfer<S>(
    channel: &mut SecureChannel<S>,
    ctx: &ConnectionContext,
    progress: &mut ProgressTracker,
    request: crate::protocol::messages::FileRequest,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let accept_fn: Option<AcceptFn> = if ctx.auto_accept {
        None
    } else {
        Some(Box::new(|filename: &str, file_size: u64| {
            super::terminal::prompt_accept(filename, &format_bytes(file_size))
        }))
    };

    match receiver::receive_file_from_request(
        channel,
        &ctx.save_dir,
        progress,
        accept_fn,
        ctx.max_file_size,
        &ctx.resume_hmac_key,
        request,
    )
    .await
    {
        Ok(result) => {
            output::print_file_received(
                &result.file_name,
                result.total_bytes,
                result.elapsed.as_secs_f64(),
                result.verified,
                &result.path.display().to_string(),
            );
        }
        Err(e) => {
            output::print_box_msg(&format!("Transfer error: {e}"));
            output::print_box_close();
        }
    }
}

async fn handle_dir_transfer<S>(
    channel: &mut SecureChannel<S>,
    ctx: &ConnectionContext,
    progress: &mut ProgressTracker,
    batch_begin: crate::protocol::messages::BatchBegin,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    output::print_box_msg(&format!(
        "Directory: {} ({} files, {})",
        batch_begin.dir_name,
        batch_begin.file_count,
        format_bytes(batch_begin.total_bytes),
    ));

    match dir_receiver::receive_directory(
        channel,
        &ctx.save_dir,
        progress,
        batch_begin,
        ctx.max_file_size,
        &ctx.resume_hmac_key,
    )
    .await
    {
        Ok(result) => {
            output::print_dir_received(
                &result.dir_name,
                result.files_transferred,
                result.total_bytes,
                result.elapsed.as_secs_f64(),
                result.all_verified,
                &ctx.save_dir.display().to_string(),
            );
        }
        Err(e) => {
            output::print_box_msg(&format!("Transfer error: {e}"));
            output::print_box_close();
        }
    }
}
