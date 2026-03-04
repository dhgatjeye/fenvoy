use crate::crypto::identity::{fingerprint_of, verify_signature};
use crate::discovery::{DiscoveryEvent, PeerInfo};
use crate::error::{FenvoyError, Result};
use crate::protocol::{DEFAULT_PORT, DISCOVERY_MAGIC, PROTOCOL_VERSION};

use ed25519_dalek::Signer;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

const MULTICAST_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 70, 69);
const DISCOVERY_PORT: u16 = DEFAULT_PORT;
const ANNOUNCE_INTERVAL_FAST: Duration = Duration::from_secs(5);
const ANNOUNCE_INTERVAL_SLOW: Duration = Duration::from_secs(15);
const PEER_EXPIRY: Duration = Duration::from_secs(60);
const FAST_ANNOUNCE_DURATION: Duration = Duration::from_secs(30);

const MAX_ANNOUNCE_SIZE: usize = 512;

#[derive(Clone)]
pub struct DiscoveryConfig {
    pub local_name: String,
    pub tcp_port: u16,
    pub fingerprint: [u8; 8],
    pub capabilities: u8,
    pub signing_key: [u8; 32],
    pub public_key: [u8; 32],
}

pub struct DiscoveryService {
    event_tx: broadcast::Sender<DiscoveryEvent>,
    announcer_handle: Option<JoinHandle<()>>,
    listener_handle: Option<JoinHandle<()>>,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl DiscoveryService {
    pub fn start(config: DiscoveryConfig) -> Result<Self> {
        let (event_tx, _) = broadcast::channel(64);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let announcer_config = config.clone();
        let mut announcer_shutdown = shutdown_rx.clone();

        let announcer_handle = tokio::spawn(async move {
            if let Err(e) = run_announcer(announcer_config, &mut announcer_shutdown).await {
                eprintln!("[discovery] announcer error: {e}");
            }
        });

        let listener_config = config;
        let listener_event_tx = event_tx.clone();
        let mut listener_shutdown = shutdown_rx;

        let listener_handle = tokio::spawn(async move {
            if let Err(e) =
                run_listener(listener_config, listener_event_tx, &mut listener_shutdown).await
            {
                eprintln!("[discovery] listener error: {e}");
            }
        });

        Ok(Self {
            event_tx,
            announcer_handle: Some(announcer_handle),
            listener_handle: Some(listener_handle),
            shutdown: shutdown_tx,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.event_tx.subscribe()
    }

    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);

        if let Some(h) = self.announcer_handle.take() {
            let _ = h.await;
        }
        if let Some(h) = self.listener_handle.take() {
            let _ = h.await;
        }
    }
}

fn encode_announcement(config: &DiscoveryConfig) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(DISCOVERY_MAGIC);
    buf.push(PROTOCOL_VERSION);
    buf.extend_from_slice(&config.tcp_port.to_be_bytes());

    let name_bytes = config.local_name.as_bytes();
    buf.push(name_bytes.len().min(255) as u8);
    buf.extend_from_slice(&name_bytes[..name_bytes.len().min(255)]);
    buf.extend_from_slice(&config.fingerprint);
    buf.push(config.capabilities);
    buf.extend_from_slice(&config.public_key);

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&config.signing_key);
    let signature = signing_key.sign(&buf);
    buf.extend_from_slice(&signature.to_bytes());

    buf
}

fn decode_announcement(data: &[u8], src_addr: SocketAddr) -> Option<PeerInfo> {
    if data.len() < 8 {
        return None;
    }

    if &data[0..4] != DISCOVERY_MAGIC {
        return None;
    }

    let version = data[4];
    if version != PROTOCOL_VERSION {
        return None;
    }

    let tcp_port = u16::from_be_bytes([data[5], data[6]]);
    let name_len = data[7] as usize;

    let required = 8 + name_len + 8 + 1 + 32 + 64;
    if data.len() < required {
        return None;
    }

    let name = std::str::from_utf8(&data[8..8 + name_len])
        .ok()?
        .to_string();

    let fp_start = 8 + name_len;
    let mut fingerprint = [0u8; 8];
    fingerprint.copy_from_slice(&data[fp_start..fp_start + 8]);

    let capabilities = data[fp_start + 8];

    let pk_start = fp_start + 9;
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&data[pk_start..pk_start + 32]);

    let sig_start = pk_start + 32;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[sig_start..sig_start + 64]);

    if data.len() != sig_start + 64 {
        return None;
    }

    if fingerprint_of(&public_key) != fingerprint {
        return None;
    }

    let signed_data = &data[..sig_start];
    if verify_signature(&public_key, signed_data, &signature).is_err() {
        return None;
    }

    Some(PeerInfo {
        name,
        addr: src_addr,
        tcp_port,
        fingerprint,
        capabilities,
        last_seen: Instant::now(),
    })
}

async fn run_announcer(
    config: DiscoveryConfig,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| FenvoyError::MulticastJoinFailed(format!("socket creation: {e}")))?;

    socket
        .set_multicast_ttl_v4(1)
        .map_err(|e| FenvoyError::MulticastJoinFailed(format!("set TTL: {e}")))?;

    socket
        .set_nonblocking(true)
        .map_err(|e| FenvoyError::MulticastJoinFailed(format!("set nonblocking: {e}")))?;

    let dest = SocketAddrV4::new(MULTICAST_V4, DISCOVERY_PORT);
    let _dest_addr = SockAddr::from(dest);

    let std_socket: std::net::UdpSocket = socket.into();
    let udp = tokio::net::UdpSocket::from_std(std_socket)
        .map_err(|e| FenvoyError::MulticastJoinFailed(format!("tokio wrap: {e}")))?;

    let payload = encode_announcement(&config);
    let start = Instant::now();

    loop {
        let interval = if start.elapsed() < FAST_ANNOUNCE_DURATION {
            ANNOUNCE_INTERVAL_FAST
        } else {
            ANNOUNCE_INTERVAL_SLOW
        };

        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                let _ = udp.send_to(&payload, dest).await;
            }
            _ = shutdown.changed() => {
                break;
            }
        }
    }

    Ok(())
}

async fn run_listener(
    config: DiscoveryConfig,
    event_tx: broadcast::Sender<DiscoveryEvent>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| FenvoyError::MulticastJoinFailed(format!("socket creation: {e}")))?;

    socket
        .set_reuse_address(true)
        .map_err(|e| FenvoyError::MulticastJoinFailed(format!("reuse addr: {e}")))?;

    #[cfg(not(windows))]
    {
        socket.set_reuse_port(true).ok();
    }

    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT);
    socket
        .bind(&SockAddr::from(bind_addr))
        .map_err(|e| FenvoyError::MulticastJoinFailed(format!("bind: {e}")))?;

    socket
        .join_multicast_v4(&MULTICAST_V4, &Ipv4Addr::UNSPECIFIED)
        .map_err(|e| FenvoyError::MulticastJoinFailed(format!("join multicast: {e}")))?;

    socket
        .set_nonblocking(true)
        .map_err(|e| FenvoyError::MulticastJoinFailed(format!("set nonblocking: {e}")))?;

    let std_socket: std::net::UdpSocket = socket.into();
    let udp = tokio::net::UdpSocket::from_std(std_socket)
        .map_err(|e| FenvoyError::MulticastJoinFailed(format!("tokio wrap: {e}")))?;

    eprintln!(
        "[discovery] listening on multicast {}:{} (SO_REUSEADDR — \
         other local processes may observe discovery traffic)",
        MULTICAST_V4, DISCOVERY_PORT
    );

    let mut peers: HashMap<[u8; 8], PeerInfo> = HashMap::new();
    let mut buf = [0u8; MAX_ANNOUNCE_SIZE];
    let mut cleanup_interval = tokio::time::interval(Duration::from_secs(15));

    loop {
        tokio::select! {
            result = udp.recv_from(&mut buf) => {
                match result {
                    Ok((n, src)) => {
                        if let Some(peer) = decode_announcement(&buf[..n], src) {
                            if peer.fingerprint == config.fingerprint {
                                continue;
                            }

                            let event = if peers.contains_key(&peer.fingerprint) {
                                DiscoveryEvent::PeerUpdated(peer.clone())
                            } else {
                                DiscoveryEvent::PeerDiscovered(peer.clone())
                            };

                            peers.insert(peer.fingerprint, peer);
                            let _ = event_tx.send(event);
                        }
                    }
                    Err(e) => {
                        eprintln!("[discovery] recv error: {e}");
                    }
                }
            }
            _ = cleanup_interval.tick() => {
                let now = Instant::now();
                let expired: Vec<[u8; 8]> = peers
                    .iter()
                    .filter(|(_, p)| now.duration_since(p.last_seen) > PEER_EXPIRY)
                    .map(|(fp, _)| *fp)
                    .collect();

                for fp in expired {
                    if let Some(peer) = peers.remove(&fp) {
                        let _ = event_tx.send(DiscoveryEvent::PeerExpired {
                            name: peer.name,
                            fingerprint: fp,
                        });
                    }
                }
            }
            _ = shutdown.changed() => {
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::fingerprint_of;
    use crate::discovery::capabilities;

    fn test_config() -> DiscoveryConfig {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let fingerprint = fingerprint_of(&public_key);

        DiscoveryConfig {
            local_name: "TestPeer".into(),
            tcp_port: 19527,
            fingerprint,
            capabilities: capabilities::BOTH,
            signing_key: signing_key.to_bytes(),
            public_key,
        }
    }

    #[test]
    fn announcement_roundtrip() {
        let config = test_config();

        let encoded = encode_announcement(&config);
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345));
        let decoded = decode_announcement(&encoded, src).unwrap();

        assert_eq!(decoded.name, "TestPeer");
        assert_eq!(decoded.tcp_port, 19527);
        assert_eq!(decoded.fingerprint, config.fingerprint);
        assert_eq!(decoded.capabilities, capabilities::BOTH);
    }

    #[test]
    fn decode_invalid_magic() {
        let data = b"XXXX\x01\x00\x00\x00";
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));
        assert!(decode_announcement(data, src).is_none());
    }

    #[test]
    fn decode_too_short() {
        let data = b"FNV";
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));
        assert!(decode_announcement(data, src).is_none());
    }

    #[test]
    fn decode_rejects_tampered_payload() {
        let config = test_config();
        let mut encoded = encode_announcement(&config);
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345));

        encoded[8] ^= 0xFF;
        assert!(decode_announcement(&encoded, src).is_none());
    }

    #[test]
    fn decode_rejects_wrong_signature() {
        let config = test_config();
        let mut encoded = encode_announcement(&config);
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345));

        let len = encoded.len();
        encoded[len - 1] ^= 0xFF;
        assert!(decode_announcement(&encoded, src).is_none());
    }

    #[test]
    fn decode_rejects_fingerprint_mismatch() {
        let config = test_config();
        let mut encoded = encode_announcement(&config);
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345));

        let fp_start = 8 + config.local_name.len();
        encoded[fp_start] ^= 0xFF;
        assert!(decode_announcement(&encoded, src).is_none());
    }

    #[test]
    fn decode_rejects_trailing_data() {
        let config = test_config();
        let mut encoded = encode_announcement(&config);
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345));

        encoded.push(0x00);
        assert!(decode_announcement(&encoded, src).is_none());
    }
}
