pub mod multicast;

use std::net::SocketAddr;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub name: String,
    pub addr: SocketAddr,
    pub tcp_port: u16,
    pub fingerprint: [u8; 8],
    pub capabilities: u8,
    pub last_seen: Instant,
}

pub mod capabilities {
    pub const CAN_SEND: u8 = 0x01;
    pub const CAN_RECV: u8 = 0x02;
    pub const BOTH: u8 = CAN_SEND | CAN_RECV;
}

#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    PeerDiscovered(PeerInfo),
    PeerUpdated(PeerInfo),
    PeerExpired { name: String, fingerprint: [u8; 8] },
}
