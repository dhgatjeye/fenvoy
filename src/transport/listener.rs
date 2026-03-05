use crate::crypto::identity::Identity;
use crate::error::{FenvoyError, Result};
use crate::protocol::handshake;
use crate::transport::tcp;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

const MAX_CONCURRENT_HANDSHAKES: usize = 10;
const MAX_PER_IP: usize = 3;

pub struct ListenerConfig {
    pub bind_addr: SocketAddr,
    pub local_name: String,
    pub identity: Arc<Identity>,
}

struct IpTracker {
    counts: HashMap<IpAddr, usize>,
}

impl IpTracker {
    fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    fn admit_locked(&mut self, ip: IpAddr) -> bool {
        let count = self.counts.entry(ip).or_insert(0);
        if *count >= MAX_PER_IP {
            return false;
        }
        *count += 1;
        true
    }

    fn release(&mut self, ip: &IpAddr) {
        if let Some(count) = self.counts.get_mut(ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.counts.remove(ip);
            }
        }
    }
}

struct IpGuard {
    tracker: Arc<Mutex<IpTracker>>,
    ip: IpAddr,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut t = self.tracker.lock().expect("IpTracker lock poisoned");
        t.release(&self.ip);
    }
}

pub struct ConnectionListener {
    listener: TcpListener,
    config: ListenerConfig,
    handshake_semaphore: Arc<Semaphore>,
    ip_tracker: Arc<Mutex<IpTracker>>,
}

impl ConnectionListener {
    pub async fn bind(config: ListenerConfig) -> Result<Self> {
        let listener = tcp::listen(config.bind_addr).await?;
        Ok(Self {
            listener,
            config,
            handshake_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_HANDSHAKES)),
            ip_tracker: Arc::new(Mutex::new(IpTracker::new())),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener.local_addr().map_err(FenvoyError::Io)
    }

    pub async fn accept_one(
        &self,
    ) -> Result<(
        handshake::HandshakeResult<tokio::net::TcpStream>,
        SocketAddr,
    )> {
        let permit = self
            .handshake_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| FenvoyError::HandshakeFailed("semaphore closed".into()))?;

        let (stream, addr) = self.listener.accept().await.map_err(FenvoyError::Io)?;

        let ip = addr.ip();
        let _ip_guard = {
            let mut tracker = self.ip_tracker.lock().expect("IpTracker lock poisoned");
            if !tracker.admit_locked(ip) {
                drop(stream);
                drop(permit);
                return Err(FenvoyError::HandshakeFailed(format!(
                    "per-IP limit exceeded for {ip}"
                )));
            }
            IpGuard {
                tracker: self.ip_tracker.clone(),
                ip,
            }
        };

        tcp::configure_stream(&stream)?;

        let result =
            handshake::respond(stream, &self.config.local_name, &self.config.identity).await?;

        Ok((result, addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::handshake as hs;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn listener_accept_handshake() {
        let identity = Arc::new(Identity::generate());
        let config = ListenerConfig {
            bind_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            local_name: "TestServer".into(),
            identity: identity.clone(),
        };

        let listener = ConnectionListener::bind(config).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client_identity = Identity::generate();

        let client = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            hs::initiate(stream, "TestClient", &client_identity)
                .await
                .unwrap()
        });

        let (server_result, _) = listener.accept_one().await.unwrap();
        let client_result = client.await.unwrap();

        assert_eq!(server_result.remote_name, "TestClient");
        assert_eq!(client_result.remote_name, "TestServer");
        assert_eq!(server_result.sas_bytes, client_result.sas_bytes);
    }
}
