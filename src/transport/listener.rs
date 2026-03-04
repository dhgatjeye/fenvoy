use crate::crypto::identity::Identity;
use crate::error::Result;
use crate::protocol::handshake;
use crate::transport::tcp;

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

const MAX_CONCURRENT_HANDSHAKES: usize = 10;

pub struct ListenerConfig {
    pub bind_addr: SocketAddr,
    pub local_name: String,
    pub identity: Arc<Identity>,
}

pub struct ConnectionListener {
    listener: TcpListener,
    config: ListenerConfig,
    handshake_semaphore: Arc<Semaphore>,
}

impl ConnectionListener {
    pub async fn bind(config: ListenerConfig) -> Result<Self> {
        let listener = tcp::listen(config.bind_addr).await?;
        Ok(Self {
            listener,
            config,
            handshake_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_HANDSHAKES)),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(crate::error::FenvoyError::Io)
    }

    pub async fn accept_one(
        &self,
    ) -> Result<(
        handshake::HandshakeResult<tokio::net::TcpStream>,
        SocketAddr,
    )> {
        let (stream, addr) = self
            .listener
            .accept()
            .await
            .map_err(crate::error::FenvoyError::Io)?;

        stream
            .set_nodelay(true)
            .map_err(crate::error::FenvoyError::Io)?;

        let _permit =
            self.handshake_semaphore.acquire().await.map_err(|_| {
                crate::error::FenvoyError::HandshakeFailed("semaphore closed".into())
            })?;

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
