use crate::error::{FenvoyError, Result};
use crate::transport::TransportStream;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

const BUFFER_SIZE: usize = 4 * 1024 * 1024;

impl TransportStream for TcpStream {
    fn peer_addr(&self) -> Result<SocketAddr> {
        TcpStream::peer_addr(self).map_err(FenvoyError::Io)
    }
}

pub async fn connect(addr: SocketAddr) -> Result<TcpStream> {
    let stream = TcpStream::connect(addr)
        .await
        .map_err(FenvoyError::ConnectionFailed)?;

    configure_stream(&stream)?;
    Ok(stream)
}

pub async fn listen(addr: SocketAddr) -> Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(FenvoyError::Io)?;

    socket.set_reuse_address(true).map_err(FenvoyError::Io)?;

    if addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }

    let _ = socket.set_send_buffer_size(BUFFER_SIZE);
    let _ = socket.set_recv_buffer_size(BUFFER_SIZE);

    socket
        .bind(&SockAddr::from(addr))
        .map_err(|_e| FenvoyError::AddressInUse(addr))?;

    socket.listen(128).map_err(FenvoyError::Io)?;

    socket.set_nonblocking(true).map_err(FenvoyError::Io)?;
    let std_listener: std::net::TcpListener = socket.into();
    let listener = TcpListener::from_std(std_listener).map_err(FenvoyError::Io)?;

    Ok(listener)
}

fn configure_stream(stream: &TcpStream) -> Result<()> {
    stream.set_nodelay(true).map_err(FenvoyError::Io)?;

    let socket = socket2::SockRef::from(stream);
    let _ = socket.set_send_buffer_size(BUFFER_SIZE);
    let _ = socket.set_recv_buffer_size(BUFFER_SIZE);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[tokio::test]
    async fn listen_and_connect() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let listener = listen(addr).await.unwrap();
        let bound_addr = listener.local_addr().unwrap();

        let connector = tokio::spawn(async move { connect(bound_addr).await.unwrap() });

        let (server_stream, _client_addr) = listener.accept().await.unwrap();
        let client_stream = connector.await.unwrap();

        assert_eq!(
            TransportStream::peer_addr(&server_stream).unwrap(),
            client_stream.local_addr().unwrap()
        );
    }
}
