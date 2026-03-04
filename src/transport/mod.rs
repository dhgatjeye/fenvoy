pub mod listener;
pub mod tcp;

use crate::error::Result;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait TransportStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {
    fn peer_addr(&self) -> Result<SocketAddr>;
}
