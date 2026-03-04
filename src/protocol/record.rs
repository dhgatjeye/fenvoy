use crate::crypto::aead::{CipherState, TAG_LEN};
use crate::error::{FenvoyError, Result};
use crate::protocol::MAX_RECORD_PAYLOAD;

use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const RECORD_HEADER_LEN: usize = 5;

pub struct SecureChannel<S> {
    stream: S,
    tx: CipherState,
    rx: CipherState,
}

impl<S: AsyncRead + AsyncWrite + Unpin> SecureChannel<S> {
    pub fn new(stream: S, tx_key: &[u8; 32], rx_key: &[u8; 32]) -> Self {
        Self {
            stream,
            tx: CipherState::new(tx_key),
            rx: CipherState::new(rx_key),
        }
    }

    pub async fn send_record(&mut self, record_type: u8, payload: &[u8]) -> Result<()> {
        if payload.len() > MAX_RECORD_PAYLOAD {
            return Err(FenvoyError::MessageTooLarge {
                size: payload.len(),
                max: MAX_RECORD_PAYLOAD,
            });
        }

        let payload_len = payload.len() as u32;
        let mut aad = [0u8; RECORD_HEADER_LEN];
        aad[0] = record_type;
        aad[1..5].copy_from_slice(&payload_len.to_be_bytes());

        let ciphertext = self.tx.encrypt(payload, &aad)?;

        self.stream.write_all(&aad).await?;
        self.stream.write_all(&ciphertext).await?;
        self.stream.flush().await?;

        Ok(())
    }

    pub async fn recv_record(&mut self) -> Result<(u8, Vec<u8>)> {
        let mut header = [0u8; RECORD_HEADER_LEN];
        self.stream
            .read_exact(&mut header)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => FenvoyError::UnexpectedEof,
                _ => FenvoyError::Io(e),
            })?;

        let record_type = header[0];
        let payload_len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;

        if payload_len > MAX_RECORD_PAYLOAD {
            return Err(FenvoyError::MessageTooLarge {
                size: payload_len,
                max: MAX_RECORD_PAYLOAD,
            });
        }

        let ct_len = payload_len + TAG_LEN;
        let mut ciphertext = vec![0u8; ct_len];
        self.stream
            .read_exact(&mut ciphertext)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => FenvoyError::UnexpectedEof,
                _ => FenvoyError::Io(e),
            })?;

        let plaintext = self.rx.decrypt(&ciphertext, &header)?;

        Ok((record_type, plaintext))
    }

    pub async fn recv_record_with_timeout(&mut self, timeout: Duration) -> Result<(u8, Vec<u8>)> {
        tokio::time::timeout(timeout, self.recv_record())
            .await
            .map_err(|_| FenvoyError::ConnectionTimeout)?
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn record_roundtrip() {
        let (client, server) = duplex(8192);

        let tx_key = [1u8; 32];
        let rx_key = [2u8; 32];

        let mut sender = SecureChannel::new(client, &tx_key, &rx_key);
        let mut receiver = SecureChannel::new(server, &rx_key, &tx_key);

        let payload = b"Hello, encrypted world!";
        sender.send_record(0x01, payload).await.unwrap();

        let (rt, pt) = receiver.recv_record().await.unwrap();
        assert_eq!(rt, 0x01);
        assert_eq!(pt, payload);
    }

    #[tokio::test]
    async fn multiple_records() {
        let (client, server) = duplex(65536);

        let tx_key = [3u8; 32];
        let rx_key = [4u8; 32];

        let mut sender = SecureChannel::new(client, &tx_key, &rx_key);
        let mut receiver = SecureChannel::new(server, &rx_key, &tx_key);

        for i in 0u8..10 {
            let msg = format!("message {i}");
            sender.send_record(0x01, msg.as_bytes()).await.unwrap();
        }

        for i in 0u8..10 {
            let (rt, pt) = receiver.recv_record().await.unwrap();
            assert_eq!(rt, 0x01);
            assert_eq!(pt, format!("message {i}").as_bytes());
        }
    }

    #[tokio::test]
    async fn empty_payload() {
        let (client, server) = duplex(8192);

        let tx_key = [5u8; 32];
        let rx_key = [6u8; 32];

        let mut sender = SecureChannel::new(client, &tx_key, &rx_key);
        let mut receiver = SecureChannel::new(server, &rx_key, &tx_key);

        sender.send_record(0x05, b"").await.unwrap();

        let (rt, pt) = receiver.recv_record().await.unwrap();
        assert_eq!(rt, 0x05);
        assert!(pt.is_empty());
    }

    #[tokio::test]
    async fn large_payload() {
        let (client, server) = duplex(1024 * 1024);

        let tx_key = [7u8; 32];
        let rx_key = [8u8; 32];

        let mut sender = SecureChannel::new(client, &tx_key, &rx_key);
        let mut receiver = SecureChannel::new(server, &rx_key, &tx_key);

        let big = vec![0xAA; 256 * 1024];
        sender.send_record(0x01, &big).await.unwrap();

        let (rt, pt) = receiver.recv_record().await.unwrap();
        assert_eq!(rt, 0x01);
        assert_eq!(pt.len(), 256 * 1024);
        assert!(pt.iter().all(|&b| b == 0xAA));
    }

    #[tokio::test]
    async fn recv_with_timeout_ok() {
        let (client, server) = duplex(8192);

        let tx_key = [9u8; 32];
        let rx_key = [10u8; 32];

        let mut sender = SecureChannel::new(client, &tx_key, &rx_key);
        let mut receiver = SecureChannel::new(server, &rx_key, &tx_key);

        sender.send_record(0x01, b"timely").await.unwrap();

        let (rt, pt) = receiver
            .recv_record_with_timeout(Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(rt, 0x01);
        assert_eq!(pt, b"timely");
    }

    #[tokio::test]
    async fn recv_with_timeout_expires() {
        let (_client, server) = duplex(8192);

        let rx_key = [12u8; 32];
        let tx_key = [11u8; 32];

        let mut receiver = SecureChannel::new(server, &rx_key, &tx_key);

        let result = receiver
            .recv_record_with_timeout(Duration::from_millis(50))
            .await;
        assert!(result.is_err());
    }
}
