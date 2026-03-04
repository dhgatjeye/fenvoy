use crate::crypto::aead::CipherState;
use crate::crypto::identity::Identity;
use crate::crypto::{hybrid, identity, kdf, kem, x25519};
use crate::error::{FenvoyError, Result};

use crate::protocol::messages::{
    HandshakeFinish, HandshakeIdentity, HandshakeInit, HandshakeResponse,
};
use crate::protocol::record::SecureChannel;
use crate::protocol::{PROTOCOL_LABEL, PROTOCOL_VERSION};

use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub struct HandshakeResult<S> {
    pub channel: SecureChannel<S>,
    pub remote_static_key: [u8; 32],
    pub remote_name: String,
    pub sas_bytes: [u8; 12],
}

struct Transcript {
    hasher: Sha256,
}

impl Transcript {
    fn new() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(PROTOCOL_LABEL);
        Self { hasher }
    }

    fn absorb(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn current_hash(&self) -> [u8; 32] {
        let h = self.hasher.clone().finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&h);
        out
    }
}

async fn read_message<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => {
                FenvoyError::HandshakeFailed("connection closed during handshake".into())
            }
            _ => FenvoyError::Io(e),
        })?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 64 * 1024 {
        return Err(FenvoyError::HandshakeFailed(format!(
            "handshake message too large: {len} bytes"
        )));
    }

    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => {
                FenvoyError::HandshakeFailed("connection closed during handshake".into())
            }
            _ => FenvoyError::Io(e),
        })?;

    Ok(buf)
}

async fn write_message<S: AsyncWrite + Unpin>(stream: &mut S, data: &[u8]) -> Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn initiate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    local_name: &str,
    identity: &Identity,
) -> Result<HandshakeResult<S>> {
    tokio::time::timeout(
        Duration::from_secs(crate::protocol::HANDSHAKE_TIMEOUT_SECS),
        initiate_inner(stream, local_name, identity),
    )
    .await
    .map_err(|_| FenvoyError::ConnectionTimeout)?
}

async fn initiate_inner<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    local_name: &str,
    identity: &Identity,
) -> Result<HandshakeResult<S>> {
    let static_key = identity.public_key_bytes();
    let mut transcript = Transcript::new();

    let initiator_keys = hybrid::initiator_keygen();

    let msg1 = HandshakeInit {
        version: PROTOCOL_VERSION,
        x25519_public: initiator_keys.x25519_kp.public_key_bytes(),
        kem_encaps_key: initiator_keys.kem_material.ek_bytes.clone(),
    };

    let msg1_bytes = msg1.encode();
    transcript.absorb(&msg1_bytes);
    write_message(&mut stream, &msg1_bytes).await?;

    let transcript_hash = transcript.current_hash();

    let msg2_bytes = read_message(&mut stream).await?;

    let msg2 = HandshakeResponse::decode(&msg2_bytes)?;

    let x25519_kp = initiator_keys.x25519_kp;
    let x25519_ss = x25519_kp.diffie_hellman(&msg2.x25519_public)?;

    let kem_ss = kem::decapsulate(&initiator_keys.kem_material, &msg2.kem_ciphertext)?;

    let master_secret = hybrid::combine_secrets(&x25519_ss, &kem_ss, &transcript_hash)?;

    let hs_key_r = kdf::derive_key(&master_secret[..], &transcript_hash, b"fenvoy-hs-enc-r")?;
    let hs_key_i = kdf::derive_key(&master_secret[..], &transcript_hash, b"fenvoy-hs-enc-i")?;

    let mut hs_cipher_r = CipherState::new(&hs_key_r);
    let identity_bytes = hs_cipher_r
        .decrypt(&msg2.encrypted_payload, b"fenvoy-hs-identity-r")
        .map_err(|_| FenvoyError::HandshakeFailed("failed to decrypt responder identity".into()))?;

    let remote_identity = HandshakeIdentity::decode(&identity_bytes)?;

    identity::verify_signature(
        &remote_identity.static_public_key,
        &transcript_hash,
        &remote_identity.signature,
    )?;

    transcript.absorb(&msg2_bytes);

    let transcript_for_msg3 = transcript.current_hash();
    let signature = identity.sign(&transcript_for_msg3);

    let my_identity = HandshakeIdentity {
        static_public_key: static_key,
        name: local_name.to_string(),
        signature,
    };

    let my_identity_bytes = my_identity.encode()?;
    let mut hs_cipher_i = CipherState::new(&hs_key_i);
    let encrypted_identity = hs_cipher_i
        .encrypt(&my_identity_bytes, b"fenvoy-hs-identity-i")
        .map_err(|_| FenvoyError::HandshakeFailed("failed to encrypt initiator identity".into()))?;

    let msg3 = HandshakeFinish {
        encrypted_payload: encrypted_identity,
    };

    let msg3_bytes = msg3.encode()?;
    transcript.absorb(&msg3_bytes);
    write_message(&mut stream, &msg3_bytes).await?;

    let final_transcript = transcript.current_hash();

    let mut info_tx = Vec::from(&final_transcript[..]);
    info_tx.extend_from_slice(b"fenvoy-session-i-tx");
    let tx_key = kdf::derive_key(&master_secret[..], &final_transcript, &info_tx)?;

    let mut info_rx = Vec::from(&final_transcript[..]);
    info_rx.extend_from_slice(b"fenvoy-session-i-rx");
    let rx_key = kdf::derive_key(&master_secret[..], &final_transcript, &info_rx)?;

    let sas_material = kdf::derive(&master_secret[..], &final_transcript, b"fenvoy-sas", 12)?;
    let mut sas_bytes = [0u8; 12];
    sas_bytes.copy_from_slice(&sas_material);

    let channel = SecureChannel::new(stream, &tx_key, &rx_key);

    Ok(HandshakeResult {
        channel,
        remote_static_key: remote_identity.static_public_key,
        remote_name: remote_identity.name,
        sas_bytes,
    })
}

pub async fn respond<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    local_name: &str,
    identity: &Identity,
) -> Result<HandshakeResult<S>> {
    tokio::time::timeout(
        Duration::from_secs(crate::protocol::HANDSHAKE_TIMEOUT_SECS),
        respond_inner(stream, local_name, identity),
    )
    .await
    .map_err(|_| FenvoyError::ConnectionTimeout)?
}

async fn respond_inner<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    local_name: &str,
    identity: &Identity,
) -> Result<HandshakeResult<S>> {
    let static_key = identity.public_key_bytes();
    let mut transcript = Transcript::new();

    let msg1_bytes = read_message(&mut stream).await?;
    transcript.absorb(&msg1_bytes);

    let msg1 = HandshakeInit::decode(&msg1_bytes)?;

    if msg1.version != PROTOCOL_VERSION {
        return Err(FenvoyError::ProtocolVersionMismatch {
            expected: PROTOCOL_VERSION,
            got: msg1.version,
        });
    }

    let responder_x25519 = x25519::X25519Keypair::generate();
    let responder_x25519_pk = responder_x25519.public_key_bytes();

    let x25519_ss = responder_x25519.diffie_hellman(&msg1.x25519_public)?;

    let (kem_ct, kem_ss) = kem::encapsulate(&msg1.kem_encaps_key)?;

    let transcript_hash = transcript.current_hash();

    let master_secret = hybrid::combine_secrets(&x25519_ss, &kem_ss, &transcript_hash)?;

    let hs_key_r = kdf::derive_key(&master_secret[..], &transcript_hash, b"fenvoy-hs-enc-r")?;
    let hs_key_i = kdf::derive_key(&master_secret[..], &transcript_hash, b"fenvoy-hs-enc-i")?;
    let mut hs_cipher_r = CipherState::new(&hs_key_r);

    let signature = identity.sign(&transcript_hash);

    let my_identity = HandshakeIdentity {
        static_public_key: static_key,
        name: local_name.to_string(),
        signature,
    };

    let identity_bytes = my_identity.encode()?;
    let encrypted_identity = hs_cipher_r
        .encrypt(&identity_bytes, b"fenvoy-hs-identity-r")
        .map_err(|_| FenvoyError::HandshakeFailed("failed to encrypt responder identity".into()))?;

    let msg2 = HandshakeResponse {
        x25519_public: responder_x25519_pk,
        kem_ciphertext: kem_ct,
        encrypted_payload: encrypted_identity,
    };

    let msg2_bytes = msg2.encode()?;
    transcript.absorb(&msg2_bytes);
    write_message(&mut stream, &msg2_bytes).await?;

    let transcript_for_msg3_verify = transcript.current_hash();

    let msg3_bytes = read_message(&mut stream).await?;
    transcript.absorb(&msg3_bytes);

    let msg3 = HandshakeFinish::decode(&msg3_bytes)?;

    let mut hs_cipher_i = CipherState::new(&hs_key_i);
    let identity_bytes = hs_cipher_i
        .decrypt(&msg3.encrypted_payload, b"fenvoy-hs-identity-i")
        .map_err(|_| FenvoyError::HandshakeFailed("failed to decrypt initiator identity".into()))?;

    let remote_identity = HandshakeIdentity::decode(&identity_bytes)?;

    identity::verify_signature(
        &remote_identity.static_public_key,
        &transcript_for_msg3_verify,
        &remote_identity.signature,
    )?;

    let final_transcript = transcript.current_hash();

    let mut info_rx = Vec::from(&final_transcript[..]);
    info_rx.extend_from_slice(b"fenvoy-session-i-tx");
    let rx_key = kdf::derive_key(&master_secret[..], &final_transcript, &info_rx)?;

    let mut info_tx = Vec::from(&final_transcript[..]);
    info_tx.extend_from_slice(b"fenvoy-session-i-rx");
    let tx_key = kdf::derive_key(&master_secret[..], &final_transcript, &info_tx)?;

    let sas_material = kdf::derive(&master_secret[..], &final_transcript, b"fenvoy-sas", 12)?;
    let mut sas_bytes = [0u8; 12];
    sas_bytes.copy_from_slice(&sas_material);

    let channel = SecureChannel::new(stream, &tx_key, &rx_key);

    Ok(HandshakeResult {
        channel,
        remote_static_key: remote_identity.static_public_key,
        remote_name: remote_identity.name,
        sas_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::Identity;
    use tokio::io::duplex;

    #[tokio::test]
    async fn full_handshake() {
        let (client, server) = duplex(65536);

        let initiator_id = Identity::from_secret_bytes([1u8; 32]);
        let responder_id = Identity::from_secret_bytes([2u8; 32]);
        let initiator_pk = initiator_id.public_key_bytes();
        let responder_pk = responder_id.public_key_bytes();

        let initiator =
            tokio::spawn(async move { initiate(client, "Alice", &initiator_id).await.unwrap() });

        let responder =
            tokio::spawn(async move { respond(server, "Bob", &responder_id).await.unwrap() });

        let (i_result, r_result) = tokio::join!(initiator, responder);
        let i_result = i_result.unwrap();
        let r_result = r_result.unwrap();

        assert_eq!(i_result.remote_static_key, responder_pk);
        assert_eq!(r_result.remote_static_key, initiator_pk);

        assert_eq!(i_result.remote_name, "Bob");
        assert_eq!(r_result.remote_name, "Alice");

        assert_eq!(i_result.sas_bytes, r_result.sas_bytes);
    }

    #[tokio::test]
    async fn handshake_then_record() {
        let (client, server) = duplex(65536);

        let initiator_id = Identity::from_secret_bytes([10u8; 32]);
        let responder_id = Identity::from_secret_bytes([20u8; 32]);

        let initiator = tokio::spawn(async move {
            let mut result = initiate(client, "I", &initiator_id).await.unwrap();
            result
                .channel
                .send_record(0x01, b"hello from initiator")
                .await
                .unwrap();
            let (_, msg) = result.channel.recv_record().await.unwrap();
            assert_eq!(msg, b"hello from responder");
        });

        let responder = tokio::spawn(async move {
            let mut result = respond(server, "R", &responder_id).await.unwrap();
            let (_, msg) = result.channel.recv_record().await.unwrap();
            assert_eq!(msg, b"hello from initiator");
            result
                .channel
                .send_record(0x01, b"hello from responder")
                .await
                .unwrap();
        });

        initiator.await.unwrap();
        responder.await.unwrap();
    }
}
