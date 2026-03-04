use crate::crypto::kem;
use crate::error::{FenvoyError, Result};
use crate::protocol::codec::{self, Reader};

pub mod record_type {
    pub const DATA: u8 = 0x01;
    pub const CONTROL: u8 = 0x02;
    pub const FILE_META: u8 = 0x03;
    pub const FILE_ACCEPT: u8 = 0x04;
    pub const FILE_ACK: u8 = 0x07;
    pub const PING: u8 = 0x05;
    pub const CLOSE: u8 = 0x06;
    pub const BATCH: u8 = 0x08;
    pub const SAS_CONFIRM: u8 = 0x09;
}

pub mod control_type {
    pub const PING: u8 = 0x00;
    pub const FILE_COMPLETE: u8 = 0x01;
    pub const CANCEL: u8 = 0x02;
    pub const ERROR: u8 = 0x03;
    pub const CHUNK_RETRY: u8 = 0x04;
    pub const CLOSE: u8 = 0xFF;
}

pub mod batch_type {
    pub const BEGIN: u8 = 0x01;
    pub const END: u8 = 0x02;
}

#[derive(Debug, Clone)]
pub struct HandshakeInit {
    pub version: u8,
    pub x25519_public: [u8; 32],
    pub kem_encaps_key: Vec<u8>,
}

impl HandshakeInit {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 32 + kem::ENCAPS_KEY_LEN);
        codec::write_u8(&mut buf, self.version);
        codec::write_raw(&mut buf, &self.x25519_public);
        codec::write_raw(&mut buf, &self.kem_encaps_key);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let version = r.read_u8()?;
        let x25519_public = r.read_array::<32>()?;
        let kem_encaps_key = r.read_exact(kem::ENCAPS_KEY_LEN)?.to_vec();
        Ok(Self {
            version,
            x25519_public,
            kem_encaps_key,
        })
    }
}

#[derive(Debug, Clone)]
pub struct HandshakeResponse {
    pub x25519_public: [u8; 32],
    pub kem_ciphertext: Vec<u8>,
    pub encrypted_payload: Vec<u8>,
}

impl HandshakeResponse {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf =
            Vec::with_capacity(32 + kem::CIPHERTEXT_LEN + 4 + self.encrypted_payload.len());
        codec::write_raw(&mut buf, &self.x25519_public);
        codec::write_raw(&mut buf, &self.kem_ciphertext);
        codec::write_bytes(&mut buf, &self.encrypted_payload)?;
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let x25519_public = r.read_array::<32>()?;
        let kem_ciphertext = r.read_exact(kem::CIPHERTEXT_LEN)?.to_vec();
        let encrypted_payload = r.read_bytes()?.to_vec();
        Ok(Self {
            x25519_public,
            kem_ciphertext,
            encrypted_payload,
        })
    }
}

#[derive(Debug, Clone)]
pub struct HandshakeFinish {
    pub encrypted_payload: Vec<u8>,
}

impl HandshakeFinish {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(4 + self.encrypted_payload.len());
        codec::write_bytes(&mut buf, &self.encrypted_payload)?;
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let encrypted_payload = r.read_bytes()?.to_vec();
        Ok(Self { encrypted_payload })
    }
}

#[derive(Debug, Clone)]
pub struct HandshakeIdentity {
    pub static_public_key: [u8; 32],
    pub name: String,
    pub signature: [u8; 64],
}

impl HandshakeIdentity {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(32 + 2 + self.name.len() + 64);
        codec::write_raw(&mut buf, &self.static_public_key);
        codec::write_str(&mut buf, &self.name)?;
        codec::write_raw(&mut buf, &self.signature);
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let static_public_key = r.read_array::<32>()?;
        let name = r.read_str()?.to_string();
        let signature = r.read_array::<64>()?;
        Ok(Self {
            static_public_key,
            name,
            signature,
        })
    }
}

#[derive(Debug, Clone)]
pub struct FileRequest {
    pub filename: String,
    pub file_size: u64,
    pub sha256: [u8; 32],
    pub chunk_size: u32,
    pub modified_time: i64,
    pub permissions: u32,
}

impl FileRequest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(2 + self.filename.len() + 8 + 32 + 4 + 8 + 4);
        codec::write_str(&mut buf, &self.filename)?;
        codec::write_u64(&mut buf, self.file_size);
        codec::write_raw(&mut buf, &self.sha256);
        codec::write_u32(&mut buf, self.chunk_size);
        codec::write_i64(&mut buf, self.modified_time);
        codec::write_u32(&mut buf, self.permissions);
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let filename = r.read_str()?.to_string();
        let file_size = r.read_u64()?;
        let sha256 = r.read_array::<32>()?;
        let chunk_size = r.read_u32()?;
        let modified_time = r.read_i64()?;
        let permissions = r.read_u32()?;
        Ok(Self {
            filename,
            file_size,
            sha256,
            chunk_size,
            modified_time,
            permissions,
        })
    }
}

#[derive(Debug, Clone)]
pub struct FileAccept {
    pub accepted: bool,
    pub resume_offset: u64,
    pub reason: String,
}

impl FileAccept {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(1 + 8 + 2 + self.reason.len());
        codec::write_u8(&mut buf, if self.accepted { 1 } else { 0 });
        codec::write_u64(&mut buf, self.resume_offset);
        codec::write_str(&mut buf, &self.reason)?;
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let accepted = r.read_u8()? != 0;
        let resume_offset = r.read_u64()?;
        let reason = r.read_str()?.to_string();
        Ok(Self {
            accepted,
            resume_offset,
            reason,
        })
    }
}

#[derive(Debug, Clone)]
pub struct FileChunk {
    pub offset: u64,
    pub data: Vec<u8>,
    pub blake3_hash: [u8; 32],
}

impl FileChunk {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(8 + 4 + self.data.len() + 32);
        codec::write_u64(&mut buf, self.offset);
        codec::write_bytes(&mut buf, &self.data)?;
        codec::write_raw(&mut buf, &self.blake3_hash);
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let offset = r.read_u64()?;
        let chunk_data = r.read_bytes()?.to_vec();
        let blake3_hash = r.read_array::<32>()?;
        Ok(Self {
            offset,
            data: chunk_data,
            blake3_hash,
        })
    }
}

#[derive(Debug, Clone)]
pub struct FileComplete {
    pub sha256: [u8; 32],
    pub total_bytes: u64,
}

impl FileComplete {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 8);
        codec::write_raw(&mut buf, &self.sha256);
        codec::write_u64(&mut buf, self.total_bytes);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let sha256 = r.read_array::<32>()?;
        let total_bytes = r.read_u64()?;
        Ok(Self {
            sha256,
            total_bytes,
        })
    }
}

#[derive(Debug, Clone)]
pub struct FileAck {
    pub verified: bool,
    pub error_message: String,
}

impl FileAck {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(1 + 2 + self.error_message.len());
        codec::write_u8(&mut buf, if self.verified { 1 } else { 0 });
        codec::write_str(&mut buf, &self.error_message)?;
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let verified = r.read_u8()? != 0;
        let error_message = r.read_str()?.to_string();
        Ok(Self {
            verified,
            error_message,
        })
    }
}

#[derive(Debug, Clone)]
pub struct BatchBegin {
    pub dir_name: String,
    pub file_count: u32,
    pub total_bytes: u64,
}

impl BatchBegin {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(2 + self.dir_name.len() + 4 + 8);
        codec::write_str(&mut buf, &self.dir_name)?;
        codec::write_u32(&mut buf, self.file_count);
        codec::write_u64(&mut buf, self.total_bytes);
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let dir_name = r.read_str()?.to_string();
        let file_count = r.read_u32()?;
        let total_bytes = r.read_u64()?;
        Ok(Self {
            dir_name,
            file_count,
            total_bytes,
        })
    }
}

#[derive(Debug, Clone)]
pub struct BatchEnd {
    pub files_transferred: u32,
    pub total_bytes: u64,
    pub all_verified: bool,
}

impl BatchEnd {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 8 + 1);
        codec::write_u32(&mut buf, self.files_transferred);
        codec::write_u64(&mut buf, self.total_bytes);
        codec::write_u8(&mut buf, if self.all_verified { 1 } else { 0 });
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let files_transferred = r.read_u32()?;
        let total_bytes = r.read_u64()?;
        let all_verified = r.read_u8()? != 0;
        Ok(Self {
            files_transferred,
            total_bytes,
            all_verified,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SasConfirm {
    pub confirmed: bool,
}

impl SasConfirm {
    pub fn encode(&self) -> Vec<u8> {
        vec![if self.confirmed { 0x01 } else { 0x00 }]
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let confirmed = r.read_u8()? != 0;
        Ok(Self { confirmed })
    }
}

#[derive(Debug, Clone)]
pub struct ChunkRetry {
    pub offset: u64,
}

impl ChunkRetry {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8);
        codec::write_u64(&mut buf, self.offset);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let offset = r.read_u64()?;
        Ok(Self { offset })
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    FileRequest(FileRequest),
    FileAccept(FileAccept),
    FileChunk(FileChunk),
    FileComplete(FileComplete),
    FileAck(FileAck),
    BatchBegin(BatchBegin),
    BatchEnd(BatchEnd),
    SasConfirm(SasConfirm),
    ChunkRetry(ChunkRetry),
    Ping,
    Close,
    Cancel,
    PeerError(String),
}

impl Message {
    pub fn encode(&self) -> Result<(u8, Vec<u8>)> {
        match self {
            Self::FileRequest(m) => Ok((record_type::FILE_META, m.encode()?)),
            Self::FileAccept(m) => Ok((record_type::FILE_ACCEPT, m.encode()?)),
            Self::FileChunk(m) => Ok((record_type::DATA, m.encode()?)),
            Self::FileComplete(m) => Ok((record_type::CONTROL, {
                let mut buf = vec![control_type::FILE_COMPLETE];
                buf.extend_from_slice(&m.encode());
                buf
            })),
            Self::FileAck(m) => Ok((record_type::FILE_ACK, m.encode()?)),
            Self::BatchBegin(m) => Ok((record_type::BATCH, {
                let mut buf = vec![batch_type::BEGIN];
                buf.extend_from_slice(&m.encode()?);
                buf
            })),
            Self::BatchEnd(m) => Ok((record_type::BATCH, {
                let mut buf = vec![batch_type::END];
                buf.extend_from_slice(&m.encode());
                buf
            })),
            Self::Ping => Ok((record_type::PING, vec![])),
            Self::Close => Ok((record_type::CLOSE, vec![])),
            Self::Cancel => Ok((record_type::CONTROL, vec![control_type::CANCEL])),
            Self::ChunkRetry(m) => Ok((record_type::CONTROL, {
                let mut buf = vec![control_type::CHUNK_RETRY];
                buf.extend_from_slice(&m.encode());
                buf
            })),
            Self::PeerError(msg) => Ok((record_type::CONTROL, {
                let mut buf = vec![control_type::ERROR];
                codec::write_str(&mut buf, msg)?;
                buf
            })),
            Self::SasConfirm(m) => Ok((record_type::SAS_CONFIRM, m.encode())),
        }
    }

    pub fn decode(record_ty: u8, payload: &[u8]) -> Result<Self> {
        match record_ty {
            record_type::DATA => Ok(Self::FileChunk(FileChunk::decode(payload)?)),
            record_type::CONTROL => {
                if payload.is_empty() {
                    return Err(FenvoyError::InvalidMessage("empty control message".into()));
                }
                match payload[0] {
                    control_type::FILE_COMPLETE => {
                        Ok(Self::FileComplete(FileComplete::decode(&payload[1..])?))
                    }
                    control_type::CLOSE => Ok(Self::Close),
                    control_type::CANCEL => Ok(Self::Cancel),
                    control_type::ERROR => {
                        let error_msg = if payload.len() > 1 {
                            let mut r = Reader::new(&payload[1..]);
                            r.read_str().unwrap_or("unknown error").to_string()
                        } else {
                            "unknown error".to_string()
                        };
                        Ok(Self::PeerError(error_msg))
                    }
                    control_type::CHUNK_RETRY => {
                        Ok(Self::ChunkRetry(ChunkRetry::decode(&payload[1..])?))
                    }
                    control_type::PING => Ok(Self::Ping),
                    _ => Err(FenvoyError::InvalidMessage(format!(
                        "unknown control sub-type: 0x{:02x}",
                        payload[0]
                    ))),
                }
            }
            record_type::FILE_META => Ok(Self::FileRequest(FileRequest::decode(payload)?)),
            record_type::FILE_ACCEPT => Ok(Self::FileAccept(FileAccept::decode(payload)?)),
            record_type::FILE_ACK => Ok(Self::FileAck(FileAck::decode(payload)?)),
            record_type::BATCH => {
                if payload.is_empty() {
                    return Err(FenvoyError::InvalidMessage("empty batch message".into()));
                }
                match payload[0] {
                    batch_type::BEGIN => Ok(Self::BatchBegin(BatchBegin::decode(&payload[1..])?)),
                    batch_type::END => Ok(Self::BatchEnd(BatchEnd::decode(&payload[1..])?)),
                    _ => Err(FenvoyError::InvalidMessage(format!(
                        "unknown batch sub-type: 0x{:02x}",
                        payload[0]
                    ))),
                }
            }
            record_type::PING => Ok(Self::Ping),
            record_type::CLOSE => Ok(Self::Close),
            record_type::SAS_CONFIRM => Ok(Self::SasConfirm(SasConfirm::decode(payload)?)),
            _ => Err(FenvoyError::InvalidMessage(format!(
                "unknown record type: 0x{:02x}",
                record_ty
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_init_roundtrip() {
        let msg = HandshakeInit {
            version: 1,
            x25519_public: [42u8; 32],
            kem_encaps_key: vec![7u8; kem::ENCAPS_KEY_LEN],
        };
        let encoded = msg.encode();
        let decoded = HandshakeInit::decode(&encoded).unwrap();
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.x25519_public, [42u8; 32]);
        assert_eq!(decoded.kem_encaps_key.len(), kem::ENCAPS_KEY_LEN);
    }

    #[test]
    fn handshake_response_roundtrip() {
        let msg = HandshakeResponse {
            x25519_public: [1u8; 32],
            kem_ciphertext: vec![2u8; kem::CIPHERTEXT_LEN],
            encrypted_payload: vec![3u8; 64],
        };
        let encoded = msg.encode().unwrap();
        let decoded = HandshakeResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.x25519_public, [1u8; 32]);
        assert_eq!(decoded.kem_ciphertext.len(), kem::CIPHERTEXT_LEN);
        assert_eq!(decoded.encrypted_payload.len(), 64);
    }

    #[test]
    fn file_request_roundtrip() {
        let msg = FileRequest {
            filename: "test.txt".into(),
            file_size: 1024 * 1024,
            sha256: [0xAA; 32],
            chunk_size: 262144,
            modified_time: 1709337600,
            permissions: 0o644,
        };
        let encoded = msg.encode().unwrap();
        let decoded = FileRequest::decode(&encoded).unwrap();
        assert_eq!(decoded.filename, "test.txt");
        assert_eq!(decoded.file_size, 1024 * 1024);
        assert_eq!(decoded.sha256, [0xAA; 32]);
        assert_eq!(decoded.chunk_size, 262144);
        assert_eq!(decoded.modified_time, 1709337600);
        assert_eq!(decoded.permissions, 0o644);
    }

    #[test]
    fn file_accept_roundtrip() {
        let msg = FileAccept {
            accepted: true,
            resume_offset: 0,
            reason: String::new(),
        };
        let encoded = msg.encode().unwrap();
        let decoded = FileAccept::decode(&encoded).unwrap();
        assert!(decoded.accepted);
        assert_eq!(decoded.resume_offset, 0);
    }

    #[test]
    fn file_chunk_roundtrip() {
        let msg = FileChunk {
            offset: 262144,
            data: vec![0xFF; 100],
            blake3_hash: [0xBB; 32],
        };
        let encoded = msg.encode().unwrap();
        let decoded = FileChunk::decode(&encoded).unwrap();
        assert_eq!(decoded.offset, 262144);
        assert_eq!(decoded.data.len(), 100);
        assert_eq!(decoded.blake3_hash, [0xBB; 32]);
    }

    #[test]
    fn file_complete_roundtrip() {
        let msg = FileComplete {
            sha256: [0xCC; 32],
            total_bytes: 1_000_000,
        };
        let encoded = msg.encode();
        let decoded = FileComplete::decode(&encoded).unwrap();
        assert_eq!(decoded.sha256, [0xCC; 32]);
        assert_eq!(decoded.total_bytes, 1_000_000);
    }

    #[test]
    fn file_ack_roundtrip() {
        let msg = FileAck {
            verified: true,
            error_message: String::new(),
        };
        let encoded = msg.encode().unwrap();
        let decoded = FileAck::decode(&encoded).unwrap();
        assert!(decoded.verified);
    }

    #[test]
    fn message_enum_roundtrip() {
        let req = Message::FileRequest(FileRequest {
            filename: "data.bin".into(),
            file_size: 42,
            sha256: [0; 32],
            chunk_size: 262144,
            modified_time: 0,
            permissions: 0,
        });
        let (rt, payload) = req.encode().unwrap();
        let decoded = Message::decode(rt, &payload).unwrap();
        match decoded {
            Message::FileRequest(r) => assert_eq!(r.filename, "data.bin"),
            _ => panic!("expected FileRequest"),
        }
    }

    #[test]
    fn sas_confirm_roundtrip_confirmed() {
        let msg = SasConfirm { confirmed: true };
        let encoded = msg.encode();
        assert_eq!(encoded, vec![0x01]);
        let decoded = SasConfirm::decode(&encoded).unwrap();
        assert!(decoded.confirmed);
    }

    #[test]
    fn sas_confirm_roundtrip_rejected() {
        let msg = SasConfirm { confirmed: false };
        let encoded = msg.encode();
        assert_eq!(encoded, vec![0x00]);
        let decoded = SasConfirm::decode(&encoded).unwrap();
        assert!(!decoded.confirmed);
    }

    #[test]
    fn sas_confirm_message_enum_roundtrip() {
        let msg = Message::SasConfirm(SasConfirm { confirmed: true });
        let (rt, payload) = msg.encode().unwrap();
        assert_eq!(rt, record_type::SAS_CONFIRM);
        let decoded = Message::decode(rt, &payload).unwrap();
        match decoded {
            Message::SasConfirm(sc) => assert!(sc.confirmed),
            _ => panic!("expected SasConfirm"),
        }
    }

    #[test]
    fn cancel_roundtrip() {
        let msg = Message::Cancel;
        let (rt, payload) = msg.encode().unwrap();
        assert_eq!(rt, record_type::CONTROL);
        assert_eq!(payload, vec![control_type::CANCEL]);
        let decoded = Message::decode(rt, &payload).unwrap();
        assert!(matches!(decoded, Message::Cancel));
    }

    #[test]
    fn peer_error_roundtrip() {
        let msg = Message::PeerError("disk full".into());
        let (rt, payload) = msg.encode().unwrap();
        assert_eq!(rt, record_type::CONTROL);
        assert_eq!(payload[0], control_type::ERROR);
        let decoded = Message::decode(rt, &payload).unwrap();
        match decoded {
            Message::PeerError(e) => assert_eq!(e, "disk full"),
            _ => panic!("expected PeerError"),
        }
    }

    #[test]
    fn peer_error_empty_payload() {
        let payload = vec![control_type::ERROR];
        let decoded = Message::decode(record_type::CONTROL, &payload).unwrap();
        match decoded {
            Message::PeerError(e) => assert_eq!(e, "unknown error"),
            _ => panic!("expected PeerError"),
        }
    }

    #[test]
    fn chunk_retry_roundtrip() {
        let msg = Message::ChunkRetry(ChunkRetry {
            offset: 1024 * 1024,
        });
        let (rt, payload) = msg.encode().unwrap();
        assert_eq!(rt, record_type::CONTROL);
        assert_eq!(payload[0], control_type::CHUNK_RETRY);
        let decoded = Message::decode(rt, &payload).unwrap();
        match decoded {
            Message::ChunkRetry(cr) => assert_eq!(cr.offset, 1024 * 1024),
            _ => panic!("expected ChunkRetry"),
        }
    }
}
