use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug)]
pub enum FenvoyError {
    KeyExchangeFailed(String),
    EncryptionFailed(String),
    DecryptionFailed,
    InvalidTag,
    AuthenticationFailed(String),
    KeyDerivationFailed(String),
    InvalidMessage(String),
    ProtocolVersionMismatch {
        expected: u8,
        got: u8,
    },
    HandshakeFailed(String),
    NonceError(String),
    MessageTooLarge {
        size: usize,
        max: usize,
    },
    ConnectionFailed(std::io::Error),
    ConnectionTimeout,
    AddressInUse(SocketAddr),
    UnexpectedEof,
    FileNotFound(PathBuf),
    PermissionDenied(PathBuf),
    ChunkCorrupted {
        offset: u64,
    },
    HashMismatch,
    TransferCancelled,
    SasRejected(String),
    DiskFull,
    TransferRejected(String),
    InvalidFilename(String),
    MulticastJoinFailed(String),
    PeerKeyChanged {
        name: String,
        expected_fingerprint: String,
        actual_fingerprint: String,
    },
    UnknownPeer(String),
    PeerNotFound(String),
    ConfigNotFound(PathBuf),
    ConfigParseError(String),
    Io(std::io::Error),
}

impl fmt::Display for FenvoyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyExchangeFailed(msg) => write!(f, "key exchange failed: {msg}"),
            Self::EncryptionFailed(msg) => write!(f, "encryption failed: {msg}"),
            Self::DecryptionFailed => write!(f, "decryption failed: invalid ciphertext or tag"),
            Self::InvalidTag => write!(f, "invalid authentication tag"),
            Self::AuthenticationFailed(msg) => write!(f, "authentication failed: {msg}"),
            Self::KeyDerivationFailed(msg) => write!(f, "key derivation failed: {msg}"),

            Self::InvalidMessage(msg) => write!(f, "invalid message: {msg}"),
            Self::ProtocolVersionMismatch { expected, got } => {
                write!(
                    f,
                    "protocol version mismatch: expected {expected}, got {got}"
                )
            }
            Self::HandshakeFailed(msg) => write!(f, "handshake failed: {msg}"),
            Self::NonceError(msg) => write!(f, "nonce error: {msg}"),
            Self::MessageTooLarge { size, max } => {
                write!(f, "message too large: {size} bytes (max {max})")
            }

            Self::ConnectionFailed(e) => write!(f, "connection failed: {e}"),
            Self::ConnectionTimeout => write!(f, "connection timed out"),
            Self::AddressInUse(addr) => write!(f, "address already in use: {addr}"),
            Self::UnexpectedEof => write!(f, "unexpected end of stream"),

            Self::FileNotFound(p) => write!(f, "file not found: {}", p.display()),
            Self::PermissionDenied(p) => write!(f, "permission denied: {}", p.display()),
            Self::ChunkCorrupted { offset } => {
                write!(f, "chunk corrupted at offset {offset}")
            }
            Self::HashMismatch => write!(f, "file hash mismatch"),
            Self::TransferCancelled => write!(f, "transfer cancelled"),
            Self::SasRejected(msg) => write!(f, "SAS verification rejected: {msg}"),
            Self::DiskFull => write!(f, "disk full"),
            Self::TransferRejected(reason) => write!(f, "transfer rejected: {reason}"),
            Self::InvalidFilename(msg) => write!(f, "invalid filename: {msg}"),

            Self::MulticastJoinFailed(msg) => write!(f, "multicast join failed: {msg}"),

            Self::PeerKeyChanged {
                name,
                expected_fingerprint,
                actual_fingerprint,
            } => {
                write!(
                    f,
                    "peer key changed for \"{name}\": expected {expected_fingerprint}, got {actual_fingerprint}"
                )
            }
            Self::UnknownPeer(name) => write!(f, "unknown peer: {name}"),
            Self::PeerNotFound(name) => write!(f, "peer not found: {name}"),

            Self::ConfigNotFound(p) => write!(f, "config not found: {}", p.display()),
            Self::ConfigParseError(msg) => write!(f, "config parse error: {msg}"),

            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for FenvoyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConnectionFailed(e) | Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for FenvoyError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, FenvoyError>;
