pub mod codec;
pub mod handshake;
pub mod messages;
pub mod record;

pub const PROTOCOL_VERSION: u8 = 1;

pub const PROTOCOL_LABEL: &[u8] =
    b"fenvoy-handshake-v1-X25519-MLKEM1024-Ed25519-ChaCha20Poly1305-HKDF_SHA256";

pub const DISCOVERY_MAGIC: &[u8; 4] = b"FNVY";
pub const DEFAULT_PORT: u16 = 19527;
pub const DEFAULT_CHUNK_SIZE: u32 = 256 * 1024;
pub const MAX_RECORD_PAYLOAD: usize = 16 * 1024 * 1024;
pub const MAX_FILENAME_LEN: usize = 255;
pub const MAX_CHUNK_RETRIES: u32 = 3;
pub const MAX_BATCH_FILES: u32 = 100_000;
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 30;
pub const IDLE_TIMEOUT_SECS: u64 = 300;
