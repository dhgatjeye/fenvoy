pub const USAGE: &str = "\
fenvoy — Secure peer-to-peer file transfer

USAGE:
    fenvoy <COMMAND> [OPTIONS]

COMMANDS:
    daemon, d [OPTIONS]  Start listener and peer discovery
      --bind, -b <addr>    Bind to a specific address (default: 0.0.0.0:19527)
    send, s <path> <peer>
                       Send a file or directory to a peer (name or address)
    peers, p           List known and discovered peers
    verify, v <peer>   Verify a peer's identity via SAS
    config, c          Show current configuration
    identity, id       Show or generate local identity
      --encrypt          Encrypt an existing key with a password
      --decrypt          Remove password protection from the key
    help               Show this help message
    version            Show version

EXAMPLES:
    fenvoy daemon
    fenvoy send ./report.pdf Alice
    fenvoy send ./my-folder/ Alice
    fenvoy send ./data.zip 192.168.1.42
    fenvoy peers
    fenvoy verify Alice
";

pub const CONFIRM_PASSWORD: &str = "Confirm password: ";
pub const PASSWORDS_MISMATCH: &str = "Passwords do not match. Please try again.";
pub const PROMPT_YES_NO: &str = "Do the SAS words match? (y/n): ";

pub const ENTER_KEY_PASSWORD: &str = "Enter identity key password: ";
pub const WARN_KEY_UNPROTECTED: &str =
    "Warning: Identity key is stored without password protection.";
pub const HINT_ENCRYPT_KEY: &str =
    "  Run 'fenvoy identity --encrypt' to protect it with a password.";
pub const GENERATING_KEY: &str = "Generating new identity key...";
pub const PROMPT_NEW_KEY_PASSWORD: &str =
    "Set a password to protect your identity key (Enter to skip): ";
pub const NOTE_KEY_NO_PASSWORD: &str = "Note: Identity key saved without password protection.";
pub const HINT_ADD_PASSWORD: &str = "  Run 'fenvoy identity --encrypt' to add a password.";
pub const KEY_ENCRYPTED_SAVED: &str = "Identity key encrypted and saved.";

pub const BANNER_TOP: &str = "╔══════════════════════════════════════════════════╗";
pub const BANNER_MID: &str = "║              fenvoy — secure transfer            ║";
pub const BANNER_BOT: &str = "╚══════════════════════════════════════════════════╝";

pub const BIND_REQUIRES_ADDR: &str = "--bind requires an address (e.g. 127.0.0.1:19527)";
pub const DISCOVERY_ENABLED: &str = "  Discovery:   enabled (multicast)";
pub const DISCOVERY_DISABLED: &str = "  Discovery:   disabled";
pub const WAITING_CONNECTIONS: &str = "  Waiting for connections... (Ctrl+C to stop)";

pub const BOX_PREFIX: &str = "  │  ";
pub const BOX_TOP_PREFIX: &str = "  ┌─ ";
pub const BOX_BOTTOM: &str = "  └─";
pub const BOX_SEPARATOR: &str = "  │";

pub const TOFU_SKIP: &str = "✓ Peer previously verified (TOFU). Skipping SAS prompt.";
pub const SAS_REJECTED_REMOTE: &str = "✗ Remote peer rejected SAS.";
pub const SAS_INVALID_RESPONSE: &str = "✗ Invalid SAS response.";
pub const SAS_FAILED_ABORT: &str = "✗ SAS verification failed — connection aborted.";
pub const UNEXPECTED_MESSAGE: &str = "Unexpected message type";

pub const INTEGRITY_OK: &str = "✓ Integrity verified (SHA-256)";
pub const INTEGRITY_FAIL: &str = "✗ Integrity check FAILED";
pub const DIR_INTEGRITY_OK: &str = "✓ All files integrity verified (SHA-256)";
pub const DIR_INTEGRITY_FAIL: &str = "✗ Some files failed integrity check";

pub const SEND_USAGE: &str = "Usage: fenvoy send <file-or-directory> <peer-name-or-address>";
pub const SEND_MISSING_ARGS: &str = "missing arguments";
pub const HANDSHAKE_COMPLETE: &str = "Handshake complete.";
pub const SEND_TOFU_SKIP: &str = "✓ Peer previously verified (TOFU). Skipping SAS prompt.";
pub const SEND_REMOTE_REJECTED: &str = "Remote peer rejected SAS verification.";
pub const SEND_REMOTE_REJECTED_ERR: &str = "remote peer rejected";
pub const EXPECT_SAS_CONFIRM: &str = "expected SasConfirm message";
pub const SEND_SAS_ABORT: &str = "SAS verification failed — connection aborted";

pub const SEND_DIR_VERIFIED: &str = "✓ Remote verified all file integrity";
pub const SEND_DIR_UNVERIFIED: &str = "✗ Remote could not verify integrity for some files";
pub const SEND_FILE_VERIFIED: &str = "✓ Remote verified file integrity";
pub const SEND_FILE_UNVERIFIED: &str = "✗ Remote could not verify integrity";

pub const NO_KNOWN_PEERS: &str = "No known peers.";
pub const PEERS_HINT: &str = "Use 'fenvoy daemon' to discover peers on the network.";
pub const PEERS_COL_NAME: &str = "NAME";
pub const PEERS_COL_FP: &str = "FINGERPRINT";
pub const PEERS_COL_VERIFIED: &str = "VERIFIED";
pub const PEERS_COL_ADDR: &str = "LAST ADDRESS";

pub const VERIFY_USAGE_1: &str = "Usage: fenvoy verify <peer-name> Mark a peer as verified";
pub const VERIFY_USAGE_2: &str =
    "       fenvoy verify <peer-name> --remove  Remove verified status";
pub const VERIFY_MISSING_NAME: &str = "missing peer name";
pub const VERIFY_SAS_HINT_1: &str =
    "Have you compared the SAS words with this peer and confirmed they match?";
pub const VERIFY_SAS_HINT_2: &str =
    "(This should be done during an active connection — see 'fenvoy send')";

pub const SAS_REJECTED_LOCAL: &str = "SAS verification rejected (local).";
pub const SAS_REJECTED_BY_REMOTE: &str = "SAS verification rejected by remote peer.";
pub const SAS_VERIFIED_BOTH: &str = "✓ SAS verified by both peers.";

pub const IDENTITY_USAGE: &str = "Usage: fenvoy identity [--encrypt | --decrypt]";
pub const KEY_ALREADY_ENCRYPTED: &str = "Identity key is already encrypted.";
pub const PROMPT_PROTECT_KEY: &str = "Set a password to protect your identity key: ";
pub const KEY_NOT_ENCRYPTED_ABORT: &str = "No password entered. Identity key was not encrypted.";
pub const KEY_ENCRYPT_SUCCESS: &str = "Identity key encrypted successfully.";
pub const KEY_NOT_ENCRYPTED: &str = "Identity key is not encrypted.";
pub const ENTER_CURRENT_PASSWORD: &str = "Enter current identity key password: ";
pub const KEY_DECRYPT_SUCCESS: &str =
    "Identity key decrypted and saved without password protection.";
pub const WARN_KEY_PLAINTEXT: &str = "Warning: Your identity key is now stored in plaintext.";
