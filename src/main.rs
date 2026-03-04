use fenvoy::config::Config;
use fenvoy::crypto::identity::Identity;
use fenvoy::discovery::multicast::{DiscoveryConfig, DiscoveryService};
use fenvoy::discovery::{DiscoveryEvent, capabilities};
use fenvoy::error::{FenvoyError, Result};
use fenvoy::peer::store::PeerStore;
use fenvoy::peer::verification;
use fenvoy::protocol::handshake;
use fenvoy::transfer::dir_receiver;
use fenvoy::transfer::dir_sender;
use fenvoy::transfer::progress::ProgressTracker;
use fenvoy::transfer::sender;
use fenvoy::transport::listener::{ConnectionListener, ListenerConfig};
use fenvoy::transport::tcp;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    let result = match args[1].as_str() {
        "daemon" | "d" => rt.block_on(cmd_daemon(&args[2..])),
        "send" | "s" => rt.block_on(cmd_send(&args[2..])),
        "peers" | "p" => cmd_peers(&args[2..]),
        "verify" | "v" => cmd_verify(&args[2..]),
        "config" | "c" => cmd_config(),
        "identity" | "id" => cmd_identity(&args[2..]),
        "help" | "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        "version" | "-V" | "--version" => {
            println!("fenvoy {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        other => {
            eprintln!("Unknown command: {other}");
            print_usage();
            Err(FenvoyError::InvalidMessage(format!(
                "unknown command: {other}"
            )))
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn print_usage() {
    println!(
        "\
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
"
    );
}

fn read_password(prompt: &str) -> String {
    use std::io::{self, Write};
    eprint!("{prompt}");
    io::stderr().flush().ok();
    let pw = read_line_no_echo();
    eprintln!();
    pw
}

fn read_password_confirmed(prompt: &str) -> String {
    loop {
        let pw1 = read_password(prompt);
        if pw1.is_empty() {
            return pw1;
        }
        let pw2 = read_password("Confirm password: ");
        if pw1 == pw2 {
            return pw1;
        }
        eprintln!("Passwords do not match. Please try again.");
    }
}

#[cfg(windows)]
fn read_line_no_echo() -> String {
    use std::io::{self, BufRead};

    #[allow(non_snake_case)]
    unsafe extern "system" {
        fn GetStdHandle(nStdHandle: u32) -> *mut core::ffi::c_void;
        fn GetConsoleMode(hConsoleHandle: *mut core::ffi::c_void, lpMode: *mut u32) -> i32;
        fn SetConsoleMode(hConsoleHandle: *mut core::ffi::c_void, dwMode: u32) -> i32;
    }

    const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6;
    const ENABLE_ECHO_INPUT: u32 = 0x0004;

    let (handle, original_mode) = unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode: u32 = 0;
        GetConsoleMode(h, &mut mode);
        let orig = mode;
        SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT);
        (h, orig)
    };

    let mut input = String::new();
    let _ = io::stdin().lock().read_line(&mut input);

    unsafe {
        SetConsoleMode(handle, original_mode);
    }

    input.trim_end().to_string()
}

#[cfg(unix)]
fn read_line_no_echo() -> String {
    use std::io::{self, BufRead};

    let _ = std::process::Command::new("stty").arg("-echo").status();

    let mut input = String::new();
    let _ = io::stdin().lock().read_line(&mut input);

    let _ = std::process::Command::new("stty").arg("echo").status();

    input.trim_end().to_string()
}

#[cfg(not(any(windows, unix)))]
fn read_line_no_echo() -> String {
    use std::io::{self, BufRead};
    let mut input = String::new();
    let _ = io::stdin().lock().read_line(&mut input);
    input.trim_end().to_string()
}

fn load_identity(config: &Config) -> Result<Identity> {
    let path = &config.identity_path;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(FenvoyError::Io)?;
    }

    if path.exists() {
        if Identity::is_encrypted_file(path)? {
            let password = read_password("Enter identity key password: ");
            Identity::load_from_file(path, Some(password.as_bytes()))
        } else {
            eprintln!("Warning: Identity key is stored without password protection.");
            eprintln!("  Run 'fenvoy identity --encrypt' to protect it with a password.");
            Identity::load_from_file(path, None)
        }
    } else {
        println!("Generating new identity key...");
        let password = read_password_confirmed(
            "Set a password to protect your identity key (Enter to skip): ",
        );
        if password.is_empty() {
            let id = Identity::load_or_generate(path, None)?;
            eprintln!("Note: Identity key saved without password protection.");
            eprintln!("  Run 'fenvoy identity --encrypt' to add a password.");
            Ok(id)
        } else {
            let id = Identity::load_or_generate(path, Some(password.as_bytes()))?;
            println!("Identity key encrypted and saved.");
            Ok(id)
        }
    }
}

async fn cmd_daemon(args: &[String]) -> Result<()> {
    let mut config = Config::default();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" | "-b" => {
                i += 1;
                let addr_str = args.get(i).ok_or_else(|| {
                    FenvoyError::InvalidMessage(
                        "--bind requires an address (e.g. 127.0.0.1:19527)".into(),
                    )
                })?;
                config.listen_addr = addr_str.parse::<SocketAddr>().map_err(|e| {
                    FenvoyError::InvalidMessage(format!("invalid bind address '{addr_str}': {e}"))
                })?;
            }
            other => {
                return Err(FenvoyError::InvalidMessage(format!(
                    "unknown daemon flag: {other}"
                )));
            }
        }
        i += 1;
    }

    let identity = load_identity(&config)?;
    let fingerprint = identity.fingerprint();

    let resume_hmac_key = identity.derive_resume_key()?;

    let peers_hmac_key = identity.derive_peers_key()?;

    let identity = Arc::new(identity);

    println!("╔══════════════════════════════════════════════════╗");
    println!("║              fenvoy — secure transfer            ║");
    println!("╚══════════════════════════════════════════════════╝");
    println!();
    println!("  Name:        {}", config.peer_name);
    println!(
        "  Fingerprint: {}",
        fenvoy::crypto::identity::hex_encode(&fingerprint)
    );
    println!("  Listen:      {}", config.listen_addr);
    println!("  Save dir:    {}", config.save_dir.display());

    if config.listen_addr.ip().is_unspecified() {
        println!();
        println!(
            "  ⚠  Binding to all interfaces ({})",
            config.listen_addr.ip()
        );
        println!("     This exposes fenvoy on WAN-facing interfaces.");
        println!(
            "     Use --bind 127.0.0.1:{} for loopback only,",
            config.listen_addr.port()
        );
        println!(
            "     or --bind <LAN_IP>:{} to restrict to a specific interface.",
            config.listen_addr.port()
        );
    }
    println!();

    std::fs::create_dir_all(&config.save_dir).map_err(FenvoyError::Io)?;

    let _discovery = if config.discovery_enabled {
        let disc_config = DiscoveryConfig {
            local_name: config.peer_name.clone(),
            tcp_port: config.listen_addr.port(),
            fingerprint,
            capabilities: capabilities::BOTH,
            signing_key: identity.signing_key_bytes(),
            public_key: identity.public_key_bytes(),
        };

        let service = DiscoveryService::start(disc_config)?;
        let mut rx = service.subscribe();

        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(DiscoveryEvent::PeerDiscovered(peer)) => {
                        println!(
                            "  [+] Discovered: {} ({}) at {}:{}",
                            peer.name,
                            fenvoy::crypto::identity::hex_encode(&peer.fingerprint),
                            peer.addr.ip(),
                            peer.tcp_port
                        );
                    }
                    Ok(DiscoveryEvent::PeerUpdated(_)) => {}
                    Ok(DiscoveryEvent::PeerExpired { name, .. }) => {
                        println!("  [-] Expired: {name}");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                }
            }
        });

        println!("  Discovery:   enabled (multicast)");
        Some(service)
    } else {
        println!("  Discovery:   disabled");
        None
    };

    let listener_config = ListenerConfig {
        bind_addr: config.listen_addr,
        local_name: config.peer_name.clone(),
        identity: identity.clone(),
    };

    let listener = ConnectionListener::bind(listener_config).await?;
    let bound = listener.local_addr()?;
    println!("  Listening:   {bound}");
    println!();
    println!("  Waiting for connections... (Ctrl+C to stop)");
    println!();

    loop {
        match listener.accept_one().await {
            Ok((hs_result, addr)) => {
                let sas = verification::format_sas(&hs_result.sas_bytes);
                let remote_fp =
                    fenvoy::crypto::identity::fingerprint_of(&hs_result.remote_static_key);
                println!("  ┌─ Connection from {addr}");
                println!("  │  Name:        {}", hs_result.remote_name);
                println!(
                    "  │  Fingerprint: {}",
                    fenvoy::crypto::identity::hex_encode(&remote_fp)
                );
                println!("  │  SAS:         {sas}");
                println!("  │");

                let mut store =
                    PeerStore::with_hmac_key(config.peers_path.clone(), *peers_hmac_key);
                let already_verified = store.load().is_ok()
                    && store
                        .get_by_public_key(&hs_result.remote_static_key)
                        .is_some_and(|p| p.verified);

                let save_dir = config.save_dir.clone();
                let auto_accept = config.auto_accept;
                let max_file_size = config.max_file_size;
                let resume_hmac_key = *resume_hmac_key;
                let peers_hmac_key = *peers_hmac_key;
                let peers_path = config.peers_path.clone();
                let remote_name = hs_result.remote_name.clone();
                let remote_key = hs_result.remote_static_key;

                tokio::spawn(async move {
                    let mut channel = hs_result.channel;

                    let sas_ok = if already_verified {
                        println!("  │  ✓ Peer previously verified (TOFU). Skipping SAS prompt.");

                        let msg = fenvoy::protocol::messages::Message::SasConfirm(
                            fenvoy::protocol::messages::SasConfirm { confirmed: true },
                        );
                        let (rt, payload) =
                            msg.encode().expect("SasConfirm encoding is infallible");
                        if let Err(e) = channel.send_record(rt, &payload).await {
                            println!("  │  SAS exchange error: {e}");
                            println!("  └─");
                            return;
                        }

                        match channel
                            .recv_record_with_timeout(std::time::Duration::from_secs(60))
                            .await
                        {
                            Ok((rt, payload)) => {
                                match fenvoy::protocol::messages::Message::decode(rt, &payload) {
                                    Ok(fenvoy::protocol::messages::Message::SasConfirm(sc)) => {
                                        if !sc.confirmed {
                                            println!("  │  ✗ Remote peer rejected SAS.");
                                            println!("  └─");
                                            return;
                                        }
                                        true
                                    }
                                    _ => {
                                        println!("  │  ✗ Invalid SAS response.");
                                        println!("  └─");
                                        return;
                                    }
                                }
                            }
                            Err(e) => {
                                println!("  │  SAS exchange error: {e}");
                                println!("  └─");
                                return;
                            }
                        }
                    } else {
                        match sas_exchange(&mut channel).await {
                            Ok(confirmed) => confirmed,
                            Err(e) => {
                                println!("  │  SAS exchange error: {e}");
                                println!("  └─");
                                return;
                            }
                        }
                    };

                    if !sas_ok {
                        println!("  │  ✗ SAS verification failed — connection aborted.");
                        println!("  └─");
                        return;
                    }

                    let mut store = PeerStore::with_hmac_key(peers_path, peers_hmac_key);
                    let _ = store.locked_update(|s| {
                        s.upsert(&remote_name, &remote_key, &addr.to_string(), true)
                    });

                    let mut progress = ProgressTracker::new();

                    let idle = std::time::Duration::from_secs(fenvoy::protocol::IDLE_TIMEOUT_SECS);
                    let (rt, payload) = match channel.recv_record_with_timeout(idle).await {
                        Ok(v) => v,
                        Err(e) => {
                            println!("  │  Transfer error: {e}");
                            println!("  └─");
                            return;
                        }
                    };

                    let first_msg = match fenvoy::protocol::messages::Message::decode(rt, &payload)
                    {
                        Ok(m) => m,
                        Err(e) => {
                            println!("  │  Protocol error: {e}");
                            println!("  └─");
                            return;
                        }
                    };

                    match first_msg {
                        fenvoy::protocol::messages::Message::FileRequest(request) => {
                            let accept_fn: Option<fenvoy::transfer::AcceptFn> = if auto_accept {
                                None
                            } else {
                                Some(Box::new(|filename: &str, file_size: u64| {
                                    use std::io::{self, Write};
                                    println!(
                                        "  │  Incoming file: {} ({})",
                                        filename,
                                        fenvoy::transfer::progress::format_bytes(file_size),
                                    );
                                    print!("  │  Accept? (y/n): ");
                                    io::stdout().flush().ok();
                                    let mut input = String::new();
                                    if io::stdin().read_line(&mut input).is_ok() {
                                        let answer = input.trim().to_lowercase();
                                        answer == "y" || answer == "yes"
                                    } else {
                                        false
                                    }
                                }))
                            };

                            match fenvoy::transfer::receiver::receive_file_from_request(
                                &mut channel,
                                &save_dir,
                                &mut progress,
                                accept_fn,
                                max_file_size,
                                &resume_hmac_key,
                                request,
                            )
                            .await
                            {
                                Ok(result) => {
                                    println!(
                                        "  │  Received: {} ({} in {:.1}s)",
                                        result.file_name,
                                        fenvoy::transfer::progress::format_bytes(
                                            result.total_bytes
                                        ),
                                        result.elapsed.as_secs_f64(),
                                    );
                                    if result.verified {
                                        println!("  │  ✓ Integrity verified (SHA-256)");
                                    } else {
                                        println!("  │  ✗ Integrity check FAILED");
                                    }
                                    println!("  │  Saved to: {}", result.path.display());
                                    println!("  └─");
                                }
                                Err(e) => {
                                    println!("  │  Transfer error: {e}");
                                    println!("  └─");
                                }
                            }
                        }
                        fenvoy::protocol::messages::Message::BatchBegin(batch_begin) => {
                            println!(
                                "  │  Directory: {} ({} files, {})",
                                batch_begin.dir_name,
                                batch_begin.file_count,
                                fenvoy::transfer::progress::format_bytes(batch_begin.total_bytes),
                            );

                            match dir_receiver::receive_directory(
                                &mut channel,
                                &save_dir,
                                &mut progress,
                                batch_begin,
                                max_file_size,
                                &resume_hmac_key,
                            )
                            .await
                            {
                                Ok(result) => {
                                    println!(
                                        "  │  Received: {} ({} files, {} in {:.1}s)",
                                        result.dir_name,
                                        result.files_transferred,
                                        fenvoy::transfer::progress::format_bytes(
                                            result.total_bytes
                                        ),
                                        result.elapsed.as_secs_f64(),
                                    );
                                    if result.all_verified {
                                        println!("  │  ✓ All files integrity verified (SHA-256)");
                                    } else {
                                        println!("  │  ✗ Some files failed integrity check");
                                    }
                                    println!("  │  Saved to: {}", save_dir.display());
                                    println!("  └─");
                                }
                                Err(e) => {
                                    println!("  │  Transfer error: {e}");
                                    println!("  └─");
                                }
                            }
                        }
                        _ => {
                            println!("  │  Unexpected message type");
                            println!("  └─");
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!("  Accept error: {e}");
            }
        }
    }
}

async fn cmd_send(args: &[String]) -> Result<()> {
    if args.len() < 2 {
        eprintln!("Usage: fenvoy send <file-or-directory> <peer-name-or-address>");
        return Err(FenvoyError::InvalidMessage("missing arguments".into()));
    }

    let file_path = PathBuf::from(&args[0]);
    let target = &args[1];

    if !file_path.exists() {
        return Err(FenvoyError::FileNotFound(file_path));
    }

    let config = Config::default();

    let identity = load_identity(&config)?;

    let peers_hmac_key = identity.derive_peers_key()?;

    let addr: SocketAddr = if let Ok(addr) = target.parse::<SocketAddr>() {
        addr
    } else {
        let mut store = PeerStore::with_hmac_key(config.peers_path.clone(), *peers_hmac_key);
        let _ = store.load();

        if let Some(peer) = store.get_by_name(target) {
            peer.last_address
                .parse()
                .map_err(|_| FenvoyError::PeerNotFound(target.to_string()))?
        } else {
            let with_port = if target.contains(':') {
                target.to_string()
            } else {
                format!("{target}:{}", fenvoy::protocol::DEFAULT_PORT)
            };

            use std::net::ToSocketAddrs;
            with_port
                .to_socket_addrs()
                .map_err(|_| FenvoyError::PeerNotFound(target.to_string()))?
                .next()
                .ok_or_else(|| FenvoyError::PeerNotFound(target.to_string()))?
        }
    };

    println!("Connecting to {addr}...");

    let stream = tcp::connect(addr).await?;
    println!("Connected. Performing handshake...");

    let hs_result = handshake::initiate(stream, &config.peer_name, &identity).await?;

    let sas = verification::format_sas(&hs_result.sas_bytes);
    let remote_fp = fenvoy::crypto::identity::fingerprint_of(&hs_result.remote_static_key);
    println!("Handshake complete.");
    println!("  Remote:      {}", hs_result.remote_name);
    println!(
        "  Fingerprint: {}",
        fenvoy::crypto::identity::hex_encode(&remote_fp)
    );
    println!("  SAS:         {sas}");
    println!();

    let mut store = PeerStore::with_hmac_key(config.peers_path.clone(), *peers_hmac_key);
    let already_verified = store.load().is_ok()
        && store
            .get_by_public_key(&hs_result.remote_static_key)
            .is_some_and(|p| p.verified);

    let mut channel = hs_result.channel;

    let sas_ok = if already_verified {
        println!("✓ Peer previously verified (TOFU). Skipping SAS prompt.");

        let msg = fenvoy::protocol::messages::Message::SasConfirm(
            fenvoy::protocol::messages::SasConfirm { confirmed: true },
        );
        let (rt, payload) = msg.encode()?;
        channel.send_record(rt, &payload).await?;

        let (remote_rt, remote_payload) = channel
            .recv_record_with_timeout(std::time::Duration::from_secs(60))
            .await?;

        let remote_msg = fenvoy::protocol::messages::Message::decode(remote_rt, &remote_payload)?;
        match remote_msg {
            fenvoy::protocol::messages::Message::SasConfirm(sc) => {
                if !sc.confirmed {
                    println!("Remote peer rejected SAS verification.");
                    return Err(FenvoyError::SasRejected("remote peer rejected".into()));
                }
                true
            }
            _ => {
                return Err(FenvoyError::InvalidMessage(
                    "expected SasConfirm message".into(),
                ));
            }
        }
    } else {
        sas_exchange(&mut channel).await?
    };

    if !sas_ok {
        return Err(FenvoyError::SasRejected(
            "SAS verification failed — connection aborted".into(),
        ));
    }

    let mut progress = ProgressTracker::new();

    if file_path.is_dir() {
        println!("Sending directory: {}", file_path.display());

        let result = dir_sender::send_directory(&mut channel, &file_path, &mut progress).await?;

        println!(
            "Transfer complete: {} ({} files, {} in {:.1}s, {})",
            result.dir_name,
            result.files_transferred,
            fenvoy::transfer::progress::format_bytes(result.total_bytes),
            result.elapsed.as_secs_f64(),
            fenvoy::transfer::progress::format_bytes_per_sec(
                result.total_bytes as f64 / result.elapsed.as_secs_f64()
            ),
        );

        if result.all_verified {
            println!("✓ Remote verified all file integrity");
        } else {
            println!("✗ Remote could not verify integrity for some files");
        }
    } else {
        println!("Sending: {}", file_path.display());

        let result = sender::send_file(&mut channel, &file_path, &mut progress).await?;

        println!(
            "Transfer complete: {} ({} in {:.1}s, {})",
            result.file_name,
            fenvoy::transfer::progress::format_bytes(result.total_bytes),
            result.elapsed.as_secs_f64(),
            fenvoy::transfer::progress::format_bytes_per_sec(
                result.total_bytes as f64 / result.elapsed.as_secs_f64()
            ),
        );

        if result.verified {
            println!("✓ Remote verified file integrity");
        } else {
            println!("✗ Remote could not verify integrity");
        }
    }

    {
        let mut store = PeerStore::with_hmac_key(config.peers_path.clone(), *peers_hmac_key);
        let _ = store.locked_update(|s| {
            s.upsert(
                &hs_result.remote_name,
                &hs_result.remote_static_key,
                &addr.to_string(),
                true,
            )
        });
    }

    Ok(())
}

fn cmd_peers(_args: &[String]) -> Result<()> {
    let config = Config::default();
    let mut store = PeerStore::new(config.peers_path.clone());
    let _ = store.load();

    let peers = store.list();
    if peers.is_empty() {
        println!("No known peers.");
        println!("Use 'fenvoy daemon' to discover peers on the network.");
        return Ok(());
    }

    println!("Known peers ({}):", peers.len());
    println!();
    println!(
        "  {:20} {:18} {:10} {:20}",
        "NAME", "FINGERPRINT", "VERIFIED", "LAST ADDRESS"
    );
    println!(
        "  {:20} {:18} {:10} {:20}",
        "─".repeat(20),
        "─".repeat(18),
        "─".repeat(10),
        "─".repeat(20)
    );

    for peer in peers {
        let fp = fenvoy::crypto::identity::hex_encode(&peer.fingerprint);
        let verified = if peer.verified { "yes" } else { "no" };
        println!(
            "  {:20} {:18} {:10} {:20}",
            peer.name, fp, verified, peer.last_address
        );
    }

    Ok(())
}

fn cmd_verify(args: &[String]) -> Result<()> {
    if args.is_empty() {
        eprintln!("Usage: fenvoy verify <peer-name>          Mark a peer as verified");
        eprintln!("       fenvoy verify <peer-name> --remove  Remove verified status");
        return Err(FenvoyError::InvalidMessage("missing peer name".into()));
    }

    let config = Config::default();

    let identity = load_identity(&config)?;
    let peers_hmac_key = identity.derive_peers_key()?;

    let mut store = PeerStore::with_hmac_key(config.peers_path.clone(), *peers_hmac_key);
    let _ = store.load();

    let name = &args[0];
    let remove_flag = args.get(1).map(|a| a.as_str()) == Some("--remove");

    let peer = store
        .get_by_name(name)
        .ok_or_else(|| FenvoyError::PeerNotFound(name.to_string()))?
        .clone();

    if remove_flag {
        if !peer.verified {
            println!("Peer '{}' is not verified. Nothing to remove.", peer.name);
            return Ok(());
        }

        println!("Peer:        {}", peer.name);
        println!(
            "Fingerprint: {}",
            fenvoy::crypto::identity::hex_encode(&peer.fingerprint)
        );
        println!();
        print!("Remove verified status? (y/n): ");

        if prompt_yes_no() {
            store.set_verified(name, false);
            store.save()?;
            println!("✓ Verified status removed for '{}'.", peer.name);
        } else {
            println!("Cancelled.");
        }
    } else if peer.verified {
        println!("Peer '{}' is already verified.", peer.name);
        println!(
            "Fingerprint: {}",
            fenvoy::crypto::identity::hex_encode(&peer.fingerprint)
        );
        println!();
        println!(
            "Use 'fenvoy verify {} --remove' to remove verified status.",
            peer.name
        );
    } else {
        println!("Peer:        {}", peer.name);
        println!(
            "Fingerprint: {}",
            fenvoy::crypto::identity::hex_encode(&peer.fingerprint)
        );
        println!();
        println!("Have you compared the SAS words with this peer and confirmed they match?");
        println!("(This should be done during an active connection — see 'fenvoy send')");
        println!();
        print!("Mark '{}' as verified? (y/n): ", peer.name);

        if prompt_yes_no() {
            store.set_verified(name, true);
            store.save()?;
            println!("✓ Peer '{}' is now verified.", peer.name);
        } else {
            println!("Cancelled. Peer remains unverified.");
        }
    }

    Ok(())
}

fn prompt_yes_no() -> bool {
    use std::io::{self, Write};
    io::stdout().flush().ok();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() {
        let answer = input.trim().to_lowercase();
        answer == "y" || answer == "yes"
    } else {
        false
    }
}

async fn sas_exchange<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    channel: &mut fenvoy::protocol::record::SecureChannel<S>,
) -> Result<bool> {
    use fenvoy::protocol::messages::{Message, SasConfirm};

    let local_confirmed = tokio::task::spawn_blocking(|| {
        use std::io::{self, Write};
        print!("Do the SAS words match? (y/n): ");
        io::stdout().flush().ok();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            let answer = input.trim().to_lowercase();
            answer == "y" || answer == "yes"
        } else {
            false
        }
    })
    .await
    .unwrap_or(false);

    let msg = Message::SasConfirm(SasConfirm {
        confirmed: local_confirmed,
    });
    let (rt, payload) = msg.encode()?;
    channel.send_record(rt, &payload).await?;

    let (remote_rt, remote_payload) = channel
        .recv_record_with_timeout(std::time::Duration::from_secs(60))
        .await?;

    let remote_msg = Message::decode(remote_rt, &remote_payload)?;
    let remote_confirmed = match remote_msg {
        Message::SasConfirm(sc) => sc.confirmed,
        _ => {
            return Err(FenvoyError::InvalidMessage(
                "expected SasConfirm message".into(),
            ));
        }
    };

    if !local_confirmed {
        println!("SAS verification rejected (local).");
        return Ok(false);
    }
    if !remote_confirmed {
        println!("SAS verification rejected by remote peer.");
        return Ok(false);
    }

    println!("✓ SAS verified by both peers.");
    Ok(true)
}

fn cmd_config() -> Result<()> {
    let config = Config::default();

    println!("fenvoy configuration:");
    println!();
    println!("  Peer name:    {}", config.peer_name);
    println!("  Listen:       {}", config.listen_addr);
    println!("  Save dir:     {}", config.save_dir.display());
    println!("  Identity:     {}", config.identity_path.display());
    println!("  Peers DB:     {}", config.peers_path.display());
    println!("  Chunk size:   {} bytes", config.chunk_size);
    println!("  Auto-accept:  {}", config.auto_accept);
    println!("  Discovery:    {}", config.discovery_enabled);

    Ok(())
}

fn cmd_identity(args: &[String]) -> Result<()> {
    let config = Config::default();

    if let Some(flag) = args.first() {
        return match flag.as_str() {
            "--encrypt" => encrypt_identity_key(&config),
            "--decrypt" => decrypt_identity_key(&config),
            other => {
                eprintln!("Unknown identity flag: {other}");
                eprintln!("Usage: fenvoy identity [--encrypt | --decrypt]");
                Err(FenvoyError::InvalidMessage(format!(
                    "unknown identity flag: {other}"
                )))
            }
        };
    }

    let identity = load_identity(&config)?;

    println!("fenvoy identity:");
    println!();
    println!(
        "  Public key:   {}",
        fenvoy::crypto::identity::hex_encode(&identity.public_key_bytes())
    );
    println!("  Fingerprint:  {}", identity.fingerprint_hex());
    println!("  Key file:     {}", config.identity_path.display());

    if config.identity_path.exists() {
        let encrypted = Identity::is_encrypted_file(&config.identity_path)?;
        println!(
            "  Protected:    {}",
            if encrypted { "yes (password)" } else { "no" }
        );
    }

    Ok(())
}

fn encrypt_identity_key(config: &Config) -> Result<()> {
    let path = &config.identity_path;

    if !path.exists() {
        return Err(FenvoyError::ConfigNotFound(path.clone()));
    }

    if Identity::is_encrypted_file(path)? {
        println!("Identity key is already encrypted.");
        return Ok(());
    }

    let identity = Identity::load_from_file(path, None)?;

    let password = read_password_confirmed("Set a password to protect your identity key: ");

    if password.is_empty() {
        eprintln!("No password entered. Identity key was not encrypted.");
        return Ok(());
    }

    identity.save_encrypted(path, password.as_bytes())?;
    println!("Identity key encrypted successfully.");

    Ok(())
}

fn decrypt_identity_key(config: &Config) -> Result<()> {
    let path = &config.identity_path;

    if !path.exists() {
        return Err(FenvoyError::ConfigNotFound(path.clone()));
    }

    if !Identity::is_encrypted_file(path)? {
        println!("Identity key is not encrypted.");
        return Ok(());
    }

    let password = read_password("Enter current identity key password: ");
    let identity = Identity::load_from_file(path, Some(password.as_bytes()))?;

    identity.save_to_file(path)?;
    println!("Identity key decrypted and saved without password protection.");
    eprintln!("Warning: Your identity key is now stored in plaintext.");

    Ok(())
}
