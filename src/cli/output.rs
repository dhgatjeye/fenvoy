use super::strings;
use crate::crypto::identity;
use crate::peer::store::KnownPeer;
use crate::transfer::progress::{format_bytes, format_bytes_per_sec};
use std::net::SocketAddr;

const COL_W_NAME: usize = 20;
const COL_W_FP: usize = 18;
const COL_W_VERIFIED: usize = 10;
const COL_W_ADDR: usize = 20;

pub fn print_banner(name: &str, fingerprint: &[u8], listen_addr: SocketAddr, save_dir: &str) {
    println!("{}", strings::BANNER_TOP);
    println!("{}", strings::BANNER_MID);
    println!("{}", strings::BANNER_BOT);
    println!();
    println!("  Name:        {}", name);
    println!("  Fingerprint: {}", identity::hex_encode(fingerprint));
    println!("  Listen:      {}", listen_addr);
    println!("  Save dir:    {}", save_dir);
}

pub fn print_wildcard_warning(listen_addr: SocketAddr) {
    if listen_addr.ip().is_unspecified() {
        println!();
        println!("  ⚠  Binding to all interfaces ({})", listen_addr.ip());
        println!("     This exposes fenvoy on WAN-facing interfaces.");
        println!(
            "     Use --bind 127.0.0.1:{} for loopback only,",
            listen_addr.port()
        );
        println!(
            "     or --bind <LAN_IP>:{} to restrict to a specific interface.",
            listen_addr.port()
        );
    }
}

pub fn print_connection_header(addr: SocketAddr, name: &str, fingerprint: &[u8], sas: &str) {
    println!("{}Connection from {addr}", strings::BOX_TOP_PREFIX);
    println!("{}Name:        {name}", strings::BOX_PREFIX);
    println!(
        "{}Fingerprint: {}",
        strings::BOX_PREFIX,
        identity::hex_encode(fingerprint)
    );
    println!("{}SAS:         {sas}", strings::BOX_PREFIX);
    println!("{}", strings::BOX_SEPARATOR);
}

pub fn print_box_msg(msg: &str) {
    println!("{}{msg}", strings::BOX_PREFIX);
}

pub fn print_box_close() {
    println!("{}", strings::BOX_BOTTOM);
}

pub fn print_file_received(
    file_name: &str,
    total_bytes: u64,
    elapsed_secs: f64,
    verified: bool,
    saved_path: &str,
) {
    println!(
        "{}Received: {} ({} in {:.1}s)",
        strings::BOX_PREFIX,
        file_name,
        format_bytes(total_bytes),
        elapsed_secs,
    );
    if verified {
        println!("{}{}", strings::BOX_PREFIX, strings::INTEGRITY_OK);
    } else {
        println!("{}{}", strings::BOX_PREFIX, strings::INTEGRITY_FAIL);
    }
    println!("{}Saved to: {}", strings::BOX_PREFIX, saved_path);
    print_box_close();
}

pub fn print_dir_received(
    dir_name: &str,
    files: u32,
    total_bytes: u64,
    elapsed_secs: f64,
    all_verified: bool,
    saved_path: &str,
) {
    println!(
        "{}Received: {} ({} files, {} in {:.1}s)",
        strings::BOX_PREFIX,
        dir_name,
        files,
        format_bytes(total_bytes),
        elapsed_secs,
    );
    if all_verified {
        println!("{}{}", strings::BOX_PREFIX, strings::DIR_INTEGRITY_OK);
    } else {
        println!("{}{}", strings::BOX_PREFIX, strings::DIR_INTEGRITY_FAIL);
    }
    println!("{}Saved to: {}", strings::BOX_PREFIX, saved_path);
    print_box_close();
}

pub fn print_send_file_result(
    file_name: &str,
    total_bytes: u64,
    elapsed_secs: f64,
    verified: bool,
) {
    let bps = total_bytes as f64 / elapsed_secs;
    println!(
        "Transfer complete: {} ({} in {:.1}s, {})",
        file_name,
        format_bytes(total_bytes),
        elapsed_secs,
        format_bytes_per_sec(bps),
    );
    if verified {
        println!("{}", strings::SEND_FILE_VERIFIED);
    } else {
        println!("{}", strings::SEND_FILE_UNVERIFIED);
    }
}

pub fn print_send_dir_result(
    dir_name: &str,
    files: u32,
    total_bytes: u64,
    elapsed_secs: f64,
    all_verified: bool,
) {
    let bps = total_bytes as f64 / elapsed_secs;
    println!(
        "Transfer complete: {} ({} files, {} in {:.1}s, {})",
        dir_name,
        files,
        format_bytes(total_bytes),
        elapsed_secs,
        format_bytes_per_sec(bps),
    );
    if all_verified {
        println!("{}", strings::SEND_DIR_VERIFIED);
    } else {
        println!("{}", strings::SEND_DIR_UNVERIFIED);
    }
}

pub fn print_peers_table(peers: &[&KnownPeer]) {
    println!("Known peers ({}):", peers.len());
    println!();
    println!(
        "  {:COL_W_NAME$} {:COL_W_FP$} {:COL_W_VERIFIED$} {:COL_W_ADDR$}",
        strings::PEERS_COL_NAME,
        strings::PEERS_COL_FP,
        strings::PEERS_COL_VERIFIED,
        strings::PEERS_COL_ADDR,
    );
    println!(
        "  {:COL_W_NAME$} {:COL_W_FP$} {:COL_W_VERIFIED$} {:COL_W_ADDR$}",
        "─".repeat(COL_W_NAME),
        "─".repeat(COL_W_FP),
        "─".repeat(COL_W_VERIFIED),
        "─".repeat(COL_W_ADDR),
    );

    for peer in peers {
        let fp = identity::hex_encode(&peer.fingerprint);
        let verified = if peer.verified { "yes" } else { "no" };
        println!(
            "  {:COL_W_NAME$} {:COL_W_FP$} {:COL_W_VERIFIED$} {:COL_W_ADDR$}",
            peer.name, fp, verified, peer.last_address,
        );
    }
}

pub fn print_discovered(name: &str, fingerprint: &[u8], ip: &str, port: u16) {
    println!(
        "  [+] Discovered: {} ({}) at {}:{}",
        name,
        identity::hex_encode(fingerprint),
        ip,
        port,
    );
}

pub fn print_expired(name: &str) {
    println!("  [-] Expired: {name}");
}
