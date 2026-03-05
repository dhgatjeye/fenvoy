use super::{identity_ops, strings, terminal};
use crate::config::Config;
use crate::crypto::identity;
use crate::error::{FenvoyError, Result};
use crate::peer::store::PeerStore;

pub fn run(args: &[String]) -> Result<()> {
    if args.is_empty() {
        eprintln!("{}", strings::VERIFY_USAGE_1);
        eprintln!("{}", strings::VERIFY_USAGE_2);
        return Err(FenvoyError::InvalidMessage(
            strings::VERIFY_MISSING_NAME.into(),
        ));
    }

    let config = Config::default();
    let id = identity_ops::load_identity(&config)?;
    let peers_hmac_key = id.derive_peers_key()?;

    let mut store = PeerStore::with_hmac_key(config.peers_path.clone(), *peers_hmac_key);
    let _ = store.load();

    let name = &args[0];
    let remove_flag = args.get(1).map(|a| a.as_str()) == Some("--remove");

    let peer = store
        .get_by_name(name)
        .ok_or_else(|| FenvoyError::PeerNotFound(name.to_string()))?
        .clone();

    if remove_flag {
        remove_verified(&mut store, &peer)?;
    } else if peer.verified {
        already_verified(&peer);
    } else {
        mark_verified(&mut store, &peer)?;
    }

    Ok(())
}

fn remove_verified(store: &mut PeerStore, peer: &crate::peer::store::KnownPeer) -> Result<()> {
    if !peer.verified {
        println!("Peer '{}' is not verified. Nothing to remove.", peer.name);
        return Ok(());
    }

    println!("Peer:        {}", peer.name);
    println!("Fingerprint: {}", identity::hex_encode(&peer.fingerprint));
    println!();
    print!("Remove verified status? (y/n): ");

    if terminal::prompt_yes_no() {
        store.set_verified(&peer.name, false);
        store.save()?;
        println!("✓ Verified status removed for '{}'.", peer.name);
    } else {
        println!("Cancelled.");
    }
    Ok(())
}

fn already_verified(peer: &crate::peer::store::KnownPeer) {
    println!("Peer '{}' is already verified.", peer.name);
    println!("Fingerprint: {}", identity::hex_encode(&peer.fingerprint));
    println!();
    println!(
        "Use 'fenvoy verify {} --remove' to remove verified status.",
        peer.name
    );
}

fn mark_verified(store: &mut PeerStore, peer: &crate::peer::store::KnownPeer) -> Result<()> {
    println!("Peer:        {}", peer.name);
    println!("Fingerprint: {}", identity::hex_encode(&peer.fingerprint));
    println!();
    println!("{}", strings::VERIFY_SAS_HINT_1);
    println!("{}", strings::VERIFY_SAS_HINT_2);
    println!();
    print!("Mark '{}' as verified? (y/n): ", peer.name);

    if terminal::prompt_yes_no() {
        store.set_verified(&peer.name, true);
        store.save()?;
        println!("✓ Peer '{}' is now verified.", peer.name);
    } else {
        println!("Cancelled. Peer remains unverified.");
    }
    Ok(())
}
