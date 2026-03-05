use super::{output, strings};
use crate::config::Config;
use crate::error::Result;
use crate::peer::store::PeerStore;

pub fn run(_args: &[String]) -> Result<()> {
    let config = Config::default();
    let mut store = PeerStore::new(config.peers_path.clone());
    let _ = store.load();

    let peers = store.list();
    if peers.is_empty() {
        println!("{}", strings::NO_KNOWN_PEERS);
        println!("{}", strings::PEERS_HINT);
        return Ok(());
    }

    output::print_peers_table(&peers);
    Ok(())
}
