use crate::config::Config;
use crate::error::Result;

pub fn run() -> Result<()> {
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
