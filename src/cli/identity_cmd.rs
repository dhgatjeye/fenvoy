use super::{identity_ops, strings};
use crate::config::Config;
use crate::crypto::identity::{self, Identity};
use crate::error::{FenvoyError, Result};

pub fn run(args: &[String]) -> Result<()> {
    let config = Config::default();

    if let Some(flag) = args.first() {
        return match flag.as_str() {
            "--encrypt" => identity_ops::encrypt_identity_key(&config),
            "--decrypt" => identity_ops::decrypt_identity_key(&config),
            other => {
                eprintln!("Unknown identity flag: {other}");
                eprintln!("{}", strings::IDENTITY_USAGE);
                Err(FenvoyError::InvalidMessage(format!(
                    "unknown identity flag: {other}"
                )))
            }
        };
    }

    let id = identity_ops::load_identity(&config)?;

    println!("fenvoy identity:");
    println!();
    println!(
        "  Public key:   {}",
        identity::hex_encode(&id.public_key_bytes())
    );
    println!("  Fingerprint:  {}", id.fingerprint_hex());
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
