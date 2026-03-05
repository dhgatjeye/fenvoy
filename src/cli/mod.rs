mod config_cmd;
mod daemon;
mod guarded;
mod identity_cmd;
mod identity_ops;
mod output;
mod peers;
mod sas;
mod send;
pub mod strings;
mod terminal;
mod verify;

use crate::error::{FenvoyError, Result};

pub fn run(args: Vec<String>) -> Result<()> {
    if args.len() < 2 {
        println!("{}", strings::USAGE);
        return Ok(());
    }

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    match args[1].as_str() {
        "daemon" | "d" => rt.block_on(daemon::run(&args[2..])),
        "send" | "s" => rt.block_on(send::run(&args[2..])),
        "peers" | "p" => peers::run(&args[2..]),
        "verify" | "v" => verify::run(&args[2..]),
        "config" | "c" => config_cmd::run(),
        "identity" | "id" => identity_cmd::run(&args[2..]),
        "help" | "-h" | "--help" => {
            println!("{}", strings::USAGE);
            Ok(())
        }
        "version" | "-V" | "--version" => {
            println!("fenvoy {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        other => {
            eprintln!("Unknown command: {other}");
            println!("{}", strings::USAGE);
            Err(FenvoyError::InvalidMessage(format!(
                "unknown command: {other}"
            )))
        }
    }
}
