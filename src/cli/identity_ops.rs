use super::strings;
use super::terminal;
use crate::config::Config;
use crate::crypto::identity::Identity;
use crate::error::{FenvoyError, Result};

pub fn load_identity(config: &Config) -> Result<Identity> {
    let path = &config.identity_path;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(FenvoyError::Io)?;
    }

    if path.exists() {
        if Identity::is_encrypted_file(path)? {
            let password = terminal::read_password(strings::ENTER_KEY_PASSWORD);
            Identity::load_from_file(path, Some(password.as_bytes()))
        } else {
            eprintln!("{}", strings::WARN_KEY_UNPROTECTED);
            eprintln!("{}", strings::HINT_ENCRYPT_KEY);
            Identity::load_from_file(path, None)
        }
    } else {
        println!("{}", strings::GENERATING_KEY);
        let password = terminal::read_password_confirmed(strings::PROMPT_NEW_KEY_PASSWORD);
        if password.is_empty() {
            let id = Identity::load_or_generate(path, None)?;
            eprintln!("{}", strings::NOTE_KEY_NO_PASSWORD);
            eprintln!("{}", strings::HINT_ADD_PASSWORD);
            Ok(id)
        } else {
            let id = Identity::load_or_generate(path, Some(password.as_bytes()))?;
            println!("{}", strings::KEY_ENCRYPTED_SAVED);
            Ok(id)
        }
    }
}

pub fn encrypt_identity_key(config: &Config) -> Result<()> {
    let path = &config.identity_path;

    if !path.exists() {
        return Err(FenvoyError::ConfigNotFound(path.clone()));
    }

    if Identity::is_encrypted_file(path)? {
        println!("{}", strings::KEY_ALREADY_ENCRYPTED);
        return Ok(());
    }

    let identity = Identity::load_from_file(path, None)?;
    let password = terminal::read_password_confirmed(strings::PROMPT_PROTECT_KEY);

    if password.is_empty() {
        eprintln!("{}", strings::KEY_NOT_ENCRYPTED_ABORT);
        return Ok(());
    }

    identity.save_encrypted(path, password.as_bytes())?;
    println!("{}", strings::KEY_ENCRYPT_SUCCESS);
    Ok(())
}

pub fn decrypt_identity_key(config: &Config) -> Result<()> {
    let path = &config.identity_path;

    if !path.exists() {
        return Err(FenvoyError::ConfigNotFound(path.clone()));
    }

    if !Identity::is_encrypted_file(path)? {
        println!("{}", strings::KEY_NOT_ENCRYPTED);
        return Ok(());
    }

    let password = terminal::read_password(strings::ENTER_CURRENT_PASSWORD);
    let identity = Identity::load_from_file(path, Some(password.as_bytes()))?;

    identity.save_to_file(path)?;
    println!("{}", strings::KEY_DECRYPT_SUCCESS);
    eprintln!("{}", strings::WARN_KEY_PLAINTEXT);
    Ok(())
}
