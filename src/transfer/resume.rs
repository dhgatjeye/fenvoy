use crate::error::{FenvoyError, Result};
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;

use std::path::{Path, PathBuf};

fn resume_path(save_dir: &Path, filename: &str) -> PathBuf {
    save_dir.join(format!("{filename}.fenvoy.partial"))
}

fn compute_hmac(hmac_key: &[u8; 32], content: &str) -> String {
    let hash = blake3::keyed_hash(hmac_key, content.as_bytes());
    hash.to_hex().to_string()
}

pub async fn save_resume(
    save_dir: &Path,
    filename: &str,
    sha256: &[u8; 32],
    total_size: u64,
    bytes_received: u64,
    hmac_key: &[u8; 32],
) -> Result<()> {
    let path = resume_path(save_dir, filename);
    let sha_hex: String = sha256.iter().map(|b| format!("{b:02x}")).collect();

    let content = format!(
        "sha256={sha_hex}\nsize={total_size}\nreceived={bytes_received}\ntimestamp={}\n",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    );

    let hmac_hex = compute_hmac(hmac_key, &content);
    let authenticated = format!("{content}hmac={hmac_hex}\n");

    let mut f = tokio::fs::File::create(&path)
        .await
        .map_err(FenvoyError::Io)?;
    f.write_all(authenticated.as_bytes())
        .await
        .map_err(FenvoyError::Io)?;
    f.sync_all().await.map_err(FenvoyError::Io)?;

    Ok(())
}

pub async fn check_resume(
    save_dir: &Path,
    filename: &str,
    expected_sha256: &[u8; 32],
    expected_size: u64,
    hmac_key: &[u8; 32],
) -> Result<u64> {
    let path = resume_path(save_dir, filename);

    let full_content = tokio::fs::read_to_string(&path)
        .await
        .map_err(FenvoyError::Io)?;

    let mut sha256_str = None;
    let mut size = None;
    let mut received = None;
    let mut timestamp: Option<u64> = None;
    let mut stored_hmac = None;

    for line in full_content.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "sha256" => sha256_str = Some(value.trim().to_string()),
                "size" => size = value.trim().parse().ok(),
                "received" => received = value.trim().parse().ok(),
                "timestamp" => timestamp = value.trim().parse().ok(),
                "hmac" => stored_hmac = Some(value.trim().to_string()),
                _ => {}
            }
        }
    }

    let stored_hmac = stored_hmac
        .ok_or_else(|| FenvoyError::ConfigParseError("missing hmac in resume file".into()))?;

    let hmac_line_start = full_content
        .rfind("hmac=")
        .ok_or_else(|| FenvoyError::ConfigParseError("malformed resume file".into()))?;
    let content_without_hmac = &full_content[..hmac_line_start];

    let expected_hmac = compute_hmac(hmac_key, content_without_hmac);
    if bool::from(stored_hmac.as_bytes().ct_ne(expected_hmac.as_bytes())) {
        let _ = tokio::fs::remove_file(&path).await;
        return Err(FenvoyError::ConfigParseError(
            "resume file integrity check failed (HMAC mismatch)".into(),
        ));
    }

    let sha256_str = sha256_str
        .ok_or_else(|| FenvoyError::ConfigParseError("missing sha256 in resume file".into()))?;
    let size: u64 =
        size.ok_or_else(|| FenvoyError::ConfigParseError("missing size in resume file".into()))?;
    let received: u64 = received
        .ok_or_else(|| FenvoyError::ConfigParseError("missing received in resume file".into()))?;

    const MAX_RESUME_AGE_SECS: u64 = 7 * 24 * 3600;

    if let Some(ts) = timestamp {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.saturating_sub(ts) > MAX_RESUME_AGE_SECS {
            let _ = tokio::fs::remove_file(&path).await;
            return Ok(0);
        }
    }

    let expected_hex: String = expected_sha256.iter().map(|b| format!("{b:02x}")).collect();
    if sha256_str != expected_hex {
        return Err(FenvoyError::HashMismatch);
    }

    if size != expected_size {
        return Err(FenvoyError::HashMismatch);
    }

    let file_path = save_dir.join(filename);
    if file_path.exists() {
        let meta = tokio::fs::metadata(&file_path)
            .await
            .map_err(FenvoyError::Io)?;
        if meta.len() >= received {
            return Ok(received);
        }
    }

    Ok(0)
}

pub async fn clear_resume(save_dir: &Path, filename: &str) {
    let path = resume_path(save_dir, filename);
    let _ = tokio::fs::remove_file(&path).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn save_and_check_resume() {
        let dir = std::env::temp_dir().join("fenvoy_resume_test");
        tokio::fs::create_dir_all(&dir).await.ok();

        let filename = "test_resume.dat";
        let sha256 = [0xAA; 32];
        let total = 1_000_000;
        let received = 500_000;
        let hmac_key = [0x42u8; 32];

        let file_path = dir.join(filename);
        tokio::fs::write(&file_path, vec![0u8; received as usize])
            .await
            .unwrap();

        save_resume(&dir, filename, &sha256, total, received, &hmac_key)
            .await
            .unwrap();

        let offset = check_resume(&dir, filename, &sha256, total, &hmac_key)
            .await
            .unwrap();
        assert_eq!(offset, received);

        let wrong_sha = [0xBB; 32];
        assert!(
            check_resume(&dir, filename, &wrong_sha, total, &hmac_key)
                .await
                .is_err()
        );

        let wrong_key = [0x99u8; 32];
        assert!(
            check_resume(&dir, filename, &sha256, total, &wrong_key)
                .await
                .is_err()
        );

        clear_resume(&dir, filename).await;
        let _ = tokio::fs::remove_file(&file_path).await;
        let _ = tokio::fs::remove_dir(&dir).await;
    }

    #[tokio::test]
    async fn tampered_state_file_rejected() {
        let dir = std::env::temp_dir().join("fenvoy_resume_tamper_test");
        tokio::fs::create_dir_all(&dir).await.ok();

        let filename = "test_tamper.dat";
        let sha256 = [0xCC; 32];
        let total = 2_000_000;
        let received = 1_000_000;
        let hmac_key = [0x42u8; 32];

        let file_path = dir.join(filename);
        tokio::fs::write(&file_path, vec![0u8; received as usize])
            .await
            .unwrap();

        save_resume(&dir, filename, &sha256, total, received, &hmac_key)
            .await
            .unwrap();

        let state_path = resume_path(&dir, filename);
        let content = tokio::fs::read_to_string(&state_path).await.unwrap();
        let tampered = content.replace(&format!("received={received}"), "received=0");
        tokio::fs::write(&state_path, tampered).await.unwrap();

        let result = check_resume(&dir, filename, &sha256, total, &hmac_key).await;
        assert!(result.is_err());

        assert!(!state_path.exists());

        let _ = tokio::fs::remove_file(&file_path).await;
        let _ = tokio::fs::remove_dir(&dir).await;
    }

    #[tokio::test]
    async fn expired_resume_state_rejected() {
        let dir = std::env::temp_dir().join("fenvoy_resume_expired_test");
        tokio::fs::create_dir_all(&dir).await.ok();

        let filename = "test_expired.dat";
        let sha256 = [0xDD; 32];
        let total = 1_000_000u64;
        let received = 500_000u64;
        let hmac_key = [0x42u8; 32];

        let file_path = dir.join(filename);
        tokio::fs::write(&file_path, vec![0u8; received as usize])
            .await
            .unwrap();

        save_resume(&dir, filename, &sha256, total, received, &hmac_key)
            .await
            .unwrap();

        let eight_days_ago = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 8 * 24 * 3600;
        let sha_hex: String = sha256.iter().map(|b| format!("{b:02x}")).collect();
        let old_content = format!(
            "sha256={sha_hex}\nsize={total}\nreceived={received}\ntimestamp={eight_days_ago}\n"
        );
        let hmac_hex = compute_hmac(&hmac_key, &old_content);
        let authenticated = format!("{old_content}hmac={hmac_hex}\n");
        let state_path = resume_path(&dir, filename);
        tokio::fs::write(&state_path, authenticated).await.unwrap();

        let offset = check_resume(&dir, filename, &sha256, total, &hmac_key)
            .await
            .unwrap();
        assert_eq!(offset, 0);

        assert!(!state_path.exists());

        let _ = tokio::fs::remove_file(&file_path).await;
        let _ = tokio::fs::remove_dir(&dir).await;
    }
}
