use crate::error::{FenvoyError, Result};
use crate::protocol::IDLE_TIMEOUT_SECS;
use crate::protocol::MAX_BATCH_FILES;
use crate::protocol::MAX_CHUNK_RETRIES;
use crate::protocol::messages::{ChunkRetry, FileAccept, FileAck, Message};
use crate::protocol::record::SecureChannel;
use crate::transfer::available_disk_space;
use crate::transfer::dir_sender::DirectoryTransferResult;
use crate::transfer::progress::ProgressTracker;
use crate::transfer::sanitize_filename;
use subtle::ConstantTimeEq;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncRead, AsyncSeekExt, AsyncWrite, AsyncWriteExt, BufWriter};

fn batch_state_path(save_dir: &Path, dir_name: &str) -> PathBuf {
    save_dir.join(format!("{dir_name}.fenvoy.batch"))
}

fn compute_batch_hmac(hmac_key: &[u8; 32], content: &str) -> String {
    let hash = blake3::keyed_hash(hmac_key, content.as_bytes());
    hash.to_hex().to_string()
}

async fn save_batch_state(
    save_dir: &Path,
    dir_name: &str,
    batch_dir: &Path,
    hmac_key: &[u8; 32],
) -> Result<()> {
    let path = batch_state_path(save_dir, dir_name);
    let content = batch_dir.to_string_lossy().to_string();
    let hmac_hex = compute_batch_hmac(hmac_key, &content);
    let authenticated = format!("{content}\nhmac={hmac_hex}\n");

    let mut f = File::create(&path).await.map_err(FenvoyError::Io)?;
    f.write_all(authenticated.as_bytes())
        .await
        .map_err(FenvoyError::Io)?;
    f.sync_all().await.map_err(FenvoyError::Io)?;

    Ok(())
}

async fn load_batch_state(save_dir: &Path, dir_name: &str, hmac_key: &[u8; 32]) -> Option<PathBuf> {
    let path = batch_state_path(save_dir, dir_name);
    if let Ok(full_content) = tokio::fs::read_to_string(&path).await {
        let hmac_line_start = full_content.rfind("hmac=")?;
        let content = full_content[..hmac_line_start].trim_end_matches('\n');
        let hmac_line = full_content[hmac_line_start..].trim();
        let stored_hmac = hmac_line.strip_prefix("hmac=")?;

        let expected_hmac = compute_batch_hmac(hmac_key, content);
        if bool::from(
            stored_hmac
                .trim()
                .as_bytes()
                .ct_ne(expected_hmac.as_bytes()),
        ) {
            let _ = tokio::fs::remove_file(&path).await;
            return None;
        }

        let dir = PathBuf::from(content.trim());
        if dir.is_dir() {
            return Some(dir);
        }
    }
    None
}

async fn clear_batch_state(save_dir: &Path, dir_name: &str) {
    let path = batch_state_path(save_dir, dir_name);
    let _ = tokio::fs::remove_file(&path).await;
}

pub async fn receive_directory<S: AsyncRead + AsyncWrite + Unpin>(
    channel: &mut SecureChannel<S>,
    save_dir: &Path,
    progress: &mut ProgressTracker,
    batch_begin: crate::protocol::messages::BatchBegin,
    max_file_size: u64,
    hmac_key: &[u8; 32],
) -> Result<DirectoryTransferResult> {
    let start = Instant::now();

    let dir_name = sanitize_dir_name(&batch_begin.dir_name)?;

    if batch_begin.file_count > MAX_BATCH_FILES {
        let reject = FileAccept {
            accepted: false,
            resume_offset: 0,
            reason: format!(
                "batch file count too large: {} files (limit: {})",
                batch_begin.file_count, MAX_BATCH_FILES
            ),
        };
        let (rt, payload) = Message::FileAccept(reject).encode()?;
        channel.send_record(rt, &payload).await?;
        return Err(FenvoyError::InvalidMessage(format!(
            "batch file count {} exceeds limit {}",
            batch_begin.file_count, MAX_BATCH_FILES
        )));
    }

    if max_file_size > 0 && batch_begin.total_bytes > max_file_size {
        let reject = FileAccept {
            accepted: false,
            resume_offset: 0,
            reason: format!(
                "batch too large: {} bytes (limit: {} bytes)",
                batch_begin.total_bytes, max_file_size
            ),
        };
        let (rt, payload) = Message::FileAccept(reject).encode()?;
        channel.send_record(rt, &payload).await?;
        return Err(FenvoyError::MessageTooLarge {
            size: batch_begin.total_bytes as usize,
            max: max_file_size as usize,
        });
    }

    match available_disk_space(save_dir) {
        Ok(available) if batch_begin.total_bytes > available => {
            let reject = FileAccept {
                accepted: false,
                resume_offset: 0,
                reason: format!(
                    "insufficient disk space: need {} bytes, have {} bytes",
                    batch_begin.total_bytes, available
                ),
            };
            let (rt, payload) = Message::FileAccept(reject).encode()?;
            channel.send_record(rt, &payload).await?;
            return Err(FenvoyError::DiskFull);
        }
        Ok(_) => {}
        Err(_) => {}
    }

    let batch_dir = if let Some(existing) = load_batch_state(save_dir, &dir_name, hmac_key).await {
        existing
    } else {
        resolve_dir_collision(save_dir, &dir_name)?
    };

    tokio::fs::create_dir_all(&batch_dir)
        .await
        .map_err(FenvoyError::Io)?;

    save_batch_state(save_dir, &dir_name, &batch_dir, hmac_key).await?;

    let accept = FileAccept {
        accepted: true,
        resume_offset: 0,
        reason: String::new(),
    };
    let (rt, payload) = Message::FileAccept(accept).encode()?;
    channel.send_record(rt, &payload).await?;

    let mut files_received: u32 = 0;
    let mut total_bytes: u64 = 0;
    let mut all_verified = true;

    let idle = Duration::from_secs(IDLE_TIMEOUT_SECS);
    loop {
        let (rt, payload) = channel.recv_record_with_timeout(idle).await?;
        let msg = Message::decode(rt, &payload)?;

        match msg {
            Message::FileRequest(request) => {
                if files_received >= batch_begin.file_count {
                    return Err(FenvoyError::InvalidMessage(format!(
                        "sender exceeded declared file count of {}",
                        batch_begin.file_count
                    )));
                }

                let rel_path = sanitize_relative_path(&request.filename)?;
                let save_path = batch_dir.join(&rel_path);

                if let Some(parent) = save_path.parent() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .map_err(FenvoyError::Io)?;
                }

                let resume_offset = if save_path.exists() {
                    let meta = tokio::fs::metadata(&save_path)
                        .await
                        .map_err(FenvoyError::Io)?;
                    if meta.len() < request.file_size {
                        meta.len()
                    } else {
                        request.file_size
                    }
                } else {
                    0
                };

                let accept = FileAccept {
                    accepted: true,
                    resume_offset,
                    reason: String::new(),
                };
                let (rt, payload) = Message::FileAccept(accept).encode()?;
                channel.send_record(rt, &payload).await?;

                progress.start(
                    &format!(
                        "[{}/{}] {}",
                        files_received + 1,
                        batch_begin.file_count,
                        rel_path
                    ),
                    request.file_size,
                    resume_offset,
                );

                let file = if resume_offset > 0 {
                    OpenOptions::new()
                        .write(true)
                        .open(&save_path)
                        .await
                        .map_err(FenvoyError::Io)?
                } else {
                    File::create(&save_path).await.map_err(FenvoyError::Io)?
                };

                let mut writer = BufWriter::with_capacity(256 * 1024, file);
                if resume_offset > 0 {
                    writer
                        .seek(std::io::SeekFrom::Start(resume_offset))
                        .await
                        .map_err(FenvoyError::Io)?;
                }

                let mut bytes_received = resume_offset;
                let mut corrupted_offsets: Vec<u64> = Vec::new();

                loop {
                    let (rt, payload) = channel.recv_record_with_timeout(idle).await?;
                    let msg = Message::decode(rt, &payload)?;

                    match msg {
                        Message::FileChunk(chunk) => {
                            let hash = blake3::hash(&chunk.data);
                            let mut expected = [0u8; 32];
                            expected.copy_from_slice(hash.as_bytes());

                            if bool::from(expected.ct_ne(&chunk.blake3_hash)) {
                                eprintln!(
                                    "[dir-recv] chunk at offset {} failed BLAKE3 check, will retry",
                                    chunk.offset
                                );
                                corrupted_offsets.push(chunk.offset);
                                bytes_received += chunk.data.len() as u64;
                                progress.update(bytes_received);
                                continue;
                            }

                            writer
                                .seek(std::io::SeekFrom::Start(chunk.offset))
                                .await
                                .map_err(FenvoyError::Io)?;
                            writer
                                .write_all(&chunk.data)
                                .await
                                .map_err(FenvoyError::Io)?;

                            bytes_received += chunk.data.len() as u64;
                            progress.update(bytes_received);
                        }
                        Message::FileComplete(complete) => {
                            writer.flush().await.map_err(FenvoyError::Io)?;

                            let mut retry_counts: std::collections::HashMap<u64, u32> =
                                corrupted_offsets.iter().map(|&off| (off, 0u32)).collect();

                            while !corrupted_offsets.is_empty() {
                                for &offset in &corrupted_offsets {
                                    let retry_msg = Message::ChunkRetry(ChunkRetry { offset });
                                    let (rt, payload) = retry_msg.encode()?;
                                    channel.send_record(rt, &payload).await?;
                                }

                                let mut still_corrupted: Vec<u64> = Vec::new();
                                for _ in 0..corrupted_offsets.len() {
                                    let (rt, payload) =
                                        channel.recv_record_with_timeout(idle).await?;
                                    let msg = Message::decode(rt, &payload)?;

                                    match msg {
                                        Message::FileChunk(chunk) => {
                                            let hash = blake3::hash(&chunk.data);
                                            let mut expected = [0u8; 32];
                                            expected.copy_from_slice(hash.as_bytes());

                                            if bool::from(expected.ct_ne(&chunk.blake3_hash)) {
                                                let count = retry_counts
                                                    .get_mut(&chunk.offset)
                                                    .expect("offset must be tracked");
                                                *count += 1;
                                                if *count >= MAX_CHUNK_RETRIES {
                                                    return Err(FenvoyError::ChunkCorrupted {
                                                        offset: chunk.offset,
                                                    });
                                                }
                                                still_corrupted.push(chunk.offset);
                                            } else {
                                                writer
                                                    .seek(std::io::SeekFrom::Start(chunk.offset))
                                                    .await
                                                    .map_err(FenvoyError::Io)?;
                                                writer
                                                    .write_all(&chunk.data)
                                                    .await
                                                    .map_err(FenvoyError::Io)?;
                                            }
                                        }
                                        Message::Cancel => {
                                            return Err(FenvoyError::TransferCancelled);
                                        }
                                        Message::PeerError(msg) => {
                                            return Err(FenvoyError::InvalidMessage(format!(
                                                "peer reported error during retry: {msg}"
                                            )));
                                        }
                                        _ => {
                                            return Err(FenvoyError::InvalidMessage(
                                                "unexpected message during chunk retry".into(),
                                            ));
                                        }
                                    }
                                }

                                corrupted_offsets = still_corrupted;
                            }

                            writer.flush().await.map_err(FenvoyError::Io)?;

                            let inner = writer.into_inner();
                            inner.sync_all().await.map_err(FenvoyError::Io)?;
                            drop(inner);

                            let actual_hash = super::compute_file_sha256(&save_path).await?;
                            let verified = bool::from(actual_hash.ct_eq(&complete.sha256))
                                && bool::from(actual_hash.ct_eq(&request.sha256));

                            let ack = FileAck {
                                verified,
                                error_message: if verified {
                                    String::new()
                                } else {
                                    "SHA-256 hash mismatch".into()
                                },
                            };
                            let (rt, payload) = Message::FileAck(ack).encode()?;
                            channel.send_record(rt, &payload).await?;

                            progress.finish();

                            if !verified {
                                all_verified = false;
                            }

                            total_bytes += bytes_received;
                            files_received += 1;
                            break;
                        }
                        Message::Close | Message::Cancel => {
                            return Err(FenvoyError::TransferCancelled);
                        }
                        Message::PeerError(msg) => {
                            return Err(FenvoyError::InvalidMessage(format!(
                                "peer reported error: {msg}"
                            )));
                        }
                        _ => {
                            return Err(FenvoyError::InvalidMessage(
                                "unexpected message during file transfer".into(),
                            ));
                        }
                    }
                }
            }
            Message::BatchEnd(_) => {
                break;
            }
            Message::Close | Message::Cancel => {
                return Err(FenvoyError::TransferCancelled);
            }
            Message::PeerError(msg) => {
                return Err(FenvoyError::InvalidMessage(format!(
                    "peer reported error: {msg}"
                )));
            }
            _ => {
                return Err(FenvoyError::InvalidMessage(
                    "unexpected message during batch transfer".into(),
                ));
            }
        }
    }

    let elapsed = start.elapsed();

    clear_batch_state(save_dir, &dir_name).await;

    Ok(DirectoryTransferResult {
        dir_name,
        files_transferred: files_received,
        total_bytes,
        elapsed,
        all_verified,
    })
}

fn sanitize_dir_name(name: &str) -> Result<String> {
    if name.is_empty() {
        return Err(FenvoyError::InvalidFilename("empty directory name".into()));
    }
    if name.contains("..") {
        return Err(FenvoyError::InvalidFilename("contains '..'".into()));
    }

    let name = Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| FenvoyError::InvalidFilename("invalid directory name".into()))?;

    if name.len() > 255 {
        return Err(FenvoyError::InvalidFilename("exceeds 255 bytes".into()));
    }

    Ok(name.to_string())
}

fn sanitize_relative_path(rel_path: &str) -> Result<String> {
    if rel_path.is_empty() {
        return Err(FenvoyError::InvalidFilename("empty relative path".into()));
    }
    if rel_path.contains("..") {
        return Err(FenvoyError::InvalidFilename("contains '..'".into()));
    }

    let parts: Vec<&str> = rel_path.split('/').collect();
    let mut sanitized = Vec::new();

    for part in &parts {
        if part.is_empty() {
            continue;
        }
        let clean = sanitize_filename(part)?;
        sanitized.push(clean);
    }

    if sanitized.is_empty() {
        return Err(FenvoyError::InvalidFilename(
            "no valid path components".into(),
        ));
    }

    let result: PathBuf = sanitized.iter().collect();
    Ok(result.to_string_lossy().to_string())
}

fn resolve_dir_collision(parent: &Path, name: &str) -> Result<PathBuf> {
    let target = parent.join(name);
    if !target.exists() {
        return Ok(target);
    }

    let prefix = format!("{name} (");

    let mut max_n: u64 = 0;

    let entries = std::fs::read_dir(parent).map_err(FenvoyError::Io)?;
    for entry in entries {
        let entry = entry.map_err(FenvoyError::Io)?;
        let fname = entry.file_name();
        let fname = fname.to_string_lossy();

        if let Some(rest) = fname.strip_prefix(&prefix) {
            if let Some(num_str) = rest.strip_suffix(')') {
                if let Ok(n) = num_str.parse::<u64>() {
                    max_n = max_n.max(n);
                }
            }
        }
    }

    let next = max_n.checked_add(1).ok_or_else(|| {
        FenvoyError::InvalidFilename(
            "collision counter overflow: a directory entry has suffix (u64::MAX)".into(),
        )
    })?;
    Ok(parent.join(format!("{name} ({next})")))
}
