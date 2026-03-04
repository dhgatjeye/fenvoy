use crate::error::{FenvoyError, Result};
use crate::protocol::IDLE_TIMEOUT_SECS;
use crate::protocol::MAX_CHUNK_RETRIES;
use crate::protocol::messages::{ChunkRetry, FileAccept, FileAck, Message};
use crate::protocol::record::SecureChannel;
use crate::transfer::progress::ProgressTracker;
use crate::transfer::{
    AcceptFn, TransferResult, available_disk_space, create_unique_file, sanitize_filename,
};
use subtle::ConstantTimeEq;

use std::path::Path;
use std::time::{Duration, Instant};
use tokio::fs::OpenOptions;
use tokio::io::{AsyncRead, AsyncSeekExt, AsyncWrite, AsyncWriteExt, BufWriter};

pub async fn receive_file<S: AsyncRead + AsyncWrite + Unpin>(
    channel: &mut SecureChannel<S>,
    save_dir: &Path,
    progress: &mut ProgressTracker,
    accept_fn: Option<AcceptFn>,
    max_file_size: u64,
    hmac_key: &[u8; 32],
) -> Result<TransferResult> {
    let idle = Duration::from_secs(IDLE_TIMEOUT_SECS);
    let (rt, payload) = channel.recv_record_with_timeout(idle).await?;
    let request = match Message::decode(rt, &payload)? {
        Message::FileRequest(r) => r,
        other => {
            return Err(FenvoyError::InvalidMessage(format!(
                "expected FileRequest, got {:?}",
                std::mem::discriminant(&other)
            )));
        }
    };

    receive_file_from_request(
        channel,
        save_dir,
        progress,
        accept_fn,
        max_file_size,
        hmac_key,
        request,
    )
    .await
}

pub async fn receive_file_from_request<S: AsyncRead + AsyncWrite + Unpin>(
    channel: &mut SecureChannel<S>,
    save_dir: &Path,
    progress: &mut ProgressTracker,
    accept_fn: Option<AcceptFn>,
    max_file_size: u64,
    hmac_key: &[u8; 32],
    request: crate::protocol::messages::FileRequest,
) -> Result<TransferResult> {
    let start = Instant::now();
    let idle = Duration::from_secs(IDLE_TIMEOUT_SECS);

    let safe_name = sanitize_filename(&request.filename)?;

    if max_file_size > 0 && request.file_size > max_file_size {
        let reject = FileAccept {
            accepted: false,
            resume_offset: 0,
            reason: format!(
                "file too large: {} bytes (limit: {} bytes)",
                request.file_size, max_file_size
            ),
        };
        let (rt, payload) = Message::FileAccept(reject).encode()?;
        channel.send_record(rt, &payload).await?;
        return Err(FenvoyError::MessageTooLarge {
            size: request.file_size as usize,
            max: max_file_size as usize,
        });
    }

    match available_disk_space(save_dir) {
        Ok(available) if request.file_size > available => {
            let reject = FileAccept {
                accepted: false,
                resume_offset: 0,
                reason: format!(
                    "insufficient disk space: need {} bytes, have {} bytes",
                    request.file_size, available
                ),
            };
            let (rt, payload) = Message::FileAccept(reject).encode()?;
            channel.send_record(rt, &payload).await?;
            return Err(FenvoyError::DiskFull);
        }
        Ok(_) => {}
        Err(_) => {}
    }

    let resume_offset = crate::transfer::resume::check_resume(
        save_dir,
        &safe_name,
        &request.sha256,
        request.file_size,
        hmac_key,
    )
    .await
    .unwrap_or(0);

    let (file, save_path) = if resume_offset > 0 {
        let path = save_dir.join(&safe_name);
        let f = OpenOptions::new()
            .write(true)
            .open(&path)
            .await
            .map_err(FenvoyError::Io)?;
        (f, path)
    } else {
        create_unique_file(save_dir, &safe_name).await?
    };

    if let Some(prompt) = accept_fn {
        let fname = safe_name.clone();
        let fsize = request.file_size;
        let accepted = tokio::task::spawn_blocking(move || prompt(&fname, fsize))
            .await
            .unwrap_or(false);

        if !accepted {
            let _ = tokio::fs::remove_file(&save_path).await;

            let reject = FileAccept {
                accepted: false,
                resume_offset: 0,
                reason: "declined by user".into(),
            };
            let (rt, payload) = Message::FileAccept(reject).encode()?;
            channel.send_record(rt, &payload).await?;
            return Err(FenvoyError::TransferRejected("declined by user".into()));
        }
    }

    let accept = FileAccept {
        accepted: true,
        resume_offset,
        reason: String::new(),
    };
    let (rt, payload) = Message::FileAccept(accept).encode()?;
    channel.send_record(rt, &payload).await?;

    progress.start(&safe_name, request.file_size, resume_offset);

    let mut writer = BufWriter::with_capacity(256 * 1024, file);
    if resume_offset > 0 {
        writer
            .seek(std::io::SeekFrom::Start(resume_offset))
            .await
            .map_err(FenvoyError::Io)?;
    }

    crate::transfer::resume::save_resume(
        save_dir,
        &safe_name,
        &request.sha256,
        request.file_size,
        resume_offset,
        hmac_key,
    )
    .await?;

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
                        "[recv] chunk at offset {} failed BLAKE3 check, will retry",
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

                if bytes_received % (1024 * 1024) < request.chunk_size as u64 {
                    crate::transfer::resume::save_resume(
                        save_dir,
                        &safe_name,
                        &request.sha256,
                        request.file_size,
                        bytes_received,
                        hmac_key,
                    )
                    .await?;
                }
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
                        let (rt, payload) = channel.recv_record_with_timeout(idle).await?;
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
                                    eprintln!(
                                        "[recv] retry {}/{} for chunk at offset {} still corrupt",
                                        count, MAX_CHUNK_RETRIES, chunk.offset
                                    );
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

                crate::transfer::resume::clear_resume(save_dir, &safe_name).await;

                let elapsed = start.elapsed();
                progress.finish();

                return Ok(TransferResult {
                    file_name: safe_name,
                    total_bytes: bytes_received,
                    elapsed,
                    verified,
                    path: save_path,
                });
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
                    "unexpected message during transfer".into(),
                ));
            }
        }
    }
}
