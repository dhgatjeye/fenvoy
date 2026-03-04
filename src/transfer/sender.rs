use crate::error::{FenvoyError, Result};
use crate::protocol::DEFAULT_CHUNK_SIZE;
use crate::protocol::IDLE_TIMEOUT_SECS;
use crate::protocol::messages::{FileChunk, FileComplete, FileRequest, Message};
use crate::protocol::record::SecureChannel;
use crate::transfer::TransferResult;
use crate::transfer::progress::ProgressTracker;

use std::path::Path;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, BufReader};

pub async fn send_file<S: AsyncRead + AsyncWrite + Unpin>(
    channel: &mut SecureChannel<S>,
    file_path: &Path,
    progress: &mut ProgressTracker,
) -> Result<TransferResult> {
    let start = Instant::now();

    let file = File::open(file_path).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => FenvoyError::FileNotFound(file_path.to_path_buf()),
        std::io::ErrorKind::PermissionDenied => {
            FenvoyError::PermissionDenied(file_path.to_path_buf())
        }
        _ => FenvoyError::Io(e),
    })?;

    let metadata = file.metadata().await.map_err(FenvoyError::Io)?;
    let file_size = metadata.len();
    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unnamed")
        .to_string();

    let sha256 = super::compute_file_sha256(file_path).await?;

    let modified_time = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    #[cfg(unix)]
    let permissions = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode()
    };
    #[cfg(not(unix))]
    let permissions: u32 = 0;

    let request = FileRequest {
        filename: file_name.clone(),
        file_size,
        sha256,
        chunk_size: DEFAULT_CHUNK_SIZE,
        modified_time,
        permissions,
    };

    let (rt, payload) = Message::FileRequest(request).encode()?;
    channel.send_record(rt, &payload).await?;

    let idle = Duration::from_secs(IDLE_TIMEOUT_SECS);
    let (recv_rt, recv_payload) = channel.recv_record_with_timeout(idle).await?;
    let accept = match Message::decode(recv_rt, &recv_payload)? {
        Message::FileAccept(a) => a,
        other => {
            return Err(FenvoyError::HandshakeFailed(format!(
                "expected FileAccept, got {:?}",
                std::mem::discriminant(&other)
            )));
        }
    };

    if !accept.accepted {
        return Err(FenvoyError::TransferRejected(accept.reason));
    }

    let resume_offset = accept.resume_offset;

    progress.start(&file_name, file_size, resume_offset);

    let file = File::open(file_path).await.map_err(FenvoyError::Io)?;
    let mut reader = BufReader::with_capacity(DEFAULT_CHUNK_SIZE as usize, file);

    if resume_offset > 0 {
        reader
            .seek(std::io::SeekFrom::Start(resume_offset))
            .await
            .map_err(FenvoyError::Io)?;
    }

    let mut offset = resume_offset;
    let chunk_size = DEFAULT_CHUNK_SIZE as usize;

    loop {
        let mut chunk_buf = vec![0u8; chunk_size];
        let mut bytes_read = 0;

        while bytes_read < chunk_size {
            let n = reader
                .read(&mut chunk_buf[bytes_read..])
                .await
                .map_err(FenvoyError::Io)?;
            if n == 0 {
                break;
            }
            bytes_read += n;
        }

        if bytes_read == 0 {
            break;
        }

        chunk_buf.truncate(bytes_read);

        let hash = blake3::hash(&chunk_buf);
        let mut blake3_hash = [0u8; 32];
        blake3_hash.copy_from_slice(hash.as_bytes());

        let chunk = FileChunk {
            offset,
            data: chunk_buf,
            blake3_hash,
        };

        let (rt, payload) = Message::FileChunk(chunk).encode()?;
        channel.send_record(rt, &payload).await?;

        offset += bytes_read as u64;
        progress.update(offset);
    }

    let complete = FileComplete {
        sha256,
        total_bytes: file_size,
    };
    let (rt, payload) = Message::FileComplete(complete).encode()?;
    channel.send_record(rt, &payload).await?;

    let ack = wait_for_ack_or_retry(channel, file_path, DEFAULT_CHUNK_SIZE as usize).await?;

    let elapsed = start.elapsed();
    progress.finish();

    Ok(TransferResult {
        file_name,
        total_bytes: file_size,
        elapsed,
        verified: ack.verified,
        path: file_path.to_path_buf(),
    })
}

pub async fn wait_for_ack_or_retry<S: AsyncRead + AsyncWrite + Unpin>(
    channel: &mut SecureChannel<S>,
    file_path: &Path,
    chunk_size: usize,
) -> Result<crate::protocol::messages::FileAck> {
    loop {
        let idle = Duration::from_secs(IDLE_TIMEOUT_SECS);
        let (recv_rt, recv_payload) = channel.recv_record_with_timeout(idle).await?;
        match Message::decode(recv_rt, &recv_payload)? {
            Message::FileAck(a) => return Ok(a),
            Message::ChunkRetry(retry) => {
                let mut file = File::open(file_path).await.map_err(FenvoyError::Io)?;
                file.seek(std::io::SeekFrom::Start(retry.offset))
                    .await
                    .map_err(FenvoyError::Io)?;

                let mut buf = vec![0u8; chunk_size];
                let mut bytes_read = 0;
                while bytes_read < chunk_size {
                    let n = file
                        .read(&mut buf[bytes_read..])
                        .await
                        .map_err(FenvoyError::Io)?;
                    if n == 0 {
                        break;
                    }
                    bytes_read += n;
                }
                buf.truncate(bytes_read);

                let hash = blake3::hash(&buf);
                let mut blake3_hash = [0u8; 32];
                blake3_hash.copy_from_slice(hash.as_bytes());

                let chunk = FileChunk {
                    offset: retry.offset,
                    data: buf,
                    blake3_hash,
                };
                let (rt, payload) = Message::FileChunk(chunk).encode()?;
                channel.send_record(rt, &payload).await?;
            }
            Message::Cancel => return Err(FenvoyError::TransferCancelled),
            other => {
                return Err(FenvoyError::HandshakeFailed(format!(
                    "expected FileAck or ChunkRetry, got {:?}",
                    std::mem::discriminant(&other)
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    #[tokio::test]
    async fn compute_sha256_known() {
        let dir = std::env::temp_dir();
        let path = dir.join("fenvoy_test_sha256.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"hello fenvoy").unwrap();
        }

        let hash = crate::transfer::compute_file_sha256(&path).await.unwrap();
        let hash2 = crate::transfer::compute_file_sha256(&path).await.unwrap();
        assert_eq!(hash, hash2);

        std::fs::remove_file(&path).ok();
    }
}
