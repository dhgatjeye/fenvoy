use crate::error::{FenvoyError, Result};
use crate::protocol::DEFAULT_CHUNK_SIZE;
use crate::protocol::IDLE_TIMEOUT_SECS;
use crate::protocol::messages::{
    BatchBegin, BatchEnd, FileChunk, FileComplete, FileRequest, Message,
};
use crate::protocol::record::SecureChannel;
use crate::transfer::progress::ProgressTracker;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, BufReader};

#[derive(Debug)]
pub struct DirectoryTransferResult {
    pub dir_name: String,
    pub files_transferred: u32,
    pub total_bytes: u64,
    pub elapsed: Duration,
    pub all_verified: bool,
}

fn collect_files(root: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut files = Vec::new();
    collect_files_recursive(root, root, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

fn collect_files_recursive(
    root: &Path,
    current: &Path,
    files: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    let entries = std::fs::read_dir(current).map_err(FenvoyError::Io)?;

    for entry in entries {
        let entry = entry.map_err(FenvoyError::Io)?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(FenvoyError::Io)?;

        if file_type.is_symlink() {
            eprintln!("[dir-send] skipping symlink: {}", path.display());
            continue;
        }

        if file_type.is_dir() {
            collect_files_recursive(root, &path, files)?;
        } else if file_type.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| FenvoyError::InvalidFilename("path prefix error".into()))?;
            let rel_str = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join("/");
            files.push((rel_str, path));
        }
    }

    Ok(())
}

pub async fn send_directory<S: AsyncRead + AsyncWrite + Unpin>(
    channel: &mut SecureChannel<S>,
    dir_path: &Path,
    progress: &mut ProgressTracker,
) -> Result<DirectoryTransferResult> {
    let start = Instant::now();

    if !dir_path.is_dir() {
        return Err(FenvoyError::FileNotFound(dir_path.to_path_buf()));
    }

    let dir_name = dir_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unnamed")
        .to_string();

    let files = collect_files(dir_path)?;

    if files.is_empty() {
        return Err(FenvoyError::InvalidMessage("directory is empty".into()));
    }

    let mut total_bytes: u64 = 0;
    for (_, path) in &files {
        let meta = std::fs::metadata(path).map_err(FenvoyError::Io)?;
        total_bytes += meta.len();
    }

    let batch_begin = BatchBegin {
        dir_name: dir_name.clone(),
        file_count: files.len() as u32,
        total_bytes,
    };
    let (rt, payload) = Message::BatchBegin(batch_begin).encode()?;
    channel.send_record(rt, &payload).await?;

    let idle = Duration::from_secs(IDLE_TIMEOUT_SECS);
    let (recv_rt, recv_payload) = channel.recv_record_with_timeout(idle).await?;
    match Message::decode(recv_rt, &recv_payload)? {
        Message::FileAccept(a) if a.accepted => {}
        Message::FileAccept(a) => {
            return Err(FenvoyError::TransferRejected(a.reason));
        }
        other => {
            return Err(FenvoyError::HandshakeFailed(format!(
                "expected FileAccept for batch, got {:?}",
                std::mem::discriminant(&other)
            )));
        }
    }

    let mut files_transferred: u32 = 0;
    let mut bytes_sent: u64 = 0;
    let mut all_verified = true;

    for (i, (rel_path, abs_path)) in files.iter().enumerate() {
        let sha256 = super::compute_file_sha256(abs_path).await?;

        let file = File::open(abs_path).await.map_err(FenvoyError::Io)?;
        let metadata = file.metadata().await.map_err(FenvoyError::Io)?;
        let file_size = metadata.len();

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
            filename: rel_path.clone(),
            file_size,
            sha256,
            chunk_size: DEFAULT_CHUNK_SIZE,
            modified_time,
            permissions,
        };
        let (rt, payload) = Message::FileRequest(request).encode()?;
        channel.send_record(rt, &payload).await?;

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
            continue;
        }

        let resume_offset = accept.resume_offset;

        progress.start(
            &format!("[{}/{}] {}", i + 1, files.len(), rel_path),
            file_size,
            resume_offset,
        );

        let file = File::open(abs_path).await.map_err(FenvoyError::Io)?;
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

        let ack = crate::transfer::sender::wait_for_ack_or_retry(
            channel,
            abs_path,
            DEFAULT_CHUNK_SIZE as usize,
        )
        .await?;

        progress.finish();

        if !ack.verified {
            all_verified = false;
        }

        bytes_sent += file_size;
        files_transferred += 1;
    }

    let batch_end = BatchEnd {
        files_transferred,
        total_bytes: bytes_sent,
        all_verified,
    };
    let (rt, payload) = Message::BatchEnd(batch_end).encode()?;
    channel.send_record(rt, &payload).await?;

    let elapsed = start.elapsed();

    Ok(DirectoryTransferResult {
        dir_name,
        files_transferred,
        total_bytes: bytes_sent,
        elapsed,
        all_verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("fenvoy_test")
            .join(name)
            .join(format!("{:x}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn collect_files_normal_dir() {
        let root = test_dir("collect_normal");

        fs::write(root.join("a.txt"), b"hello").unwrap();
        fs::create_dir(root.join("sub")).unwrap();
        fs::write(root.join("sub").join("b.txt"), b"world").unwrap();

        let files = collect_files(&root).unwrap();
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["a.txt", "sub/b.txt"]);

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn collect_files_skips_symlinks() {
        let root = test_dir("collect_symlinks");

        fs::write(root.join("real.txt"), b"real").unwrap();

        std::os::unix::fs::symlink("/etc/passwd", root.join("sneaky_link")).unwrap();

        std::os::unix::fs::symlink("/etc", root.join("dir_link")).unwrap();

        let files = collect_files(&root).unwrap();
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();

        assert_eq!(names, vec!["real.txt"]);

        let _ = fs::remove_dir_all(&root);
    }
}
