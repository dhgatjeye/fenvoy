pub mod dir_receiver;
pub mod dir_sender;
pub mod progress;
pub mod receiver;
pub mod resume;
pub mod sender;

use crate::error::{FenvoyError, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;

pub async fn compute_file_sha256(path: &Path) -> Result<[u8; 32]> {
    let mut file = tokio::fs::File::open(path).await.map_err(FenvoyError::Io)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        let n = file.read(&mut buf).await.map_err(FenvoyError::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(hash)
}

#[derive(Debug)]
pub struct TransferResult {
    pub file_name: String,
    pub total_bytes: u64,
    pub elapsed: std::time::Duration,
    pub verified: bool,
    pub path: PathBuf,
}

pub type AcceptFn = Box<dyn FnOnce(&str, u64) -> bool + Send>;

pub fn sanitize_filename(name: &str) -> Result<String> {
    use crate::error::FenvoyError;

    if name.is_empty() {
        return Err(FenvoyError::InvalidFilename("empty filename".into()));
    }

    if name.contains("..") {
        return Err(FenvoyError::InvalidFilename("contains '..'".into()));
    }

    let name = Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| FenvoyError::InvalidFilename("contains only path separators".into()))?;

    if name.len() > 255 {
        return Err(FenvoyError::InvalidFilename("exceeds 255 bytes".into()));
    }

    let upper = name.to_uppercase();
    let stem = upper.split('.').next().unwrap_or("");
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if RESERVED.contains(&stem) {
        return Err(FenvoyError::InvalidFilename(format!(
            "reserved Windows filename: {name}"
        )));
    }

    Ok(name.to_string())
}

pub fn resolve_collision(dir: &Path, name: &str) -> Result<PathBuf> {
    use crate::error::FenvoyError;

    let target = dir.join(name);
    if !target.exists() {
        return Ok(target);
    }

    let path = Path::new(name);
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or(name);
    let ext = path.extension().and_then(|e| e.to_str());

    let prefix = format!("{stem} (");
    let suffix = ext
        .map(|e| format!(").{e}"))
        .unwrap_or_else(|| ")".to_string());

    let mut max_n: u64 = 0;

    let entries = std::fs::read_dir(dir).map_err(FenvoyError::Io)?;
    for entry in entries {
        let entry = entry.map_err(FenvoyError::Io)?;
        let fname = entry.file_name();
        let fname = fname.to_string_lossy();

        if let Some(rest) = fname.strip_prefix(&prefix) {
            if let Some(num_str) = rest.strip_suffix(suffix.as_str()) {
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
    let new_name = match ext {
        Some(e) => format!("{stem} ({next}).{e}"),
        None => format!("{stem} ({next})"),
    };
    Ok(dir.join(new_name))
}

pub async fn create_unique_file(dir: &Path, name: &str) -> Result<(tokio::fs::File, PathBuf)> {
    use crate::error::FenvoyError;

    const MAX_ATTEMPTS: u32 = 16;

    tokio::fs::create_dir_all(dir)
        .await
        .map_err(FenvoyError::Io)?;

    let target = dir.join(name);
    match tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
        .await
    {
        Ok(file) => return Ok((file, target)),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(FenvoyError::Io(e)),
    }

    let path_name = Path::new(name);
    let stem = path_name
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(name);
    let ext = path_name.extension().and_then(|e| e.to_str());

    let prefix = format!("{stem} (");
    let suffix_pat = ext
        .map(|e| format!(").{e}"))
        .unwrap_or_else(|| ")".to_string());

    let mut max_n: u64 = 0;

    let entries = std::fs::read_dir(dir).map_err(FenvoyError::Io)?;
    for entry in entries {
        let entry = entry.map_err(FenvoyError::Io)?;
        let fname = entry.file_name();
        let fname = fname.to_string_lossy();

        if let Some(rest) = fname.strip_prefix(&prefix) {
            if let Some(num_str) = rest.strip_suffix(suffix_pat.as_str()) {
                if let Ok(n) = num_str.parse::<u64>() {
                    max_n = max_n.max(n);
                }
            }
        }
    }

    for attempt in 0..MAX_ATTEMPTS {
        let next = max_n
            .checked_add(1)
            .and_then(|n| n.checked_add(attempt as u64))
            .ok_or_else(|| FenvoyError::InvalidFilename("collision counter overflow".into()))?;

        let new_name = match ext {
            Some(e) => format!("{stem} ({next}).{e}"),
            None => format!("{stem} ({next})"),
        };
        let candidate = dir.join(&new_name);

        match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
            .await
        {
            Ok(file) => return Ok((file, candidate)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(FenvoyError::Io(e)),
        }
    }

    Err(FenvoyError::InvalidFilename(
        "could not create unique file after maximum attempts".into(),
    ))
}

pub fn available_disk_space(path: &Path) -> std::io::Result<u64> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        let canonical = std::fs::canonicalize(path).or_else(|_| {
            path.parent().map(std::fs::canonicalize).unwrap_or_else(|| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no parent",
                ))
            })
        })?;

        let wide: Vec<u16> = canonical
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut free_bytes_available: u64 = 0;

        let ok = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut free_bytes_available,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(free_bytes_available)
    }

    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let canonical = std::fs::canonicalize(path).or_else(|_| {
            path.parent().map(std::fs::canonicalize).unwrap_or_else(|| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no parent",
                ))
            })
        })?;

        let c_path = CString::new(canonical.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains nul")
        })?;

        unsafe {
            let mut stat: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(c_path.as_ptr(), &mut stat) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(stat.f_bavail as u64 * stat.f_frsize as u64)
        }
    }

    #[cfg(not(any(windows, unix)))]
    {
        let _ = path;
        Ok(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_valid() {
        assert_eq!(sanitize_filename("test.txt").unwrap(), "test.txt");
        assert_eq!(sanitize_filename("My File.pdf").unwrap(), "My File.pdf");
    }

    #[test]
    fn sanitize_strips_path() {
        assert_eq!(sanitize_filename("/etc/passwd").unwrap(), "passwd");
        assert_eq!(
            sanitize_filename("C:\\Windows\\system32\\cmd.exe").unwrap(),
            "cmd.exe"
        );
    }

    #[test]
    fn sanitize_rejects_traversal() {
        assert!(sanitize_filename("../../../etc/passwd").is_err());
        assert!(sanitize_filename("..").is_err());
    }

    #[test]
    fn sanitize_rejects_empty() {
        assert!(sanitize_filename("").is_err());
    }

    #[test]
    fn sanitize_rejects_reserved() {
        assert!(sanitize_filename("CON").is_err());
        assert!(sanitize_filename("NUL.txt").is_err());
        assert!(sanitize_filename("COM1").is_err());
    }

    #[test]
    fn sanitize_rejects_too_long() {
        let long_name = "a".repeat(256);
        assert!(sanitize_filename(&long_name).is_err());
    }

    #[test]
    fn collision_no_conflict() {
        let dir = std::env::temp_dir();
        let name = "nonexistent_fenvoy_test_12345.txt";
        let result = resolve_collision(&dir, name).unwrap();
        assert_eq!(result, dir.join(name));
    }

    #[test]
    fn disk_space_returns_nonzero() {
        let space = available_disk_space(Path::new(".")).unwrap();
        assert!(space > 1024 * 1024, "available space too small: {space}");
    }

    #[tokio::test]
    async fn create_unique_file_no_conflict() {
        let dir = std::env::temp_dir().join("fenvoy_test_unique_no_conflict");
        let _ = std::fs::remove_dir_all(&dir);
        let (file, path) = create_unique_file(&dir, "hello.txt").await.unwrap();
        drop(file);
        assert_eq!(path, dir.join("hello.txt"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn create_unique_file_with_collision() {
        let dir = std::env::temp_dir().join("fenvoy_test_unique_collision");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        std::fs::write(dir.join("report.txt"), b"existing").unwrap();

        let (file, path) = create_unique_file(&dir, "report.txt").await.unwrap();
        drop(file);

        assert_eq!(path, dir.join("report (1).txt"));

        let (file2, path2) = create_unique_file(&dir, "report.txt").await.unwrap();
        drop(file2);
        assert_eq!(path2, dir.join("report (2).txt"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
