use std::path::PathBuf;

pub fn data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return PathBuf::from(appdata).join("fenvoy");
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("fenvoy");
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(config) = std::env::var_os("XDG_CONFIG_HOME") {
            return PathBuf::from(config).join("fenvoy");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".config").join("fenvoy");
        }
    }

    PathBuf::from(".fenvoy")
}

pub fn downloads_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(profile) = std::env::var_os("USERPROFILE") {
            let downloads = PathBuf::from(profile).join("Downloads").join("fenvoy");
            return downloads;
        }
    }

    #[cfg(unix)]
    {
        if let Some(home) = std::env::var_os("HOME") {
            let downloads = PathBuf::from(home).join("Downloads").join("fenvoy");
            return downloads;
        }
    }

    PathBuf::from("fenvoy_downloads")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_not_empty() {
        let dir = data_dir();
        assert!(!dir.as_os_str().is_empty());
    }

    #[test]
    fn downloads_dir_not_empty() {
        let dir = downloads_dir();
        assert!(!dir.as_os_str().is_empty());
    }
}
