use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct TransferProgress {
    pub file_name: String,
    pub total_bytes: u64,
    pub transferred_bytes: u64,
    pub elapsed: Duration,
    pub rate_bytes_per_sec: f64,
    pub estimated_remaining: Duration,
    pub is_complete: bool,
}

pub struct ProgressTracker {
    file_name: String,
    total_bytes: u64,
    transferred_bytes: u64,
    start_time: Option<Instant>,
    last_update: Option<Instant>,
    last_bytes: u64,
    ewma_rate: f64,
    is_complete: bool,
}

const EWMA_ALPHA: f64 = 0.3;

impl ProgressTracker {
    pub fn new() -> Self {
        Self {
            file_name: String::new(),
            total_bytes: 0,
            transferred_bytes: 0,
            start_time: None,
            last_update: None,
            last_bytes: 0,
            ewma_rate: 0.0,
            is_complete: false,
        }
    }

    pub fn start(&mut self, file_name: &str, total_bytes: u64, resume_offset: u64) {
        self.file_name = file_name.to_string();
        self.total_bytes = total_bytes;
        self.transferred_bytes = resume_offset;
        self.start_time = Some(Instant::now());
        self.last_update = Some(Instant::now());
        self.last_bytes = resume_offset;
        self.ewma_rate = 0.0;
        self.is_complete = false;
    }

    pub fn update(&mut self, transferred_bytes: u64) {
        self.transferred_bytes = transferred_bytes;

        if let Some(last) = self.last_update {
            let now = Instant::now();
            let dt = now.duration_since(last).as_secs_f64();
            if dt > 0.1 {
                let bytes_delta = (transferred_bytes - self.last_bytes) as f64;
                let instant_rate = bytes_delta / dt;

                if self.ewma_rate < 1.0 {
                    self.ewma_rate = instant_rate;
                } else {
                    self.ewma_rate =
                        EWMA_ALPHA * instant_rate + (1.0 - EWMA_ALPHA) * self.ewma_rate;
                }

                self.last_update = Some(now);
                self.last_bytes = transferred_bytes;
            }
        }
    }

    pub fn finish(&mut self) {
        self.is_complete = true;
        self.transferred_bytes = self.total_bytes;
    }

    pub fn snapshot(&self) -> TransferProgress {
        let elapsed = self
            .start_time
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO);

        let remaining_bytes = self.total_bytes.saturating_sub(self.transferred_bytes);
        let estimated_remaining = if self.ewma_rate > 0.0 {
            Duration::from_secs_f64(remaining_bytes as f64 / self.ewma_rate)
        } else {
            Duration::from_secs(0)
        };

        TransferProgress {
            file_name: self.file_name.clone(),
            total_bytes: self.total_bytes,
            transferred_bytes: self.transferred_bytes,
            elapsed,
            rate_bytes_per_sec: self.ewma_rate,
            estimated_remaining,
            is_complete: self.is_complete,
        }
    }

    pub fn percentage(&self) -> f64 {
        if self.total_bytes == 0 {
            return 100.0;
        }
        (self.transferred_bytes as f64 / self.total_bytes as f64) * 100.0
    }

    pub fn format_rate(&self) -> String {
        format_bytes_per_sec(self.ewma_rate)
    }
}

impl Default for ProgressTracker {
    fn default() -> Self {
        Self::new()
    }
}

pub fn format_bytes_per_sec(bps: f64) -> String {
    if bps >= 1_000_000_000.0 {
        format!("{:.1} GB/s", bps / 1_000_000_000.0)
    } else if bps >= 1_000_000.0 {
        format!("{:.1} MB/s", bps / 1_000_000.0)
    } else if bps >= 1_000.0 {
        format!("{:.1} KB/s", bps / 1_000.0)
    } else {
        format!("{:.0} B/s", bps)
    }
}

pub fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.1} GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1_500), "1.5 KB");
        assert_eq!(format_bytes(1_500_000), "1.5 MB");
        assert_eq!(format_bytes(1_500_000_000), "1.5 GB");
    }

    #[test]
    fn format_rate_units() {
        assert_eq!(format_bytes_per_sec(500.0), "500 B/s");
        assert_eq!(format_bytes_per_sec(1_500.0), "1.5 KB/s");
        assert_eq!(format_bytes_per_sec(1_500_000.0), "1.5 MB/s");
        assert_eq!(format_bytes_per_sec(1_500_000_000.0), "1.5 GB/s");
    }

    #[test]
    fn progress_percentage() {
        let mut p = ProgressTracker::new();
        p.start("test", 1000, 0);
        assert_eq!(p.percentage(), 0.0);

        p.update(500);
        assert_eq!(p.percentage(), 50.0);

        p.finish();
        assert_eq!(p.percentage(), 100.0);
    }

    #[test]
    fn progress_zero_size_file() {
        let mut p = ProgressTracker::new();
        p.start("empty", 0, 0);
        assert_eq!(p.percentage(), 100.0);
    }
}
