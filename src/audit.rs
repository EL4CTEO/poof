//! Append-only audit trail of every destructive action, plus the app data folder.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use windows::Win32::System::SystemInformation::GetLocalTime;

use crate::app_info::APP_DIR;
use crate::security::known_dirs;

const MAX_LOG_BYTES: u64 = 1 << 20;

/// `%LOCALAPPDATA%\<App>` (created on demand).
pub fn data_dir() -> PathBuf {
    let dir = known_dirs().local_app_data.join(APP_DIR);
    let _ = fs::create_dir_all(&dir);
    dir
}

/// `YYYY-MM-DD HH:MM:SS` in local time.
pub fn timestamp() -> String {
    // SAFETY: GetLocalTime has no preconditions.
    let t = unsafe { GetLocalTime() };
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond)
}

/// `YYYYMMDD-HHMMSS`, safe for file names.
pub fn timestamp_compact() -> String {
    timestamp().replace(['-', ':'], "").replace(' ', "-")
}

/// Appends one line. Never panics, never fails the caller; control characters are neutralised.
pub fn log(msg: &str) {
    let path = data_dir().join("audit.log");
    if fs::metadata(&path).map(|m| m.len() > MAX_LOG_BYTES).unwrap_or(false) {
        let _ = fs::rename(&path, path.with_extension("old"));
    }
    let clean: String = msg.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{} {}", timestamp(), clean);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_have_expected_shape() {
        assert_eq!(timestamp().len(), 19);
        let c = timestamp_compact();
        assert_eq!(c.len(), 15);
        assert!(c.chars().all(|ch| ch.is_ascii_digit() || ch == '-'));
    }
}
