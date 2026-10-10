//! Small shared helpers: UTF-16 conversion, size formatting, env expansion.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows::core::PCWSTR;

/// UTF-8 -> NUL-terminated UTF-16.
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Path -> NUL-terminated UTF-16 (lossless).
pub fn path_to_wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// UTF-16 (optionally NUL-terminated) -> String (lossy).
pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Expands `%VAR%` references. Returns the input unchanged on failure.
pub fn expand_env(s: &str) -> String {
    if !s.contains('%') {
        return s.to_owned();
    }
    let src = to_wide(s);
    // SAFETY: `src` is NUL-terminated and outlives both calls; buffer length is passed to the API.
    unsafe {
        let needed = ExpandEnvironmentStringsW(PCWSTR(src.as_ptr()), None);
        if needed == 0 || needed > 32_768 {
            return s.to_owned();
        }
        let mut buf = vec![0u16; needed as usize];
        let written = ExpandEnvironmentStringsW(PCWSTR(src.as_ptr()), Some(&mut buf));
        if written == 0 || written as usize > buf.len() {
            return s.to_owned();
        }
        from_wide(&buf)
    }
}

/// Human readable size, e.g. `1.4 GB`.
pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if v >= 100.0 {
        format!("{v:.0} {}", UNITS[i])
    } else if v >= 10.0 {
        format!("{v:.1} {}", UNITS[i])
    } else {
        format!("{v:.2} {}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_roundtrip() {
        let w = to_wide("héllo");
        assert_eq!(*w.last().unwrap(), 0);
        assert_eq!(from_wide(&w), "héllo");
    }

    #[test]
    fn sizes() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(5 * 1024 * 1024), "5.00 MB");
    }

    #[test]
    fn env_expansion() {
        assert!(!expand_env("%SystemRoot%\\x").contains('%'));
        assert_eq!(expand_env("plain"), "plain");
    }
}
