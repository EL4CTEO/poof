//! Deletes leftovers behind the safety policy, with a registry backup and an audit trail.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use windows::Win32::UI::Shell::{
    FO_DELETE, FOF_ALLOWUNDO, FOF_NOCONFIRMATION, FOF_NOERRORUI, FOF_SILENT, FOF_WANTNUKEWARNING, SHFILEOPSTRUCTW,
    SHFileOperationW,
};
use windows::core::PCWSTR;

use crate::audit;
use crate::leftovers::{Leftover, Target};
use crate::model::{Hive, RegLocation};
use crate::security::{self, SafetyError};
use crate::util::{from_wide, path_to_wide};
use crate::winreg::{self, RegKey};

#[derive(Clone, Debug, Default)]
pub struct CleanOptions {
    /// Send files/folders to the Recycle Bin instead of deleting permanently.
    pub use_recycle_bin: bool,
    /// Validated install location of the app (see `security::validate_install_root`), if any.
    pub install_root: Option<PathBuf>,
}

#[derive(Clone, Debug, Default)]
pub struct CleanReport {
    pub removed: usize,
    /// `(display path, reason)` for items that could not be removed (access denied, in use...).
    pub failed: Vec<(String, String)>,
    /// `(display path, reason)` for items the safety policy refused.
    pub skipped: Vec<(String, String)>,
    pub freed_bytes: u64,
    /// `.reg` file with everything deleted from the registry, if any registry item was removed.
    pub registry_backup: Option<PathBuf>,
}

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const REG_SZ: u32 = 1;
const REG_BINARY: u32 = 3;
const REG_DWORD: u32 = 4;
const REG_HEADER: &str = "Windows Registry Editor Version 5.00\r\n\r\n";
/// Deepest registry level the backup descends into.
const MAX_REG_DEPTH: usize = 32;
/// Cap on the exported text. UTF-16 output is at most twice the text length, so the file stays under 64 MiB.
const MAX_EXPORT_CHARS: usize = 32 << 20;
/// `ERROR_FILE_NOT_FOUND`.
const ERROR_FILE_NOT_FOUND: i32 = 2;

/// Result of one deletion attempt.
enum Outcome {
    Removed,
    /// Nothing was there (any more): success without freed bytes.
    AlreadyGone,
    Failed(String),
}

/// Removes the given items. Blocking; run on a worker thread.
pub fn clean(items: &[Leftover], opts: &CleanOptions) -> CleanReport {
    let mut report = CleanReport::default();
    let (registry, paths): (Vec<&Leftover>, Vec<&Leftover>) = items.iter().partition(|l| is_registry(&l.target));
    clean_registry(&registry, &mut report);
    let gate_roots: Vec<PathBuf> = opts.install_root.iter().cloned().collect();
    for item in paths {
        clean_path(item, opts, &gate_roots, &mut report);
    }
    report
}

fn is_registry(target: &Target) -> bool {
    matches!(target, Target::RegKey(_) | Target::RegValue(..))
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

fn clean_registry(items: &[&Leftover], report: &mut CleanReport) {
    let mut approved = Vec::new();
    for &item in items {
        match registry_gate(&item.target) {
            Ok(()) => approved.push(item),
            Err(e) => refuse(item.display_path(), e.0, report),
        }
    }
    let (present, missing): (Vec<&Leftover>, Vec<&Leftover>) =
        approved.into_iter().partition(|item| registry_present(&item.target));
    for item in missing {
        record("REGDELETE", &item.display_path(), Outcome::AlreadyGone, None, report);
    }
    if present.is_empty() {
        return;
    }

    // Nothing is deleted unless the backup is complete and on disk.
    let backup = match write_backup(&present) {
        Ok(path) => path,
        Err(reason) => {
            audit::log(&format!("REGBACKUP FAILED {reason}"));
            for item in present {
                report.failed.push((item.display_path(), "backup failed".to_owned()));
            }
            return;
        }
    };
    audit::log(&format!("REGBACKUP {}", backup.display()));

    let mut deleted_any = false;
    for item in present {
        let display = item.display_path();
        let outcome = delete_registry(&item.target);
        deleted_any |= matches!(outcome, Outcome::Removed);
        record("REGDELETE", &display, outcome, None, report);
    }
    if deleted_any {
        report.registry_backup = Some(backup);
    }
}

fn registry_gate(target: &Target) -> Result<(), SafetyError> {
    match target {
        Target::RegKey(loc) => security::check_registry_delete(loc.hive, &loc.subkey),
        Target::RegValue(loc, name) => security::check_registry_value_delete(loc.hive, &loc.subkey, name),
        Target::Folder(_) | Target::File(_) => Err(SafetyError("not a registry item".into())),
    }
}

fn registry_present(target: &Target) -> bool {
    match target {
        Target::RegKey(loc) => RegKey::exists(loc.hive, &loc.subkey),
        Target::RegValue(loc, name) => {
            RegKey::open(loc.hive, &loc.subkey, false).is_some_and(|key| key.value_names().iter().any(|n| n == name))
        }
        Target::Folder(_) | Target::File(_) => false,
    }
}

fn delete_registry(target: &Target) -> Outcome {
    let result = match target {
        Target::RegKey(loc) => winreg::delete_tree(loc.hive, &loc.subkey),
        Target::RegValue(loc, name) => winreg::delete_value(loc.hive, &loc.subkey, name),
        Target::Folder(_) | Target::File(_) => return Outcome::Failed("not a registry item".to_owned()),
    };
    match result {
        Ok(()) => Outcome::Removed,
        Err(msg) => match win32_code(&msg) {
            Some(ERROR_FILE_NOT_FOUND) => Outcome::AlreadyGone,
            Some(code) => Outcome::Failed(friendly_reason(Some(code), format!("Windows error {code}"))),
            None => Outcome::Failed(msg),
        },
    }
}

/// Parses the `error N` text produced by `winreg`.
fn win32_code(msg: &str) -> Option<i32> {
    msg.strip_prefix("error ")?.trim().parse().ok()
}

/// Writes the `.reg` backup of `items` and syncs it to disk. Returns its path.
fn write_backup(items: &[&Leftover]) -> Result<PathBuf, String> {
    let text = export_items(items)?;
    let dir = audit::data_dir().join("backups");
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let (path, mut file) = create_backup_file(&dir)?;
    let written = file.write_all(&encode_reg_file(&text)).and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written {
        let _ = fs::remove_file(&path);
        return Err(format!("cannot write {}: {e}", path.display()));
    }
    Ok(path)
}

/// Creates a new backup file, adding a counter when the same second already has one.
fn create_backup_file(dir: &Path) -> Result<(PathBuf, File), String> {
    let stamp = audit::timestamp_compact();
    for n in 0..100u32 {
        let name = if n == 0 {
            format!("{stamp}-registry.reg")
        } else {
            format!("{stamp}-{n}-registry.reg")
        };
        let path = dir.join(name);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("cannot create backup file: {e}")),
        }
    }
    Err("no free backup file name".to_owned())
}

/// Full `.reg` text for the items. Fails when anything cannot be read completely.
fn export_items(items: &[&Leftover]) -> Result<String, String> {
    let mut text = String::from(REG_HEADER);
    for item in items {
        match &item.target {
            Target::RegKey(loc) => export_key(loc.hive, &loc.subkey, 0, &mut text)?,
            Target::RegValue(loc, name) => export_value(loc, name, &mut text)?,
            Target::Folder(_) | Target::File(_) => {}
        }
    }
    Ok(text)
}

fn export_key(hive: Hive, subkey: &str, depth: usize, out: &mut String) -> Result<(), String> {
    if depth > MAX_REG_DEPTH {
        return Err(format!("registry tree deeper than {MAX_REG_DEPTH} levels"));
    }
    if has_control(subkey) {
        return Err("key name contains control characters".to_owned());
    }
    let Some(key) = RegKey::open(hive, subkey, false) else {
        // A top-level key that vanished is simply not exported; any other unreadable key fails the backup.
        return if depth == 0 {
            Ok(())
        } else {
            Err(format!("cannot read {subkey}"))
        };
    };
    let values = read_values(&key, subkey)?;
    let children = read_subkeys(&key, subkey)?;
    drop(key);

    out.push_str(&format!("[{}\\{subkey}]\r\n", hive_name(hive)));
    for (name, ty, data) in &values {
        out.push_str(&format_value(name, *ty, data));
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    check_size(out)?;
    for child in children {
        export_key(hive, &format!("{subkey}\\{child}"), depth + 1, out)?;
    }
    Ok(())
}

fn export_value(loc: &RegLocation, name: &str, out: &mut String) -> Result<(), String> {
    let Some(key) = RegKey::open(loc.hive, &loc.subkey, false) else {
        return Ok(());
    };
    let values = read_values(&key, &loc.subkey)?;
    let Some((_, ty, data)) = values.iter().find(|(n, _, _)| n.as_str() == name) else {
        return Ok(());
    };
    out.push_str(&format!("[{}\\{}]\r\n", hive_name(loc.hive), loc.subkey));
    out.push_str(&format_value(name, *ty, data));
    out.push_str("\r\n\r\n");
    check_size(out)
}

/// All values of `key`, failing when the read is incomplete (oversize or unreadable values).
fn read_values(key: &RegKey, subkey: &str) -> Result<Vec<(String, u32, Vec<u8>)>, String> {
    let values = key.enum_values();
    let (_, count) = key.counts();
    if values.len() != count as usize || values.iter().any(|(name, _, _)| has_control(name)) {
        return Err(format!("incomplete or unsupported values in {subkey}"));
    }
    Ok(values)
}

/// Direct subkey names of `key`, failing when the listing is incomplete.
fn read_subkeys(key: &RegKey, subkey: &str) -> Result<Vec<String>, String> {
    let names = key.subkey_names();
    let (count, _) = key.counts();
    if names.len() != count as usize || names.iter().any(|n| has_control(n)) {
        return Err(format!("incomplete or unsupported subkeys in {subkey}"));
    }
    Ok(names)
}

fn check_size(out: &str) -> Result<(), String> {
    if out.len() > MAX_EXPORT_CHARS {
        Err("registry backup would be too large".to_owned())
    } else {
        Ok(())
    }
}

fn has_control(s: &str) -> bool {
    s.chars().any(char::is_control)
}

fn hive_name(hive: Hive) -> &'static str {
    match hive {
        Hive::LocalMachine => "HKEY_LOCAL_MACHINE",
        Hive::CurrentUser => "HKEY_CURRENT_USER",
    }
}

/// One value line of a `.reg` file (no line ending). Strings with control characters and malformed
/// DWORDs are written as hex so the file stays valid.
fn format_value(name: &str, ty: u32, data: &[u8]) -> String {
    let lhs = if name.is_empty() {
        "@".to_owned()
    } else {
        format!("\"{}\"", escape_reg_string(name))
    };
    let rhs = match ty {
        REG_SZ => {
            let text = wide_to_string(data);
            if has_control(&text) {
                hex_value(ty, data)
            } else {
                format!("\"{}\"", escape_reg_string(&text))
            }
        }
        REG_DWORD if data.len() == 4 => {
            format!("dword:{:08x}", u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        }
        _ => hex_value(ty, data),
    };
    format!("{lhs}={rhs}")
}

/// Escapes backslash and double quote for a `.reg` string.
fn escape_reg_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// `hex:` for binary, `hex(N):` for every other type. Lines wrap with a `\` continuation every 25 bytes.
fn hex_value(ty: u32, data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = if ty == REG_BINARY {
        "hex:".to_owned()
    } else {
        format!("hex({ty:x}):")
    };
    for (i, &byte) in data.iter().enumerate() {
        if i > 0 {
            s.push(',');
            if i % 25 == 0 {
                s.push_str("\\\r\n  ");
            }
        }
        s.push(char::from(DIGITS[usize::from(byte >> 4)]));
        s.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    s
}

/// UTF-16LE registry string bytes to text (stops at the first NUL).
fn wide_to_string(data: &[u8]) -> String {
    let wide: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    from_wide(&wide)
}

/// `.reg` files are UTF-16LE with a byte order mark.
fn encode_reg_file(text: &str) -> Vec<u8> {
    let mut bytes = vec![0xFF, 0xFE];
    bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    bytes
}

// ---------------------------------------------------------------------------
// Files and folders
// ---------------------------------------------------------------------------

fn clean_path(item: &Leftover, opts: &CleanOptions, gate_roots: &[PathBuf], report: &mut CleanReport) {
    let display = item.display_path();
    let (Target::Folder(path) | Target::File(path)) = &item.target else {
        return;
    };
    let target = match security::check_path_delete(path, gate_roots) {
        Ok(resolved) => resolved,
        Err(e) => {
            refuse(display, e.0, report);
            return;
        }
    };
    let outcome = remove_path(&target, opts.use_recycle_bin);
    record("DELETE", &display, outcome, item.size_bytes, report);
}

fn remove_path(path: &Path, recycle: bool) -> Outcome {
    if security::is_reparse_point(path) {
        return remove_link(path).map_or_else(|e| io_outcome(&e), |()| Outcome::Removed);
    }
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) => return io_outcome(&e),
    };
    if recycle {
        return recycle_path(path);
    }
    let result = if meta.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    result.map_or_else(|e| io_outcome(&e), |()| Outcome::Removed)
}

/// Removes only the link itself. `remove_dir` for directory links and junctions, `remove_file` otherwise.
/// Nothing behind the link is touched.
fn remove_link(path: &Path) -> io::Result<()> {
    let is_dir_link = fs::symlink_metadata(path).is_ok_and(|m| m.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0);
    if is_dir_link {
        fs::remove_dir(path)
    } else {
        fs::remove_file(path)
    }
}

/// Sends a file or folder to the Recycle Bin. Failure is reported, never replaced by a permanent delete.
fn recycle_path(path: &Path) -> Outcome {
    // Double NUL-terminated, as SHFileOperationW requires.
    let mut from = path_to_wide(path);
    from.push(0);
    // FOF_WANTNUKEWARNING: if an item is too big for the bin the shell asks instead of deleting it for good.
    let flags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT | FOF_WANTNUKEWARNING;
    let mut op = SHFILEOPSTRUCTW {
        wFunc: FO_DELETE,
        pFrom: PCWSTR(from.as_ptr()),
        // The API takes a 16-bit flag word; these flags are all small.
        fFlags: flags.0 as u16,
        ..Default::default()
    };
    // SAFETY: `op` is a valid, exclusively borrowed struct and `from` outlives the call.
    let code = unsafe { SHFileOperationW(&mut op) };
    if code != 0 {
        return Outcome::Failed(format!("could not move to the Recycle Bin (code {code})"));
    }
    if op.fAnyOperationsAborted.as_bool() {
        return Outcome::Failed("Recycle Bin operation was cancelled".to_owned());
    }
    Outcome::Removed
}

fn io_outcome(e: &io::Error) -> Outcome {
    if e.kind() == io::ErrorKind::NotFound {
        Outcome::AlreadyGone
    } else {
        Outcome::Failed(friendly_reason(e.raw_os_error(), os_message(e)))
    }
}

/// The OS text without the Rust `(os error N)` suffix.
fn os_message(e: &io::Error) -> String {
    let text = e.to_string();
    match text.find(" (os error") {
        Some(i) => text[..i].to_owned(),
        None => text,
    }
}

/// Plain-language reasons for the common Windows error codes; everything else keeps `fallback`.
fn friendly_reason(code: Option<i32>, fallback: String) -> String {
    match code {
        Some(5) if !security::is_elevated() => "Access denied - restart as administrator".to_owned(),
        Some(32 | 33) => "In use by another program".to_owned(),
        _ => fallback,
    }
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

fn refuse(display: String, reason: String, report: &mut CleanReport) {
    audit::log(&format!("REFUSED {display} [{reason}]"));
    report.skipped.push((display, reason));
}

fn record(action: &str, display: &str, outcome: Outcome, size: Option<u64>, report: &mut CleanReport) {
    let label = match &outcome {
        Outcome::Removed => "removed".to_owned(),
        Outcome::AlreadyGone => "already gone".to_owned(),
        Outcome::Failed(reason) => format!("failed: {reason}"),
    };
    audit::log(&format!("{action} {display} [{label}]"));
    match outcome {
        Outcome::Removed => {
            report.removed += 1;
            report.freed_bytes += size.unwrap_or(0);
        }
        Outcome::AlreadyGone => report.removed += 1,
        Outcome::Failed(reason) => report.failed.push((display.to_owned(), reason)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::atomic::{AtomicU32, Ordering};

    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW,
        RegSetValueExW,
    };
    use windows::core::PCWSTR;

    use super::*;
    use crate::leftovers::Confidence;
    use crate::security::known_dirs;
    use crate::util::to_wide;

    const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn unique_name() -> String {
        format!(
            "PoofTest-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn leftover(target: Target) -> Leftover {
        Leftover {
            target,
            confidence: Confidence::High,
            reason: "test".to_owned(),
            size_bytes: None,
        }
    }

    /// Removes a test folder when the test ends, even after a failed assertion.
    struct FolderGuard(PathBuf);
    impl Drop for FolderGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Removes a test registry tree when the test ends, even after a failed assertion.
    struct KeyGuard(String);
    impl Drop for KeyGuard {
        fn drop(&mut self) {
            let _ = winreg::delete_tree(Hive::CurrentUser, &self.0);
        }
    }

    /// Removes a test autostart value when the test ends, even after a failed assertion.
    struct RunValueGuard(String);
    impl Drop for RunValueGuard {
        fn drop(&mut self) {
            let _ = winreg::delete_value(Hive::CurrentUser, RUN_KEY, &self.0);
        }
    }

    fn utf16_text(bytes: &[u8]) -> String {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    }

    /// REG_SZ payload: UTF-16LE with a terminating NUL.
    fn wide_bytes(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).chain([0, 0]).collect()
    }

    /// Creates `HKCU\<path>` (with parents) and runs `f` with its handle.
    fn with_test_key(path: &str, f: impl FnOnce(HKEY)) {
        let sub = to_wide(path);
        let mut key = HKEY::default();
        // SAFETY: NUL-terminated path; `key` receives a handle that is closed below.
        let r = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(sub.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                None,
                &mut key,
                None,
            )
        };
        assert_eq!(r, ERROR_SUCCESS, "cannot create test key {path}");
        f(key);
        // SAFETY: `key` was opened above and is closed exactly once.
        unsafe {
            let _ = RegCloseKey(key);
        }
    }

    fn set_value(key: HKEY, name: &str, ty: u32, data: &[u8]) {
        let n = to_wide(name);
        // SAFETY: `key` is open (owned by `with_test_key`); `n` is NUL-terminated and `data` is a valid slice.
        unsafe {
            let _ = RegSetValueExW(key, PCWSTR(n.as_ptr()), None, REG_VALUE_TYPE(ty), Some(data));
        }
    }

    #[test]
    fn escapes_registry_strings() {
        assert_eq!(escape_reg_string("a\\b\"c"), "a\\\\b\\\"c");
        assert_eq!(escape_reg_string("plain"), "plain");
    }

    #[test]
    fn formats_values() {
        assert_eq!(format_value("", REG_SZ, &wide_bytes("hi")), "@=\"hi\"");
        assert_eq!(format_value("Name", REG_SZ, &wide_bytes("x\\y")), "\"Name\"=\"x\\\\y\"");
        assert_eq!(format_value("n", REG_DWORD, &[1, 0, 0, 0]), "\"n\"=dword:00000001");
        assert_eq!(format_value("n", REG_DWORD, &[1, 0]), "\"n\"=hex(4):01,00");
        assert_eq!(
            format_value("q", 11, &[1, 2, 3, 4, 5, 6, 7, 8]),
            "\"q\"=hex(b):01,02,03,04,05,06,07,08"
        );
        assert_eq!(format_value("e", 2, &[0x41, 0]), "\"e\"=hex(2):41,00");
        assert_eq!(format_value("m", 7, &[0x41, 0, 0, 0]), "\"m\"=hex(7):41,00,00,00");
        assert_eq!(format_value("b", REG_BINARY, &[0xab, 0x01]), "\"b\"=hex:ab,01");
        assert_eq!(
            format_value("c", REG_SZ, &wide_bytes("a\nb")),
            "\"c\"=hex(1):61,00,0a,00,62,00,00,00"
        );
    }

    #[test]
    fn binary_lines_wrap_after_25_bytes() {
        let data: Vec<u8> = (0..30).collect();
        let text = format_value("v", REG_BINARY, &data);
        assert!(text.starts_with("\"v\"=hex:00,01,"));
        assert!(text.contains(",\\\r\n  19,"), "{text}");
        assert!(text.ends_with("1d"), "{text}");
    }

    #[test]
    fn reg_file_has_bom_and_utf16() {
        let bytes = encode_reg_file("A\r\n");
        assert_eq!(&bytes[..6], &[0xFF, 0xFE, 0x41, 0x00, 0x0D, 0x00]);
        assert_eq!(utf16_text(&bytes), "A\r\n");
    }

    #[test]
    fn hive_names_and_codes() {
        assert_eq!(hive_name(Hive::CurrentUser), "HKEY_CURRENT_USER");
        assert_eq!(hive_name(Hive::LocalMachine), "HKEY_LOCAL_MACHINE");
        assert_eq!(win32_code("error 5"), Some(5));
        assert_eq!(win32_code("cannot open"), None);
    }

    #[test]
    fn removes_folder_and_refuses_system_folder() {
        let root = known_dirs().local_app_data.join(unique_name());
        let _guard = FolderGuard(root.clone());
        let nested = root.join("Nested");
        fs::create_dir_all(&nested).expect("create test folder");
        fs::write(nested.join("data.bin"), b"test").expect("create test file");

        let system32 = known_dirs().system32.clone();
        let items = [
            leftover(Target::Folder(root.clone())),
            leftover(Target::Folder(system32.clone())),
        ];
        let report = clean(&items, &CleanOptions::default());

        assert!(!root.exists(), "test folder should be gone");
        assert_eq!(report.removed, 1);
        assert!(report.failed.is_empty(), "{:?}", report.failed);
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].0, system32.display().to_string());
        assert!(system32.is_dir(), "System32 must be untouched");
        assert!(report.registry_backup.is_none());
    }

    #[test]
    fn missing_folder_counts_as_removed() {
        let root = known_dirs().local_app_data.join(unique_name());
        let report = clean(&[leftover(Target::Folder(root))], &CleanOptions::default());
        assert_eq!(report.removed, 1);
        assert!(report.failed.is_empty());
    }

    #[test]
    fn refuses_registry_outside_policy() {
        let item = leftover(Target::RegKey(RegLocation {
            hive: Hive::CurrentUser,
            subkey: "Software\\Microsoft".into(),
        }));
        let report = clean(&[item], &CleanOptions::default());
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.removed, 0);
        assert!(report.registry_backup.is_none());
    }

    #[test]
    fn registry_tree_is_backed_up_then_removed() {
        let subkey = format!("Software\\PoofTest-{}", std::process::id());
        let _guard = KeyGuard(subkey.clone());
        with_test_key(&subkey, |key| {
            set_value(key, "Name", REG_SZ, &wide_bytes("Test value"));
            set_value(key, "Count", REG_DWORD, &7u32.to_le_bytes());
        });
        with_test_key(&format!("{subkey}\\Child"), |key| {
            set_value(key, "Quoted", REG_SZ, &wide_bytes("a\"b\\c"))
        });
        with_test_key(&format!("{subkey}\\Child\\Deep"), |_| {});
        assert!(RegKey::exists(Hive::CurrentUser, &subkey));

        let item = leftover(Target::RegKey(RegLocation {
            hive: Hive::CurrentUser,
            subkey: subkey.clone(),
        }));
        let report = clean(&[item], &CleanOptions::default());

        assert_eq!(report.removed, 1, "{:?}", report.failed);
        assert!(report.failed.is_empty());
        assert!(!RegKey::exists(Hive::CurrentUser, &subkey));
        let backup = report.registry_backup.expect("backup path");
        let bytes = fs::read(&backup).expect("backup readable");
        let _ = fs::remove_file(&backup);

        assert_eq!(&bytes[..2], &[0xFF, 0xFE]);
        let text = utf16_text(&bytes);
        assert!(text.starts_with("Windows Registry Editor Version 5.00\r\n\r\n"));
        assert!(text.contains(&format!("[HKEY_CURRENT_USER\\{subkey}]\r\n")));
        assert!(text.contains("\"Name\"=\"Test value\""));
        assert!(text.contains("\"Count\"=dword:00000007"));
        assert!(text.contains(&format!("[HKEY_CURRENT_USER\\{subkey}\\Child]\r\n")));
        assert!(text.contains("\"Quoted\"=\"a\\\"b\\\\c\""));
        assert!(text.contains(&format!("[HKEY_CURRENT_USER\\{subkey}\\Child\\Deep]")));
    }

    #[test]
    fn autostart_value_is_removed_after_backup() {
        let name = format!("PoofTest-{}", std::process::id());
        let _guard = RunValueGuard(name.clone());
        let command = "C:\\PoofTest\\missing.exe";
        with_test_key(RUN_KEY, |key| set_value(key, &name, REG_SZ, &wide_bytes(command)));
        let target = Target::RegValue(
            RegLocation {
                hive: Hive::CurrentUser,
                subkey: RUN_KEY.into(),
            },
            name.clone(),
        );
        assert!(registry_present(&target));

        let report = clean(&[leftover(target.clone())], &CleanOptions::default());

        assert_eq!(report.removed, 1, "{:?}", report.failed);
        assert!(!registry_present(&target));
        let backup = report.registry_backup.expect("backup path");
        let text = utf16_text(&fs::read(&backup).expect("backup readable"));
        let _ = fs::remove_file(&backup);
        assert!(text.contains(&format!(
            "[HKEY_CURRENT_USER\\{RUN_KEY}]\r\n\"{name}\"=\"C:\\\\PoofTest\\\\missing.exe\""
        )));
    }

    #[test]
    fn registry_value_outside_autostart_is_refused() {
        let subkey = format!("Software\\PoofTest-{}-values", std::process::id());
        let _guard = KeyGuard(subkey.clone());
        with_test_key(&subkey, |key| set_value(key, "Keep", REG_SZ, &wide_bytes("stay")));
        let item = leftover(Target::RegValue(
            RegLocation {
                hive: Hive::CurrentUser,
                subkey: subkey.clone(),
            },
            "Keep".into(),
        ));
        let report = clean(&[item], &CleanOptions::default());
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.removed, 0);
        assert!(RegKey::exists(Hive::CurrentUser, &subkey));
        assert!(report.registry_backup.is_none());
    }
}
