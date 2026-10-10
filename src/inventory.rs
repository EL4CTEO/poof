//! Enumerates installed desktop programs (registry) and Store apps.

use std::collections::HashSet;
use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::command;
use crate::model::{AppKind, Health, Hive, InstallDate, InstalledApp, RegLocation};
use crate::security::{self, known_dirs};
use crate::store;
use crate::winreg::RegKey;

const UNINSTALL_ROOTS: [(Hive, &str); 3] = [
    (Hive::LocalMachine, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (Hive::LocalMachine, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (Hive::CurrentUser, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
];

const UPDATE_RELEASE_TYPES: [&str; 5] = ["Update", "Hotfix", "Security Update", "Service Pack", "Update Rollup"];

/// Reparse point attribute (symlink, junction, mount point). Never followed.
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// Every user-visible program: classic (HKLM x64, HKLM WOW6432Node, HKCU) + Store apps.
/// Blocking; the caller runs it on a worker thread. Must be fast (target < 300 ms).
pub fn scan_all() -> Vec<InstalledApp> {
    let (mut apps, store_apps) = std::thread::scope(|scope| {
        let store = scope.spawn(store::scan_store);
        let win32 = scan_win32();
        (win32, store.join().unwrap_or_default())
    });
    apps.extend(store_apps);
    apps.sort_by(|a, b| compare_names(&a.name, &b.name));
    apps
}

/// Classic programs only.
pub fn scan_win32() -> Vec<InstalledApp> {
    let mut apps = Vec::new();
    let mut seen = HashSet::new();
    for (hive, root) in UNINSTALL_ROOTS {
        let Some(root_key) = RegKey::open(hive, root, false) else { continue };
        for key_name in root_key.subkey_names() {
            let subkey = format!("{root}\\{key_name}");
            let Some(key) = RegKey::open(hive, &subkey, false) else { continue };
            let Some(app) = build_app(hive, subkey, &key_name, &key) else { continue };
            if seen.insert(dedupe_key(&app)) {
                apps.push(app);
            }
        }
    }
    apps
}

/// Recursive size in bytes. Never follows symlinks/junctions. Returns early when `cancel` is set.
pub fn dir_size(path: &Path, cancel: &AtomicBool) -> u64 {
    if security::is_reparse_point(path) {
        return 0;
    }
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let Ok(entries) = fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if is_link_like(&meta) {
                continue;
            }
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
}

/// True if the app's registration (registry key / package) still exists.
pub fn is_registered(app: &InstalledApp) -> bool {
    match app.kind {
        AppKind::Win32 => app.reg.as_ref().is_some_and(|reg| RegKey::exists(reg.hive, &reg.subkey)),
        AppKind::Store => app.package_full_name.as_deref().is_some_and(store::is_installed),
    }
}

/// Packs a calendar date as `yyyymmdd`; 0 when the date is not plausible.
pub(crate) fn pack_date(year: i64, month: i64, day: i64) -> InstallDate {
    if !(1970..=2200).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return 0;
    }
    u32::try_from(year * 10_000 + month * 100 + day).unwrap_or(0)
}

fn build_app(hive: Hive, subkey: String, key_name: &str, key: &RegKey) -> Option<InstalledApp> {
    let name = key.get_string("DisplayName")?;
    if is_hidden_or_update(key, &name) {
        return None;
    }
    let reg = RegLocation { hive, subkey };
    let uninstall = key.get_string("UninstallString");
    let quiet = key.get_string("QuietUninstallString");
    let msi_product_code = msi_product_code(key, key_name, uninstall.as_deref());
    let icon_source = key.get_string("DisplayIcon").as_deref().and_then(clean_icon);
    let install_location = install_location(key, uninstall.as_deref(), icon_source.as_deref());
    let health = health(msi_product_code.is_some(), uninstall.as_deref(), quiet.as_deref());
    Some(InstalledApp {
        id: format!("win32:{}", reg.display()),
        kind: AppKind::Win32,
        name,
        publisher: key.get_string("Publisher").unwrap_or_default(),
        version: key.get_string("DisplayVersion").unwrap_or_default(),
        install_date: key.get_string("InstallDate").map_or(0, |s| parse_install_date(&s)),
        install_location,
        size_bytes: key.get_u32("EstimatedSize").map(|kb| u64::from(kb).saturating_mul(1024)),
        icon_source,
        uninstall_string: uninstall,
        quiet_uninstall_string: quiet,
        msi_product_code,
        help_link: help_link(key),
        reg: Some(reg),
        package_full_name: None,
        health,
    })
}

/// Hotfixes, service packs and entries the system hides from Programs and Features.
fn is_hidden_or_update(key: &RegKey, name: &str) -> bool {
    key.get_u32("SystemComponent") == Some(1)
        || key.get_string("ParentKeyName").is_some()
        || key.get_string("ParentDisplayName").is_some()
        || key.get_string("ReleaseType").is_some_and(|t| UPDATE_RELEASE_TYPES.contains(&t.as_str()))
        || is_update_name(name)
}

fn is_update_name(name: &str) -> bool {
    let kb = name.strip_prefix("KB").is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()));
    kb || name.starts_with("Security Update for") || name.starts_with("Update for Microsoft")
}

/// The product code is the key name for MSI registrations, or the GUID inside an `msiexec` command.
/// A GUID key is trusted only when it is a Windows Installer product or has no other uninstaller.
fn msi_product_code(key: &RegKey, key_name: &str, uninstall: Option<&str>) -> Option<String> {
    let msiexec = uninstall.filter(|u| command::is_msiexec_command(u));
    let guid_key_is_msi = key.get_u32("WindowsInstaller") == Some(1) || uninstall.is_none() || msiexec.is_some();
    if command::is_guid(key_name) && guid_key_is_msi {
        return Some(key_name.to_ascii_uppercase());
    }
    msiexec.and_then(command::extract_msi_guid)
}

fn install_location(key: &RegKey, uninstall: Option<&str>, icon: Option<&str>) -> Option<PathBuf> {
    let explicit = key
        .get_string("InstallLocation")
        .and_then(|s| security::validate_install_root(Path::new(&clean_path(&s))).ok());
    explicit.or_else(|| {
        let uninstall_dir =
            uninstall.and_then(|u| command::parse(u).ok()).and_then(|cmd| cmd.exe.parent().map(Path::to_path_buf));
        let icon_dir = icon.and_then(|i| Path::new(i).parent().map(Path::to_path_buf));
        [uninstall_dir, icon_dir].into_iter().flatten().find_map(|dir| validated_program_dir(&dir))
    })
}

/// A folder may be derived from an uninstaller only when it lies strictly inside a per-program root.
fn validated_program_dir(dir: &Path) -> Option<PathBuf> {
    let k = known_dirs();
    let inside_program_root = [&k.program_files, &k.program_files_x86, &k.local_programs]
        .into_iter()
        .any(|root| security::is_under_or_equal(dir, root) && !security::is_under_or_equal(root, dir));
    if inside_program_root { security::validate_install_root(dir).ok() } else { None }
}

fn health(has_msi: bool, uninstall: Option<&str>, quiet: Option<&str>) -> Health {
    if has_msi {
        return Health::Ok;
    }
    let Some(raw) = uninstall.or(quiet) else { return Health::NoUninstaller };
    match command::parse(raw) {
        Ok(_) => Health::Ok,
        Err(_) => Health::UninstallerMissing,
    }
}

fn help_link(key: &RegKey) -> Option<String> {
    ["HelpLink", "URLInfoAbout"]
        .into_iter()
        .filter_map(|name| key.get_string(name))
        .find_map(|url| security::sanitize_http_url(&url))
}

/// `DisplayIcon` without surrounding quotes and without a trailing `,<index>`.
fn clean_icon(raw: &str) -> Option<String> {
    let mut s = raw.trim();
    if let Some((head, tail)) = s.rsplit_once(',') {
        let tail = tail.trim();
        let digits = tail.strip_prefix('-').unwrap_or(tail);
        if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
            s = head;
        }
    }
    let s = s.trim().trim_matches('"').trim();
    (!s.is_empty()).then(|| s.to_owned())
}

/// Trims whitespace, quotes and trailing separators from a registry path value.
fn clean_path(raw: &str) -> String {
    raw.trim().trim_matches('"').trim().trim_end_matches(['\\', '/']).to_owned()
}

/// `yyyymmdd` from the registry, 0 when malformed or implausible.
fn parse_install_date(s: &str) -> InstallDate {
    let s = s.trim();
    if s.len() != 8 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return 0;
    }
    let field = |range: std::ops::Range<usize>| s[range].parse::<i64>().unwrap_or(-1);
    pack_date(field(0..4), field(4..6), field(6..8))
}

fn is_link_like(meta: &fs::Metadata) -> bool {
    meta.file_type().is_symlink() || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
}

fn dedupe_key(app: &InstalledApp) -> (String, String, String, String) {
    (
        app.name.to_lowercase(),
        app.version.to_lowercase(),
        app.publisher.to_lowercase(),
        app.uninstall_string.as_deref().unwrap_or_default().to_lowercase(),
    )
}

/// Case-insensitive name order without allocating per comparison.
fn compare_names(a: &str, b: &str) -> std::cmp::Ordering {
    a.chars().flat_map(char::to_lowercase).cmp(b.chars().flat_map(char::to_lowercase))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_win32_smoke() {
        let apps = scan_win32();
        assert!(!apps.is_empty());
        for app in &apps {
            assert!(!app.name.is_empty());
            assert!(app.id.starts_with("win32:"), "bad id {}", app.id);
        }
    }

    #[test]
    fn install_dates() {
        assert_eq!(parse_install_date("20240315"), 20_240_315);
        assert_eq!(parse_install_date("2024031"), 0);
        assert_eq!(parse_install_date("20241345"), 0);
        assert_eq!(parse_install_date("abcdefgh"), 0);
        assert_eq!(parse_install_date("19500101"), 0);
        assert_eq!(pack_date(1969, 12, 31), 0);
    }

    #[test]
    fn icon_cleanup() {
        assert_eq!(clean_icon("\"C:\\Program Files\\A\\a.exe\",0").as_deref(), Some("C:\\Program Files\\A\\a.exe"));
        assert_eq!(clean_icon("C:\\x\\y.ico").as_deref(), Some("C:\\x\\y.ico"));
        assert_eq!(clean_icon("C:\\x\\a.exe,-101").as_deref(), Some("C:\\x\\a.exe"));
        assert_eq!(clean_icon("   "), None);
    }

    #[test]
    fn path_cleanup() {
        assert_eq!(clean_path(" \"C:\\Foo\\\" "), "C:\\Foo");
    }

    #[test]
    fn update_names() {
        assert!(is_update_name("KB5001234 Update"));
        assert!(is_update_name("Security Update for Windows"));
        assert!(is_update_name("Update for Microsoft Office"));
        assert!(!is_update_name("KB Tool"));
        assert!(!is_update_name("Notepad++"));
    }

    #[test]
    fn names_sort_case_insensitively() {
        assert_eq!(compare_names("apple", "Banana"), std::cmp::Ordering::Less);
        assert_eq!(compare_names("Zed", "zed"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn dir_size_handles_missing_and_cancelled() {
        let never = AtomicBool::new(false);
        assert_eq!(dir_size(Path::new("C:\\definitely\\missing\\folder"), &never), 0);
        let cancelled = AtomicBool::new(true);
        assert_eq!(dir_size(&known_dirs().windows, &cancelled), 0);
    }
}
