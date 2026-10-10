//! Central safety policy.
//!
//! Every destructive action (file deletion, registry deletion) and every URL we
//! open must pass through this module first. The policy is deny-by-default:
//! a path/key is only accepted if it lies inside a known, narrow allow-list
//! *and* is not a protected location. Checks run on the canonical (symlink and
//! 8.3-resolved) location, never on the raw string supplied by the registry.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::Storage::FileSystem::GetDriveTypeW;
use windows::Win32::System::WindowsProgramming::DRIVE_FIXED;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::{
    FOLDERID_CommonPrograms, FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_Downloads, FOLDERID_LocalAppData,
    FOLDERID_Music, FOLDERID_Pictures, FOLDERID_ProgramData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86,
    FOLDERID_Profile, FOLDERID_Programs, FOLDERID_PublicDesktop, FOLDERID_RoamingAppData, FOLDERID_System,
    FOLDERID_Videos, FOLDERID_Windows, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
};
use windows::core::{GUID, PCWSTR};

use crate::model::Hive;
use crate::util::to_wide;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyError(pub String);

impl std::fmt::Display for SafetyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for SafetyError {}

fn deny<T>(msg: impl Into<String>) -> Result<T, SafetyError> {
    Err(SafetyError(msg.into()))
}

// ---------------------------------------------------------------------------
// Elevation
// ---------------------------------------------------------------------------

/// True when the current process runs with an elevated (administrator) token.
pub fn is_elevated() -> bool {
    // SAFETY: standard token query on our own process; the handle is closed before return.
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let r = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        let _ = CloseHandle(token);
        r.is_ok() && elevation.TokenIsElevated != 0
    }
}

// ---------------------------------------------------------------------------
// Known folders
// ---------------------------------------------------------------------------

pub struct KnownDirs {
    pub windows: PathBuf,
    pub system32: PathBuf,
    pub program_files: PathBuf,
    pub program_files_x86: PathBuf,
    pub program_data: PathBuf,
    pub local_app_data: PathBuf,
    pub local_programs: PathBuf,
    pub roaming_app_data: PathBuf,
    pub user_profile: PathBuf,
    pub users_root: PathBuf,
    pub start_menu_user: PathBuf,
    pub start_menu_common: PathBuf,
    pub desktop_user: PathBuf,
    pub desktop_common: PathBuf,
    /// Personal folders that must never be removed as a whole.
    pub personal: Vec<PathBuf>,
}

fn known_folder(id: &GUID) -> Option<PathBuf> {
    // SAFETY: the returned buffer is owned by us and freed with CoTaskMemFree.
    unsafe {
        let p = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None).ok()?;
        let s = p.to_string().ok();
        CoTaskMemFree(Some(p.0 as *const _));
        s.filter(|s| !s.is_empty()).map(PathBuf::from)
    }
}

/// Resolved once; falls back to conventional locations if the shell cannot answer.
pub fn known_dirs() -> &'static KnownDirs {
    static DIRS: OnceLock<KnownDirs> = OnceLock::new();
    DIRS.get_or_init(|| {
        let get = |id: &GUID, fallback: &str| known_folder(id).unwrap_or_else(|| PathBuf::from(fallback));
        let windows = get(&FOLDERID_Windows, "C:\\Windows");
        let local_app_data = get(&FOLDERID_LocalAppData, "C:\\Users\\Default\\AppData\\Local");
        let user_profile = get(&FOLDERID_Profile, "C:\\Users\\Default");
        let users_root = user_profile.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("C:\\Users"));
        let personal = [&FOLDERID_Documents, &FOLDERID_Downloads, &FOLDERID_Pictures, &FOLDERID_Music, &FOLDERID_Videos]
            .iter()
            .filter_map(|id| known_folder(id))
            .collect();
        KnownDirs {
            system32: get(&FOLDERID_System, "C:\\Windows\\System32"),
            program_files: get(&FOLDERID_ProgramFiles, "C:\\Program Files"),
            program_files_x86: get(&FOLDERID_ProgramFilesX86, "C:\\Program Files (x86)"),
            program_data: get(&FOLDERID_ProgramData, "C:\\ProgramData"),
            local_programs: local_app_data.join("Programs"),
            roaming_app_data: get(&FOLDERID_RoamingAppData, "C:\\Users\\Default\\AppData\\Roaming"),
            start_menu_user: get(&FOLDERID_Programs, "C:\\Users\\Default\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs"),
            start_menu_common: get(&FOLDERID_CommonPrograms, "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs"),
            desktop_user: get(&FOLDERID_Desktop, "C:\\Users\\Default\\Desktop"),
            desktop_common: get(&FOLDERID_PublicDesktop, "C:\\Users\\Public\\Desktop"),
            local_app_data,
            user_profile,
            users_root,
            windows,
            personal,
        }
    })
}

// ---------------------------------------------------------------------------
// Path normalisation and comparison
// ---------------------------------------------------------------------------

const RESERVED_NAMES: [&str; 22] = [
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2",
    "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Turns an untrusted string into a clean `X:\a\b` path or rejects it.
/// Rejects: UNC/device paths, relative paths, `.`/`..`, ADS (`:`), wildcards,
/// control characters, trailing dot/space segments and reserved device names.
pub fn normalize_lexical(p: &Path) -> Result<PathBuf, SafetyError> {
    let Some(s) = p.to_str() else { return deny("path is not valid Unicode") };
    let s = s.strip_prefix("\\\\?\\").unwrap_or(s);
    if s.starts_with("UNC\\") || s.starts_with("\\\\") || s.starts_with("//") {
        return deny("network and device paths are not allowed");
    }
    let b = s.as_bytes();
    if b.len() < 3 || !b[0].is_ascii_alphabetic() || b[1] != b':' || (b[2] != b'\\' && b[2] != b'/') {
        return deny("not an absolute local path");
    }
    let mut out = format!("{}:\\", (b[0] as char).to_ascii_uppercase());
    let mut first = true;
    for seg in s[3..].split(['\\', '/']) {
        if seg.is_empty() {
            continue;
        }
        if seg == "." || seg == ".." {
            return deny("relative path segments are not allowed");
        }
        if seg.chars().any(|c| c.is_control() || "<>:\"|?*".contains(c)) {
            return deny("path contains illegal characters");
        }
        if seg.ends_with('.') || seg.ends_with(' ') {
            return deny("path segment ends with dot or space");
        }
        let stem = seg.split('.').next().unwrap_or("").to_lowercase();
        if RESERVED_NAMES.contains(&stem.as_str()) {
            return deny("reserved device name in path");
        }
        if !first {
            out.push('\\');
        }
        out.push_str(seg);
        first = false;
    }
    Ok(PathBuf::from(out))
}

fn comps_ci(p: &Path) -> Vec<String> {
    p.to_string_lossy().split(['\\', '/']).filter(|s| !s.is_empty()).map(str::to_lowercase).collect()
}

/// True if `path` equals `prefix` or lies below it (component-wise, case-insensitive).
pub fn is_under_or_equal(path: &Path, prefix: &Path) -> bool {
    let (a, b) = (comps_ci(path), comps_ci(prefix));
    !b.is_empty() && a.len() >= b.len() && a[..b.len()] == b[..]
}

/// Components of `path` below `prefix` (lower-cased), `None` if not under it.
fn rel_below(path: &Path, prefix: &Path) -> Option<Vec<String>> {
    let (a, b) = (comps_ci(path), comps_ci(prefix));
    if b.is_empty() || a.len() < b.len() || a[..b.len()] != b[..] {
        return None;
    }
    Some(a[b.len()..].to_vec())
}

fn strip_verbatim(p: PathBuf) -> Result<PathBuf, SafetyError> {
    let s = p.to_string_lossy();
    if s.starts_with("\\\\?\\UNC\\") {
        return deny("resolves to a network location");
    }
    Ok(match s.strip_prefix("\\\\?\\") {
        Some(rest) => PathBuf::from(rest.to_owned()),
        None => p,
    })
}

/// Fully resolves symlinks/junctions/8.3 names of an existing path.
pub fn canonicalize(p: &Path) -> Result<PathBuf, SafetyError> {
    let c = std::fs::canonicalize(p).map_err(|e| SafetyError(format!("cannot resolve path: {e}")))?;
    strip_verbatim(c)
}

/// Canonical parent + original file name: resolves links in every ancestor while
/// leaving the final component alone (so a link itself can be removed, never followed).
fn resolve_parent(lexical: &Path) -> Result<PathBuf, SafetyError> {
    let Some(parent) = lexical.parent() else { return deny("path has no parent") };
    let Some(name) = lexical.file_name() else { return deny("path has no file name") };
    Ok(canonicalize(parent)?.join(name))
}

pub fn is_reparse_point(p: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    std::fs::symlink_metadata(p).map(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0).unwrap_or(false)
}

fn is_fixed_drive(p: &Path) -> bool {
    let s = p.to_string_lossy();
    let Some(drive) = s.get(..2) else { return false };
    let root = to_wide(&format!("{drive}\\"));
    // SAFETY: NUL-terminated root path.
    unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) == DRIVE_FIXED }
}

/// Folder names that must never be touched when found directly under a
/// standard root (Program Files, ProgramData, AppData, ...).
const PROTECTED_TOP: &[&str] = &[
    "microsoft", "microsoft shared", "microsoft.net", "windows", "windows nt", "windows defender",
    "windows defender advanced threat protection", "windows mail", "windows media player", "windows photo viewer",
    "windows portable devices", "windows security", "windows sidebar", "windowsapps", "modifiablewindowsapps",
    "windowspowershell", "common files", "internet explorer", "reference assemblies", "msbuild", "dotnet",
    "package cache", "packages", "temp", "tmp", "uninstall information", "application data", "history",
    "temporary internet files", "crashdumps", "d3dscache", "connecteddevicesplatform", "comms", "publishers",
    "systemapps", "system32", "syswow64", "installer", "ssh", "nvidia corporation", "nvidia", "intel", "amd",
    "driverstore", "sentinel", "usoshared", "usoprivate", "regid.1991-06.com.microsoft",
];

/// Roots under which deletions may happen. `bool` = strictly-below-only.
fn standard_roots() -> Vec<&'static Path> {
    let k = known_dirs();
    vec![
        &k.program_files,
        &k.program_files_x86,
        &k.program_data,
        &k.local_app_data,
        &k.local_programs,
        &k.roaming_app_data,
        &k.start_menu_user,
        &k.start_menu_common,
        &k.desktop_user,
        &k.desktop_common,
    ]
}

/// Folders that may never be removed *as a whole* (and neither may any ancestor of them).
fn protected_dirs() -> Vec<&'static Path> {
    let k = known_dirs();
    let mut v: Vec<&Path> = vec![
        &k.windows,
        &k.system32,
        &k.program_files,
        &k.program_files_x86,
        &k.program_data,
        &k.local_app_data,
        &k.local_programs,
        &k.roaming_app_data,
        &k.user_profile,
        &k.users_root,
        &k.start_menu_user,
        &k.start_menu_common,
        &k.desktop_user,
        &k.desktop_common,
    ];
    v.extend(k.personal.iter().map(PathBuf::as_path));
    v
}

fn check_protected(resolved: &Path) -> Result<(), SafetyError> {
    let k = known_dirs();
    let comps = comps_ci(resolved);
    if comps.len() < 2 {
        return deny("refusing to remove a drive root");
    }
    for d in protected_dirs() {
        if is_under_or_equal(d, resolved) {
            return deny(format!("refusing to remove protected folder '{}'", resolved.display()));
        }
    }
    if is_under_or_equal(resolved, &k.windows) {
        return deny("refusing to touch the Windows directory");
    }
    let shell_area = [&k.start_menu_user, &k.start_menu_common, &k.desktop_user, &k.desktop_common]
        .into_iter()
        .any(|r| rel_below(resolved, r).is_some());
    if shell_area {
        // Start Menu / Desktop live under Roaming and ProgramData\Microsoft; guard the OS-owned shortcut folders.
        const SHELL_PROTECTED: &[&str] = &[
            "accessories", "administrative tools", "startup", "system tools", "windows accessories", "windows powershell",
            "windows system", "windows administrative tools", "windows ease of access", "maintenance", "accessibility",
        ];
        for root in [&k.start_menu_user, &k.start_menu_common] {
            if let Some(first) = rel_below(resolved, root).and_then(|r| r.first().cloned()) {
                if SHELL_PROTECTED.contains(&first.as_str()) {
                    return deny(format!("'{first}' is a protected Start Menu folder"));
                }
            }
        }
    } else {
        for root in standard_roots() {
            if let Some(first) = rel_below(resolved, root).and_then(|r| r.first().cloned()) {
                if PROTECTED_TOP.contains(&first.as_str()) && !is_under_or_equal(root, &k.local_programs) {
                    return deny(format!("'{first}' is a protected system/vendor folder"));
                }
            }
        }
    }
    // Drive-root level system folders.
    if comps.len() == 2 {
        const ROOT_PROTECTED: &[&str] = &[
            "windows", "users", "program files", "program files (x86)", "programdata", "system volume information",
            "$recycle.bin", "recovery", "boot", "perflogs", "documents and settings", "config.msi", "msocache",
            "$windows.~bt", "$windows.~ws", "windows.old", "efi", "intel", "onedrivetemp", "sources",
        ];
        if ROOT_PROTECTED.contains(&comps[1].as_str()) {
            return deny("refusing to remove a system folder");
        }
    }
    Ok(())
}

/// Validates an application's install location so it can be used as an extra
/// deletion root. Returns the canonical directory.
pub fn validate_install_root(p: &Path) -> Result<PathBuf, SafetyError> {
    let lexical = normalize_lexical(p)?;
    if comps_ci(&lexical).len() < 2 {
        return deny("install location is a drive root");
    }
    if is_reparse_point(&lexical) {
        return deny("install location is a link");
    }
    let resolved = canonicalize(&lexical)?;
    if !resolved.is_dir() {
        return deny("install location is not a folder");
    }
    if !is_fixed_drive(&resolved) {
        return deny("install location is not on a fixed drive");
    }
    check_protected(&resolved)?;
    Ok(resolved)
}

/// Gatekeeper for deleting a file or folder. `extra_roots` must come from
/// [`validate_install_root`]. Returns the canonical path to delete.
pub fn check_path_delete(path: &Path, extra_roots: &[PathBuf]) -> Result<PathBuf, SafetyError> {
    let lexical = normalize_lexical(path)?;
    let resolved = resolve_parent(&lexical)?;
    if !is_fixed_drive(&resolved) {
        return deny("only fixed drives are allowed");
    }
    check_protected(&resolved)?;

    let mut allowed = standard_roots().into_iter().any(|r| rel_below(&resolved, r).is_some_and(|rel| !rel.is_empty()));
    if !allowed {
        allowed = extra_roots.iter().any(|r| is_under_or_equal(&resolved, r));
    }
    if !allowed {
        return deny("location is outside the permitted cleanup areas");
    }

    // Shortcuts only on the desktops: never delete user files there.
    let k = known_dirs();
    if is_under_or_equal(&resolved, &k.desktop_user) || is_under_or_equal(&resolved, &k.desktop_common) {
        let ext = resolved.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
        if ext != "lnk" && ext != "url" {
            return deny("only shortcuts may be removed from the desktop");
        }
    }
    Ok(resolved)
}

// ---------------------------------------------------------------------------
// Registry policy
// ---------------------------------------------------------------------------

/// Top-level `SOFTWARE\<name>` keys that are never removable.
const PROTECTED_SOFTWARE: &[&str] = &[
    "microsoft", "classes", "policies", "wow6432node", "windows", "clients", "registeredapplications", "odbc",
    "javasoft", "partner", "intel", "nvidia corporation", "amd", "realtek", "dolby", "windows nt", "setup", "ime",
    "wow6432node\\microsoft",
];

fn split_key(subkey: &str) -> Result<Vec<String>, SafetyError> {
    let trimmed = subkey.trim_matches('\\');
    if trimmed.is_empty() {
        return deny("empty registry path");
    }
    if trimmed.chars().any(|c| c.is_control()) || trimmed.len() > 1024 {
        return deny("invalid registry path");
    }
    let parts: Vec<String> = trimmed.split('\\').map(str::to_lowercase).collect();
    if parts.iter().any(String::is_empty) {
        return deny("invalid registry path");
    }
    Ok(parts)
}

/// Splits `software[\wow6432node]\rest` and returns `rest`.
fn software_rest(parts: &[String]) -> Result<&[String], SafetyError> {
    if parts.first().map(String::as_str) != Some("software") {
        return deny("only keys under SOFTWARE may be removed");
    }
    let mut rest = &parts[1..];
    if rest.first().map(String::as_str) == Some("wow6432node") {
        rest = &rest[1..];
    }
    if rest.is_empty() {
        return deny("refusing to remove a top-level software key");
    }
    Ok(rest)
}

/// Gatekeeper for deleting a registry key (recursively).
pub fn check_registry_delete(_hive: Hive, subkey: &str) -> Result<(), SafetyError> {
    let parts = split_key(subkey)?;
    let rest = software_rest(&parts)?;

    // Uninstall / App Paths registrations: exactly one level below the container.
    const CONTAINERS: [[&str; 4]; 2] =
        [["microsoft", "windows", "currentversion", "uninstall"], ["microsoft", "windows", "currentversion", "app paths"]];
    for c in CONTAINERS {
        if rest.len() >= 4 && rest[..4].iter().map(String::as_str).eq(c) {
            return if rest.len() == 5 { Ok(()) } else { deny("only a single registration key may be removed here") };
        }
    }
    if PROTECTED_SOFTWARE.contains(&rest[0].as_str()) {
        return deny(format!("'{}' is a protected registry area", rest[0]));
    }
    Ok(())
}

/// Gatekeeper for deleting a single registry value (autostart entries only).
pub fn check_registry_value_delete(_hive: Hive, subkey: &str, value: &str) -> Result<(), SafetyError> {
    if value.is_empty() || value.chars().any(|c| c.is_control()) {
        return deny("invalid value name");
    }
    let parts = split_key(subkey)?;
    let rest = software_rest(&parts)?;
    let joined = rest.join("\\");
    const ALLOWED: [&str; 3] = [
        "microsoft\\windows\\currentversion\\run",
        "microsoft\\windows\\currentversion\\runonce",
        "microsoft\\windows\\currentversion\\explorer\\startupapproved\\run",
    ];
    if ALLOWED.contains(&joined.as_str()) { Ok(()) } else { deny("values may only be removed from autostart keys") }
}

// ---------------------------------------------------------------------------
// URLs
// ---------------------------------------------------------------------------

/// Accepts only plain `http(s)` URLs without control characters or whitespace.
pub fn sanitize_http_url(s: &str) -> Option<String> {
    let s = s.trim();
    let lower = s.to_ascii_lowercase();
    let scheme_ok = lower.starts_with("https://") || lower.starts_with("http://");
    if !scheme_ok || s.len() > 2048 || s.chars().any(|c| c.is_control() || c.is_whitespace() || c == '"' || c == '<' || c == '>') {
        return None;
    }
    Some(s.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn lexical_rejects_bad_paths() {
        for bad in [
            "relative\\path", "\\\\server\\share\\x", "\\\\?\\UNC\\s\\x", "\\\\.\\C:\\x", "C:\\a\\..\\b", "C:\\a\\.\\b",
            "C:\\a\\b:stream", "C:\\a\\b*", "C:\\a\\nul", "C:\\a\\con.txt", "C:\\a\\b.", "C:\\a\\b ", "C:foo", "",
        ] {
            assert!(normalize_lexical(&p(bad)).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn lexical_normalizes() {
        assert_eq!(normalize_lexical(&p("c:/Foo//Bar\\")).unwrap(), p("C:\\Foo\\Bar"));
        assert_eq!(normalize_lexical(&p("\\\\?\\C:\\Foo")).unwrap(), p("C:\\Foo"));
    }

    #[test]
    fn prefix_logic() {
        assert!(is_under_or_equal(&p("C:\\A\\B"), &p("c:\\a")));
        assert!(is_under_or_equal(&p("C:\\A"), &p("C:\\a")));
        assert!(!is_under_or_equal(&p("C:\\AB"), &p("C:\\A")));
        assert!(!is_under_or_equal(&p("C:\\A"), &p("C:\\A\\B")));
    }

    #[test]
    fn deletes_outside_roots_are_denied() {
        for bad in [
            "C:\\", "C:\\Windows", "C:\\Windows\\System32\\drivers", "C:\\Users", "C:\\Program Files",
            "C:\\Program Files\\Microsoft", "C:\\Program Files\\Windows Defender\\x", "C:\\ProgramData",
            "C:\\ProgramData\\Microsoft\\Windows", "C:\\Users\\Public\\Documents", "\\\\srv\\share\\a",
        ] {
            assert!(check_path_delete(&p(bad), &[]).is_err(), "should deny {bad:?}");
        }
        let k = known_dirs();
        for bad in [&k.local_app_data, &k.roaming_app_data, &k.user_profile, &k.local_programs] {
            assert!(check_path_delete(bad, &[]).is_err(), "should deny root {bad:?}");
        }
        assert!(check_path_delete(&k.local_app_data.join("Microsoft").join("Edge"), &[]).is_err());
        assert!(check_path_delete(&k.local_app_data.join("Temp"), &[]).is_err());
    }

    #[test]
    fn deletes_inside_roots_are_allowed() {
        let k = known_dirs();
        assert!(check_path_delete(&k.local_app_data.join("SomeVendorApp"), &[]).is_ok());
        assert!(check_path_delete(&k.local_programs.join("SomeApp"), &[]).is_ok());
        assert!(check_path_delete(&k.program_files.join("SomeApp"), &[]).is_ok());
    }

    #[test]
    fn desktop_only_shortcuts() {
        let k = known_dirs();
        assert!(check_path_delete(&k.desktop_user.join("notes.docx"), &[]).is_err());
        assert!(check_path_delete(&k.desktop_user.join("SomeApp.lnk"), &[]).is_ok());
    }

    #[test]
    fn install_root_validation() {
        assert!(validate_install_root(&p("C:\\")).is_err());
        assert!(validate_install_root(&p("C:\\Windows")).is_err());
        assert!(validate_install_root(&p("C:\\Users")).is_err());
        assert!(validate_install_root(&known_dirs().user_profile).is_err());
        assert!(validate_install_root(&p("C:\\Program Files")).is_err());
        assert!(validate_install_root(&p("C:\\Program Files\\Microsoft")).is_err());
        assert!(validate_install_root(&p("relative")).is_err());
    }

    #[test]
    fn registry_key_policy() {
        use Hive::*;
        for bad in [
            "", "SOFTWARE", "SOFTWARE\\Microsoft", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "SOFTWARE\\Classes\\CLSID",
            "SOFTWARE\\WOW6432Node", "SOFTWARE\\WOW6432Node\\Microsoft\\Windows", "SYSTEM\\CurrentControlSet\\Services\\x",
            "SOFTWARE\\Policies\\Foo", "SOFTWARE\\\\Foo", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\A\\B",
        ] {
            assert!(check_registry_delete(LocalMachine, bad).is_err(), "should deny {bad:?}");
        }
        for good in [
            "SOFTWARE\\SomeVendor", "SOFTWARE\\SomeVendor\\Product", "SOFTWARE\\WOW6432Node\\SomeVendor\\Product",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{GUID}",
            "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\App",
            "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\app.exe",
        ] {
            assert!(check_registry_delete(CurrentUser, good).is_ok(), "should allow {good:?}");
        }
    }

    #[test]
    fn registry_value_policy() {
        use Hive::*;
        let run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        assert!(check_registry_value_delete(CurrentUser, run, "Foo").is_ok());
        assert!(check_registry_value_delete(CurrentUser, run, "").is_err());
        assert!(check_registry_value_delete(CurrentUser, "Software\\Foo", "x").is_err());
    }

    #[test]
    fn url_policy() {
        assert!(sanitize_http_url("https://example.com/a?b=c").is_some());
        assert!(sanitize_http_url("javascript:alert(1)").is_none());
        assert!(sanitize_http_url("file:///C:/x").is_none());
        assert!(sanitize_http_url("https://a.com/ b").is_none());
        assert!(sanitize_http_url("https://a.com/\"x").is_none());
    }
}
