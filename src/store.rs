//! Microsoft Store / MSIX packages via WinRT PackageManager.

use std::path::PathBuf;

use windows::ApplicationModel::{Package, PackageId, PackageSignatureKind};
use windows::Management::Deployment::PackageManager;
use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize};
use windows::core::HSTRING;

use crate::audit;
use crate::inventory::pack_date;
use crate::model::{AppKind, Health, InstallDate, InstalledApp};

/// Seconds between 1601-01-01 (WinRT DateTime epoch) and 1970-01-01 (Unix epoch).
const FILETIME_UNIX_EPOCH_SECS: i64 = 11_644_473_600;
const TICKS_PER_SEC: i64 = 10_000_000;
const MAX_FULL_NAME_LEN: usize = 256;

/// Installed Store apps of the current user (frameworks, resource packs, system/non-removable
/// packages excluded). Blocking.
pub fn scan_store() -> Vec<InstalledApp> {
    let _winrt = WinRt::init();
    let Ok(manager) = PackageManager::new() else { return Vec::new() };
    let Ok(packages) = manager.FindPackagesByUserSecurityId(&HSTRING::new()) else { return Vec::new() };
    packages.into_iter().filter_map(|package| to_app(&package)).collect()
}

/// Removes a package for the current user. Blocking (waits for the async operation).
pub fn remove_package(package_full_name: &str) -> Result<(), String> {
    if !is_valid_full_name(package_full_name) {
        return Err("invalid package name".into());
    }
    let _winrt = WinRt::init();
    let manager = PackageManager::new().map_err(|e| describe("cannot reach the Store package manager", &e))?;
    let operation = manager
        .RemovePackageAsync(&HSTRING::from(package_full_name))
        .map_err(|e| describe("the Store app could not be removed", &e))?;
    let result = operation.join().map_err(|e| describe("the Store app could not be removed", &e))?;

    let failed = result.ExtendedErrorCode().is_ok_and(|code| code.is_err());
    let text = result.ErrorText().map(|t| t.to_string()).unwrap_or_default();
    if failed || !text.trim().is_empty() {
        let reason = first_line(&text);
        audit::log(&format!("store uninstall failed: {package_full_name}: {reason}"));
        return Err(format!("the Store app could not be removed: {reason}"));
    }
    audit::log(&format!("store uninstall ok: {package_full_name}"));
    Ok(())
}

/// True if a package with this full name is still installed for the current user.
pub fn is_installed(package_full_name: &str) -> bool {
    if !is_valid_full_name(package_full_name) {
        return false;
    }
    let _winrt = WinRt::init();
    PackageManager::new().is_ok_and(|manager| {
        manager.FindPackageByUserSecurityIdPackageFullName(&HSTRING::new(), &HSTRING::from(package_full_name)).is_ok()
    })
}

/// Per-thread WinRT initialisation. The guard undoes it on drop, but only when this call is the one that succeeded.
struct WinRt(bool);

impl WinRt {
    fn init() -> Self {
        // SAFETY: plain per-thread initialisation with a valid apartment type.
        Self(unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.is_ok())
    }
}

impl Drop for WinRt {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: balances the successful RoInitialize call made in `init` on this same thread.
            unsafe { RoUninitialize() };
        }
    }
}

/// Strict whitelist for package full names (`Name_Version_Arch__PublisherId`).
fn is_valid_full_name(name: &str) -> bool {
    (1..=MAX_FULL_NAME_LEN).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
}

/// Converts one package; `None` for anything that should not be listed or cannot be read.
fn to_app(package: &Package) -> Option<InstalledApp> {
    if package.IsFramework().unwrap_or(true)
        || package.IsResourcePackage().unwrap_or(true)
        || package.IsBundle().unwrap_or(true)
    {
        return None;
    }
    if package.SignatureKind().ok()? == PackageSignatureKind::System || !is_removable(package) {
        return None;
    }
    let id = package.Id().ok()?;
    let full_name = id.FullName().ok()?.to_string();
    let name = display_name(package, &id)?;
    let version = id.Version().ok()?;
    Some(InstalledApp {
        id: format!("store:{full_name}"),
        kind: AppKind::Store,
        name,
        publisher: package.PublisherDisplayName().map(|s| s.to_string()).unwrap_or_default(),
        version: format!("{}.{}.{}.{}", version.Major, version.Minor, version.Build, version.Revision),
        install_date: package.InstalledDate().map_or(0, |date| date_from_ticks(date.UniversalTime)),
        install_location: package
            .InstalledPath()
            .map(|s| s.to_string())
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from),
        size_bytes: None,
        icon_source: None,
        uninstall_string: None,
        quiet_uninstall_string: None,
        msi_product_code: None,
        help_link: None,
        reg: None,
        package_full_name: Some(full_name),
        health: Health::Ok,
    })
}

/// Packages the system reports as not available cannot be removed reliably.
fn is_removable(package: &Package) -> bool {
    package.Status().is_ok_and(|status| !status.NotAvailable().unwrap_or(true))
}

/// The display name, falling back to the package identity name. `None` when it is empty or only a resource reference.
fn display_name(package: &Package, id: &PackageId) -> Option<String> {
    let raw = match package.DisplayName() {
        Ok(name) => name.to_string(),
        Err(_) => id.Name().ok()?.to_string(),
    };
    let name = raw.trim();
    let resource_reference = name.starts_with('@') || name.to_ascii_lowercase().contains("ms-resource:");
    (!name.is_empty() && !resource_reference).then(|| name.to_owned())
}

/// WinRT DateTime (100 ns ticks since 1601-01-01 UTC) as `yyyymmdd`.
fn date_from_ticks(ticks: i64) -> InstallDate {
    let days = (ticks / TICKS_PER_SEC - FILETIME_UNIX_EPOCH_SECS).div_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    pack_date(year, month, day)
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn describe(context: &str, error: &windows::core::Error) -> String {
    format!("{context} (HRESULT 0x{:08X})", error.code().0 as u32)
}

/// First non-empty line of a WinRT error text, shortened for display.
fn first_line(text: &str) -> String {
    text.lines().map(str::trim).find(|line| !line.is_empty()).unwrap_or("unknown error").chars().take(160).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_name_whitelist() {
        assert!(is_valid_full_name("Microsoft.WindowsCalculator_11.2409.4.0_x64__8wekyb3d8bbwe"));
        assert!(is_valid_full_name(&"a".repeat(MAX_FULL_NAME_LEN)));
        assert!(!is_valid_full_name(""));
        assert!(!is_valid_full_name(&"a".repeat(MAX_FULL_NAME_LEN + 1)));
        for bad in ["a b", "a/b", "a;calc", "a\\b", "a\"b", "a|b", "a\0b"] {
            assert!(!is_valid_full_name(bad), "should reject {bad:?}");
        }
    }

    #[test]
    fn winrt_dates_to_yyyymmdd() {
        assert_eq!(date_from_ticks(0), 0);
        assert_eq!(date_from_ticks(FILETIME_UNIX_EPOCH_SECS * TICKS_PER_SEC), 19_700_101);
        assert_eq!(date_from_ticks((951_868_800 + FILETIME_UNIX_EPOCH_SECS) * TICKS_PER_SEC), 20_000_301);
    }

    #[test]
    fn invalid_names_never_reach_winrt() {
        assert!(remove_package("bad;name").is_err());
        assert!(!is_installed("bad;name"));
        assert!(!is_installed(""));
    }

    #[test]
    fn first_line_is_short_and_non_empty() {
        assert_eq!(first_line("  \n\nreal error\nmore"), "real error");
        assert_eq!(first_line(""), "unknown error");
        assert_eq!(first_line(&"x".repeat(500)).chars().count(), 160);
    }
}
