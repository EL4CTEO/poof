//! Core data types shared by every module. No Win32 calls in here.

use std::path::PathBuf;

use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

/// Registry hive an entry lives in. Only the 64-bit view is used; 32-bit
/// software is reached through the physical `WOW6432Node` path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Hive {
    LocalMachine,
    CurrentUser,
}

impl Hive {
    pub fn hkey(self) -> HKEY {
        match self {
            Hive::LocalMachine => HKEY_LOCAL_MACHINE,
            Hive::CurrentUser => HKEY_CURRENT_USER,
        }
    }
    pub fn short(self) -> &'static str {
        match self {
            Hive::LocalMachine => "HKLM",
            Hive::CurrentUser => "HKCU",
        }
    }
}

/// A registry key location (physical path under the hive, no leading backslash).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RegLocation {
    pub hive: Hive,
    pub subkey: String,
}

impl RegLocation {
    pub fn display(&self) -> String {
        format!("{}\\{}", self.hive.short(), self.subkey)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppKind {
    /// Classic desktop program (registered under an `Uninstall` key, incl. MSI).
    Win32,
    /// Microsoft Store / MSIX package.
    Store,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Health {
    Ok,
    /// Has an uninstall command, but its executable no longer exists.
    UninstallerMissing,
    /// Registered without any uninstall command.
    NoUninstaller,
}

/// Install date as `yyyymmdd` (sortable); 0 = unknown.
pub type InstallDate = u32;

#[derive(Clone, Debug)]
pub struct InstalledApp {
    /// Stable unique id: `win32:HKLM\<subkey>` or `store:<PackageFullName>`.
    pub id: String,
    pub kind: AppKind,
    pub name: String,
    pub publisher: String,
    pub version: String,
    pub install_date: InstallDate,
    pub install_location: Option<PathBuf>,
    /// Best known size in bytes (registry EstimatedSize or measured).
    pub size_bytes: Option<u64>,
    /// Raw `DisplayIcon` / executable used to fetch the icon (env vars expanded).
    pub icon_source: Option<String>,
    pub uninstall_string: Option<String>,
    pub quiet_uninstall_string: Option<String>,
    /// `{GUID}` when the product is an MSI product.
    pub msi_product_code: Option<String>,
    pub help_link: Option<String>,
    pub reg: Option<RegLocation>,
    /// Store apps only.
    pub package_full_name: Option<String>,
    pub health: Health,
}

impl InstalledApp {
    /// Lower-cased haystack for the live search box.
    pub fn haystack(&self) -> String {
        format!("{} {} {}", self.name, self.publisher, self.version).to_lowercase()
    }
    pub fn is_store(&self) -> bool {
        self.kind == AppKind::Store
    }
}
