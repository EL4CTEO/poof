//! End-to-end test on a fake app: inventory -> uninstall -> force remove -> leftover scan -> clean.
//! Touches only `HKCU\Software\PoofE2E<pid>`, its Uninstall key and `%LOCALAPPDATA%\PoofE2E<pid>`.

use std::fs;
use std::sync::atomic::AtomicBool;

use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegSetValueExW,
};
use windows::core::PCWSTR;

use crate::cleaner::{self, CleanOptions};
use crate::inventory;
use crate::leftovers::{self, Target};
use crate::model::Hive;
use crate::security::known_dirs;
use crate::uninstall::{self, Mode};
use crate::util::to_wide;
use crate::winreg;

fn set_str(subkey: &str, name: &str, value: &str) {
    let sub = to_wide(subkey);
    let mut key = HKEY::default();
    // SAFETY: NUL-terminated strings, out handle valid; the key is closed before returning.
    unsafe {
        let r = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(sub.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut key,
            None,
        );
        assert_eq!(r, ERROR_SUCCESS, "cannot create {subkey}");
        let data: Vec<u8> = value.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
        let n = to_wide(name);
        let r = RegSetValueExW(key, PCWSTR(n.as_ptr()), None, REG_SZ, Some(&data));
        assert_eq!(r, ERROR_SUCCESS);
        let _ = RegCloseKey(key);
    }
}

/// Removes everything the test created, even when an assertion fails.
struct Cleanup {
    folder: std::path::PathBuf,
    keys: Vec<String>,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.folder);
        for k in &self.keys {
            let _ = winreg::delete_tree(Hive::CurrentUser, k);
        }
    }
}

#[test]
fn fake_app_full_pipeline() {
    let name = format!("PoofE2E{}", std::process::id());
    let uninstall_key = format!("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{name}");
    let software_key = format!("Software\\{name}");
    let folder = known_dirs().local_app_data.join(&name);
    let _guard = Cleanup { folder: folder.clone(), keys: vec![uninstall_key.clone(), software_key.clone()] };

    // A fake installed app whose "uninstaller" (whoami.exe) exits at once and removes nothing.
    fs::create_dir_all(folder.join("sub")).expect("create folder");
    fs::write(folder.join("sub").join("data.txt"), b"leftover").expect("write file");
    set_str(&software_key, "Setting", "1");
    set_str(&uninstall_key, "DisplayName", &name);
    set_str(&uninstall_key, "Publisher", "PoofE2E Labs");
    set_str(&uninstall_key, "InstallLocation", &folder.to_string_lossy());
    let whoami = known_dirs().system32.join("whoami.exe");
    set_str(&uninstall_key, "UninstallString", &format!("\"{}\"", whoami.display()));

    // 1. Inventory sees it.
    let app = inventory::scan_win32().into_iter().find(|a| a.name == name).expect("fake app listed");
    assert_eq!(app.health, crate::model::Health::Ok);
    assert!(app.install_location.is_some());

    // 2. Uninstaller runs (cooperative cancel flag unused); registration stays because whoami removes nothing.
    let cancel = AtomicBool::new(false);
    let outcome = uninstall::run(&app, Mode::Interactive, &cancel).expect("uninstaller runs");
    assert_eq!(outcome.exit_code, Some(0));
    assert!(outcome.still_registered);

    // 3. Force-remove the registration.
    uninstall::force_remove_entry(&app).expect("force remove");
    assert!(!inventory::is_registered(&app));

    // 4. Leftover scan finds the folder and the vendor settings key.
    let items = leftovers::scan(&app, &cancel, &|_| {});
    let has_folder = items.iter().any(|i| matches!(&i.target, Target::Folder(p) if p == &folder));
    let has_key = items.iter().any(|i| matches!(&i.target, Target::RegKey(k) if k.subkey.eq_ignore_ascii_case(&software_key)));
    assert!(has_folder && has_key, "scan result: {items:?}");

    // 5. Clean everything found (permanent delete), then verify.
    let opts = CleanOptions { use_recycle_bin: false, install_root: app.install_location.clone() };
    let report = cleaner::clean(&items, &opts);
    assert!(report.failed.is_empty() && report.skipped.is_empty(), "{report:?}");
    assert!(!folder.exists());
    assert!(!winreg::RegKey::exists(Hive::CurrentUser, &software_key));
    let backup = report.registry_backup.expect("registry backup written");
    assert!(backup.exists());
    let _ = fs::remove_file(backup);
}
