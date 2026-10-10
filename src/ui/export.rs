//! CSV export of the program list: UTF-8 with BOM, RFC 4180 quoting, and a guard against
//! spreadsheet formula injection (cells starting with `= + - @`, tab or CR are prefixed with `'`).

use std::ffi::c_void;
use std::fs;
use std::path::PathBuf;

use windows::Win32::Foundation::HWND;
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance, CoTaskMemFree};
use windows::Win32::UI::Shell::Common::COMDLG_FILTERSPEC;
use windows::Win32::UI::Shell::{FileSaveDialog, IFileSaveDialog, IShellItem, SIGDN_FILESYSPATH};
use windows::core::w;

use crate::model::{AppKind, InstalledApp};
use crate::ui::list::format_date;

const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];
const HEADER: &str = "Name,Publisher,Version,Installed,Size (bytes),Type,Install location";

/// One CSV field, with formula-injection guard and RFC 4180 quoting.
pub fn csv_cell(text: &str) -> String {
    let guarded = if text.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{text}") } else { text.to_owned() };
    if guarded.contains([',', '"', '\r', '\n']) { format!("\"{}\"", guarded.replace('"', "\"\"")) } else { guarded }
}

/// The whole file: BOM, header row, one row per program. CRLF line endings.
pub fn build_csv(apps: &[InstalledApp]) -> Vec<u8> {
    let mut out = Vec::with_capacity(UTF8_BOM.len() + HEADER.len() + apps.len() * 96);
    out.extend_from_slice(UTF8_BOM);
    out.extend_from_slice(HEADER.as_bytes());
    out.extend_from_slice(b"\r\n");
    for app in apps {
        let size = app.size_bytes.map(|b| b.to_string()).unwrap_or_default();
        let kind = match app.kind {
            AppKind::Win32 => "Program",
            AppKind::Store => "Store app",
        };
        let location = app.install_location.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
        let fields = [
            csv_cell(&app.name),
            csv_cell(&app.publisher),
            csv_cell(&app.version),
            csv_cell(&format_date(app.install_date)),
            csv_cell(&size),
            csv_cell(kind),
            csv_cell(&location),
        ];
        out.extend_from_slice(fields.join(",").as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Asks for a destination and writes the CSV. `Ok(None)` when the user cancels.
pub fn save_csv(owner: HWND, apps: &[InstalledApp]) -> Result<Option<PathBuf>, String> {
    let Some(path) = pick_path(owner)? else { return Ok(None) };
    let bytes = build_csv(apps);
    fs::write(&path, bytes).map_err(|e| format!("Could not write the file: {e}"))?;
    Ok(Some(path))
}

fn pick_path(owner: HWND) -> Result<Option<PathBuf>, String> {
    // SAFETY: COM is initialised on the UI thread by `run`; the interface pointers are released on drop.
    unsafe {
        let dialog: IFileSaveDialog =
            CoCreateInstance(&FileSaveDialog, None, CLSCTX_INPROC_SERVER).map_err(|e| e.to_string())?;
        dialog.SetFileName(w!("programs.csv")).map_err(|e| e.to_string())?;
        dialog.SetDefaultExtension(w!("csv")).map_err(|e| e.to_string())?;
        let filter = [COMDLG_FILTERSPEC { pszName: w!("CSV file"), pszSpec: w!("*.csv") }];
        dialog.SetFileTypes(&filter).map_err(|e| e.to_string())?;
        if dialog.Show(Some(owner)).is_err() {
            return Ok(None); // cancelled
        }
        let item: IShellItem = dialog.GetResult().map_err(|e| e.to_string())?;
        let name = item.GetDisplayName(SIGDN_FILESYSPATH).map_err(|e| e.to_string())?;
        let path = name.to_string();
        CoTaskMemFree(Some(name.0 as *const c_void));
        path.map(|p| Some(PathBuf::from(p))).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Health;

    #[test]
    fn formula_prefixes_are_neutralised() {
        assert_eq!(csv_cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_cell("+1"), "'+1");
        assert_eq!(csv_cell("-Tool"), "'-Tool");
        assert_eq!(csv_cell("@sum"), "'@sum");
        assert_eq!(csv_cell("\tx"), "'\tx");
        assert_eq!(csv_cell("a=b"), "a=b");
    }

    #[test]
    fn rfc4180_quoting() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("line\nbreak"), "\"line\nbreak\"");
        assert_eq!(csv_cell(""), "");
    }

    #[test]
    fn csv_has_bom_header_and_rows() {
        let app = InstalledApp {
            id: "win32:HKLM\\x".into(),
            kind: AppKind::Store,
            name: "=calc".into(),
            publisher: "Acme, Inc".into(),
            version: "1.0".into(),
            install_date: 20_250_131,
            install_location: None,
            size_bytes: Some(42),
            icon_source: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            msi_product_code: None,
            help_link: None,
            reg: None,
            package_full_name: None,
            health: Health::Ok,
        };
        let bytes = build_csv(&[app]);
        assert!(bytes.starts_with(UTF8_BOM));
        let text = String::from_utf8(bytes[UTF8_BOM.len()..].to_vec()).unwrap_or_default();
        let mut lines = text.split("\r\n");
        assert_eq!(lines.next(), Some(HEADER));
        assert_eq!(lines.next(), Some("'=calc,\"Acme, Inc\",1.0,2025-01-31,42,Store app,"));
        assert_eq!(lines.next(), Some(""));
    }
}
