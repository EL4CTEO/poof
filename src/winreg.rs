//! Minimal RAII registry wrapper (64-bit view). All reads are bounded and lossy-safe.

use windows::Win32::Foundation::{ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Registry::{
    HKEY, KEY_READ, KEY_WOW64_64KEY, KEY_WRITE, REG_DWORD, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
    RegCloseKey, RegDeleteTreeW, RegDeleteValueW, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW,
    RegQueryInfoKeyW, RegQueryValueExW,
};
use windows::core::{PCWSTR, PWSTR};

use crate::model::Hive;
use crate::util::{expand_env, from_wide, to_wide};

/// Upper bound for a single value we are willing to read (1 MiB).
const MAX_VALUE_BYTES: usize = 1 << 20;

pub struct RegKey(HKEY);

impl Drop for RegKey {
    fn drop(&mut self) {
        // SAFETY: handle was returned by RegOpenKeyExW and is closed exactly once.
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

fn ok(e: WIN32_ERROR) -> bool {
    e == ERROR_SUCCESS
}

impl RegKey {
    /// Opens `hive\subkey` read-only (or read+write when `write`).
    pub fn open(hive: Hive, subkey: &str, write: bool) -> Option<RegKey> {
        let sub = to_wide(subkey);
        let mut out = HKEY::default();
        let sam = KEY_WOW64_64KEY | if write { KEY_READ | KEY_WRITE } else { KEY_READ };
        // SAFETY: `sub` is NUL-terminated; `out` receives the handle on success.
        let r = unsafe { RegOpenKeyExW(hive.hkey(), PCWSTR(sub.as_ptr()), None, sam, &mut out) };
        ok(r).then_some(RegKey(out))
    }

    pub fn exists(hive: Hive, subkey: &str) -> bool {
        RegKey::open(hive, subkey, false).is_some()
    }

    pub fn subkey_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        let mut buf = vec![0u16; 256]; // registry key names are <= 255 chars
        for index in 0u32.. {
            let mut len = buf.len() as u32;
            // SAFETY: buffer/length pair is valid for the call.
            let r = unsafe {
                RegEnumKeyExW(self.0, index, Some(PWSTR(buf.as_mut_ptr())), &mut len, None, None, None, None)
            };
            if r == ERROR_NO_MORE_ITEMS {
                break;
            }
            if !ok(r) {
                break; // key names are at most 255 chars, so ERROR_MORE_DATA cannot occur with this buffer
            }
            names.push(from_wide(&buf[..len as usize]));
        }
        names
    }

    /// Number of direct subkeys and values (cheap emptiness check).
    pub fn counts(&self) -> (u32, u32) {
        let (mut subkeys, mut values) = (0u32, 0u32);
        // SAFETY: only the two out-pointers we need are supplied.
        let r = unsafe {
            RegQueryInfoKeyW(
                self.0, None, None, None, Some(&mut subkeys), None, None, Some(&mut values), None, None, None, None,
            )
        };
        if ok(r) { (subkeys, values) } else { (u32::MAX, u32::MAX) }
    }

    pub fn value_names(&self) -> Vec<String> {
        self.enum_values().into_iter().map(|(n, _, _)| n).collect()
    }

    /// Every value as `(name, type, raw bytes)`; oversize values are skipped.
    pub fn enum_values(&self) -> Vec<(String, u32, Vec<u8>)> {
        let mut out = Vec::new();
        let mut name = vec![0u16; 16_384]; // max value-name length is 16,383
        for index in 0u32.. {
            let mut nlen = name.len() as u32;
            let mut ty = REG_VALUE_TYPE(0);
            let mut dlen = 0u32;
            // SAFETY: first call only queries the data size.
            let r = unsafe {
                RegEnumValueW(self.0, index, Some(PWSTR(name.as_mut_ptr())), &mut nlen, None, Some(&mut ty.0), None, Some(&mut dlen))
            };
            if r == ERROR_NO_MORE_ITEMS {
                break;
            }
            if !ok(r) && r != ERROR_MORE_DATA {
                break;
            }
            let vname = from_wide(&name[..nlen as usize]);
            if dlen as usize > MAX_VALUE_BYTES {
                continue;
            }
            if let Some((t, data)) = self.query_raw(&vname) {
                out.push((vname, t, data));
            }
        }
        out
    }

    fn query_raw(&self, name: &str) -> Option<(u32, Vec<u8>)> {
        let w = to_wide(name);
        let mut ty = REG_VALUE_TYPE(0);
        let mut size = 0u32;
        // SAFETY: size query first, then read into a buffer of exactly that size.
        unsafe {
            let r = RegQueryValueExW(self.0, PCWSTR(w.as_ptr()), None, Some(&mut ty), None, Some(&mut size));
            if !ok(r) || size as usize > MAX_VALUE_BYTES {
                return None;
            }
            let mut buf = vec![0u8; size as usize];
            let mut size2 = size;
            let r = RegQueryValueExW(self.0, PCWSTR(w.as_ptr()), None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut size2));
            if !ok(r) {
                return None;
            }
            buf.truncate(size2 as usize);
            Some((ty.0, buf))
        }
    }

    /// REG_SZ / REG_EXPAND_SZ (expanded). Empty strings yield `None`.
    pub fn get_string(&self, name: &str) -> Option<String> {
        let (ty, data) = self.query_raw(name)?;
        if ty != REG_SZ.0 && ty != REG_EXPAND_SZ.0 {
            return None;
        }
        let wide: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let s = from_wide(&wide);
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        Some(if ty == REG_EXPAND_SZ.0 { expand_env(s) } else { s.to_owned() })
    }

    pub fn get_u32(&self, name: &str) -> Option<u32> {
        let (ty, data) = self.query_raw(name)?;
        if ty != REG_DWORD.0 || data.len() < 4 {
            return None;
        }
        Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
    }
}

/// Recursively deletes `hive\subkey`. Callers MUST have passed `security::check_registry_delete`.
pub fn delete_tree(hive: Hive, subkey: &str) -> Result<(), String> {
    let sub = to_wide(subkey);
    // SAFETY: NUL-terminated key path; deletes the key and everything below it.
    let r = unsafe { RegDeleteTreeW(hive.hkey(), PCWSTR(sub.as_ptr())) };
    if ok(r) {
        // RegDeleteTree removes the children but the key itself too when subkey is given.
        return Ok(());
    }
    Err(format!("error {}", r.0))
}

/// Deletes one value. Callers MUST have passed `security::check_registry_value_delete`.
pub fn delete_value(hive: Hive, subkey: &str, value: &str) -> Result<(), String> {
    let key = RegKey::open(hive, subkey, true).ok_or_else(|| "cannot open key for writing".to_owned())?;
    let v = to_wide(value);
    // SAFETY: valid open key + NUL-terminated name.
    let r = unsafe { RegDeleteValueW(key.0, PCWSTR(v.as_ptr())) };
    if ok(r) { Ok(()) } else { Err(format!("error {}", r.0)) }
}
