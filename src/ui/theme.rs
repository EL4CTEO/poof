//! Light/dark theme, fonts, DPI scaling and the owner-drawn controls.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use windows::Win32::Foundation::{COLORREF, FARPROC, HMODULE, HWND, LPARAM, POINT, RECT};
use windows::Win32::Graphics::Dwm::{DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute};
use windows::Win32::Graphics::Gdi::{
    CreateFontIndirectW, CreatePen, CreateSolidBrush, DEFAULT_CHARSET, DEFAULT_GUI_FONT, DRAW_TEXT_FORMAT, DT_CENTER,
    DT_END_ELLIPSIS, DT_LEFT, DT_NOPREFIX, DT_SINGLELINE, DT_VCENTER, DeleteObject, DrawFocusRect, DrawTextW,
    FW_NORMAL, GetStockObject, HDC, HFONT, HGDIOBJ, LOGFONTW, LineTo, MoveToEx, NULL_BRUSH, PS_SOLID, RoundRect,
    SelectObject, SetBkMode, SetTextColor, TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW};
use windows::Win32::UI::Controls::{
    DRAWITEMSTRUCT, LVM_GETHEADER, LVM_SETBKCOLOR, LVM_SETTEXTBKCOLOR, LVM_SETTEXTCOLOR, ODS_DISABLED, ODS_FOCUS,
    ODS_SELECTED, SetWindowTheme,
};
use windows::Win32::UI::HiDpi::{GetDpiForWindow, SystemParametersInfoForDpi};
use windows::Win32::UI::WindowsAndMessaging::{
    GetClassNameW, NONCLIENTMETRICSW, SPI_GETNONCLIENTMETRICS, SendMessageW,
};
use windows::core::{BOOL, PCSTR, PCWSTR, w};

use crate::model::Hive;
use crate::util::to_wide;
use crate::winreg::RegKey;

const PERSONALIZE_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize";
const UI_FONT_FACE: &str = "Segoe UI";

/// Set by [`apply_window`] so that [`palette`] stays a cheap, registry-free call.
static DARK: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug)]
pub struct Palette {
    pub bg: COLORREF,
    pub bg_alt: COLORREF,
    pub text: COLORREF,
    pub text_dim: COLORREF,
    pub accent: COLORREF,
    pub border: COLORREF,
    /// Reserved for the flow dialogs' error emphasis.
    #[allow(dead_code)]
    pub danger: COLORREF,
}

const fn rgb(r: u8, g: u8, b: u8) -> COLORREF {
    COLORREF(r as u32 | (g as u32) << 8 | (b as u32) << 16)
}

const LIGHT: Palette = Palette {
    bg: rgb(255, 255, 255),
    bg_alt: rgb(243, 243, 243),
    text: rgb(0, 0, 0),
    text_dim: rgb(96, 96, 96),
    accent: rgb(0, 120, 212),
    border: rgb(200, 200, 200),
    danger: rgb(196, 43, 28),
};

const DARK_PALETTE: Palette = Palette {
    bg: rgb(32, 32, 32),
    bg_alt: rgb(43, 43, 43),
    text: rgb(240, 240, 240),
    text_dim: rgb(160, 160, 160),
    accent: rgb(76, 160, 255),
    border: rgb(70, 70, 70),
    danger: rgb(255, 99, 88),
};

/// True when the user's apps theme is dark (`AppsUseLightTheme == 0`).
pub fn is_dark() -> bool {
    RegKey::open(Hive::CurrentUser, PERSONALIZE_KEY, false)
        .and_then(|key| key.get_u32("AppsUseLightTheme"))
        .is_some_and(|light| light == 0)
}

/// Colours of the mode chosen by the last [`apply_window`].
pub fn palette() -> Palette {
    if DARK.load(Ordering::Relaxed) { DARK_PALETTE } else { LIGHT }
}

/// Dark title bar, dark popup menus, and the cached mode used by [`palette`]. Call on creation and
/// whenever the system theme changes.
pub fn apply_window(hwnd: HWND) {
    let dark = is_dark();
    DARK.store(dark, Ordering::Relaxed);
    let value = BOOL::from(dark);
    // SAFETY: `value` outlives the call and has the size the attribute expects. Failure (older
    // Windows without the attribute) is harmless, so the result is ignored.
    unsafe {
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            &value as *const BOOL as *const c_void,
            size_of::<BOOL>() as u32,
        );
    }
    set_app_mode(dark);
}

type SetPreferredAppMode = unsafe extern "system" fn(i32) -> i32;
type FlushMenuThemes = unsafe extern "system" fn();

/// Undocumented uxtheme exports (ordinals 135/136). Best effort: `None` when unavailable.
fn uxtheme_export(ordinal: usize) -> FARPROC {
    // SAFETY: the system copy of uxtheme.dll is loaded; the module stays mapped for the process lifetime.
    let module: HMODULE = unsafe { LoadLibraryExW(w!("uxtheme.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32) }.ok()?;
    // SAFETY: a PCSTR holding a small integer is the documented MAKEINTRESOURCE ordinal form.
    unsafe { GetProcAddress(module, PCSTR(ordinal as *const u8)) }
}

/// Lets popup menus follow the app theme and refreshes their cached theme data.
fn set_app_mode(dark: bool) {
    let Some(set) = uxtheme_export(135) else { return };
    let Some(flush) = uxtheme_export(136) else { return };
    // SAFETY: ordinal 135 is SetPreferredAppMode(int) -> int and 136 is FlushMenuThemes() on Windows 10 1903+;
    // on other systems the lookup above already failed.
    unsafe {
        let set: SetPreferredAppMode = std::mem::transmute::<unsafe extern "system" fn() -> isize, _>(set);
        let flush: FlushMenuThemes = std::mem::transmute::<unsafe extern "system" fn() -> isize, _>(flush);
        // 1 = AllowDark (follow the app theme), 0 = Default (light).
        set(i32::from(dark));
        flush();
    }
}

fn class_name(hwnd: HWND) -> String {
    let mut buf = [0u16; 64];
    // SAFETY: `buf` is a valid writable buffer whose length is passed to the call.
    let len = unsafe { GetClassNameW(hwnd, &mut buf) };
    String::from_utf16_lossy(&buf[..usize::try_from(len).unwrap_or(0).min(buf.len())])
}

/// Applies the matching visual style to one control (dark variants when the app theme is dark).
/// ListViews also get their colours and header theme.
pub fn apply_control(hwnd: HWND) {
    let dark = DARK.load(Ordering::Relaxed);
    let class = class_name(hwnd);
    let theme = match (class.as_str(), dark) {
        ("ComboBox" | "Edit", true) => "DarkMode_CFD",
        (_, true) => "DarkMode_Explorer",
        (_, false) => "Explorer",
    };
    let theme = to_wide(theme);
    // SAFETY: `theme` is NUL-terminated and outlives the call; no sub-id list is passed.
    unsafe {
        let _ = SetWindowTheme(hwnd, PCWSTR(theme.as_ptr()), PCWSTR::null());
    }
    if class == "SysListView32" {
        style_list_view(hwnd, dark);
    }
}

fn style_list_view(list: HWND, dark: bool) {
    let p = palette();
    // SAFETY: `list` is a live ListView owned by this thread; the colour messages take a COLORREF in lParam.
    unsafe {
        SendMessageW(list, LVM_SETBKCOLOR, None, Some(LPARAM(p.bg.0 as isize)));
        SendMessageW(list, LVM_SETTEXTBKCOLOR, None, Some(LPARAM(p.bg.0 as isize)));
        SendMessageW(list, LVM_SETTEXTCOLOR, None, Some(LPARAM(p.text.0 as isize)));
        let header = HWND(SendMessageW(list, LVM_GETHEADER, None, None).0 as *mut c_void);
        let theme = to_wide(if dark { "DarkMode_ItemsView" } else { "Explorer" });
        let _ = SetWindowTheme(header, PCWSTR(theme.as_ptr()), PCWSTR::null());
    }
}

/// Font cache per DPI. Values are `HFONT` handles stored as integers; fonts are never deleted.
static FONTS: Mutex<Option<HashMap<u32, isize>>> = Mutex::new(None);

/// Cached UI font (Segoe UI) for the given DPI. Never delete the returned handle.
pub fn ui_font(dpi: u32) -> HFONT {
    let Ok(mut cache) = FONTS.lock() else { return HFONT::default() };
    let map = cache.get_or_insert_with(HashMap::new);
    if let Some(&raw) = map.get(&dpi) {
        return HFONT(raw as *mut c_void);
    }
    let font = create_ui_font(dpi);
    map.insert(dpi, font.0 as isize);
    font
}

fn create_ui_font(dpi: u32) -> HFONT {
    let mut ncm = NONCLIENTMETRICSW { cbSize: size_of::<NONCLIENTMETRICSW>() as u32, ..Default::default() };
    // SAFETY: `ncm` is a writable NONCLIENTMETRICSW whose size is passed in cbSize.
    let got = unsafe {
        SystemParametersInfoForDpi(
            SPI_GETNONCLIENTMETRICS.0,
            size_of::<NONCLIENTMETRICSW>() as u32,
            Some(&mut ncm as *mut NONCLIENTMETRICSW as *mut c_void),
            0,
            dpi,
        )
    }
    .is_ok();
    let lf = if got { ncm.lfMessageFont } else { fallback_font(dpi) };
    // SAFETY: plain value conversion; `lf` is a complete LOGFONTW for the duration of the call.
    let font = unsafe { CreateFontIndirectW(&lf) };
    if font.0.is_null() {
        // SAFETY: stock objects need no cleanup.
        return HFONT(unsafe { GetStockObject(DEFAULT_GUI_FONT) }.0);
    }
    font
}

fn fallback_font(dpi: u32) -> LOGFONTW {
    let mut lf = LOGFONTW {
        lfHeight: -((9 * dpi as i32 + 36) / 72),
        lfWeight: FW_NORMAL.0 as i32,
        lfCharSet: DEFAULT_CHARSET,
        ..Default::default()
    };
    for (slot, unit) in lf.lfFaceName.iter_mut().zip(UI_FONT_FACE.encode_utf16()) {
        *slot = unit;
    }
    lf
}

/// Scales a 96-dpi pixel value to `dpi`.
pub fn scale(px: i32, dpi: u32) -> i32 {
    (px as i64 * dpi as i64 / 96) as i32
}

/// Linear blend `a -> b` by `t` in 0..=1.
pub fn mix(a: COLORREF, b: COLORREF, t: f32) -> COLORREF {
    let channel = |shift: u32| {
        let x = ((a.0 >> shift) & 0xff) as f32;
        let y = ((b.0 >> shift) & 0xff) as f32;
        (x + (y - x) * t).round().clamp(0.0, 255.0) as u32
    };
    COLORREF(channel(0) | (channel(8) << 8) | (channel(16) << 16))
}

/// Selects a GDI object into a DC and restores the previous one on drop.
struct Selected {
    hdc: HDC,
    old: HGDIOBJ,
}

impl Selected {
    fn new(hdc: HDC, object: HGDIOBJ) -> Self {
        // SAFETY: `hdc` is a valid DC for the duration of the paint call; the old object is restored on drop.
        let old = unsafe { SelectObject(hdc, object) };
        Self { hdc, old }
    }
}

impl Drop for Selected {
    fn drop(&mut self) {
        // SAFETY: restores the object that was selected before us into the same DC.
        unsafe {
            SelectObject(self.hdc, self.old);
        }
    }
}

/// Owns a GDI pen or brush and deletes it on drop.
struct GdiObject(HGDIOBJ);

impl Drop for GdiObject {
    fn drop(&mut self) {
        // SAFETY: the handle was created by us and is not selected into any DC at this point.
        unsafe {
            let _ = DeleteObject(self.0);
        }
    }
}

fn dpi_of(hwnd: HWND) -> u32 {
    // SAFETY: a stale handle just yields 0.
    match unsafe { GetDpiForWindow(hwnd) } {
        0 => 96,
        dpi => dpi,
    }
}

/// Filled rounded rectangle with an optional 1 px border.
fn round_rect(hdc: HDC, rect: RECT, fill: COLORREF, border: COLORREF, radius: i32) {
    let brush = GdiObject(HGDIOBJ(
        // SAFETY: plain GDI object creation; the returned handle is owned by `brush` below.
        unsafe { CreateSolidBrush(fill) }.0,
    ));
    let pen = GdiObject(HGDIOBJ(
        // SAFETY: as above.
        unsafe { CreatePen(PS_SOLID, 1, border) }.0,
    ));
    let _brush = Selected::new(hdc, brush.0);
    let _pen = Selected::new(hdc, pen.0);
    // SAFETY: valid DC with the pen and brush selected; coordinates come from the item rectangle.
    unsafe {
        let _ = RoundRect(hdc, rect.left, rect.top, rect.right, rect.bottom, radius, radius);
    }
}

/// Outline-only rounded rectangle.
fn round_frame(hdc: HDC, rect: RECT, color: COLORREF, radius: i32) {
    let pen = GdiObject(HGDIOBJ(
        // SAFETY: plain GDI object creation, owned by `pen`.
        unsafe { CreatePen(PS_SOLID, 1, color) }.0,
    ));
    // SAFETY: NULL_BRUSH is a stock object and needs no cleanup.
    let hollow = unsafe { GetStockObject(NULL_BRUSH) };
    let _pen = Selected::new(hdc, pen.0);
    let _brush = Selected::new(hdc, hollow);
    // SAFETY: valid DC with the pen selected.
    unsafe {
        let _ = RoundRect(hdc, rect.left, rect.top, rect.right, rect.bottom, radius, radius);
    }
}

fn draw_label(hdc: HDC, rect: &mut RECT, text: &str, color: COLORREF, format: DRAW_TEXT_FORMAT) {
    let mut wide: Vec<u16> = text.encode_utf16().collect();
    // SAFETY: valid DC; `rect` and the text buffer are live for the call.
    unsafe {
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, color);
        DrawTextW(hdc, &mut wide, rect as *mut RECT, format);
    }
}

/// Paints an owner-drawn push button (`BS_OWNERDRAW`) from `WM_DRAWITEM`: flat, rounded corners,
/// palette colours, pressed / disabled / focus states. `primary` = accent-filled.
pub fn draw_button(dis: &DRAWITEMSTRUCT, label: &str, primary: bool) {
    let p = palette();
    let dpi = dpi_of(dis.hwndItem);
    let state = dis.itemState.0;
    let disabled = state & ODS_DISABLED.0 != 0;
    let pressed = state & ODS_SELECTED.0 != 0;
    let focused = state & ODS_FOCUS.0 != 0;

    let (fill, text, border) = match (primary, pressed) {
        (true, false) => (p.accent, rgb(255, 255, 255), p.accent),
        (true, true) => (mix(p.accent, rgb(0, 0, 0), 0.2), rgb(255, 255, 255), p.accent),
        (false, false) => (p.bg_alt, p.text, p.border),
        (false, true) => (mix(p.bg_alt, p.border, 0.6), p.text, p.border),
    };
    let (fill, text) = if disabled { (mix(fill, p.bg, 0.6), mix(text, p.bg, 0.45)) } else { (fill, text) };

    let hdc = dis.hDC;
    let radius = scale(6, dpi);
    let mut rect = dis.rcItem;
    round_rect(hdc, rect, fill, border, radius);
    {
        let _font = Selected::new(hdc, HGDIOBJ(ui_font(dpi).0));
        draw_label(hdc, &mut rect, label, text, DT_SINGLELINE | DT_VCENTER | DT_CENTER | DT_NOPREFIX | DT_END_ELLIPSIS);
    }
    if focused {
        let inset = scale(4, dpi);
        let frame = RECT {
            left: dis.rcItem.left + inset,
            top: dis.rcItem.top + inset,
            right: dis.rcItem.right - inset,
            bottom: dis.rcItem.bottom - inset,
        };
        let focus_color = if primary { rgb(255, 255, 255) } else { p.accent };
        round_frame(hdc, frame, focus_color, (radius - inset).max(1));
    }
}

/// Paints an owner-drawn checkbox (`BS_OWNERDRAW`) from `WM_DRAWITEM`; `checked` is supplied by the caller.
pub fn draw_checkbox(dis: &DRAWITEMSTRUCT, label: &str, checked: bool) {
    let p = palette();
    let dpi = dpi_of(dis.hwndItem);
    let state = dis.itemState.0;
    let disabled = state & ODS_DISABLED.0 != 0;
    let focused = state & ODS_FOCUS.0 != 0;
    let hdc = dis.hDC;
    let row = dis.rcItem;

    let side = scale(16, dpi);
    let top = row.top + (row.bottom - row.top - side) / 2;
    let boxed = RECT { left: row.left, top, right: row.left + side, bottom: top + side };
    let (fill, border, text) = match (checked, disabled) {
        (true, false) => (p.accent, p.accent, p.text),
        (true, true) => (p.border, p.border, p.text_dim),
        (false, false) => (p.bg_alt, p.border, p.text),
        (false, true) => (p.bg_alt, p.border, p.text_dim),
    };
    round_rect(hdc, boxed, fill, border, scale(3, dpi));

    if checked {
        let pen = GdiObject(HGDIOBJ(
            // SAFETY: plain GDI object creation, owned by `pen`.
            unsafe { CreatePen(PS_SOLID, scale(2, dpi), rgb(255, 255, 255)) }.0,
        ));
        let _pen = Selected::new(hdc, pen.0);
        let at = |fx: f32, fy: f32| POINT {
            x: boxed.left + (side as f32 * fx) as i32,
            y: boxed.top + (side as f32 * fy) as i32,
        };
        let (a, b, c) = (at(0.25, 0.52), at(0.43, 0.7), at(0.76, 0.3));
        // SAFETY: valid DC with the check-mark pen selected; points are inside the box.
        unsafe {
            let _ = MoveToEx(hdc, a.x, a.y, None);
            let _ = LineTo(hdc, b.x, b.y);
            let _ = LineTo(hdc, c.x, c.y);
        }
    }

    let mut label_rect = RECT { left: boxed.right + scale(8, dpi), top: row.top, right: row.right, bottom: row.bottom };
    {
        let _font = Selected::new(hdc, HGDIOBJ(ui_font(dpi).0));
        draw_label(
            hdc,
            &mut label_rect,
            label,
            text,
            DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_NOPREFIX | DT_END_ELLIPSIS,
        );
    }
    if focused {
        // SAFETY: valid DC; the rectangle is the label area of this item.
        unsafe {
            let _ = DrawFocusRect(hdc, &label_rect);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaling() {
        assert_eq!(scale(100, 96), 100);
        assert_eq!(scale(100, 144), 150);
        assert_eq!(scale(44, 192), 88);
    }

    #[test]
    fn colour_mix_endpoints_and_midpoint() {
        let black = rgb(0, 0, 0);
        let white = rgb(255, 255, 255);
        assert_eq!(mix(black, white, 0.0), black);
        assert_eq!(mix(black, white, 1.0), white);
        let mid = mix(black, white, 0.5);
        assert!((mid.0 & 0xff).abs_diff(128) <= 1);
    }

    #[test]
    fn rgb_packs_channels_in_colorref_order() {
        assert_eq!(rgb(0x11, 0x22, 0x33).0, 0x0033_2211);
    }
}
