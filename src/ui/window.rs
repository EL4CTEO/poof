//! Main window: creation, the window procedure, layout, the status strip, commands and menus.
//!
//! Re-entrancy rule: `with` hands out the window state for the length of one closure. Never send
//! messages, show menus or enter modal loops inside that closure; do the work, drop the borrow, then act.

use std::collections::HashSet;
use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};

use windows::Win32::Foundation::{GlobalFree, HANDLE, HINSTANCE, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateSolidBrush, DRAW_TEXT_FORMAT, DT_LEFT, DT_NOPREFIX, DT_RIGHT, DT_SINGLELINE, DT_VCENTER,
    DeleteObject, DrawTextW, EndPaint, FillRect, HBRUSH, HDC, HGDIOBJ, InvalidateRect, PAINTSTRUCT, SelectObject,
    SetBkColor, SetBkMode, SetTextColor, TRANSPARENT,
};
use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize};
use windows::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use windows::Win32::UI::Controls::{
    CDDS_ITEMPREPAINT, CDDS_PREPAINT, CDDS_SUBITEM, CDRF_NEWFONT, CDRF_NOTIFYITEMDRAW, CDRF_NOTIFYSUBITEMDRAW,
    DRAWITEMSTRUCT, EM_SETCUEBANNER, EM_SETSEL, ICC_BAR_CLASSES, ICC_LISTVIEW_CLASSES, ICC_STANDARD_CLASSES,
    INITCOMMONCONTROLSEX, InitCommonControlsEx, LVN_COLUMNCLICK, LVN_GETDISPINFOW, LVN_ITEMCHANGED, LVS_OWNERDATA,
    LVS_REPORT, LVS_SHOWSELALWAYS, NM_CUSTOMDRAW, NM_DBLCLK, NM_RCLICK, NMHDR, NMITEMACTIVATE, NMLISTVIEW,
    NMLVCUSTOMDRAW, NMLVDISPINFOW,
};
use windows::Win32::UI::HiDpi::{AdjustWindowRectExForDpi, GetDpiForSystem, GetDpiForWindow};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    EnableWindow, GetKeyState, SetFocus, VIRTUAL_KEY, VK_A, VK_APPS, VK_C, VK_CONTROL, VK_DELETE, VK_DOWN, VK_ESCAPE,
    VK_F, VK_F5, VK_F10, VK_RETURN, VK_SHIFT,
};
use windows::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass, ShellExecuteW};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, BN_CLICKED, BS_OWNERDRAW, CB_ADDSTRING, CB_GETCURSEL, CB_SETCURSEL, CBN_SELCHANGE, CBS_DROPDOWNLIST,
    CBS_HASSTRINGS, CS_HREDRAW, CS_VREDRAW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu,
    DestroyWindow, DispatchMessageW, EN_CHANGE, ES_AUTOHSCROLL, FindWindowW, GWLP_USERDATA, GetClientRect,
    GetCursorPos, GetMessageW, GetParent, GetSystemMetrics, GetWindowLongPtrW, GetWindowRect, GetWindowTextLengthW,
    GetWindowTextW, HCURSOR, HICON, HMENU, IDC_ARROW, IMAGE_ICON, IsChild, IsIconic, KillTimer, LR_DEFAULTCOLOR,
    LoadCursorW, LoadImageW, MENU_ITEM_FLAGS, MF_GRAYED, MF_SEPARATOR, MF_STRING, MINMAXINFO, MSG, MoveWindow,
    PostQuitMessage, RegisterClassExW, SM_CXICON, SM_CXSCREEN, SM_CXSMICON, SM_CYICON, SM_CYSCREEN, SM_CYSMICON,
    SPI_GETWORKAREA, SW_RESTORE, SW_SHOW, SW_SHOWNORMAL, SWP_NOACTIVATE, SWP_NOZORDER, SendMessageW,
    SetForegroundWindow, SetTimer, SetWindowLongPtrW, SetWindowPos, SetWindowTextW, ShowWindow, SystemParametersInfoW,
    TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenu, TranslateMessage, WINDOW_EX_STYLE, WINDOW_STYLE, WM_COMMAND,
    WM_CREATE, WM_CTLCOLOREDIT, WM_CTLCOLORLISTBOX, WM_DESTROY, WM_DPICHANGED, WM_DRAWITEM, WM_ERASEBKGND,
    WM_GETMINMAXINFO, WM_KEYDOWN, WM_NCCREATE, WM_NCDESTROY, WM_NOTIFY, WM_PAINT, WM_SETFONT, WM_SETTINGCHANGE,
    WM_SIZE, WM_SYSKEYDOWN, WM_TIMER, WNDCLASSEXW, WS_BORDER, WS_CHILD, WS_CLIPCHILDREN, WS_OVERLAPPEDWINDOW,
    WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
};
use windows::core::{PCWSTR, w};

use crate::RELAUNCH_ARG;
use crate::app_info::{APP_NAME, WINDOW_CLASS};
use crate::audit;
use crate::model::{AppKind, Health, InstalledApp};
use crate::security;
use crate::ui::dialogs::{self, Icon};
use crate::ui::export;
use crate::ui::flow::{self, Action};
use crate::ui::list::{self, Column, Filter, Icons, Model, Sort};
use crate::ui::msg::{WM_APP_REFRESH, WM_APP_SCAN_DONE, WM_APP_SIZE_DONE};
use crate::ui::theme::{self, scale};
use crate::ui::worker::{self, ScanResult, SizeResult, SizeWorker};
use crate::uninstall;
use crate::util::{format_size, path_to_wide, to_wide};

// ---------------------------------------------------------------------------
// Ids and layout constants (96-dpi pixels; scaled at use)
// ---------------------------------------------------------------------------

const IDC_SEARCH: i32 = 101;
const IDC_FILTER: i32 = 102;
const IDC_UNINSTALL: i32 = 103;
const IDC_REFRESH: i32 = 104;
const IDC_MORE: i32 = 105;
const IDC_LIST: i32 = 106;

const IDM_UNINSTALL: usize = 201;
const IDM_QUIET: usize = 202;
const IDM_FORCE: usize = 203;
const IDM_OPEN_FOLDER: usize = 204;
const IDM_OPEN_WEB: usize = 205;
const IDM_SEARCH_WEB: usize = 206;
const IDM_COPY_NAME: usize = 207;
const IDM_COPY_DETAILS: usize = 208;
const IDM_EXPORT: usize = 301;
const IDM_RUNAS: usize = 302;
const IDM_DATA_FOLDER: usize = 303;
const IDM_ABOUT: usize = 304;
const IDM_EXIT: usize = 305;

const TIMER_SEARCH: usize = 1;
const SEARCH_DEBOUNCE_MS: u32 = 120;
const LIST_SUBCLASS: usize = 1;
const SEARCH_SUBCLASS: usize = 2;

const START_W: i32 = 1000;
const START_H: i32 = 640;
const MIN_W: i32 = 760;
const MIN_H: i32 = 420;
const TOOLBAR_H: i32 = 44;
const STATUS_H: i32 = 28;
const CONTROL_H: i32 = 28;
const FILTER_DROP_H: i32 = 220;
const PAD: i32 = 12;
const GAP: i32 = 8;

const EDIT_STYLE: u32 = WS_CHILD.0 | WS_VISIBLE.0 | WS_TABSTOP.0 | WS_BORDER.0 | ES_AUTOHSCROLL as u32;
const COMBO_STYLE: u32 =
    WS_CHILD.0 | WS_VISIBLE.0 | WS_TABSTOP.0 | WS_VSCROLL.0 | CBS_DROPDOWNLIST as u32 | CBS_HASSTRINGS as u32;
const BUTTON_STYLE: u32 = WS_CHILD.0 | WS_VISIBLE.0 | WS_TABSTOP.0 | BS_OWNERDRAW as u32;
const LIST_STYLE: u32 =
    WS_CHILD.0 | WS_VISIBLE.0 | WS_TABSTOP.0 | WS_BORDER.0 | LVS_REPORT | LVS_OWNERDATA | LVS_SHOWSELALWAYS;

/// Handle of the main window, readable from the message loop without the state.
static MAIN: AtomicIsize = AtomicIsize::new(0);

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Brushes used for the palette backgrounds. Recreated on theme change, deleted on drop.
#[derive(Default)]
struct Brushes {
    bg: HBRUSH,
    alt: HBRUSH,
}

impl Brushes {
    fn new() -> Self {
        let p = theme::palette();
        Brushes { bg: solid_brush(p.bg), alt: solid_brush(p.bg_alt) }
    }
}

impl Drop for Brushes {
    fn drop(&mut self) {
        for brush in [self.bg, self.alt] {
            if !brush.0.is_null() {
                // SAFETY: created by `solid_brush`, not selected into any DC at this point.
                unsafe {
                    let _ = DeleteObject(HGDIOBJ(brush.0));
                }
            }
        }
    }
}

fn solid_brush(color: windows::Win32::Foundation::COLORREF) -> HBRUSH {
    // SAFETY: plain GDI object creation; the caller owns the result through `Brushes`.
    unsafe { CreateSolidBrush(color) }
}

struct State {
    dpi: u32,
    search: HWND,
    filter: HWND,
    uninstall: HWND,
    refresh: HWND,
    more: HWND,
    list: HWND,
    icons: Icons,
    model: Model,
    /// Incremented by every scan; results from older generations are ignored.
    generation: u32,
    scanning: bool,
    selected: usize,
    /// Cancels the size jobs of the current generation.
    cancel: Arc<AtomicBool>,
    sizes: Option<SizeWorker>,
    brushes: Brushes,
}

impl State {
    fn new() -> Self {
        State {
            dpi: 96,
            search: HWND::default(),
            filter: HWND::default(),
            uninstall: HWND::default(),
            refresh: HWND::default(),
            more: HWND::default(),
            list: HWND::default(),
            icons: Icons::default(),
            model: Model::default(),
            generation: 0,
            scanning: false,
            selected: 0,
            cancel: Arc::new(AtomicBool::new(false)),
            sizes: None,
            brushes: Brushes::default(),
        }
    }

    fn controls(&self) -> [HWND; 6] {
        [self.search, self.filter, self.uninstall, self.refresh, self.more, self.list]
    }

    fn status_texts(&self) -> (String, String) {
        let left = if self.scanning {
            "Loading programs...".to_owned()
        } else {
            let count = self.model.count();
            let noun = if count == 1 { "program" } else { "programs" };
            format!("{count} {noun} \u{b7} {}", format_size(self.model.total_bytes()))
        };
        let right = if self.selected > 0 { format!("{} selected", self.selected) } else { String::new() };
        (left, right)
    }
}

impl Drop for State {
    fn drop(&mut self) {
        // Stops any folder measurement still running for this window.
        self.cancel.store(true, Ordering::Relaxed);
    }
}

/// Runs `f` on the window state. See the module note: never send messages inside `f`.
fn with<R>(hwnd: HWND, f: impl FnOnce(&mut State) -> R) -> Option<R> {
    // SAFETY: GWLP_USERDATA holds the pointer installed at WM_NCCREATE; it is cleared at WM_NCDESTROY.
    let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut State;
    // SAFETY: the UI thread is the only user and no other reference to the state is alive (module note).
    unsafe { raw.as_mut() }.map(f)
}

fn list_of(hwnd: HWND) -> HWND {
    with(hwnd, |st| st.list).unwrap_or_default()
}

fn main_hwnd() -> Option<HWND> {
    let raw = MAIN.load(Ordering::Relaxed);
    (raw != 0).then_some(HWND(raw as *mut c_void))
}

fn parent_of(child: HWND) -> HWND {
    // SAFETY: plain query; a stale handle yields an error, which becomes the default (null) handle.
    unsafe { GetParent(child) }.unwrap_or_default()
}

fn dpi_of(hwnd: HWND) -> u32 {
    // SAFETY: plain query; 0 for an invalid handle.
    match unsafe { GetDpiForWindow(hwnd) } {
        0 => 96,
        dpi => dpi,
    }
}

fn client_rect(hwnd: HWND) -> RECT {
    let mut rc = RECT::default();
    // SAFETY: `rc` is a valid out-parameter.
    let _ = unsafe { GetClientRect(hwnd, &mut rc) };
    rc
}

fn window_rect(hwnd: HWND) -> RECT {
    let mut rc = RECT::default();
    // SAFETY: `rc` is a valid out-parameter.
    let _ = unsafe { GetWindowRect(hwnd, &mut rc) };
    rc
}

fn cursor_position() -> POINT {
    let mut pt = POINT::default();
    // SAFETY: `pt` is a valid out-parameter.
    let _ = unsafe { GetCursorPos(&mut pt) };
    pt
}

fn ctrl_down() -> bool {
    // SAFETY: plain keyboard state query.
    unsafe { GetKeyState(i32::from(VK_CONTROL.0)) < 0 }
}

fn shift_down() -> bool {
    // SAFETY: plain keyboard state query.
    unsafe { GetKeyState(i32::from(VK_SHIFT.0)) < 0 }
}

fn move_window(hwnd: HWND, x: i32, y: i32, width: i32, height: i32) {
    // SAFETY: geometry change on a child control owned by this window.
    unsafe {
        let _ = MoveWindow(hwnd, x, y, width.max(0), height.max(0), true);
    }
}

fn window_text(hwnd: HWND) -> String {
    // SAFETY: plain queries on a control we own; buffers are sized from the reported lengths.
    let len = unsafe { GetWindowTextLengthW(hwnd) }.max(0) as usize;
    let mut buf = vec![0u16; len + 1];
    let copied = unsafe { GetWindowTextW(hwnd, &mut buf) }.max(0) as usize;
    String::from_utf16_lossy(&buf[..copied.min(buf.len())])
}

fn today() -> i64 {
    list::timestamp_days(&audit::timestamp()).unwrap_or(0)
}

fn status_rect(client: RECT, dpi: u32) -> RECT {
    RECT { left: 0, top: client.bottom - scale(STATUS_H, dpi), right: client.right, bottom: client.bottom }
}

fn invalidate_status(hwnd: HWND) {
    let strip = status_rect(client_rect(hwnd), dpi_of(hwnd));
    // SAFETY: `strip` is valid for the call.
    unsafe {
        let _ = InvalidateRect(Some(hwnd), Some(&strip as *const RECT), false);
    }
}

// ---------------------------------------------------------------------------
// Start-up and message loop
// ---------------------------------------------------------------------------

/// Creates the main window and runs the message loop. Returns the process exit code.
pub fn run() -> i32 {
    // SAFETY: first COM call on the UI thread; the apartment is single-threaded as the shell dialogs require.
    let com = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    init_common_controls();
    if !register_class() {
        return 1;
    }
    let Some(hwnd) = create_window() else { return 1 };
    MAIN.store(hwnd.0 as isize, Ordering::Relaxed);
    // SAFETY: `hwnd` is our live main window.
    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetForegroundWindow(hwnd);
    }
    let code = message_loop();
    if com.is_ok() {
        // SAFETY: balances the successful CoInitializeEx above.
        unsafe { CoUninitialize() };
    }
    code
}

/// Brings an already-running instance's window to the foreground (single-instance support).
pub fn activate_existing() {
    let class = to_wide(WINDOW_CLASS);
    // SAFETY: NUL-terminated class name; only a handle is returned.
    let Ok(hwnd) = (unsafe { FindWindowW(PCWSTR(class.as_ptr()), PCWSTR::null()) }) else { return };
    // SAFETY: `hwnd` was just returned by FindWindowW.
    unsafe {
        if IsIconic(hwnd).as_bool() {
            let _ = ShowWindow(hwnd, SW_RESTORE);
        }
        let _ = SetForegroundWindow(hwnd);
    }
}

fn message_loop() -> i32 {
    let mut msg = MSG::default();
    loop {
        // SAFETY: `msg` is a valid out-parameter; blocks on this thread's queue.
        let got = unsafe { GetMessageW(&mut msg, None, 0, 0) }.0;
        match got {
            0 => return msg.wParam.0 as i32,
            -1 => return 1,
            _ => {}
        }
        if pre_translate(&msg) {
            continue;
        }
        // SAFETY: `msg` was filled in by GetMessageW.
        unsafe {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

/// Global shortcuts that work whichever control has the focus: F5 refresh, Ctrl+F search.
fn pre_translate(msg: &MSG) -> bool {
    if msg.message != WM_KEYDOWN && msg.message != WM_SYSKEYDOWN {
        return false;
    }
    let Some(main) = main_hwnd() else { return false };
    // SAFETY: plain query on handles from the message queue.
    let ours = msg.hwnd == main || unsafe { IsChild(main, msg.hwnd) }.as_bool();
    if !ours {
        return false;
    }
    match VIRTUAL_KEY(msg.wParam.0 as u16) {
        VK_F5 => {
            start_scan(main);
            true
        }
        VK_F if ctrl_down() => {
            focus_search(main);
            true
        }
        _ => false,
    }
}

fn init_common_controls() {
    let icc = INITCOMMONCONTROLSEX {
        dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
        dwICC: ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES | ICC_BAR_CLASSES,
    };
    // SAFETY: `icc` is a correctly sized, initialised structure.
    unsafe {
        let _ = InitCommonControlsEx(&icc);
    }
}

fn instance() -> HINSTANCE {
    // SAFETY: a null name returns the handle of the executable.
    unsafe { GetModuleHandleW(PCWSTR::null()) }.map(|m| HINSTANCE(m.0)).unwrap_or_default()
}

/// Loads the executable's icon resource (id 1, embedded by build.rs) at the requested size.
fn load_icon(width: i32, height: i32) -> HICON {
    // SAFETY: MAKEINTRESOURCE(1) names the embedded application icon; the loader copies it.
    let resource = PCWSTR(std::ptr::without_provenance::<u16>(1));
    unsafe { LoadImageW(Some(instance()), resource, IMAGE_ICON, width, height, LR_DEFAULTCOLOR) }
        .map(|h| HICON(h.0))
        .unwrap_or_default()
}

fn register_class() -> bool {
    let class = to_wide(WINDOW_CLASS);
    // SAFETY: plain system metric queries.
    let (icon_w, icon_h, small_w, small_h) = unsafe {
        (
            GetSystemMetrics(SM_CXICON),
            GetSystemMetrics(SM_CYICON),
            GetSystemMetrics(SM_CXSMICON),
            GetSystemMetrics(SM_CYSMICON),
        )
    };
    let definition = WNDCLASSEXW {
        cbSize: size_of::<WNDCLASSEXW>() as u32,
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(wnd_proc),
        hInstance: instance(),
        hIcon: load_icon(icon_w, icon_h),
        hIconSm: load_icon(small_w, small_h),
        // SAFETY: stock cursor; loaded from the system module.
        hCursor: unsafe { LoadCursorW(None, IDC_ARROW) }.unwrap_or(HCURSOR::default()),
        lpszClassName: PCWSTR(class.as_ptr()),
        ..Default::default()
    };
    // SAFETY: `definition` and the class name outlive the call.
    unsafe { RegisterClassExW(&definition) != 0 }
}

fn title_text() -> String {
    if security::is_elevated() { format!("{APP_NAME} (Administrator)") } else { APP_NAME.to_owned() }
}

fn work_area() -> RECT {
    let mut rc = RECT::default();
    // SAFETY: `rc` is a RECT-sized out-buffer for SPI_GETWORKAREA.
    let got = unsafe {
        SystemParametersInfoW(SPI_GETWORKAREA, 0, Some(&mut rc as *mut RECT as *mut c_void), Default::default())
    };
    if got.is_ok() {
        return rc;
    }
    // SAFETY: plain metric queries.
    let (w, h) = unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };
    RECT { left: 0, top: 0, right: w, bottom: h }
}

fn create_window() -> Option<HWND> {
    // SAFETY: plain system query.
    let dpi = unsafe { GetDpiForSystem() };
    let style = WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN;
    let mut rc = RECT { left: 0, top: 0, right: scale(START_W, dpi), bottom: scale(START_H, dpi) };
    // SAFETY: `rc` is a valid in-out rectangle.
    unsafe { AdjustWindowRectExForDpi(&mut rc, style, false, WINDOW_EX_STYLE(0), dpi) }.ok()?;
    let (w, h) = (rc.right - rc.left, rc.bottom - rc.top);
    let work = work_area();
    let x = work.left + (work.right - work.left - w) / 2;
    let y = work.top + (work.bottom - work.top - h) / 2;
    let class = to_wide(WINDOW_CLASS);
    let title = to_wide(&title_text());
    // SAFETY: NUL-terminated strings outlive the call; the state is installed in WM_NCCREATE.
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            PCWSTR(class.as_ptr()),
            PCWSTR(title.as_ptr()),
            style,
            x,
            y,
            w,
            h,
            None,
            None,
            Some(instance()),
            None,
        )
    }
    .ok()
}

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------

/// Window procedure. Returns `None` to let `DefWindowProc` handle the message.
///
/// # Safety
/// Called only by the system, on the thread that created the window, with its valid handle.
unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let handled = match msg {
        WM_NCCREATE => {
            install_state(hwnd);
            None
        }
        WM_CREATE => {
            if !on_create(hwnd) {
                return LRESULT(-1);
            }
            None
        }
        WM_NCDESTROY => {
            release_state(hwnd);
            None
        }
        WM_DESTROY => {
            MAIN.store(0, Ordering::Relaxed);
            // SAFETY: posts WM_QUIT to end the message loop in `run`.
            unsafe { PostQuitMessage(0) };
            None
        }
        WM_SIZE => {
            layout(hwnd);
            None
        }
        WM_GETMINMAXINFO => {
            min_track_size(hwnd, lparam);
            Some(LRESULT(0))
        }
        WM_DPICHANGED => {
            on_dpi_changed(hwnd, wparam, lparam);
            Some(LRESULT(0))
        }
        WM_SETTINGCHANGE => {
            if is_colour_change(lparam) {
                on_theme_changed(hwnd);
            }
            None
        }
        WM_ERASEBKGND => erase_background(hwnd, wparam),
        WM_CTLCOLOREDIT | WM_CTLCOLORLISTBOX => control_colours(hwnd, wparam),
        WM_PAINT => {
            paint_status(hwnd);
            Some(LRESULT(0))
        }
        WM_DRAWITEM => draw_owner_item(lparam),
        WM_COMMAND => {
            on_command(hwnd, wparam);
            Some(LRESULT(0))
        }
        WM_NOTIFY => on_notify(hwnd, lparam),
        WM_TIMER => {
            if wparam.0 == TIMER_SEARCH {
                on_search_timer(hwnd);
            }
            Some(LRESULT(0))
        }
        WM_APP_REFRESH => {
            start_scan(hwnd);
            Some(LRESULT(0))
        }
        WM_APP_SCAN_DONE => {
            on_scan_done(hwnd, wparam, lparam);
            Some(LRESULT(0))
        }
        WM_APP_SIZE_DONE => {
            on_size_done(hwnd, wparam, lparam);
            Some(LRESULT(0))
        }
        _ => None,
    };
    handled.unwrap_or_else(|| {
        // SAFETY: forwards the untouched message to the default handler.
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    })
}

fn install_state(hwnd: HWND) {
    let raw = Box::into_raw(Box::new(State::new()));
    // SAFETY: the pointer is owned by the window until WM_NCDESTROY reclaims it.
    unsafe {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, raw as isize);
    }
}

fn release_state(hwnd: HWND) {
    // SAFETY: clears the slot so that no later message can reach the state.
    let raw = unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) } as *mut State;
    if !raw.is_null() {
        // SAFETY: `raw` came from Box::into_raw in install_state and is reclaimed exactly once.
        drop(unsafe { Box::from_raw(raw) });
    }
}

fn min_track_size(hwnd: HWND, lparam: LPARAM) {
    let dpi = dpi_of(hwnd);
    // SAFETY: WM_GETMINMAXINFO passes a valid MINMAXINFO for the duration of the message.
    if let Some(info) = unsafe { (lparam.0 as *mut MINMAXINFO).as_mut() } {
        info.ptMinTrackSize = POINT { x: scale(MIN_W, dpi), y: scale(MIN_H, dpi) };
    }
}

/// Creates the child controls. Returns false when one of them could not be created.
fn on_create(hwnd: HWND) -> bool {
    theme::apply_window(hwnd);
    let dpi = dpi_of(hwnd);
    let font = theme::ui_font(dpi);

    let search = child(hwnd, "EDIT", "", EDIT_STYLE, IDC_SEARCH);
    let filter = child(hwnd, "COMBOBOX", "", COMBO_STYLE, IDC_FILTER);
    let uninstall = child(hwnd, "BUTTON", "Uninstall", BUTTON_STYLE, IDC_UNINSTALL);
    let refresh = child(hwnd, "BUTTON", "Refresh", BUTTON_STYLE, IDC_REFRESH);
    let more = child(hwnd, "BUTTON", "More", BUTTON_STYLE, IDC_MORE);
    // Created last so that it sits on top of the (taller) filter drop-down area.
    let list = child(hwnd, "SysListView32", "", LIST_STYLE, IDC_LIST);
    if [search, filter, uninstall, refresh, more, list].iter().any(|h| h.0.is_null()) {
        return false;
    }

    for label in Filter::ALL.iter().map(|f| f.label()) {
        let text = to_wide(label);
        // SAFETY: `text` is NUL-terminated and outlives the call.
        unsafe {
            SendMessageW(filter, CB_ADDSTRING, None, Some(LPARAM(text.as_ptr() as isize)));
        }
    }
    let cue = to_wide("Search programs...");
    // SAFETY: plain messages to controls we just created; the cue text is copied by the control.
    unsafe {
        SendMessageW(filter, CB_SETCURSEL, Some(WPARAM(0)), None);
        SendMessageW(search, EM_SETCUEBANNER, Some(WPARAM(1)), Some(LPARAM(cue.as_ptr() as isize)));
    }
    for control in [search, filter, uninstall, refresh, more, list] {
        // SAFETY: WM_SETFONT takes the font handle in wParam and a redraw flag in lParam.
        unsafe {
            SendMessageW(control, WM_SETFONT, Some(WPARAM(font.0 as usize)), Some(LPARAM(1)));
        }
    }
    for control in [search, filter, list] {
        theme::apply_control(control);
    }
    // SAFETY: subclasses are removed in WM_NCDESTROY of their controls.
    unsafe {
        let _ = SetWindowSubclass(list, Some(list_proc), LIST_SUBCLASS, 0);
        let _ = SetWindowSubclass(search, Some(search_proc), SEARCH_SUBCLASS, 0);
    }
    let icons = list::configure(list, dpi);
    list::update_sort_arrows(list, Sort::default());

    with(hwnd, |st| {
        st.dpi = dpi;
        st.search = search;
        st.filter = filter;
        st.uninstall = uninstall;
        st.refresh = refresh;
        st.more = more;
        st.list = list;
        st.icons = icons;
        st.brushes = Brushes::new();
    });
    layout(hwnd);
    start_scan(hwnd);
    true
}

fn child(parent: HWND, class: &str, text: &str, style: u32, id: i32) -> HWND {
    let class = to_wide(class);
    let text = to_wide(text);
    // SAFETY: NUL-terminated strings outlive the call; the control id travels in the menu-handle slot.
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            PCWSTR(class.as_ptr()),
            PCWSTR(text.as_ptr()),
            WINDOW_STYLE(style),
            0,
            0,
            0,
            0,
            Some(parent),
            Some(HMENU(id as usize as *mut c_void)),
            None,
            None,
        )
    }
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Layout, painting, theme and DPI
// ---------------------------------------------------------------------------

/// Places the toolbar row, the list and the status strip from the client size and DPI.
fn layout(hwnd: HWND) {
    let Some((dpi, controls)) = with(hwnd, |st| (st.dpi, st.controls())) else { return };
    let [search, filter, uninstall, refresh, more, list] = controls;
    let client = client_rect(hwnd);
    let (w, h) = (client.right - client.left, client.bottom - client.top);
    let (toolbar, pad, gap, control_h) =
        (scale(TOOLBAR_H, dpi), scale(PAD, dpi), scale(GAP, dpi), scale(CONTROL_H, dpi));
    let top = (toolbar - control_h) / 2;

    let mut right = w - pad;
    for (control, width_px) in [(more, 84), (refresh, 96), (uninstall, 120), (filter, 190)] {
        let width = scale(width_px, dpi);
        let x = right - width;
        let height = if control == filter { scale(FILTER_DROP_H, dpi) } else { control_h };
        move_window(control, x, top, width, height);
        right = x - gap;
    }
    move_window(search, pad, top, right - pad, control_h);
    move_window(list, pad, toolbar, w - 2 * pad, h - toolbar - scale(STATUS_H, dpi));
}

fn paint_status(hwnd: HWND) {
    let mut ps = PAINTSTRUCT::default();
    // SAFETY: called from WM_PAINT; BeginPaint is paired with EndPaint below.
    let hdc = unsafe { BeginPaint(hwnd, &mut ps) };
    let dpi = dpi_of(hwnd);
    let strip = status_rect(client_rect(hwnd), dpi);
    let p = theme::palette();
    let (left, right, brush) = with(hwnd, |st| {
        let (left, right) = st.status_texts();
        (left, right, st.brushes.bg)
    })
    .unwrap_or_default();
    let pad = scale(PAD, dpi);
    let mut text_rect = RECT { left: strip.left + pad, top: strip.top, right: strip.right - pad, bottom: strip.bottom };
    // SAFETY: valid DC for the paint cycle; the font and objects are restored before EndPaint.
    unsafe {
        FillRect(hdc, &strip, brush);
        let old = SelectObject(hdc, HGDIOBJ(theme::ui_font(dpi).0));
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, p.text_dim);
        draw_text(hdc, &mut text_rect, &left, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_NOPREFIX);
        if !right.is_empty() {
            draw_text(hdc, &mut text_rect, &right, DT_SINGLELINE | DT_VCENTER | DT_RIGHT | DT_NOPREFIX);
        }
        SelectObject(hdc, old);
        let _ = EndPaint(hwnd, &ps);
    }
}

fn draw_text(hdc: HDC, rect: &mut RECT, text: &str, format: DRAW_TEXT_FORMAT) {
    let mut wide: Vec<u16> = text.encode_utf16().collect();
    // SAFETY: valid DC and rectangle for the call; the buffer is live for the call.
    unsafe {
        DrawTextW(hdc, &mut wide, rect as *mut RECT, format);
    }
}

fn erase_background(hwnd: HWND, wparam: WPARAM) -> Option<LRESULT> {
    let brush = with(hwnd, |st| st.brushes.bg)?;
    let rc = client_rect(hwnd);
    // SAFETY: wParam is the DC the system asks us to erase with.
    unsafe {
        FillRect(HDC(wparam.0 as *mut c_void), &rc, brush);
    }
    Some(LRESULT(1))
}

/// Edit and combo colours from the palette (`WM_CTLCOLOR*` is sent to the parent window).
fn control_colours(hwnd: HWND, wparam: WPARAM) -> Option<LRESULT> {
    let brush = with(hwnd, |st| st.brushes.alt)?;
    let p = theme::palette();
    let hdc = HDC(wparam.0 as *mut c_void);
    // SAFETY: wParam is the DC supplied by the system for this control colour request.
    unsafe {
        SetTextColor(hdc, p.text);
        SetBkColor(hdc, p.bg_alt);
    }
    Some(LRESULT(brush.0 as isize))
}

fn draw_owner_item(lparam: LPARAM) -> Option<LRESULT> {
    // SAFETY: WM_DRAWITEM passes a valid DRAWITEMSTRUCT for the duration of the message.
    let dis = unsafe { (lparam.0 as *const DRAWITEMSTRUCT).as_ref() }?;
    match dis.CtlID as i32 {
        IDC_UNINSTALL => theme::draw_button(dis, "Uninstall", true),
        IDC_REFRESH => theme::draw_button(dis, "Refresh", false),
        IDC_MORE => theme::draw_button(dis, "More", false),
        _ => return None,
    }
    Some(LRESULT(1))
}

fn is_colour_change(lparam: LPARAM) -> bool {
    if lparam.0 == 0 {
        return false;
    }
    // SAFETY: WM_SETTINGCHANGE passes a NUL-terminated string (checked non-null above).
    unsafe { PCWSTR(lparam.0 as *const u16).to_string() }.is_ok_and(|s| s == "ImmersiveColorSet")
}

fn on_theme_changed(hwnd: HWND) {
    theme::apply_window(hwnd);
    let Some(controls) = with(hwnd, |st| {
        st.brushes = Brushes::new();
        st.controls()
    }) else {
        return;
    };
    for control in controls {
        if !control.0.is_null() {
            theme::apply_control(control);
            // SAFETY: repaint request for a control we own.
            unsafe {
                let _ = InvalidateRect(Some(control), None, true);
            }
        }
    }
    // SAFETY: repaint request for our own window (the status strip).
    unsafe {
        let _ = InvalidateRect(Some(hwnd), None, true);
    }
}

fn on_dpi_changed(hwnd: HWND, wparam: WPARAM, lparam: LPARAM) {
    let new_dpi = (wparam.0 & 0xffff) as u32;
    // SAFETY: WM_DPICHANGED passes the suggested window rectangle for the duration of the message.
    let suggested = unsafe { *(lparam.0 as *const RECT) };
    let Some((old_dpi, controls)) = with(hwnd, |st| {
        let old = st.dpi;
        st.dpi = new_dpi;
        (old, st.controls())
    }) else {
        return;
    };
    // SAFETY: moves our own window to the rectangle Windows suggested for the new DPI.
    unsafe {
        let _ = SetWindowPos(
            hwnd,
            None,
            suggested.left,
            suggested.top,
            suggested.right - suggested.left,
            suggested.bottom - suggested.top,
            SWP_NOZORDER | SWP_NOACTIVATE,
        );
    }
    let font = theme::ui_font(new_dpi);
    for control in controls {
        // SAFETY: WM_SETFONT on controls we own.
        unsafe {
            SendMessageW(control, WM_SETFONT, Some(WPARAM(font.0 as usize)), Some(LPARAM(1)));
        }
    }
    list::rescale_columns(controls[5], old_dpi, new_dpi);
    layout(hwnd);
    // SAFETY: repaint request for our own window.
    unsafe {
        let _ = InvalidateRect(Some(hwnd), None, true);
    }
}

// ---------------------------------------------------------------------------
// Scanning and the program view
// ---------------------------------------------------------------------------

/// Starts a new scan. Older results are ignored, older size jobs are cancelled.
fn start_scan(hwnd: HWND) {
    let Some(generation) = with(hwnd, |st| {
        st.generation = st.generation.wrapping_add(1);
        st.cancel.store(true, Ordering::Relaxed);
        st.cancel = Arc::new(AtomicBool::new(false));
        st.scanning = true;
        st.generation
    }) else {
        return;
    };
    if !worker::spawn_scan(hwnd, generation) {
        with(hwnd, |st| st.scanning = false);
    }
    invalidate_status(hwnd);
}

fn on_scan_done(hwnd: HWND, wparam: WPARAM, lparam: LPARAM) {
    let generation = wparam.0 as u32;
    let is_current = with(hwnd, |st| st.generation == generation).unwrap_or(false);
    let Some(result) = worker::take::<ScanResult>(lparam) else { return };
    if !is_current {
        return;
    }
    let ScanResult { apps, haystacks } = *result;
    let kept = selected_ids(hwnd, list_of(hwnd));
    with(hwnd, |st| {
        st.scanning = false;
        st.model.replace(apps, haystacks);
        st.model.rebuild(today());
        let jobs = worker::size_jobs(st.model.apps(), generation, &st.cancel);
        if st.sizes.is_none() {
            st.sizes = SizeWorker::start(hwnd);
        }
        if let Some(sizes) = st.sizes.as_ref() {
            sizes.queue(jobs);
        }
    });
    present(hwnd, &kept);
}

fn on_size_done(hwnd: HWND, wparam: WPARAM, lparam: LPARAM) {
    let generation = wparam.0 as u32;
    let Some(result) = worker::take::<SizeResult>(lparam) else { return };
    let row =
        with(hwnd, |st| if st.generation == generation { st.model.set_size(&result.id, result.bytes) } else { None })
            .flatten();
    if let Some(pos) = row {
        list::redraw_item(list_of(hwnd), pos);
        invalidate_status(hwnd);
    }
}

/// Rebuilds the view (filter, search, sort) keeping the selection by app id.
fn refresh_view(hwnd: HWND, keep_selection: bool) {
    let kept = if keep_selection { selected_ids(hwnd, list_of(hwnd)) } else { HashSet::new() };
    with(hwnd, |st| st.model.rebuild(today()));
    present(hwnd, &kept);
}

/// Pushes the model's current view into the ListView and restores the selection.
fn present(hwnd: HWND, kept: &HashSet<String>) {
    let list = list_of(hwnd);
    let Some((count, positions, sort)) =
        with(hwnd, |st| (st.model.count(), st.model.positions_of(kept), st.model.sort))
    else {
        return;
    };
    list::set_count(list, count);
    list::set_all_selected(list, false);
    for pos in positions {
        list::set_selected(list, pos, true);
    }
    list::update_sort_arrows(list, sort);
    update_chrome(hwnd);
}

fn selected_ids(hwnd: HWND, list: HWND) -> HashSet<String> {
    let positions = list::selected_positions(list);
    with(hwnd, |st| positions.iter().filter_map(|&pos| st.model.id_at(pos)).map(str::to_owned).collect())
        .unwrap_or_default()
}

fn selected_apps(hwnd: HWND) -> Vec<InstalledApp> {
    let positions = list::selected_positions(list_of(hwnd));
    with(hwnd, |st| st.model.selected_apps(&positions)).unwrap_or_default()
}

/// Keeps the selection count, the Uninstall button and the status strip in step with the list.
fn update_chrome(hwnd: HWND) {
    let selected = list::selected_count(list_of(hwnd));
    let Some(uninstall) = with(hwnd, |st| {
        st.selected = selected;
        st.uninstall
    }) else {
        return;
    };
    // SAFETY: enables or disables our own button.
    unsafe {
        let _ = EnableWindow(uninstall, selected > 0);
    }
    invalidate_status(hwnd);
}

// ---------------------------------------------------------------------------
// Search and filter
// ---------------------------------------------------------------------------

fn schedule_search(hwnd: HWND) {
    // SAFETY: (re)starts the debounce timer of our own window.
    unsafe {
        SetTimer(Some(hwnd), TIMER_SEARCH, SEARCH_DEBOUNCE_MS, None);
    }
}

fn on_search_timer(hwnd: HWND) {
    // SAFETY: stops the one-shot debounce timer.
    unsafe {
        let _ = KillTimer(Some(hwnd), TIMER_SEARCH);
    }
    let search = with(hwnd, |st| st.search).unwrap_or_default();
    let query = window_text(search);
    with(hwnd, |st| st.model.set_query(&query));
    refresh_view(hwnd, true);
}

fn on_filter_changed(hwnd: HWND) {
    let Some(combo) = with(hwnd, |st| st.filter) else { return };
    // SAFETY: plain query to our combo box.
    let index = unsafe { SendMessageW(combo, CB_GETCURSEL, None, None) }.0;
    let filter = Filter::from_index(usize::try_from(index).unwrap_or(0));
    with(hwnd, |st| st.model.filter = filter);
    refresh_view(hwnd, true);
}

fn focus_search(hwnd: HWND) {
    let search = with(hwnd, |st| st.search).unwrap_or_default();
    // SAFETY: focus change and select-all on our own edit control.
    unsafe {
        let _ = SetFocus(Some(search));
        SendMessageW(search, EM_SETSEL, Some(WPARAM(0)), Some(LPARAM(-1)));
    }
}

// ---------------------------------------------------------------------------
// Subclassed controls: keyboard shortcuts
// ---------------------------------------------------------------------------

/// Subclass of the ListView: Delete/Enter uninstall, Ctrl+A/Ctrl+C, context-menu keys.
///
/// # Safety
/// Called only by the system (comctl32 subclass chain) on the UI thread.
unsafe extern "system" fn list_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _id: usize,
    _data: usize,
) -> LRESULT {
    match msg {
        WM_KEYDOWN if list_key(hwnd, VIRTUAL_KEY(wparam.0 as u16)) => return LRESULT(0),
        WM_NCDESTROY => {
            // SAFETY: removes our own subclass during the control's final message.
            unsafe {
                let _ = RemoveWindowSubclass(hwnd, Some(list_proc), LIST_SUBCLASS);
            }
        }
        _ => {}
    }
    // SAFETY: passes the untouched message down the subclass chain.
    unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) }
}

fn list_key(list: HWND, key: VIRTUAL_KEY) -> bool {
    let main = parent_of(list);
    match key {
        VK_DELETE | VK_RETURN => uninstall_selected(main, false),
        VK_A if ctrl_down() => {
            list::set_all_selected(list, true);
            update_chrome(main);
        }
        VK_C if ctrl_down() => copy_names(main),
        VK_APPS => show_context_menu(main, None),
        VK_F10 if shift_down() => show_context_menu(main, None),
        _ => return false,
    }
    true
}

/// Subclass of the search box: Esc clears, Down/Enter move to the list, Ctrl+A selects the text.
///
/// # Safety
/// Called only by the system (comctl32 subclass chain) on the UI thread.
unsafe extern "system" fn search_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _id: usize,
    _data: usize,
) -> LRESULT {
    match msg {
        WM_KEYDOWN if search_key(hwnd, VIRTUAL_KEY(wparam.0 as u16)) => return LRESULT(0),
        WM_NCDESTROY => {
            // SAFETY: removes our own subclass during the control's final message.
            unsafe {
                let _ = RemoveWindowSubclass(hwnd, Some(search_proc), SEARCH_SUBCLASS);
            }
        }
        _ => {}
    }
    // SAFETY: passes the untouched message down the subclass chain.
    unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) }
}

fn search_key(edit: HWND, key: VIRTUAL_KEY) -> bool {
    match key {
        VK_ESCAPE => {
            if !window_text(edit).is_empty() {
                // SAFETY: clears our own edit; EN_CHANGE then reschedules the search.
                unsafe {
                    let _ = SetWindowTextW(edit, w!(""));
                }
            }
        }
        VK_DOWN | VK_RETURN => {
            let list = list_of(parent_of(edit));
            // SAFETY: moves the focus to our list.
            unsafe {
                let _ = SetFocus(Some(list));
            }
        }
        VK_A if ctrl_down() => {
            // SAFETY: select-all on our own edit control.
            unsafe {
                SendMessageW(edit, EM_SETSEL, Some(WPARAM(0)), Some(LPARAM(-1)));
            }
        }
        _ => return false,
    }
    true
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

fn on_command(hwnd: HWND, wparam: WPARAM) {
    let id = (wparam.0 & 0xffff) as i32;
    let code = ((wparam.0 >> 16) & 0xffff) as u32;
    match (id, code) {
        (IDC_SEARCH, EN_CHANGE) => schedule_search(hwnd),
        (IDC_FILTER, CBN_SELCHANGE) => on_filter_changed(hwnd),
        (IDC_UNINSTALL, BN_CLICKED) => {
            uninstall_selected(hwnd, false);
        }
        (IDC_REFRESH, BN_CLICKED) => start_scan(hwnd),
        (IDC_MORE, BN_CLICKED) => more_menu(hwnd),
        _ => {}
    }
}

fn on_notify(hwnd: HWND, lparam: LPARAM) -> Option<LRESULT> {
    // SAFETY: WM_NOTIFY passes a valid NMHDR; the larger structures are only read for their codes below.
    let header = unsafe { (lparam.0 as *const NMHDR).as_ref() }?;
    if header.idFrom != IDC_LIST as usize {
        return None;
    }
    match header.code {
        LVN_GETDISPINFOW => {
            // SAFETY: LVN_GETDISPINFOW is sent with an NMLVDISPINFOW for the duration of the call.
            let info = unsafe { (lparam.0 as *mut NMLVDISPINFOW).as_mut() }?;
            with(hwnd, |st| list::fill_dispinfo(&mut st.model, &st.icons, info));
        }
        LVN_COLUMNCLICK => {
            // SAFETY: LVN_COLUMNCLICK is sent with an NMLISTVIEW for the duration of the call.
            let nm = unsafe { (lparam.0 as *const NMLISTVIEW).as_ref() }?;
            on_column_click(hwnd, nm.iSubItem);
        }
        LVN_ITEMCHANGED => update_chrome(hwnd),
        NM_DBLCLK => {
            // SAFETY: NM_DBLCLK on a ListView is sent with an NMITEMACTIVATE for the duration of the call.
            let activate = unsafe { (lparam.0 as *const NMITEMACTIVATE).as_ref() }?;
            if activate.iItem >= 0 {
                uninstall_selected(hwnd, false);
            }
        }
        NM_RCLICK => {
            // SAFETY: as NM_DBLCLK above.
            let activate = unsafe { (lparam.0 as *const NMITEMACTIVATE).as_ref() }?;
            right_click(hwnd, activate.iItem);
        }
        NM_CUSTOMDRAW => return custom_draw(hwnd, lparam),
        _ => {}
    }
    None
}

fn on_column_click(hwnd: HWND, sub_item: i32) {
    let Some(column) = Column::from_index(sub_item) else { return };
    with(hwnd, |st| st.model.toggle_sort(column));
    refresh_view(hwnd, true);
}

fn right_click(hwnd: HWND, item: i32) {
    let list = list_of(hwnd);
    match usize::try_from(item) {
        Ok(pos) => {
            if !list::is_selected(list, pos) {
                list::select_only(list, pos);
            }
            show_context_menu(hwnd, None);
        }
        Err(_) => {
            list::set_all_selected(list, false);
            update_chrome(hwnd);
        }
    }
}

/// Publisher cells of Store apps without a publisher are drawn faint.
fn custom_draw(hwnd: HWND, lparam: LPARAM) -> Option<LRESULT> {
    // SAFETY: NM_CUSTOMDRAW on a ListView is sent with an NMLVCUSTOMDRAW for the duration of the call.
    let cd = unsafe { (lparam.0 as *mut NMLVCUSTOMDRAW).as_mut() }?;
    let stage = cd.nmcd.dwDrawStage.0;
    if stage == CDDS_PREPAINT.0 {
        return Some(LRESULT(CDRF_NOTIFYITEMDRAW as isize));
    }
    if stage == CDDS_ITEMPREPAINT.0 {
        return Some(LRESULT(CDRF_NOTIFYSUBITEMDRAW as isize));
    }
    if stage == (CDDS_ITEMPREPAINT.0 | CDDS_SUBITEM.0) && cd.iSubItem == 1 {
        let pos = cd.nmcd.dwItemSpec;
        let faint = with(hwnd, |st| st.model.app_at(pos).is_some_and(|app| app.is_store() && app.publisher.is_empty()))
            .unwrap_or(false);
        if faint {
            cd.clrText = theme::palette().text_dim;
            return Some(LRESULT(CDRF_NEWFONT as isize));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Uninstall and other program actions
// ---------------------------------------------------------------------------

/// Runs the uninstall flow for the selection. Quiet mode is only used when every app supports it.
fn uninstall_selected(hwnd: HWND, quiet: bool) {
    let apps = selected_apps(hwnd);
    if apps.is_empty() || (quiet && !apps.iter().all(uninstall::supports_quiet)) {
        return;
    }
    // No borrow of the state is alive here: the flow runs nested modal loops.
    flow::start(hwnd, apps, Action::Uninstall { quiet });
}

fn force_remove(hwnd: HWND) {
    let broken: Vec<InstalledApp> = selected_apps(hwnd).into_iter().filter(needs_force).collect();
    if !broken.is_empty() {
        flow::start(hwnd, broken, Action::ForceRemove);
    }
}

fn needs_force(app: &InstalledApp) -> bool {
    app.kind == AppKind::Win32 && app.health != Health::Ok
}

fn folder_of(app: &InstalledApp) -> Option<PathBuf> {
    app.install_location.as_deref().and_then(worker::local_dir)
}

fn website_of(app: &InstalledApp) -> Option<String> {
    app.help_link.as_deref().and_then(security::sanitize_http_url)
}

fn copy_names(hwnd: HWND) {
    let apps = selected_apps(hwnd);
    if apps.is_empty() {
        return;
    }
    let names = apps.iter().map(|app| app.name.as_str()).collect::<Vec<_>>().join("\r\n");
    set_clipboard_text(hwnd, &names);
}

fn copy_details(hwnd: HWND) {
    let apps = selected_apps(hwnd);
    if !apps.is_empty() {
        set_clipboard_text(hwnd, &list::details_text(&apps));
    }
}

fn open_install_folder(hwnd: HWND) {
    if let Some(dir) = selected_apps(hwnd).first().and_then(folder_of) {
        shell_open(hwnd, &dir.to_string_lossy());
    }
}

fn open_website(hwnd: HWND) {
    if let Some(url) = selected_apps(hwnd).first().and_then(website_of) {
        shell_open(hwnd, &url);
    }
}

fn search_online(hwnd: HWND) {
    let apps = selected_apps(hwnd);
    let Some(app) = apps.first() else { return };
    let url = list::search_url(&app.name, &app.publisher);
    if let Some(safe) = security::sanitize_http_url(&url) {
        shell_open(hwnd, &safe);
    }
}

fn export_list(hwnd: HWND) {
    let apps = with(hwnd, |st| st.model.visible_apps()).unwrap_or_default();
    if let Err(message) = export::save_csv(hwnd, &apps) {
        dialogs::message_box(hwnd, APP_NAME, &message, Icon::Error);
    }
}

/// Restarts the program elevated (UAC prompt) and lets this instance close.
fn run_elevated(hwnd: HWND) {
    let Ok(exe) = std::env::current_exe() else { return };
    let exe = path_to_wide(&exe);
    let args = to_wide(RELAUNCH_ARG);
    // SAFETY: NUL-terminated strings outlive the call; "runas" shows the UAC consent prompt.
    let result = unsafe {
        ShellExecuteW(
            Some(hwnd),
            w!("runas"),
            PCWSTR(exe.as_ptr()),
            PCWSTR(args.as_ptr()),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if result.0 as isize > 32 {
        // SAFETY: the elevated copy takes over; this window is closed. Nothing touches the state afterwards.
        unsafe {
            let _ = DestroyWindow(hwnd);
        }
    }
}

fn open_data_folder(hwnd: HWND) {
    let dir = audit::data_dir();
    shell_open(hwnd, &dir.to_string_lossy());
}

/// Opens a file, folder or (already sanitised) http(s) URL with the shell. Returns true on success.
fn shell_open(owner: HWND, target: &str) -> bool {
    let wide = to_wide(target);
    // SAFETY: NUL-terminated target outlives the call; ShellExecuteW copies what it needs.
    let result = unsafe {
        ShellExecuteW(Some(owner), w!("open"), PCWSTR(wide.as_ptr()), PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL)
    };
    result.0 as isize > 32
}

/// Puts `text` on the clipboard as CF_UNICODETEXT. Returns false on any failure.
fn set_clipboard_text(owner: HWND, text: &str) -> bool {
    let wide = to_wide(text);
    let bytes = wide.len() * size_of::<u16>();
    // SAFETY: opens the clipboard for our own window; closed by the guard on every path.
    if unsafe { OpenClipboard(Some(owner)) }.is_err() {
        return false;
    }
    let _open = ClipboardGuard;
    // SAFETY: the clipboard is open on this thread.
    if unsafe { EmptyClipboard() }.is_err() {
        return false;
    }
    // SAFETY: plain allocation; freed below unless the clipboard takes ownership of it.
    let Ok(mem) = (unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes) }) else { return false };
    // SAFETY: `mem` is a valid movable block of `bytes` bytes.
    let dst = unsafe { GlobalLock(mem) } as *mut u16;
    if dst.is_null() {
        // SAFETY: the block was never handed to the clipboard.
        unsafe {
            let _ = GlobalFree(Some(mem));
        }
        return false;
    }
    // SAFETY: `dst` addresses `wide.len()` units inside the locked block.
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), dst, wide.len());
        let _ = GlobalUnlock(mem);
    }
    // SAFETY: on success the clipboard owns `mem`; on failure we still own it and free it.
    let stored = unsafe { SetClipboardData(u32::from(CF_UNICODETEXT.0), Some(HANDLE(mem.0))) };
    if stored.is_err() {
        // SAFETY: the clipboard rejected the block, so we free it.
        unsafe {
            let _ = GlobalFree(Some(mem));
        }
        return false;
    }
    true
}

struct ClipboardGuard;

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        // SAFETY: closes the clipboard opened in `set_clipboard_text`.
        unsafe {
            let _ = CloseClipboard();
        }
    }
}

// ---------------------------------------------------------------------------
// Menus
// ---------------------------------------------------------------------------

/// A popup menu that is destroyed when dropped.
struct Menu(HMENU);

impl Menu {
    fn new() -> Option<Menu> {
        // SAFETY: plain creation; destroyed by Drop.
        unsafe { CreatePopupMenu() }.ok().map(Menu)
    }

    fn item(&self, id: usize, text: &str, enabled: bool) {
        let flags = MF_STRING | if enabled { MENU_ITEM_FLAGS(0) } else { MF_GRAYED };
        let wide = to_wide(text);
        // SAFETY: the menu is ours; the text is copied by the call.
        unsafe {
            let _ = AppendMenuW(self.0, flags, id, PCWSTR(wide.as_ptr()));
        }
    }

    fn separator(&self) {
        // SAFETY: the menu is ours; a separator has no text.
        unsafe {
            let _ = AppendMenuW(self.0, MF_SEPARATOR, 0, PCWSTR::null());
        }
    }

    /// Shows the menu at a screen point and returns the chosen command id, if any.
    fn track(&self, owner: HWND, at: POINT) -> Option<usize> {
        // SAFETY: foreground activation is required so that the menu closes on outside clicks.
        unsafe {
            let _ = SetForegroundWindow(owner);
        }
        // SAFETY: TPM_RETURNCMD makes the call return the chosen id instead of posting WM_COMMAND.
        let picked =
            unsafe { TrackPopupMenu(self.0, TPM_RETURNCMD | TPM_RIGHTBUTTON, at.x, at.y, None, owner, None) }.0;
        usize::try_from(picked).ok().filter(|&id| id != 0)
    }
}

impl Drop for Menu {
    fn drop(&mut self) {
        // SAFETY: destroys the menu created in `Menu::new`.
        unsafe {
            let _ = DestroyMenu(self.0);
        }
    }
}

fn show_context_menu(hwnd: HWND, at: Option<POINT>) {
    let apps = selected_apps(hwnd);
    if apps.is_empty() {
        return;
    }
    let Some(menu) = Menu::new() else { return };
    let primary = apps.first();
    let quiet = apps.iter().all(uninstall::supports_quiet);
    let broken = apps.iter().any(needs_force);
    let folder = primary.and_then(folder_of).is_some();
    let website = primary.and_then(website_of).is_some();

    menu.item(IDM_UNINSTALL, "Uninstall", true);
    menu.item(IDM_QUIET, "Quiet uninstall", quiet);
    if broken {
        menu.item(IDM_FORCE, "Force remove entry...", true);
    }
    menu.separator();
    if folder {
        menu.item(IDM_OPEN_FOLDER, "Open install folder", true);
    }
    menu.item(IDM_OPEN_WEB, "Open website", website);
    menu.item(IDM_SEARCH_WEB, "Search online", true);
    menu.item(IDM_COPY_NAME, "Copy name", true);
    menu.item(IDM_COPY_DETAILS, "Copy details", true);

    let point = at.unwrap_or_else(cursor_position);
    if let Some(id) = menu.track(hwnd, point) {
        menu_action(hwnd, id);
    }
}

fn more_menu(hwnd: HWND) {
    let Some(button) = with(hwnd, |st| st.more) else { return };
    let rect = window_rect(button);
    let Some(menu) = Menu::new() else { return };
    menu.item(IDM_EXPORT, "Export list (CSV)...", true);
    if !security::is_elevated() {
        menu.item(IDM_RUNAS, "Run as administrator", true);
    }
    menu.item(IDM_DATA_FOLDER, "Open data folder", true);
    menu.separator();
    menu.item(IDM_ABOUT, "About", true);
    menu.item(IDM_EXIT, "Exit", true);
    if let Some(id) = menu.track(hwnd, POINT { x: rect.left, y: rect.bottom }) {
        menu_action(hwnd, id);
    }
}

fn menu_action(hwnd: HWND, id: usize) {
    match id {
        IDM_UNINSTALL => uninstall_selected(hwnd, false),
        IDM_QUIET => uninstall_selected(hwnd, true),
        IDM_FORCE => force_remove(hwnd),
        IDM_OPEN_FOLDER => open_install_folder(hwnd),
        IDM_OPEN_WEB => open_website(hwnd),
        IDM_SEARCH_WEB => search_online(hwnd),
        IDM_COPY_NAME => copy_names(hwnd),
        IDM_COPY_DETAILS => copy_details(hwnd),
        IDM_EXPORT => export_list(hwnd),
        IDM_RUNAS => run_elevated(hwnd),
        IDM_DATA_FOLDER => open_data_folder(hwnd),
        IDM_ABOUT => dialogs::about(hwnd),
        IDM_EXIT => {
            // SAFETY: closes our own window; the state is released in WM_NCDESTROY.
            unsafe {
                let _ = DestroyWindow(hwnd);
            }
        }
        _ => {}
    }
}
