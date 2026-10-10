//! Leftovers review window: a themed, modal checklist where the user chooses what gets removed.
//! `show` runs its own message loop (the owner is disabled meanwhile) and returns when the window closes.

use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::mem::size_of;
use std::sync::Once;

use windows::Win32::Foundation::{COLORREF, HINSTANCE, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    CreateSolidBrush, DeleteObject, FillRect, GetMonitorInfoW, HBRUSH, HDC, HGDIOBJ, InvalidateRect,
    MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromWindow, SetBkMode, SetTextColor, TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::SystemServices::{SS_ENDELLIPSIS, SS_NOPREFIX};
use windows::Win32::UI::Controls::{
    DRAWITEMSTRUCT, ICC_LISTVIEW_CLASSES, INITCOMMONCONTROLSEX, InitCommonControlsEx, LIST_VIEW_ITEM_STATE_FLAGS,
    LVCF_FMT, LVCF_SUBITEM, LVCF_TEXT, LVCF_WIDTH, LVCFMT_LEFT, LVCFMT_RIGHT, LVCOLUMNW, LVIF_STATE, LVIF_TEXT,
    LVIS_STATEIMAGEMASK, LVITEMW, LVM_INSERTCOLUMNW, LVM_INSERTITEMW, LVM_SETBKCOLOR, LVM_SETCOLUMNWIDTH,
    LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETITEMSTATE, LVM_SETITEMTEXTW, LVM_SETTEXTBKCOLOR, LVM_SETTEXTCOLOR,
    LVN_ITEMCHANGED, LVS_EX_CHECKBOXES, LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT, LVS_REPORT, LVS_SHOWSELALWAYS,
    NMHDR, NMLISTVIEW,
};
use windows::Win32::UI::HiDpi::GetDpiForWindow;
use windows::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus, VK_ESCAPE};
use windows::Win32::UI::WindowsAndMessaging::{
    BN_CLICKED, BS_OWNERDRAW, CREATESTRUCTW, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, CreateWindowExW, DefWindowProcW,
    DestroyWindow, DispatchMessageW, GWLP_USERDATA, GetClientRect, GetDlgItem, GetMessageW, GetWindowLongPtrW,
    GetWindowRect, HMENU, IDC_ARROW, IsDialogMessageW, IsWindow, LoadCursorW, MINMAXINFO, MSG, MoveWindow,
    PostMessageW, PostQuitMessage, RegisterClassExW, SET_WINDOW_POS_FLAGS, SW_SHOW, SWP_NOACTIVATE, SWP_NOZORDER,
    SendMessageW, SetForegroundWindow, SetWindowLongPtrW, SetWindowPos, SetWindowTextW, ShowWindow, TranslateMessage,
    WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLOSE, WM_COMMAND, WM_CREATE, WM_CTLCOLORSTATIC, WM_DPICHANGED, WM_DRAWITEM,
    WM_ERASEBKGND, WM_GETMINMAXINFO, WM_KEYDOWN, WM_NCCREATE, WM_NCDESTROY, WM_NOTIFY, WM_SETFONT, WM_SETREDRAW,
    WM_SIZE, WNDCLASSEXW, WS_BORDER, WS_CHILD, WS_OVERLAPPEDWINDOW, WS_TABSTOP, WS_VISIBLE,
};
use windows::core::{PCWSTR, PWSTR, w};

use crate::app_info::APP_NAME;
use crate::leftovers::{Confidence, Leftover};
use crate::model::InstalledApp;
use crate::util::{format_size, to_wide};

use super::theme;

/// The user's choice: indices into the `items` slice passed to [`show`], and the recycle-bin option.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewResult {
    pub selected: Vec<usize>,
    pub recycle: bool,
}

// Control ids.
const ID_HEADING: i32 = 100;
const ID_HINT: i32 = 101;
const ID_LIST: i32 = 102;
const ID_RECYCLE: i32 = 103;
const ID_SELECT_ALL: i32 = 104;
const ID_SELECT_NONE: i32 = 105;
const ID_KEEP: i32 = 106;
const ID_REMOVE: i32 = 107;
const CHILD_IDS: [i32; 8] = [
    ID_HEADING,
    ID_HINT,
    ID_LIST,
    ID_RECYCLE,
    ID_SELECT_ALL,
    ID_SELECT_NONE,
    ID_KEEP,
    ID_REMOVE,
];

/// Image indices of the list's checkbox state image list.
const UNCHECKED_IMAGE: u32 = 1;
const CHECKED_IMAGE: u32 = 2;

// Layout, in 96-dpi pixels.
const BASE_W: i32 = 860;
const BASE_H: i32 = 540;
const MIN_W: i32 = 640;
const MIN_H: i32 = 380;
const MARGIN: i32 = 16;
const GAP: i32 = 8;
const HEADING_H: i32 = 28;
const HINT_H: i32 = 22;
const ROW_H: i32 = 28;
const BUTTON_H: i32 = 34;
const RECYCLE_W: i32 = 360;
const SMALL_BUTTON_W: i32 = 120;
const KEEP_W: i32 = 150;
const REMOVE_W: i32 = 200;
/// Scrollbar allowance subtracted from the list width when sizing its columns.
const SCROLLBAR_W: i32 = 20;

const COLUMNS: [&str; 4] = ["Item", "Type", "Why", "Size"];
/// Share of the list width per column, in percent.
const COLUMN_SHARE: [i32; 4] = [50, 15, 25, 10];

const RECYCLE_LABEL: &str = "Move files to the Recycle Bin (recommended)";
const HINT_TEXT: &str = "Checked items will be removed. Registry changes are backed up first.";

/// Shows the leftovers of `app` and lets the user pick what to remove. High-confidence items start checked.
/// Returns `Some` only when the user presses "Remove selected"; closing the window or "Keep everything" gives `None`.
pub fn show(owner: HWND, app: &InstalledApp, items: &[Leftover]) -> Option<ReviewResult> {
    register_class();
    let dpi = dpi_of(owner);
    // SAFETY: plain call; the returned brush is owned by `State` and deleted when it drops.
    let background = unsafe { CreateSolidBrush(theme::palette().bg) };
    if background.is_invalid() {
        return None;
    }
    let state = State {
        checked: RefCell::new(items.iter().map(|item| starts_checked(item.confidence)).collect()),
        recycle: Cell::new(true),
        suppress: Cell::new(false),
        result: RefCell::new(None),
        background,
    };
    let (x, y, w, h) = initial_rect(owner, dpi);
    let title = to_wide(&format!("{APP_NAME} - Leftovers"));
    // SAFETY: class name and title are NUL-terminated and outlive the call. `state` lives on this stack frame
    // until after the message loop, and the window that stores its address is destroyed before it returns.
    let created = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("PoofReviewWindow"),
            PCWSTR(title.as_ptr()),
            WS_OVERLAPPEDWINDOW,
            x,
            y,
            w,
            h,
            Some(owner),
            None,
            None,
            Some(&state as *const State as *const c_void),
        )
    };
    let Ok(hwnd) = created else { return None };
    theme::apply_window(hwnd);
    if let Some(list) = dlg_item(hwnd, ID_LIST) {
        state.suppress.set(true);
        populate(list, items, &state.checked.borrow());
        state.suppress.set(false);
    }
    update_remove_button(&state, hwnd);
    set_text_of(hwnd, ID_HEADING, &heading_text(&app.name));
    set_text_of(hwnd, ID_HINT, HINT_TEXT);
    run_modal(owner, hwnd);
    state.result.take()
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Only high-confidence leftovers start checked.
fn starts_checked(confidence: Confidence) -> bool {
    confidence == Confidence::High
}

/// Text of the "Why" column; uncertain (medium confidence) items are flagged.
fn why_text(reason: &str, confidence: Confidence) -> String {
    match confidence {
        Confidence::High => reason.to_owned(),
        Confidence::Medium => format!("{reason} (uncertain)"),
    }
}

/// Indices of the checked rows, in list order.
fn selected_indices(checked: &[bool]) -> Vec<usize> {
    checked
        .iter()
        .enumerate()
        .filter(|(_, on)| **on)
        .map(|(i, _)| i)
        .collect()
}

fn count_checked(checked: &[bool]) -> usize {
    checked.iter().filter(|on| **on).count()
}

fn remove_label(count: usize) -> String {
    format!("Remove selected ({count})")
}

fn heading_text(app_name: &str) -> String {
    format!("{app_name} was removed. These leftovers remain")
}

fn size_text(size: Option<u64>) -> String {
    size.map(format_size).unwrap_or_default()
}

/// Top-left corner that centres a `width` x `height` window over `outer`, kept fully inside `work`.
fn centred_origin(outer: RECT, width: i32, height: i32, work: RECT) -> (i32, i32) {
    let x = outer.left + (outer.right - outer.left - width) / 2;
    let y = outer.top + (outer.bottom - outer.top - height) / 2;
    let x = x.clamp(work.left, (work.right - width).max(work.left));
    let y = y.clamp(work.top, (work.bottom - height).max(work.top));
    (x, y)
}

/// Checkbox state image index of a list item (1 = unchecked, 2 = checked, 0 = no checkbox).
fn image_index(state: u32) -> u32 {
    (state & LVIS_STATEIMAGEMASK.0) >> 12
}

// ---------------------------------------------------------------------------
// Window state
// ---------------------------------------------------------------------------

/// Per-window state, owned by `show`. The window reaches it through GWLP_USERDATA; the pointer is cleared at
/// WM_NCDESTROY, so nothing is allocated for it and nothing can be freed twice. Interior mutability keeps
/// re-entrant messages (sent while a handler runs) from creating aliasing `&mut` references.
struct State {
    checked: RefCell<Vec<bool>>,
    recycle: Cell<bool>,
    /// Set while the list is updated in bulk, so per-item notifications are ignored.
    suppress: Cell<bool>,
    result: RefCell<Option<ReviewResult>>,
    background: HBRUSH,
}

impl Drop for State {
    fn drop(&mut self) {
        // SAFETY: `background` was created by CreateSolidBrush in `show` and is owned by this state only.
        let _ = unsafe { DeleteObject(HGDIOBJ(self.background.0)) };
    }
}

/// Returns the state of a review window.
///
/// # Safety
/// `hwnd` must be a review window whose user data was set in WM_NCCREATE and that is still
/// being serviced by `show`, so the `State` it points to is alive.
unsafe fn state_of<'a>(hwnd: HWND) -> Option<&'a State> {
    // SAFETY: GWLP_USERDATA holds the address of the State owned by `show` (see the caller contract).
    let ptr = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const State;
    // SAFETY: the pointer is either null or the live State described above.
    unsafe { ptr.as_ref() }
}

// ---------------------------------------------------------------------------
// Window class and modal loop
// ---------------------------------------------------------------------------

fn register_class() {
    static REGISTER: Once = Once::new();
    REGISTER.call_once(|| {
        let icc = INITCOMMONCONTROLSEX {
            dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES,
        };
        // SAFETY: `icc` is a valid, fully initialised structure for the duration of the call.
        let _ = unsafe { InitCommonControlsEx(&icc) };
        // SAFETY: no arguments; returns the module handle of this executable.
        let instance = unsafe { GetModuleHandleW(None) }
            .map(|m| HINSTANCE(m.0))
            .unwrap_or_default();
        // SAFETY: standard cursor resource; a failure only leaves the cursor unset.
        let cursor = unsafe { LoadCursorW(None, IDC_ARROW) }.unwrap_or_default();
        let class = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(review_proc),
            hInstance: instance,
            hCursor: cursor,
            lpszClassName: w!("PoofReviewWindow"),
            ..Default::default()
        };
        // SAFETY: `class` is fully initialised; the window procedure has the `WNDPROC` signature.
        let _ = unsafe { RegisterClassExW(&class) };
    });
}

/// Pumps messages until the window is gone, then re-enables the owner. Blocks the caller, as a modal dialog does.
fn run_modal(owner: HWND, hwnd: HWND) {
    // SAFETY: `owner` and `hwnd` are the live windows created above; all calls run on this thread.
    unsafe {
        let _ = EnableWindow(owner, false);
        let _ = ShowWindow(hwnd, SW_SHOW);
    }
    if let Some(list) = dlg_item(hwnd, ID_LIST) {
        // SAFETY: focusing a control of our own window.
        let _ = unsafe { SetFocus(Some(list)) };
    }
    pump(hwnd);
    // SAFETY: as above; the window may already be gone, which IsWindow reports.
    unsafe {
        if IsWindow(Some(hwnd)).as_bool() {
            let _ = DestroyWindow(hwnd);
        }
        let _ = EnableWindow(owner, true);
        let _ = SetForegroundWindow(owner);
    }
}

fn pump(hwnd: HWND) {
    loop {
        // SAFETY: plain handle query.
        if !unsafe { IsWindow(Some(hwnd)) }.as_bool() {
            return;
        }
        let mut msg = MSG::default();
        // SAFETY: `msg` is a valid out-parameter.
        let got = unsafe { GetMessageW(&mut msg, None, 0, 0) }.0;
        if got == 0 {
            // WM_QUIT belongs to the caller's loop: pass it on.
            // SAFETY: plain call.
            unsafe { PostQuitMessage(msg.wParam.0 as i32) };
            return;
        }
        if got < 0 {
            return;
        }
        if msg.message == WM_KEYDOWN && msg.wParam.0 == VK_ESCAPE.0 as usize {
            // SAFETY: posting WM_CLOSE to our own window; a closed window just makes the call fail.
            let _ = unsafe { PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0)) };
            continue;
        }
        // SAFETY: `msg` was filled in by GetMessageW.
        if unsafe { IsDialogMessageW(hwnd, &msg) }.as_bool() {
            continue;
        }
        // SAFETY: `msg` was filled in by GetMessageW.
        unsafe {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

/// Window position: centred over the owner, clamped to the owner's work area. Size is DPI scaled.
fn initial_rect(owner: HWND, dpi: u32) -> (i32, i32, i32, i32) {
    let (w, h) = (theme::scale(BASE_W, dpi), theme::scale(BASE_H, dpi));
    let mut outer = RECT::default();
    // SAFETY: `outer` is a valid out-parameter.
    if unsafe { GetWindowRect(owner, &mut outer) }.is_err() {
        return (CW_USEDEFAULT, CW_USEDEFAULT, w, h);
    }
    let mut info = MONITORINFO {
        cbSize: size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: plain query; `info` is correctly sized and valid for the call.
    let monitor = unsafe { MonitorFromWindow(owner, MONITOR_DEFAULTTONEAREST) };
    // SAFETY: as above.
    let work = if unsafe { GetMonitorInfoW(monitor, &mut info) }.as_bool() {
        info.rcWork
    } else {
        outer
    };
    let (x, y) = centred_origin(outer, w, h, work);
    (x, y, w, h)
}

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------

/// # Safety
/// Called by the system for windows of [`register_class`]'s class only.
unsafe extern "system" fn review_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_NCCREATE => {
            // SAFETY: for WM_NCCREATE, lParam points to the CREATESTRUCTW given to CreateWindowExW.
            let create = unsafe { &*(lparam.0 as *const CREATESTRUCTW) };
            // SAFETY: stores the State address `show` passed as the creation parameter.
            unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, create.lpCreateParams as isize) };
            return default_proc(hwnd, msg, wparam, lparam);
        }
        WM_NCDESTROY => {
            // SAFETY: clears the pointer so no later message can reach the State.
            unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) };
            return default_proc(hwnd, msg, wparam, lparam);
        }
        _ => {}
    }
    // SAFETY: the window is one of ours and `show` keeps its State alive until it is destroyed.
    let Some(st) = (unsafe { state_of(hwnd) }) else {
        return default_proc(hwnd, msg, wparam, lparam);
    };
    match msg {
        WM_CREATE => {
            on_create(hwnd);
            LRESULT(0)
        }
        WM_SIZE => {
            layout(hwnd);
            LRESULT(0)
        }
        WM_GETMINMAXINFO => {
            let dpi = dpi_of(hwnd);
            // SAFETY: lParam points to a MINMAXINFO that is valid for the duration of this message.
            if let Some(info) = unsafe { (lparam.0 as *mut MINMAXINFO).as_mut() } {
                info.ptMinTrackSize = POINT {
                    x: theme::scale(MIN_W, dpi),
                    y: theme::scale(MIN_H, dpi),
                };
            }
            LRESULT(0)
        }
        WM_DPICHANGED => {
            let dpi = (wparam.0 & 0xffff) as u32;
            // SAFETY: lParam points to the suggested window rectangle, valid for this message.
            if let Some(r) = unsafe { (lparam.0 as *const RECT).as_ref() } {
                // SAFETY: moving our own window to the rectangle the system suggested.
                let _ = unsafe {
                    SetWindowPos(
                        hwnd,
                        None,
                        r.left,
                        r.top,
                        r.right - r.left,
                        r.bottom - r.top,
                        SET_WINDOW_POS_FLAGS(SWP_NOZORDER.0 | SWP_NOACTIVATE.0),
                    )
                };
            }
            apply_fonts(hwnd, dpi);
            layout(hwnd);
            LRESULT(0)
        }
        WM_ERASEBKGND => {
            let mut rc = RECT::default();
            // SAFETY: `rc` is a valid out-parameter; wParam is the device context for this message.
            if unsafe { GetClientRect(hwnd, &mut rc) }.is_ok() {
                unsafe { FillRect(HDC(wparam.0 as *mut c_void), &rc, st.background) };
            }
            LRESULT(1)
        }
        WM_CTLCOLORSTATIC => {
            let p = theme::palette();
            // SAFETY: wParam is the device context the system passes for this message.
            unsafe {
                SetTextColor(HDC(wparam.0 as *mut c_void), p.text);
                SetBkMode(HDC(wparam.0 as *mut c_void), TRANSPARENT);
            }
            LRESULT(st.background.0 as isize)
        }
        WM_DRAWITEM => {
            // SAFETY: for WM_DRAWITEM, lParam points to a DRAWITEMSTRUCT valid for this message.
            if let Some(dis) = unsafe { (lparam.0 as *const DRAWITEMSTRUCT).as_ref() } {
                draw_item(st, dis);
            }
            LRESULT(1)
        }
        WM_NOTIFY => {
            // SAFETY: for WM_NOTIFY, lParam points to an NMHDR, or to a larger struct that starts with one.
            let hdr = unsafe { &*(lparam.0 as *const NMHDR) };
            if hdr.idFrom == ID_LIST as usize && hdr.code == LVN_ITEMCHANGED {
                // SAFETY: LVN_ITEMCHANGED notifications carry an NMLISTVIEW, valid for this message.
                let nm = unsafe { &*(lparam.0 as *const NMLISTVIEW) };
                on_item_changed(st, hwnd, nm);
            }
            LRESULT(0)
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xffff) as i32;
            let code = ((wparam.0 >> 16) & 0xffff) as u32;
            if code == BN_CLICKED {
                on_button(st, hwnd, id);
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            destroy(hwnd);
            LRESULT(0)
        }
        _ => default_proc(hwnd, msg, wparam, lparam),
    }
}

fn default_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // SAFETY: the standard default handling for any message.
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

/// Creates the child controls (in tab order) and fills in the static columns.
fn on_create(hwnd: HWND) {
    child(hwnd, w!("STATIC"), "", SS_NOPREFIX.0 | SS_ENDELLIPSIS.0, ID_HEADING);
    child(hwnd, w!("STATIC"), "", SS_NOPREFIX.0, ID_HINT);
    child(
        hwnd,
        w!("SysListView32"),
        "",
        WS_BORDER.0 | WS_TABSTOP.0 | LVS_REPORT | LVS_SHOWSELALWAYS,
        ID_LIST,
    );
    child(
        hwnd,
        w!("BUTTON"),
        RECYCLE_LABEL,
        BS_OWNERDRAW as u32 | WS_TABSTOP.0,
        ID_RECYCLE,
    );
    child(
        hwnd,
        w!("BUTTON"),
        "Select all",
        BS_OWNERDRAW as u32 | WS_TABSTOP.0,
        ID_SELECT_ALL,
    );
    child(
        hwnd,
        w!("BUTTON"),
        "Select none",
        BS_OWNERDRAW as u32 | WS_TABSTOP.0,
        ID_SELECT_NONE,
    );
    child(
        hwnd,
        w!("BUTTON"),
        "Keep everything",
        BS_OWNERDRAW as u32 | WS_TABSTOP.0,
        ID_KEEP,
    );
    child(
        hwnd,
        w!("BUTTON"),
        &remove_label(0),
        BS_OWNERDRAW as u32 | WS_TABSTOP.0,
        ID_REMOVE,
    );
    if let Some(list) = dlg_item(hwnd, ID_LIST) {
        setup_list(list);
    }
    apply_fonts(hwnd, dpi_of(hwnd));
}

fn child(parent: HWND, class: PCWSTR, text: &str, style: u32, id: i32) {
    let text = to_wide(text);
    // SAFETY: class and text are NUL-terminated and alive for the call; the parent is our own window.
    let _ = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            PCWSTR(text.as_ptr()),
            WINDOW_STYLE(WS_CHILD.0 | WS_VISIBLE.0 | style),
            0,
            0,
            0,
            0,
            Some(parent),
            Some(HMENU(id as usize as *mut c_void)),
            None,
            None,
        )
    };
}

/// Checkboxes, the theme, the colours and the columns of the list.
fn setup_list(list: HWND) {
    let ex_style = LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER;
    send(list, LVM_SETEXTENDEDLISTVIEWSTYLE, ex_style as usize, ex_style as isize);
    for (index, title) in COLUMNS.iter().enumerate() {
        let mut text = to_wide(title);
        let column = LVCOLUMNW {
            mask: LVCF_FMT | LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM,
            fmt: if index == COLUMNS.len() - 1 {
                LVCFMT_RIGHT
            } else {
                LVCFMT_LEFT
            },
            cx: 0,
            pszText: PWSTR(text.as_mut_ptr()),
            cchTextMax: 0,
            iSubItem: index as i32,
            iImage: 0,
            iOrder: 0,
            cxMin: 0,
            cxDefault: 0,
            cxIdeal: 0,
        };
        send(list, LVM_INSERTCOLUMNW, index, &column as *const LVCOLUMNW as isize);
    }
    theme::apply_control(list);
    let p = theme::palette();
    send(list, LVM_SETBKCOLOR, 0, colour(p.bg));
    send(list, LVM_SETTEXTBKCOLOR, 0, colour(p.bg));
    send(list, LVM_SETTEXTCOLOR, 0, colour(p.text));
}

fn colour(c: COLORREF) -> isize {
    c.0 as isize
}

/// Fills the list: one row per leftover, in the order of `items`, so row indices match the result indices.
fn populate(list: HWND, items: &[Leftover], checked: &[bool]) {
    send(list, WM_SETREDRAW, 0, 0);
    for (row, (item, on)) in items.iter().zip(checked).enumerate() {
        let row = row as i32;
        let mut path = to_wide(&item.display_path());
        let image = if *on { CHECKED_IMAGE } else { UNCHECKED_IMAGE };
        let entry = LVITEMW {
            mask: LVIF_TEXT | LVIF_STATE,
            iItem: row,
            state: LIST_VIEW_ITEM_STATE_FLAGS(image << 12),
            stateMask: LVIS_STATEIMAGEMASK,
            pszText: PWSTR(path.as_mut_ptr()),
            ..Default::default()
        };
        send(list, LVM_INSERTITEMW, 0, &entry as *const LVITEMW as isize);
        let cells = [
            item.kind_label().to_owned(),
            why_text(&item.reason, item.confidence),
            size_text(item.size_bytes),
        ];
        for (column, cell) in cells.iter().enumerate() {
            let mut text = to_wide(cell);
            let sub = LVITEMW {
                iItem: row,
                iSubItem: column as i32 + 1,
                pszText: PWSTR(text.as_mut_ptr()),
                ..Default::default()
            };
            send(list, LVM_SETITEMTEXTW, row as usize, &sub as *const LVITEMW as isize);
        }
    }
    send(list, WM_SETREDRAW, 1, 0);
    // SAFETY: invalidating our own list.
    let _ = unsafe { InvalidateRect(Some(list), None, true) };
}

/// Places every control for the current client size and DPI.
fn layout(hwnd: HWND) {
    let dpi = dpi_of(hwnd);
    let s = |px: i32| theme::scale(px, dpi);
    let mut rc = RECT::default();
    // SAFETY: `rc` is a valid out-parameter.
    if unsafe { GetClientRect(hwnd, &mut rc) }.is_err() {
        return;
    }
    let (w, h) = (rc.right - rc.left, rc.bottom - rc.top);
    let (margin, gap) = (s(MARGIN), s(GAP));
    let inner_w = (w - 2 * margin).max(0);
    let button_h = s(BUTTON_H);
    let button_row_y = h - margin - button_h;
    let recycle_y = button_row_y - gap - s(ROW_H);
    let heading_y = margin;
    let hint_y = heading_y + s(HEADING_H);
    let list_y = hint_y + s(HINT_H) + gap / 2;
    let list_h = (recycle_y - gap - list_y).max(0);

    place(hwnd, ID_HEADING, margin, heading_y, inner_w, s(HEADING_H));
    place(hwnd, ID_HINT, margin, hint_y, inner_w, s(HINT_H));
    place(hwnd, ID_LIST, margin, list_y, inner_w, list_h);
    place(hwnd, ID_RECYCLE, margin, recycle_y, s(RECYCLE_W), s(ROW_H));

    let remove_w = s(REMOVE_W);
    let keep_w = s(KEEP_W);
    let small_w = s(SMALL_BUTTON_W);
    place(hwnd, ID_REMOVE, w - margin - remove_w, button_row_y, remove_w, button_h);
    place(
        hwnd,
        ID_KEEP,
        w - margin - remove_w - gap - keep_w,
        button_row_y,
        keep_w,
        button_h,
    );
    place(hwnd, ID_SELECT_ALL, margin, button_row_y, small_w, button_h);
    place(
        hwnd,
        ID_SELECT_NONE,
        margin + small_w + gap,
        button_row_y,
        small_w,
        button_h,
    );

    if let Some(list) = dlg_item(hwnd, ID_LIST) {
        let columns_w = (inner_w - s(SCROLLBAR_W)).max(0);
        for (index, share) in COLUMN_SHARE.iter().enumerate() {
            send(list, LVM_SETCOLUMNWIDTH, index, (columns_w * share / 100) as isize);
        }
    }
}

fn place(hwnd: HWND, id: i32, x: i32, y: i32, w: i32, h: i32) {
    if let Some(item) = dlg_item(hwnd, id) {
        // SAFETY: moving a child control of our own window.
        let _ = unsafe { MoveWindow(item, x, y, w, h, true) };
    }
}

fn apply_fonts(hwnd: HWND, dpi: u32) {
    let font = theme::ui_font(dpi);
    for id in CHILD_IDS {
        if let Some(item) = dlg_item(hwnd, id) {
            send(item, WM_SETFONT, font.0 as usize, 1);
        }
    }
}

fn draw_item(st: &State, dis: &DRAWITEMSTRUCT) {
    match dis.CtlID as i32 {
        ID_SELECT_ALL => theme::draw_button(dis, "Select all", false),
        ID_SELECT_NONE => theme::draw_button(dis, "Select none", false),
        ID_KEEP => theme::draw_button(dis, "Keep everything", false),
        ID_REMOVE => {
            let label = remove_label(count_checked(&st.checked.borrow()));
            theme::draw_button(dis, &label, true);
        }
        ID_RECYCLE => theme::draw_checkbox(dis, RECYCLE_LABEL, st.recycle.get()),
        _ => {}
    }
}

/// Keeps the checkbox state and the Remove count in step with the list.
fn on_item_changed(st: &State, hwnd: HWND, nm: &NMLISTVIEW) {
    if st.suppress.get() {
        return;
    }
    let (old, new) = (image_index(nm.uOldState), image_index(nm.uNewState));
    if old == new {
        return;
    }
    let Ok(index) = usize::try_from(nm.iItem) else { return };
    {
        let mut checked = st.checked.borrow_mut();
        let Some(slot) = checked.get_mut(index) else { return };
        *slot = new == CHECKED_IMAGE;
    }
    update_remove_button(st, hwnd);
}

fn on_button(st: &State, hwnd: HWND, id: i32) {
    match id {
        ID_RECYCLE => {
            st.recycle.set(!st.recycle.get());
            if let Some(button) = dlg_item(hwnd, ID_RECYCLE) {
                // SAFETY: invalidating our own control so it is repainted in its new state.
                let _ = unsafe { InvalidateRect(Some(button), None, true) };
            }
        }
        ID_SELECT_ALL => set_all(st, hwnd, true),
        ID_SELECT_NONE => set_all(st, hwnd, false),
        ID_REMOVE => {
            let selected = selected_indices(&st.checked.borrow());
            if !selected.is_empty() {
                *st.result.borrow_mut() = Some(ReviewResult {
                    selected,
                    recycle: st.recycle.get(),
                });
                destroy(hwnd);
            }
        }
        ID_KEEP => destroy(hwnd),
        _ => {}
    }
}

/// Checks or unchecks every row with a single list update.
fn set_all(st: &State, hwnd: HWND, value: bool) {
    let Some(list) = dlg_item(hwnd, ID_LIST) else { return };
    st.checked.borrow_mut().iter_mut().for_each(|slot| *slot = value);
    st.suppress.set(true);
    let image = if value { CHECKED_IMAGE } else { UNCHECKED_IMAGE };
    let entry = LVITEMW {
        state: LIST_VIEW_ITEM_STATE_FLAGS(image << 12),
        stateMask: LVIS_STATEIMAGEMASK,
        ..Default::default()
    };
    // Index -1 applies the change to every item.
    send(list, LVM_SETITEMSTATE, usize::MAX, &entry as *const LVITEMW as isize);
    st.suppress.set(false);
    update_remove_button(st, hwnd);
}

fn update_remove_button(st: &State, hwnd: HWND) {
    let count = count_checked(&st.checked.borrow());
    if let Some(button) = dlg_item(hwnd, ID_REMOVE) {
        set_text(button, &remove_label(count));
        // SAFETY: enabling or disabling our own control; repainted so its disabled look shows at once.
        unsafe {
            let _ = EnableWindow(button, count > 0);
            let _ = InvalidateRect(Some(button), None, true);
        }
    }
}

fn destroy(hwnd: HWND) {
    // SAFETY: destroying our own window; the modal loop in `run_modal` then ends.
    let _ = unsafe { DestroyWindow(hwnd) };
}

fn dlg_item(hwnd: HWND, id: i32) -> Option<HWND> {
    // SAFETY: a lookup of a child control by id; no pointers involved.
    unsafe { GetDlgItem(Some(hwnd), id) }.ok()
}

fn set_text_of(hwnd: HWND, id: i32, text: &str) {
    if let Some(item) = dlg_item(hwnd, id) {
        set_text(item, text);
    }
}

fn set_text(hwnd: HWND, text: &str) {
    let buf = to_wide(text);
    // SAFETY: `buf` is NUL-terminated and alive for the call.
    let _ = unsafe { SetWindowTextW(hwnd, PCWSTR(buf.as_ptr())) };
}

fn dpi_of(hwnd: HWND) -> u32 {
    // SAFETY: plain query; a zero result means an invalid window, handled below.
    match unsafe { GetDpiForWindow(hwnd) } {
        0 => 96,
        dpi => dpi,
    }
}

/// Sends a message synchronously. Any pointer in `lparam` must outlive the call (it always does here).
fn send(hwnd: HWND, msg: u32, wparam: usize, lparam: isize) -> isize {
    // SAFETY: callers pass plain values or a pointer to a struct that lives across this synchronous call.
    unsafe { SendMessageW(hwnd, msg, Some(WPARAM(wparam)), Some(LPARAM(lparam))) }.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(left: i32, top: i32, right: i32, bottom: i32) -> RECT {
        RECT {
            left,
            top,
            right,
            bottom,
        }
    }

    #[test]
    fn only_high_confidence_starts_checked() {
        assert!(starts_checked(Confidence::High));
        assert!(!starts_checked(Confidence::Medium));
    }

    #[test]
    fn uncertain_suffix_only_for_medium() {
        assert_eq!(why_text("Install folder", Confidence::High), "Install folder");
        assert_eq!(
            why_text("Install folder", Confidence::Medium),
            "Install folder (uncertain)"
        );
    }

    #[test]
    fn selection_collects_checked_indices_in_order() {
        assert_eq!(selected_indices(&[true, false, true, true]), vec![0, 2, 3]);
        assert!(selected_indices(&[false, false]).is_empty());
        assert!(selected_indices(&[]).is_empty());
    }

    #[test]
    fn counts_and_labels() {
        assert_eq!(count_checked(&[true, false, true]), 2);
        assert_eq!(remove_label(0), "Remove selected (0)");
        assert_eq!(remove_label(12), "Remove selected (12)");
    }

    #[test]
    fn heading_names_the_app() {
        assert_eq!(heading_text("Foo"), "Foo was removed. These leftovers remain");
    }

    #[test]
    fn size_column_is_empty_when_unknown() {
        assert_eq!(size_text(None), "");
        assert_eq!(size_text(Some(1024)), "1.00 KB");
    }

    #[test]
    fn image_index_reads_the_checkbox_bits() {
        assert_eq!(image_index(CHECKED_IMAGE << 12), CHECKED_IMAGE);
        assert_eq!(image_index(UNCHECKED_IMAGE << 12 | 0x2), UNCHECKED_IMAGE);
        assert_eq!(image_index(0), 0);
    }

    #[test]
    fn window_is_centred_and_kept_on_screen() {
        let work = rect(0, 0, 1000, 800);
        assert_eq!(centred_origin(rect(200, 100, 600, 500), 400, 300, work), (200, 150));
        // Owner at the right edge: the window is pulled back inside the work area.
        assert_eq!(centred_origin(rect(900, 0, 1000, 100), 400, 300, work), (600, 0));
        // Window larger than the work area: stays at the top-left corner.
        assert_eq!(centred_origin(rect(0, 0, 100, 100), 2000, 2000, work), (0, 0));
    }
}
