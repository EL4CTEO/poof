//! Small modal dialogs (message, confirm, about, report) and the wait dialog that covers work running
//! on a worker thread. Everything is a TaskDialog, so it follows the system theme.

use std::cell::Cell;
use std::mem::size_of;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use windows::Win32::Foundation::{HWND, LPARAM, S_FALSE, S_OK, WPARAM};
use windows::Win32::UI::Controls::{
    TASKDIALOG_BUTTON, TASKDIALOG_COMMON_BUTTON_FLAGS, TASKDIALOG_ELEMENTS, TASKDIALOG_MESSAGES,
    TASKDIALOG_NOTIFICATIONS, TASKDIALOGCONFIG, TASKDIALOGCONFIG_0, TD_ERROR_ICON, TD_INFORMATION_ICON,
    TD_WARNING_ICON, TDCBF_CANCEL_BUTTON, TDCBF_OK_BUTTON, TDE_MAIN_INSTRUCTION, TDF_ALLOW_DIALOG_CANCELLATION,
    TDF_CALLBACK_TIMER, TDF_POSITION_RELATIVE_TO_WINDOW, TDF_SHOW_MARQUEE_PROGRESS_BAR, TDM_CLICK_BUTTON,
    TDM_ENABLE_BUTTON, TDM_SET_ELEMENT_TEXT, TDM_SET_PROGRESS_BAR_MARQUEE, TDN_BUTTON_CLICKED, TDN_CREATED, TDN_TIMER,
    TaskDialogIndirect,
};
use windows::Win32::UI::WindowsAndMessaging::{PostMessageW, SendMessageW};
use windows::core::{HRESULT, PCWSTR};

use crate::app_info::{APP_NAME, VERSION};
use crate::audit;
use crate::util::to_wide;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    Info,
    Warning,
    Error,
    Question,
}

/// Button ids. Common buttons keep their standard ids (IDOK = 1, IDCANCEL = 2).
const ID_OK: i32 = 1;
const ID_CANCEL: i32 = 2;
/// Placeholder button of a non-cancellable wait. It stays disabled until the work is done.
const ID_WAIT: i32 = 1001;

/// Modal message with an OK button.
pub fn message_box(owner: HWND, title: &str, text: &str, icon: Icon) {
    let mut plain = Plain::new(title, icon);
    plain.content = text;
    plain.common = TDCBF_OK_BUTTON;
    show_plain(owner, &plain);
}

/// Modal Yes/No style confirmation: returns true when the user chose the `ok_label` button.
pub fn confirm(owner: HWND, title: &str, text: &str, ok_label: &str) -> bool {
    ask(owner, title, "", text, ok_label)
}

/// Confirmation with a bold main line and a longer body. Cancel is the default button.
pub fn ask(owner: HWND, title: &str, main: &str, content: &str, ok_label: &str) -> bool {
    let buttons = [(ID_OK, ok_label)];
    let mut plain = Plain::new(title, Icon::Question);
    plain.main = main;
    plain.content = content;
    plain.buttons = &buttons;
    plain.common = TDCBF_CANCEL_BUTTON;
    plain.default_button = ID_CANCEL;
    show_plain(owner, &plain) == ID_OK
}

/// Information dialog with a main line, a body and an expandable details section (empty = none).
pub fn report(owner: HWND, title: &str, main: &str, content: &str, details: &str, icon: Icon) {
    let mut plain = Plain::new(title, icon);
    plain.main = main;
    plain.content = content;
    plain.details = details;
    plain.common = TDCBF_OK_BUTTON;
    show_plain(owner, &plain);
}

/// About box (name, version, short description).
pub fn about(owner: HWND) {
    let main = format!("{APP_NAME} {VERSION}");
    let content = format!(
        "Fast, lightweight and safe program uninstaller.\n\n\
         Every removal is policy-checked, registry changes are backed up and logged in {}",
        audit::data_dir().display()
    );
    let mut plain = Plain::new("About", Icon::Info);
    plain.main = &main;
    plain.content = &content;
    plain.common = TDCBF_OK_BUTTON;
    show_plain(owner, &plain);
}

/// Runs `work` on a worker thread while a wait dialog with a marquee bar is shown, then returns its result.
///
/// `work` receives the cancel flag. When the dialog is cancellable and the user presses Cancel, the flag is
/// set and the dialog stays open until `work` returns, so no result is ever lost. Returns `None` only when
/// the worker could not be started or panicked.
pub(crate) fn run_with_progress<T: Send + 'static>(
    owner: HWND,
    title: &str,
    text: &str,
    cancellable: bool,
    work: impl FnOnce(&AtomicBool) -> T + Send + 'static,
) -> Option<T> {
    let done = Arc::new(AtomicBool::new(false));
    let cancel = Arc::new(AtomicBool::new(false));
    let worker = {
        let (done, cancel) = (Arc::clone(&done), Arc::clone(&cancel));
        std::thread::Builder::new().name("poof-worker".into()).spawn(move || {
            let _signal = DoneSignal(done);
            work(&cancel)
        })
    };
    let worker = worker.ok()?;
    while !done.load(Ordering::Acquire) {
        let state = WaitState {
            done: &done,
            cancel: &cancel,
            cancellable,
            closing: Cell::new(false),
        };
        if !show_wait(owner, title, text, &state) {
            break;
        }
        // The callback keeps the dialog open until the work is done. Closing it some other way (Esc, the
        // close box) counts as a cancel request, and the dialog comes back until the work has returned.
        if cancellable {
            cancel.store(true, Ordering::Release);
        }
    }
    // Normally the worker has already finished here. Joining also covers a dialog that could not be shown.
    worker.join().ok()
}

/// Sets the done flag when the worker returns or unwinds, so the wait dialog always closes.
struct DoneSignal(Arc<AtomicBool>);

impl Drop for DoneSignal {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// State read by the wait dialog callback. It lives on the caller's stack for the whole TaskDialogIndirect
/// call, which runs its callbacks on this same thread.
struct WaitState<'a> {
    done: &'a AtomicBool,
    cancel: &'a AtomicBool,
    cancellable: bool,
    closing: Cell<bool>,
}

impl WaitState<'_> {
    fn button_id(&self) -> i32 {
        if self.cancellable { ID_CANCEL } else { ID_WAIT }
    }

    /// Lets the dialog close: enables its button and clicks it (posted, so the click lands after the callback).
    fn close(&self, hwnd: HWND) {
        if self.closing.replace(true) {
            return;
        }
        td_send(hwnd, TDM_ENABLE_BUTTON, self.button_id() as usize, 1);
        td_post(hwnd, TDM_CLICK_BUTTON, self.button_id() as usize);
    }

    /// Cancel was pressed while the work is still running: request it and keep the dialog open.
    fn request_cancel(&self, hwnd: HWND) {
        self.cancel.store(true, Ordering::Release);
        td_send(hwnd, TDM_ENABLE_BUTTON, ID_CANCEL as usize, 0);
        set_element_text(hwnd, TDE_MAIN_INSTRUCTION, "Stopping, please wait...");
    }
}

/// Shows the wait dialog until it closes. Returns false when the dialog could not be shown at all.
fn show_wait(owner: HWND, title: &str, text: &str, state: &WaitState<'_>) -> bool {
    let title = to_wide(title);
    let main = to_wide(text);
    let wait_label = to_wide("Please wait");
    let mut flags = TDF_SHOW_MARQUEE_PROGRESS_BAR | TDF_CALLBACK_TIMER | TDF_POSITION_RELATIVE_TO_WINDOW;
    let (common, placeholder) = if state.cancellable {
        flags |= TDF_ALLOW_DIALOG_CANCELLATION;
        (TDCBF_CANCEL_BUTTON, None)
    } else {
        let button = TASKDIALOG_BUTTON {
            nButtonID: ID_WAIT,
            pszButtonText: PCWSTR(wait_label.as_ptr()),
        };
        (TASKDIALOG_COMMON_BUTTON_FLAGS::default(), Some(button))
    };
    let cfg = TASKDIALOGCONFIG {
        cbSize: size_of::<TASKDIALOGCONFIG>() as u32,
        hwndParent: owner,
        dwFlags: flags,
        dwCommonButtons: common,
        pszWindowTitle: PCWSTR(title.as_ptr()),
        pszMainInstruction: PCWSTR(main.as_ptr()),
        cButtons: u32::from(placeholder.is_some()),
        pButtons: placeholder
            .as_ref()
            .map_or(ptr::null(), |b| b as *const TASKDIALOG_BUTTON),
        pfCallback: Some(wait_callback),
        lpCallbackData: state as *const WaitState<'_> as isize,
        ..TASKDIALOGCONFIG::default()
    };
    // SAFETY: `cfg` and everything it points to (title, text, placeholder button, `state`) stay alive until
    // TaskDialogIndirect returns, and `cbSize` is the exact size of the struct.
    unsafe { TaskDialogIndirect(&cfg, None, None, None) }.is_ok()
}

/// Notification handler of the wait dialog.
///
/// # Safety
/// Called by comctl32 only, with `data` set to the address of a live `WaitState` on this thread.
unsafe extern "system" fn wait_callback(
    hwnd: HWND,
    msg: TASKDIALOG_NOTIFICATIONS,
    wparam: WPARAM,
    _lparam: LPARAM,
    data: isize,
) -> HRESULT {
    // SAFETY: `data` is the address of the WaitState owned by `show_wait`'s caller; it outlives this callback.
    let state = unsafe { &*(data as *const WaitState<'_>) };
    let finished = state.done.load(Ordering::Acquire);
    match msg {
        TDN_CREATED => {
            td_send(hwnd, TDM_SET_PROGRESS_BAR_MARQUEE, 1, 30);
            if !state.cancellable {
                td_send(hwnd, TDM_ENABLE_BUTTON, ID_WAIT as usize, 0);
            }
            if finished {
                state.close(hwnd);
            }
        }
        TDN_TIMER => {
            if finished {
                state.close(hwnd);
            }
        }
        TDN_BUTTON_CLICKED => {
            if finished {
                return S_OK;
            }
            if state.cancellable && wparam.0 == ID_CANCEL as usize {
                state.request_cancel(hwnd);
            }
            // Keep the dialog open until the work is done.
            return S_FALSE;
        }
        _ => {}
    }
    S_OK
}

/// Sends a TaskDialog message synchronously. Any pointer in `lparam` must outlive the call (it does here).
fn td_send(hwnd: HWND, msg: TASKDIALOG_MESSAGES, wparam: usize, lparam: isize) {
    // SAFETY: `hwnd` is the live wait dialog passed to the callback; the call is synchronous.
    let _ = unsafe { SendMessageW(hwnd, msg.0 as u32, Some(WPARAM(wparam)), Some(LPARAM(lparam))) };
}

/// Posts a TaskDialog message with plain values only.
fn td_post(hwnd: HWND, msg: TASKDIALOG_MESSAGES, wparam: usize) {
    // SAFETY: plain values only; posting to a dialog that already closed simply fails.
    let _ = unsafe { PostMessageW(Some(hwnd), msg.0 as u32, WPARAM(wparam), LPARAM(0)) };
}

fn set_element_text(hwnd: HWND, element: TASKDIALOG_ELEMENTS, text: &str) {
    let buf = to_wide(text);
    td_send(hwnd, TDM_SET_ELEMENT_TEXT, element.0 as usize, buf.as_ptr() as isize);
}

/// Everything a plain TaskDialog needs. The strings are converted to UTF-16 inside `show_plain`.
struct Plain<'a> {
    title: &'a str,
    main: &'a str,
    content: &'a str,
    details: &'a str,
    icon: Icon,
    buttons: &'a [(i32, &'a str)],
    common: TASKDIALOG_COMMON_BUTTON_FLAGS,
    default_button: i32,
}

impl<'a> Plain<'a> {
    fn new(title: &'a str, icon: Icon) -> Self {
        Self {
            title,
            main: "",
            content: "",
            details: "",
            icon,
            buttons: &[],
            common: TASKDIALOG_COMMON_BUTTON_FLAGS::default(),
            default_button: 0,
        }
    }
}

/// Shows a plain TaskDialog and returns the id of the button that closed it (0 if it could not be shown).
fn show_plain(owner: HWND, plain: &Plain<'_>) -> i32 {
    let title = to_wide(plain.title);
    let main = to_wide(plain.main);
    let content = to_wide(plain.content);
    let details = to_wide(plain.details);
    let labels: Vec<Vec<u16>> = plain.buttons.iter().map(|(_, label)| to_wide(label)).collect();
    let buttons: Vec<TASKDIALOG_BUTTON> = plain
        .buttons
        .iter()
        .zip(&labels)
        .map(|((id, _), label)| TASKDIALOG_BUTTON {
            nButtonID: *id,
            pszButtonText: PCWSTR(label.as_ptr()),
        })
        .collect();
    let cfg = TASKDIALOGCONFIG {
        cbSize: size_of::<TASKDIALOGCONFIG>() as u32,
        hwndParent: owner,
        dwFlags: TDF_POSITION_RELATIVE_TO_WINDOW | TDF_ALLOW_DIALOG_CANCELLATION,
        dwCommonButtons: plain.common,
        pszWindowTitle: PCWSTR(title.as_ptr()),
        Anonymous1: TASKDIALOGCONFIG_0 {
            pszMainIcon: icon_resource(plain.icon),
        },
        pszMainInstruction: text_or_null(&main),
        pszContent: text_or_null(&content),
        cButtons: buttons.len() as u32,
        pButtons: buttons.as_ptr(),
        nDefaultButton: plain.default_button,
        pszExpandedInformation: text_or_null(&details),
        ..TASKDIALOGCONFIG::default()
    };
    let mut pressed = 0;
    // SAFETY: `cfg` and every buffer it points to (title, texts, labels, buttons) stay alive until
    // TaskDialogIndirect returns, and `cbSize` is the exact size of the struct.
    match unsafe { TaskDialogIndirect(&cfg, Some(&mut pressed), None, None) } {
        Ok(()) => pressed,
        Err(_) => 0,
    }
}

fn icon_resource(icon: Icon) -> PCWSTR {
    match icon {
        Icon::Info => TD_INFORMATION_ICON,
        Icon::Warning => TD_WARNING_ICON,
        Icon::Error => TD_ERROR_ICON,
        Icon::Question => PCWSTR::null(),
    }
}

/// A NUL-terminated UTF-16 string with no characters is passed as null (the dialog then skips that element).
fn text_or_null(wide: &[u16]) -> PCWSTR {
    if wide.len() > 1 {
        PCWSTR(wide.as_ptr())
    } else {
        PCWSTR::null()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn question_has_no_icon() {
        assert!(icon_resource(Icon::Question).0.is_null());
        assert!(!icon_resource(Icon::Error).0.is_null());
    }

    #[test]
    fn empty_text_is_null() {
        assert!(text_or_null(&to_wide("")).0.is_null());
        assert!(!text_or_null(&to_wide("x")).0.is_null());
    }
}
