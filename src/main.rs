#![windows_subsystem = "windows"]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod app_info;
mod audit;
mod cleaner;
mod command;
#[cfg(test)]
mod e2e;
mod hardening;
mod inventory;
mod leftovers;
mod model;
mod security;
mod store;
mod ui;
mod uninstall;
mod util;
mod winreg;

use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
use windows::Win32::System::Threading::CreateMutexW;
use windows::core::PCWSTR;

/// Passed by the "run as administrator" action so the new process waits for the old one to exit.
pub const RELAUNCH_ARG: &str = "--relaunch";

fn main() {
    hardening::apply();
    install_panic_hook();

    let relaunch = std::env::args().any(|a| a == RELAUNCH_ARG);
    let Some(mutex) = acquire_single_instance(relaunch) else {
        ui::activate_existing();
        return;
    };

    let code = ui::run();
    // SAFETY: handle came from CreateMutexW in `acquire_single_instance`.
    unsafe {
        let _ = CloseHandle(mutex);
    }
    std::process::exit(code);
}

/// Returns the instance mutex, or `None` when another instance already owns it.
/// When relaunching, retries for a few seconds while the previous instance shuts down.
fn acquire_single_instance(relaunch: bool) -> Option<HANDLE> {
    let name = util::to_wide(app_info::MUTEX_NAME);
    let deadline = Instant::now() + Duration::from_secs(if relaunch { 6 } else { 0 });
    loop {
        // SAFETY: NUL-terminated name; the handle is closed by us (or the OS at exit).
        let handle = unsafe { CreateMutexW(None, false, PCWSTR(name.as_ptr())) };
        // SAFETY: reads the thread's last error right after the call above.
        let exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        match handle {
            Ok(h) if !exists => return Some(h),
            Ok(h) => {
                // SAFETY: valid handle from the call above.
                unsafe {
                    let _ = CloseHandle(h);
                }
            }
            Err(_) => return Some(HANDLE::default()), // cannot enforce single instance; run anyway
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Panics abort the process (release profile); record them first so they are diagnosable.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        audit::log(&format!("PANIC: {info}"));
    }));
}
