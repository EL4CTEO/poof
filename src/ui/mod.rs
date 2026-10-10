//! Native Win32 user interface: the main window, the program list, theme, CSV export and the
//! uninstall flow (`flow` and `dialogs` are owned by the flow module).

pub mod dialogs;
pub mod flow;
pub mod msg;
pub mod review;
pub mod theme;

mod export;
mod list;
mod window;
mod worker;

/// Creates the main window and runs the message loop. Returns the process exit code.
pub fn run() -> i32 {
    window::run()
}

/// Brings an already-running instance's window to the foreground (single-instance support).
pub fn activate_existing() {
    window::activate_existing();
}
