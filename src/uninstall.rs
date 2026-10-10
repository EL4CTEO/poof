//! Runs an application's uninstaller safely and reports what happened.

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessW, GetExitCodeProcess, PROCESS_INFORMATION, STARTUPINFOW,
    WaitForSingleObject,
};
use windows::Win32::UI::Shell::{SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{PCWSTR, PWSTR};

use crate::audit;
use crate::command::{self, CommandError, ParsedCommand};
use crate::inventory;
use crate::model::{AppKind, Hive, InstalledApp};
use crate::security;
use crate::store;
use crate::util::{path_to_wide, to_wide};
use crate::winreg;

/// Win32 error codes we react to (ERROR_ELEVATION_REQUIRED, ERROR_CANCELLED).
const ERROR_ELEVATION_REQUIRED: u32 = 740;
const ERROR_CANCELLED: u32 = 1223;

const WAIT_SLICE: u32 = 250;
const REGISTRATION_POLL: Duration = Duration::from_millis(500);
const REGISTRATION_WAIT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The vendor's normal uninstaller UI.
    Interactive,
    /// Silent uninstall (QuietUninstallString / `msiexec /qn`). Check [`supports_quiet`] first.
    Quiet,
}

#[derive(Clone, Debug)]
pub struct Outcome {
    /// Exit code of the uninstaller, `None` if we could not wait for it.
    pub exit_code: Option<u32>,
    /// Whether the app's registration is still present after the uninstaller finished.
    pub still_registered: bool,
}

#[derive(Clone, Debug)]
pub enum UninstallError {
    NoUninstaller,
    /// Rejected by the safety policy (message is user-presentable).
    Rejected(String),
    /// The process could not be started.
    Launch(String),
    Cancelled,
}

impl std::fmt::Display for UninstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UninstallError::NoUninstaller => f.write_str("this program has no uninstaller"),
            UninstallError::Rejected(m) | UninstallError::Launch(m) => f.write_str(m),
            UninstallError::Cancelled => f.write_str("cancelled"),
        }
    }
}

/// Whether a silent uninstall is available for this app.
pub fn supports_quiet(app: &InstalledApp) -> bool {
    app.is_store() || app.quiet_uninstall_string.is_some() || app.msi_product_code.is_some()
}

/// Uninstalls `app` (Win32 or Store) and BLOCKS until finished. Run on a worker thread.
/// Setting `cancel` abandons the wait (the uninstaller process itself is never killed).
pub fn run(app: &InstalledApp, mode: Mode, cancel: &AtomicBool) -> Result<Outcome, UninstallError> {
    if app.is_store() {
        return run_store(app);
    }
    let cmd = build_command(app, mode)?;
    audit::log(&format!("uninstall start: {} | {}", app.name, cmd.command_line()));

    let process = launch(&cmd)?;
    let exit_code = match &process {
        Some(handle) => wait_for_exit(handle, cancel)?,
        None => None,
    };
    await_registration_gone(app, cancel);

    let outcome = Outcome { exit_code, still_registered: inventory::is_registered(app) };
    let exit = exit_code.map_or_else(|| "unknown".to_owned(), |code| code.to_string());
    audit::log(&format!("uninstall end: {} | exit {exit} | still registered {}", app.name, outcome.still_registered));
    Ok(outcome)
}

/// Forced removal of a broken registration: deletes the app's Uninstall registry key (policy-checked).
pub fn force_remove_entry(app: &InstalledApp) -> Result<(), String> {
    let reg = match (app.kind, app.reg.as_ref()) {
        (AppKind::Win32, Some(reg)) => reg,
        _ => return Err("not supported".into()),
    };
    security::check_registry_delete(reg.hive, &reg.subkey).map_err(|e| e.0)?;
    let result = winreg::delete_tree(reg.hive, &reg.subkey);
    let status = if result.is_ok() { "ok" } else { "failed" };
    audit::log(&format!("registry entry removed: {} ({}) | {status}", app.name, reg.display()));
    result
}

fn run_store(app: &InstalledApp) -> Result<Outcome, UninstallError> {
    let full_name = app.package_full_name.as_deref().ok_or(UninstallError::NoUninstaller)?;
    store::remove_package(full_name).map_err(UninstallError::Launch)?;
    Ok(Outcome { exit_code: Some(0), still_registered: store::is_installed(full_name) })
}

/// The command we are willing to run for this app and mode, after the privilege-context check.
fn build_command(app: &InstalledApp, mode: Mode) -> Result<ParsedCommand, UninstallError> {
    let cmd = resolve_command(app, mode)?;
    let from_user_hive = app.reg.as_ref().is_some_and(|reg| reg.hive == Hive::CurrentUser);
    command::check_context(&cmd, from_user_hive, security::is_elevated()).map_err(|e| UninstallError::Rejected(e.0))?;
    Ok(cmd)
}

fn resolve_command(app: &InstalledApp, mode: Mode) -> Result<ParsedCommand, UninstallError> {
    match mode {
        Mode::Quiet => quiet_command(app),
        Mode::Interactive => interactive_command(app),
    }
}

fn quiet_command(app: &InstalledApp) -> Result<ParsedCommand, UninstallError> {
    if let Some(raw) = app.quiet_uninstall_string.as_deref() {
        return command::parse(raw).map_err(parse_error);
    }
    match app.msi_product_code.as_deref() {
        Some(code) => msi_command(code, true),
        None => Err(UninstallError::Rejected("no silent uninstall available".into())),
    }
}

fn interactive_command(app: &InstalledApp) -> Result<ParsedCommand, UninstallError> {
    let uninstall = app.uninstall_string.as_deref();
    // Repair strings (`/I`) of MSI products are replaced by a proper removal (`/x`).
    let msi = app.msi_product_code.as_deref().filter(|_| uninstall.is_none_or(command::is_msiexec_command));
    if let Some(code) = msi {
        return msi_command(code, false);
    }
    // Some vendors only register a silent command; running it beats reporting "no uninstaller".
    match uninstall.or(app.quiet_uninstall_string.as_deref()) {
        Some(raw) => command::parse(raw).map_err(parse_error),
        None => Err(UninstallError::NoUninstaller),
    }
}

fn msi_command(code: &str, quiet: bool) -> Result<ParsedCommand, UninstallError> {
    command::msi_uninstall_command(code, quiet).map_err(|e| UninstallError::Rejected(e.to_string()))
}

fn parse_error(e: CommandError) -> UninstallError {
    match e {
        CommandError::NotFound(path) => UninstallError::Rejected(format!("the uninstaller was not found: {path}")),
        other => UninstallError::Rejected(other.to_string()),
    }
}

/// Owned kernel handle, closed on drop.
struct Handle(HANDLE);

impl Handle {
    /// Wraps a handle returned by the OS; `None` for null or invalid values.
    fn new(handle: HANDLE) -> Option<Self> {
        (!handle.0.is_null() && !handle.is_invalid()).then_some(Self(handle))
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this guard and closed exactly once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Win32 error code carried by a `windows` error (unwrapping the `HRESULT_FROM_WIN32` form).
fn win32_code(e: &windows::core::Error) -> u32 {
    let hr = e.code().0 as u32;
    if hr >> 16 == 0x8007 { hr & 0xFFFF } else { hr }
}

/// Starts the uninstaller. `Ok(None)` when no process handle is available to wait on.
fn launch(cmd: &ParsedCommand) -> Result<Option<Handle>, UninstallError> {
    match create_process(cmd) {
        Ok(handle) => Ok(handle),
        Err(e) if win32_code(&e) == ERROR_ELEVATION_REQUIRED => shell_execute_runas(cmd),
        Err(e) => Err(launch_error(win32_code(&e))),
    }
}

fn create_process(cmd: &ParsedCommand) -> windows::core::Result<Option<Handle>> {
    let exe = path_to_wide(&cmd.exe);
    let mut command_line = to_wide(&cmd.command_line());
    let dir = cmd.exe.parent().map(path_to_wide);
    let dir_ptr = dir.as_ref().map_or(PCWSTR::null(), |d| PCWSTR(d.as_ptr()));
    let startup = STARTUPINFOW { cb: size_of::<STARTUPINFOW>() as u32, ..Default::default() };
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: every string is NUL-terminated and outlives the call; the command line buffer is writable as the API
    // may modify it; `startup` and `info` are valid for the access the API performs.
    unsafe {
        CreateProcessW(
            PCWSTR(exe.as_ptr()),
            Some(PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_UNICODE_ENVIRONMENT,
            None,
            dir_ptr,
            &startup,
            &mut info,
        )?;
    }
    let _thread = Handle::new(info.hThread);
    Ok(Handle::new(info.hProcess))
}

/// Elevation fallback: the uninstaller asks for administrator rights through the UAC prompt.
fn shell_execute_runas(cmd: &ParsedCommand) -> Result<Option<Handle>, UninstallError> {
    let verb = to_wide("runas");
    let file = path_to_wide(&cmd.exe);
    let params = to_wide(&cmd.args);
    let dir = cmd.exe.parent().map(path_to_wide);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(params.as_ptr()),
        lpDirectory: dir.as_ref().map_or(PCWSTR::null(), |d| PCWSTR(d.as_ptr())),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    // SAFETY: all string pointers are NUL-terminated and alive for the call; `info` is a fully initialised struct
    // whose `cbSize` matches its type.
    unsafe { ShellExecuteExW(&mut info) }.map_err(|e| match win32_code(&e) {
        ERROR_CANCELLED => UninstallError::Cancelled,
        code => launch_error(code),
    })?;
    Ok(Handle::new(info.hProcess))
}

fn launch_error(code: u32) -> UninstallError {
    UninstallError::Launch(format!("could not start the uninstaller (Windows error {code})"))
}

/// Waits in short slices so `cancel` is honoured. `Ok(None)` if the wait itself failed.
fn wait_for_exit(process: &Handle, cancel: &AtomicBool) -> Result<Option<u32>, UninstallError> {
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(UninstallError::Cancelled);
        }
        // SAFETY: `process` is a live handle owned by a `Handle` guard for the whole call.
        let state = unsafe { WaitForSingleObject(process.0, WAIT_SLICE) };
        if state == WAIT_OBJECT_0 {
            break;
        }
        if state != WAIT_TIMEOUT {
            return Ok(None);
        }
    }
    let mut code = 0u32;
    // SAFETY: valid process handle and a valid out pointer.
    let read = unsafe { GetExitCodeProcess(process.0, &mut code) };
    Ok(read.is_ok().then_some(code))
}

/// Many uninstallers relaunch themselves and exit at once, so give the real removal time to finish.
fn await_registration_gone(app: &InstalledApp, cancel: &AtomicBool) {
    let deadline = Instant::now() + REGISTRATION_WAIT;
    while inventory::is_registered(app) && Instant::now() < deadline && !cancel.load(Ordering::Relaxed) {
        thread::sleep(REGISTRATION_POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Health, RegLocation};

    const GUID: &str = "{0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9}";
    const MISSING: &str = "C:\\poof-test-missing\\unins000.exe";

    fn app(uninstall: Option<&str>, quiet: Option<&str>, msi: Option<&str>, hive: Hive) -> InstalledApp {
        InstalledApp {
            id: "win32:test".into(),
            kind: AppKind::Win32,
            name: "Test".into(),
            publisher: String::new(),
            version: String::new(),
            install_date: 0,
            install_location: None,
            size_bytes: None,
            icon_source: None,
            uninstall_string: uninstall.map(Into::into),
            quiet_uninstall_string: quiet.map(Into::into),
            msi_product_code: msi.map(Into::into),
            help_link: None,
            reg: Some(RegLocation { hive, subkey: "SOFTWARE\\Test".into() }),
            package_full_name: None,
            health: Health::Ok,
        }
    }

    fn msi_app(uninstall: Option<&str>) -> InstalledApp {
        app(uninstall, None, Some(GUID), Hive::LocalMachine)
    }

    #[test]
    fn quiet_msi_uses_msiexec_quiet_flags() {
        let cmd = build_command(&msi_app(None), Mode::Quiet).unwrap();
        assert!(cmd.exe.ends_with("msiexec.exe"));
        assert_eq!(cmd.args, format!("/x {GUID} /qn /norestart"));
    }

    #[test]
    fn quiet_prefers_quiet_string() {
        let quiet = format!("\"{MISSING}\" /S");
        let a = app(None, Some(&quiet), Some(GUID), Hive::LocalMachine);
        assert!(matches!(build_command(&a, Mode::Quiet), Err(UninstallError::Rejected(m)) if m.contains("not found")));
    }

    #[test]
    fn quiet_without_any_silent_path_is_rejected() {
        let a = app(Some(MISSING), None, None, Hive::LocalMachine);
        assert!(
            matches!(build_command(&a, Mode::Quiet), Err(UninstallError::Rejected(m)) if m == "no silent uninstall available")
        );
    }

    #[test]
    fn interactive_msi_repair_string_becomes_removal() {
        let repair = format!("MsiExec.exe /I{GUID}");
        let cmd = build_command(&msi_app(Some(&repair)), Mode::Interactive).unwrap();
        assert_eq!(cmd.args, format!("/x {GUID}"));
    }

    #[test]
    fn interactive_msi_without_uninstall_string_uses_removal() {
        let cmd = build_command(&msi_app(None), Mode::Interactive).unwrap();
        assert_eq!(cmd.args, format!("/x {GUID}"));
        assert!(!cmd.args.contains("/qn"));
    }

    #[test]
    fn interactive_vendor_uninstaller_is_parsed_not_replaced() {
        let a = msi_app(Some(MISSING));
        assert!(
            matches!(build_command(&a, Mode::Interactive), Err(UninstallError::Rejected(m)) if m.contains("not found"))
        );
    }

    #[test]
    fn interactive_without_any_uninstaller() {
        let a = app(None, None, None, Hive::LocalMachine);
        assert!(matches!(build_command(&a, Mode::Interactive), Err(UninstallError::NoUninstaller)));
    }

    #[test]
    fn unsafe_uninstall_string_is_rejected() {
        let a = app(Some("evil.exe /x"), None, None, Hive::LocalMachine);
        assert!(matches!(build_command(&a, Mode::Interactive), Err(UninstallError::Rejected(_))));
    }

    #[test]
    fn supports_quiet_reflects_available_strings() {
        assert!(supports_quiet(&app(None, Some("x"), None, Hive::LocalMachine)));
        assert!(supports_quiet(&msi_app(None)));
        assert!(!supports_quiet(&app(Some(MISSING), None, None, Hive::LocalMachine)));
    }

    #[test]
    fn win32_code_unwraps_hresult_from_win32() {
        let hr = windows::core::Error::from_hresult(windows::core::HRESULT(0x8007_02E4_u32 as i32));
        assert_eq!(win32_code(&hr), ERROR_ELEVATION_REQUIRED);
    }
}
