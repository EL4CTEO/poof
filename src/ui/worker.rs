//! Background work for the main window: the program scan, lazy folder sizes, and the helpers that
//! hand their results back to the UI thread. Threads never touch window state.

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::thread;

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::Storage::FileSystem::GetDriveTypeW;
use windows::Win32::System::WindowsProgramming::DRIVE_REMOTE;
use windows::Win32::UI::WindowsAndMessaging::PostMessageW;
use windows::core::PCWSTR;

use crate::inventory;
use crate::model::InstalledApp;
use crate::security::normalize_lexical;
use crate::ui::msg;
use crate::util::to_wide;

/// Output of one program scan, with the lower-cased search haystacks precomputed.
pub struct ScanResult {
    pub apps: Vec<InstalledApp>,
    pub haystacks: Vec<String>,
}

/// One measured folder.
pub struct SizeResult {
    pub id: String,
    pub bytes: u64,
}

/// A folder to measure. `cancel` is shared by every job of one scan generation.
pub struct SizeJob {
    pub generation: u32,
    pub id: String,
    pub path: PathBuf,
    pub cancel: Arc<AtomicBool>,
}

/// Normalised absolute path on a local (non-network) drive, or `None`.
/// Network paths are rejected so that the UI thread never waits on the network.
pub fn local_path(p: &Path) -> Option<PathBuf> {
    let norm = normalize_lexical(p).ok()?;
    let root = to_wide(norm.to_str()?.get(..3)?);
    // SAFETY: `root` is a NUL-terminated drive root; GetDriveTypeW only reads it.
    let kind = unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) };
    (kind != DRIVE_REMOTE).then_some(norm)
}

/// An existing local directory, or `None`.
pub fn local_dir(p: &Path) -> Option<PathBuf> {
    local_path(p).filter(|dir| dir.is_dir())
}

/// Posts a boxed payload to `hwnd`. The box is reclaimed with [`take`] when the message is delivered;
/// if the window is gone the box is dropped here.
pub fn post<T: Send + 'static>(hwnd: isize, msg: u32, generation: u32, payload: T) {
    let raw = Box::into_raw(Box::new(payload));
    // SAFETY: PostMessageW only queues the message. A stale handle makes it fail, handled below.
    let posted = unsafe {
        PostMessageW(Some(HWND(hwnd as *mut c_void)), msg, WPARAM(generation as usize), LPARAM(raw as isize))
    };
    if posted.is_err() {
        // SAFETY: the message was never queued, so nobody else owns `raw`.
        drop(unsafe { Box::from_raw(raw) });
    }
}

/// Takes back a payload delivered by [`post`]. Call exactly once per delivered message.
pub fn take<T>(lparam: LPARAM) -> Option<Box<T>> {
    if lparam.0 == 0 {
        return None;
    }
    // SAFETY: `lparam` was produced by `post::<T>` for this message, which is delivered exactly once.
    Some(unsafe { Box::from_raw(lparam.0 as *mut T) })
}

/// Runs the program scan on a detached thread and posts a [`ScanResult`] tagged with `generation`.
pub fn spawn_scan(hwnd: HWND, generation: u32) -> bool {
    let target = hwnd.0 as isize;
    thread::Builder::new()
        .name("poof-scan".into())
        .spawn(move || {
            let apps = inventory::scan_all();
            let haystacks = apps.iter().map(InstalledApp::haystack).collect();
            post(target, msg::WM_APP_SCAN_DONE, generation, ScanResult { apps, haystacks });
        })
        .is_ok()
}

/// Folder sizes that are still unknown, as jobs for one scan generation.
pub fn size_jobs(apps: &[InstalledApp], generation: u32, cancel: &Arc<AtomicBool>) -> Vec<SizeJob> {
    apps.iter()
        .filter(|app| app.size_bytes.is_none())
        .filter_map(|app| {
            Some(SizeJob {
                generation,
                id: app.id.clone(),
                path: app.install_location.clone()?,
                cancel: Arc::clone(cancel),
            })
        })
        .collect()
}

/// The single background thread that measures folders, one at a time. It exits when the
/// [`SizeWorker`] is dropped (the queue closes) and skips jobs whose scan generation was cancelled.
pub struct SizeWorker {
    tx: Sender<SizeJob>,
}

impl SizeWorker {
    pub fn start(hwnd: HWND) -> Option<Self> {
        let (tx, rx) = mpsc::channel::<SizeJob>();
        let target = hwnd.0 as isize;
        thread::Builder::new()
            .name("poof-size".into())
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    if job.cancel.load(Ordering::Relaxed) {
                        continue;
                    }
                    let Some(dir) = local_dir(&job.path) else { continue };
                    let bytes = inventory::dir_size(&dir, &job.cancel);
                    if !job.cancel.load(Ordering::Relaxed) {
                        post(target, msg::WM_APP_SIZE_DONE, job.generation, SizeResult { id: job.id, bytes });
                    }
                }
            })
            .ok()?;
        Some(Self { tx })
    }

    pub fn queue(&self, jobs: Vec<SizeJob>) {
        for job in jobs {
            if self.tx.send(job).is_err() {
                break;
            }
        }
    }
}
