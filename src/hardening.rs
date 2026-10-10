//! Process-level hardening applied before any window or file work happens.

use std::ffi::c_void;

use windows::Win32::System::LibraryLoader::{LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories, SetDllDirectoryW};
use windows::Win32::System::Memory::{HeapEnableTerminationOnCorruption, HeapSetInformation};
use windows::Win32::System::SystemServices::PROCESS_MITIGATION_IMAGE_LOAD_POLICY;
use windows::Win32::System::Threading::{
    ProcessImageLoadPolicy, SetProcessMitigationPolicy,
};
use windows::core::w;

/// Call first thing in `main`. Every step is best-effort: failure never stops the app.
pub fn apply() {
    // SAFETY: plain process-wide configuration calls with valid arguments.
    unsafe {
        // Never load DLLs from the working directory / PATH: System32 only (plus explicit full paths).
        let _ = SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
        let _ = SetDllDirectoryW(w!(""));
        // Abort on heap corruption instead of continuing in a corrupt state.
        let _ = HeapSetInformation(None, HeapEnableTerminationOnCorruption, None, 0);

        // No images from network shares or low-integrity locations; prefer System32 copies.
        let mut policy = PROCESS_MITIGATION_IMAGE_LOAD_POLICY::default();
        policy.Anonymous.Flags = 0b111;
        let _ = SetProcessMitigationPolicy(
            ProcessImageLoadPolicy,
            &policy as *const _ as *const c_void,
            size_of::<PROCESS_MITIGATION_IMAGE_LOAD_POLICY>(),
        );
    }
}
