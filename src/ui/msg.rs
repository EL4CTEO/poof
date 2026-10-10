//! Window messages shared between UI modules.

use windows::Win32::UI::WindowsAndMessaging::WM_APP;

/// flow -> main window: the program list is stale, rescan it.
pub const WM_APP_REFRESH: u32 = WM_APP + 1;

/// First message id the main window keeps for itself (scan results, sizes, icons...).
pub const WM_APP_MAIN_BASE: u32 = WM_APP + 10;

/// worker -> main window: a finished program scan. `wParam` = scan generation, `lParam` = boxed result.
pub const WM_APP_SCAN_DONE: u32 = WM_APP_MAIN_BASE + 1;

/// size worker -> main window: one measured folder. `wParam` = scan generation, `lParam` = boxed result.
pub const WM_APP_SIZE_DONE: u32 = WM_APP_MAIN_BASE + 2;
