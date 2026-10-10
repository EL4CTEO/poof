//! The uninstall pipeline: confirm -> uninstall -> leftover scan -> review -> clean -> report.
//! Straight-line code on the UI thread. Only the blocking calls run on workers (`dialogs::run_with_progress`).

use std::path::PathBuf;

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::PostMessageW;

use crate::app_info::APP_NAME;
use crate::audit;
use crate::cleaner::{self, CleanOptions, CleanReport};
use crate::leftovers::{self, Leftover};
use crate::model::InstalledApp;
use crate::security;
use crate::uninstall::{self, Mode, UninstallError};
use crate::util;

use super::dialogs::{self, Icon};
use super::msg;
use super::review;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Run the uninstaller (`quiet` = silent mode), then scan and clean leftovers.
    Uninstall { quiet: bool },
    /// Broken entries: remove the registration without running anything, then scan leftovers.
    ForceRemove,
}

/// Runs the pipeline for `apps` (processed one after another). Called on the UI thread from a
/// command handler (never while holding references into window state). It BLOCKS in nested modal
/// loops (the owner window stays responsive to painting but is disabled); all blocking work runs
/// on worker threads. When it finishes it posts `msg::WM_APP_REFRESH` to `owner`.
pub fn start(owner: HWND, apps: Vec<InstalledApp>, action: Action) {
    if apps.is_empty() || !confirm(owner, &apps, action) {
        return;
    }
    let ids: Vec<&str> = apps.iter().map(|app| app.id.as_str()).collect();
    audit::log(&format!("pipeline start: {action:?} [{}]", ids.join(", ")));

    let mut totals = Totals::default();
    for app in &apps {
        process(owner, app, action, &mut totals);
    }
    finish(owner, &apps, &totals);
    post_refresh(owner);
    audit::log(&format!(
        "pipeline end: {} app(s), {} item(s) removed",
        apps.len(),
        totals.removed
    ));
}

const TITLE: &str = APP_NAME;
/// Names listed in the confirmation before the rest is summarised.
const LIST_CAP: usize = 8;
/// Detail lines shown in the report's expandable section.
const DETAIL_CAP: usize = 40;
const FORCE_NOTE: &str = "This removes the broken entry from the list without running an uninstaller. \
     Afterwards you can review any leftover files and registry entries.";
const STORE_NOTE: &str = "Store apps are removed silently.";
const ADMIN_HINT: &str = "Some items need administrator rights - choose More > Run as administrator.";

/// One yes/no question before anything runs. Returns false when the user backs out.
fn confirm(owner: HWND, apps: &[InstalledApp], action: Action) -> bool {
    let names = bullets(&apps.iter().map(|app| app.name.clone()).collect::<Vec<_>>());
    let (main, content, ok) = match (action, apps) {
        (Action::ForceRemove, [app]) => (
            format!("Remove the broken entry for {}?", app.name),
            FORCE_NOTE.to_owned(),
            "Remove entry",
        ),
        (Action::ForceRemove, _) => (
            format!("Remove the broken entries for {} programs?", apps.len()),
            paragraphs(&[join_capped(&names, LIST_CAP), FORCE_NOTE.to_owned()]),
            "Remove entries",
        ),
        (Action::Uninstall { .. }, [app]) => {
            let note = if app.is_store() { STORE_NOTE } else { "" };
            (format!("Uninstall {}?", app.name), note.to_owned(), "Uninstall")
        }
        (Action::Uninstall { .. }, _) => {
            let note = if apps.iter().any(InstalledApp::is_store) {
                STORE_NOTE
            } else {
                ""
            };
            (
                format!("Uninstall {} programs one after another?", apps.len()),
                paragraphs(&[join_capped(&names, LIST_CAP), note.to_owned()]),
                "Uninstall",
            )
        }
    };
    dialogs::ask(owner, TITLE, &main, &content, ok)
}

/// Runs the removal step for one app, then its leftover scan and cleanup if the removal went through.
fn process(owner: HWND, app: &InstalledApp, action: Action, totals: &mut Totals) {
    // Resolved before anything runs: the install folder may be gone once an uninstaller has finished.
    let install_root = app
        .install_location
        .as_ref()
        .and_then(|path| security::validate_install_root(path).ok());
    let removed = match action {
        Action::Uninstall { quiet } => uninstall_app(owner, app, quiet),
        Action::ForceRemove => force_remove(owner, app),
    };
    if removed {
        scan_and_clean(owner, app, install_root, totals);
    }
}

/// Runs the app's uninstaller. Returns true when the leftover scan should follow.
fn uninstall_app(owner: HWND, app: &InstalledApp, quiet: bool) -> bool {
    let mode = if quiet && uninstall::supports_quiet(app) {
        Mode::Quiet
    } else {
        Mode::Interactive
    };
    let target = app.clone();
    let text = format!("Waiting for {} to finish uninstalling...", app.name);
    let result = dialogs::run_with_progress(owner, TITLE, &text, true, move |cancel| {
        uninstall::run(&target, mode, cancel)
    });
    let outcome = match result {
        Some(Ok(outcome)) => outcome,
        // The user stopped waiting. The uninstaller keeps running; nothing more happens for this app.
        Some(Err(UninstallError::Cancelled)) => return false,
        Some(Err(err)) => {
            show_uninstall_error(owner, app, &err);
            return false;
        }
        None => {
            dialogs::message_box(
                owner,
                TITLE,
                &format!("{} could not be uninstalled.", app.name),
                Icon::Error,
            );
            return false;
        }
    };
    audit::log(&format!(
        "uninstall {} exit={:?} still_registered={}",
        app.id, outcome.exit_code, outcome.still_registered
    ));
    // A self-relaunching uninstaller can leave the entry behind with a 0 exit code: that counts as done.
    if !outcome.still_registered || outcome.exit_code == Some(0) {
        return true;
    }
    let text = match outcome.exit_code {
        Some(code) => format!(
            "{} still appears to be installed (exit code {code}). Scan for leftovers anyway?",
            app.name
        ),
        None => format!("{} still appears to be installed. Scan for leftovers anyway?", app.name),
    };
    dialogs::confirm(owner, TITLE, &text, "Scan")
}

fn show_uninstall_error(owner: HWND, app: &InstalledApp, err: &UninstallError) {
    let mut text = format!("{} could not be uninstalled.\n\n{err}", app.name);
    if matches!(err, UninstallError::NoUninstaller) {
        text.push_str("\n\nUse Force remove from the right-click menu to clear its entry.");
    }
    dialogs::message_box(owner, TITLE, &text, Icon::Error);
}

/// Removes a broken registration without running anything. Returns true when the leftover scan should follow.
fn force_remove(owner: HWND, app: &InstalledApp) -> bool {
    match uninstall::force_remove_entry(app) {
        Ok(()) => {
            audit::log(&format!("force-removed entry {}", app.id));
            true
        }
        Err(reason) => {
            dialogs::message_box(
                owner,
                TITLE,
                &format!("{} could not be removed from the list.\n\n{reason}", app.name),
                Icon::Error,
            );
            false
        }
    }
}

/// Scans for leftovers, lets the user review them, and removes the selected ones.
fn scan_and_clean(owner: HWND, app: &InstalledApp, install_root: Option<PathBuf>, totals: &mut Totals) {
    let Some(items) = scan(owner, app) else { return };
    if items.is_empty() {
        totals.no_leftovers.push(app.name.clone());
        return;
    }
    let Some(choice) = review::show(owner, app, &items) else {
        return;
    };

    let mut keep = vec![false; items.len()];
    for &index in &choice.selected {
        if let Some(slot) = keep.get_mut(index) {
            *slot = true;
        }
    }
    let chosen: Vec<Leftover> = items
        .into_iter()
        .zip(keep)
        .filter_map(|(item, kept)| kept.then_some(item))
        .collect();
    if chosen.is_empty() {
        return;
    }
    let opts = CleanOptions {
        use_recycle_bin: choice.recycle,
        install_root,
    };
    match dialogs::run_with_progress(owner, TITLE, "Removing selected items...", false, move |_| {
        cleaner::clean(&chosen, &opts)
    }) {
        Some(report) => {
            audit::log(&format!(
                "clean {}: removed {}, failed {}, skipped {}",
                app.id,
                report.removed,
                report.failed.len(),
                report.skipped.len()
            ));
            totals.add(report);
        }
        None => dialogs::message_box(
            owner,
            TITLE,
            "Removing the selected items failed unexpectedly.",
            Icon::Error,
        ),
    }
}

fn scan(owner: HWND, app: &InstalledApp) -> Option<Vec<Leftover>> {
    let target = app.clone();
    let text = format!("Looking for leftovers of {}...", app.name);
    let found = dialogs::run_with_progress(owner, TITLE, &text, true, move |cancel| {
        leftovers::scan(&target, cancel, &|_: &str| {})
    });
    if found.is_none() {
        dialogs::message_box(
            owner,
            TITLE,
            &format!("Looking for leftovers of {} failed.", app.name),
            Icon::Error,
        );
    }
    found
}

/// Results of every clean run, combined for the final report.
#[derive(Default)]
struct Totals {
    /// Apps whose removal went through but had nothing left behind.
    no_leftovers: Vec<String>,
    /// Clean runs that completed (each produced a report).
    cleaned_runs: usize,
    removed: usize,
    freed: u64,
    backups: Vec<PathBuf>,
    failed: Vec<String>,
    skipped: Vec<String>,
    access_denied: bool,
}

impl Totals {
    fn add(&mut self, report: CleanReport) {
        self.cleaned_runs += 1;
        self.removed += report.removed;
        self.freed = self.freed.saturating_add(report.freed_bytes);
        self.backups.extend(report.registry_backup);
        for (path, reason) in report.failed {
            self.access_denied |= is_access_problem(&reason);
            self.failed.push(format!("Could not remove {path} ({reason})"));
        }
        self.skipped.extend(
            report
                .skipped
                .into_iter()
                .map(|(path, reason)| format!("Skipped {path} ({reason})")),
        );
    }
}

/// Final summary: one report for all clean runs, or a short note when nothing was left behind.
fn finish(owner: HWND, apps: &[InstalledApp], totals: &Totals) {
    if totals.cleaned_runs > 0 {
        show_report(owner, totals);
        return;
    }
    if totals.no_leftovers.is_empty() {
        return;
    }
    let text = match apps {
        [app] => format!("{} was removed. No leftovers found.", app.name),
        _ => format!(
            "No leftovers found for these programs:\n\n{}",
            join_capped(&bullets(&totals.no_leftovers), LIST_CAP)
        ),
    };
    dialogs::message_box(owner, TITLE, &text, Icon::Info);
}

fn show_report(owner: HWND, totals: &Totals) {
    let mut lines = Vec::new();
    if totals.freed > 0 {
        lines.push(format!("Freed {}", util::format_size(totals.freed)));
    }
    lines.extend(
        totals
            .backups
            .iter()
            .map(|path| format!("Registry backup saved to {}", path.display())),
    );
    if totals.access_denied && !security::is_elevated() {
        lines.push(ADMIN_HINT.to_owned());
    }
    let details: Vec<String> = totals.failed.iter().chain(&totals.skipped).cloned().collect();
    let icon = if details.is_empty() { Icon::Info } else { Icon::Warning };
    dialogs::report(
        owner,
        TITLE,
        &removed_headline(totals.removed),
        &lines.join("\n"),
        &join_capped(&details, DETAIL_CAP),
        icon,
    );
}

fn post_refresh(owner: HWND) {
    // SAFETY: posting a plain message; if the owner is gone the call simply fails.
    let _ = unsafe { PostMessageW(Some(owner), msg::WM_APP_REFRESH, WPARAM(0), LPARAM(0)) };
}

// ---------------------------------------------------------------------------
// Pure text helpers
// ---------------------------------------------------------------------------

/// Failure reasons that point at missing rights (offers "Run as administrator").
fn is_access_problem(reason: &str) -> bool {
    let reason = reason.to_ascii_lowercase();
    reason.contains("access") || reason.contains("denied")
}

fn removed_headline(removed: usize) -> String {
    match removed {
        0 => "Nothing was removed".to_owned(),
        1 => "Removed 1 item".to_owned(),
        n => format!("Removed {n} items"),
    }
}

/// One "- name" line per entry.
fn bullets(names: &[String]) -> Vec<String> {
    names.iter().map(|name| format!("- {name}")).collect()
}

/// Joins at most `cap` lines, then a "...and N more" line for the rest.
fn join_capped(lines: &[String], cap: usize) -> String {
    let mut shown: Vec<&str> = lines.iter().take(cap).map(String::as_str).collect();
    let more = format!("...and {} more", lines.len().saturating_sub(cap));
    if lines.len() > cap {
        shown.push(&more);
    }
    shown.join("\n")
}

/// Joins non-empty blocks with a blank line between them.
fn paragraphs(parts: &[String]) -> String {
    parts
        .iter()
        .filter(|part| !part.is_empty())
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capped_list_names_the_rest() {
        let names: Vec<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        assert_eq!(join_capped(&names, 2), "a\nb\n...and 1 more");
        assert_eq!(join_capped(&names, 3), "a\nb\nc");
        assert_eq!(join_capped(&names, 10), "a\nb\nc");
        assert_eq!(join_capped(&[], 4), "");
    }

    #[test]
    fn paragraphs_skip_empty_blocks() {
        let parts = vec!["one".to_owned(), String::new(), "two".to_owned()];
        assert_eq!(paragraphs(&parts), "one\n\ntwo");
        assert_eq!(paragraphs(&[String::new()]), "");
    }

    #[test]
    fn headline_uses_the_right_plural() {
        assert_eq!(removed_headline(0), "Nothing was removed");
        assert_eq!(removed_headline(1), "Removed 1 item");
        assert_eq!(removed_headline(7), "Removed 7 items");
    }

    #[test]
    fn access_problems_are_recognised() {
        assert!(is_access_problem("Access is denied. (os error 5)"));
        assert!(is_access_problem("Permission denied"));
        assert!(!is_access_problem("file is in use"));
    }

    #[test]
    fn bullets_prefix_each_name() {
        assert_eq!(bullets(&["A".to_owned(), "B".to_owned()]), vec!["- A", "- B"]);
    }
}
