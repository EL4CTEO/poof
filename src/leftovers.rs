//! Finds files, folders and registry entries an uninstaller left behind.
//!
//! Matching is conservative by design: only exact normalised name matches are pre-selected, only a
//! handful of known locations are looked at (one directory level each), and every candidate must pass
//! the `security` gates before it is returned, so the review list never offers what the cleaner refuses.

use std::collections::HashSet;
use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::command::{self, CommandError};
use crate::inventory;
use crate::model::{Hive, InstalledApp, RegLocation};
use crate::security::{self, known_dirs};
use crate::winreg::RegKey;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// Pre-selected in the review dialog (exact name/publisher match, or the install folder itself).
    High,
    /// Shown but NOT pre-selected.
    Medium,
}

#[derive(Clone, Debug)]
pub enum Target {
    Folder(PathBuf),
    File(PathBuf),
    RegKey(RegLocation),
    /// A single value inside a key (autostart entries).
    RegValue(RegLocation, String),
}

#[derive(Clone, Debug)]
pub struct Leftover {
    pub target: Target,
    pub confidence: Confidence,
    /// Short human reason, e.g. "Install folder", "Start Menu shortcut", "Autostart entry".
    pub reason: String,
    pub size_bytes: Option<u64>,
}

impl Leftover {
    /// Text shown in the UI list.
    pub fn display_path(&self) -> String {
        match &self.target {
            Target::Folder(p) | Target::File(p) => p.display().to_string(),
            Target::RegKey(k) => k.display(),
            Target::RegValue(k, v) => format!("{}  [{}]", k.display(), v),
        }
    }
    pub fn kind_label(&self) -> &'static str {
        match self.target {
            Target::Folder(_) => "Folder",
            Target::File(_) => "File",
            Target::RegKey(_) => "Registry key",
            Target::RegValue(..) => "Registry value",
        }
    }
}

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
/// Shortest name worth matching on; shorter ones collide with unrelated folders.
const MIN_NAME_CHARS: usize = 4;
/// Shortest strong name allowed to match a longer folder name as a whole word (Medium only).
const MIN_PARTIAL_CHARS: usize = 6;
/// Registry roots that hold per-program keys, as (hive, prefix).
const SOFTWARE_ROOTS: [(Hive, &str); 3] = [
    (Hive::CurrentUser, "Software"),
    (Hive::LocalMachine, "Software"),
    (Hive::LocalMachine, "Software\\WOW6432Node"),
];
/// Autostart keys below each software root.
const RUN_KEYS: [&str; 2] = [
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
];
/// Words too common to identify a product on their own.
const GENERIC_WORDS: &[&str] = &[
    "setup",
    "update",
    "updater",
    "installer",
    "windows",
    "microsoft",
    "app",
    "apps",
    "driver",
    "drivers",
    "tools",
    "software",
    "client",
    "launcher",
    "service",
    "runtime",
    "framework",
    "sdk",
    "library",
    "common",
    "shared",
    "system",
    "program",
    "programs",
    "data",
    "files",
    "packages",
    "temp",
    "cache",
    "logs",
    "assets",
    "plugins",
    "bin",
    "game",
    "games",
    "office",
    "adobe",
    "google",
    "uninstall",
    "uninstaller",
    "uninst",
    "unins",
    "remove",
    "msiexec",
    "rundll32",
    "unwise",
    "nsis",
    "inno",
    "wix",
    "x86",
    "x64",
    "portable",
    "default",
    "debug",
    "release",
    "test",
];
/// Legal-entity suffixes dropped from publisher names.
const PUBLISHER_SUFFIXES: &[&str] = &[
    "inc",
    "ltd",
    "llc",
    "corp",
    "corporation",
    "gmbh",
    "co",
    "limited",
    "software",
    "technologies",
    "the",
];

/// Scans for leftovers of `app`. Blocking; run on a worker thread. `progress` receives
/// short status lines. Honour `cancel`. Result is sorted: High before Medium, then by path.
pub fn scan(app: &InstalledApp, cancel: &AtomicBool, progress: &dyn Fn(&str)) -> Vec<Leftover> {
    let install_root = app
        .install_location
        .as_deref()
        .and_then(|p| security::validate_install_root(p).ok());
    let names = derived_names(app, install_root.as_deref());
    let derived: Vec<&str> = names.iter().map(String::as_str).collect();
    let install_trusted = install_root.as_deref().is_some_and(|root| install_folder_is_trusted(app, root));
    let mut scan = Scan {
        cancel,
        install_trusted,
        products: product_names(&app.name, &derived),
        publisher: publisher_names(&app.publisher),
        gate_roots: install_root.iter().cloned().collect(),
        install_root,
        found: Vec::new(),
        seen: HashSet::new(),
    };
    scan.collect(app.reg.as_ref(), progress);
    scan.finish(progress)
}

/// The install folder is pre-selected only with evidence it belongs to the app: it sits in a standard
/// per-program location, or the app's own uninstaller / icon path points inside it. `InstallLocation` is
/// untrusted registry data, so a bogus value must not get an arbitrary folder pre-checked.
/// (Raw strings are compared because the uninstaller executable is already gone after an uninstall.)
fn install_folder_is_trusted(app: &InstalledApp, root: &Path) -> bool {
    let k = known_dirs();
    if [&k.program_files, &k.program_files_x86, &k.local_programs].iter().any(|r| security::is_under_or_equal(root, r)) {
        return true;
    }
    let root_text = root.to_string_lossy().to_lowercase();
    [&app.uninstall_string, &app.quiet_uninstall_string, &app.icon_source]
        .into_iter()
        .flatten()
        .any(|text| text.to_lowercase().contains(&root_text))
}

/// Working state of one scan. Every candidate is gated before it is stored.
struct Scan<'a> {
    cancel: &'a AtomicBool,
    /// Whether the install folder shows evidence of belonging to the app (see `install_folder_is_trusted`).
    install_trusted: bool,
    products: Vec<Product>,
    publisher: Vec<String>,
    install_root: Option<PathBuf>,
    /// Extra deletion root for the gate: the validated install folder, if any.
    gate_roots: Vec<PathBuf>,
    found: Vec<Leftover>,
    seen: HashSet<String>,
}

impl Scan<'_> {
    fn collect(&mut self, registration: Option<&RegLocation>, progress: &dyn Fn(&str)) {
        if let Some(root) = self.install_root.clone() {
            let confidence = if self.install_trusted { Confidence::High } else { Confidence::Medium };
            self.push(Target::Folder(root), confidence, "Install folder");
        }
        progress("Looking for program folders...");
        self.scan_program_folders();
        if self.cancelled() {
            return;
        }
        progress("Checking Start Menu...");
        self.scan_start_menus();
        progress("Checking desktop shortcuts...");
        self.scan_desktops();
        if self.cancelled() {
            return;
        }
        progress("Checking registry...");
        self.scan_registry(registration);
        progress("Checking autostart entries...");
        self.scan_autostart();
    }

    fn finish(self, progress: &dyn Fn(&str)) -> Vec<Leftover> {
        let cancel = self.cancel;
        let mut found = drop_nested(self.found);
        progress("Measuring sizes...");
        for item in &mut found {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            item.size_bytes = size_of(&item.target, cancel);
        }
        found.sort_by_cached_key(|l| (l.confidence, l.display_path().to_lowercase()));
        found
    }

    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// Exact product match is High, unless the same name is also a vendor name.
    fn confidence(&self, strong: bool, name: &str) -> Confidence {
        if strong && !is_vendor(&self.publisher, name) {
            Confidence::High
        } else {
            Confidence::Medium
        }
    }

    fn allowed(&self, target: &Target) -> bool {
        match target {
            Target::Folder(p) | Target::File(p) => security::check_path_delete(p, &self.gate_roots).is_ok(),
            Target::RegKey(loc) => security::check_registry_delete(loc.hive, &loc.subkey).is_ok(),
            Target::RegValue(loc, name) => security::check_registry_value_delete(loc.hive, &loc.subkey, name).is_ok(),
        }
    }

    /// Adds a gated, de-duplicated candidate. Returns true when the target is listed afterwards.
    fn push(&mut self, target: Target, confidence: Confidence, reason: &str) -> bool {
        if !self.allowed(&target) {
            return false;
        }
        let leftover = Leftover {
            target,
            confidence,
            reason: reason.to_owned(),
            size_bytes: None,
        };
        if self.seen.insert(leftover.display_path().to_lowercase()) {
            self.found.push(leftover);
        }
        true
    }

    /// Program Files, ProgramData, AppData and friends: direct children and one level inside vendor folders.
    fn scan_program_folders(&mut self) {
        let k = known_dirs();
        let roots: [(&Path, &str); 6] = [
            (k.program_files.as_path(), "Program files"),
            (k.program_files_x86.as_path(), "Program files"),
            (k.program_data.as_path(), "Program data"),
            (k.local_app_data.as_path(), "Program data"),
            (k.local_programs.as_path(), "Program data"),
            (k.roaming_app_data.as_path(), "Program data"),
        ];
        for (root, reason) in roots {
            for entry in entries(root) {
                if self.cancelled() {
                    return;
                }
                if entry.is_dir && !entry.is_link {
                    self.check_program_folder(entry, reason);
                }
            }
        }
    }

    fn check_program_folder(&mut self, entry: Entry, reason: &str) {
        if let Some(strong) = product_hit(&self.products, &entry.name) {
            let conf = self.confidence(strong, &entry.name);
            self.push(Target::Folder(entry.path), conf, reason);
        } else if is_vendor(&self.publisher, &entry.name) {
            self.scan_vendor_folder(&entry.path, reason);
        } else if partial_hit(&self.products, &entry.name) {
            self.push(
                Target::Folder(entry.path),
                Confidence::Medium,
                "Possibly related folder",
            );
        }
    }

    /// A vendor folder: its product sub-folders are High; the vendor folder itself is Medium only when
    /// every one of its entries was a matched product folder (so it would be left empty).
    fn scan_vendor_folder(&mut self, dir: &Path, reason: &str) {
        let mut matched = 0usize;
        let mut all_matched = true;
        for child in entries(dir) {
            if self.cancelled() {
                return;
            }
            let strong = if child.is_dir && !child.is_link {
                product_hit(&self.products, &child.name)
            } else {
                None
            };
            match strong {
                Some(strong) => {
                    let conf = self.confidence(strong, &child.name);
                    if self.push(Target::Folder(child.path), conf, reason) {
                        matched += 1;
                    } else {
                        all_matched = false;
                    }
                }
                None => all_matched = false,
            }
        }
        if matched > 0 && all_matched {
            self.push(
                Target::Folder(dir.to_path_buf()),
                Confidence::Medium,
                "Vendor folder left empty",
            );
        }
    }

    fn scan_start_menus(&mut self) {
        let k = known_dirs();
        for root in [k.start_menu_user.as_path(), k.start_menu_common.as_path()] {
            for entry in entries(root) {
                if self.cancelled() {
                    return;
                }
                if entry.is_link {
                    continue;
                }
                let stem = if entry.is_dir {
                    Some(entry.name.as_str())
                } else {
                    stem_with_ext(&entry.name, &["lnk"])
                };
                let Some(stem) = stem else { continue };
                let Some(strong) = product_hit(&self.products, stem) else {
                    continue;
                };
                let conf = self.confidence(strong, stem);
                let target = if entry.is_dir {
                    Target::Folder(entry.path)
                } else {
                    Target::File(entry.path)
                };
                self.push(target, conf, "Start Menu shortcut");
            }
        }
    }

    fn scan_desktops(&mut self) {
        let k = known_dirs();
        for root in [k.desktop_user.as_path(), k.desktop_common.as_path()] {
            for entry in entries(root) {
                if self.cancelled() {
                    return;
                }
                if entry.is_dir || entry.is_link {
                    continue;
                }
                let Some(stem) = stem_with_ext(&entry.name, &["lnk", "url"]) else {
                    continue;
                };
                let Some(strong) = product_hit(&self.products, stem) else {
                    continue;
                };
                let conf = self.confidence(strong, stem);
                self.push(Target::File(entry.path), conf, "Desktop shortcut");
            }
        }
    }

    fn scan_registry(&mut self, registration: Option<&RegLocation>) {
        for (hive, prefix) in SOFTWARE_ROOTS {
            let Some(root) = RegKey::open(hive, prefix, false) else {
                continue;
            };
            for name in root.subkey_names() {
                if self.cancelled() {
                    return;
                }
                let subkey = format!("{prefix}\\{name}");
                if let Some(strong) = product_hit(&self.products, &name) {
                    let conf = self.confidence(strong, &name);
                    self.push(Target::RegKey(RegLocation { hive, subkey }), conf, "Registry settings");
                } else if is_vendor(&self.publisher, &name) {
                    self.scan_vendor_key(hive, &subkey);
                }
            }
        }
        if let Some(loc) = registration {
            if !self.cancelled() && RegKey::exists(loc.hive, &loc.subkey) {
                self.push(Target::RegKey(loc.clone()), Confidence::High, "Program registration");
            }
        }
    }

    /// Vendor registry key: product sub-keys are High; the vendor key itself is Medium only when it holds
    /// nothing but matched product keys and no values.
    fn scan_vendor_key(&mut self, hive: Hive, subkey: &str) {
        let Some(key) = RegKey::open(hive, subkey, false) else {
            return;
        };
        let (subkeys, values) = key.counts();
        let mut matched = 0u32;
        for child in key.subkey_names() {
            if self.cancelled() {
                return;
            }
            let Some(strong) = product_hit(&self.products, &child) else {
                continue;
            };
            let conf = self.confidence(strong, &child);
            let target = Target::RegKey(RegLocation {
                hive,
                subkey: format!("{subkey}\\{child}"),
            });
            if self.push(target, conf, "Registry settings") {
                matched += 1;
            }
        }
        if matched > 0 && subkeys == matched && values == 0 {
            self.push(
                Target::RegKey(RegLocation {
                    hive,
                    subkey: subkey.to_owned(),
                }),
                Confidence::Medium,
                "Vendor key left empty",
            );
        }
    }

    fn scan_autostart(&mut self) {
        for (hive, prefix) in SOFTWARE_ROOTS {
            for run in RUN_KEYS {
                if self.cancelled() {
                    return;
                }
                let subkey = format!("{prefix}\\{run}");
                let Some(key) = RegKey::open(hive, &subkey, false) else {
                    continue;
                };
                for name in key.value_names() {
                    if self.cancelled() {
                        return;
                    }
                    if let Some(command) = key.get_string(&name) {
                        self.scan_autostart_value(hive, &subkey, &name, &command);
                    }
                }
            }
        }
    }

    fn scan_autostart_value(&mut self, hive: Hive, subkey: &str, name: &str, command: &str) {
        let in_install = self
            .install_root
            .as_deref()
            .is_some_and(|root| command_mentions(command, root));
        let conf = if in_install {
            Confidence::High
        } else {
            let Some(strong) = product_hit(&self.products, name) else {
                return;
            };
            let missing = matches!(command::parse(command), Err(CommandError::NotFound(_)));
            if strong && missing {
                Confidence::High
            } else {
                Confidence::Medium
            }
        };
        let target = Target::RegValue(
            RegLocation {
                hive,
                subkey: subkey.to_owned(),
            },
            name.to_owned(),
        );
        self.push(target, conf, "Autostart entry");
    }
}

/// A normalised name that identifies the product. `strong` = exact display-name match, not generic.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Product {
    text: String,
    strong: bool,
}

/// Direct child of a scanned folder: names and attributes only, nothing is followed.
struct Entry {
    path: PathBuf,
    name: String,
    is_dir: bool,
    /// Symlink, junction or other reparse point. Never matched, never followed.
    is_link: bool,
}

/// Direct children of `dir`. Empty when it cannot be read.
fn entries(dir: &Path) -> Vec<Entry> {
    let Ok(read) = fs::read_dir(dir) else { return Vec::new() };
    read.flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let attrs = e.metadata().ok()?.file_attributes();
            Some(Entry {
                path: e.path(),
                name,
                is_dir: attrs & FILE_ATTRIBUTE_DIRECTORY != 0,
                is_link: attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0,
            })
        })
        .collect()
}

fn size_of(target: &Target, cancel: &AtomicBool) -> Option<u64> {
    match target {
        Target::Folder(p) => Some(inventory::dir_size(p, cancel)),
        Target::File(p) => fs::metadata(p).ok().map(|m| m.len()),
        Target::RegKey(_) | Target::RegValue(..) => None,
    }
}

// ---------------------------------------------------------------------------
// Name normalisation and matching (pure)
// ---------------------------------------------------------------------------

/// Names the uninstaller itself reveals: the install folder and the uninstaller executable.
fn derived_names(app: &InstalledApp, install_root: Option<&Path>) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(name) = install_root.and_then(Path::file_name) {
        names.push(name.to_string_lossy().into_owned());
    }
    let exe = app.uninstall_string.as_deref().and_then(|raw| command::parse(raw).ok());
    if let Some(stem) = exe.as_ref().and_then(|c| c.exe.file_stem()) {
        let stem = stem.to_string_lossy().into_owned();
        if !is_uninstaller_name(&stem) {
            names.push(stem);
        }
    }
    names
}

/// Generic uninstaller executables (`unins000.exe`, `uninstall.exe`) say nothing about the product.
fn is_uninstaller_name(stem: &str) -> bool {
    let lower = stem.to_lowercase();
    lower.starts_with("unins") || lower.starts_with("uninst")
}

/// Lower-cased name with version tokens, architecture tags and symbols removed and words joined by one space.
fn clean_name(name: &str) -> String {
    let lower = name.to_lowercase();
    let mut words: Vec<&str> = Vec::new();
    for token in lower.split_whitespace() {
        let token = token.trim_matches(|c: char| !c.is_alphanumeric() && c != '.');
        if token.is_empty() || is_version_token(token) {
            continue;
        }
        words.extend(token.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()));
    }
    words.join(" ")
}

/// `2.1.3`, `v5`, `(x64)`, `(64-bit)`, `x86`.
fn is_version_token(token: &str) -> bool {
    let t = token.trim_matches('.');
    let compact: String = t.chars().filter(|&c| c != '-').collect();
    if matches!(compact.as_str(), "x86" | "x64" | "amd64" | "ia64" | "32bit" | "64bit") {
        return true;
    }
    if let Some(rest) = t.strip_prefix('v') {
        if is_numeric_dotted(rest) {
            return true;
        }
    }
    t.contains('.') && is_numeric_dotted(t)
}

fn is_numeric_dotted(s: &str) -> bool {
    !s.is_empty()
        && s.split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}

/// Publisher name with legal suffixes (Inc, Ltd, Corporation...) removed.
fn clean_publisher(name: &str) -> String {
    name.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty() && !PUBLISHER_SUFFIXES.contains(w))
        .collect::<Vec<_>>()
        .join(" ")
}

fn squash(s: &str) -> String {
    s.replace(' ', "")
}

/// True when every word of `text` is a generic word.
fn is_generic(text: &str) -> bool {
    text.split(' ').all(|w| GENERIC_WORDS.contains(&w))
}

/// Product candidates from the display name plus names the uninstaller revealed. Generic or too short
/// candidates are dropped; a generic display name is kept but never strong (so never pre-selected).
fn product_names(display: &str, derived: &[&str]) -> Vec<Product> {
    let full = clean_name(display);
    let full_squashed = squash(&full);
    let candidates = std::iter::once(full.clone()).chain(derived.iter().map(|d| clean_name(d)));
    let mut out: Vec<Product> = Vec::new();
    for base in candidates {
        if base.is_empty() {
            continue;
        }
        let generic = is_generic(&base);
        let same_as_full = squash(&base) == full_squashed;
        if generic && !same_as_full {
            continue;
        }
        let strong = same_as_full && !generic;
        for text in [squash(&base), base] {
            if text.chars().count() < MIN_NAME_CHARS || out.iter().any(|p| p.text == text) {
                continue;
            }
            out.push(Product { text, strong });
        }
    }
    out
}

/// Publisher forms (spaced and squashed); empty when the publisher is unusable (too short or generic).
fn publisher_names(publisher: &str) -> Vec<String> {
    let text = clean_publisher(publisher);
    if text.chars().count() < MIN_NAME_CHARS || is_generic(&text) {
        return Vec::new();
    }
    let squashed = squash(&text);
    if squashed == text {
        vec![text]
    } else {
        vec![text, squashed]
    }
}

/// Exact match of a child name against the product candidates. Returns the candidate's strength.
fn product_hit(products: &[Product], name: &str) -> Option<bool> {
    let key = clean_name(name);
    let squashed = squash(&key);
    products
        .iter()
        .find(|p| p.text == key || p.text == squashed)
        .map(|p| p.strong)
}

/// A name that contains a strong product name as whole words, e.g. "Foo Bar Suite" for "Foo Bar".
fn partial_hit(products: &[Product], name: &str) -> bool {
    let key = format!(" {} ", clean_name(name));
    products
        .iter()
        .any(|p| p.strong && p.text.chars().count() >= MIN_PARTIAL_CHARS && key.contains(&format!(" {} ", p.text)))
}

fn is_vendor(publisher: &[String], name: &str) -> bool {
    let key = clean_publisher(name);
    if key.is_empty() {
        return false;
    }
    let squashed = squash(&key);
    publisher.iter().any(|p| *p == key || *p == squashed)
}

/// True when `command` contains `root` (case-insensitive) as a whole path, not as a prefix of a longer name.
fn command_mentions(command: &str, root: &Path) -> bool {
    let root = root.to_string_lossy().to_lowercase().replace('/', "\\");
    let hay = command.to_lowercase().replace('/', "\\");
    hay.match_indices(root.as_str()).any(|(i, _)| {
        let before_ok = hay[..i].chars().next_back().is_none_or(|c| !c.is_alphanumeric());
        let after_ok = hay[i + root.len()..]
            .chars()
            .next()
            .is_none_or(|c| matches!(c, '\\' | '/' | '"'));
        before_ok && after_ok
    })
}

/// `name` file stem when its extension is one of `exts` (case-insensitive).
fn stem_with_ext<'a>(name: &'a str, exts: &[&str]) -> Option<&'a str> {
    let path = Path::new(name);
    let ext = path.extension()?.to_str()?;
    if exts.iter().any(|e| e.eq_ignore_ascii_case(ext)) {
        path.file_stem()?.to_str()
    } else {
        None
    }
}

/// `child` equals `parent` or lies below it (registry key paths, case-insensitive, `\` boundary).
fn subkey_under(child: &str, parent: &str) -> bool {
    let (c, p) = (child.to_lowercase(), parent.to_lowercase());
    c == p || c.strip_prefix(&p).is_some_and(|rest| rest.starts_with('\\'))
}

/// True when `child` is `parent` or lies inside it.
fn is_nested(child: &Target, parent: &Target) -> bool {
    match (child, parent) {
        (Target::Folder(c) | Target::File(c), Target::Folder(p)) => security::is_under_or_equal(c, p),
        (Target::RegKey(c) | Target::RegValue(c, _), Target::RegKey(p)) => {
            c.hive == p.hive && subkey_under(&c.subkey, &p.subkey)
        }
        _ => false,
    }
}

/// Removes items that lie inside another High folder or key: that parent is removed as a unit.
fn drop_nested(found: Vec<Leftover>) -> Vec<Leftover> {
    let keep: Vec<bool> = (0..found.len())
        .map(|i| {
            !found.iter().enumerate().any(|(j, parent)| {
                j != i && parent.confidence == Confidence::High && is_nested(&found[i].target, &parent.target)
            })
        })
        .collect();
    found
        .into_iter()
        .zip(keep)
        .filter_map(|(l, k)| k.then_some(l))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_name_drops_versions_and_symbols() {
        assert_eq!(clean_name("Notepad++ (x64) 8.5.1"), "notepad");
        assert_eq!(clean_name("Visual Studio Code"), "visual studio code");
        assert_eq!(clean_name("Foo\u{2122} Bar v5"), "foo bar");
        assert_eq!(clean_name("7-Zip 23.01 (x64)"), "7 zip");
        assert_eq!(clean_name("Adobe Acrobat (64-bit)"), "adobe acrobat");
        assert_eq!(clean_name("AutoCAD 2024"), "autocad 2024");
        assert_eq!(
            clean_name("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.36.32532"),
            "microsoft visual c 2015 2022 redistributable"
        );
    }

    #[test]
    fn version_tokens() {
        for v in ["2.1.3", "v5", "x64", "64-bit", "32bit", "1.0"] {
            assert!(is_version_token(v), "{v}");
        }
        for w in ["2024", "7-zip", "vlc", "v", "c++", "2015-2022"] {
            assert!(!is_version_token(w), "{w}");
        }
    }

    #[test]
    fn publisher_suffixes_removed() {
        assert_eq!(clean_publisher("Dropbox, Inc."), "dropbox");
        assert_eq!(clean_publisher("The Foo Software Ltd"), "foo");
        assert_eq!(clean_publisher("Microsoft Corporation"), "microsoft");
        assert!(publisher_names("Microsoft Corporation").is_empty());
        assert!(publisher_names("Co.").is_empty());
        assert_eq!(
            publisher_names("Foo Bar Inc"),
            vec!["foo bar".to_owned(), "foobar".to_owned()]
        );
    }

    #[test]
    fn generic_detection() {
        assert!(is_generic("office"));
        assert!(is_generic("microsoft office"));
        assert!(!is_generic("google drive"));
        assert!(!is_generic("foo"));
    }

    #[test]
    fn short_and_generic_candidates_rejected() {
        assert!(product_names("Foo", &[]).is_empty());
        assert!(product_names("VLC", &["VLC"]).is_empty());
        // A derived generic word never becomes a candidate.
        assert!(
            product_names("Foo Bar Pro", &["bin", "setup"])
                .iter()
                .all(|p| p.text.contains("foo"))
        );
    }

    #[test]
    fn generic_display_name_is_weak() {
        let names = product_names("Google", &[]);
        assert!(!names.is_empty());
        assert!(names.iter().all(|p| !p.strong));
    }

    #[test]
    fn strong_candidates_from_display_name() {
        let names = product_names("Foo Bar Pro 2.0", &[]);
        assert!(names.iter().all(|p| p.strong));
        let texts: Vec<&str> = names.iter().map(|p| p.text.as_str()).collect();
        assert_eq!(texts, ["foobarpro", "foo bar pro"]);
    }

    #[test]
    fn derived_names_are_weak_unless_equal_to_name() {
        let names = product_names("Dropbox", &["Dropbox", "Community"]);
        assert!(names.iter().any(|p| p.text == "dropbox" && p.strong));
        assert!(names.iter().any(|p| p.text == "community" && !p.strong));
    }

    #[test]
    fn product_matching_is_exact_after_cleaning() {
        let products = product_names("Foo Bar", &[]);
        assert_eq!(product_hit(&products, "Foo Bar"), Some(true));
        assert_eq!(product_hit(&products, "FooBar"), Some(true));
        assert_eq!(product_hit(&products, "foo-bar 1.2.3"), Some(true));
        assert_eq!(product_hit(&products, "Foo Bar Suite"), None);
        assert_eq!(product_hit(&products, "Foo"), None);
    }

    #[test]
    fn partial_matching_needs_whole_words_and_length() {
        let products = product_names("Foo Bar", &[]);
        assert!(partial_hit(&products, "Foo Bar Suite"));
        assert!(partial_hit(&products, "FooBar Suite"));
        assert!(!partial_hit(&products, "Foo Barrel"));
        // "Ab Cd" is a valid strong name (5 chars) but too short to match inside a longer folder name.
        let short = product_names("Ab Cd", &[]);
        assert!(!partial_hit(&short, "Ab Cd Suite"));
    }

    #[test]
    fn vendor_matching() {
        let publisher = publisher_names("Dropbox, Inc.");
        assert!(is_vendor(&publisher, "Dropbox"));
        assert!(is_vendor(&publisher, "Dropbox Inc"));
        assert!(!is_vendor(&publisher, "Dropbox Sync"));
        assert!(!is_vendor(&[], "Dropbox"));
    }

    #[test]
    fn command_mentions_whole_root_only() {
        let root = Path::new("C:\\Program Files\\Foo");
        assert!(command_mentions("\"C:\\Program Files\\Foo\\foo.exe\" --tray", root));
        assert!(command_mentions("c:/program files/foo/foo.exe", root));
        assert!(!command_mentions("\"C:\\Program Files\\Foo Bar\\x.exe\"", root));
        assert!(!command_mentions("\"xC:\\Program Files\\Foo\\a.exe\"", root));
    }

    #[test]
    fn uninstaller_names_are_generic() {
        assert!(is_uninstaller_name("unins000"));
        assert!(is_uninstaller_name("Uninstall"));
        assert!(!is_uninstaller_name("foo"));
    }

    #[test]
    fn stem_extension_filter() {
        assert_eq!(stem_with_ext("Foo.lnk", &["lnk"]), Some("Foo"));
        assert_eq!(stem_with_ext("Foo.LNK", &["lnk"]), Some("Foo"));
        assert_eq!(stem_with_ext("Foo.txt", &["lnk"]), None);
        assert_eq!(stem_with_ext("Foo", &["lnk"]), None);
    }

    #[test]
    fn subkey_containment() {
        assert!(subkey_under("Software\\Foo\\Bar", "software\\foo"));
        assert!(subkey_under("Software\\Foo", "Software\\Foo"));
        assert!(!subkey_under("Software\\Foobar", "Software\\Foo"));
    }

    #[test]
    fn nested_items_are_dropped_under_high_parents() {
        let folder = |p: &str, c| Leftover {
            target: Target::Folder(PathBuf::from(p)),
            confidence: c,
            reason: String::new(),
            size_bytes: None,
        };
        let key = |s: &str, c| Leftover {
            target: Target::RegKey(RegLocation {
                hive: Hive::CurrentUser,
                subkey: s.to_owned(),
            }),
            confidence: c,
            reason: String::new(),
            size_bytes: None,
        };
        let value = Leftover {
            target: Target::RegValue(
                RegLocation {
                    hive: Hive::CurrentUser,
                    subkey: "Software\\Foo\\Run".into(),
                },
                "x".into(),
            ),
            confidence: Confidence::High,
            reason: String::new(),
            size_bytes: None,
        };
        let kept = drop_nested(vec![
            folder("C:\\Program Files\\Foo", Confidence::High),
            folder("C:\\Program Files\\Foo\\Sub", Confidence::Medium),
            folder("C:\\Program Files\\Foobar", Confidence::Medium),
            key("Software\\Foo", Confidence::High),
            key("Software\\Foo\\Child", Confidence::High),
            value,
        ]);
        let paths: Vec<String> = kept.iter().map(Leftover::display_path).collect();
        assert_eq!(paths.len(), 3, "{paths:?}");
        assert!(paths.contains(&"C:\\Program Files\\Foo".to_owned()));
        assert!(paths.contains(&"C:\\Program Files\\Foobar".to_owned()));
        assert!(paths.contains(&"HKCU\\Software\\Foo".to_owned()));
    }
}
