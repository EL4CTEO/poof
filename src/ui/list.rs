//! Program list: the model (filter, search, sort, cell text, lazy icons) and the virtual ListView plumbing.
//! Everything above the "ListView" section is pure and unit tested.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::fmt::Write as _;
use std::path::Path;

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_NORMAL, FILE_FLAGS_AND_ATTRIBUTES};
use windows::Win32::UI::Controls::{
    HDF_SORTDOWN, HDF_SORTUP, HDI_FORMAT, HDITEMW, HDM_GETITEMW, HDM_SETITEMW, HEADER_CONTROL_FORMAT_FLAGS,
    LIST_VIEW_ITEM_STATE_FLAGS, LVCF_FMT, LVCF_SUBITEM, LVCF_TEXT, LVCF_WIDTH, LVCFMT_LEFT, LVCFMT_RIGHT, LVCOLUMNW,
    LVIF_IMAGE, LVIF_STATE, LVIF_TEXT, LVIS_SELECTED, LVITEMW, LVM_ENSUREVISIBLE, LVM_GETCOLUMNWIDTH, LVM_GETHEADER,
    LVM_GETITEMSTATE, LVM_GETNEXTITEM, LVM_GETSELECTEDCOUNT, LVM_INSERTCOLUMNW, LVM_REDRAWITEMS, LVM_SETCOLUMNWIDTH,
    LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETIMAGELIST, LVM_SETITEMCOUNT, LVM_SETITEMSTATE, LVNI_SELECTED,
    LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT, LVS_EX_HEADERDRAGDROP, LVSICF_NOSCROLL, LVSIL_SMALL, NMLVDISPINFOW,
};
use windows::Win32::UI::Shell::{
    SHFILEINFOW, SHGFI_SMALLICON, SHGFI_SYSICONINDEX, SHGFI_USEFILEATTRIBUTES, SHGSI_SMALLICON, SHGSI_SYSICONINDEX,
    SHGetFileInfoW, SHGetStockIconInfo, SHSTOCKICONINFO, SIID_APPLICATION,
};
use windows::Win32::UI::WindowsAndMessaging::SendMessageW;
use windows::core::{PCWSTR, PWSTR, w};

use crate::model::{AppKind, Health, InstalledApp};
use crate::security::normalize_lexical;
use crate::ui::theme::scale;
use crate::util::{format_size, path_to_wide, to_wide};

/// Programs at least this big (known size) match the "Large" filter.
pub const LARGE_BYTES: u64 = 500 * 1024 * 1024;
/// "Recently installed" covers this many days (plus one day of clock slack).
pub const RECENT_DAYS: i64 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Column {
    Name,
    Publisher,
    Version,
    Size,
    Installed,
}

impl Column {
    pub const ALL: [Column; 5] = [Column::Name, Column::Publisher, Column::Version, Column::Size, Column::Installed];

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|&c| c == self).unwrap_or(0)
    }

    pub fn from_index(i: i32) -> Option<Column> {
        usize::try_from(i).ok().and_then(|i| Self::ALL.get(i).copied())
    }

    pub fn title(self) -> &'static str {
        match self {
            Column::Name => "Name",
            Column::Publisher => "Publisher",
            Column::Version => "Version",
            Column::Size => "Size",
            Column::Installed => "Installed",
        }
    }

    /// Width in pixels at 96 dpi.
    pub fn base_width(self) -> i32 {
        match self {
            Column::Name => 340,
            Column::Publisher => 200,
            Column::Version => 110,
            Column::Size => 90,
            Column::Installed => 100,
        }
    }

    fn right_aligned(self) -> bool {
        self == Column::Size
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Filter {
    #[default]
    All,
    Programs,
    Store,
    Large,
    Recent,
    Attention,
}

impl Filter {
    pub const ALL: [Filter; 6] =
        [Filter::All, Filter::Programs, Filter::Store, Filter::Large, Filter::Recent, Filter::Attention];

    pub fn label(self) -> &'static str {
        match self {
            Filter::All => "All",
            Filter::Programs => "Programs",
            Filter::Store => "Store apps",
            Filter::Large => "Large (500 MB+)",
            Filter::Recent => "Recently installed",
            Filter::Attention => "Needs attention",
        }
    }

    pub fn from_index(i: usize) -> Filter {
        Self::ALL.get(i).copied().unwrap_or_default()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sort {
    pub column: Column,
    pub descending: bool,
}

impl Default for Sort {
    fn default() -> Self {
        Sort { column: Column::Name, descending: false }
    }
}

impl Sort {
    /// Clicking the active column flips the direction; a new column starts ascending.
    pub fn click(self, column: Column) -> Sort {
        if column == self.column {
            Sort { descending: !self.descending, ..self }
        } else {
            Sort { column, descending: false }
        }
    }
}

// ---------------------------------------------------------------------------
// Pure logic
// ---------------------------------------------------------------------------

/// Case-insensitive text order without allocating.
pub fn cmp_text(a: &str, b: &str) -> Ordering {
    a.chars().flat_map(char::to_lowercase).cmp(b.chars().flat_map(char::to_lowercase))
}

/// Ascending order for one column. Ties fall back to the name so the order is predictable.
pub fn compare(a: &InstalledApp, b: &InstalledApp, column: Column) -> Ordering {
    let by_name = || cmp_text(&a.name, &b.name);
    match column {
        Column::Name => by_name(),
        Column::Publisher => cmp_text(&a.publisher, &b.publisher).then_with(by_name),
        Column::Version => cmp_text(&a.version, &b.version).then_with(by_name),
        Column::Size => a.size_bytes.unwrap_or(0).cmp(&b.size_bytes.unwrap_or(0)).then_with(by_name),
        Column::Installed => a.install_date.cmp(&b.install_date).then_with(by_name),
    }
}

/// Days since 1970-01-01 (proleptic Gregorian, valid for any year).
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Day number of a `yyyymmdd` install date, or `None` for "unknown" (0) and invalid dates.
pub fn install_days(date: u32) -> Option<i64> {
    let (y, m, d) = (i64::from(date / 10_000), i64::from(date / 100 % 100), i64::from(date % 100));
    (y >= 1 && (1..=12).contains(&m) && (1..=31).contains(&d)).then(|| days_from_civil(y, m, d))
}

/// `yyyymmdd` -> `yyyy-mm-dd`; empty when unknown.
pub fn format_date(date: u32) -> String {
    if install_days(date).is_none() {
        return String::new();
    }
    format!("{:04}-{:02}-{:02}", date / 10_000, date / 100 % 100, date % 100)
}

/// Day number of an audit timestamp (`YYYY-MM-DD HH:MM:SS`).
pub fn timestamp_days(ts: &str) -> Option<i64> {
    let y: i64 = ts.get(0..4)?.parse().ok()?;
    let m: i64 = ts.get(5..7)?.parse().ok()?;
    let d: i64 = ts.get(8..10)?.parse().ok()?;
    Some(days_from_civil(y, m, d))
}

/// True when the install happened within [`RECENT_DAYS`] of `today` (a day number).
pub fn is_recent(date: u32, today: i64) -> bool {
    install_days(date).is_some_and(|d| (-1..=RECENT_DAYS).contains(&(today - d)))
}

pub fn passes(app: &InstalledApp, filter: Filter, today: i64) -> bool {
    match filter {
        Filter::All => true,
        Filter::Programs => app.kind == AppKind::Win32,
        Filter::Store => app.kind == AppKind::Store,
        Filter::Large => app.size_bytes.is_some_and(|bytes| bytes >= LARGE_BYTES),
        Filter::Recent => is_recent(app.install_date, today),
        Filter::Attention => app.health != Health::Ok,
    }
}

/// Lower-cased whitespace-separated search terms.
pub fn search_terms(query: &str) -> Vec<String> {
    query.split_whitespace().map(str::to_lowercase).collect()
}

/// Every term must appear in the (already lower-cased) haystack.
pub fn matches_terms(haystack: &str, terms: &[String]) -> bool {
    terms.iter().all(|term| haystack.contains(term.as_str()))
}

/// Text shown in one cell.
pub fn cell_text(app: &InstalledApp, column: Column) -> Cow<'_, str> {
    match column {
        Column::Name => Cow::Borrowed(&app.name),
        Column::Publisher if app.publisher.is_empty() && app.is_store() => Cow::Borrowed("(Store)"),
        Column::Publisher => Cow::Borrowed(&app.publisher),
        Column::Version => Cow::Borrowed(&app.version),
        Column::Size => Cow::Owned(app.size_bytes.map(format_size).unwrap_or_default()),
        Column::Installed => Cow::Owned(format_date(app.install_date)),
    }
}

/// RFC 3986 percent-encoding of the UTF-8 bytes (unreserved characters are kept).
pub fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 3);
    for b in text.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(char::from(b)),
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Web search for "<name> <publisher>".
pub fn search_url(name: &str, publisher: &str) -> String {
    let query = format!("{} {}", name.trim(), publisher.trim());
    format!("https://www.google.com/search?q={}", percent_encode(query.trim()))
}

/// The file part of a `DisplayIcon` value: `"C:\app\app.exe",0` -> `C:\app\app.exe`.
pub fn icon_file(raw: &str) -> &str {
    let s = raw.trim();
    if let Some(quoted) = s.strip_prefix('"') {
        return quoted.split('"').next().unwrap_or_default();
    }
    match s.rsplit_once(',') {
        Some((file, index)) if index.trim().trim_start_matches('-').bytes().all(|b| b.is_ascii_digit()) => {
            file.trim_end()
        }
        _ => s,
    }
}

/// Plain-text report of the given programs (clipboard "Copy details").
pub fn details_text(apps: &[InstalledApp]) -> String {
    apps.iter()
        .map(|app| {
            let location = app.install_location.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
            format!(
                "Name: {}\r\nPublisher: {}\r\nVersion: {}\r\nLocation: {}",
                app.name, app.publisher, app.version, location
            )
        })
        .collect::<Vec<_>>()
        .join("\r\n\r\n")
}

// ---------------------------------------------------------------------------
// Icons (shared system image list)
// ---------------------------------------------------------------------------

/// Fallback icon indices into the system small-icon list.
#[derive(Clone, Copy, Debug, Default)]
pub struct Icons {
    generic_exe: i32,
    store: i32,
}

impl Icons {
    /// Attaches the system small-icon list to `list` (never destroyed by us) and resolves the fallbacks.
    fn attach(list: HWND) -> Icons {
        let mut info = SHFILEINFOW::default();
        // SAFETY: SHGFI_USEFILEATTRIBUTES never touches the disk; `info` is a valid out-buffer.
        let himl = unsafe {
            SHGetFileInfoW(
                w!(".exe"),
                FILE_ATTRIBUTE_NORMAL,
                Some(&mut info),
                size_of::<SHFILEINFOW>() as u32,
                SHGFI_USEFILEATTRIBUTES | SHGFI_SYSICONINDEX | SHGFI_SMALLICON,
            )
        };
        if himl != 0 {
            // SAFETY: `himl` is the shared system image list; the control only reads it.
            unsafe {
                SendMessageW(list, LVM_SETIMAGELIST, Some(WPARAM(LVSIL_SMALL as usize)), Some(LPARAM(himl as isize)));
            }
        }
        let mut stock = SHSTOCKICONINFO { cbSize: size_of::<SHSTOCKICONINFO>() as u32, ..Default::default() };
        // SAFETY: `stock` is a correctly sized out-struct.
        let store = if unsafe { SHGetStockIconInfo(SIID_APPLICATION, SHGSI_SYSICONINDEX | SHGSI_SMALLICON, &mut stock) }
            .is_ok()
        {
            stock.iSysImageIndex
        } else {
            info.iIcon
        };
        Icons { generic_exe: info.iIcon, store }
    }

    /// Image index for one app: its own file icon when the path is acceptable, else a generic icon.
    fn for_app(&self, app: &InstalledApp) -> i32 {
        let own = app
            .icon_source
            .as_deref()
            .map(icon_file)
            .filter(|s| !s.is_empty())
            .and_then(|s| normalize_lexical(Path::new(s)).ok())
            .and_then(|path| system_icon_index(&path));
        own.unwrap_or(if app.is_store() { self.store } else { self.generic_exe })
    }
}

fn system_icon_index(path: &Path) -> Option<i32> {
    let wide = path_to_wide(path);
    let mut info = SHFILEINFOW::default();
    // SAFETY: NUL-terminated path and a valid out-buffer; the call only reads the file's icon index.
    let ok = unsafe {
        SHGetFileInfoW(
            PCWSTR(wide.as_ptr()),
            FILE_FLAGS_AND_ATTRIBUTES(0),
            Some(&mut info),
            size_of::<SHFILEINFOW>() as u32,
            SHGFI_SYSICONINDEX | SHGFI_SMALLICON,
        )
    } != 0;
    ok.then_some(info.iIcon)
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// Every program of the last scan plus the filtered and sorted view the list displays.
/// The view holds indices into `apps`; list rows are view positions.
#[derive(Default)]
pub struct Model {
    apps: Vec<InstalledApp>,
    haystacks: Vec<String>,
    index: HashMap<String, usize>,
    icons: Vec<i32>,
    view: Vec<usize>,
    pub filter: Filter,
    pub sort: Sort,
    terms: Vec<String>,
}

impl Model {
    /// Replaces the data with a new scan. Call [`Model::rebuild`] afterwards.
    pub fn replace(&mut self, apps: Vec<InstalledApp>, haystacks: Vec<String>) {
        self.index = apps.iter().enumerate().map(|(i, app)| (app.id.clone(), i)).collect();
        self.icons = vec![-1; apps.len()];
        self.apps = apps;
        self.haystacks = haystacks;
    }

    pub fn apps(&self) -> &[InstalledApp] {
        &self.apps
    }

    /// Number of rows in the current view.
    pub fn count(&self) -> usize {
        self.view.len()
    }

    pub fn set_query(&mut self, query: &str) {
        self.terms = search_terms(query);
    }

    pub fn toggle_sort(&mut self, column: Column) {
        self.sort = self.sort.click(column);
    }

    /// Recomputes the view: filter, then search, then sort (stable).
    pub fn rebuild(&mut self, today: i64) {
        let (apps, haystacks, terms) = (&self.apps, &self.haystacks, &self.terms);
        let filter = self.filter;
        let view = &mut self.view;
        view.clear();
        view.extend(
            (0..apps.len()).filter(|&i| {
                passes(&apps[i], filter, today) && haystacks.get(i).is_some_and(|h| matches_terms(h, terms))
            }),
        );
        let Sort { column, descending } = self.sort;
        view.sort_by(|&x, &y| {
            let ord = compare(&apps[x], &apps[y], column);
            if descending { ord.reverse() } else { ord }
        });
    }

    pub fn app_at(&self, pos: usize) -> Option<&InstalledApp> {
        self.view.get(pos).and_then(|&i| self.apps.get(i))
    }

    pub fn id_at(&self, pos: usize) -> Option<&str> {
        self.app_at(pos).map(|app| app.id.as_str())
    }

    /// View positions whose app id is in `ids`.
    pub fn positions_of(&self, ids: &HashSet<String>) -> Vec<usize> {
        if ids.is_empty() {
            return Vec::new();
        }
        self.view
            .iter()
            .enumerate()
            .filter(|&(_, &i)| self.apps.get(i).is_some_and(|app| ids.contains(&app.id)))
            .map(|(pos, _)| pos)
            .collect()
    }

    pub fn selected_apps(&self, positions: &[usize]) -> Vec<InstalledApp> {
        positions.iter().filter_map(|&pos| self.app_at(pos)).cloned().collect()
    }

    pub fn visible_apps(&self) -> Vec<InstalledApp> {
        self.view.iter().filter_map(|&i| self.apps.get(i)).cloned().collect()
    }

    /// Sum of the known sizes in the view.
    pub fn total_bytes(&self) -> u64 {
        self.view.iter().filter_map(|&i| self.apps.get(i)?.size_bytes).sum()
    }

    /// Stores a measured size. Returns the view position when the app is currently listed.
    pub fn set_size(&mut self, id: &str, bytes: u64) -> Option<usize> {
        let &idx = self.index.get(id)?;
        self.apps.get_mut(idx)?.size_bytes = Some(bytes);
        self.view.iter().position(|&i| i == idx)
    }

    /// Icon index of the row at `pos`, resolved once per app and cached.
    pub fn icon(&mut self, pos: usize, icons: &Icons) -> i32 {
        let Some(&idx) = self.view.get(pos) else { return icons.generic_exe };
        match self.icons.get(idx).copied() {
            Some(cached) if cached >= 0 => cached,
            _ => {
                let resolved = self.apps.get(idx).map_or(icons.generic_exe, |app| icons.for_app(app));
                if let Some(slot) = self.icons.get_mut(idx) {
                    *slot = resolved;
                }
                resolved
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ListView plumbing
// ---------------------------------------------------------------------------

/// One-time configuration of the ListView: extended styles, columns and the shared image list.
pub fn configure(list: HWND, dpi: u32) -> Icons {
    let style = LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT | LVS_EX_HEADERDRAGDROP;
    // SAFETY: `list` is a live ListView owned by this thread; the extended style is applied to the mask bits.
    unsafe {
        SendMessageW(list, LVM_SETEXTENDEDLISTVIEWSTYLE, Some(WPARAM(style as usize)), Some(LPARAM(style as isize)));
    }
    for column in Column::ALL {
        insert_column(list, column, dpi);
    }
    Icons::attach(list)
}

fn insert_column(list: HWND, column: Column, dpi: u32) {
    let mut title = to_wide(column.title());
    let item = LVCOLUMNW {
        mask: LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_FMT,
        fmt: if column.right_aligned() { LVCFMT_RIGHT } else { LVCFMT_LEFT },
        cx: scale(column.base_width(), dpi),
        pszText: PWSTR(title.as_mut_ptr()),
        iSubItem: column.index() as i32,
        ..Default::default()
    };
    // SAFETY: `item` and the title buffer outlive the call; the control copies the text.
    unsafe {
        SendMessageW(list, LVM_INSERTCOLUMNW, Some(WPARAM(column.index())), Some(LPARAM(&item as *const _ as isize)));
    }
}

/// Sets the virtual row count. `LVSICF_NOSCROLL` keeps the current scroll position.
pub fn set_count(list: HWND, count: usize) {
    // SAFETY: plain message to a live ListView.
    unsafe {
        SendMessageW(list, LVM_SETITEMCOUNT, Some(WPARAM(count)), Some(LPARAM(LVSICF_NOSCROLL as isize)));
    }
}

/// View positions of the selected rows.
pub fn selected_positions(list: HWND) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from: isize = -1;
    loop {
        // SAFETY: plain query to a live ListView; `from` is passed as the (signed) start index.
        let next = unsafe {
            SendMessageW(list, LVM_GETNEXTITEM, Some(WPARAM(from as usize)), Some(LPARAM(LVNI_SELECTED as isize)))
        }
        .0 as isize;
        if next <= from {
            break;
        }
        out.push(next as usize);
        from = next;
    }
    out
}

pub fn selected_count(list: HWND) -> usize {
    // SAFETY: plain query to a live ListView.
    let count = unsafe { SendMessageW(list, LVM_GETSELECTEDCOUNT, None, None) }.0;
    usize::try_from(count).unwrap_or(0)
}

pub fn is_selected(list: HWND, pos: usize) -> bool {
    // SAFETY: plain query to a live ListView.
    let state =
        unsafe { SendMessageW(list, LVM_GETITEMSTATE, Some(WPARAM(pos)), Some(LPARAM(LVIS_SELECTED.0 as isize))).0 };
    state as u32 & LVIS_SELECTED.0 != 0
}

/// Selects (`on`) or clears one row; `index` = -1 means every row.
fn set_item_selected(list: HWND, index: isize, on: bool) {
    let item = LVITEMW {
        mask: LVIF_STATE,
        state: if on { LVIS_SELECTED } else { LIST_VIEW_ITEM_STATE_FLAGS(0) },
        stateMask: LVIS_SELECTED,
        ..Default::default()
    };
    // SAFETY: `item` outlives the call; a -1 index applies to all rows as documented.
    unsafe {
        SendMessageW(list, LVM_SETITEMSTATE, Some(WPARAM(index as usize)), Some(LPARAM(&item as *const _ as isize)));
    }
}

pub fn set_all_selected(list: HWND, on: bool) {
    set_item_selected(list, -1, on);
}

pub fn set_selected(list: HWND, pos: usize, on: bool) {
    set_item_selected(list, pos as isize, on);
}

/// Selects exactly one row and scrolls it into view.
pub fn select_only(list: HWND, pos: usize) {
    set_all_selected(list, false);
    set_selected(list, pos, true);
    // SAFETY: plain message to a live ListView.
    unsafe {
        SendMessageW(list, LVM_ENSUREVISIBLE, Some(WPARAM(pos)), Some(LPARAM(0)));
    }
}

pub fn redraw_item(list: HWND, pos: usize) {
    // SAFETY: plain message to a live ListView.
    unsafe {
        SendMessageW(list, LVM_REDRAWITEMS, Some(WPARAM(pos)), Some(LPARAM(pos as isize)));
    }
}

fn header_of(list: HWND) -> HWND {
    // SAFETY: plain query; the header is owned by the ListView.
    let raw = unsafe { SendMessageW(list, LVM_GETHEADER, None, None) }.0;
    HWND(raw as *mut c_void)
}

/// Shows the sort direction arrow on the active column header.
pub fn update_sort_arrows(list: HWND, sort: Sort) {
    let header = header_of(list);
    let arrows = HDF_SORTUP.0 | HDF_SORTDOWN.0;
    for column in Column::ALL {
        let mut item = HDITEMW { mask: HDI_FORMAT, ..Default::default() };
        let index = WPARAM(column.index());
        // SAFETY: `item` is a valid HDITEMW that the header fills in.
        unsafe {
            SendMessageW(header, HDM_GETITEMW, Some(index), Some(LPARAM(&mut item as *mut _ as isize)));
        }
        let arrow = match (column == sort.column, sort.descending) {
            (false, _) => 0,
            (true, false) => HDF_SORTUP.0,
            (true, true) => HDF_SORTDOWN.0,
        };
        item.fmt = HEADER_CONTROL_FORMAT_FLAGS((item.fmt.0 & !arrows) | arrow);
        // SAFETY: as above.
        unsafe {
            SendMessageW(header, HDM_SETITEMW, Some(index), Some(LPARAM(&item as *const _ as isize)));
        }
    }
}

fn column_width(list: HWND, index: usize) -> i32 {
    // SAFETY: plain query to a live ListView.
    unsafe { SendMessageW(list, LVM_GETCOLUMNWIDTH, Some(WPARAM(index)), None) }.0 as i32
}

/// Moves every column width from `from_dpi` to `to_dpi`, keeping any width the user chose.
pub fn rescale_columns(list: HWND, from_dpi: u32, to_dpi: u32) {
    for column in Column::ALL {
        let index = column.index();
        let width = i64::from(column_width(list, index));
        let scaled = width * i64::from(to_dpi) / i64::from(from_dpi.max(1));
        // SAFETY: plain message to a live ListView.
        unsafe {
            SendMessageW(list, LVM_SETCOLUMNWIDTH, Some(WPARAM(index)), Some(LPARAM(scaled as isize)));
        }
    }
}

/// Answers `LVN_GETDISPINFOW`: text for the requested sub-item and the (cached) icon.
pub fn fill_dispinfo(model: &mut Model, icons: &Icons, info: &mut NMLVDISPINFOW) {
    let item = &mut info.item;
    let Ok(pos) = usize::try_from(item.iItem) else { return };
    if item.mask.0 & LVIF_IMAGE.0 != 0 {
        item.iImage = model.icon(pos, icons);
    }
    if item.mask.0 & LVIF_TEXT.0 != 0 {
        if let (Some(app), Some(column)) = (model.app_at(pos), Column::from_index(item.iSubItem)) {
            write_text(item.pszText, item.cchTextMax, &cell_text(app, column));
        }
    }
}

/// Copies `text` into a control-owned buffer of `capacity` UTF-16 units, always NUL-terminated.
fn write_text(dst: PWSTR, capacity: i32, text: &str) {
    let Ok(cap) = usize::try_from(capacity) else { return };
    if dst.0.is_null() || cap == 0 {
        return;
    }
    let units: Vec<u16> = text.encode_utf16().take(cap - 1).collect();
    // SAFETY: during LVN_GETDISPINFO the control guarantees `cchTextMax` writable units at `pszText`.
    unsafe {
        let buf = std::slice::from_raw_parts_mut(dst.0, cap);
        buf[..units.len()].copy_from_slice(&units);
        buf[units.len()] = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(name: &str, publisher: &str, kind: AppKind) -> InstalledApp {
        InstalledApp {
            id: format!("win32:HKLM\\{name}"),
            kind,
            name: name.into(),
            publisher: publisher.into(),
            version: String::new(),
            install_date: 0,
            install_location: None,
            size_bytes: None,
            icon_source: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            msi_product_code: None,
            help_link: None,
            reg: None,
            package_full_name: None,
            health: Health::Ok,
        }
    }

    fn with_size(mut a: InstalledApp, bytes: u64) -> InstalledApp {
        a.size_bytes = Some(bytes);
        a
    }

    fn with_date(mut a: InstalledApp, date: u32) -> InstalledApp {
        a.install_date = date;
        a
    }

    fn haystack(a: &InstalledApp) -> String {
        a.haystack()
    }

    const TODAY: i64 = 20_000; // arbitrary day number for filter tests

    #[test]
    fn text_compare_is_case_insensitive() {
        assert_eq!(cmp_text("apple", "APPLE"), Ordering::Equal);
        assert_eq!(cmp_text("Banana", "apple"), Ordering::Greater);
        assert_eq!(cmp_text("", "a"), Ordering::Less);
    }

    #[test]
    fn size_sort_treats_unknown_as_zero_and_ties_by_name() {
        let a = app("Zed", "", AppKind::Win32);
        let b = with_size(app("Alpha", "", AppKind::Win32), 10);
        assert_eq!(compare(&a, &b, Column::Size), Ordering::Less);
        let c = app("Beta", "", AppKind::Win32);
        assert_eq!(compare(&c, &a, Column::Size), Ordering::Less);
    }

    #[test]
    fn model_sorts_filters_and_searches() {
        let apps = vec![
            with_size(app("Photo Editor", "Acme", AppKind::Win32), 600 * 1024 * 1024),
            app("store thing", "", AppKind::Store),
            app("Zip Tool", "Acme", AppKind::Win32),
        ];
        let haystacks = apps.iter().map(haystack).collect();
        let mut model = Model::default();
        model.replace(apps, haystacks);
        model.rebuild(TODAY);
        let names = |m: &Model| -> Vec<String> { m.view.iter().map(|&i| m.apps[i].name.clone()).collect() };
        assert_eq!(names(&model), ["Photo Editor", "store thing", "Zip Tool"]);

        model.filter = Filter::Store;
        model.rebuild(TODAY);
        assert_eq!(names(&model), ["store thing"]);

        model.filter = Filter::Large;
        model.rebuild(TODAY);
        assert_eq!(names(&model), ["Photo Editor"]);

        model.filter = Filter::All;
        model.set_query("  ACME   zip ");
        model.rebuild(TODAY);
        assert_eq!(names(&model), ["Zip Tool"]);

        model.set_query("");
        model.toggle_sort(Column::Name);
        model.rebuild(TODAY);
        assert_eq!(names(&model), ["Zip Tool", "store thing", "Photo Editor"]);
    }

    #[test]
    fn filter_recent_and_attention() {
        let today = days_from_civil(2026, 10, 10);
        let recent = with_date(app("New", "", AppKind::Win32), 20_261_001);
        let old = with_date(app("Old", "", AppKind::Win32), 20_250_101);
        assert!(passes(&recent, Filter::Recent, today));
        assert!(!passes(&old, Filter::Recent, today));
        assert!(!passes(&app("Unknown", "", AppKind::Win32), Filter::Recent, today));

        let mut broken = app("Broken", "", AppKind::Win32);
        broken.health = Health::UninstallerMissing;
        assert!(passes(&broken, Filter::Attention, today));
        assert!(!passes(&app("Fine", "", AppKind::Win32), Filter::Attention, today));
    }

    #[test]
    fn search_requires_every_term() {
        let hay = haystack(&app("Photo Editor", "Acme Labs", AppKind::Win32));
        assert!(matches_terms(&hay, &search_terms("photo acme")));
        assert!(!matches_terms(&hay, &search_terms("photo zip")));
        assert!(matches_terms(&hay, &search_terms("   ")));
    }

    #[test]
    fn dates_format_and_validate() {
        assert_eq!(format_date(20_250_131), "2025-01-31");
        assert_eq!(format_date(0), "");
        assert_eq!(format_date(20_251_345), "");
        assert_eq!(format_date(20_250_100), "");
    }

    #[test]
    fn civil_day_numbers() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(timestamp_days("2026-10-10 23:59:59"), Some(days_from_civil(2026, 10, 10)));
        assert_eq!(timestamp_days("garbage"), None);
    }

    #[test]
    fn cell_text_for_store_publisher() {
        let store = app("Calc", "", AppKind::Store);
        assert_eq!(cell_text(&store, Column::Publisher), "(Store)");
        let win = app("Tool", "", AppKind::Win32);
        assert_eq!(cell_text(&win, Column::Publisher), "");
        assert_eq!(cell_text(&with_size(win, 1536), Column::Size), "1.50 KB");
    }

    #[test]
    fn percent_encoding_and_search_url() {
        assert_eq!(percent_encode("a b&c"), "a%20b%26c");
        assert_eq!(percent_encode("é"), "%C3%A9");
        assert_eq!(percent_encode("A-z_0.~"), "A-z_0.~");
        assert_eq!(search_url("Foo Bar", "Acme"), "https://www.google.com/search?q=Foo%20Bar%20Acme");
        assert_eq!(search_url("Foo", "  "), "https://www.google.com/search?q=Foo");
    }

    #[test]
    fn display_icon_file_part() {
        assert_eq!(icon_file("\"C:\\a b\\x.exe\",0"), "C:\\a b\\x.exe");
        assert_eq!(icon_file("C:\\x.exe,-5"), "C:\\x.exe");
        assert_eq!(icon_file("C:\\x.exe"), "C:\\x.exe");
        assert_eq!(icon_file("C:\\a,b\\x.exe"), "C:\\a,b\\x.exe");
    }

    #[test]
    fn details_report_lines() {
        let mut a = app("Tool", "Acme", AppKind::Win32);
        a.version = "1.2".into();
        let text = details_text(&[a]);
        assert_eq!(text, "Name: Tool\r\nPublisher: Acme\r\nVersion: 1.2\r\nLocation: ");
        assert_eq!(details_text(&[]), "");
    }

    #[test]
    fn write_text_truncates_and_terminates() {
        let mut buf = [7u16; 4];
        write_text(PWSTR(buf.as_mut_ptr()), 4, "abcdef");
        assert_eq!(buf, [u16::from(b'a'), u16::from(b'b'), u16::from(b'c'), 0]);
        let mut small = [7u16; 2];
        write_text(PWSTR(small.as_mut_ptr()), 2, "xyz");
        assert_eq!(small, [u16::from(b'x'), 0]);
    }

    #[test]
    fn sort_click_toggles_and_resets() {
        let s = Sort::default().click(Column::Name);
        assert!(s.descending);
        let s = s.click(Column::Size);
        assert_eq!(s, Sort { column: Column::Size, descending: false });
    }

    #[test]
    fn set_size_reports_view_position() {
        let apps = vec![app("A", "", AppKind::Win32), app("B", "", AppKind::Win32)];
        let haystacks = apps.iter().map(haystack).collect();
        let mut model = Model::default();
        model.replace(apps, haystacks);
        model.set_query("b");
        model.rebuild(TODAY);
        assert_eq!(model.set_size("win32:HKLM\\B", 9), Some(0));
        assert_eq!(model.set_size("win32:HKLM\\A", 9), None);
        assert_eq!(model.set_size("missing", 9), None);
        assert_eq!(model.total_bytes(), 9);
    }
}
