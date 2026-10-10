//! Safe parsing of `UninstallString` values into a directly spawnable command.
//!
//! No shell is ever involved. The executable is always resolved to an existing
//! absolute `.exe` on a local drive (or one of two allow-listed System32 tools),
//! so the classic unquoted-path hijack (`C:\Program.exe`) cannot happen: for
//! unquoted strings the *longest* existing prefix wins, never the shortest.

use std::path::{Path, PathBuf};

use crate::security::{self, SafetyError, known_dirs, normalize_lexical};
use crate::util::expand_env;

const MAX_COMMAND_LEN: usize = 8192;
/// Bare executable names we resolve (strictly inside System32, never PATH/CWD).
const SYSTEM_TOOLS: [&str; 2] = ["msiexec.exe", "rundll32.exe"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommand {
    pub exe: PathBuf,
    /// Arguments exactly as the vendor wrote them (already env-expanded).
    pub args: String,
}

impl ParsedCommand {
    /// Command line suitable for `CreateProcessW` (`"exe" args`).
    pub fn command_line(&self) -> String {
        if self.args.is_empty() {
            format!("\"{}\"", self.exe.display())
        } else {
            format!("\"{}\" {}", self.exe.display(), self.args)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandError {
    Invalid(String),
    /// Syntactically fine but the executable does not exist.
    NotFound(String),
    Unsafe(String),
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandError::Invalid(m) => write!(f, "invalid uninstall command: {m}"),
            CommandError::NotFound(p) => write!(f, "uninstaller not found: {p}"),
            CommandError::Unsafe(m) => write!(f, "uninstall command rejected: {m}"),
        }
    }
}
impl std::error::Error for CommandError {}

impl From<SafetyError> for CommandError {
    fn from(e: SafetyError) -> Self {
        CommandError::Unsafe(e.0)
    }
}

/// Parses with the real file system and environment.
pub fn parse(raw: &str) -> Result<ParsedCommand, CommandError> {
    let expanded = expand_env(raw.trim());
    parse_with(&expanded, &|p| p.is_file(), &known_dirs().system32)
}

/// Pure core (injectable file-existence check) so the logic is unit-testable.
pub fn parse_with(raw: &str, is_file: &dyn Fn(&Path) -> bool, system32: &Path) -> Result<ParsedCommand, CommandError> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_COMMAND_LEN {
        return Err(CommandError::Invalid("empty or too long".into()));
    }
    if raw.chars().any(|c| c.is_control()) {
        return Err(CommandError::Invalid("contains control characters".into()));
    }

    let (exe_text, args) = if let Some(rest) = raw.strip_prefix('"') {
        let Some(end) = rest.find('"') else {
            return Err(CommandError::Invalid("unterminated quote".into()));
        };
        (rest[..end].to_owned(), rest[end + 1..].trim().to_owned())
    } else {
        split_unquoted(raw, is_file, system32)?
    };

    let exe = resolve_exe(&exe_text, is_file, system32)?;
    Ok(ParsedCommand { exe, args })
}

/// Unquoted: pick the LONGEST prefix (cut at a space) that resolves to an existing exe.
fn split_unquoted(raw: &str, is_file: &dyn Fn(&Path) -> bool, system32: &Path) -> Result<(String, String), CommandError> {
    let mut cuts: Vec<usize> = raw.match_indices(' ').map(|(i, _)| i).collect();
    cuts.push(raw.len());
    for &cut in cuts.iter().rev() {
        let prefix = raw[..cut].trim_end();
        if prefix.is_empty() {
            continue;
        }
        if resolve_exe(prefix, is_file, system32).is_ok() {
            return Ok((prefix.to_owned(), raw[cut..].trim().to_owned()));
        }
    }
    // Nothing exists: report the most plausible candidate (first token).
    let first = raw.split(' ').next().unwrap_or(raw);
    Err(CommandError::NotFound(first.to_owned()))
}

fn resolve_exe(text: &str, is_file: &dyn Fn(&Path) -> bool, system32: &Path) -> Result<PathBuf, CommandError> {
    let text = text.trim();
    let has_sep = text.contains('\\') || text.contains('/') || text.contains(':');
    if !has_sep {
        let mut name = text.to_ascii_lowercase();
        if !name.ends_with(".exe") {
            name.push_str(".exe");
        }
        if !SYSTEM_TOOLS.contains(&name.as_str()) {
            return Err(CommandError::Unsafe(format!("'{text}' is not an absolute path")));
        }
        let p = system32.join(&name);
        return if is_file(&p) { Ok(p) } else { Err(CommandError::NotFound(p.display().to_string())) };
    }
    let norm = normalize_lexical(Path::new(text))?;
    let with_ext = |p: &Path| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe"));
    let candidate = if with_ext(&norm) { norm } else { PathBuf::from(format!("{}.exe", norm.display())) };
    if !with_ext(&candidate) {
        return Err(CommandError::Unsafe("only .exe uninstallers can be launched".into()));
    }
    if is_file(&candidate) { Ok(candidate) } else { Err(CommandError::NotFound(candidate.display().to_string())) }
}

/// `{8-4-4-4-12}` hexadecimal GUID, braces included.
pub fn is_guid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 38 || b[0] != b'{' || b[37] != b'}' {
        return false;
    }
    b[1..37].iter().enumerate().all(|(i, &c)| match i {
        8 | 13 | 18 | 23 => c == b'-',
        _ => c.is_ascii_hexdigit(),
    })
}

/// Finds a `{GUID}` inside strings such as `MsiExec.exe /X{GUID}`.
pub fn extract_msi_guid(s: &str) -> Option<String> {
    let start = s.find('{')?;
    let cand = s.get(start..start + 38)?;
    is_guid(cand).then(|| cand.to_ascii_uppercase())
}

/// True for strings that invoke Windows Installer (`msiexec`).
pub fn is_msiexec_command(s: &str) -> bool {
    s.to_ascii_lowercase().contains("msiexec")
}

/// Builds `msiexec.exe /x {GUID}` (+ `/qn /norestart` when quiet) from a validated GUID.
pub fn msi_uninstall_command(product_code: &str, quiet: bool) -> Result<ParsedCommand, CommandError> {
    if !is_guid(product_code) {
        return Err(CommandError::Invalid("bad MSI product code".into()));
    }
    let exe = known_dirs().system32.join("msiexec.exe");
    let args = if quiet { format!("/x {product_code} /qn /norestart") } else { format!("/x {product_code}") };
    Ok(ParsedCommand { exe, args })
}

/// Privilege-context rule. An elevated process must not run commands that a
/// standard user could have planted: per-user (HKCU) registrations are only
/// accepted when they point into admin-owned locations.
pub fn check_context(cmd: &ParsedCommand, from_user_hive: bool, elevated: bool) -> Result<(), SafetyError> {
    if !(elevated && from_user_hive) {
        return Ok(());
    }
    let k = known_dirs();
    let trusted = [&k.program_files, &k.program_files_x86, &k.windows];
    if trusted.iter().any(|d| security::is_under_or_equal(&cmd.exe, d)) {
        Ok(())
    } else {
        Err(SafetyError(
            "per-user programs must be uninstalled without administrator rights (restart the app normally)".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYS: &str = "C:\\Windows\\System32";

    fn fs(files: &'static [&'static str]) -> impl Fn(&Path) -> bool {
        move |p: &Path| files.iter().any(|f| f.eq_ignore_ascii_case(&p.to_string_lossy()))
    }

    #[test]
    fn quoted_with_args() {
        let f = fs(&["C:\\Program Files\\A\\unins000.exe"]);
        let c = parse_with("\"C:\\Program Files\\A\\unins000.exe\" /SILENT", &f, Path::new(SYS)).unwrap();
        assert_eq!(c.exe, PathBuf::from("C:\\Program Files\\A\\unins000.exe"));
        assert_eq!(c.args, "/SILENT");
    }

    #[test]
    fn unquoted_with_spaces_picks_longest_existing() {
        // An attacker-planted C:\Program.exe must NOT win over the real uninstaller.
        let f = fs(&["C:\\Program.exe", "C:\\Program Files\\A\\unins000.exe"]);
        let c = parse_with("C:\\Program Files\\A\\unins000.exe /S", &f, Path::new(SYS)).unwrap();
        assert_eq!(c.exe, PathBuf::from("C:\\Program Files\\A\\unins000.exe"));
        assert_eq!(c.args, "/S");
    }

    #[test]
    fn unquoted_without_extension() {
        let f = fs(&["C:\\Tools\\un.exe"]);
        let c = parse_with("C:\\Tools\\un /x", &f, Path::new(SYS)).unwrap();
        assert_eq!(c.exe, PathBuf::from("C:\\Tools\\un.exe"));
    }

    #[test]
    fn bare_names_only_from_system32() {
        let f = fs(&["C:\\Windows\\System32\\msiexec.exe"]);
        let c = parse_with("MsiExec.exe /X{11111111-2222-3333-4444-555555555555}", &f, Path::new(SYS)).unwrap();
        assert_eq!(c.exe, PathBuf::from("C:\\Windows\\System32\\msiexec.exe"));
        assert!(matches!(parse_with("evil.exe /x", &f, Path::new(SYS)), Err(CommandError::NotFound(_) | CommandError::Unsafe(_))));
        assert!(parse_with("cmd /c del x", &f, Path::new(SYS)).is_err());
    }

    #[test]
    fn rejects_dangerous_input() {
        let f = fs(&["C:\\a\\b.exe", "\\\\srv\\s\\x.exe"]);
        for bad in ["", "   ", "\"C:\\a\\b.exe", "C:\\a\\b.exe\u{0}", "C:\\a\\b.exe\r\nnet user", "\\\\srv\\s\\x.exe /s", "C:\\a\\..\\a\\b.exe"] {
            assert!(parse_with(bad, &f, Path::new(SYS)).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn non_exe_targets_rejected() {
        let f = fs(&["C:\\a\\run.bat", "C:\\a\\run.cmd", "C:\\a\\setup.msi"]);
        for bad in ["C:\\a\\run.bat", "\"C:\\a\\run.cmd\" /c", "C:\\a\\setup.msi /x"] {
            assert!(parse_with(bad, &f, Path::new(SYS)).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn missing_exe_is_not_found() {
        let f = fs(&[]);
        assert!(matches!(parse_with("\"C:\\gone\\u.exe\" /S", &f, Path::new(SYS)), Err(CommandError::NotFound(_))));
    }

    #[test]
    fn guid_helpers() {
        let g = "{0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9}";
        assert!(is_guid(g));
        assert!(!is_guid("{0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F}"));
        assert!(!is_guid("{0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8FZ}"));
        assert_eq!(extract_msi_guid(&format!("MsiExec.exe /X{g}")).as_deref(), Some(g));
        assert_eq!(extract_msi_guid("MsiExec.exe /X{bad}"), None);
        assert!(msi_uninstall_command(g, true).unwrap().args.ends_with("/qn /norestart"));
        assert!(msi_uninstall_command("{x}; calc", false).is_err());
    }

    #[test]
    fn command_line_is_quoted() {
        let c = ParsedCommand { exe: PathBuf::from("C:\\P F\\u.exe"), args: "/S".into() };
        assert_eq!(c.command_line(), "\"C:\\P F\\u.exe\" /S");
    }

    #[test]
    fn elevated_context_rule() {
        let user = ParsedCommand { exe: PathBuf::from("C:\\Users\\x\\AppData\\Local\\A\\u.exe"), args: String::new() };
        assert!(check_context(&user, true, true).is_err());
        assert!(check_context(&user, true, false).is_ok());
        assert!(check_context(&user, false, true).is_ok());
        let pf = ParsedCommand { exe: known_dirs().program_files.join("A\\u.exe"), args: String::new() };
        assert!(check_context(&pf, true, true).is_ok());
    }
}
