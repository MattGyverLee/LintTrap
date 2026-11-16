//! Where things live on this PC. The first run asks installed tools where they keep their caches
//! (rules with a `locate` command) and picks the drive that "move" items should go to.
//! Saved in %APPDATA%\LintTrap\locations.toml, so the built-in rules hold no machine-specific paths.

use crate::rules::{user_rules_path, Rule};
use crate::safety::Guard;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Locations {
    /// Drive for "move" items, e.g. "D:". None when no other drive has more free space than the system drive.
    #[serde(default)]
    pub move_to: Option<String>,
    /// Folders the tools reported, by rule id. Added to that rule's `paths`.
    #[serde(default)]
    pub paths: BTreeMap<String, Vec<String>>,
}

impl Locations {
    pub fn file() -> PathBuf {
        user_rules_path().with_file_name("locations.toml")
    }
    pub fn load() -> Option<Locations> {
        fs::read_to_string(Self::file()).ok().and_then(|t| toml::from_str(&t).ok())
    }
    /// The first run has not happened yet (an unreadable file is not rescanned, so hand edits are kept).
    pub fn first_run() -> bool {
        !Self::file().exists()
    }
    pub fn save(&self) -> std::io::Result<()> {
        let f = Self::file();
        if let Some(d) = f.parent() {
            fs::create_dir_all(d)?;
        }
        let body = toml::to_string_pretty(self).map_err(std::io::Error::other)?;
        fs::write(
            f,
            format!(
                "# Where things live on this PC, found by LintTrap's first run. Edit freely; delete this file\n\
                 # (or run `linttrap-cli locate`) to look again.\n\
                 # move_to  the drive \"move\" items should go to\n\
                 # [paths]  folders each tool reported, added to the rule with that id\n{body}"
            ),
        )
    }
    /// The saved locations, or a fresh scan (saved) on the first run. A file that cannot be read is
    /// left alone (it may hold the user's edits) and reported as a warning.
    pub fn load_or_scan(rules: &[Rule]) -> (Locations, Option<String>) {
        if Self::first_run() {
            let l = scan(rules);
            let _ = l.save();
            return (l, None);
        }
        let f = Self::file();
        match fs::read_to_string(&f).map_err(|e| e.to_string()).and_then(|t| toml::from_str(&t).map_err(|e| e.to_string())) {
            Ok(l) => (l, None),
            Err(e) => (Locations::default(), Some(format!("{} could not be read and was ignored: {e}", f.display()))),
        }
    }
    pub fn scan_and_save(rules: &[Rule]) -> std::io::Result<Locations> {
        let l = scan(rules);
        l.save()?;
        Ok(l)
    }
}

/// Ask each rule's `locate` command (when its program is installed) and pick the move drive.
pub fn scan(rules: &[Rule]) -> Locations {
    let guard = Guard::detect();
    let paths = rules
        .par_iter()
        .filter_map(|r| {
            let cmd = r.locate.as_deref()?;
            if !crate::sys::on_path(crate::sys::program_of(cmd)) {
                return None;
            }
            let out = crate::sys::query(cmd, Duration::from_secs(60))?;
            let found: Vec<String> = parse_paths(&out).into_iter().filter(|p| usable(p, &guard)).map(|p| p.display().to_string()).collect();
            (!found.is_empty()).then(|| (r.id.clone(), found))
        })
        .collect();
    Locations { move_to: move_target(&crate::sys::drives()), paths }
}

/// Folder paths in a tool's output, one per line: a bare path, a YAML list item ("  - D:\pkgs")
/// or a "name: path" line ("global-packages: C:\Users\me\.nuget\packages\").
pub fn parse_paths(out: &str) -> Vec<PathBuf> {
    out.lines()
        .filter_map(|l| {
            let l = l.trim();
            let l = l.strip_prefix("- ").unwrap_or(l);
            let p = if is_abs(l) { l } else { l.split_once(": ").map(|(_, v)| v.trim()).filter(|v| is_abs(v))? };
            let p = p.trim_end_matches('\\');
            Some(PathBuf::from(if p.len() == 2 { format!("{p}\\") } else { p.to_string() }))
        })
        .collect()
}

fn is_abs(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
}

/// An existing folder that is not a drive root, a link, or a protected or cloud-synced folder.
fn usable(p: &Path, guard: &Guard) -> bool {
    let Ok(md) = fs::symlink_metadata(p) else { return false };
    use std::os::windows::fs::MetadataExt;
    let depth = p.components().filter(|c| matches!(c, Component::Normal(_))).count();
    md.is_dir() && !crate::scan::is_link(md.file_attributes(), &md.file_type()) && depth >= 1 && p.parent().is_some_and(|parent| guard.check(p, parent).is_ok())
}

/// The fixed drive, other than the system drive, with the most free space, if it has more than the system drive.
pub fn move_target(drives: &[crate::sys::Drive]) -> Option<String> {
    let system = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    let name = |d: &crate::sys::Drive| d.root.trim_end_matches('\\').to_string();
    let system_free = drives.iter().find(|d| name(d).eq_ignore_ascii_case(&system)).map_or(0, |d| d.free);
    drives.iter().filter(|d| !name(d).eq_ignore_ascii_case(&system)).max_by_key(|d| d.free).filter(|d| d.free > system_free).map(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::Drive;

    #[test]
    fn parses_tool_output() {
        assert_eq!(parse_paths("C:\\Users\\me\\AppData\\Local\\uv\\cache\r\n"), vec![PathBuf::from(r"C:\Users\me\AppData\Local\uv\cache")]);
        assert_eq!(
            parse_paths("pkgs_dirs:\n  - D:\\Apps\\anaconda3\\pkgs\n  - C:\\Users\\me\\.conda\\pkgs\n"),
            vec![PathBuf::from(r"D:\Apps\anaconda3\pkgs"), PathBuf::from(r"C:\Users\me\.conda\pkgs")]
        );
        assert_eq!(parse_paths("global-packages: C:\\Users\\me\\.nuget\\packages\\\n"), vec![PathBuf::from(r"C:\Users\me\.nuget\packages")]);
        assert!(parse_paths("npm warn config cache is deprecated\nno path here: really\n").is_empty());
    }

    #[test]
    fn move_target_needs_more_free_space() {
        let d = |root: &str, free: u64| Drive { root: root.into(), total: 1000, free };
        let system = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        let other = if system.eq_ignore_ascii_case("D:") { "E:\\" } else { "D:\\" };
        let third = if system.eq_ignore_ascii_case("F:") { "G:\\" } else { "F:\\" };
        let sys_root = format!("{system}\\");
        assert_eq!(move_target(&[d(&sys_root, 100), d(other, 500), d(third, 300)]), Some(other.trim_end_matches('\\').to_string()));
        assert_eq!(move_target(&[d(&sys_root, 600), d(other, 500)]), None);
        assert_eq!(move_target(&[d(&sys_root, 100)]), None);
    }
}
