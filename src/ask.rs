//! Asking Claude about folders no rule covers. LintTrap finds large uncovered folders, describes them
//! (size, file types, ages, subfolders) and wraps that in a prompt whose answer is LintTrap rules.
//! The answer is checked with `linttrap-cli rules check` before it is used.

use crate::rules::{Dismissed, RuleResult, DEFAULT_RULES};
use crate::scan::{self, human, strip_prefix_ci, Kind, Progress, Tree};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// How far below a search root a folder is reported on its own (Vendor\App\Cache is 3).
const MAX_DEPTH: usize = 4;

/// Where unknown fluff usually lives: per-app data folders, plus the dot folders in the profile.
/// The bool says whether the root itself may be reported (a dot folder may; %APPDATA% may not).
pub fn search_roots() -> Vec<(PathBuf, bool)> {
    let env = |v: &str| std::env::var_os(v).filter(|s| !s.is_empty()).map(PathBuf::from);
    let mut roots: Vec<(PathBuf, bool)> = Vec::new();
    for v in ["LOCALAPPDATA", "APPDATA", "ProgramData"] {
        roots.extend(env(v).map(|p| (p, false)));
    }
    if let Some(home) = env("USERPROFILE") {
        roots.push((home.join("AppData").join("LocalLow"), false));
        if let Ok(rd) = fs::read_dir(&home) {
            for e in rd.flatten() {
                let (Ok(md), Ok(ft)) = (e.metadata(), e.file_type()) else { continue };
                if md.is_dir() && !scan::is_link(md.file_attributes(), &ft) && e.file_name().to_string_lossy().starts_with('.') {
                    roots.push((e.path(), true));
                }
            }
        }
    }
    roots.retain(|(p, _)| p.is_dir());
    roots
}

fn key(p: &Path) -> String {
    p.to_string_lossy().trim_end_matches('\\').to_lowercase()
}

/// Folders of at least `min` bytes that no rule found and the user has not dismissed, largest first.
/// A folder is reported as deep as it can be: when one subfolder holds most of it, that subfolder is reported.
pub fn unknown_folders(results: &[RuleResult], dismissed: &Dismissed, min: u64) -> Vec<(PathBuf, u64)> {
    let mut covered: HashSet<String> = HashSet::new();
    for r in results {
        covered.extend(r.found.iter().chain(&r.dismissed_paths).map(|p| key(p)));
        covered.extend(r.candidates.iter().map(|c| key(&c.path)));
    }
    covered.extend(dismissed.paths.iter().map(|p| key(Path::new(p))));
    // Every folder that has a covered folder somewhere below it.
    let mut above: HashSet<String> = HashSet::new();
    for c in &covered {
        let mut p = Path::new(c.as_str());
        while let Some(parent) = p.parent() {
            above.insert(key(parent));
            p = parent;
        }
    }
    let finder = Finder { covered, above, min };
    let mut out: Vec<(PathBuf, u64)> = search_roots()
        .par_iter()
        .flat_map(|(root, reportable)| {
            let tree = scan::scan(root, &Progress::default());
            let mut found = Vec::new();
            finder.visit(&tree, 0, root.clone(), if *reportable { 1 } else { 0 }, &mut found);
            found
        })
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1));
    out
}

struct Finder {
    covered: HashSet<String>,
    above: HashSet<String>,
    min: u64,
}

impl Finder {
    /// Returns (uncovered bytes in this subtree, bytes of it already reported).
    fn visit(&self, tree: &Tree, idx: u32, path: PathBuf, depth: usize, out: &mut Vec<(PathBuf, u64)>) -> (u64, u64) {
        let k = key(&path);
        if self.covered.contains(&k) {
            return (0, 0);
        }
        let node = &tree.nodes[idx as usize];
        if node.kind != Kind::Dir {
            return (node.size, 0);
        }
        let has_covered_below = self.above.contains(&k);
        if depth > MAX_DEPTH && !has_covered_below {
            return (node.size, 0);
        }
        let (mut total, mut reported) = (0u64, 0u64);
        for &c in &node.children {
            let child = &tree.nodes[c as usize];
            let (t, r) = if child.kind == Kind::Dir { self.visit(tree, c, path.join(&*child.name), depth + 1, out) } else { (child.size, 0) };
            total += t;
            reported += r;
        }
        if (1..=MAX_DEPTH).contains(&depth) && !node.unreadable && total - reported >= self.min {
            out.push((path, total));
            reported = total;
        }
        (total, reported)
    }
}

/// What a folder holds, for someone who has never seen it.
pub struct Profile {
    pub path: PathBuf,
    pub bytes: u64,
    pub files: u64,
    pub newest: i64,
    pub oldest: i64,
    /// Bytes per file extension, largest first.
    pub types: Vec<(String, u64)>,
    /// Immediate subfolders with their size, largest first.
    pub subfolders: Vec<(String, u64)>,
    /// Folders inside it that were left out (described on their own).
    pub skipped: Vec<PathBuf>,
}

#[derive(Default)]
struct Acc {
    bytes: u64,
    files: u64,
    newest: i64,
    oldest: i64,
    types: HashMap<String, u64>,
}

impl Acc {
    fn add_file(&mut self, p: &Path, md: &fs::Metadata) {
        self.bytes += md.len();
        self.files += 1;
        let t = scan::unix_secs(md);
        self.newest = self.newest.max(t);
        self.oldest = if self.oldest == 0 { t } else { self.oldest.min(t) };
        let ext = p.extension().map(|e| format!(".{}", e.to_string_lossy().to_lowercase())).unwrap_or_else(|| "(no extension)".into());
        *self.types.entry(ext).or_default() += md.len();
    }
    fn merge(&mut self, o: Acc) {
        self.bytes += o.bytes;
        self.files += o.files;
        self.newest = self.newest.max(o.newest);
        if o.oldest != 0 {
            self.oldest = if self.oldest == 0 { o.oldest } else { self.oldest.min(o.oldest) };
        }
        for (k, v) in o.types {
            *self.types.entry(k).or_default() += v;
        }
    }
}

/// Walk `dir` (never through links, never opening cloud placeholders, not into `skip`) into `acc`.
fn walk(dir: &Path, skip: &[PathBuf], acc: &mut Acc) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let (Ok(md), Ok(ft)) = (e.metadata(), e.file_type()) else { continue };
        let attrs = md.file_attributes();
        if scan::is_link(attrs, &ft) || scan::is_placeholder(attrs) {
            continue;
        }
        if md.is_dir() {
            let p = e.path();
            if !skip.iter().any(|s| key(s) == key(&p)) {
                walk(&p, skip, acc);
            }
        } else {
            acc.add_file(&e.path(), &md);
        }
    }
}

/// Describe `path`, leaving out the folders in `skip` that are inside it (those described on their own).
pub fn profile(path: &Path, skip: &[PathBuf]) -> Profile {
    let skip: Vec<PathBuf> = skip.iter().filter(|s| strip_prefix_ci(s, path).is_some_and(|r| !r.as_os_str().is_empty())).cloned().collect();
    let mut top = Acc::default();
    let mut dirs = Vec::new();
    if let Ok(rd) = fs::read_dir(path) {
        for e in rd.flatten() {
            let (Ok(md), Ok(ft)) = (e.metadata(), e.file_type()) else { continue };
            let attrs = md.file_attributes();
            if scan::is_link(attrs, &ft) || scan::is_placeholder(attrs) {
                continue;
            }
            if md.is_dir() {
                if !skip.iter().any(|s| key(s) == key(&e.path())) {
                    dirs.push(e.path());
                }
            } else {
                top.add_file(&e.path(), &md);
            }
        }
    }
    let subs: Vec<(String, Acc)> = dirs
        .par_iter()
        .map(|d| {
            let mut a = Acc::default();
            walk(d, &skip, &mut a);
            (d.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(), a)
        })
        .collect();
    let mut subfolders = Vec::new();
    for (name, a) in subs {
        subfolders.push((name, a.bytes));
        top.merge(a);
    }
    subfolders.sort_by(|a, b| b.1.cmp(&a.1));
    let mut types: Vec<(String, u64)> = top.types.into_iter().collect();
    types.sort_by(|a, b| b.1.cmp(&a.1));
    Profile { path: path.to_path_buf(), bytes: top.bytes, files: top.files, newest: top.newest, oldest: top.oldest, types, subfolders, skipped: skip }
}

/// The path written with %VARIABLES% instead of this PC's user name and folders, as rules use them.
pub fn pretty(path: &Path) -> String {
    for v in ["LOCALAPPDATA", "APPDATA", "ProgramData", "USERPROFILE", "ProgramFiles(x86)", "ProgramFiles", "SystemRoot"] {
        if let Some(base) = std::env::var_os(v).filter(|s| !s.is_empty()) {
            if let Some(rest) = strip_prefix_ci(path, Path::new(&base)) {
                let rest = rest.display().to_string();
                return if rest.is_empty() { format!("%{v}%") } else { format!("%{v}%\\{rest}") };
            }
        }
    }
    path.display().to_string()
}

fn age(t: i64) -> String {
    if t == 0 {
        return "unknown".into();
    }
    match (crate::rules::now_secs() - t).max(0) / 86_400 {
        0 => "today".into(),
        1 => "yesterday".into(),
        d if d < 60 => format!("{d} days ago"),
        d if d < 730 => format!("{} months ago", d / 30),
        d => format!("{} years ago", d / 365),
    }
}

/// A few lines about one folder.
pub fn describe(p: &Profile) -> String {
    let list = |items: &[(String, u64)]| items.iter().take(6).map(|(n, b)| format!("{n} {}", human(*b))).collect::<Vec<_>>().join(", ");
    let mut s = format!("### {}\n{} in {} files. Newest file changed {}, oldest {}.\n", pretty(&p.path), human(p.bytes), p.files, age(p.newest), age(p.oldest));
    if !p.types.is_empty() {
        s.push_str(&format!("File types: {}\n", list(&p.types)));
    }
    if !p.subfolders.is_empty() {
        let more = if p.subfolders.len() > 6 { format!(" (+{} more)", p.subfolders.len() - 6) } else { String::new() };
        s.push_str(&format!("Subfolders: {}{more}\n", list(&p.subfolders)));
    }
    if !p.skipped.is_empty() {
        let names: Vec<String> = p.skipped.iter().map(|x| pretty(x)).collect();
        s.push_str(&format!("Not counted here (described separately): {}\n", names.join(", ")));
    }
    s
}

/// The rule format: the comment block at the top of the built-in rules.
fn rule_format() -> String {
    DEFAULT_RULES.lines().take_while(|l| l.starts_with('#')).collect::<Vec<_>>().join("\n")
}

/// The full message to paste into Claude.
pub fn prompt(folders: &[Profile]) -> String {
    let body: Vec<String> = folders.iter().map(describe).collect();
    format!(
        "I use LintTrap, a Windows disk cleaner driven by rules. No LintTrap rule covers the folders below. \
For each one, tell me which program it belongs to and whether its contents can be deleted, then write LintTrap \
rules for the ones that are worth cleaning or moving.\n\n\
Guidelines:\n\
- safety = \"safe\" only when the program rebuilds the contents by itself and nothing is lost (caches, downloaded \
installers, old logs). \"review\" when it is probably junk but something could be lost (offline copies, old versions). \
\"move\" for real data that is just big. No rule when you are unsure; say so instead.\n\
- Never \"safe\" or \"review\" for documents, settings, saved games, databases, mail, or anything synced.\n\
- If the program has its own cleanup command, put it in `command` (with use_command = true if it runs without questions).\n\
- List the program's .exe names in `processes`, so LintTrap does not clean while it is running.\n\
- Write paths with the %VARIABLES% exactly as below; never use my user name.\n\
- Start every id with \"my-\" so it does not replace a built-in rule.\n\
- Put all the rules in one ```toml block, then say briefly how sure you are about each and what I should check first.\n\n\
The rule format (from LintTrap's built-in rules):\n\n```\n{}\n```\n\n\
The folders:\n\n{}",
        rule_format(),
        body.join("\n")
    )
}

/// The TOML in a reply from Claude: the contents of its ``` blocks, or the whole text when it has none.
pub fn extract_toml(reply: &str) -> String {
    if !reply.contains("```") {
        return reply.to_string();
    }
    let mut out = Vec::new();
    let mut inside = false;
    for line in reply.lines() {
        let t = line.trim_start();
        if t.starts_with("```") {
            inside = !inside;
            continue;
        }
        if inside {
            out.push(line);
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_toml_from_a_reply() {
        let reply = "Here you go:\n\n```toml\n[[rule]]\nid = \"my-x\"\n```\n\nI am fairly sure.";
        assert_eq!(extract_toml(reply), "[[rule]]\nid = \"my-x\"");
        assert_eq!(extract_toml("[[rule]]\nid = \"my-y\""), "[[rule]]\nid = \"my-y\"");
    }

    #[test]
    fn pretty_hides_the_user_folder() {
        let local = std::env::var("LOCALAPPDATA").unwrap();
        assert_eq!(pretty(&Path::new(&local).join(r"Foo\Cache")), r"%LOCALAPPDATA%\Foo\Cache");
        assert_eq!(pretty(Path::new(r"Q:\x")), r"Q:\x");
    }

    #[test]
    fn prompt_carries_the_rule_format() {
        let p = prompt(&[]);
        assert!(p.contains("#   safety"));
        assert!(p.contains("my-"));
    }

    #[test]
    fn finder_reports_the_deepest_big_folder_and_skips_covered_ones() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join(format!("linttrap-test-finder-{}", std::process::id()));
        let mb = vec![0u8; 1024 * 1024];
        for (dir, n) in [(r"App\Cache", 3), (r"App", 1), (r"Known\Stuff", 3), (r"Small", 1)] {
            fs::create_dir_all(root.join(dir)).unwrap();
            for i in 0..n {
                fs::write(root.join(dir).join(format!("f{i}.bin")), &mb).unwrap();
            }
        }
        let covered: HashSet<String> = [key(&root.join("Known"))].into();
        let mut above = HashSet::new();
        let mut p = root.join("Known");
        while let Some(parent) = p.parent().map(Path::to_path_buf) {
            above.insert(key(&parent));
            p = parent;
        }
        let finder = Finder { covered, above, min: 2 * 1024 * 1024 };
        let tree = scan::scan(&root, &Progress::default());
        let mut out = Vec::new();
        finder.visit(&tree, 0, root.clone(), 0, &mut out);
        let _ = fs::remove_dir_all(&root);
        // App\Cache (3 MB) is reported; App's own 1 MB is below the threshold; Known is covered; Small is small.
        assert_eq!(out.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>(), vec![root.join(r"App\Cache")]);
    }
}
