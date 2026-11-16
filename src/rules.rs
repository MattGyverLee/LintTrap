//! Rule loading and evaluation. Evaluation only measures; it never deletes.

use crate::safety;
use crate::scan::{is_link, is_placeholder, unix_secs};
use rayon::prelude::*;
use serde::Deserialize;
use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const DEFAULT_RULES: &str = include_str!("../rules/default_rules.toml");

#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Safety {
    Safe,
    Review,
    Move,
    Info,
}

/// The drive "move" items should go to (from locations.toml), set by `load_rules`.
static MOVE_TO: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

impl Safety {
    pub fn label(self) -> String {
        match self {
            Safety::Safe => "Safe".into(),
            Safety::Review => "Review".into(),
            Safety::Move => match MOVE_TO.read().ok().and_then(|m| m.clone()) {
                Some(d) => format!("Move to {d}"),
                None => format!("Move off {}", std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into())),
            },
            Safety::Info => "Leave alone".into(),
        }
    }
    pub fn tag(self) -> &'static str {
        match self {
            Safety::Safe => "safe",
            Safety::Review => "review",
            Safety::Move => "move",
            Safety::Info => "info",
        }
    }
}

#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Contents,
    Whole,
    Versions,
    /// Older versions of third-party drivers, removed with pnputil.
    Drivers,
    None,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub safety: Safety,
    pub action: Action,
    pub paths: Vec<String>,
    #[serde(default)]
    pub min_age_days: Option<u32>,
    #[serde(default)]
    pub keep: Option<usize>,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub processes: Vec<String>,
    #[serde(default)]
    pub admin: bool,
    #[serde(default)]
    pub command: Option<String>,
    /// Clean by running `command` instead of deleting files (when its program is installed).
    #[serde(default)]
    pub use_command: bool,
    /// Run `command` once inside each found path (pnpm picks its store by the current drive).
    #[serde(default)]
    pub per_path: bool,
    #[serde(default)]
    pub prevent: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    /// A command that prints where the tool keeps this folder; asked once, saved in locations.toml.
    #[serde(default)]
    pub locate: Option<String>,
    /// Only paths whose folder also holds an entry with this name (GPUCache marks a Chromium profile).
    #[serde(default)]
    pub beside: Option<String>,
    /// Only paths no other rule found: a general rule that picks up what the specific ones miss.
    #[serde(default)]
    pub catch_all: bool,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

impl Rule {
    pub fn can_clean(&self) -> bool {
        let how = self.action != Action::None || (self.use_command && self.command.is_some());
        how && matches!(self.safety, Safety::Safe | Safety::Review)
    }
    pub fn cutoff(&self) -> Option<i64> {
        self.min_age_days.filter(|d| *d > 0).map(|d| now_secs() - d as i64 * 86_400)
    }
}

#[derive(Deserialize)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<Rule>,
}

/// Rules in TOML (`[[rule]]` tables), e.g. pasted from a reply.
pub fn parse_rules(text: &str) -> Result<Vec<Rule>, String> {
    toml::from_str::<RuleFile>(text).map(|f| f.rule).map_err(|e| e.to_string())
}

/// The ids of the built-in rules.
pub fn builtin_ids() -> Vec<String> {
    parse_rules(DEFAULT_RULES).map(|r| r.into_iter().map(|r| r.id).collect()).unwrap_or_default()
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------- history

/// Below this much growth since its last command clean, a rule counts as "nothing new".
pub const FRESH_BYTES: u64 = 100 * 1024 * 1024;

/// One run of a rule's tool command: when, and the measured size before and after.
#[derive(serde::Serialize, Deserialize, Clone, Copy, Debug, Default)]
pub struct LastRun {
    pub at: i64,
    pub before: u64,
    pub after: u64,
}

/// When each rule's tool command last ran. Stored in %APPDATA%\LintTrap\history.toml.
/// After a prune (pnpm, conda, DISM) what is left is in use, so later only the growth counts.
#[derive(serde::Serialize, Deserialize, Default, Clone, Debug)]
pub struct History {
    #[serde(default)]
    pub runs: std::collections::BTreeMap<String, LastRun>,
}

impl History {
    pub fn file() -> PathBuf {
        user_rules_path().with_file_name("history.toml")
    }
    pub fn load() -> History {
        fs::read_to_string(Self::file()).ok().and_then(|t| toml::from_str(&t).ok()).unwrap_or_default()
    }
    /// Record a finished run now (re-reads the file so concurrent records are not lost).
    pub fn record(id: &str, before: u64, after: u64) {
        let mut h = Self::load();
        h.runs.insert(id.to_string(), LastRun { at: now_secs(), before, after });
        let f = Self::file();
        if let Some(d) = f.parent() {
            let _ = fs::create_dir_all(d);
        }
        if let Ok(body) = toml::to_string_pretty(&h) {
            let _ = fs::write(f, format!("# When each rule's tool command last ran (sizes in bytes).\n{body}"));
        }
    }
}

/// "today", "yesterday", "5 days ago".
pub fn ago(at: i64) -> String {
    let today = now_secs() / 86_400;
    match today - at / 86_400 {
        d if d <= 0 => "today".into(),
        1 => "yesterday".into(),
        d => format!("{d} days ago"),
    }
}

/// Total size of several paths.
pub fn measure_all(paths: &[PathBuf]) -> u64 {
    paths.iter().map(|p| measure(p, None).0).sum()
}

// ---------------------------------------------------------------- dismissals

/// False positives the user has dismissed: whole rules, or single paths.
/// Stored in %APPDATA%\LintTrap\dismissed.toml and honoured by the GUI and the CLI.
#[derive(serde::Serialize, Deserialize, Default, Clone, Debug)]
pub struct Dismissed {
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
}

impl Dismissed {
    pub fn file() -> PathBuf {
        user_rules_path().with_file_name("dismissed.toml")
    }
    pub fn load() -> Dismissed {
        fs::read_to_string(Self::file()).ok().and_then(|t| toml::from_str(&t).ok()).unwrap_or_default()
    }
    pub fn save(&self) -> std::io::Result<()> {
        let f = Self::file();
        if let Some(d) = f.parent() {
            fs::create_dir_all(d)?;
        }
        let body = toml::to_string_pretty(self).map_err(std::io::Error::other)?;
        fs::write(f, format!("# Items LintTrap should stop flagging. Delete a line to bring it back.\n{body}"))
    }
    pub fn has_rule(&self, id: &str) -> bool {
        self.rules.iter().any(|r| r == id)
    }
    /// True when `p` is a dismissed path or inside one.
    pub fn has_path(&self, p: &Path) -> bool {
        self.paths.iter().any(|d| crate::scan::strip_prefix_ci(p, Path::new(d)).is_some())
    }
    pub fn toggle_rule(&mut self, id: &str) {
        if self.has_rule(id) {
            self.rules.retain(|r| r != id);
        } else {
            self.rules.push(id.to_string());
        }
    }
    pub fn add_path(&mut self, p: &Path) {
        let s = p.display().to_string();
        if !self.paths.iter().any(|d| d.eq_ignore_ascii_case(&s)) {
            self.paths.push(s);
        }
    }
    pub fn remove_path(&mut self, s: &str) {
        self.paths.retain(|d| !d.eq_ignore_ascii_case(s));
    }
}

pub fn user_rules_path() -> PathBuf {
    let base = std::env::var_os("APPDATA").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    base.join("LintTrap").join("rules.toml")
}

/// Built-in rules merged with the user's overrides and placed with this PC's locations
/// (found on the first run). Returns the rules and any warnings.
pub fn load_rules() -> (Vec<Rule>, Vec<String>) {
    let (mut rules, mut warnings) = merged_rules();
    let (loc, warning) = crate::locate::Locations::load_or_scan(&rules);
    warnings.extend(warning);
    apply_locations(&mut rules, &loc);
    (rules, warnings)
}

/// Add the folders the tools reported and fill in the move drive (`%MOVE_TO%` in title, note, prevent).
/// Without a move drive, a `prevent` that needs one is dropped.
pub fn apply_locations(rules: &mut [Rule], loc: &crate::locate::Locations) {
    let to = loc.move_to.as_deref().map(str::trim).filter(|d| !d.is_empty());
    if let Ok(mut m) = MOVE_TO.write() {
        *m = to.map(String::from);
    }
    for r in rules {
        if let Some(extra) = loc.paths.get(&r.id) {
            r.paths.extend(extra.iter().cloned());
        }
        if to.is_none() && r.prevent.as_deref().is_some_and(|p| p.contains("%MOVE_TO%")) {
            r.prevent = None;
        }
        for s in [Some(&mut r.title), r.note.as_mut(), r.prevent.as_mut()].into_iter().flatten() {
            *s = s.replace("%MOVE_TO%", to.unwrap_or("another drive"));
        }
    }
}

/// Built-in rules merged with the user's overrides, enabled ones only, before `apply_locations`.
pub fn merged_rules() -> (Vec<Rule>, Vec<String>) {
    let mut warnings = Vec::new();
    let mut rules: Vec<Rule> = toml::from_str::<RuleFile>(DEFAULT_RULES).expect("built-in rules must parse").rule;
    let user = user_rules_path();
    if let Ok(text) = fs::read_to_string(&user) {
        match toml::from_str::<RuleFile>(&text) {
            Ok(f) => {
                for r in f.rule {
                    if let Some(existing) = rules.iter_mut().find(|e| e.id == r.id) {
                        *existing = r;
                    } else {
                        rules.push(r);
                    }
                }
            }
            Err(e) => warnings.push(format!("{} could not be read and was ignored: {e}", user.display())),
        }
    }
    rules.retain(|r| r.enabled);
    (rules, warnings)
}

/// Write a starter user rules file (if missing) plus a copy of the built-in rules for reference.
pub fn ensure_user_rules_file() -> std::io::Result<PathBuf> {
    let p = user_rules_path();
    if let Some(dir) = p.parent() {
        fs::create_dir_all(dir)?;
        fs::write(dir.join("rules.builtin.toml"), DEFAULT_RULES)?;
    }
    if !p.exists() {
        fs::write(
            &p,
            "# Your LintTrap rules. See rules.builtin.toml next to this file for the format and the built-in list.\n\
             # A rule with the same id as a built-in one replaces it. To turn a built-in rule off:\n\
             #\n\
             # [[rule]]\n# id = \"browser-cache\"\n# title = \"Browser caches\"\n# safety = \"safe\"\n# action = \"none\"\n# paths = []\n# enabled = false\n",
        )?;
    }
    Ok(p)
}

// ---------------------------------------------------------------- path expansion

/// Expand %VAR% references. Unknown variables are left as-is (and then simply won't exist).
pub fn expand_env(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if let Some(end) = after.find('%') {
            let name = &after[..end];
            match std::env::var(name) {
                Ok(v) if !name.is_empty() => out.push_str(&v),
                _ => {
                    out.push('%');
                    out.push_str(name);
                    out.push('%');
                }
            }
            rest = &after[end + 1..];
        } else {
            out.push_str(&rest[start..]);
            rest = "";
        }
    }
    out.push_str(rest);
    out
}

/// Case-insensitive wildcard match supporting * and ?.
pub fn wildcard(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let (mut pi, mut ti, mut star, mut mark) = (0usize, 0usize, usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = ti;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Expand env vars and wildcards into the existing paths a rule pattern refers to.
/// A first segment of `*:` means every fixed drive. Wildcard segments never descend through symlinks or junctions.
pub fn resolve(pattern: &str) -> Vec<PathBuf> {
    let expanded = expand_env(pattern);
    if expanded.contains('%') {
        return Vec::new();
    }
    let mut segs = expanded.split('\\').filter(|s| !s.is_empty());
    let Some(first) = segs.next() else { return Vec::new() };
    let mut current: Vec<PathBuf> =
        if first == "*:" { crate::sys::drives().into_iter().map(|d| PathBuf::from(d.root)).collect() } else { vec![PathBuf::from(format!("{first}\\"))] };
    for seg in segs {
        let mut next = Vec::new();
        for base in &current {
            if seg.contains('*') || seg.contains('?') {
                if let Ok(rd) = fs::read_dir(base) {
                    for e in rd.flatten() {
                        let (Ok(md), Ok(ft)) = (e.metadata(), e.file_type()) else { continue };
                        if is_link(md.file_attributes(), &ft) {
                            continue;
                        }
                        if wildcard(seg, &e.file_name().to_string_lossy()) {
                            next.push(e.path());
                        }
                    }
                }
            } else {
                next.push(base.join(seg));
            }
        }
        current = next;
    }
    current.retain(|p| fs::symlink_metadata(p).is_ok());
    current.sort();
    current.dedup();
    current
}

// ---------------------------------------------------------------- measuring

#[derive(Default)]
pub struct Tally {
    pub bytes: AtomicU64,
    pub files: AtomicU64,
    pub kept_recent: AtomicU64,
}

/// Bytes and file count under `path` that a delete with `cutoff` would remove.
/// Never follows links; cloud placeholders count as zero and are never opened.
pub fn measure(path: &Path, cutoff: Option<i64>) -> (u64, u64) {
    let t = Tally::default();
    match fs::symlink_metadata(path) {
        Ok(md) if md.is_dir() && md.file_attributes() & crate::scan::ATTR_REPARSE_POINT == 0 => measure_dir(path, cutoff, &t),
        Ok(md) if md.is_file() => {
            if cutoff.is_none_or(|c| unix_secs(&md) <= c) && !is_placeholder(md.file_attributes()) {
                t.bytes.fetch_add(md.len(), Ordering::Relaxed);
                t.files.fetch_add(1, Ordering::Relaxed);
            }
        }
        _ => {}
    }
    (t.bytes.into_inner(), t.files.into_inner())
}

fn measure_dir(dir: &Path, cutoff: Option<i64>, t: &Tally) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut subdirs = Vec::new();
    for e in rd.flatten() {
        let (Ok(md), Ok(ft)) = (e.metadata(), e.file_type()) else { continue };
        let attrs = md.file_attributes();
        if is_link(attrs, &ft) {
            continue;
        }
        if md.is_dir() {
            subdirs.push(e.path());
        } else if is_placeholder(attrs) {
            continue;
        } else if cutoff.is_some_and(|c| unix_secs(&md) > c) {
            t.kept_recent.fetch_add(1, Ordering::Relaxed);
        } else {
            t.bytes.fetch_add(md.len(), Ordering::Relaxed);
            t.files.fetch_add(1, Ordering::Relaxed);
        }
    }
    subdirs.par_iter().for_each(|d| measure_dir(d, cutoff, t));
}

// ---------------------------------------------------------------- versions

/// The dotted version number at the end of a folder name ("app-12.6.1" -> [12,6,1]).
pub fn version_key(name: &str) -> Option<Vec<u64>> {
    let start = name
        .char_indices()
        .rev()
        .find(|(_, c)| !(c.is_ascii_digit() || *c == '.'))
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0);
    let v = name[start..].trim_matches('.');
    if !v.contains('.') {
        return None;
    }
    v.split('.').map(|p| p.parse().ok()).collect()
}

/// The part of a versioned name before its version, lowercased: "IdeaIC2024.3" -> "ideaic".
pub fn version_stem(name: &str) -> String {
    let end = name.char_indices().rev().find(|(_, c)| !(c.is_ascii_digit() || *c == '.')).map(|(i, c)| i + c.len_utf8()).unwrap_or(0);
    name[..end].to_lowercase()
}

// ---------------------------------------------------------------- evaluation

#[derive(Clone, Debug)]
pub struct Candidate {
    pub path: PathBuf,
    /// The folder the candidate must stay inside (the rule path it came from).
    pub base: PathBuf,
    pub bytes: u64,
    pub files: u64,
    pub cutoff: Option<i64>,
    /// Remove by running this command instead of deleting files (e.g. pnputil for drivers).
    pub remove_with: Option<String>,
    /// Display name, when the folder name is not meaningful.
    pub label: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RuleResult {
    pub rule: Rule,
    /// Existing paths the rule's patterns resolved to.
    pub found: Vec<PathBuf>,
    pub candidates: Vec<Candidate>,
    pub bytes: u64,
    pub files: u64,
    /// Running processes that block cleaning this rule right now.
    pub blocked_by: Vec<String>,
    /// Rule needs admin and LintTrap is not elevated.
    pub needs_admin: bool,
    /// Paths refused by the safety checks, with the reason.
    pub refused: Vec<(PathBuf, String)>,
    /// The whole rule was dismissed by the user.
    pub dismissed: bool,
    /// Paths that matched but were dismissed by the user.
    pub dismissed_paths: Vec<PathBuf>,
    /// For `use_command` rules: the command's program was found.
    pub tool_found: bool,
    /// Last time this rule's tool command ran (Clean or Run).
    pub last_run: Option<LastRun>,
}

impl RuleResult {
    pub fn cleanable(&self) -> bool {
        self.cleanable_if_elevated() && !self.needs_admin
    }
    /// Cleanable now, or once LintTrap gets administrator permission.
    pub fn cleanable_if_elevated(&self) -> bool {
        !self.dismissed
            && self.rule.can_clean()
            && (self.rule.action != Action::None || self.uses_command())
            && self.blocked_by.is_empty()
            && self.bytes > 0
    }
    /// Clean will run the tool's command. Not when a path was dismissed: the tool cannot honour that.
    pub fn uses_command(&self) -> bool {
        self.rule.use_command && self.tool_found && self.dismissed_paths.is_empty()
    }
    /// Growth since the tool command last ran, for rules that have one.
    pub fn grown_since_run(&self) -> Option<u64> {
        self.rule.command.as_ref()?;
        self.last_run.map(|r| self.bytes.saturating_sub(r.after))
    }
    /// What cleaning would likely free: the growth since the last command run, else the measured size.
    pub fn estimate(&self) -> u64 {
        self.grown_since_run().unwrap_or(self.bytes)
    }
    /// The tool command ran and little has been added since: nothing worth cleaning now.
    pub fn fresh(&self) -> bool {
        self.grown_since_run().is_some_and(|g| g < FRESH_BYTES)
    }
    /// One line about the last run, e.g. "Cleaned today, freed 1.2 GB. Nothing new since."
    pub fn last_run_text(&self) -> Option<String> {
        let r = self.last_run?;
        let grown = self.grown_since_run()?;
        let since = if grown < FRESH_BYTES { "Nothing new since.".to_string() } else { format!("Grown {} since.", crate::scan::human(grown)) };
        let h = crate::scan::human;
        Some(format!("Cleaned {}, freed {}; the {} left is in use. {since}", ago(r.at), h(r.before.saturating_sub(r.after)), h(r.after)))
    }
    /// The full cmd.exe line to run for this rule's command: once, or once inside each found path.
    pub fn command_line(&self) -> Option<String> {
        let cmd = self.rule.command.as_deref()?;
        if !self.rule.per_path || self.found.is_empty() {
            return Some(cmd.to_string());
        }
        Some(self.found.iter().map(|p| format!("cd /d \"{}\" && {cmd}", p.display())).collect::<Vec<_>>().join(" & "))
    }
    /// The program a `use_command` rule wants but could not find.
    pub fn missing_tool(&self) -> Option<&str> {
        if self.rule.use_command && !self.tool_found { self.rule.command.as_deref().map(crate::sys::program_of) } else { None }
    }
}

pub struct Env {
    pub running: Vec<crate::sys::Proc>,
    pub is_admin: bool,
    pub guard: safety::Guard,
    pub dismissed: Dismissed,
    pub history: History,
}

impl Env {
    pub fn detect() -> Env {
        Env {
            running: crate::sys::processes(),
            is_admin: crate::sys::is_admin(),
            guard: safety::Guard::detect(),
            dismissed: Dismissed::load(),
            history: History::load(),
        }
    }
}

pub fn evaluate(rule: &Rule, env: &Env) -> RuleResult {
    evaluate_except(rule, env, &[])
}

/// Evaluate `rule`, leaving out paths that overlap `taken` (paths other rules already found).
fn evaluate_except(rule: &Rule, env: &Env, taken: &[PathBuf]) -> RuleResult {
    let overlaps = |p: &Path| taken.iter().any(|t| crate::scan::strip_prefix_ci(p, t).is_some() || crate::scan::strip_prefix_ci(t, p).is_some());
    let mut dismissed_paths = Vec::new();
    let mut found: Vec<PathBuf> = rule
        .paths
        .iter()
        .flat_map(|p| resolve(p))
        .filter(|p| rule.beside.as_ref().is_none_or(|b| p.parent().is_some_and(|d| d.join(b).exists())))
        .filter(|p| !overlaps(p))
        .filter(|p| {
            let d = env.dismissed.has_path(p);
            if d {
                dismissed_paths.push(p.clone());
            }
            !d
        })
        .collect();
    // A tool may report a folder a pattern already found, or one inside it (pnpm's store\v3): count it once.
    found.sort_by_key(|p| p.to_string_lossy().to_lowercase());
    let mut unique: Vec<PathBuf> = Vec::new();
    for p in found {
        if !unique.iter().any(|u| crate::scan::strip_prefix_ci(&p, u).is_some()) {
            unique.push(p);
        }
    }
    let found = unique;
    let cutoff = rule.cutoff();
    let mut res = RuleResult {
        rule: rule.clone(),
        found: found.clone(),
        candidates: Vec::new(),
        bytes: 0,
        files: 0,
        blocked_by: Vec::new(),
        needs_admin: rule.admin && !env.is_admin,
        refused: Vec::new(),
        dismissed: env.dismissed.has_rule(&rule.id),
        dismissed_paths,
        tool_found: rule.use_command && rule.command.as_deref().is_some_and(|c| crate::sys::on_path(crate::sys::program_of(c))),
        last_run: env.history.runs.get(&rule.id).copied(),
    };
    for want in &rule.processes {
        if env.running.iter().any(|p| p.name.eq_ignore_ascii_case(want)) && !res.blocked_by.iter().any(|b| b.eq_ignore_ascii_case(want)) {
            res.blocked_by.push(want.clone());
        }
    }

    let mut targets: Vec<(PathBuf, PathBuf)> = Vec::new(); // (candidate, base)
    match rule.action {
        Action::None => {
            // Report-only: show the size of what was found.
            for p in &found {
                let (b, f) = measure(p, None);
                res.bytes += b;
                res.files += f;
            }
            return res;
        }
        Action::Drivers => {
            let (old, kept) = crate::drivers::old_versions(&crate::drivers::packages(), &crate::drivers::in_use(), rule.keep.unwrap_or(1));
            for d in old {
                let Some(folder) = d.folder.clone() else { continue };
                if env.dismissed.has_path(&folder) {
                    res.dismissed_paths.push(folder);
                    continue;
                }
                let (b, f) = measure(&folder, None);
                res.bytes += b;
                res.files += f;
                res.candidates.push(Candidate {
                    path: folder.clone(),
                    base: folder.parent().map(Path::to_path_buf).unwrap_or_default(),
                    bytes: b,
                    files: f,
                    cutoff: None,
                    remove_with: Some(format!("pnputil /delete-driver {}", d.published)),
                    label: Some(format!("{} {} ({}, {})", d.original, d.version_text, d.provider, d.published)),
                });
            }
            for (d, why) in kept {
                res.refused.push((d.folder.unwrap_or_else(|| PathBuf::from(&d.published)), format!("{} {}: {why}", d.original, d.version_text)));
            }
            res.candidates.sort_by(|a, b| b.bytes.cmp(&a.bytes));
            return res;
        }
        Action::Whole => {
            for p in &found {
                let base = p.parent().map(Path::to_path_buf).unwrap_or_else(|| p.clone());
                targets.push((p.clone(), base));
            }
        }
        Action::Contents => {
            for p in &found {
                if let Ok(rd) = fs::read_dir(p) {
                    for e in rd.flatten() {
                        targets.push((e.path(), p.clone()));
                    }
                }
            }
        }
        Action::Versions => {
            let keep = rule.keep.unwrap_or(1).max(1);
            for p in &found {
                let Ok(rd) = fs::read_dir(p) else { continue };
                // Grouped by the name before the version, so IdeaIC2024.3 is only compared with IdeaIC2025.1.
                let mut groups: std::collections::BTreeMap<String, Vec<(Vec<u64>, PathBuf)>> = Default::default();
                let found_versions: Vec<(String, Vec<u64>, PathBuf)> = rd
                    .flatten()
                    .filter(|e| e.file_type().map(|t| t.is_dir() && !t.is_symlink()).unwrap_or(false))
                    .filter_map(|e| {
                        let name = e.file_name().to_string_lossy().to_string();
                        if let Some(px) = &rule.prefix {
                            if !name.to_lowercase().starts_with(&px.to_lowercase()) {
                                return None;
                            }
                        }
                        version_key(&name).map(|k| (version_stem(&name), k, e.path()))
                    })
                    .collect();
                for (stem, k, path) in found_versions {
                    groups.entry(stem).or_default().push((k, path));
                }
                let mut old = Vec::new();
                for (_, mut versions) in groups {
                    versions.sort_by(|a, b| b.0.cmp(&a.0)); // newest first, numeric
                    old.extend(versions.into_iter().skip(keep).map(|(_, p)| p));
                }
                for path in old {
                    if let Some(proc_) = env.running.iter().find(|pr| pr.path.as_ref().is_some_and(|x| crate::scan::strip_prefix_ci(x, &path).is_some())) {
                        res.refused.push((path, format!("{} is running from this folder", proc_.name)));
                        continue;
                    }
                    targets.push((path, p.clone()));
                }
            }
        }
    }

    for (path, base) in targets {
        if env.dismissed.has_path(&path) {
            res.dismissed_paths.push(path);
            continue;
        }
        if let Err(why) = env.guard.check(&path, &base) {
            res.refused.push((path, why));
            continue;
        }
        let (b, f) = measure(&path, cutoff);
        if b == 0 && f == 0 {
            continue;
        }
        res.bytes += b;
        res.files += f;
        res.candidates.push(Candidate { path, base, bytes: b, files: f, cutoff, remove_with: None, label: None });
    }
    res.candidates.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    res
}

/// Evaluate all rules in parallel, largest result first.
pub fn evaluate_all(rules: &[Rule], env: &Env) -> Vec<RuleResult> {
    let (general, specific): (Vec<&Rule>, Vec<&Rule>) = rules.iter().partition(|r| r.catch_all);
    let mut out: Vec<RuleResult> = specific.par_iter().map(|r| evaluate(r, env)).collect();
    let mut taken: Vec<PathBuf> = out.iter().flat_map(|r| r.found.iter().chain(&r.dismissed_paths).cloned()).collect();
    // A built-in rule the user turned off still owns its folders: the catch-all must not take them instead.
    let builtin = toml::from_str::<RuleFile>(DEFAULT_RULES).map(|f| f.rule).unwrap_or_default();
    for b in builtin.iter().filter(|b| !b.catch_all && !specific.iter().any(|r| r.id == b.id)) {
        taken.extend(b.paths.iter().flat_map(|p| resolve(p)));
    }
    out.extend(general.par_iter().map(|r| evaluate_except(r, env, &taken)).collect::<Vec<_>>());
    out.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards() {
        assert!(wildcard("*", "anything"));
        assert!(wildcard("wpr_record_*.etl", "WPR_record_1793732799.etl"));
        assert!(wildcard("*20??.?", "IdeaIC2024.3"));
        assert!(!wildcard("*20??.?", "IdeaIC2024.31"));
        assert!(!wildcard("Cache", "Code Cache"));
    }

    #[test]
    fn versions_sort_numerically() {
        assert_eq!(version_key("app-12.6.1"), Some(vec![12, 6, 1]));
        assert_eq!(version_key("156.0.4314.58"), Some(vec![156, 0, 4314, 58]));
        assert_eq!(version_key("Installer"), None);
        assert_eq!(version_key("2024"), None);
        assert!(version_key("app-10.0.0") > version_key("app-9.9.9"));
        assert_eq!(version_stem("IdeaIC2024.3"), "ideaic");
        assert_eq!(version_stem("PyCharm2025.1"), "pycharm");
        assert_eq!(version_stem("app-12.6.1"), "app-");
        assert_eq!(version_stem("156.0.4314.58"), "");
    }

    #[test]
    fn env_expansion() {
        unsafe { std::env::set_var("DF_TEST_VAR", r"C:\x") };
        assert_eq!(expand_env(r"%DF_TEST_VAR%\y"), r"C:\x\y");
        assert_eq!(expand_env(r"%DF_NOPE_VAR%\y"), r"%DF_NOPE_VAR%\y");
    }

    #[test]
    fn builtin_rules_parse() {
        let rules: RuleFile = toml::from_str(DEFAULT_RULES).unwrap();
        let mut ids: Vec<_> = rules.rule.iter().map(|r| r.id.clone()).collect();
        let n = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(n, ids.len(), "duplicate rule ids");
    }

    fn test_rule(id: &str, paths: &[&str]) -> Rule {
        let p: Vec<String> = paths.iter().map(|s| format!("'{s}'")).collect();
        toml::from_str::<RuleFile>(&format!("[[rule]]\nid = '{id}'\ntitle = 't'\nsafety = 'review'\naction = 'contents'\npaths = [{}]\n", p.join(", "))).unwrap().rule.remove(0)
    }

    #[test]
    fn catch_all_takes_only_unclaimed_chromium_caches() {
        // Not under %TEMP%: that is the user-temp rule's folder, so the catch-all would rightly skip it.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join(format!("linttrap-test-catchall-{}", std::process::id()));
        for d in [r"Electron\Cache", r"Electron\GPUCache", r"Claimed\Cache", r"Claimed\GPUCache", r"Tokens\Cache"] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        let r = root.display().to_string();
        let mut general = test_rule("general", &[&format!(r"{r}\*\Cache")]);
        general.beside = Some("GPUCache".into());
        general.catch_all = true;
        let specific = test_rule("specific", &[&format!(r"{r}\Claimed")]);
        let results = evaluate_all(&[general, specific], &Env::detect());
        let found = &results.iter().find(|x| x.rule.id == "general").unwrap().found;
        let _ = fs::remove_dir_all(&root);
        // Not Tokens\Cache (no GPUCache beside it) and not Claimed\Cache (another rule found it).
        assert_eq!(found, &vec![root.join(r"Electron\Cache")]);
    }

    #[test]
    fn catch_all_leaves_folders_of_a_disabled_builtin_rule() {
        let builtin: RuleFile = toml::from_str(DEFAULT_RULES).unwrap();
        let browser = builtin.rule.iter().find(|r| r.id == "browser-cache").unwrap();
        let general = builtin.rule.iter().find(|r| r.catch_all).unwrap().clone();
        let env = Env::detect();
        let off: Vec<PathBuf> = browser.paths.iter().flat_map(|p| resolve(p)).collect();
        // With browser-cache turned off (left out of the list), the catch-all still finds none of its folders.
        let results = evaluate_all(&[general], &env);
        assert!(results[0].found.iter().all(|p| !off.contains(p)));
    }

    #[test]
    fn nested_and_duplicate_paths_count_once() {
        let root = std::env::temp_dir().join(format!("linttrap-test-nested-{}", std::process::id()));
        fs::create_dir_all(root.join(r"store\v3")).unwrap();
        let r = root.display().to_string();
        let rule = test_rule("nested", &[&format!(r"{r}\store"), &format!(r"{r}\store\v3"), &format!(r"{r}\STORE")]);
        let found = evaluate(&rule, &Env::detect()).found;
        let _ = fs::remove_dir_all(&root);
        assert_eq!(found.len(), 1);
    }
}
