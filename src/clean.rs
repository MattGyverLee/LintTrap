//! Deleting. Every path is re-checked by the safety guard immediately before deletion.
//!
//! - Never follows or removes symlinks/junctions, and never touches cloud placeholders.
//! - Files in use are skipped (counted as failed) and the rest of the folder is still cleaned.
//! - With a cutoff, files modified after it are kept, and their folders are kept too.

use crate::rules::{Candidate, RuleResult};
use crate::safety::Guard;
use crate::scan::{is_placeholder, unix_secs, ATTR_REPARSE_POINT};
use rayon::prelude::*;
use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Default)]
pub struct CleanStats {
    pub freed: AtomicU64,
    pub files: AtomicU64,
    pub failed: AtomicU64,
    pub kept_recent: AtomicU64,
    pub skipped_links: AtomicU64,
    pub first_errors: Mutex<Vec<String>>,
    /// Rules skipped at clean time because one of their programs was running.
    pub skipped_rules: Mutex<Vec<String>>,
}

impl CleanStats {
    fn error(&self, msg: String) {
        self.failed.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut v) = self.first_errors.lock() {
            if v.len() < 12 {
                v.push(msg);
            }
        }
    }
    pub fn freed(&self) -> u64 {
        self.freed.load(Ordering::Relaxed)
    }
}

/// Delete one path (file or folder). Returns true when the path no longer exists.
fn delete_path(p: &Path, cutoff: Option<i64>, st: &CleanStats) -> bool {
    let md = match fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
        Err(e) => {
            st.error(format!("{}: {e}", p.display()));
            return false;
        }
    };
    let attrs = md.file_attributes();
    if attrs & ATTR_REPARSE_POINT != 0 || is_placeholder(attrs) {
        // Junction, symlink or cloud file: leave it (and therefore its parent) alone.
        st.skipped_links.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    if md.is_dir() {
        let entries: Vec<_> = match fs::read_dir(p) {
            Ok(rd) => rd.flatten().map(|e| e.path()).collect(),
            Err(e) => {
                st.error(format!("{}: {e}", p.display()));
                return false;
            }
        };
        let all_gone = entries.par_iter().map(|c| delete_path(c, cutoff, st)).reduce(|| true, |a, b| a & b);
        if !all_gone {
            return false;
        }
        match fs::remove_dir(p) {
            Ok(()) => true,
            Err(e) => {
                st.error(format!("{}: {e}", p.display()));
                false
            }
        }
    } else {
        if cutoff.is_some_and(|c| unix_secs(&md) > c) {
            st.kept_recent.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if md.permissions().readonly() {
            let mut perm = md.permissions();
            perm.set_readonly(false);
            let _ = fs::set_permissions(p, perm);
        }
        match fs::remove_file(p) {
            Ok(()) => {
                st.freed.fetch_add(md.len(), Ordering::Relaxed);
                st.files.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(e) => {
                st.error(format!("{}: {e}", p.display()));
                false
            }
        }
    }
}

/// Delete one candidate after re-running the safety guard.
pub fn clean_candidate(c: &Candidate, guard: &Guard, st: &CleanStats) {
    if let Some(cmd) = &c.remove_with {
        // Removed by a system tool (e.g. pnputil, which refuses drivers that are in use); nothing deleted here.
        let (before, files) = crate::rules::measure(&c.path, None);
        let res = crate::sys::run_hidden(cmd, std::time::Duration::from_secs(5 * 60));
        let (after, _) = crate::rules::measure(&c.path, None);
        if after < before {
            st.freed.fetch_add(before - after, Ordering::Relaxed);
            st.files.fetch_add(files, Ordering::Relaxed);
        }
        if let Err(e) = res {
            st.error(format!("{} ({cmd}): {e}", c.label.as_deref().unwrap_or(&c.path.display().to_string())));
        }
        return;
    }
    if let Err(why) = guard.check(&c.path, &c.base) {
        st.error(format!("refused {}: {why}", c.path.display()));
        return;
    }
    delete_path(&c.path, c.cutoff, st);
}

/// Clean by running the tool's own command; freed space is measured before and after.
fn clean_with_command(r: &RuleResult, st: &CleanStats) {
    let Some(cmd) = r.command_line() else { return };
    let size =|| r.found.iter().map(|p| crate::rules::measure(p, None)).fold((0u64, 0u64), |a, b| (a.0 + b.0, a.1 + b.1));
    let before = size();
    let res = crate::sys::run_hidden(&cmd, std::time::Duration::from_secs(20 * 60));
    let after = size();
    st.freed.fetch_add(before.0.saturating_sub(after.0), Ordering::Relaxed);
    st.files.fetch_add(before.1.saturating_sub(after.1), Ordering::Relaxed);
    match res {
        Ok(_) => crate::rules::History::record(&r.rule.id, before.0, after.0),
        Err(e) => st.error(format!("{} ({cmd}): {e}", r.rule.title)),
    }
}

/// Clean one rule result: with the tool's command for `use_command` rules whose tool is installed,
/// otherwise by deleting its candidates. The caller decides which results are allowed.
pub fn clean_result(r: &RuleResult, guard: &Guard, st: &CleanStats) {
    if r.uses_command() {
        clean_with_command(r, st);
        return;
    }
    for c in &r.candidates {
        clean_candidate(c, guard, st);
    }
}

/// Clean several results, re-checking running programs right now (the results may have been
/// measured minutes ago). Rules whose programs are running are skipped and listed in `skipped_rules`.
pub fn clean_all(results: &[RuleResult], guard: &Guard, st: &CleanStats, on_progress: &dyn Fn()) {
    let procs = crate::sys::processes();
    for r in results {
        let running: Vec<&str> = r
            .rule
            .processes
            .iter()
            .filter(|want| procs.iter().any(|p| p.name.eq_ignore_ascii_case(want)))
            .map(String::as_str)
            .collect();
        if !running.is_empty() {
            if let Ok(mut v) = st.skipped_rules.lock() {
                v.push(format!("{} (close {})", r.rule.title, running.join(", ")));
            }
            continue;
        }
        clean_result(r, guard, st);
        on_progress();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::PathBuf;
    use std::process::Command;

    fn fixture(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("linttrap-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn guard_for_tests() -> Guard {
        Guard { cloud_roots: vec![], critical: vec![] }
    }

    #[test]
    fn junction_target_is_never_touched() {
        let root = fixture("junction");
        let outside = root.join("outside");
        let inside = root.join("cache");
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(inside.join("sub")).unwrap();
        fs::write(outside.join("precious.txt"), b"keep me").unwrap();
        fs::write(inside.join("sub").join("junk.bin"), vec![0u8; 4096]).unwrap();
        let status = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(inside.join("link-to-outside"))
            .arg(&outside)
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J failed");

        let st = CleanStats::default();
        for e in fs::read_dir(&inside).unwrap().flatten() {
            let c = Candidate { path: e.path(), base: inside.clone(), bytes: 0, files: 0, cutoff: None, remove_with: None, label: None };
            clean_candidate(&c, &guard_for_tests(), &st);
        }
        assert!(outside.join("precious.txt").exists(), "junction target was deleted");
        assert!(!inside.join("sub").exists(), "normal folder should be gone");
        assert!(inside.join("link-to-outside").exists(), "junction itself is left alone");
        assert_eq!(st.skipped_links.load(Ordering::Relaxed), 1);
        assert_eq!(st.freed(), 4096);
        let _ = Command::new("cmd").args(["/c", "rmdir"]).arg(inside.join("link-to-outside")).status();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn locked_file_is_skipped_and_rest_is_cleaned() {
        let root = fixture("locked");
        let dir = root.join("temp");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("a.tmp"), vec![1u8; 100]).unwrap();
        fs::write(dir.join("locked.tmp"), vec![2u8; 100]).unwrap();
        // Open with no sharing so delete fails, like a file held by a running program.
        let _hold = fs::OpenOptions::new().read(true).share_mode(0).open(dir.join("locked.tmp")).unwrap();
        let st = CleanStats::default();
        let c = Candidate { path: dir.clone(), base: root.clone(), bytes: 0, files: 0, cutoff: None, remove_with: None, label: None };
        clean_candidate(&c, &guard_for_tests(), &st);
        assert!(!dir.join("a.tmp").exists());
        assert!(dir.join("locked.tmp").exists());
        assert!(dir.exists(), "folder with a locked file stays");
        assert!(st.failed.load(Ordering::Relaxed) >= 1);
        drop(_hold);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn recent_files_are_kept_with_cutoff() {
        let root = fixture("cutoff");
        let dir = root.join("t");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("new.tmp"), b"x").unwrap();
        let st = CleanStats::default();
        let cutoff = Some(crate::rules::now_secs() - 2 * 86_400);
        let c = Candidate { path: dir.clone(), base: root.clone(), bytes: 0, files: 0, cutoff, remove_with: None, label: None };
        clean_candidate(&c, &guard_for_tests(), &st);
        assert!(dir.join("new.tmp").exists());
        assert_eq!(st.kept_recent.load(Ordering::Relaxed), 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn guard_refusal_deletes_nothing() {
        let root = fixture("guard");
        let other = root.join("other");
        fs::create_dir_all(&other).unwrap();
        fs::write(other.join("f"), b"x").unwrap();
        let st = CleanStats::default();
        // Candidate claims a base it is not inside of.
        let c = Candidate { path: other.clone(), base: root.join("cache"), bytes: 0, files: 0, cutoff: None, remove_with: None, label: None };
        clean_candidate(&c, &guard_for_tests(), &st);
        assert!(other.join("f").exists());
        let _ = fs::remove_dir_all(&root);
    }
}
