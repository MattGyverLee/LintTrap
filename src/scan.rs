//! Parallel directory scanner that builds an in-memory size tree.
//!
//! Safety properties:
//! - Never follows symlinks or junctions (name-surrogate reparse points).
//! - Cloud placeholders (OneDrive / Dropbox / Google Drive "online-only" files)
//!   are counted as 0 bytes and are never opened, so scanning never triggers a download.
//! - Small files are aggregated per folder to keep memory bounded on drives with millions of files.

use rayon::prelude::*;
use std::ffi::OsString;
use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::UNIX_EPOCH;

pub const ATTR_REPARSE_POINT: u32 = 0x400;
pub const ATTR_OFFLINE: u32 = 0x1000;
pub const ATTR_RECALL_ON_OPEN: u32 = 0x40000;
pub const ATTR_RECALL_ON_DATA_ACCESS: u32 = 0x400000;

/// Files smaller than this are folded into a single "[N small files]" node per folder.
pub const SMALL_FILE_BYTES: u64 = 1024 * 1024;

pub fn is_placeholder(attrs: u32) -> bool {
    attrs & (ATTR_OFFLINE | ATTR_RECALL_ON_OPEN | ATTR_RECALL_ON_DATA_ACCESS) != 0
}

/// True when a directory entry is a symlink or junction that must not be followed.
/// `DirEntry::file_type()` on Windows reads the reparse tag from the directory listing,
/// and reports name-surrogate tags (symlinks AND junctions) as symlinks. Cloud-file
/// reparse points are not name surrogates, so synced folders are still descended into.
pub fn is_link(attrs: u32, ft: &fs::FileType) -> bool {
    attrs & ATTR_REPARSE_POINT != 0 && ft.is_symlink()
}

pub fn unix_secs(md: &fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Dir,
    File,
    SmallFiles,
}

#[derive(Debug)]
pub struct Node {
    pub name: Box<str>,
    pub kind: Kind,
    /// Total bytes (for folders: everything below it).
    pub size: u64,
    /// Number of files (for folders: everything below it).
    pub files: u64,
    /// Newest modification time in this subtree, unix seconds.
    pub newest: i64,
    pub parent: u32,
    /// Children sorted by size, largest first.
    pub children: Vec<u32>,
    /// Folder could not be read (access denied etc.).
    pub unreadable: bool,
}

#[derive(Default)]
pub struct Progress {
    pub files: AtomicU64,
    pub dirs: AtomicU64,
    pub bytes: AtomicU64,
    pub errors: AtomicU64,
    pub links: AtomicU64,
    pub placeholders: AtomicU64,
    pub cancel: AtomicBool,
}

pub struct Tree {
    pub root_path: PathBuf,
    pub nodes: Vec<Node>,
    pub errors: u64,
    pub links: u64,
    pub placeholders: u64,
    pub elapsed: std::time::Duration,
}

pub const NO_PARENT: u32 = u32::MAX;

struct Sub {
    name: Box<str>,
    kind: Kind,
    size: u64,
    files: u64,
    newest: i64,
    unreadable: bool,
    children: Vec<Sub>,
}

fn scan_dir(path: &Path, name: Box<str>, prog: &Progress) -> Sub {
    let mut me = Sub { name, kind: Kind::Dir, size: 0, files: 0, newest: 0, unreadable: false, children: Vec::new() };
    if prog.cancel.load(Ordering::Relaxed) {
        return me;
    }
    prog.dirs.fetch_add(1, Ordering::Relaxed);
    let rd = match fs::read_dir(path) {
        Ok(r) => r,
        Err(_) => {
            prog.errors.fetch_add(1, Ordering::Relaxed);
            me.unreadable = true;
            return me;
        }
    };
    let mut subdirs: Vec<(PathBuf, OsString)> = Vec::new();
    let (mut small_size, mut small_count, mut small_newest) = (0u64, 0u64, 0i64);
    for entry in rd {
        let Ok(entry) = entry else {
            prog.errors.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let (Ok(md), Ok(ft)) = (entry.metadata(), entry.file_type()) else {
            prog.errors.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let attrs = md.file_attributes();
        if is_link(attrs, &ft) {
            prog.links.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if md.is_dir() {
            subdirs.push((entry.path(), entry.file_name()));
            continue;
        }
        let size = if is_placeholder(attrs) {
            prog.placeholders.fetch_add(1, Ordering::Relaxed);
            0
        } else {
            md.len()
        };
        let mt = unix_secs(&md);
        prog.files.fetch_add(1, Ordering::Relaxed);
        prog.bytes.fetch_add(size, Ordering::Relaxed);
        me.size += size;
        me.files += 1;
        me.newest = me.newest.max(mt);
        if size >= SMALL_FILE_BYTES {
            me.children.push(Sub {
                name: entry.file_name().to_string_lossy().into(),
                kind: Kind::File,
                size,
                files: 1,
                newest: mt,
                unreadable: false,
                children: Vec::new(),
            });
        } else {
            small_size += size;
            small_count += 1;
            small_newest = small_newest.max(mt);
        }
    }
    if small_count > 0 {
        me.children.push(Sub {
            name: format!("[{small_count} small files]").into(),
            kind: Kind::SmallFiles,
            size: small_size,
            files: small_count,
            newest: small_newest,
            unreadable: false,
            children: Vec::new(),
        });
    }
    let subs: Vec<Sub> = subdirs
        .into_par_iter()
        .map(|(p, n)| scan_dir(&p, n.to_string_lossy().into(), prog))
        .collect();
    for s in subs {
        me.size += s.size;
        me.files += s.files;
        me.newest = me.newest.max(s.newest);
        me.children.push(s);
    }
    me
}

/// Scan `root` and build the tree. Runs on a dedicated rayon pool with large stacks
/// so very deep folder hierarchies cannot overflow.
pub fn scan(root: &Path, prog: &Progress) -> Tree {
    let start = std::time::Instant::now();
    let pool = rayon::ThreadPoolBuilder::new()
        .stack_size(16 * 1024 * 1024)
        .build()
        .expect("thread pool");
    let root_name: Box<str> = root.to_string_lossy().into();
    let sub = pool.install(|| scan_dir(root, root_name, prog));

    // Flatten into an arena (breadth-first so parents precede children).
    let mut nodes: Vec<Node> = Vec::new();
    let mut queue: std::collections::VecDeque<(Sub, u32)> = std::collections::VecDeque::new();
    queue.push_back((sub, NO_PARENT));
    while let Some((mut s, parent)) = queue.pop_front() {
        let idx = nodes.len() as u32;
        s.children.sort_by(|a, b| b.size.cmp(&a.size));
        let kids = std::mem::take(&mut s.children);
        nodes.push(Node {
            name: s.name,
            kind: s.kind,
            size: s.size,
            files: s.files,
            newest: s.newest,
            parent,
            children: Vec::with_capacity(kids.len()),
            unreadable: s.unreadable,
        });
        if parent != NO_PARENT {
            nodes[parent as usize].children.push(idx);
        }
        for k in kids {
            queue.push_back((k, idx));
        }
    }
    // Breadth-first order assigns child indices in the order they were queued (already size-sorted),
    // so each children list is sorted largest-first.
    Tree {
        root_path: root.to_path_buf(),
        nodes,
        errors: prog.errors.load(Ordering::Relaxed),
        links: prog.links.load(Ordering::Relaxed),
        placeholders: prog.placeholders.load(Ordering::Relaxed),
        elapsed: start.elapsed(),
    }
}

impl Tree {
    pub fn root(&self) -> u32 {
        0
    }

    pub fn path_of(&self, mut idx: u32) -> PathBuf {
        let mut parts: Vec<&str> = Vec::new();
        while idx != 0 && idx != NO_PARENT {
            parts.push(&self.nodes[idx as usize].name);
            idx = self.nodes[idx as usize].parent;
        }
        let mut p = self.root_path.clone();
        for part in parts.iter().rev() {
            p.push(part);
        }
        p
    }

    /// Find the node for an absolute path (case-insensitive), if it was scanned.
    pub fn find(&self, path: &Path) -> Option<u32> {
        let rel = strip_prefix_ci(path, &self.root_path)?;
        let mut idx = 0u32;
        for comp in rel.components() {
            let want = comp.as_os_str().to_string_lossy();
            idx = *self.nodes[idx as usize]
                .children
                .iter()
                .find(|&&c| self.nodes[c as usize].kind != Kind::SmallFiles && self.nodes[c as usize].name.eq_ignore_ascii_case(&want))?;
        }
        Some(idx)
    }
}

/// Case-insensitive `strip_prefix` for Windows paths.
pub fn strip_prefix_ci(path: &Path, base: &Path) -> Option<PathBuf> {
    let p = path.to_string_lossy().to_lowercase();
    let b = base.to_string_lossy().to_lowercase();
    let b = b.trim_end_matches('\\');
    if p == b {
        return Some(PathBuf::new());
    }
    let rest = p.strip_prefix(b)?.strip_prefix('\\')?;
    // Re-slice the original (case-preserved) string at the same byte offset.
    let orig = path.to_string_lossy();
    Some(PathBuf::from(&orig[orig.len() - rest.len()..]))
}

pub fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{bytes} B") } else { format!("{v:.1} {}", UNITS[u]) }
}
