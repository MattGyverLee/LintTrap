//! Last-line checks applied to every path before it is measured or deleted.

use crate::scan::strip_prefix_ci;
use std::path::{Component, Path, PathBuf};

pub struct Guard {
    /// Cloud-synced folders. Deleting inside them would also delete the files in the cloud.
    pub cloud_roots: Vec<PathBuf>,
    /// Folders that must never be deleted, nor any folder that contains them.
    pub critical: Vec<PathBuf>,
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// Pull every `"path": "..."` value out of Dropbox's info.json without a JSON dependency.
fn dropbox_paths(json: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut rest = json;
    while let Some(i) = rest.find("\"path\"") {
        rest = &rest[i + 6..];
        let Some(q1) = rest.find('"') else { break };
        let after = &rest[q1 + 1..];
        let mut val = String::new();
        let mut chars = after.char_indices();
        let mut end = after.len();
        while let Some((j, c)) = chars.next() {
            match c {
                '\\' => {
                    if let Some((_, n)) = chars.next() {
                        val.push(n);
                    }
                }
                '"' => {
                    end = j;
                    break;
                }
                c => val.push(c),
            }
        }
        if !val.is_empty() {
            out.push(PathBuf::from(val));
        }
        rest = &after[end.min(after.len())..];
    }
    out
}

impl Guard {
    pub fn detect() -> Guard {
        let mut cloud = Vec::new();
        for v in ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"] {
            cloud.extend(env_path(v));
        }
        for base in ["LOCALAPPDATA", "APPDATA"] {
            if let Some(b) = env_path(base) {
                if let Ok(t) = std::fs::read_to_string(b.join("Dropbox").join("info.json")) {
                    cloud.extend(dropbox_paths(&t));
                }
            }
        }
        if let Some(home) = env_path("USERPROFILE") {
            for d in ["Dropbox", "OneDrive", "Google Drive", "iCloudDrive", "Box"] {
                cloud.push(home.join(d));
            }
        }

        let mut critical = Vec::new();
        for v in ["SystemDrive", "SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "PUBLIC"] {
            if let Some(mut p) = env_path(v) {
                if p.as_os_str().len() == 2 {
                    p.push("\\"); // "C:" -> "C:\"
                }
                critical.push(p);
            }
        }
        if let Some(root) = env_path("SystemRoot") {
            critical.push(root.join("System32"));
            critical.push(root.join("SysWOW64"));
            critical.push(root.join("WinSxS"));
            critical.push(root.join("Installer"));
        }
        if let Some(home) = env_path("USERPROFILE") {
            for d in ["Documents", "Desktop", "Pictures", "Music", "Videos", "Downloads", ".ssh"] {
                critical.push(home.join(d));
            }
            if let Some(users) = home.parent() {
                critical.push(users.to_path_buf());
            }
        }
        Guard { cloud_roots: cloud, critical }
    }

    /// Ok if `path` may be deleted as part of a rule whose folder is `base`.
    pub fn check(&self, path: &Path, base: &Path) -> Result<(), String> {
        match strip_prefix_ci(path, base) {
            Some(rel) if !rel.as_os_str().is_empty() => {}
            _ => return Err(format!("not inside the rule's folder {}", base.display())),
        }
        let depth = path.components().filter(|c| matches!(c, Component::Normal(_))).count();
        if depth < 2 {
            return Err("too close to the drive root".into());
        }
        for c in &self.critical {
            if strip_prefix_ci(c, path).is_some() {
                return Err(format!("would delete the protected folder {}", c.display()));
            }
        }
        for c in &self.cloud_roots {
            if strip_prefix_ci(path, c).is_some() || strip_prefix_ci(c, path).is_some() {
                return Err(format!("inside the cloud-synced folder {}", c.display()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> Guard {
        Guard {
            cloud_roots: vec![PathBuf::from(r"D:\Dropbox")],
            critical: vec![PathBuf::from(r"C:\Users\me"), PathBuf::from(r"C:\Users\me\AppData\Local"), PathBuf::from(r"C:\Windows")],
        }
    }

    #[test]
    fn allows_children_of_base() {
        assert!(guard().check(Path::new(r"C:\Users\me\AppData\Local\Temp\x"), Path::new(r"C:\Users\me\AppData\Local\Temp")).is_ok());
    }

    #[test]
    fn refuses_outside_base() {
        assert!(guard().check(Path::new(r"C:\Users\me\AppData\Local\Other"), Path::new(r"C:\Users\me\AppData\Local\Temp")).is_err());
        assert!(guard().check(Path::new(r"C:\Users\me\AppData\Local\Temp"), Path::new(r"C:\Users\me\AppData\Local\Temp")).is_err());
    }

    #[test]
    fn refuses_critical_and_ancestors() {
        assert!(guard().check(Path::new(r"C:\Users\me\AppData\Local"), Path::new(r"C:\Users\me\AppData")).is_err());
        assert!(guard().check(Path::new(r"C:\Users\me"), Path::new(r"C:\Users")).is_err());
    }

    #[test]
    fn refuses_cloud() {
        assert!(guard().check(Path::new(r"D:\Dropbox\Apps\x"), Path::new(r"D:\Dropbox\Apps")).is_err());
        assert!(guard().check(Path::new(r"D:\stuff\Dropbox"), Path::new(r"D:\stuff")).is_ok());
    }

    #[test]
    fn parses_dropbox_info() {
        let j = r#"{"personal": {"path": "D:\\Dropbox", "host": 1}, "business": {"path": "E:\\Dropbox (Work)"}}"#;
        assert_eq!(dropbox_paths(j), vec![PathBuf::from(r"D:\Dropbox"), PathBuf::from(r"E:\Dropbox (Work)")]);
    }
}
