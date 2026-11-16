//! Old versions of third-party drivers in the Windows driver store.
//!
//! Only reads. Removal is done by `pnputil /delete-driver` (no /force), which Windows refuses
//! for a driver that any device is using.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct DriverPkg {
    /// oemNN.inf
    pub published: String,
    pub original: String,
    pub provider: String,
    pub class: String,
    pub version: Vec<u64>,
    pub version_text: String,
    /// Its folder in DriverStore\FileRepository.
    pub folder: Option<PathBuf>,
}

/// Parse `pnputil` output into blocks of `label: value` pairs (blank line between blocks).
fn blocks(text: &str) -> Vec<HashMap<String, String>> {
    let mut out = Vec::new();
    let mut cur = HashMap::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            cur.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn pnputil(args: &str) -> String {
    crate::sys::run_hidden(&format!("pnputil {args}"), std::time::Duration::from_secs(120)).unwrap_or_default()
}

fn store_folder(published: &str) -> Option<PathBuf> {
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::SetupGetInfDriverStoreLocationW;
    let inf = PathBuf::from(std::env::var_os("SystemRoot")?).join("INF").join(published);
    let name: Vec<u16> = inf.as_os_str().to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
    let mut buf = [0u16; 1024];
    let mut need = 0u32;
    let ok = unsafe { SetupGetInfDriverStoreLocationW(name.as_ptr(), std::ptr::null(), std::ptr::null(), buf.as_mut_ptr(), buf.len() as u32, &mut need) };
    if ok == 0 {
        return None;
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    PathBuf::from(String::from_utf16_lossy(&buf[..end])).parent().map(Path::to_path_buf)
}

/// "05/19/2026 15.11.30.14" -> [15, 11, 30, 14]
fn parse_version(s: &str) -> Vec<u64> {
    s.split_whitespace().last().unwrap_or("").split('.').map(|p| p.parse().unwrap_or(0)).collect()
}

/// Third-party driver packages (English pnputil labels; returns nothing on other display languages).
pub fn packages() -> Vec<DriverPkg> {
    blocks(&pnputil("/enum-drivers"))
        .into_iter()
        .filter_map(|b| {
            let published = b.get("published name")?.clone();
            let v = b.get("driver version").cloned().unwrap_or_default();
            Some(DriverPkg {
                original: b.get("original name")?.clone(),
                provider: b.get("provider name").cloned().unwrap_or_default(),
                class: b.get("class name").cloned().unwrap_or_default(),
                version: parse_version(&v),
                version_text: v.split_whitespace().last().unwrap_or("").to_string(),
                folder: store_folder(&published),
                published,
            })
        })
        .collect()
}

/// oemNN.inf names that some device (connected or not) is installed with.
pub fn in_use() -> HashSet<String> {
    blocks(&pnputil("/enum-devices"))
        .into_iter()
        .filter_map(|b| b.get("driver name").map(|d| d.to_lowercase()))
        .collect()
}

/// Older versions of drivers whose newer version is also in the store.
/// Returns (removable, kept-with-reason). Printer drivers are never offered: print queues use them
/// without being listed as devices.
/// `keep` newest versions of each driver stay (at least 1).
pub fn old_versions(pkgs: &[DriverPkg], used: &HashSet<String>, keep: usize) -> (Vec<DriverPkg>, Vec<(DriverPkg, String)>) {
    let mut groups: HashMap<(String, String), Vec<&DriverPkg>> = HashMap::new();
    for p in pkgs {
        if p.class.eq_ignore_ascii_case("Printer") {
            continue;
        }
        groups.entry((p.original.to_lowercase(), p.provider.to_lowercase())).or_default().push(p);
    }
    let (mut old, mut kept) = (Vec::new(), Vec::new());
    for (_, g) in groups {
        let mut distinct: Vec<Vec<u64>> = g.iter().map(|p| p.version.clone()).collect();
        distinct.sort_unstable_by(|a, b| b.cmp(a));
        distinct.dedup();
        let Some(oldest_kept) = distinct.get(keep.max(1) - 1).or(distinct.last()).cloned() else { continue };
        for p in g {
            if p.version >= oldest_kept {
                continue; // one of the newest `keep` versions (ties included) stays
            }
            if used.contains(&p.published.to_lowercase()) {
                kept.push((p.clone(), "a device still uses this version".to_string()));
            } else {
                old.push(p.clone());
            }
        }
    }
    (old, kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(published: &str, original: &str, class: &str, v: &str) -> DriverPkg {
        DriverPkg { published: published.into(), original: original.into(), provider: "X".into(), class: class.into(), version: parse_version(v), version_text: v.into(), folder: None }
    }

    #[test]
    fn keeps_newest_skips_used_and_printers() {
        let pkgs = vec![
            pkg("oem1.inf", "a.inf", "Media", "01/01/2024 1.4.10.0"),
            pkg("oem2.inf", "a.inf", "Media", "01/01/2025 1.4.9.0"),
            pkg("oem3.inf", "a.inf", "Media", "01/01/2023 1.3.0.0"),
            pkg("oem4.inf", "p.inf", "Printer", "01/01/2023 1.0.0.0"),
            pkg("oem5.inf", "p.inf", "Printer", "01/01/2024 2.0.0.0"),
            pkg("oem6.inf", "b.inf", "System", "01/01/2024 1.0.0.0"),
        ];
        let used: HashSet<String> = ["oem3.inf".to_string()].into();
        let (old, kept) = old_versions(&pkgs, &used, 1);
        let names: Vec<&str> = old.iter().map(|p| p.published.as_str()).collect();
        assert_eq!(names, vec!["oem2.inf"], "numeric version compare, newest kept, printers skipped");
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].0.published, "oem3.inf");
        let (old2, kept2) = old_versions(&pkgs, &used, 2);
        assert!(old2.is_empty(), "keep 2 keeps 1.4.10 and 1.4.9");
        assert_eq!(kept2.len(), 1);
    }

    #[test]
    fn parses_pnputil_blocks() {
        let text = "Microsoft PnP Utility\r\n\r\nPublished Name:     oem77.inf\r\nOriginal Name:      acpivpc.inf\r\nDriver Version:     05/19/2026 15.11.30.14\r\n\r\n";
        let b = blocks(text);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0]["published name"], "oem77.inf");
        assert_eq!(parse_version(&b[0]["driver version"]), vec![15, 11, 30, 14]);
    }
}
