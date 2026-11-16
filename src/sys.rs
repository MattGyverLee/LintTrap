//! Windows-specific helpers: running processes and elevation.

use std::path::PathBuf;
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION};
use windows_sys::Win32::UI::Shell::IsUserAnAdmin;

#[derive(Clone, Debug)]
pub struct Proc {
    pub pid: u32,
    pub name: String,
    pub path: Option<PathBuf>,
}

fn image_path(pid: u32) -> Option<PathBuf> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 { None } else { Some(PathBuf::from(String::from_utf16_lossy(&buf[..len as usize]))) }
    }
}

/// Snapshot of running processes with their executable paths (when readable).
pub fn processes() -> Vec<Proc> {
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut e) != 0 {
            loop {
                let end = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
                let name = String::from_utf16_lossy(&e.szExeFile[..end]);
                out.push(Proc { pid: e.th32ProcessID, path: image_path(e.th32ProcessID), name });
                if Process32NextW(snap, &mut e) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    out
}

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[derive(Clone, Debug)]
pub struct Drive {
    pub root: String,
    pub total: u64,
    pub free: u64,
}

/// Fixed (local hard) drives with their size and free space.
pub fn drives() -> Vec<Drive> {
    use windows_sys::Win32::Storage::FileSystem::{GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW};
    const DRIVE_FIXED: u32 = 3;
    let mut out = Vec::new();
    let mask = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let root = format!("{}:\\", (b'A' + i as u8) as char);
        let w = wide(&root);
        if unsafe { GetDriveTypeW(w.as_ptr()) } != DRIVE_FIXED {
            continue;
        }
        // Cloud virtual drives (Google Drive for desktop reports itself as a fixed disk) are not real disks.
        let mut label = [0u16; 261];
        let mut fs_name = [0u16; 261];
        let ok = unsafe {
            GetVolumeInformationW(w.as_ptr(), label.as_mut_ptr(), label.len() as u32, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), fs_name.as_mut_ptr(), fs_name.len() as u32)
        };
        if ok != 0 {
            let to_s = |b: &[u16]| String::from_utf16_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]);
            let (label, fs_name) = (to_s(&label), to_s(&fs_name));
            if label.contains("Google Drive") || fs_name.eq_ignore_ascii_case("DriveFS") {
                continue;
            }
        }
        let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
        if unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut avail, &mut total, &mut free) } != 0 {
            out.push(Drive { root, total, free: avail });
        }
    }
    out
}

/// Start another copy of this program elevated ("Run as administrator"). True if it launched.
pub fn relaunch_as_admin() -> bool {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    let Ok(exe) = std::env::current_exe() else { return false };
    let verb = wide("runas");
    let file = wide(&exe.display().to_string());
    let h = unsafe { ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), file.as_ptr(), std::ptr::null(), std::ptr::null(), 1) };
    h as usize > 32
}

/// The program a command line starts (its first word).
pub fn program_of(command: &str) -> &str {
    command.split_whitespace().next().unwrap_or("")
}

/// True when `program` can be started: an existing path, or a name on PATH (with a PATHEXT extension).
pub fn on_path(program: &str) -> bool {
    if program.is_empty() {
        return false;
    }
    let p = std::path::Path::new(program);
    if p.components().count() > 1 {
        return p.is_file();
    }
    let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
    let Some(paths) = std::env::var_os("PATH") else { return false };
    std::env::split_paths(&paths).any(|d| {
        (p.extension().is_some() && d.join(program).is_file()) || exts.split(';').filter(|e| !e.is_empty()).any(|e| d.join(format!("{program}{e}")).is_file())
    })
}

/// Run a command line hidden (`cmd /c`, no window, no input) from the user's profile folder and wait
/// for it. Ok with its output on exit code 0; killed after `timeout`.
pub fn run_hidden(command: &str, timeout: std::time::Duration) -> Result<String, String> {
    let out = run_hidden_output(command, timeout)?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    if out.status.success() {
        Ok(text)
    } else {
        let last = text.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").trim();
        Err(format!("exit code {}: {}", out.status.code().unwrap_or(-1), last.chars().take(200).collect::<String>()))
    }
}

/// Like `run_hidden`, but only the standard output, and only on exit code 0 (for asking a tool a question).
pub fn query(command: &str, timeout: std::time::Duration) -> Option<String> {
    run_hidden_output(command, timeout).ok().filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}

fn run_hidden_output(command: &str, timeout: std::time::Duration) -> Result<std::process::Output, String> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut cmd = Command::new("cmd");
    cmd.raw_arg(format!("/d /c {command}"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW);
    if let Some(home) = std::env::var_os("USERPROFILE") {
        cmd.current_dir(home);
    }
    let child = cmd.spawn().map_err(|e| format!("could not start: {e}"))?;
    let pid = child.id();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(out)) => Ok(out),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => {
            let _ = Command::new("taskkill").args(["/T", "/F", "/PID", &pid.to_string()]).creation_flags(CREATE_NO_WINDOW).status();
            Err(format!("stopped after {} minutes", timeout.as_secs() / 60))
        }
    }
}

/// A console window started by `run_in_console`; `wait` blocks until the user closes it.
pub enum Launched {
    Child(std::process::Child),
    /// Process handle from ShellExecuteExW (stored as usize so it can cross threads).
    Handle(usize),
}

impl Launched {
    pub fn wait(self) {
        match self {
            Launched::Child(mut c) => {
                let _ = c.wait();
            }
            Launched::Handle(h) => unsafe {
                use windows_sys::Win32::System::Threading::{WaitForSingleObject, INFINITE};
                WaitForSingleObject(h as windows_sys::Win32::Foundation::HANDLE, INFINITE);
                CloseHandle(h as windows_sys::Win32::Foundation::HANDLE);
            },
        }
    }
}

/// Start `program` with `args` as administrator (Windows shows its permission prompt), in a visible window.
pub fn run_elevated(program: &str, args: &str) -> Result<Launched, String> {
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    let (verb, file, params) = (wide("runas"), wide(program), wide(args));
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = 1;
    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok != 0 && !info.hProcess.is_null() { Ok(Launched::Handle(info.hProcess as usize)) } else { Err("Administrator permission was not given.".into()) }
}

/// Run a rule's tool command in its own console window (`cmd /k`, so the output stays visible).
/// With `elevated`, and LintTrap not already elevated, Windows asks for administrator permission.
pub fn run_in_console(command: &str, elevated: bool) -> Result<Launched, String> {
    let args = format!("/k {command}");
    if elevated && !is_admin() {
        return run_elevated("cmd.exe", &args);
    }
    use std::os::windows::process::CommandExt;
    const CREATE_NEW_CONSOLE: u32 = 0x10;
    std::process::Command::new("cmd")
        .raw_arg(args)
        .creation_flags(CREATE_NEW_CONSOLE)
        .spawn()
        .map(Launched::Child)
        .map_err(|e| format!("Could not start the command: {e}"))
}

/// Put `text` on the Windows clipboard (through clip.exe, as UTF-16 so any path survives).
pub fn copy_to_clipboard(text: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut child = std::process::Command::new("clip")
        .stdin(std::process::Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("could not start clip: {e}"))?;
    let bytes: Vec<u8> = [0xFFu8, 0xFE].into_iter().chain(text.encode_utf16().flat_map(u16::to_le_bytes)).collect();
    child.stdin.take().ok_or("no stdin")?.write_all(&bytes).map_err(|e| e.to_string())?;
    child.wait().map_err(|e| e.to_string()).and_then(|s| if s.success() { Ok(()) } else { Err(format!("clip failed: {s}")) })
}

/// Open Explorer with `path` selected (or opened, for a folder that should be shown inside).
pub fn reveal(path: &std::path::Path) {
    let _ = std::process::Command::new("explorer").arg(format!("/select,{}", path.display())).spawn();
}
