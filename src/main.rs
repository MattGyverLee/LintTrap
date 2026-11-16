#![windows_subsystem = "windows"]
//! LintTrap GUI: treemap of a drive plus a list of junk ("fluff") that can be cleaned.

use linttrap::ask;
use linttrap::clean::{self, CleanStats};
use linttrap::locate::Locations;
use linttrap::rules::{self, Action, Dismissed, RuleResult, Safety};
use linttrap::safety::Guard;
use linttrap::scan::{self, human, Kind, Progress, Tree};
use linttrap::sys;
use linttrap::treemap::{self, Cell, HEADER};
use eframe::egui::{self, Align, Align2, Color32, FontId, Id, Layout, Pos2, Rect, RichText, Sense, Stroke, StrokeKind, Vec2};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("LintTrap")
            .with_inner_size([1440.0, 900.0])
            .with_min_inner_size([960.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native("LintTrap", options, Box::new(|cc| Ok(Box::new(App::new(&cc.egui_ctx)))))
}

// ---------------------------------------------------------------- colours

struct Pal {
    dirs: [Color32; 3],
    file: Color32,
    small: Color32,
    edge: Color32,
    text: Color32,
    weak: Color32,
}

fn pal(dark: bool) -> Pal {
    if dark {
        Pal {
            dirs: [Color32::from_rgb(0x2a, 0x31, 0x2d), Color32::from_rgb(0x33, 0x3b, 0x37), Color32::from_rgb(0x3d, 0x46, 0x41)],
            file: Color32::from_rgb(0x2c, 0x38, 0x46),
            small: Color32::from_rgb(0x23, 0x29, 0x26),
            edge: Color32::from_rgb(0x15, 0x19, 0x17),
            text: Color32::from_rgb(0xe6, 0xeb, 0xe7),
            weak: Color32::from_rgb(0x9a, 0xa6, 0x9f),
        }
    } else {
        Pal {
            dirs: [Color32::from_rgb(0xe2, 0xe6, 0xdf), Color32::from_rgb(0xd3, 0xd9, 0xd1), Color32::from_rgb(0xc4, 0xcc, 0xc2)],
            file: Color32::from_rgb(0xcf, 0xd8, 0xe3),
            small: Color32::from_rgb(0xe9, 0xeb, 0xe7),
            edge: Color32::from_rgb(0xf3, 0xf4, 0xf1),
            text: Color32::from_rgb(0x1d, 0x23, 0x20),
            weak: Color32::from_rgb(0x5f, 0x6a, 0x64),
        }
    }
}

/// (strong colour, background tint) for a safety level.
fn safety_colors(s: Safety, dark: bool) -> (Color32, Color32) {
    match (s, dark) {
        (Safety::Safe, false) => (Color32::from_rgb(0x2e, 0x8a, 0x6e), Color32::from_rgb(0xcd, 0xeb, 0xdd)),
        (Safety::Safe, true) => (Color32::from_rgb(0x5c, 0xc6, 0xa2), Color32::from_rgb(0x1f, 0x43, 0x37)),
        (Safety::Review, false) => (Color32::from_rgb(0xb7, 0x79, 0x1f), Color32::from_rgb(0xf6, 0xe2, 0xbf)),
        (Safety::Review, true) => (Color32::from_rgb(0xe3, 0xa9, 0x4f), Color32::from_rgb(0x4a, 0x37, 0x17)),
        (Safety::Move, false) => (Color32::from_rgb(0x6a, 0x5a, 0xcd), Color32::from_rgb(0xe1, 0xdc, 0xf7)),
        (Safety::Move, true) => (Color32::from_rgb(0xa8, 0x9c, 0xf0), Color32::from_rgb(0x35, 0x2f, 0x5c)),
        (Safety::Info, false) => (Color32::from_rgb(0x7a, 0x85, 0x80), Color32::from_rgb(0xe3, 0xe7, 0xe4)),
        (Safety::Info, true) => (Color32::from_rgb(0x9a, 0xa6, 0x9f), Color32::from_rgb(0x2b, 0x32, 0x2e)),
    }
}

/// Clean rules that need administrator rights by running linttrap-cli elevated (one Windows prompt),
/// then fold its report into `st`. The CLI re-measures and re-checks everything itself.
fn clean_elevated(results: &[RuleResult], st: &CleanStats) {
    let titles = results.iter().map(|r| r.rule.title.as_str()).collect::<Vec<_>>().join(", ");
    let skip = |why: &str| {
        if let Ok(mut v) = st.skipped_rules.lock() {
            v.push(format!("{titles} ({why})"));
        }
    };
    let Some(cli) = std::env::current_exe().ok().map(|e| e.with_file_name("linttrap-cli.exe")).filter(|p| p.is_file()) else {
        return skip("linttrap-cli.exe was not found next to LintTrap");
    };
    let report = std::env::temp_dir().join(format!("linttrap-elevated-{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&report);
    let ids = results.iter().map(|r| r.rule.id.as_str()).collect::<Vec<_>>().join(",");
    let args = format!("clean --rules {ids} --yes --report \"{}\"", report.display());
    match sys::run_elevated(&cli.display().to_string(), &args) {
        Ok(l) => l.wait(),
        Err(_) => return skip("administrator permission was not given"),
    }
    let Ok(text) = std::fs::read_to_string(&report) else {
        return skip("the administrator clean did not report back");
    };
    let _ = std::fs::remove_file(&report);
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let n = v.parse::<u64>().unwrap_or(0);
        match k {
            "freed" => drop(st.freed.fetch_add(n, Ordering::Relaxed)),
            "files" => drop(st.files.fetch_add(n, Ordering::Relaxed)),
            "kept_recent" => drop(st.kept_recent.fetch_add(n, Ordering::Relaxed)),
            "failed" => drop(st.failed.fetch_add(n, Ordering::Relaxed)),
            "skipped_links" => drop(st.skipped_links.fetch_add(n, Ordering::Relaxed)),
            "skipped" => {
                if let Ok(mut s) = st.skipped_rules.lock() {
                    s.push(v.to_string());
                }
            }
            "error" => {
                if let Ok(mut s) = st.first_errors.lock() {
                    s.push(v.to_string());
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------- app state

struct RulesOutput {
    results: Vec<RuleResult>,
    warnings: Vec<String>,
    is_admin: bool,
}

struct CleanJob {
    stats: Arc<CleanStats>,
    handle: JoinHandle<()>,
    planned: u64,
}

enum UiAction {
    ToggleSelect(String),
    ShowOnMap(PathBuf),
    Reveal(PathBuf),
    Copy(String),
    DismissRule(String),
    DismissPath(PathBuf),
    UndismissRule(String),
    UndismissPath(String),
    /// Ask to run this rule's tool command.
    AskRun(String),
    /// Describe this folder as a question for Claude.
    AskClaude(PathBuf),
}

struct App {
    drives: Vec<sys::Drive>,
    root_input: String,
    scan_prog: Arc<Progress>,
    scan_job: Option<(PathBuf, JoinHandle<Tree>)>,
    tree: Option<Tree>,
    current: u32,
    cache: Option<(u32, Rect, Vec<Cell>)>,
    marks: HashMap<u32, Safety>,
    context_node: Option<u32>,
    flash: Option<(u32, f64)>,

    rules_job: Option<JoinHandle<RulesOutput>>,
    /// The rules job is also asking the tools where their caches are (first run).
    locating: bool,
    results: Vec<RuleResult>,
    warnings: Vec<String>,
    is_admin: bool,
    selected: HashSet<String>,
    reset_selection: bool,
    dismissed: Dismissed,
    filter: Option<Safety>,
    this_drive_only: bool,

    confirm_open: bool,
    /// Rule id whose tool command is waiting for confirmation.
    confirm_run: Option<String>,
    /// A Run window that is open: (rule title, thread that waits for it and returns size before/after).
    run_job: Option<(String, JoinHandle<Result<(u64, u64), String>>)>,
    clean_job: Option<CleanJob>,
    last_clean: Option<String>,
    map_stale: bool,
    /// The question for Claude about a folder: being written, then shown until closed.
    ask_job: Option<JoinHandle<String>>,
    ask_text: Option<String>,
}

impl App {
    fn new(ctx: &egui::Context) -> App {
        ctx.all_styles_mut(|s| {
            s.spacing.item_spacing = Vec2::new(8.0, 6.0);
            s.spacing.button_padding = Vec2::new(10.0, 4.0);
        });
        let start = std::env::var("SystemDrive").map(|d| format!("{d}\\")).unwrap_or_else(|_| "C:\\".into());
        let mut app = App {
            drives: sys::drives(),
            root_input: start.clone(),
            scan_prog: Arc::new(Progress::default()),
            scan_job: None,
            tree: None,
            current: 0,
            cache: None,
            marks: HashMap::new(),
            context_node: None,
            flash: None,
            rules_job: None,
            locating: false,
            results: Vec::new(),
            warnings: Vec::new(),
            is_admin: sys::is_admin(),
            selected: HashSet::new(),
            reset_selection: true,
            dismissed: Dismissed::load(),
            filter: None,
            this_drive_only: true,
            confirm_open: false,
            confirm_run: None,
            run_job: None,
            clean_job: None,
            last_clean: None,
            map_stale: false,
            ask_job: None,
            ask_text: None,
        };
        app.start_scan(PathBuf::from(start), ctx);
        app.start_rules(ctx);
        app
    }

    fn start_scan(&mut self, root: PathBuf, ctx: &egui::Context) {
        if self.scan_job.is_some() {
            return;
        }
        self.scan_prog = Arc::new(Progress::default());
        let prog = self.scan_prog.clone();
        let r = root.clone();
        let ctx = ctx.clone();
        let handle = std::thread::spawn(move || {
            let t = scan::scan(&r, &prog);
            ctx.request_repaint();
            t
        });
        self.scan_job = Some((root, handle));
        self.map_stale = false;
    }

    fn start_rules(&mut self, ctx: &egui::Context) {
        if self.rules_job.is_some() {
            return;
        }
        let ctx = ctx.clone();
        self.locating = Locations::first_run();
        self.rules_job = Some(std::thread::spawn(move || {
            let (all, warnings) = rules::load_rules();
            let env = rules::Env::detect();
            let results = rules::evaluate_all(&all, &env);
            ctx.request_repaint();
            RulesOutput { results, warnings, is_admin: env.is_admin }
        }));
    }

    fn poll_jobs(&mut self, ctx: &egui::Context) {
        if self.scan_job.as_ref().is_some_and(|(_, h)| h.is_finished()) {
            let (_, h) = self.scan_job.take().unwrap();
            if let Ok(t) = h.join() {
                self.tree = Some(t);
                self.current = 0;
                self.cache = None;
                self.rebuild_marks();
            }
        }
        if self.rules_job.as_ref().is_some_and(|h| h.is_finished()) {
            if let Ok(out) = self.rules_job.take().unwrap().join() {
                self.results = out.results;
                self.warnings = out.warnings;
                self.is_admin = out.is_admin;
                if self.reset_selection {
                    self.selected = self.results.iter().filter(|r| r.rule.safety == Safety::Safe && r.cleanable_if_elevated() && !r.fresh()).map(|r| r.rule.id.clone()).collect();
                    self.reset_selection = false;
                }
                self.rebuild_marks();
            }
        }
        if self.run_job.as_ref().is_some_and(|(_, h)| h.is_finished()) {
            let (title, h) = self.run_job.take().unwrap();
            self.last_clean = Some(match h.join() {
                Ok(Ok((before, after))) => format!("{title}: the window was closed. Freed {}; LintTrap will remember this.", human(before.saturating_sub(after))),
                Ok(Err(e)) => format!("[WARN] {e}"),
                Err(_) => "[WARN] The run could not be tracked.".into(),
            });
            self.drives = sys::drives();
            self.reset_selection = true;
            self.start_rules(ctx);
        }
        if self.clean_job.as_ref().is_some_and(|j| j.handle.is_finished()) {
            let job = self.clean_job.take().unwrap();
            let _ = job.handle.join();
            let s = &job.stats;
            let mut msg = format!(
                "Freed {} of {} planned. Kept {} recent files. {} could not be deleted (in use or no access).",
                human(s.freed()),
                human(job.planned),
                s.kept_recent.load(Ordering::Relaxed),
                s.failed.load(Ordering::Relaxed)
            );
            if s.skipped_links.load(Ordering::Relaxed) > 0 {
                msg.push_str(&format!(" Left {} links alone.", s.skipped_links.load(Ordering::Relaxed)));
            }
            if let Ok(v) = s.skipped_rules.lock() {
                if !v.is_empty() {
                    msg.push_str(&format!(" Skipped because a program is running: {}.", v.join("; ")));
                }
            }
            self.last_clean = Some(msg);
            self.map_stale = true;
            self.drives = sys::drives();
            // Re-measure so the list shows what is left.
            self.reset_selection = true;
            self.start_rules(ctx);
        }
    }

    /// Which tree nodes to tint, from the current rule results.
    fn rebuild_marks(&mut self) {
        self.marks.clear();
        let Some(t) = &self.tree else { return };
        for r in &self.results {
            if r.dismissed {
                continue;
            }
            let paths: Vec<&PathBuf> = if matches!(r.rule.action, Action::Versions | Action::Drivers) { r.candidates.iter().map(|c| &c.path).collect() } else { r.found.iter().collect() };
            for p in paths {
                if let Some(idx) = t.find(p) {
                    if idx != 0 {
                        self.marks.insert(idx, r.rule.safety);
                    }
                }
            }
        }
    }

    fn on_scanned_drive(&self, r: &RuleResult) -> bool {
        let Some(t) = &self.tree else { return true };
        let root = t.root_path.to_string_lossy().to_lowercase();
        r.found.iter().chain(r.dismissed_paths.iter()).any(|p| p.to_string_lossy().to_lowercase().starts_with(&root))
    }

    /// Results to list: cleanable kinds first (Safe, Review), then Move, then Leave alone; largest first within each.
    fn visible_results(&self) -> Vec<usize> {
        let mut v: Vec<usize> = (0..self.results.len())
            .filter(|&i| {
                let r = &self.results[i];
                (r.bytes > 0 || !r.refused.is_empty())
                    && !r.dismissed
                    && self.filter.is_none_or(|f| r.rule.safety == f)
                    && (!self.this_drive_only || self.on_scanned_drive(r))
            })
            .collect();
        v.sort_by(|&a, &b| {
            let (ra, rb) = (&self.results[a], &self.results[b]);
            ra.rule.safety.cmp(&rb.rule.safety).then(rb.estimate().cmp(&ra.estimate()))
        });
        v
    }

    fn apply(&mut self, a: UiAction, ctx: &egui::Context) {
        let mut changed = false;
        match a {
            UiAction::ToggleSelect(id) => {
                if !self.selected.remove(&id) {
                    self.selected.insert(id);
                }
            }
            UiAction::ShowOnMap(p) => {
                if let Some(t) = &self.tree {
                    if let Some(idx) = t.find(&p) {
                        let parent = t.nodes[idx as usize].parent;
                        self.current = if parent == scan::NO_PARENT { 0 } else { parent };
                        self.flash = Some((idx, ctx.input(|i| i.time)));
                    }
                }
            }
            UiAction::Reveal(p) => sys::reveal(&p),
            UiAction::Copy(s) => ctx.copy_text(s),
            UiAction::AskClaude(p) => {
                let ctx2 = ctx.clone();
                self.ask_text = None;
                self.ask_job = Some(std::thread::spawn(move || {
                    let text = ask::prompt(&[ask::profile(&p, &[])]);
                    ctx2.request_repaint();
                    text
                }));
            }
            UiAction::DismissRule(id) => {
                if !self.dismissed.has_rule(&id) {
                    self.dismissed.toggle_rule(&id);
                }
                self.selected.remove(&id);
                changed = true;
            }
            UiAction::DismissPath(p) => {
                self.dismissed.add_path(&p);
                changed = true;
            }
            UiAction::UndismissRule(id) => {
                if self.dismissed.has_rule(&id) {
                    self.dismissed.toggle_rule(&id);
                }
                changed = true;
            }
            UiAction::UndismissPath(s) => {
                self.dismissed.remove_path(&s);
                changed = true;
            }
            UiAction::AskRun(id) => self.confirm_run = Some(id),
        }
        if changed {
            let _ = self.dismissed.save();
            // Flag rules locally for an instant update, then re-measure for path-level changes.
            for r in &mut self.results {
                r.dismissed = self.dismissed.has_rule(&r.rule.id);
            }
            self.rebuild_marks();
            self.start_rules(ctx);
        }
    }

    fn start_clean(&mut self, ctx: &egui::Context) {
        let chosen: Vec<RuleResult> = self.results.iter().filter(|r| self.selected.contains(&r.rule.id) && r.cleanable_if_elevated()).cloned().collect();
        let planned = chosen.iter().map(|r| r.estimate()).sum();
        let stats = Arc::new(CleanStats::default());
        let st = stats.clone();
        let ctx2 = ctx.clone();
        let handle = std::thread::spawn(move || {
            let (elevated, here): (Vec<RuleResult>, Vec<RuleResult>) = chosen.into_iter().partition(|r| r.needs_admin);
            let guard = Guard::detect();
            clean::clean_all(&here, &guard, &st, &|| ctx2.request_repaint());
            ctx2.request_repaint();
            if !elevated.is_empty() {
                clean_elevated(&elevated, &st);
            }
            ctx2.request_repaint();
        });
        self.clean_job = Some(CleanJob { stats, handle, planned });
        self.last_clean = None;
    }

    // ---------------------------------------------------------------- top bar

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        let busy = self.scan_job.is_some();
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("LintTrap").size(20.0).strong());
            ui.add_space(12.0);
            for d in self.drives.clone() {
                let pct_free = if d.total > 0 { d.free as f64 / d.total as f64 * 100.0 } else { 0.0 };
                let label = format!("{}  {} free", d.root.trim_end_matches('\\'), human(d.free));
                let selected = self.tree.as_ref().is_some_and(|t| t.root_path.to_string_lossy().eq_ignore_ascii_case(&d.root));
                let b = ui
                    .add_enabled(!busy, egui::Button::new(label).selected(selected))
                    .on_hover_text(format!("{} of {} free ({pct_free:.0}%). Click to scan.", human(d.free), human(d.total)));
                if b.clicked() {
                    self.root_input = d.root.clone();
                    self.start_scan(PathBuf::from(&d.root), ui.ctx());
                }
            }
            ui.add_space(8.0);
            ui.add(egui::TextEdit::singleline(&mut self.root_input).desired_width(220.0).hint_text("Folder to scan"));
            if ui.add_enabled(!busy, egui::Button::new("Scan folder")).clicked() {
                let p = PathBuf::from(self.root_input.trim());
                if p.is_dir() {
                    self.start_scan(p, ui.ctx());
                }
            }
            if ui.add_enabled(self.rules_job.is_none(), egui::Button::new("Re-check fluff")).on_hover_text("Measure every rule again").clicked() {
                self.start_rules(ui.ctx());
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if self.is_admin {
                    ui.label(RichText::new("Administrator").color(safety_colors(Safety::Safe, ui.visuals().dark_mode).0));
                } else if ui.button("Restart as administrator").on_hover_text("Needed to read and clean Windows folders").clicked() && sys::relaunch_as_admin() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
                if ui.button("Edit rules").on_hover_text("Opens your rules folder").clicked() {
                    if let Ok(p) = rules::ensure_user_rules_file() {
                        sys::reveal(&p);
                    }
                }
            });
        });
        if let Some((root, _)) = &self.scan_job {
            let p = &self.scan_prog;
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(format!(
                    "Scanning {} ...  {} files  {} folders  {}",
                    root.display(),
                    p.files.load(Ordering::Relaxed),
                    p.dirs.load(Ordering::Relaxed),
                    human(p.bytes.load(Ordering::Relaxed))
                ));
            });
            ui.ctx().request_repaint_after(Duration::from_millis(120));
        }
    }

    // ---------------------------------------------------------------- fluff panel

    fn fluff_panel(&mut self, ui: &mut egui::Ui) {
        let dark = ui.visuals().dark_mode;
        let weak = pal(dark).weak;
        let mut actions: Vec<UiAction> = Vec::new();

        ui.add_space(6.0);
        ui.label(RichText::new("Fluff found").size(18.0).strong());
        if self.rules_job.is_some() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(if self.locating { "First run: finding where your tools keep their caches ..." } else { "Measuring rules ..." });
            });
        }
        let vis = self.visible_results();
        let sum = |s: Safety| {
            self.results
                .iter()
                .filter(|r| r.rule.safety == s && !r.dismissed && (!self.this_drive_only || self.on_scanned_drive(r)))
                .map(|r| r.estimate())
                .sum::<u64>()
        };
        ui.horizontal_wrapped(|ui| {
            for s in [Safety::Safe, Safety::Review, Safety::Move] {
                let (fg, _) = safety_colors(s, dark);
                ui.label(RichText::new(format!("{} {}", s.label(), human(sum(s)))).color(fg).strong());
            }
        });
        ui.horizontal_wrapped(|ui| {
            if ui.selectable_label(self.filter.is_none(), "All").clicked() {
                self.filter = None;
            }
            for s in [Safety::Safe, Safety::Review, Safety::Move, Safety::Info] {
                if ui.selectable_label(self.filter == Some(s), s.label()).clicked() {
                    self.filter = Some(s);
                }
            }
            ui.checkbox(&mut self.this_drive_only, "This drive only");
        });

        // Clean bar
        let selected_bytes: u64 = self.results.iter().filter(|r| self.selected.contains(&r.rule.id) && r.cleanable_if_elevated()).map(|r| r.estimate()).sum();
        ui.separator();
        if let Some(job) = &self.clean_job {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(format!("Cleaning ... freed {} of {}", human(job.stats.freed()), human(job.planned)));
            });
            ui.ctx().request_repaint_after(Duration::from_millis(150));
        } else {
            ui.horizontal_wrapped(|ui| {
                let btn = egui::Button::new(RichText::new(format!("Clean selected ({})", human(selected_bytes))).strong());
                if ui.add_enabled(selected_bytes > 0 && self.rules_job.is_none(), btn).clicked() {
                    self.confirm_open = true;
                }
                ui.label(RichText::new("Deletes permanently; the Recycle Bin would not free space.").small().color(weak));
            });
        }
        if let Some((title, _)) = &self.run_job {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(format!("{title}: waiting for its window to be closed ..."));
            });
            ui.ctx().request_repaint_after(Duration::from_millis(500));
        }
        if let Some(msg) = &self.last_clean {
            ui.label(RichText::new(msg).color(safety_colors(Safety::Safe, dark).0));
        }
        for w in &self.warnings {
            ui.label(RichText::new(format!("[WARN] {w}")).color(safety_colors(Safety::Review, dark).0));
        }
        ui.separator();

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            if vis.is_empty() && self.rules_job.is_none() {
                ui.label("Nothing flagged here.");
            }
            for &i in &vis {
                self.fluff_item(ui, &self.results[i], dark, &mut actions);
            }

            let dismissed_rules: Vec<&RuleResult> = self.results.iter().filter(|r| r.dismissed).collect();
            let dismissed_paths = self.dismissed.paths.clone();
            if !dismissed_rules.is_empty() || !dismissed_paths.is_empty() {
                ui.add_space(8.0);
                egui::CollapsingHeader::new(format!("Dismissed ({})", dismissed_rules.len() + dismissed_paths.len())).show(ui, |ui| {
                    for r in dismissed_rules {
                        ui.horizontal(|ui| {
                            ui.label(format!("{}  ({})", r.rule.title, human(r.bytes)));
                            if ui.small_button("Undo").clicked() {
                                actions.push(UiAction::UndismissRule(r.rule.id.clone()));
                            }
                        });
                    }
                    for p in dismissed_paths {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&p).monospace().small());
                            if ui.small_button("Undo").clicked() {
                                actions.push(UiAction::UndismissPath(p.clone()));
                            }
                        });
                    }
                });
            }
        });

        let ctx = ui.ctx().clone();
        for a in actions {
            self.apply(a, &ctx);
        }
    }

    fn fluff_item(&self, ui: &mut egui::Ui, r: &RuleResult, dark: bool, actions: &mut Vec<UiAction>) {
        let (fg, bg) = safety_colors(r.rule.safety, dark);
        let p = pal(dark);
        let warn = safety_colors(Safety::Review, dark).0;
        ui.horizontal(|ui| {
            if r.cleanable_if_elevated() {
                let mut on = self.selected.contains(&r.rule.id);
                if ui.checkbox(&mut on, "").changed() {
                    actions.push(UiAction::ToggleSelect(r.rule.id.clone()));
                }
            } else {
                ui.add_space(22.0);
            }
            ui.label(RichText::new(format!(" {} ", r.rule.safety.label())).small().strong().color(fg).background_color(bg));
            ui.label(RichText::new(&r.rule.title).strong());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let size = RichText::new(human(r.estimate())).monospace();
                if r.fresh() {
                    ui.label(size.color(p.weak)).on_hover_text(format!("Nothing new since the last clean. The {} on disk is in use.", human(r.bytes)));
                } else {
                    ui.label(size.strong());
                }
            });
        });
        ui.indent(("fluff", &r.rule.id), |ui| {
            if let Some(first) = r.found.first() {
                let more = if r.found.len() > 1 { format!("   +{} more", r.found.len() - 1) } else { String::new() };
                ui.label(RichText::new(format!("{}{more}", first.display())).monospace().small().color(p.weak));
            }
            if !r.blocked_by.is_empty() && r.rule.can_clean() {
                ui.label(RichText::new(format!("Close {} to clean this.", r.blocked_by.join(", "))).color(warn));
            }
            if r.needs_admin && r.rule.can_clean() && r.bytes > 0 {
                ui.label(RichText::new("Windows will ask for administrator permission when this is cleaned.").small().color(warn));
            }
            if let Some(n) = &r.rule.note {
                ui.label(RichText::new(n).small());
            }
            if let Some(t) = r.last_run_text() {
                ui.label(RichText::new(t).small().color(fg));
            }
            if let Some(tool) = r.missing_tool() {
                let what = if r.rule.action == Action::None { "so it can't be cleaned from here" } else { "so Clean deletes the files instead" };
                ui.label(RichText::new(format!("{tool} was not found, {what}.")).small().color(warn));
            }
            let cmd_label = if r.uses_command() { "Clean runs:" } else { "Tool command:" };
            for (label, cmd) in [(cmd_label, &r.rule.command), ("Stop it coming back:", &r.rule.prevent)] {
                if let Some(c) = cmd {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(label).small().color(p.weak));
                        ui.label(RichText::new(c).monospace().small());
                        if ui.small_button("Copy").clicked() {
                            actions.push(UiAction::Copy(c.clone()));
                        }
                        if label == cmd_label
                            && ui.add_enabled(self.run_job.is_none(), egui::Button::new("Run").small()).on_hover_text("Run it in a new window (asks first)").clicked()
                        {
                            actions.push(UiAction::AskRun(r.rule.id.clone()));
                        }
                    });
                }
            }
            ui.horizontal(|ui| {
                let target = if matches!(r.rule.action, Action::Versions | Action::Drivers) { r.candidates.first().map(|c| c.path.clone()) } else { r.found.first().cloned() };
                if let Some(target) = target {
                    if self.tree.is_some() && ui.small_button("Show on map").clicked() {
                        actions.push(UiAction::ShowOnMap(target.clone()));
                    }
                    if ui.small_button("Open folder").clicked() {
                        actions.push(UiAction::Reveal(target));
                    }
                }
                if ui.small_button("Dismiss").on_hover_text("Stop flagging this rule. Undo it under Dismissed.").clicked() {
                    actions.push(UiAction::DismissRule(r.rule.id.clone()));
                }
            });
            let detail: Vec<(PathBuf, u64, Option<String>)> = if !r.candidates.is_empty() {
                r.candidates.iter().map(|c| (c.path.clone(), c.bytes, c.label.clone())).collect()
            } else {
                r.found.iter().map(|f| (f.clone(), 0, None)).collect()
            };
            if detail.len() > 1 || !r.refused.is_empty() {
                egui::CollapsingHeader::new(RichText::new(format!("{} items", detail.len())).small()).id_salt(("items", &r.rule.id)).show(ui, |ui| {
                    for (path, bytes, label) in detail.iter().take(200) {
                        ui.horizontal(|ui| {
                            if *bytes > 0 {
                                ui.label(RichText::new(format!("{:>9}", human(*bytes))).monospace().small());
                            }
                            let name = label.clone().unwrap_or_else(|| path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| path.display().to_string()));
                            ui.label(RichText::new(name).small()).on_hover_text(path.display().to_string());
                            if ui.small_button("Dismiss").on_hover_text("Never flag this path").clicked() {
                                actions.push(UiAction::DismissPath(path.clone()));
                            }
                        });
                    }
                    if detail.len() > 200 {
                        ui.label(RichText::new(format!("... and {} more", detail.len() - 200)).small());
                    }
                    for (path, why) in &r.refused {
                        ui.label(RichText::new(format!("[SKIP] {}: {why}", path.display())).small().color(p.weak));
                    }
                });
            }
        });
        ui.separator();
    }

    // ---------------------------------------------------------------- treemap

    fn map_panel(&mut self, ui: &mut egui::Ui) {
        let dark = ui.visuals().dark_mode;
        let p = pal(dark);
        let Some(tree) = &self.tree else {
            ui.centered_and_justified(|ui| {
                ui.label(if self.scan_job.is_some() { "Scanning ..." } else { "Pick a drive to scan." });
            });
            return;
        };

        // Breadcrumbs
        let mut nav: Option<u32> = None;
        ui.horizontal_wrapped(|ui| {
            let mut chain = vec![self.current];
            let mut n = self.current;
            while n != 0 {
                n = tree.nodes[n as usize].parent;
                chain.push(n);
            }
            chain.reverse();
            if ui.add_enabled(self.current != 0, egui::Button::new("Up")).clicked() {
                nav = Some(tree.nodes[self.current as usize].parent);
            }
            for (i, &c) in chain.iter().enumerate() {
                let name = if c == 0 { tree.root_path.display().to_string().trim_end_matches('\\').to_string() } else { tree.nodes[c as usize].name.to_string() };
                if i > 0 {
                    ui.label(RichText::new("\\").color(p.weak));
                }
                if i + 1 == chain.len() {
                    ui.label(RichText::new(name).strong());
                } else if ui.link(name).clicked() {
                    nav = Some(c);
                }
            }
            let cur = &tree.nodes[self.current as usize];
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(RichText::new(format!("{}  ·  {} files", human(cur.size), cur.files)).color(p.weak));
            });
        });
        if self.map_stale {
            ui.label(RichText::new("Sizes on the map are from before cleaning. Click the drive again to rescan.").color(safety_colors(Safety::Review, dark).0));
        }

        let (rect, resp) = ui.allocate_exact_size(ui.available_size() - Vec2::new(0.0, 22.0), Sense::click());
        let key_ok = self.cache.as_ref().is_some_and(|(n, r, _)| *n == self.current && *r == rect);
        if !key_ok {
            // Nesting stops on its own once boxes get too small to show children.
            self.cache = Some((self.current, rect, treemap::layout(tree, self.current, rect, 12)));
        }
        let cells = &self.cache.as_ref().unwrap().2;

        // Inherited mark: the nearest marked ancestor of the current folder.
        let mut inherited = None;
        let mut a = self.current;
        loop {
            if let Some(s) = self.marks.get(&a) {
                inherited = Some(*s);
                break;
            }
            if a == 0 {
                break;
            }
            a = tree.nodes[a as usize].parent;
        }
        let mut cell_mark: Vec<Option<Safety>> = Vec::with_capacity(cells.len());
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 4.0, p.small);
        let now = ui.input(|i| i.time);
        for c in cells.iter() {
            let own = self.marks.get(&c.node).copied();
            let m = own.or_else(|| c.parent.and_then(|pi| cell_mark[pi])).or(inherited);
            cell_mark.push(m);
            let n = &tree.nodes[c.node as usize];
            let fill = match (m, n.kind) {
                (Some(s), _) => safety_colors(s, dark).1,
                (None, Kind::File) => p.file,
                (None, Kind::SmallFiles) => p.small,
                (None, Kind::Dir) => p.dirs[(c.depth as usize).saturating_sub(1).min(2)],
            };
            painter.rect_filled(c.rect, 2.0, fill);
            match own {
                Some(s) => painter.rect_stroke(c.rect, 2.0, Stroke::new(2.0, safety_colors(s, dark).0), StrokeKind::Inside),
                None => painter.rect_stroke(c.rect, 2.0, Stroke::new(1.0, p.edge), StrokeKind::Inside),
            };
            if let Some((f, t0)) = self.flash {
                if f == c.node && now - t0 < 2.5 {
                    let w = 4.0 - ((now - t0) as f32 * 1.4).min(3.0);
                    painter.rect_stroke(c.rect, 2.0, Stroke::new(w, p.text), StrokeKind::Inside);
                    ui.ctx().request_repaint();
                }
            }
            if c.rect.width() > 44.0 && c.rect.height() > 14.0 {
                let clip = painter.with_clip_rect(Rect::from_min_max(c.rect.min, Pos2::new(c.rect.max.x - 3.0, (c.rect.min.y + HEADER).min(c.rect.max.y))));
                clip.text(c.rect.min + Vec2::new(4.0, 2.0), Align2::LEFT_TOP, format!("{}  {}", n.name, human(n.size)), FontId::proportional(11.5), p.text);
            }
        }

        // Hover, click, right-click
        let hovered = resp.hover_pos().and_then(|pos| cells.iter().rposition(|c| c.rect.contains(pos)));
        if let Some(hi) = hovered {
            let c = cells[hi];
            painter.rect_stroke(c.rect, 2.0, Stroke::new(1.5, p.text), StrokeKind::Inside);
            let n = &tree.nodes[c.node as usize];
            let path = tree.path_of(c.node);
            let parent_size = tree.nodes[n.parent as usize].size.max(1);
            let mark = cell_mark[hi];
            let flagged = self.marks.contains_key(&c.node).then(|| {
                self.results.iter().find(|r| !r.dismissed && r.found.iter().chain(r.candidates.iter().map(|c| &c.path)).any(|f| tree.find(f) == Some(c.node)))
            }).flatten();
            resp.clone().on_hover_ui_at_pointer(|ui| {
                ui.label(RichText::new(&*n.name).strong());
                ui.label(RichText::new(path.display().to_string()).monospace().small());
                ui.label(format!("{}  ·  {} files  ·  {:.1}% of parent", human(n.size), n.files, n.size as f64 * 100.0 / parent_size as f64));
                if let Some(r) = flagged {
                    ui.label(RichText::new(format!("{}: {}", r.rule.safety.label(), r.rule.title)).color(safety_colors(r.rule.safety, dark).0));
                } else if let Some(s) = mark {
                    ui.label(RichText::new(format!("Inside a '{}' item", s.label())).color(safety_colors(s, dark).0));
                }
                ui.label(RichText::new("Click to zoom in. Right-click for more.").small().color(p.weak));
            });
        }
        if resp.clicked() {
            let mut ci = hovered;
            while let Some(i) = ci {
                let n = &tree.nodes[cells[i].node as usize];
                if n.kind == Kind::Dir && !n.children.is_empty() {
                    nav = Some(cells[i].node);
                    break;
                }
                ci = cells[i].parent;
            }
        }
        if resp.secondary_clicked() {
            self.context_node = hovered.map(|hi| cells[hi].node);
        }
        let mut ctx_action: Option<UiAction> = None;
        if let Some(node) = self.context_node {
            let path = tree.path_of(node);
            let is_dir = tree.nodes[node as usize].kind == Kind::Dir;
            let up = tree.nodes[self.current as usize].parent;
            let current = self.current;
            resp.context_menu(|ui| {
                ui.label(RichText::new(path.display().to_string()).monospace().small());
                if ui.button("Open in Explorer").clicked() {
                    ctx_action = Some(UiAction::Reveal(path.clone()));
                    ui.close();
                }
                if ui.button("Copy path").clicked() {
                    ctx_action = Some(UiAction::Copy(path.display().to_string()));
                    ui.close();
                }
                if is_dir && ui.button("Zoom here").clicked() {
                    nav = Some(node);
                    ui.close();
                }
                if current != 0 && ui.button("Zoom out").clicked() {
                    nav = Some(up);
                    ui.close();
                }
                if ui.button("Never flag this path").clicked() {
                    ctx_action = Some(UiAction::DismissPath(path.clone()));
                    ui.close();
                }
                if is_dir && ui.button("Ask Claude about this folder").on_hover_text("Describes the folder for Claude, who can write a cleanup rule for it").clicked() {
                    ctx_action = Some(UiAction::AskClaude(path.clone()));
                    ui.close();
                }
            });
        }
        if ui.input(|i| i.pointer.button_clicked(egui::PointerButton::Extra1)) && self.current != 0 {
            nav = Some(tree.nodes[self.current as usize].parent);
        }

        ui.label(
            RichText::new(format!(
                "Scanned {} in {:.0}s · {} unreadable folders · {} links skipped · cloud-only files count as 0 · WinSxS hard links make C:\\Windows look bigger than it is",
                human(tree.nodes[0].size),
                tree.elapsed.as_secs_f64(),
                tree.errors,
                tree.links
            ))
            .small()
            .color(p.weak),
        );

        if let Some(n) = nav {
            self.current = n;
        }
        if let Some(a) = ctx_action {
            let ctx = ui.ctx().clone();
            self.apply(a, &ctx);
        }
    }

    fn confirm_dialog(&mut self, ctx: &egui::Context) {
        if !self.confirm_open {
            return;
        }
        let chosen: Vec<(String, String, u64, String)> = self
            .results
            .iter()
            .filter(|r| self.selected.contains(&r.rule.id) && r.cleanable_if_elevated())
            .map(|r| {
                let how = match (r.command_line(), r.uses_command()) {
                    (Some(c), true) => format!("runs {c}"),
                    _ => format!("{} items", r.candidates.len()),
                };
                (r.rule.title.clone(), r.rule.safety.label(), r.estimate(), how)
            })
            .collect();
        let total: u64 = chosen.iter().map(|c| c.2).sum();
        let admin_titles: Vec<String> = self
            .results
            .iter()
            .filter(|r| self.selected.contains(&r.rule.id) && r.cleanable_if_elevated() && r.needs_admin)
            .map(|r| r.rule.title.clone())
            .collect();
        let (mut go, mut cancel) = (false, false);
        let modal = egui::Modal::new(Id::unique("confirm-clean")).show(ctx, |ui| {
            ui.set_width(520.0);
            ui.label(RichText::new(format!("Delete {} permanently?", human(total))).size(18.0).strong());
            ui.label("These files skip the Recycle Bin. Files that are in use are skipped.");
            if !admin_titles.is_empty() {
                ui.label(RichText::new(format!("Windows will ask for administrator permission once, for: {}.", admin_titles.join(", "))).strong());
            }
            ui.add_space(6.0);
            egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                for (title, safety, bytes, how) in &chosen {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("{:>9}", human(*bytes))).monospace());
                        ui.label(format!("{title}  ({safety}, {how})"));
                    });
                }
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button(RichText::new(format!("Delete {}", human(total))).strong()).clicked() {
                    go = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        if modal.should_close() {
            cancel = true;
        }
        if go {
            self.confirm_open = false;
            self.start_clean(ctx);
        } else if cancel {
            self.confirm_open = false;
        }
    }

    /// The question for Claude about one folder, shown in full before it is copied.
    fn ask_dialog(&mut self, ctx: &egui::Context) {
        if self.ask_job.as_ref().is_some_and(|h| h.is_finished()) {
            self.ask_text = self.ask_job.take().and_then(|h| h.join().ok());
        }
        if self.ask_job.is_none() && self.ask_text.is_none() {
            return;
        }
        let mut close = false;
        let modal = egui::Modal::new(Id::unique("ask-claude")).show(ctx, |ui| {
            ui.set_width(640.0);
            ui.label(RichText::new("Ask Claude about this folder").size(18.0).strong());
            let Some(text) = &self.ask_text else {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Looking through the folder ...");
                });
                return;
            };
            ui.label("Copy this and paste it into Claude (claude.ai or Claude Code). Read it first: folder names show which programs are on this PC.");
            ui.add_space(4.0);
            egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
                ui.add(egui::TextEdit::multiline(&mut text.as_str()).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY));
            });
            ui.add_space(4.0);
            ui.label(RichText::new("Claude replies with rules. Save the reply to a file and check it with: linttrap-cli rules check FILE (add --add to use them).").small());
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button(RichText::new("Copy for Claude").strong()).clicked() {
                    ui.ctx().copy_text(text.clone());
                    close = true;
                }
                if ui.button("Close").clicked() {
                    close = true;
                }
            });
        });
        if modal.should_close() || close {
            // A walk still running finishes in the background; its result is dropped.
            self.ask_job = None;
            self.ask_text = None;
        }
    }

    fn run_dialog(&mut self, ctx: &egui::Context) {
        let Some(id) = self.confirm_run.clone() else { return };
        let Some(r) = self.results.iter().find(|r| r.rule.id == id) else {
            self.confirm_run = None;
            return;
        };
        let Some(command) = r.command_line() else {
            self.confirm_run = None;
            return;
        };
        let (title, admin, note, found) = (r.rule.title.clone(), r.rule.admin, r.rule.note.clone(), r.found.clone());
        let (mut go, mut cancel) = (false, false);
        let modal = egui::Modal::new(Id::unique("confirm-run")).show(ctx, |ui| {
            ui.set_width(520.0);
            ui.label(RichText::new(format!("Run the cleanup for {title}?")).size(18.0).strong());
            ui.add_space(4.0);
            ui.label(RichText::new(&command).monospace());
            ui.add_space(4.0);
            ui.label("It opens in its own window so you can watch it. When it has finished, close the window: LintTrap then measures what it freed and remembers it, so next time only new growth counts.");
            if admin && !self.is_admin {
                ui.label("Windows will ask for administrator permission.");
            }
            if let Some(n) = &note {
                ui.label(RichText::new(n).small());
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button(RichText::new("Run").strong()).clicked() {
                    go = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        if modal.should_close() {
            cancel = true;
        }
        if go {
            self.confirm_run = None;
            let ctx2 = ctx.clone();
            let handle = std::thread::spawn(move || {
                let before = rules::measure_all(&found);
                let launched = sys::run_in_console(&command, admin)?;
                launched.wait();
                let after = rules::measure_all(&found);
                rules::History::record(&id, before, after);
                ctx2.request_repaint();
                Ok((before, after))
            });
            self.run_job = Some((title, handle));
            self.last_clean = None;
        } else if cancel {
            self.confirm_run = None;
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll_jobs(&ctx);
        egui::Panel::top("top").show(ui, |ui| {
            ui.add_space(4.0);
            self.top_bar(ui);
            ui.add_space(4.0);
        });
        egui::Panel::right("fluff").resizable(true).default_size(470.0).min_size(360.0).show(ui, |ui| {
            self.fluff_panel(ui);
        });
        egui::CentralPanel::default().show(ui, |ui| {
            self.map_panel(ui);
        });
        self.confirm_dialog(&ctx);
        self.run_dialog(&ctx);
        self.ask_dialog(&ctx);
    }
}
