//! Command-line front end: survey a drive and (later) report / clean fluff.

use linttrap::ask;
use linttrap::clean::{self, CleanStats};
use linttrap::locate::Locations;
use linttrap::rules::{self, RuleResult, Safety};
use linttrap::scan::{self, human, Kind, Progress, Tree};
use linttrap::sys;
use std::sync::atomic::Ordering;
use std::path::PathBuf;

fn usage() -> ! {
    eprintln!(
        "linttrap-cli - find and clean junk on a drive\n\n\
         USAGE:\n  \
         linttrap-cli tree [ROOT] [--min-mb N] [--depth N]   Largest folders as an indented tree\n  \
         linttrap-cli json [ROOT] [--min-mb N] [--depth N]   Pruned size tree as JSON on stdout\n  \
         linttrap-cli fluff [--all]                          Dry run: what every rule would clean\n  \
         linttrap-cli clean [--rules a,b] [--include-review] [--yes]\n      \
             Clean the 'safe' rules (or the listed ones). Without --yes it only shows the plan.\n      \
             --report FILE writes what was freed as key=value lines.\n  \
         linttrap-cli rules                                  Show where your own rules file lives\n  \
         linttrap-cli locate                                 Ask the tools again where their caches are\n  \
         linttrap-cli unknown [--min-mb N] [--limit N] [--copy]\n      \
             Describe large folders no rule covers, as a question for Claude (default 200 MB, 20 folders)\n  \
         linttrap-cli rules check FILE [--add]\n      \
             Show what the rules in FILE (e.g. Claude's saved reply; - reads stdin) would do here.\n      \
             --add appends them to your rules file.\n"
    );
    std::process::exit(2);
}

fn status_of(r: &RuleResult) -> String {
    if r.dismissed {
        return "dismissed".into();
    }
    if !r.rule.can_clean() {
        return "report only".into();
    }
    if !r.blocked_by.is_empty() {
        return format!("[WARN] close {} first", r.blocked_by.join(", "));
    }
    if r.needs_admin {
        return "[WARN] needs admin".into();
    }
    if r.bytes == 0 {
        return "nothing to clean".into();
    }
    if r.fresh() {
        return "nothing new since the last clean".into();
    }
    if let Some(tool) = r.missing_tool() {
        return if r.rule.action == linttrap::rules::Action::None { format!("[WARN] {tool} not found") } else { format!("ready ({tool} not found: deletes files)") };
    }
    if r.uses_command() {
        return format!("ready (runs: {})", r.command_line().unwrap_or_default());
    }
    "ready".into()
}

fn print_results(results: &[RuleResult], show_all: bool) {
    println!("{:>10}  {:<11} {:<26} {:<44} {}", "SIZE", "SAFETY", "RULE", "TITLE", "STATUS");
    for r in results {
        if !show_all && r.bytes == 0 && r.refused.is_empty() {
            continue;
        }
        println!("{:>10}  {:<11} {:<26} {:<44} {}", human(r.estimate()), r.rule.safety.label(), r.rule.id, r.rule.title, status_of(r));
        if let Some(t) = r.last_run_text() {
            println!("{:>10}  {:<11} {:<26} [INFO] {t}", "", "", "");
        }
        for (p, why) in &r.refused {
            println!("{:>10}  {:<11} {:<26} [SKIP] {} ({})", "", "", "", p.display(), why);
        }
    }
    // Totals count only growth since the last tool-command clean (what is left after a prune is in use).
    let total = |s: Safety| results.iter().filter(|r| r.rule.safety == s && !r.dismissed).map(|r| r.estimate()).sum::<u64>();
    println!();
    println!("[INFO] Safe: {}   Review: {}   {} {}   Leave alone: {}", human(total(Safety::Safe)), human(total(Safety::Review)), Safety::Move.label(), human(total(Safety::Move)), human(total(Safety::Info)));
}

fn print_tree(t: &Tree, idx: u32, depth: usize, max_depth: usize, min_bytes: u64) {
    let n = &t.nodes[idx as usize];
    let pct = if t.nodes[0].size > 0 { n.size as f64 * 100.0 / t.nodes[0].size as f64 } else { 0.0 };
    let flag = if n.unreadable { "  [no access]" } else { "" };
    println!("{:>10}  {:>5.1}%  {}{}{}", human(n.size), pct, "  ".repeat(depth), if depth == 0 { t.root_path.display().to_string() } else { n.name.to_string() }, flag);
    if depth >= max_depth {
        return;
    }
    for &c in &n.children {
        let cn = &t.nodes[c as usize];
        if cn.size < min_bytes {
            break; // children are sorted largest-first
        }
        if cn.kind == Kind::Dir || depth + 1 <= max_depth {
            print_tree(t, c, depth + 1, max_depth, min_bytes);
        }
    }
}

/// Show what pasted rules (e.g. Claude's reply) would do on this PC, and with `add` append them to the user's rules.
fn check_rules(file: &str, add: bool) {
    let text = if file == "-" {
        let mut s = String::new();
        let _ = std::io::Read::read_to_string(&mut std::io::stdin(), &mut s);
        s
    } else {
        std::fs::read_to_string(file).unwrap_or_else(|e| { eprintln!("[ERROR] {file}: {e}"); std::process::exit(1) })
    };
    let toml_text = ask::extract_toml(&text);
    let new = match rules::parse_rules(&toml_text) {
        Ok(r) if !r.is_empty() => r,
        Ok(_) => { eprintln!("[ERROR] No [[rule]] found in {file}."); std::process::exit(1) }
        Err(e) => { eprintln!("[ERROR] The rules could not be read: {e}"); std::process::exit(1) }
    };
    let builtin = rules::builtin_ids();
    let mine: Vec<String> = std::fs::read_to_string(rules::user_rules_path()).ok().and_then(|t| rules::parse_rules(&t).ok()).unwrap_or_default().into_iter().map(|r| r.id).collect();
    let env = rules::Env::detect();
    let mut problems = 0;
    for r in &new {
        println!("\n{}  \"{}\"  (safety {}, action {})", r.id, r.title, r.safety.tag(), format!("{:?}", r.action).to_lowercase());
        if builtin.contains(&r.id) {
            println!("  [WARN] Replaces the built-in rule '{}'. Give it a new id, e.g. my-{}.", r.id, r.id);
            problems += 1;
        }
        if mine.contains(&r.id) {
            println!("  [INFO] Replaces your existing rule '{}'.", r.id);
        }
        for p in r.paths.iter().filter(|p| !p.contains('%') && !p.starts_with("*:")) {
            println!("  [INFO] {p} is written for this PC only; use %VARIABLES% to share the rule.");
        }
        if let Some(c) = &r.command {
            if !sys::on_path(sys::program_of(c)) {
                println!("  [INFO] {} is not installed here, so its command cannot run.", sys::program_of(c));
            }
        }
        let res = rules::evaluate(r, &env);
        if res.found.is_empty() {
            println!("  [INFO] Matches nothing on this PC.");
        }
        for p in &res.found {
            println!("  found {:>10}  {}", human(rules::measure(p, None).0), p.display());
        }
        if r.can_clean() && !res.found.is_empty() {
            println!("  Clean would free about {} ({} items{})", human(res.bytes), res.candidates.len(), if res.uses_command() { ", by running its command" } else { "" });
        } else if !res.found.is_empty() {
            println!("  Report only: {}", human(res.bytes));
        }
        if r.can_clean() && !res.found.is_empty() && res.candidates.is_empty() && res.refused.is_empty() && !res.uses_command() {
            println!("  [INFO] It finds folders but would clean nothing in them; the rule may not fit (e.g. `versions` needs numbered folder names).");
        }
        for (p, why) in &res.refused {
            println!("  [WARN] Refused {}: {why}", p.display());
            problems += 1;
        }
        if !res.blocked_by.is_empty() {
            println!("  [INFO] Waits while {} is running.", res.blocked_by.join(", "));
        }
    }
    println!();
    if !add {
        println!("[INFO] {} rules read. If they look right, add them with: linttrap-cli rules check {file} --add", new.len());
        return;
    }
    if problems > 0 {
        eprintln!("[ERROR] Not added: fix the warnings above first.");
        std::process::exit(1);
    }
    let p = rules::ensure_user_rules_file().unwrap_or_else(|e| { eprintln!("[ERROR] {e}"); std::process::exit(1) });
    let mut body = std::fs::read_to_string(&p).unwrap_or_default();
    body.push_str(&format!("\n# Added with linttrap-cli rules check\n{}\n", toml_text.trim()));
    match std::fs::write(&p, body) {
        Ok(()) => println!("[OK] Added {} rules to {}", new.len(), p.display()),
        Err(e) => { eprintln!("[ERROR] {e}"); std::process::exit(1); }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else { usage() };
    let mut root = PathBuf::from("C:\\");
    let mut min_mb: Option<u64> = None;
    let mut depth = 6usize;
    let (mut show_all, mut yes, mut include_review) = (false, false, false);
    let (mut copy, mut add) = (false, false);
    let mut limit = 20usize;
    let mut only: Option<Vec<String>> = None;
    let mut report: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--min-mb" => { i += 1; min_mb = Some(args.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| usage())); }
            "--depth" => { i += 1; depth = args.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| usage()); }
            "--all" => show_all = true,
            "--yes" => yes = true,
            "--include-review" => include_review = true,
            "--copy" => copy = true,
            "--add" => add = true,
            "--limit" => { i += 1; limit = args.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| usage()); }
            "--report" => { i += 1; report = Some(PathBuf::from(args.get(i).unwrap_or_else(|| usage()))); }
            "--rules" => { i += 1; only = Some(args.get(i).unwrap_or_else(|| usage()).split(',').map(|s| s.trim().to_string()).collect()); }
            s if !s.starts_with("--") => root = PathBuf::from(s),
            _ => usage(),
        }
        i += 1;
    }
    match cmd.as_str() {
        "tree" => {
            let prog = Progress::default();
            eprintln!("[INFO] Scanning {} ...", root.display());
            let t = scan::scan(&root, &prog);
            eprintln!(
                "[INFO] {} in {} files, {} folders, {:.1}s. Unreadable folders: {}, links skipped: {}, cloud placeholders: {}",
                human(t.nodes[0].size),
                t.nodes[0].files,
                prog.dirs.load(std::sync::atomic::Ordering::Relaxed),
                t.elapsed.as_secs_f64(),
                t.errors,
                t.links,
                t.placeholders
            );
            print_tree(&t, 0, 0, depth, min_mb.unwrap_or(500) * 1024 * 1024);
        }
        "json" => {
            let prog = Progress::default();
            eprintln!("[INFO] Scanning {} ...", root.display());
            let t = scan::scan(&root, &prog);
            let min = min_mb.unwrap_or(500) * 1024 * 1024;
            let mut out = String::new();
            out.push_str(&format!(
                "{{\"root\":{},\"scanned\":{},\"secs\":{:.1},\"errors\":{},\"links\":{},\"placeholders\":{},\"tree\":",
                json_str(&t.root_path.display().to_string()),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                t.elapsed.as_secs_f64(),
                t.errors,
                t.links,
                t.placeholders
            ));
            write_json(&t, 0, 0, depth, min, &mut out);
            out.push('}');
            println!("{out}");
            eprintln!("[OK] {} total, scan {:.1}s", human(t.nodes[0].size), t.elapsed.as_secs_f64());
        }
        "rules" if args.get(1).is_some_and(|a| a == "check") => {
            let file = args.get(2).filter(|f| !f.starts_with("--")).unwrap_or_else(|| usage());
            check_rules(file, add);
        }
        "rules" => match rules::ensure_user_rules_file() {
            Ok(p) => println!("[OK] Your rules: {}\n[INFO] Built-in rules for reference: {}", p.display(), p.with_file_name("rules.builtin.toml").display()),
            Err(e) => { eprintln!("[ERROR] {e}"); std::process::exit(1); }
        },
        "unknown" => {
            let min = min_mb.unwrap_or(200) * 1024 * 1024;
            let (all_rules, warnings) = rules::load_rules();
            for w in warnings { eprintln!("[WARN] {w}"); }
            let env = rules::Env::detect();
            eprintln!("[INFO] Measuring {} rules ...", all_rules.len());
            let results = rules::evaluate_all(&all_rules, &env);
            eprintln!("[INFO] Looking for folders over {} that no rule covers ...", human(min));
            let folders = ask::unknown_folders(&results, &env.dismissed, min);
            if folders.is_empty() {
                println!("[OK] No folder over {} is left that no rule covers.", human(min));
                return;
            }
            let shown = &folders[..folders.len().min(limit)];
            eprintln!("[INFO] Describing {} folders ...", shown.len());
            let listed: Vec<PathBuf> = shown.iter().map(|(p, _)| p.clone()).collect();
            let profiles: Vec<ask::Profile> = listed.iter().map(|p| ask::profile(p, &listed)).collect();
            let text = ask::prompt(&profiles);
            println!("{text}");
            eprintln!();
            if folders.len() > shown.len() { eprintln!("[INFO] {} more folders not included; raise --limit to add them.", folders.len() - shown.len()); }
            eprintln!("[NOTE] Read the text above before sharing it: folder names show which programs are on this PC.");
            if copy {
                match sys::copy_to_clipboard(&text) {
                    Ok(()) => eprintln!("[OK] Copied. Paste it into Claude, save the reply to a file, then run: linttrap-cli rules check FILE"),
                    Err(e) => { eprintln!("[ERROR] {e}"); std::process::exit(1); }
                }
            } else {
                eprintln!("[INFO] Add --copy to put it on the clipboard for Claude.");
            }
        }
        "locate" => {
            let (all_rules, warnings) = rules::merged_rules();
            for w in warnings { eprintln!("[WARN] {w}"); }
            eprintln!("[INFO] Asking the installed tools where their caches are ...");
            let loc = Locations::scan_and_save(&all_rules).unwrap_or_else(|e| { eprintln!("[ERROR] {e}"); std::process::exit(1) });
            println!("[OK] Saved {}", Locations::file().display());
            println!("[INFO] Move items to: {}", loc.move_to.as_deref().unwrap_or("(no drive has more free space than the system drive)"));
            for (id, paths) in &loc.paths {
                for p in paths { println!("  {id:<20} {p}"); }
            }
        }
        "fluff" | "clean" => {
            let (all_rules, warnings) = rules::load_rules();
            for w in warnings { eprintln!("[WARN] {w}"); }
            let env = rules::Env::detect();
            if !env.is_admin { eprintln!("[INFO] Not running as administrator: rules marked 'needs admin' are measured but not cleaned."); }
            eprintln!("[INFO] Measuring {} rules ...", all_rules.len());
            let results = rules::evaluate_all(&all_rules, &env);
            if cmd == "fluff" {
                print_results(&results, show_all);
                return;
            }
            // clean
            if let Some(ids) = &only {
                for id in ids {
                    if !results.iter().any(|r| &r.rule.id == id) { eprintln!("[ERROR] No rule with id '{id}'"); std::process::exit(2); }
                }
            }
            let chosen: Vec<&RuleResult> = results.iter().filter(|r| {
                let selected = match &only { Some(ids) => ids.iter().any(|id| id == &r.rule.id), None => r.rule.safety == Safety::Safe || (include_review && r.rule.safety == Safety::Review) };
                selected && r.rule.can_clean()
            }).collect();
            // Rules cleaned recently with little added since are skipped, unless named with --rules.
            let skip_fresh = |r: &RuleResult| only.is_none() && r.fresh();
            let ready: Vec<&RuleResult> = chosen.iter().copied().filter(|r| r.cleanable() && !skip_fresh(r)).collect();
            for r in chosen.iter().filter(|r| (!r.cleanable() || skip_fresh(r)) && r.bytes > 0) {
                println!("[SKIP] {:<26} {:>10}  {}", r.rule.id, human(r.estimate()), status_of(r));
            }
            let planned: u64 = ready.iter().map(|r| r.estimate()).sum();
            for r in &ready {
                let how = if r.uses_command() { format!("runs: {}", r.command_line().unwrap_or_default()) } else { format!("{} items", r.candidates.len()) };
                println!("[PLAN] {:<26} {:>10}  {} ({how})", r.rule.id, human(r.estimate()), r.rule.title);
            }
            println!("[INFO] Planned: {}", human(planned));
            if !yes { println!("[INFO] Dry run. Add --yes to delete."); return; }
            let st = CleanStats::default();
            for r in &ready {
                let before = st.freed();
                clean::clean_all(std::slice::from_ref(*r), &env.guard, &st, &|| {});
                println!("[DONE] {:<26} freed {}", r.rule.id, human(st.freed() - before));
            }
            if let Ok(v) = st.skipped_rules.lock() {
                for s in v.iter() { println!("[SKIP] {s}"); }
            }
            println!("[OK] Freed {} in {} files. Kept (too recent): {}. Could not delete: {}. Links left alone: {}.",
                human(st.freed()), st.files.load(Ordering::Relaxed), st.kept_recent.load(Ordering::Relaxed), st.failed.load(Ordering::Relaxed), st.skipped_links.load(Ordering::Relaxed));
            if let Ok(errs) = st.first_errors.lock() { for e in errs.iter() { println!("[WARN] {e}"); } }
            if let Some(path) = &report {
                // Read back by the GUI after an elevated clean.
                let mut out = format!(
                    "freed={}\nfiles={}\nkept_recent={}\nfailed={}\nskipped_links={}\n",
                    st.freed(), st.files.load(Ordering::Relaxed), st.kept_recent.load(Ordering::Relaxed), st.failed.load(Ordering::Relaxed), st.skipped_links.load(Ordering::Relaxed)
                );
                if let Ok(v) = st.skipped_rules.lock() { for s in v.iter() { out.push_str(&format!("skipped={s}\n")); } }
                if let Ok(v) = st.first_errors.lock() { for e in v.iter() { out.push_str(&format!("error={e}\n")); } }
                let _ = std::fs::write(path, out);
            }
        }
        _ => usage(),
    }
}

fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for ch in s.chars() {
        match ch {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// Emit a pruned tree: children below `min` bytes are folded into one "[smaller items]" node.
fn write_json(t: &Tree, idx: u32, depth: usize, max_depth: usize, min: u64, out: &mut String) {
    let n = &t.nodes[idx as usize];
    let k = match n.kind { Kind::Dir => "d", Kind::File => "f", Kind::SmallFiles => "s" };
    let name = if depth == 0 { t.root_path.display().to_string() } else { n.name.to_string() };
    out.push_str(&format!("{{\"n\":{},\"s\":{},\"f\":{},\"k\":\"{}\",\"m\":{}", json_str(&name), n.size, n.files, k, n.newest));
    if n.unreadable {
        out.push_str(",\"u\":1");
    }
    if depth < max_depth && !n.children.is_empty() {
        out.push_str(",\"c\":[");
        let mut first = true;
        let (mut rest_s, mut rest_f, mut rest_n) = (0u64, 0u64, 0u32);
        for &c in &n.children {
            let cn = &t.nodes[c as usize];
            if cn.size >= min {
                if !first { out.push(','); }
                first = false;
                write_json(t, c, depth + 1, max_depth, min, out);
            } else {
                rest_s += cn.size;
                rest_f += cn.files;
                rest_n += 1;
            }
        }
        if rest_n > 0 && rest_s > 0 {
            if !first { out.push(','); }
            out.push_str(&format!("{{\"n\":\"[{rest_n} smaller items]\",\"s\":{rest_s},\"f\":{rest_f},\"k\":\"o\"}}"));
        }
        out.push(']');
    }
    out.push('}');
}
