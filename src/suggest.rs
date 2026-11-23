//! Sending a rule or a missed folder back for the built-in list, as a GitHub issue the user reads and submits.
//! Nothing is sent from here: the issue form opens in the browser, filled in.

use crate::ask;
use crate::rules::{self, RuleResult};
use crate::scan::human;
use std::fs;
use std::path::Path;

pub const REPO: &str = env!("CARGO_PKG_REPOSITORY");

/// GitHub refuses longer URLs; long fields are cut to stay under this.
const MAX_URL: usize = 7500;

/// The user's own rule `id` from their rules.toml, as TOML for the built-in list (without the `my-` prefix).
pub fn user_rule_toml(id: &str) -> Option<String> {
    let text = fs::read_to_string(rules::user_rules_path()).ok()?;
    rule_toml_from(&text, id)
}

fn rule_toml_from(text: &str, id: &str) -> Option<String> {
    let file: toml::Table = toml::from_str(text).ok()?;
    let mut rule = file.get("rule")?.as_array()?.iter().filter_map(|r| r.as_table()).find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))?.clone();
    rule.insert("id".into(), toml::Value::String(id.strip_prefix("my-").unwrap_or(id).to_string()));
    rule.remove("enabled");
    let mut out = toml::Table::new();
    out.insert("rule".into(), toml::Value::Array(vec![toml::Value::Table(rule)]));
    toml::to_string(&out).ok()
}

/// What stops a rule going into the built-in list as it is. `paths` are the ones written in the rule, before
/// locations.toml adds this PC's.
pub fn problems(paths: &[String], r: &RuleResult) -> Vec<String> {
    let mut out = Vec::new();
    for p in paths.iter().filter(|p| !p.contains('%') && !p.starts_with("*:")) {
        out.push(format!("{p} is written for this PC only; use %VARIABLES% so it holds on other PCs."));
    }
    if r.found.is_empty() {
        out.push("It matches nothing on this PC, so there is nothing to show that it works.".into());
    }
    for (p, why) in &r.refused {
        out.push(format!("The safety checks refuse {}: {why}", ask::pretty(p)));
    }
    out
}

/// What the rule does on this PC, like `linttrap-cli rules check`, with paths written as %VARIABLES%.
pub fn check_summary(r: &RuleResult) -> String {
    let id = r.rule.id.strip_prefix("my-").unwrap_or(&r.rule.id);
    let mut s = format!("{id}  \"{}\"  (safety {}, action {})\n",r.rule.title, r.rule.safety.tag(), format!("{:?}", r.rule.action).to_lowercase());
    for p in r.found.iter().take(20) {
        s.push_str(&format!("  found  {}\n", ask::pretty(p)));
    }
    if r.found.len() > 20 {
        s.push_str(&format!("  ... and {} more\n", r.found.len() - 20));
    }
    if r.rule.can_clean() && !r.found.is_empty() {
        s.push_str(&format!("  Clean would free about {} ({} items{})\n", human(r.bytes), r.candidates.len(), if r.uses_command() { ", by running its command" } else { "" }));
    } else if !r.found.is_empty() {
        s.push_str(&format!("  Report only: {}\n", human(r.bytes)));
    }
    if !r.blocked_by.is_empty() {
        s.push_str(&format!("  Waits while {} is running.\n", r.blocked_by.join(", ")));
    }
    s.push_str(&format!("LintTrap {}", env!("CARGO_PKG_VERSION")));
    s
}

/// The new-issue page for `template`, with the form's fields filled in. Fields are cut, longest first,
/// when the URL would be too long for GitHub.
pub fn issue_url(template: &str, fields: &[(&str, String)]) -> String {
    let mut fields: Vec<(&str, String)> = fields.to_vec();
    loop {
        let mut url = format!("{REPO}/issues/new?template={}", encode(template));
        for (k, v) in &fields {
            url.push_str(&format!("&{k}={}", encode(v)));
        }
        let Some(longest) = fields.iter_mut().max_by_key(|(_, v)| v.len()) else { return url };
        if url.len() <= MAX_URL || longest.1.len() < 200 {
            return url;
        }
        let keep = longest.1.floor_char_boundary(longest.1.len() * 2 / 3);
        longest.1.truncate(keep);
        longest.1.push_str("\n... (cut to fit)");
    }
}

/// The issue for one of the user's rules.
pub fn rule_issue_url(rule_toml: &str, r: &RuleResult) -> String {
    let title = format!("Rule: {}", r.rule.title);
    issue_url("new-rule.yml", &[("title", title), ("rule", rule_toml.trim().to_string()), ("check", check_summary(r))])
}

/// The issue for a big folder no rule covers.
pub fn missed_folder_url(path: &Path, description: &str) -> String {
    let title = format!("Missed: {}", ask::pretty(path));
    issue_url("missed-folder.yml", &[("title", title), ("unknown", description.trim().to_string())])
}

/// Percent-encode for a URL query value.
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_query_values() {
        assert_eq!(encode("a b&c=%\\é"), "a%20b%26c%3D%25%5C%C3%A9");
    }

    #[test]
    fn takes_the_users_rule_without_its_prefix() {
        let text = "[[rule]]\nid = \"other\"\ntitle = \"x\"\nsafety = \"safe\"\naction = \"contents\"\npaths = []\n\n\
                    [[rule]]\nid = \"my-foo\"\ntitle = \"Foo cache\"\nsafety = \"safe\"\naction = \"contents\"\npaths = ['%LOCALAPPDATA%\\Foo\\Cache']\nenabled = true\n";
        let t = rule_toml_from(text, "my-foo").unwrap();
        assert!(t.contains("[[rule]]"));
        assert!(t.contains("id = \"foo\""));
        assert!(t.contains("Foo cache"));
        assert!(!t.contains("enabled"));
        assert!(rules::parse_rules(&t).unwrap()[0].paths[0].ends_with(r"Foo\Cache"));
        assert!(rule_toml_from(text, "my-bar").is_none());
    }

    #[test]
    fn long_fields_are_cut_to_fit_a_url() {
        let url = issue_url("new-rule.yml", &[("title", "Rule: x".into()), ("check", "found  %LOCALAPPDATA%\\x\n".repeat(2000))]);
        assert!(url.len() <= MAX_URL);
        assert!(url.contains("cut%20to%20fit"));
        assert!(url.starts_with(&format!("{REPO}/issues/new?template=new-rule.yml&title=Rule%3A%20x&check=")));
    }
}
