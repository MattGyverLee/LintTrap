# Contributing to LintTrap

## Rules

LintTrap only flags folders a rule knows about, and nobody has every program installed. Rules that work on
your PC are the most useful thing to send back.

**From LintTrap.** Your own rules (from `%APPDATA%\LintTrap\rules.toml`) have a *Suggest for LintTrap*
button in the fluff list. It shows the rule and what it found on your PC, then opens the issue form below in
your browser, filled in. For a folder you have no rule for, right-click it in the treemap, choose *Ask Claude
about this folder*, then *Report on GitHub*.

**Through an issue.** Use the [*Suggest a cleanup rule*](https://github.com/MattGyverLee/LintTrap/issues/new?template=new-rule.yml)
form: paste the rule, the output of `linttrap-cli rules check FILE`, and what owns the folder. If you found a big
folder but have no rule for it, use [*Report a folder LintTrap misses*](https://github.com/MattGyverLee/LintTrap/issues/new?template=missed-folder.yml).

**Through a pull request.** Add the rule to `rules/default_rules.toml`, in the section it belongs to. The format
is the comment block at the top of that file. Run `cargo test --lib` and `linttrap-cli rules check` on the
rule before you open the PR, and put the check output in the description.

A built-in rule has to be right on any PC:

- `safe` only when the program rebuilds the contents and nothing is lost (caches, downloaded installers, old
  logs). `review` when it is probably junk but something could be lost. `move` for real data that is just big.
- Never `safe` or `review` for documents, settings, saved games, databases, mail, or anything synced.
- Put the program's `.exe` names in `processes`, and its own cleanup `command` where it has one.
- Write paths with `%LOCALAPPDATA%`-style variables, `*:\` for every fixed drive, never a user name or a path
  only your PC has. Those belong in your own `%APPDATA%\LintTrap\rules.toml`.
- Ids have no `my-` prefix; that is for your own rules.
- If you are not sure what owns a folder, report it as a missed folder rather than guessing a rule.

## Code

```
cargo build --release
cargo test --lib
```

`safety.rs` and `clean.rs` are the last checks before anything is deleted; changes there need a clear reason
and tests. Console output uses `[OK]`, `[INFO]`, `[WARN]`, `[ERROR]`, `[NOTE]`, never emoji.
