# LintTrap

A Windows disk cleaner in Rust: a treemap GUI (`linttrap.exe`, `src/main.rs`) and a CLI
(`linttrap-cli.exe`, `src/bin/linttrap-cli.rs`) over one library. What gets cleaned is decided by rules in
`rules/default_rules.toml` plus the user's own `%APPDATA%\LintTrap\rules.toml`. The README has the user-facing
details.

## Teaching LintTrap new rules

When the user asks what is filling their drive, what LintTrap misses, or to "teach" or "train" LintTrap, do it
yourself instead of the copy-and-paste loop in the README:

1. **Find.** `cargo run --release --bin linttrap-cli -- unknown` lists large folders (200 MB+; `--min-mb N`,
   `--limit N`) under AppData, ProgramData and the profile's dot folders that no rule covers, with size, file
   types, ages and subfolders. It takes about a minute. Leave off `--copy`; the output is for you.
2. **Look.** Before writing a rule, look inside the folder: file names, a `README` or `.json` manifest, which
   program's `.exe` is nearby, whether the program has its own cleanup command. Only read: never delete, move
   or rename anything by hand. If you still can't tell what owns a folder, say so and write no rule for it.
3. **Write** the rules to a `.toml` file in your scratchpad. The format is the comment block at the top of
   `rules/default_rules.toml`. Follow the same guidelines Claude gets in `ask::prompt` (`src/ask.rs`):
   - `safe` only when the program rebuilds the contents and nothing is lost (caches, downloaded installers,
     old logs). `review` when it is probably junk but something could be lost. `move` for real data that is just
     big.
   - Never `safe` or `review` for documents, settings, saved games, databases, mail, or anything synced.
   - Put the program's `.exe` names in `processes`; use its own cleanup `command` where it has one.
   - Write paths with `%LOCALAPPDATA%`-style variables, never the user's name.
   - Start every id with `my-`, so a rule never replaces a built-in one.
4. **Check.** `cargo run --release --bin linttrap-cli -- rules check FILE` shows what each rule matches on this
   PC, what Clean would free, and what the safety checks refuse. Fix anything it warns about, especially a rule
   that finds folders but would clean nothing (version folders named by hash, a wrong `prefix`).
5. **Show the user** each rule, what it would free and how sure you are, and ask before keeping them.
   `rules check FILE --add` appends them to the user's `rules.toml`. Don't add without a yes.

Never run `linttrap-cli clean --yes` or click Clean unless the user asks for that specific clean: deletes are
permanent.

A rule that would hold on any PC (no machine-specific paths, a well-known program) can go into
`rules/default_rules.toml` instead, without the `my-` prefix. Offer it; don't do it unasked.

## Working on the code

```
cargo build --release      # target\release\linttrap.exe and linttrap-cli.exe
cargo test --lib
```

- `safety.rs` is the last check on every path before it is measured or deleted, and `clean.rs` re-checks
  just before deleting. Keep both strict: never follow junctions or symlinks, never open cloud
  placeholders, never touch synced folders or profile and system roots.
- `rules.rs` loads and evaluates rules; evaluating only measures. `locate.rs` holds what is specific to this
  PC (`locations.toml`), so the built-in rules hold no machine-specific paths.
- If you change the rule format, update the comment block at the top of `default_rules.toml`: `ask.rs` sends it
  to Claude as the format spec. If you change the guidelines in `ask::prompt`, update step 3 above to match.
- Console output uses `[OK]`, `[INFO]`, `[WARN]`, `[ERROR]`, `[NOTE]`, never emoji.
