# LintTrap

A disk-space treemap for Windows that also finds the junk ("fluff") filling your drives and cleans it safely.

- **Treemap**: click a box to zoom in, use the breadcrumbs or the mouse Back button to go back up, right-click for Explorer / copy path / never flag.
- **Fluff list**: rules flag caches, temp files, old app versions, browser AI models and more. Each item is marked:
  - **Safe**: rebuilt automatically, ticked for cleaning by default
  - **Review**: probably junk, never ticked by default
  - **Move to D:**: real data that belongs on the drive with the most free space (report only; the drive is
    chosen on the first run, and the label reads "Move off C:" when no other drive has more room)
  - **Leave alone**: use the Windows tool shown instead (report only)
- **Tool commands**: where a tool has its own cleanup (`pnpm store prune`, `conda clean`, `uv cache clean`, DISM ...),
  Clean runs that instead of deleting files (`use_command = true` in the rule), and every command has a **Run**
  button that opens it in its own window after asking.
- **Last cleaned**: each tool-command run (Clean, or Run once its window is closed) is remembered in
  `%APPDATA%\LintTrap\history.toml`. What a prune leaves is in use, so afterwards the item shows
  "Cleaned today, freed X. Nothing new since." and only growth counts: it is not ticked or counted until it has
  grown by 100 MB, and `linttrap-cli clean` skips it unless named with `--rules`.
- **Old versions**: keeps the newest version folder per app (Squirrel apps, JetBrains) and the newest version of each
  driver; old drivers are removed with `pnputil /delete-driver`, which refuses any driver a device still uses.
- **Dismiss**: hide a false positive (a whole rule, or a single path). Stored in `%APPDATA%\LintTrap\dismissed.toml`; undo it under *Dismissed* at the bottom of the list.

## Safety

- Deletes are permanent (the Recycle Bin on the same drive would not free any space), always after a confirmation.
- Never follows or deletes junctions or symlinks; never touches cloud placeholders (OneDrive / Dropbox / Google Drive "online-only" files).
- Refuses anything inside a cloud-synced folder, and any system or profile root.
- Every path is re-checked just before deletion and must stay inside its rule's folder.
- Files in use are skipped; rules with a `processes` list are skipped while those programs run.
- Temp rules only delete files older than their `min_age_days`.

## Command line

```
linttrap-cli fluff                      dry run: what every rule would clean
linttrap-cli clean                      plan for the 'safe' rules (add --yes to delete)
linttrap-cli clean --rules npm-cache,uv-cache --yes
linttrap-cli clean --include-review --yes
linttrap-cli tree C:\ --min-mb 500      largest folders as text
linttrap-cli rules                      where your own rules file lives
linttrap-cli locate                     ask the tools again where their caches are
linttrap-cli unknown --copy             large folders no rule covers, as a question for Claude
linttrap-cli rules check reply.md       what the rules in Claude's reply would do here (--add to keep them)
```

## Rules

Built-in rules are in `rules/default_rules.toml` (the format is documented at the top). They hold no paths
specific to one PC: they use `%ENV%` variables, `*:\` for "every fixed drive", and the catch-all
`app-web-caches` rule, which picks up the caches of Chromium-based apps no other rule covers.

On the first run LintTrap asks the installed tools where their caches are (`uv cache dir`,
`conda config --show pkgs_dirs`, ...) and picks the drive with the most free space for "move" items. The answers
are saved in `%APPDATA%\LintTrap\locations.toml`; edit it, or run `linttrap-cli locate` (or delete the file) to
look again.

A few rules search every drive at any depth (`*:\**\node_modules`), skipping Windows, Program Files,
ProgramData, `.git` and cloud folders. They are all *Review*, so nothing is ticked:

- `__pycache__` folders that hold only `.pyc` files git doesn't track. Python rebuilds them; set
  `PYTHONPYCACHEPREFIX` to gather them in one folder (a *Safe* rule) so they stop coming back.
- `node_modules` and Python venvs of git projects (not app clones in AppData or `.claude`-style folders) where nothing in the repo
  has changed for 90 days. `npm install` or `uv sync` brings them back.

Add or override rules in `%APPDATA%\LintTrap\rules.toml`; a rule with the same `id` replaces the built-in one,
and `enabled = false` turns it off. Folders that only exist on your PC belong there.

## Teaching LintTrap with Claude

LintTrap only flags folders a rule knows about. For the rest, Claude can write the rules:

1. **Ask.** `linttrap-cli unknown --copy` finds large folders (200 MB+) under AppData, ProgramData and the
   profile's dot folders that no rule covers. It describes each one (size, file types, ages, subfolders) and
   copies the description to the clipboard with instructions and the rule format. In the GUI, right-click a folder
   in the treemap and choose *Ask Claude about this folder*. Paths are written as `%LOCALAPPDATA%\...`, not with
   your user name, but folder names still show which programs you have: read the text before you paste it.
2. **Paste** it into Claude (claude.ai or Claude Code) and save the reply to a file.
3. **Check.** `linttrap-cli rules check reply.md` reads the rules out of the reply and shows, for each one, which
   folders it matches here, what Clean would free, and what the safety checks refuse. It warns when a rule would
   replace a built-in one or finds folders but would clean nothing.
4. **Keep.** `linttrap-cli rules check reply.md --add` appends them to your `rules.toml`; it refuses while
   there are warnings. Rules that work well on other PCs are worth sending back for the built-in list.

With Claude Code you can skip the copying: open it in this folder and ask it to teach LintTrap about your PC.
`CLAUDE.md` tells it to run `unknown`, look inside the folders itself, check its rules with `rules check`, and ask
you before adding them.

## Build

```
cargo build --release      # target\release\linttrap.exe (GUI) and linttrap-cli.exe
cargo test --lib
```

## License

MIT. See [LICENSE](LICENSE).
