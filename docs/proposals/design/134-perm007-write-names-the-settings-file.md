<!-- SPDX-License-Identifier: MIT -->
# 134 — `PERM-007` fired high on scripts that read a Claude settings file and write some other file: 118 of 136 findings on public status line scripts

- **Source**: P-133's measurement (PR #159), 2026-11-17; the maintainer decided that this lands before P-133's
  every-rule reading of the scripts settings helpers name (P-133 Open question 1)
- **Depends on**: none. Moves `rulesEpoch` 19 → 20 and builds rules version `cbaa8a115ff1`, as P-133's branch does
  (neither changes `builtinRules()`); P-133 waits for this one and moves on after it
- **Branch**: `p/134-perm007-write-names-the-settings-file`

## Problem

`PERM-007` ("Writes Claude Code's permission settings file", high) has two halves. The line half needs a write verb right
before the file name. The file-level half (P-016, widened by P-124) closes when a script has a line that **names** a
Claude settings file (`settings.json`, `settings.local.json` under `.claude`, or `.claude.json`) and is not a read
(`settingsReadRE`: `cat`, `jq`, `grep`, `<`, `.read_text(` …), and a line that **writes any file**. It does not ask
whether the file written is the file named.

P-133 measured what that costs on code that reads the settings to show them. 1,100 public status line scripts that
mention `transcript_path`, each placed where `main` reads it with every rule (`~/.claude/statusline.<ext>`, a loose
script under the root): 159 carry a high, and `PERM-007` accounts for 136 findings in 125 of them, 106 with no other
high. 118 of the 136 are the file-level half, and every one read is a status line that names a settings file in order
to read it — an assignment later only read, a `jq … "$HOME/.claude.json"` (the read pattern looks for the word
`settings`), a `for f in "$HOME/.claude/settings.json" …`, a help string — and writes a cache file somewhere else.
The other 18 are the line half on test files the search picked up, which write a fixture settings file.

The corpus shows the same shape. Of the 21 `PERM-007` findings on `main` (`5de9737`), 17 are the file-level half on
benign samples: a help string or a comment naming the file and an unrelated write, a `for` loop or a `return` naming it,
a parameter default. One is the malicious target the half was written for: `p = pathlib.Path.home() / ".claude" /
"settings.local.json"` then `p.write_text(…)`.

## Initial direction

Ask the half the question its title asks: is the named file the one written? Follow the name one level in the same
file, as `FS-005`'s file-level half does (P-092): the naming line assigns the path to a name, and a later line writes
through that name. One line that both names the file and writes stays as P-124 made it.

## Decisions

1. **The two-line half follows a name, one level.** A naming line (as before: `settingsFileRE`, not `settingsReadRE`)
   that **assigns** — shell `NAME=…` (with `export`, `local`, `readonly`, `declare`), Python `name = …` (an annotation
   and `self.x` included), Node `const|let|var name = …` — starts a name. A **later** line closes the finding when it
   writes **through that name** (`writesName`):
   - shell: a redirect (`>`, `>>`, `>|`) or `tee` into `"$NAME"`/`${NAME}`, `mv`/`cp`/`install` with it as the target,
     `sponge`;
   - Python: `name.write_text(`/`write_bytes(`, `name.open("w")`, `open(name, "w")` and `open(str(name), "w")`,
     `os.replace`/`os.rename`/`shutil.move|copy|copy2|copyfile` onto it, `x.replace(name)`;
   - Node: `writeFile`, `writeFileSync`, `appendFile`, `createWriteStream` (and fs-extra's `outputFile`, `writeJson`)
     of it; `rename`, `copyFile`, `move` onto it.

   `$NAME.tmp` is another file. The finding cites the assigning line and the writing line, in that order.
2. **A name assigned again ends** — unless the new value is still named like a settings file (`settingsBaseRE`:
   `settings.json`, `settings.local.json`, `.claude.json` without the `.claude` context `settingsFileRE` asks for).
   `path` is reused across functions in real scripts; brainbox's installer reads `join(homedir(), ".claude",
   "settings.json")` in one function and writes `join(claudeDir, "settings.json")` under the same name in the next.
   That exception only keeps a name; it never starts one.
3. **One line that names the file and writes it** closes as P-124 made it, reading the write in code only
   (`writesItself`): a shell redirect or `tee` on the line is the line rule's when it targets the settings file
   (PERM-007's own pattern has `>`/`tee` right before the name), and writes another file otherwise —
   `echo "see ~/.claude/settings.json" >> "$LOG"` names the file in the text it logs.
4. **Not followed** (pinned in `TestPERM007_OneLevelOnly`): the name handed to a function that writes, copied into a
   second name, or a path a function returns; a path in an object property or a `for` list; a path handed to another
   program (`python3 - "$PROJECT/.claude/settings.local.json"`). Each closed the half before, together with every
   script that read the file and wrote a cache. The measurement (below) found real code of each of these shapes that
   does write Claude's settings — installers that register an MCP server in `~/.claude.json` — and no malicious sample.
5. **Same ID, title and severity** (high, dimension 2). The line half and `settingsFileRE`/`settingsReadRE` do not
   change. `rulesEpoch` 19 → 20.

## Done criteria

- [x] `TestPERM007_WriteThroughTheName` (`internal/detect/perm007_name_test.go`), 13 rows, all high: redirect, append
  through braces, `tee`, `cp`, `os.replace`, `Path.replace`, `name.open("w")`, an attribute name, `renameSync`,
  `createWriteStream`, a name reassigned to a settings file under a directory variable (brainbox), a name reassigned to
  another settings path.
- [x] `TestPERM007_ReadThenWriteElsewhere`, 12 rows, quiet: the status line shapes (an assignment read later, a
  `jq … "$HOME/.claude.json"`, a `for` loop, a default for an override variable, a help line), a Python read and a
  Node read with another file written, a parameter default, an object property, a message logged into a file, a
  generic name reassigned before the write (Python and shell).
- [x] `TestPERM007_OneLevelOnly`, 3 rows, quiet and pinned: a helper function, a second name, a returned path.
- [x] `TestPERM007_CitesTheNameAndTheWrite`: the assigning line, then the writing line — not the first write of the
  file.
- [x] **Reverse**: every P-016 and P-124 row (`TestDetect_PermissionFileRewrite`,
  `_OnOneLine`, `_OneLineCitesItOnce`, `_InAHookCommand`, `TestWritesAFile`) passes unchanged; the corpus's malicious
  `mal-hook-userpromptsubmit-perm-rewrite` keeps `PERM-007`.
- [x] Static over the corpus and the held-out ClawHub set, `main` against the branch; the 1,100 public status line
  scripts P-133 gathered; the 1,425 public hook stages P-128 gathered; the 721 public settings files P-133 gathered
  (Measured).
- [x] `rulesEpoch` 19 → 20; `make docs`; `.claude/rules/detect.md`; `make verify` green; `go.mod` line 2 is
  `go 1.23.5` and `go version` does not switch toolchains.

## Out of scope

- The line half. It reads a `>` in `<your-cwd>/.claude/settings.json` (help text) as a redirect into the file: one such
  finding is in the hook sample, on both sides.
- Following further than one level (decision 4), and `settingsFileRE`'s own reach (a name built as
  `join(claudeDir, "settings.json")` does not start a name).
- P-133 (PR #159): it waits for this proposal, by its Open question 1's decision, and re-measures on top of it.

## Must not claim

- Not that `PERM-007` now catches every write of Claude's settings: decision 4's shapes are not followed, and real
  installers written that way are no longer reported (Measured).
- Not a recall change: no malicious sample in the corpus or the held-out set moved.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | The draft | `proposals: P-134 draft, PERM-007's file-level half asks whether the named file is the one written (P-134)` |
| 2 | Tests first, then the name leg (`permfile.go`, `scanUnits`), `rulesEpoch` 20, regenerated `docs/rules.md` | `detect: PERM-007's file-level half follows the settings path one level (P-134)` |
| 2a | A reassigned name ends (found reading the status line scripts) | `detect: a name assigned again is no longer the settings path (P-134)` |
| 2b | … unless it is still a settings-named file (found in the corpus run) | `detect: a name assigned another settings-named file keeps it (P-134)` |
| 3 | `.claude/rules/detect.md` | `docs: PERM-007's file-level half follows the name it assigns (P-134)` |
| 4 | The static runs | `baselines: P-134 static runs, main and branch, corpus and held-out ClawHub (P-134)` |
| 5 | Design and measurement | `proposals: P-134 design and measured (P-134)` |
| 6 | The two answers. The file stays in `design/` until the maintainer says ship it; the move to `complete/`, the Done block and the index row come then | `proposals: P-134 open questions decided (P-134)` |

## Open questions

Both asked at once (2026-11-17), each with a recommended answer. The maintainer took both recommendations the same day
("all as recommended", relayed by the session that started this one).

1. **Installers that write `~/.claude.json` through a returned path or an object property** (decision 4) are no
   longer reported: five benign corpus samples and five of the real hooks (Measured). Recommended: accept it. The
   half reached them only because it accepted any write — on two of the five corpus samples it cited a docstring or a
   backup copy as the write — and following a returned path, a property or a helper's parameter is a reading of the
   language that FS-005 and P-061 also decline. A malicious script written that way is the miss to name; none is in the
   corpus or the held-out set.
   **Decided (2026-11-17)**: accepted. Installers that write `~/.claude.json` through a returned path, an object
   property, a helper's parameter or another program are no longer reported.
2. **A test file that writes a fixture settings file** under a temporary home still gets `PERM-007` high (eight of
   the status line sample, and test files in the hook sample). Recommended: keep; it does write a file of that name,
   and telling a fixture from the real one is a guess about the path.
   **Decided (2026-11-17)**: kept high.

## Measured

**Before the change** (`main` at `5de9737`, the test file alone): of the 10 write-through rows, 8 passed (any write
closed the half) and `cp` and `createWriteStream` failed (not a write to the old leg); all 10 read-then-write-elsewhere
rows and all 3 one-level rows fired, which the rows forbid; the citation test failed (the first write of the file was
cited). Rows added after a reading failed before the change that answered them: the two reassignment rows (status line
scripts) and the brainbox row (corpus run).

**Static runs**, threshold high, corpus `c314e4d9` (5,272 samples) and the held-out ClawHub list (118 malicious, 208
benign, layer 2): `main` at `5de9737` (`rules=2997414a2a16`) against `fd8f820` (`rules=cbaa8a115ff1`),
`baselines/results/aguard/2026-11-17-p134-{corpus,heldout}-{main,changed}`; `compare.txt` lists every sample carrying
`PERM-007` on either side.

| | n | main | P-134 |
|---|---:|---:|---:|
| malicious, flagged high | 719 | 231 | 231 |
| benign, flagged high | 4,534 | 342 | **337** |
| hard negatives, flagged high | 19 | 4 | 4 |
| held-out ClawHub malicious | 118 | 66 | 66 |
| held-out ClawHub benign | 208 | 6 | 6 |

Per sample: no rule but `PERM-007` moved anywhere. Corpus samples carrying `PERM-007`: 14 → 7. The seven that lost it
are benign; five of them had no other high: `guaardvark` (`return Path(…) / ".claude.json"`, a docstring line cited as
the write), `capability-gateway` (a `for` list naming `~/.claude.json`), `hermes-atlas` (an object property, then
`writeFileSync(filePath, …)`), `preflight` (a `return`, then `open(tmp, "w")`), `hollow-agentos` (`SETTINGS=…`, then a
Python heredoc writing `path`); the other two keep other highs (`jevmem`'s help string; `open-computer-skills`'s
`merge_json(home / ".claude.json", …)`). Five of the seven are installers that do write Claude's configuration
through a shape decision 4 does not follow — a helper that writes the path it is handed (`guaardvark`,
`open-computer-skills`), an object property (`hermes-atlas`), a returned path (`preflight`), another program
(`hollow-agentos`) — and none of them is malicious (Open question 1); `jevmem` and `capability-gateway` only read. Kept: the malicious target, `faultline` and
`brainbox` (assign, then `writeFileSync` through the name), `engram`, `moysklad`, `gutcheck` and `guardrail-forge`
(the line half or a later write through the name).

**Public status line scripts** (P-133's 1,100, each at `~/.claude/statusline.<ext>`, where `main` reads it with every
rule as a loose script): carrying `PERM-007` 125 → **11**; carrying any high 159 → **63**; no script gained
`PERM-007`; no other rule moved. Of the 11 kept: eight test files writing a fixture settings file under a temporary
home (Open question 2), and three that write Claude's settings or `~/.claude.json` (`tmp.replace(settings_path)`,
`fs.writeFileSync(file, …)` after `path.join(P.CLAUDE, 'settings.json')`, `os.replace(tmp, path)` after
`path = os.path.join(CLAUDE_HOME, ".claude.json")`).

**Public hook stages** (P-128's 1,425: 716 command hooks and 709 scripts, each as a `Stop` hook of a fake home):
carrying `PERM-007` 35 → **11**, carrying any high 216 → 208, none gained it, no other rule moved. All 24 that lost it
were read: 19 named the file in a docstring, comment, help text or a read and wrote something else; five appear to
write Claude's settings through a shape decision 4 does not follow (a returned path in three, a helper function that
writes the path it is handed, a path handed to an inline Python program). The 11 kept: nine installers or hooks that write the settings through the name (`cp
"$target" "$SETTINGS"`, `open(SETTINGS_FILE, "w")`, `renameSync(tmp, GLOBAL_SETTINGS_FILE)`, `fs.writeFile(
CC_SETTINGS_PATH, …)`, `writeJson(SETTINGS, next)`, `os.replace(…)`), a test writing a fixture, and the line half's
`<your-cwd>` help string (Out of scope).

**Public settings files** (P-133's 721): no change.
