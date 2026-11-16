<!-- SPDX-License-Identifier: MIT -->
# 125 — `check` on a project missed a `CLAUDE.md` that imports the project's `.env`, which `scan --root <repo>/.claude` reports

- **Source**: new finding, 2026-11-16, re-testing the advice of a self-check list on v0.34.0 (`4bee868`): comparing
  `scan --root ./.claude` with `check .` on the same project
- **Depends on**: P-120 (`check` reads the configuration a target declares). Touches `internal/detect/rules_version.go`
  like P-123 and P-124: P-123 merged first and took 13, so this takes 14; P-124, if it merges later, takes the next value
- **Branch**: `p/125-check-reads-project-instructions`

## Problem

A project's `CLAUDE.md` loads into every session started in that project, and so does every file it imports with
`@path`. One line, `@.env`, puts the project's secrets into the agent's context. Under a scan, `collectInstruction` reads
the `CLAUDE.md` and `expandImports` follows its imports: an import that resolves to a credential is refused, not read,
and scored on the file that wrote it (`EXFIL-005`, high, plus a `COV-000` note; W-006).

`check <repo>` read the same `CLAUDE.md` only as one file of the directory tree. The tree read runs the line rules over
it as an instruction file but has no notion of an import, so `@.env` was text and scored nothing. P-120 made `check <repo>`
read the project's settings and `.mcp.json` with the readers a scan uses; the instruction files were not among them, and
its Out of scope did not name them. The README tells users to start with `check`.

The brief's project, in a fake `HOME`: `.claude/settings.json` with `Bash(*)` in `permissions.allow`, a PreToolUse hook
that echoes `permissionDecision: allow` and a `type: http` PostToolUse hook; `.mcp.json` with one server whose `env` sets
`NODE_OPTIONS=--require ./x.js`; `.env` with `API_KEY=sk-test-000`; `CLAUDE.md` of `# Repo notes`, a blank line, `@.env`.
Run from the project, `--config` pointing at `{}`, on v0.34.0:

| command | exit | findings |
|---|---|---|
| `check .` | 1 | `EXEC-010`, `HOOK-003`, `PERM-004`, `PERM-005`, `PERM-008` — **no `EXFIL-005`** (50/100) |
| `scan --inbox off --root ./.claude` | 0 | the same five, plus `EXFIL-005` and `COV-000` (69/100) |

`check . --verbose` lists `skills=0 mcp=1 hooks=2 permissions=1 …`; neither command's inventory line counts instruction
files, so the inventory does not show the difference.

## Initial direction

When `check` takes P-120's path for a directory, also read the project's instruction files with the collector a scan
uses, and follow their imports with the same resolution and boundary. Never instead of the tree.

## Decisions

1. **Which files.** `instructionFiles(root, home)`, split out of `collectInstruction` (unchanged behaviour), is the one
   list: with root `<dir>/.claude` and home `<dir>` it names `<dir>/.claude/CLAUDE.md` and `CLAUDE.local.md`, then
   `<dir>/CLAUDE.md` and `CLAUDE.local.md` — exactly what `scan --root <dir>/.claude` reads, under the same names
   (`CLAUDE.md (project)` and so on). Each must exist as a file and be one the tree read may open (`FileReach`): a
   `CLAUDE.md` or `.claude` symlinked out of the target is not read as the project's, as P-120 decided for settings; the
   tree read already refuses and scores it (`SCOPE-001`).
2. **Imports exactly as a scan follows them.** `expandImports` with home the target (anchored): relative imports resolve
   against the importing file, `~/` against the project (what `scan --root <dir>/.claude` does, since its home is
   `<dir>`), four hops, code spans and fences skipped, a credential refused before any boundary verdict and an import out
   of the project said (`COV-000`) and not read. `known` is what the target already produced (the tree, settings, MCP),
   as a scan passes what its other collectors produced. One change inside `expandImports`: its resolved paths are made
   absolute, so a target typed as `.` (seeds relative to the working directory) relates to the absolute home; a scan's
   paths were absolute already, so a scan is unchanged.
3. **One unit with the target.** The instruction files and the files they import carry `Within`, like P-120's
   configuration: `score.Families` counts them in the target's unit, and a finding both the tree row and an instruction
   row carry (a line rule on the `CLAUDE.md` itself) is printed once. An imported file is read with its own name's role
   (`roleForPath`, as under a scan), so a document imported from inside the tree runs the rules the tree read already
   ran on it. What this adds in practice is the import decision: `EXFIL-005` on the file that wrote a credential import,
   and the `COV-000` notes for refused, escaping and too-deep imports.
4. **Directories only.** A lone `check ./CLAUDE.md` is not expanded. Its boundary could only be its own directory, and
   the Downloads pass runs `check` on loose `CLAUDE.md` files there: following an import would read a sibling that is not
   a candidate, which that pass promises never to do. A skill, a plugin and a root keep their branches unchanged; an `@`
   in a `SKILL.md` is not an import (Claude Code expands imports in `CLAUDE.md` files).

`rulesEpoch` 13 → 14 (P-123 merged first and took 13; rules version `2879033d238e` → `c767f85ecaf7`): for the same input
`check` produces findings it did not. Measured before that merge, on top of v0.34.0, where the bump read 12 → 13
(`39b17de88dd4` → `b9d0a5520737`).

## Measured

Static, threshold high, corpus `24c15d32` (5,042 samples), `main` `4bee868` (v0.34.0, `rules=39b17de88dd4`) against
this branch (`rules=b9d0a5520737`), both built 2026-11-16: `baselines/results/aguard/2026-11-16-p125-corpus-{main,changed}`.
The branch binary was built from `ba7753b`, which is W1 before its commit message was edited: the same tree as W1 here. The
held-out ClawHub set is P-121's `agent-skill-malware` work list (layer 2, 118 malicious and 208 benign):
`…-p125-heldout-{main,changed}`; its scorecards say the samples are not in the corpus, so its figures are read from
`ledger.jsonl`.

| | n | main | P-125 |
|---|---:|---:|---:|
| malicious, flagged high | 550 | 161 | 161 |
| benign, flagged high | 4,473 | 325 | 325 |
| hard negatives, flagged high | 19 | 4 | 4 |
| held-out ClawHub malicious, flagged high | 118 | 66 | 66 |
| held-out ClawHub benign, flagged high | 208 | 6 | 6 |

Per sample, from the raw JSON of both runs (not committed): no sample in either set changed its verdict, its severity,
its overall, its set of (rule, severity) or its notes. 17 corpus samples took the new path, all benign MCP server source
trees with a top-level `CLAUDE.md` that the adapter hands to `check`; the rules on their instruction artifacts
(`FS-001`, `FS-002`, `OBF-005`) are lines of the `CLAUDE.md` the tree read already reported, and one of them
(`ben-mcp-gh-wojtyniak-mcp-mcp`) imports two Markdown documents inside its tree, both read without a finding. No sample in the corpus or the held-out set imports a credential from a directory-routed `CLAUDE.md`, so the
benchmark shows the cost (none) and not the gain; the gain is the brief's project and the tests.

## Done criteria

- [x] `TestCollectTarget_ReadsTheProjectsInstructionFiles` (`internal/collect/declared_instructions_test.go`): a
  `CLAUDE.md` importing `.env` gives `CLAUDE.md (project)` within the target with `EXFIL-005` and a high `COV-000`; all
  four instruction files of a project and its `.claude` are read under a scan's names; an import inside the project
  becomes an `@…` instruction artifact; an import out of it is a medium `COV-000`, not read; no artifact carries the
  sha256 of a credential. **Reverse** rows: a plain `CLAUDE.md` carries nothing; an `@` in a code span or fence is not an
  import; an `@` in a project skill's `SKILL.md` or `README.md` is not followed; a directory with no instruction file
  adds none.
- [x] `TestCollectTarget_ProjectImportsResolveAsAScanResolvesThem`: nine ways of writing an import (`@.env`,
  `@.env.example`, a relative path, a path with `..`, `@~/…` inside the project, a credential under `~/.aws`, a path out
  of the project, a missing file, a two-hop chain ending at `.env`) give the same imported files, `EXFIL-005` and notes
  under `check <repo>` as under `check <repo>/.claude` (the root collector a `scan --root <repo>/.claude` runs).
- [x] `TestCollectTarget_ProjectImportsDoNotDependOnTheSpelling`: `check .`, `./`, `..` from a subdirectory, `repo` and
  `../repo` give the absolute target's imports, `EXFIL-005` and notes. Without the absolute paths in `expandImports` the
  `.` and `./` rows read `@docs/guide.md` as escaping the project (a false `COV-000`, and the import not read).
- [x] **Reverse**, `TestCollectTarget_ProjectInstructionsStayInsideTheTarget`: a `CLAUDE.md` symlinked out of the target
  adds nothing.
- [x] `TestCheck_AProjectsCLAUDEmdImportIsReported` (`cmd/bas-guard/check_instructions_test.go`), the brief end to end:
  `check <repo>` reports at least what `check <repo>/.claude` reports, `EXFIL-005` included, exits 1 under
  `--fail-on high`, and prints `EXFIL-005` once, naming the `CLAUDE.md`.
- [x] **Reverse**, `TestCheck_AProjectsInstructionFilesAddNothingElse`: a plain `CLAUDE.md` and one whose `@.env` is in a
  code span give the same rules and the same overall as the project without a `CLAUDE.md`; a `CLAUDE.md` whose own line
  is `EXEC-001` gives the rules the tree read gives and prints `EXEC-001` once; every instruction artifact is in the
  target's unit.
- [x] **Reverse**, `TestCheck_ASkillsAtSignsAreNotImports`: `check <skill>` and `check <repo>` with a project skill whose
  `SKILL.md` names `@.env` report no `EXFIL-005` and no instruction artifact.
- [x] The new tests failed on `main` before the change (no instruction artifacts; `check <repo>` without `EXFIL-005`).
  The reverse ones passed there and pass here.
- [x] `check pkg.zip` with the same `CLAUDE.md`: `EXFIL-005` on `CLAUDE.md (project)`, and no path into the extraction
  directory anywhere in the JSON (P-016).
- [x] `make verify` green; `go.mod` line 2 is still `go 1.23.5`; `go version` reports go1.23.5 with no toolchain switch.

## Out of scope

- A project-rooted `~/` (issues/029): `@~/.env` in a project's `CLAUDE.md` resolves to `<repo>/.env` under both
  `scan --root <repo>/.claude` and `check <repo>`; with none there it is dropped as a stale reference, while a session in
  the project loads the user's real `~/.env`. v0.34.0 and this branch give the same 100/100 for it. Recorded, not fixed:
  either fix changes `scan` too.
- `CLAUDE.md` files in subdirectories (loaded when the agent reads files there) and `.claude/rules/*.md`: a scan does not
  follow their imports either; under `check <repo>` they stay files of the tree.
- A lone `check ./CLAUDE.md` (decision 4).
- The judge: under `check <repo> --llm` the instruction artifacts get the instruction passes a scan gives them, so a
  project with a `CLAUDE.md` gets those calls too; a directory target is still asked nothing (P-038), so
  `--fail-on-llm` still exits 4. `ExcerptVersion` does not move. Not measured here: no static figure depends on it.
- The inventory line (`skills=… mcp=…`): it counts no instruction files under either command.

## Must not claim

- Not "`check <repo>` now equals `scan --root <repo>/.claude`": P-120's differences stand (skills and agents are read as
  part of the tree), and so does issues/029, which neither command catches.
- Not "BAS Guard follows every file a project loads": only the top-level instruction files a scan names, and their
  imports.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | `instructionFiles`, `declaredInstructions`, absolute paths in `expandImports`, `rulesEpoch` bumped; tests written first | `collect: check on a directory reads the project's CLAUDE.md files and follows their imports (P-125)` |
| 1b | The spelling test for a target typed as `.` | `collect: a project's imports resolve the same whichever way check's target is typed (P-125)` |
| 2 | README pair, architecture pair, spec §3 and §5.3, `.claude/rules/pipeline.md` and `score.md` | `docs: check reads a project's CLAUDE.md files and follows their imports (P-125)` |
| 3 | issues/029, the project-rooted `~/` | `issues: 029, a project's CLAUDE.md importing @~/.env is not reported (P-125)` |
| 4 | The four static runs | `baselines: P-125 static runs, main and branch, corpus and held-out ClawHub (P-125)` |
| 5 | The proposal | `proposals: P-125 done, check reads a project's CLAUDE.md files (P-125)` |
| 6 | Merge `main` after P-123: `rulesEpoch` 14, `docs/rules.md` regenerated, both index rows kept | `Merge main into p/125-check-reads-project-instructions (P-125)` |

## Open questions

None left open by the brief; decision 4 (no expansion for a lone `CLAUDE.md`) is the one the maintainer may want to
revisit.

## Done

```
Merged: not yet — PR #151 (find the sha with git log --grep P-125 after the merge)
Released: (fill in after the release)
Evidence: TestCheck_AProjectsCLAUDEmdImportIsReported (cmd/bas-guard/check_instructions_test.go); the brief's project:
  `check .` 50/100, 5 findings, no EXFIL-005 → 25/100, EXFIL-005 + COV-000, exit 1 both; `scan --root ./.claude`
  unchanged (69/100, exit 0); corpus 24c15d32 malicious 161 → 161 of 550, benign 325 → 325
  of 4,473, held-out ClawHub 66 → 66 of 118 and 6 → 6 of 208, no per-sample change; reverse: TestCheck_AProjectsInstructionFilesAddNothingElse,
  TestCheck_ASkillsAtSignsAreNotImports, TestCollectTarget_ProjectInstructionsStayInsideTheTarget
```
