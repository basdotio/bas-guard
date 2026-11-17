<!-- SPDX-License-Identifier: MIT -->
# 127 — A repository whose settings approve the MCP servers it declares scored 100/100: the approval was never read

- **Source**: new finding, 2026-11-17, while re-testing a self-check list on v0.35.0; reproduced here on v0.35.0
- **Depends on**: none. Moves `rulesEpoch` 15 → 16
- **Branch**: `p/127-project-mcp-servers-approved-in-settings`

## Problem

Claude Code asks before it starts a server a project's `.mcp.json` declares. That prompt is where the user is shown
the command. Three settings keys answer it in advance (Claude Code's settings reference, and the MCP page's section
"Project server approvals and workspace trust"):

- `enableAllProjectMcpServers: true` approves every server of the project's `.mcp.json`;
- `enabledMcpjsonServers` approves the servers it names;
- `disabledMcpjsonServers` rejects the servers it names. A rejection in any settings file wins over both.

A repository's own `.claude/settings.json` is ignored until the user accepts the workspace trust dialog. From then on,
the servers it approves start with every session, and nobody is asked again. CVE-2025-59536 was this pair of files
honoured before the dialog. The corpus carries a reconstruction of it (`mal-conn-mcp-autorun-bypass`): a `.mcp.json`
whose server runs `npx -y @project/setup-helper@latest`, and a `.claude/settings.json` that approves it.

Measured with `check .` in each project, a fake `HOME` and an empty `--config`:

| # | Project | v0.35.0 | This branch |
|---|---|---|---|
| 1 | `.claude/settings.json` `{"enableAllProjectMcpServers": true}`, no `.mcp.json` | 100/100, exit 0 | unchanged (decision 1) |
| 2 | The corpus's CVE-2025-59536 reconstruction: both keys in `settings.json`, one `npx` server | **100/100, exit 0, no finding** | 88/100, exit 0, `PERM-009` medium citing lines 2 and 3 |
| 3 | Row 1's settings plus a `.mcp.json` server whose `env` sets `NODE_OPTIONS=--require …` | 69/100, exit 1, `EXEC-010` only | 63/100, exit 1, `EXEC-010` and `PERM-009` |
| 4 | `.claude/settings.local.json` `{"enabledMcpjsonServers": ["project-tools"]}` beside row 2's `.mcp.json` | **100/100, exit 0, no finding** | 88/100, exit 0, `PERM-009` (local) |

`--verbose` never mentions either key on v0.35.0. `scan --root ./.claude` gives the same answers as `check .` on
both sides.

**This was declined once, for a different shape.** P-016 (v0.12.0) measured a rule on the key alone and declined it:
34 of 387 real configurations used it (`.claude/rules/detect.md`, and the benchmark review of 2026-09-27). Neither file
is in `issues/`, `ROADMAP.md` or a proposal, which is where a search for the key looks. Two things changed since then:

- P-120 (v0.34.0) made `check <dir>` read a project's settings files and its `.mcp.json` with a scan's readers, in
  one collection. A scan of `<dir>/.claude` already read both.
- That makes a narrower finding possible: one on the server that the settings let start, not on the key.

## Initial direction

When one collection reads a project's `.claude` settings and its `.mcp.json`, put a finding on each server the
settings approve, following Claude Code's precedence. New rule ID `PERM-009`, dimension 2 (excessive permissions).

## Decisions

1. **The finding goes on the server, and only when both files of one project are in view.** The risk is a command
   that starts unasked, and that command is in `.mcp.json`. A settings file holding only the key approves nothing a
   scan can see. A settings file with nothing else in it is no artifact at all, so it has nothing to carry a finding.
   The key-only rule is what P-016 declined: in today's corpus it would fire on 65 benign samples (Measured).
2. **Medium, not high.** The command the approval lets start is in view, and every MCP rule reads it. A server that
   preloads code is still `EXEC-010` high (row 3). What the approval removes is the moment a person reads that command.
   This finding says so, and scores it. Teams that ship a `.mcp.json` commit the key for convenience. Of the 62 benign
   corpus samples that are a project's `.claude/settings.json` approving servers, 38 come from a repository with a
   `.mcp.json` at its top level at the same commit (Measured). High would fail `check --fail-on high` on most of those
   for a setting rather than for anything their servers do. `PERM-008` (a hook that answers every permission prompt
   with allow, a wider approval) is medium for the same reason. The cost: row 2, the CVE reconstruction, now scores
   and is printed, but still passes the default gate. Open question 1.
3. **Precedence is Claude Code's.**
   - A `disabledMcpjsonServers` entry in any file rejects the server.
   - `enabledMcpjsonServers` counts from every file.
   - For `enableAllProjectMcpServers`, the highest-precedence file that sets it decides. `settings.local.json` is
     above `settings.json`, so a local `false` overrides a project `true` in a trusted folder.

   Only the JSON literals `true` and `false` set that key, which Claude Code types Boolean. Keys are read by exact
   name: Claude Code parses settings with `JSON.parse`, which is case-sensitive, and Go's struct decoding is not
   (P-119's reason for `mcpServerMap`). Of two values for one key, the last counts, as for `JSON.parse`. The citation
   is the line of the settings file's own member, never a nested member of the same name.
4. **`settings.local.json` counts like `settings.json`.** Claude Code applies approvals from an untracked
   `settings.local.json` once the folder is trusted. Whether the file is tracked is something it asks git. A scanner
   that runs nothing cannot ask, and a downloaded archive has no git at all. The cost is in a scan of a user's own
   project: the approvals Claude Code wrote into `settings.local.json` when the user clicked approve are reported too.
   The finding's text says Claude Code writes these keys there.
5. **A user's `~/.claude/settings.json` gets no finding of its own.** It approves the servers of every project, and a
   scan of `~/.claude` reads none of those projects' `.mcp.json`. The one it reads is home's own, whose servers that
   setting really does approve. That case gets the same finding, because it is the same fact. A finding on the key in
   user settings is the shape P-016 measured on real configurations and declined.
6. **It lives in `internal/collect`, not in `permcheck` or `detect`.** Collect decides which files are read
   (`readableInTree`, the tree's `FileReach`). A second reader that opened `<dir>/.claude/settings.json` by path would
   read a settings file the tree read refused as a symlink out of the target. This is also why `EXFIL-005` lives there.
   Under `check <dir>`, only `<dir>/.claude`'s settings pair with `<dir>/.mcp.json`. `<dir>`'s own `settings*.json`
   are a config root's, and that root's project is the directory above.

## Done criteria

- [x] `TestCollect_ProjectMCPApprovals` (`internal/collect/mcpapproval_test.go`), 19 rows. Each row runs as
  `check <repo>` and as `scan --root <repo>/.claude` and must give the same answer.
  - Fire: project and local settings approving everything; project and local settings approving one server by name
    (the other stays quiet); both keys, citing both lines; a name listed in both files, cited in both; local `true`
    over project `false`; the last of two values in one file.
  - Quiet: the key `false`; the key absent; no settings; an empty list; a list naming a server the project does not
    declare; local `false` over project `true`; the last of two values `false`; a rejection over approve-all (the
    other server still fires); a rejection in another file over an approval by name; the string `"true"`; the keys in
    another case.
- [x] `TestCollect_ProjectMCPApprovalNeedsBothFilesInView`, 7 rows:
  - quiet: settings without a `.mcp.json` (under `check` and under `scan`, and no artifact is added); a config root's
    own `settings.json` beside a `.mcp.json`; a lone `.mcp.json`; a lone `settings.json`; user settings with no
    `.mcp.json` in home;
  - fires: user settings beside home's own `.mcp.json`.
- [x] `TestCollect_ProjectMCPApprovalIsAPermissionFinding` pins dimension 2, medium, `SrcPermission`, the snippet, and a
  `Why` that names both keys, the trust dialog and `disabledMcpjsonServers`.
- [x] `TestTopLevelKeyLines`, 7 rows: the cited line is the top-level member's, the last one when the key repeats, with
  CRLF line ends.
- [x] `TestCheck_ProjectMCPApprovalIsReported` (`cmd/bas-guard/check_mcp_approval_test.go`), 6 rows end to end:
  - the rule set, `--fail-on high` (0, except the preload row, which `EXEC-010` fails), an overall below 100 when it
    fires and 100 when it does not, and `PERM-009` in the terminal report exactly when it is in the result;
  - project settings, the same project as a config root, local settings by name, the brief's preload server, the key
    `false`, the key absent.
- [x] Before the change, on `main` `bf7f8fb`:
  - every row that expects a finding failed: 9 of the first test's 19 (each as `check` and as `scan`; the mixed row
    "a rejection over approve-all" among them), the user-settings row of the second, the third test, and 4 of the
    last test's 6;
  - every quiet row passed: 10, 6 and 2. `TestTopLevelKeyLines` names a function `main` does not have.
- [x] **Reverse**: P-120's `TestCheck_ATargetsDeclaredConfigurationIsRead` and
  `TestCollectTarget_ReadsTheConfigurationATargetDeclares` are untouched and green, and row 3's `EXEC-010` still fires.
- [x] The four rows above through the built binary: rows 2 and 4 100/100 → 88/100 (`PERM-009` medium, exit 0); row 3
  69/100 → 63/100 (exit 1 on both sides); row 1 unchanged at 100/100.
- [x] Static over the corpus and the held-out ClawHub set, `main` against the branch (Measured).
- [x] `rulesEpoch` 15 → 16; `make docs` (89 → 90 rule IDs); `.claude/rules/detect.md` and `pipeline.md`; the spec's §7
  and the epoch lists in the spec and both architecture documents; the `check <dir>` paragraph in both READMEs.
  `make verify` green; `go.mod` line 2 is still `go 1.23.5`, and `go version` does not switch toolchains.

## Out of scope

- **`permissions.defaultMode: "bypassPermissions"` or `"auto"` in project or local settings.** Claude Code's
  settings reference says neither takes effect from those files since v2.1.257 (`bypassPermissions` did before). A
  finding would report what current Claude Code no longer does, and the scanner does not know which version runs. In
  the corpus, 10 benign settings files and 1 hard negative set `bypassPermissions` and 3 benign set `auto`. No
  malicious sample sets either. That would be its own proposal, with the version question answered first.
- **A user's settings approving the servers of other projects** (decision 5). `check <repo>` never reads the user's
  settings, so a user-level approve-all does not show up when checking a repository.
- **A standing approval for servers a later commit adds**: row 1 stays quiet (decision 1).
- **What no file a scan reads can say**: managed settings, `--settings`, `--setting-sources`, `--strict-mcp-config`.
- **`claude -p`**, which starts a project's servers without asking whatever the keys say. A finding for that would
  be a finding on every `.mcp.json`, not on an approval.
- **Tracked and untracked `settings.local.json`** (decision 4): that needs git.
- **The plain layer's next step for dimension 2** ("Narrow the grant to the exact commands you need …") is one fixed
  sentence per dimension by design (`.claude/rules/report.md`). For approve-all it reads as written, and the finding's
  own text says what to do.
- **`check .` reporting a hook script's line twice**, once under `directory .` with `.claude/hooks/setup.sh:3` and once
  under the hook with `hooks/setup.sh:3`: a separate, cosmetic issue.
- The judge: `ExcerptVersion` and the prompts do not move.

## Must not claim

- Not "BAS Guard reports `enableAllProjectMcpServers`". It reports a server the project declares and its settings
  approve, when one run reads both files: `check <dir>`, `check <dir>/.claude`, `scan --root <dir>/.claude`, and
  for `scan` of `~/.claude` only home's own `.mcp.json`. A settings file holding only the key, `check ./.mcp.json`
  alone and `check ./.claude/settings.json` alone report nothing.
- Not "`check` fails on it". `PERM-009` is medium: the CVE reconstruction goes 100/100 → 88/100 and still exits 0 under
  the default `--fail-on high`, unless something else in the project is high.
- Not "detects CVE-2025-59536". That CVE is the pre-trust-dialog variant, fixed in Claude Code. This reports the
  configuration shape it used, which still decides what starts after the dialog.
- Not a recall gain at threshold high (Measured).

## Measured

Static, threshold high, corpus `24c15d32` (5,042 samples), `main` `bf7f8fb` (v0.35.0, `rules=35dbd6adf202`) against
this branch (`rules=400eaf0b1400`), both built 2026-11-16 (UTC): `baselines/results/aguard/2026-11-16-p127-corpus-{main,changed}`.
The held-out ClawHub set is `agent-skill-malware` (layer 2, the work list P-121 and P-124 used): `…-p127-heldout-{main,changed}`.
Its scorecards say the samples are not in the corpus, so its figures are read from `ledger.jsonl`.

| | n | main | P-127 |
|---|---:|---:|---:|
| malicious, flagged high | 550 | 161 | 161 |
| benign, flagged high | 4,473 | 326 | 326 |
| hard negatives, flagged high | 19 | 4 | 4 |
| held-out ClawHub malicious, flagged high | 118 | 66 | 66 |
| held-out ClawHub benign, flagged high | 208 | 6 | 6 |

Samples carrying `PERM-009`: malicious 0 → 1, benign 0 → 0, hard negatives 0 → 0, held-out 0 → 0.

- The one sample that changed is `mal-conn-mcp-autorun-bypass`, the CVE-2025-59536 reconstruction. Its ledger goes
  from no severity to medium, and it stays below the threshold (decision 2).
- **Benign 0 → 0 is not the cost, and this proposal does not claim it is.** The corpus harvested each benign project's
  `.claude/settings.json` on its own. 65 benign samples (and 1 hard negative) approve servers: 59 with
  `enableAllProjectMcpServers: true`, 6 with a non-empty `enabledMcpjsonServers` alone. None of them carries the
  `.mcp.json` its repository may ship, so none can fire here. For the cost, the repository each sample came from was
  asked at the sample's pinned commit (`gh api repos/<owner>/<repo>/contents/.mcp.json?ref=<sha>`, read-only):
  - 62 of the 65 are a project's `.claude/settings.json`; 38 of those have a `.mcp.json` at the top level and 24 do
    not;
  - 3 are not a project's `.claude/settings.json` (`settings.json` at the top level, `examples/settings.json`), and the
    hard negative's commit no longer exists.

  So `check` on those 38 repositories would probably report `PERM-009` (whether a name-only list matches a declared
  server was not checked). At medium that changes their score, not their verdict at the default gate. That is decision
  2's reason for medium.
- A key-only rule, the shape P-016 declined, would have fired on all 65 benign samples and the hard negative.
- A scan of a maintainer's real `~/.claude` (`scan --inbox off --json`, empty `--config`) is unchanged: overall 69,
  383 artifacts, 788 findings on both sides. There is no `~/.mcp.json` on that machine.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | `PERM-009` in `internal/collect` (`mcpapproval.go`, `settingsFrom`, `CollectAll`, `withDeclared`), `rulesEpoch` 16, regenerated `docs/rules.md`, the rules files, spec, architecture and READMEs; tests written first | `collect: PERM-009 on a project .mcp.json server its settings approve without a prompt (P-127)` |
| 2 | The four static runs | `baselines: P-127 static runs, main and branch, corpus and held-out ClawHub (P-127)` |
| 3 | The proposal and its index row | `proposals: P-127 done, measured (P-127)` |

## Open questions

1. **Severity** (decision 2). The recommended answer is medium.
   - Medium: the finding is printed and scores. The CVE reconstruction passes the default gate.
   - High: the CVE reconstruction fails the gate, and so would most benign repositories that commit the key beside a
     `.mcp.json` (38 of 62 measured upstream).
   - A middle path, high only when the approved server is itself unpinned or remote, would be the judge's
     `LLM-009` question (advisory only by design). It is not a static fact.
2. **`defaultMode` in project settings** (Out of scope). The recommended answer is to leave it until someone needs
   Claude Code before v2.1.257 covered.

## Done

```
Merged: not yet — PR #153 (find the sha with git log --grep P-127 after the merge)
Released: (filled in at the release)
Evidence: TestCollect_ProjectMCPApprovals, TestCollect_ProjectMCPApprovalNeedsBothFilesInView,
  TestCollect_ProjectMCPApprovalIsAPermissionFinding, TestTopLevelKeyLines (internal/collect/mcpapproval_test.go),
  TestCheck_ProjectMCPApprovalIsReported (cmd/bas-guard/check_mcp_approval_test.go); via check: the CVE-2025-59536
  reconstruction and the local-settings row 100/100 -> 88/100 (PERM-009 medium), the preload row 69/100 -> 63/100,
  the key alone unchanged at 100/100; corpus 24c15d32 malicious 161 -> 161 of 550, benign 326 -> 326 of 4,473,
  hard negatives 4 -> 4 of 19, held-out ClawHub 66 -> 66 of 118 and 6 -> 6 of 208; PERM-009 carriers malicious
  0 -> 1 (the CVE-2025-59536 reconstruction, medium), benign 0 -> 0 (settings harvested without their .mcp.json;
  38 of 62 upstream repositories ship one)
```
