<!-- SPDX-License-Identifier: MIT -->
# 120 — `check` on a project's top level, its `.mcp.json` or a settings file says "looks safe" over a wildcard grant, an allow-everything hook and a preloading server

- **Source**: new finding, 2026-11-12, while checking the advice of a self-check list against `origin/main` (`aba37e8`)
  with Claude Code 2.1.107 on macOS; the README tells users to start with `check`
- **Depends on**: none. Touches `internal/detect/rules_version.go` like P-119 (both move `rulesEpoch` to 10): whichever
  merges second takes 11
- **Branch**: `p/120-check-reads-project-config`

## Problem

A project keeps its agent configuration in `.claude/settings.json` (hooks, permission grants, env) and `.mcp.json` next
to it. The brief's project holds `Bash(*)`, a PreToolUse hook printing `permissionDecision: allow`, a `type: http`
PostToolUse hook, and an MCP server whose env sets `NODE_OPTIONS=--require …`. Measured on `main`:

| command | report | exit |
|---|---|---|
| `check <repo>` | 100/100, "nothing to fix" | 0 |
| `check <repo>/.mcp.json` | 100/100 | 0 |
| `check <dir>` holding the same `settings.json`, `<dir>` not named `.claude` | 100/100 | 0 |
| `check <repo>/.claude` | 69/100, `HOOK-003`, `PERM-008`, `PERM-004`, `PERM-005`, `EXEC-010` | 1 |

`collect.CollectTarget` routes a directory to the root collectors only when it is named `.claude` or holds
`plugins/installed_plugins.json`. Any other directory is one directory artifact whose tree the line rules read as text.
A tree read has no notion of a grant's shape, a hook's interception point, an env block or an MCP server, so none of the
four was seen. A lone `.mcp.json` or `settings.json` was one file read the same way.

`settings.json` must not become a routing marker. `looksLikeRoot` records the measurement: a 29-byte
`{"permissions":{"allow":[]}}` routed a payload tree to the root collectors, which read only their known layouts, and a
26/100 tree scored 100/100. The same tree read also took a project's `.claude/commands/*.md` for bundled
documents (injection rules only), where `check <repo>/.claude` reads them as slash commands (every rule).

## Initial direction

Keep the tree read whole and first. In addition, read the configuration the target declares at its top level with the
readers a scan uses, and link what that adds to the target so it is scored and printed as part of it.

## Decisions

The brief left the shape open ("read a target's `.claude/` and `.mcp.json` in addition to the tree, never instead of
it; at minimum, a directory target with zero inventory must not print 'looks safe'"). Decided here, open to the
maintainer in review:

1. **What is read.** For a directory target (the directory and MCP-server-source branches): `<dir>/.claude/settings.json`
   and `settings.local.json`, then `<dir>/settings.json` and `settings.local.json` (a config root with another name, which
   `looksLikeRoot` leaves to `scan --root`), then `<dir>/.mcp.json`. For a file target named `settings.json`,
   `settings.local.json` or `.mcp.json`: that file. Read by `settingsFrom` (split out of `collectSettings`, unchanged
   behaviour) and `mcpServersFrom`. A skill, a plugin and a root keep their branches unchanged.
2. **Never instead of the tree.** `withDeclared` only appends to the one artifact `CollectTarget` built; nothing in it
   decides how much of the tree is read. Each file must be one the tree read may open (`collect.FileReach`): a `.claude`
   or `.mcp.json` symlinked out of the target is not read as its configuration (the tree read refuses and scores it,
   `SCOPE-001`).
3. **Linked to the target, one unit.** Everything added carries `Within` (serialized as `within`, like `plugin`): the
   target artifact's name. `score.Families` treats it as P-044 treats a plugin's children: one unit of the score, so clean
   configuration cannot dilute the tree's own finding, and a finding the target's row already shows (the tree read meets
   a hook's script too) is printed once. Unlike a plugin's children these carry findings the target's row cannot, so the
   gate, `approve` and hygiene, which skip plugin children, do not skip them; `report.target` never takes one for the
   target (a lone `.mcp.json`'s servers share its path). One consequence, as for a plugin: the target is one item, so its
   findings add up across dimensions in one unit score, where `check <repo>/.claude` averages each hook, grant and
   server as an item of its own. On the brief's project `check <repo>` scores 50, `check <repo>/.claude` 69; both are
   Elevated and both exit 1.
4. **One identity per hook.** A hook or permission list carries `ConfigRoot`, the directory its settings file sits in.
   Detect resolves the scripts it names against it, for the rules and the content hash (`detect.resolveRoot`), so
   `$CLAUDE_PROJECT_DIR` is the project and not the directory above it, and a hook hashes the same under `check <repo>` as
   under `check <repo>/.claude` and `scan --root <repo>/.claude`. Evidence is still named from the check target.
5. **Project commands.** In a tree, a `.md` under `.claude/commands/` runs the command rules, as one under `commands/`
   already does (`detect.underCommands`); a document elsewhere does not.
6. **No hedge for a target that declares nothing.** The brief's fallback ("at minimum, a directory target with zero
   inventory must not print 'looks safe'") is not taken: the configuration is now read, and a directory that declares
   none is still read whole with every rule. P-105 kept "a plain directory, read" out of its exit-4 rule for the same
   reason. Say so if the headline should still hedge for it.

`rulesEpoch` 10 → 11 (P-119 merged first and took 10): for the same input `check` now produces findings it did not.

## Done criteria

- [x] `TestCollectTarget_ReadsTheConfigurationATargetDeclares` (`internal/collect/declared_test.go`), one row per shape:
  a project's top level (the tree plus two hooks, the permission list, the env block, the server; each `Within` the
  directory, hooks and grants with `ConfigRoot` its `.claude`); local settings; a settings file in a directory not named
  `.claude`; MCP server source with a `.mcp.json`; a lone `.mcp.json`; a lone `settings.json`; an unparsable settings file
  (`PARSE-000` on its own artifact). **Reverse** rows: a directory with no configuration, the W-003 tree with the 29-byte
  empty allow list, a skill with a `.mcp.json`, and a `.claude` target are exactly what they were.
- [x] **Reverse**, `TestCollectTarget_DeclaredConfigStaysInsideTheTarget`: a `.claude` and a `.mcp.json` symlinked out
  of the target add nothing.
- [x] `TestCheck_ATargetsDeclaredConfigurationIsRead` (`cmd/bas-guard/check_declared_test.go`), the brief end to end:
  `check <repo>` reports at least what `check <repo>/.claude` reports; `check <repo>/.mcp.json`, the project's
  `settings.json`, a directory not named `.claude` and its `settings.json` each report their part; every one scores ≤ 69,
  exits 1 under `--fail-on high`, and its report header names the target.
- [x] `TestCheck_AProjectHookHasOneIdentity`: a hook naming `"$CLAUDE_PROJECT_DIR"/.claude/hooks/guard.sh`, with a decoy at
  the same path one directory up, reads the project's script and has `check <repo>/.claude`'s hash.
- [x] `TestCheck_DeclaredConfigurationIsOneUnitWithTheTree`: a tree at 88 with a clean hook and server added stays 88
  (95 averaged as separate items); `TestFamilies_DeclaredConfigurationJoinsItsTarget` (`internal/score`) pins the link.
- [x] `TestCheck_AFindingOnAHookScriptIsPrintedOnce`: `[EXEC-001]` once in the terminal report, not twice.
- [x] `TestCheck_AProjectsCommandsRunTheCommandRules` and `TestUnderCommands`: `.claude/commands/deploy.md` gets
  `EXEC-001`; **reverse**, `docs/deploy.md` with the same line does not.
- [x] `TestTarget_IsNeverTheConfigurationItDeclares` (`internal/report`).
- [x] The new tests failed on `main` before the change (no configuration artifacts; the hook's hash differed and it read
  no script; 88 → 95; `[EXEC-001]` twice; no `EXEC-001` on the command; the server taken for the target).
  `TestCollectTarget_Routing` and `TestCollectTarget_RootStillRouted` now count the target's declared configuration as
  part of it, and still require the tree read whole and no root collector.
- [x] A real `~/.claude` scan (380 artifacts) gives the same overall and artifacts on `main` and on this branch.
- [x] `make verify` green; `go.mod` line 2 is still `go 1.23.5`.

## Out of scope

- Splitting a project's skills, agents, rules and output styles into artifacts of their own under `check <repo>`: they
  are read as part of the tree with the same rules (P-091's named documents of a nested skill are the one difference),
  and `scan --root <repo>/.claude` lists them one by one.
- `check <plugin>` splitting its hooks and MCP servers (`issues/023`), and a target's `.claude.json` (a user's global
  config, not a project file; P-119 reads its local scope under `scan`).
- The judge: a directory is still asked nothing (P-038), so `check <repo> --llm --fail-on-llm` still exits 4; the
  configuration artifacts get their kind's passes. `ExcerptVersion` does not move: no excerpt of an existing artifact
  changes.
- `scan`, the hook gate and `clean`: they never build `Within` artifacts.

## Must not claim

- Not "`check <repo>` is `scan --root <repo>/.claude`": the project's skills are not artifacts of their own here, and a
  named document of a nested skill runs the document rules.
- Not "a directory that declares no configuration is a Claude Code setup that looks safe": the headline is the band's,
  over a tree read with every rule (decision 6).

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | `withDeclared`, `ConfigRoot` resolution, project commands, `Within` in `score.Families` and `report.target`; tests written first | `collect: check reads the configuration a directory or file declares, in addition to its tree (P-120)` |
| 2 | README pair, architecture pair, spec §3, §4 and §5.3, `.claude/rules/pipeline.md` and `score.md` | `docs: check reads a target's declared configuration (P-120)` |
| 3 | The proposal | `proposals: P-120 done, check reads a target's declared configuration (P-120)` |

## Open questions

None left open by the brief; see Decisions, which the maintainer can overturn in review.

## Done

```
Merged: not yet — PR #146 (find the sha with git log --grep P-120 after the merge)
Released: (fill in after the release)
Evidence: TestCheck_ATargetsDeclaredConfigurationIsRead (cmd/bas-guard/check_declared_test.go); the brief's project,
  --fail-on high: `check <repo>` 100/100, exit 0 → 50/100, 4 findings, exit 1; `check <repo>/.mcp.json` 100 → 69,
  exit 1; `check <repo>/.claude/settings.json` 100 → 50, exit 1; reverse: TestCollectTarget_ReadsTheConfigurationATargetDeclares (W-003 tree, plain directory,
  skill, .claude target unchanged), TestCollectTarget_DeclaredConfigStaysInsideTheTarget
```
