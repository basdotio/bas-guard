<!-- SPDX-License-Identifier: MIT -->
# 111 — The README pair no longer opens with the rename from AgentGuard

- **Source**: maintainer, 2026-10-27
- **Depends on**: none (P-082 added the section)
- **Branch**: `p/111-drop-rename-notice`

## Problem

Since v0.30.0 (P-082) both READMEs open, right after the summary, with "Renamed from AgentGuard" / "由 AgentGuard
改名而来": the old names, why they changed, and what keeps working. Three releases later the tool's own name is the
first thing a new reader should meet, not the old one; the maintainer asked for the section to go.

## Initial direction

Delete the section from `README.md` and `README.zh-CN.md`, nothing else.

## Done criteria

- [x] Neither README has the section: `grep -n 'Renamed from AgentGuard' README.md` and
  `grep -n '由 AgentGuard 改名而来' README.zh-CN.md` print nothing; each README goes from its summary straight to
  "What it is" / "是什么".
- [x] Nothing pointed at the section: no `#renamed-from-agentguard` anchor or "rename section" reference outside
  `CHANGELOG.md` and `docs/proposals/` (checked with `grep -rn` before the change).
- [x] **Reverse**: the plugin note for installs from before v0.30.0 ("Installed the plugin before v0.30.0?" /
  "v0.30.0 之前装过插件?") is still in both READMEs, and the v0.30.0 entry of `CHANGELOG.md` still lists the switch steps.
- [x] `make verify` green.

## Out of scope

- The compatibility itself: the `aguard` command, `~/.config/aguard/`, `AGUARD_*`, the `.aguard-*` file names and
  `bas-guard version`'s switch hint are unchanged; only the README text about them goes.
- `CHANGELOG.md` and `docs/proposals/` are history and keep every mention.
- The plugin note in the README pair (see the reverse criterion).

## Must not claim

Not applicable: a documentation removal, no behaviour or measurement.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | Drop the section from the README pair and record this proposal | `docs: the README pair no longer opens with the rename from AgentGuard (P-111)` |

## Open questions

None.

## Done

```
Merged: PR #136 (2026-10-27; find the sha with git log --grep P-111)
Released: v0.33.1
Evidence: make verify: all gates passed on the branch
```
