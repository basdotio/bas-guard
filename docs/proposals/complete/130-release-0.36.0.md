<!-- SPDX-License-Identifier: MIT -->
# 130 — Release record v0.36.0: P-117, P-127, P-128

- **Source**: the maintainer said "发 v0.36.0" (2026-11-17), after P-127 and P-128 were merged. A release does not go
  through a proposal; this file is only the record.
- **Includes**: P-117 (PR #143), P-127 (PR #153), P-128 (PR #154), and the records of three rejected proposals merged
  since v0.35.0: P-114 (PR #140), P-116 (PR #142) and P-118 (PR #144, which also updates `issues/028`); those three
  change baselines tests, `.claude/rules/judge.md` and the issue, not the binary. Nothing else merged since v0.35.0;
  the open pull requests stay out (P-129 among them, a draft).
- **Branch**: `p/130-release-0.36.0`

## Why minor

One rule is new: `PERM-009` (P-127), so the rule table goes from 89 to 90 IDs. No flag, exit code or JSON field changed
meaning, but the same input can now produce findings it did not: `HOOK-003` reads command hooks and the scripts they
run (P-128), and a project's settings approving its own MCP servers is reported (P-127). A gate that passed can fail on
upgrade, on findings that were always there. The judge's server pass reads a different excerpt (P-117), so judge
results carry a new excerpt version.

`rules` `35dbd6adf202` → `dbd22857f91a` (`rulesEpoch` 15 → 17: P-127 took 16, P-128 17, in merge order);
`judge-excerpt` 9 → 10 (P-117); `judge-prompt` `9cd57da1a4bd` unchanged.

## Changelog

`CHANGELOG.md`, entry **v0.36.0 (2026-11-17)**, written from the three proposals, with an upgrade note for CI gates.

## What changed where

| Place | Before | After |
|---|---|---|
| `plugin/.claude-plugin/plugin.json` `version` | `0.35.0` | `0.36.0` |
| `.claude-plugin/marketplace.json` plugin entry `version` | `0.35.0` | `0.36.0` |
| `CHANGELOG.md` | range up to v0.35.0 | range up to v0.36.0, the entry above first |
| Index rows 117, 127, 128 and their Done | PR numbers, not released | `; v0.36.0`; merge dates; `Released: v0.36.0` |
| Index: a row for this record | — | added |
| git tag `v0.36.0` | — | on the `main` commit this PR's merge produces |

## After the tag

The release workflow publishes the six npm packages and the GitHub release. Check that all six reach `0.36.0` and that
the release lists `bas-guard-*`, `aguard-*` and `SHA256SUMS.txt`.

P-117's Done says the raw archive of its judge runs goes on the next release, with P-114's, P-115's and P-116's. None
of them is on the machine this release was cut from, so the release goes out without them, as v0.34.0 and v0.35.0 did.
Whoever holds them attaches them afterwards (`gh release upload <tag> <archive>`).

## Done

```
Merged: not yet — PR pending
Released: (fill in after the release)
Evidence: make verify: all gates passed on the branch
Evidence: bas-guard version on main before this branch: rules=dbd22857f91a judge-prompt=9cd57da1a4bd judge-excerpt=10
```
