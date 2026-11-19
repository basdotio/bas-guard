<!-- SPDX-License-Identifier: MIT -->
# 140 — Release record v0.38.0: P-084, P-107, P-136, P-137, P-138, P-139

- **Source**: the maintainer said "发 v0.38.0" (2026-11-18), after P-139 was merged. Before it was tagged, P-107 was
  merged (2026-11-19), and the maintainer chose to ship it and P-084 in this release. A release does not go through a
  proposal; this file is only the record.
- **Includes**: P-084 (PR #107), P-107 (PR #132), P-136 (PR #163), P-137 (PR #164), P-138 (PR #165), P-139 (PR #166),
  and the record of one rejected proposal merged since v0.37.0: P-113 (PR #139). Nothing else merged since v0.37.0; the
  open pull requests stay out.
- **Branch**: `p/140-release-0.38.0`

## Why minor

Three rules are new: `OBF-008` and `OBF-009` (P-136) and `INJ-007` (P-137), so the rule table goes from 95 to 98 IDs.
No flag, exit code or JSON field changed meaning, but the same input can now produce findings it did not: the matched
view drops characters that draw nothing and reads unusual spaces as spaces (P-138), a crypto-wallet key store is a
credential (P-136), and `SUP-010` reads a verb with its object (P-139). A gate that passed can fail on upgrade, on
findings that were always there.

P-107 adds a config key (`llm.request_options`) and a judge-block field (`request_options`, present only when the key is
set); without the key every request is byte-identical. P-084 changes when a static run exits 2: an `llm` section this
build cannot use no longer fails a run that never reads it, and the load-time gate keeps auditing under it.

`rules` `6e839a428eb8` → `64f57c6f747c` (`rulesEpoch` 22 → 26: P-136 took 23, P-137 24, P-138 25, P-139 26, in merge
order); `judge-prompt` `9cd57da1a4bd` and `judge-excerpt` 10 unchanged.

## Changelog

`CHANGELOG.md`, entry **v0.38.0 (2026-11-19)**, written from the six proposals, with an upgrade note for CI gates and a
line for the rejected P-113.

## What changed where

| Place | Before | After |
|---|---|---|
| `plugin/.claude-plugin/plugin.json` `version` | `0.37.0` | `0.38.0` |
| `.claude-plugin/marketplace.json` plugin entry `version` | `0.37.0` | `0.38.0` |
| `CHANGELOG.md` | range up to v0.37.0 | range up to v0.38.0, the entry above first |
| Index rows 136, 137, 138 and their Done | PR numbers, not released | `; v0.38.0`; merge dates; `Released: v0.38.0` |
| P-139 | merged from `design/`, no index row, no Done | `git mv` to `complete/`; index row; Done with merge date, release and evidence |
| Index rows 084 and 107 and their Done | `PR #107`; `PR #132; pending release` | `; v0.38.0`; merge dates; `Released: v0.38.0` |
| Index: a row for this record | — | added |
| git tag `v0.38.0` | — | on the `main` commit this PR's merge produces |

P-139 reached `main` while still in `design/`, as P-133 and P-134 did before v0.37.0. The maintainer had it merged,
which is the word to ship; the move to `complete/` and its Done section are in this record's PR so that `main` again
holds only `complete/` and `rejected/` (besides the folders' `.gitkeep`).

## After the tag

The release workflow publishes the six npm packages and the GitHub release. Check that all six reach `0.38.0` and that
the release lists `bas-guard-*`, `aguard-*` and `SHA256SUMS.txt`.

The raw archives of the judge runs of P-114, P-115, P-116 and P-117 are still not on the machine this release was cut
from.

## Done

```
Merged: PR #167 (2026-11-19; find the sha with git log --grep P-140)
Released: v0.38.0
Evidence: make verify: all gates passed on the branch, after merging main 0bf9758 (P-084 merged; P-107 and P-113 before it)
Evidence: bas-guard version on main before this branch: rules=64f57c6f747c judge-prompt=9cd57da1a4bd judge-excerpt=10, on bdfcc67 (P-139) and again on 0bf9758 (P-084)
```
