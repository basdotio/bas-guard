<!-- SPDX-License-Identifier: MIT -->
# 135 — Release record v0.37.0: P-129, P-131, P-132, P-133, P-134

- **Source**: the maintainer said "发 v0.37.0" (2026-11-17), after P-133 and P-134 were merged. A release does not go
  through a proposal; this file is only the record.
- **Includes**: P-129 (PR #155), P-131 (PR #157), P-132 (PR #158), P-133 (PR #159), P-134 (PR #160). Nothing else
  merged since v0.36.0; the open pull requests stay out.
- **Branch**: `p/135-release-0.37.0`

## Why minor

Five rules are new: `EXEC-014` and `SUP-011` (P-132), `SUP-008` and `SUP-009` (P-129), `SUP-010` (P-131), so the rule
table goes from 90 to 95 IDs. No flag, exit code or JSON field changed meaning, but the same input can now produce
findings it did not: a skill's `!` shell (P-132), a settings file's helper commands (P-133) and a package's install-time
scripts (P-129) are read, and a prerequisite lure is reported (P-131). A gate that passed can fail on upgrade, on
findings that were always there. `PERM-007` also stops firing on scripts that only read a settings file (P-134).

`rules` `dbd22857f91a` → `6e839a428eb8` (`rulesEpoch` 17 → 22: P-129 took 18, P-132 19, P-134 20, P-133 21, P-131 22,
in merge order); `judge-prompt` `9cd57da1a4bd` and `judge-excerpt` 10 unchanged.

## Changelog

`CHANGELOG.md`, entry **v0.37.0 (2026-11-17)**, written from the five proposals, with an upgrade note for CI gates.

## What changed where

| Place | Before | After |
|---|---|---|
| `plugin/.claude-plugin/plugin.json` `version` | `0.36.0` | `0.37.0` |
| `.claude-plugin/marketplace.json` plugin entry `version` | `0.36.0` | `0.37.0` |
| `CHANGELOG.md` | range up to v0.36.0 | range up to v0.37.0, the entry above first |
| Index rows 129, 131, 132 and their Done | PR numbers, not released | `; v0.37.0`; merge dates; `Released: v0.37.0` |
| P-133 and P-134 | merged from `design/`, no index row, no Done | `git mv` to `complete/`; index rows; Done with merge date, release and evidence |
| Index: a row for this record | — | added |
| git tag `v0.37.0` | — | on the `main` commit this PR's merge produces |

P-133 and P-134 reached `main` while still in `design/`, waiting for the maintainer's word to ship. The maintainer had
them merged (P-134, then P-133), which is that word; the move to `complete/` and their Done sections are in this
record's PR so that `main` again holds only `complete/` and `rejected/`, as the proposals README requires.

## After the tag

The release workflow publishes the six npm packages and the GitHub release. Check that all six reach `0.37.0` and that
the release lists `bas-guard-*`, `aguard-*` and `SHA256SUMS.txt`.

The raw archives of the judge runs of P-114, P-115, P-116 and P-117 are still not on the machine this release was cut
from.

## Done

```
Merged: PR #161 (2026-11-17; find the sha with git log --grep P-135)
Released: v0.37.0
Evidence: make verify: all gates passed on the branch
Evidence: bas-guard version on main before this branch: rules=6e839a428eb8 judge-prompt=9cd57da1a4bd judge-excerpt=10
```
