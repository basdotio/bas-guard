<!-- SPDX-License-Identifier: MIT -->
# 126 — Release record v0.35.0: P-123, P-124, P-125

- **Source**: the maintainer said "发版" (2026-11-16), after P-123, P-124 and P-125 were merged. A release does not go
  through a proposal; this file is only the record.
- **Includes**: P-123 (PR #149), P-124 (PR #150), P-125 (PR #151), and `issues/029` (recorded with P-125). Nothing else
  merged since v0.34.0; the open pull requests stay out.
- **Branch**: `p/126-release-0.35.0`

## Why minor

One rule is new: `INJ-006` (P-123), so the rule table goes from 88 to 89 IDs. No flag, exit code or JSON field changed
meaning, but the same input can now produce findings it did not: the matched view decodes tag characters (P-123),
`PERM-007`'s file-level half closes on one line (P-124), and `check <dir>` reads a project's instruction files and their
imports (P-125). A gate that passed can fail on upgrade, on findings that were always there.

`rules` `39b17de88dd4` → `35dbd6adf202` (`rulesEpoch` 12 → 15: P-123 took 13, P-124 14, P-125 15, in merge order);
`judge-prompt` `9cd57da1a4bd` and `judge-excerpt` 9 unchanged.

## Changelog

`CHANGELOG.md`, entry **v0.35.0 (2026-11-16)**, written from the three proposals, with an upgrade note for CI gates.

## What changed where

| Place | Before | After |
|---|---|---|
| `plugin/.claude-plugin/plugin.json` `version` | `0.34.0` | `0.35.0` |
| `.claude-plugin/marketplace.json` plugin entry `version` | `0.34.0` | `0.35.0` |
| `CHANGELOG.md` | range up to v0.34.0 | range up to v0.35.0, the entry above first |
| Index rows 123, 124, 125 and their Done | PR numbers, not released | `; v0.35.0`; merge dates; `Released: v0.35.0` |
| Index: a row for this record | — | added |
| git tag `v0.35.0` | — | on the `main` commit this PR's merge produces |

## After the tag

The release workflow publishes the six npm packages and the GitHub release. Check that all six reach `0.35.0` and that
the release lists `bas-guard-*`, `aguard-*` and `SHA256SUMS.txt`.

The raw archives of P-114's and P-115's judge runs, which v0.34.0's record said were to be attached afterwards, are
still not on the machine this release was cut from.

## Done

```
Merged: not yet — PR pending
Released: (fill in after the release)
Evidence: make verify: all gates passed on the branch
Evidence: bas-guard version on main before this branch: rules=35dbd6adf202 judge-prompt=9cd57da1a4bd judge-excerpt=9
```
