<!-- SPDX-License-Identifier: MIT -->
# 108 — Release record v0.33.0: P-105

- **Source**: the maintainer said "发 v0.33.0，把 P-105 写进发布记录" (2026-10-27). A release does not go through a
  proposal; this file is only the record.
- **Includes**: P-105 (PR #131). Nothing else merged since v0.32.0.
- **Branch**: `p/108-release-0.33.0`

## Why minor

An exit code gains a cause: under `--fail-on`, a root that held nothing to check, or a project's `.claude` it did not
read, exits 4 where it exited 0. A CI job that ran the old template from a project's top level goes red on upgrade —
correctly, since it never read the project's skills — so this is not a patch. No flag or JSON field was added or removed.

`rules` (`717ada4c680b`), `judge-prompt` (`b851dfd5412b`) and `judge-excerpt` (9) are the same as in v0.32.0: the new
note is a dimension-0 COV-000, not a rule.

## Changelog

`CHANGELOG.md`, entry **v0.33.0 (2026-10-27)**, written from P-105's Problem and Decisions, with an upgrade note for CI
jobs.

## What changed where

| Place | Before | After |
|---|---|---|
| `plugin/.claude-plugin/plugin.json` `version` | `0.32.0` | `0.33.0` |
| `.claude-plugin/marketplace.json` plugin entry `version` | `0.32.0` | `0.33.0` |
| `CHANGELOG.md` | range up to v0.32.0 | range up to v0.33.0, the entry above first |
| Index row 105, P-105's Done | `PR #131` | `PR #131; v0.33.0`; `Released: v0.33.0` |
| Index: a row for this record | — | added |
| git tag `v0.33.0` | — | on the `main` commit this PR's merge produces |

## After the tag

The release workflow publishes the six npm packages and the GitHub release. Check that all six reach `0.33.0` and that
the release lists `bas-guard-*`, `aguard-*` and `SHA256SUMS.txt`.

## Done

```
Merged: PR <pending> (2026-10-27; find the sha with git log --grep P-108)
Released: v0.33.0
Evidence: make verify: all gates passed on the branch
Evidence: bas-guard version on main before this branch: rules=717ada4c680b judge-prompt=b851dfd5412b judge-excerpt=9
```
