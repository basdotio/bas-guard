<!-- SPDX-License-Identifier: MIT -->
# 112 — Release record v0.33.1: P-111

- **Source**: the maintainer said "发版" (2026-10-27), after P-111 was merged. A release does not go through a
  proposal; this file is only the record.
- **Includes**: P-111 (PR #136). Nothing else merged since v0.33.0.
- **Branch**: `p/112-release-0.33.1`

## Why patch

Documentation only: the README pair loses its rename section. No code, flag, exit code or JSON field changed.
`rules` (`717ada4c680b`), `judge-prompt` (`b851dfd5412b`) and `judge-excerpt` (9) are the same as in v0.33.0.

The npm packages' READMEs come from `npm/README.md.tmpl` and `npm/alias/README.md.tmpl`, which never had the section;
they are unchanged.

## Changelog

`CHANGELOG.md`, entry **v0.33.1 (2026-10-27)**, written from P-111.

## What changed where

| Place | Before | After |
|---|---|---|
| `plugin/.claude-plugin/plugin.json` `version` | `0.33.0` | `0.33.1` |
| `.claude-plugin/marketplace.json` plugin entry `version` | `0.33.0` | `0.33.1` |
| `CHANGELOG.md` | range up to v0.33.0 | range up to v0.33.1, the entry above first |
| Index row 111, P-111's Done | `PR #136` | `PR #136; v0.33.1`; `Released: v0.33.1` |
| Index: a row for this record | — | added |
| git tag `v0.33.1` | — | on the `main` commit this PR's merge produces |

## After the tag

The release workflow publishes the six npm packages and the GitHub release. Check that all six reach `0.33.1` and that
the release lists `bas-guard-*`, `aguard-*` and `SHA256SUMS.txt`.

## Done

```
Merged: PR #<n> (2026-10-27; find the sha with git log --grep P-112)
Released: v0.33.1
Evidence: make verify: all gates passed on the branch
Evidence: bas-guard version on main before this branch: rules=717ada4c680b judge-prompt=b851dfd5412b judge-excerpt=9
```
