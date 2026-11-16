<!-- SPDX-License-Identifier: MIT -->
# 122 — Release record v0.34.0: P-115, P-119, P-120, P-121

- **Source**: the maintainer said "发 v0.34.0" (2026-11-16), after P-121 was merged. A release does not go through a
  proposal; this file is only the record.
- **Includes**: P-115 (PR #141), P-119 (PR #145), P-120 (PR #146), P-121 (PR #147), and the baselines change of PR #138
  (verdicts name the files the flagging findings pointed at; benchmark tooling, not in the binary). Nothing else merged
  since v0.33.1; the open pull requests stay out.
- **Branch**: `p/122-release-0.34.0`

## Why minor

One JSON field is added: `within`, on an artifact that a `check` target's own configuration added (P-120). No flag or
exit code changed meaning, but the same input can now produce findings it did not: `check` reads a project's
configuration (P-120), `scan` reads local-scope MCP servers (P-119), `INJ-005` reads more spellings (P-121), and two
judge categories weigh high (P-115). A gate that passed can fail on upgrade, on findings that were always there.

`rules` `717ada4c680b` → `39b17de88dd4` (`rulesEpoch` 9 → 12: P-119, P-120, P-121, plus P-121's table change);
`judge-prompt` `b851dfd5412b` → `9cd57da1a4bd` (P-115's server table); `judge-excerpt` 9 unchanged.

## Changelog

`CHANGELOG.md`, entry **v0.34.0 (2026-11-16)**, written from the four proposals, with an upgrade note for CI gates.

## What changed where

| Place | Before | After |
|---|---|---|
| `plugin/.claude-plugin/plugin.json` `version` | `0.33.1` | `0.34.0` |
| `.claude-plugin/marketplace.json` plugin entry `version` | `0.33.1` | `0.34.0` |
| `CHANGELOG.md` | range up to v0.33.1 | range up to v0.34.0, the entry above first |
| Index rows 115, 119, 120, 121 and their Done | PR numbers, not released | `; v0.34.0`; merge dates; `Released: v0.34.0` |
| Index: a row for this record | — | added |
| git tag `v0.34.0` | — | on the `main` commit this PR's merge produces |

## After the tag

The release workflow publishes the six npm packages and the GitHub release. Check that all six reach `0.34.0` and that
the release lists `bas-guard-*`, `aguard-*` and `SHA256SUMS.txt`.

P-115's Done says the raw archives of its two judge runs go on the next release, with P-114's. They are not on the
machine this release was cut from (the runs' `run.yaml` name another maintainer's working directory), so the release
goes out without them. Whoever holds them attaches them to `v0.34.0` afterwards (`gh release upload v0.34.0 <archive>`),
as earlier raw archives were; until then the P-114 and P-115 result directories cannot be re-folded from raw.

## Done

```
Merged: PR #148 (2026-11-16; find the sha with git log --grep P-122)
Released: v0.34.0
Evidence: make verify: all gates passed on the branch
Evidence: bas-guard version on main before this branch: rules=39b17de88dd4 judge-prompt=9cd57da1a4bd judge-excerpt=9
```
