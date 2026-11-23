<!-- SPDX-License-Identifier: MIT -->
# 148 — Release record v0.39.0: P-103, P-106, P-143, P-144, P-145, P-147

- **Source**: the maintainer asked for the release record ("起草发版记录", 2026-11-24), after P-147 was merged. A
  release does not go through a proposal; this file is only the record.
- **Includes**: P-103 (PR #128), P-106 (PR #130), P-143 (PR #170), P-144 (PR #171), P-145 (PR #172) and P-147
  (PR #174), which change what a user runs; P-141 (PR #168, the changelog check and its rule) and P-146 (PR #173, a
  refactor), which do not; and the record of one rejected proposal, P-142 (PR #169). Nothing else merged since
  v0.38.0, and no pull request is open.
- **Branch**: `p/148-release-0.39.0`

## Why minor

No rule is new: the rule table stays at 98 IDs. No flag, exit code or JSON field changed meaning. But the same input
can now produce findings it did not.

`EXFIL-001` drops to a low advisory when a named key goes to its own service. Three changes narrow what counts as its
own service: a base URL that ends at its host no longer vouches for what a line appends to it (P-143, which moves
`HOOK-003` in the same shape), only a host's registrable label vouches (P-144), and a well-known service's name vouches
only under that service's own domains (P-145). A fourth makes the chain see a Python client imported after another name
on its line (P-147). A gate that passed can fail on upgrade, on a script that was reported low or not at all.

How often, on the corpus, as the four proposals measured it: benign samples reported high go from 337 to 341 of 4,534
(one by P-143, three by P-144); malicious stay at 243 of 719; P-145 and P-147 change no sample.

P-106 adds a config key (`llm.result_pass`, on by default) and a judge-block field (`passes_off`, present only when a
question is off). P-103 changes how many calls the judge makes, not what it concludes: a question whose remaining
samples cannot change its outcome is not asked again, and the judge block counts those calls as `settled`.

`rules` `64f57c6f747c` → `6ed8b90f6b4f` (`rulesEpoch` 26 → 30: P-143 took 27, P-144 28, P-145 29, P-147 30, in merge
order); `judge-prompt` `9cd57da1a4bd` and `judge-excerpt` 10 unchanged.

## Changelog

`CHANGELOG.md`, entry **v0.39.0 (2026-11-24)**. This is the first release under P-141: the six entries under
`## Unreleased` move under the version as written, each with its author and day. The release adds a headline, a
summary paragraph, an upgrade note for CI gates, and one line for P-141, P-142 and P-146, which had no entry.
`## Unreleased` stays, empty.

## What changed where

| Place | Before | After |
|---|---|---|
| `plugin/.claude-plugin/plugin.json` `version` | `0.38.0` | `0.39.0` |
| `.claude-plugin/marketplace.json` plugin entry `version` | `0.38.0` | `0.39.0` |
| `CHANGELOG.md` | six entries under `## Unreleased`; range up to v0.38.0 | `## Unreleased` empty; range up to v0.39.0, the entry above first |
| Index rows 103, 106, 141, 143, 144, 145, 147 and their Done | `pending release` | `; v0.39.0`; `Released: v0.39.0`; merge dates where they were missing (103, 106, 141, 147) |
| Index row 146 and its Done | `no release entry (a refactor)` | `v0.39.0, no changelog entry (a refactor)`; `Released: v0.39.0` |
| Index: a row for this record | — | added |
| git tag `v0.39.0` | — | on the `main` commit this PR's merge produces |

## After the tag

The release workflow publishes the six npm packages and the GitHub release. Check that all six reach `0.39.0` and that
the release lists `bas-guard-*`, `aguard-*` and `SHA256SUMS.txt`.

The raw archives of the judge runs of P-114, P-115, P-116, P-117 and P-118 (`aguard-judge-raw-2026-11-p114.tar.gz` to
`…-p118.tar.gz`) are on the machine this release is cut from. Each of those proposals says its archive goes on the next
release; the releases since were cut from another machine and went out without them. Attach the five to this release
once the workflow has published it.

## Done

```
Merged: PR #175 (find the date and the sha with git log --grep P-148 after the merge)
Released: v0.39.0
Evidence: make verify: all gates passed on the branch
Evidence: bas-guard version on main 8035e47 before this branch: rules=6ed8b90f6b4f judge-prompt=9cd57da1a4bd judge-excerpt=10
Evidence: the six entries under v0.39.0 are byte for byte the block main 8035e47 held under Unreleased
```
