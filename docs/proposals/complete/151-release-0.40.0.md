<!-- SPDX-License-Identifier: MIT -->
# 151 — Release record v0.40.0: P-149, P-150

- **Source**: the maintainer asked for the release record ("起草发版记录", 2026-11-26), after P-150 was merged. A
  release does not go through a proposal; this file is only the record.
- **Includes**: P-149 (PR #176) and P-150 (PR #177), both in the optional judge. Nothing else merged since v0.39.0,
  and no pull request is open.
- **Branch**: `p/151-release-0.40.0`

## Why minor

Nothing changes for a run without `--llm`: no rule, flag, exit code, config key or JSON field is new or changed
meaning, and the rule table stays at 98 IDs. `llm preview` gains one thing, the count of script files a planned call
leaves out.

With `--llm`, the same server can end at a different weight. Until now a server finding the model marked `disclosed`
was taken one step down: high to medium, medium to low. P-150 keeps that step for skills only. Such a finding now reads
its category's weight, so a server's `overall_effective` can be lower than it was and a `--fail-on-llm` gate that
passed can fail on upgrade. The same input can produce a different answer, which is why this is a minor release and
not a patch.

How often, on the stored answers of two models over 802 Python server trees (179 malicious, 623 benign), replayed with
no model call: with gpt-4.1-mini, malicious servers at high go from 135 to 136 and benign from 38 to 40; with glm-5.3,
from 91 to 101 and from 29 to 32. Each is one run. The numbers are exact for those answers and say nothing about the
next run. Skills are weighed as before.

P-149 changes no request and no verdict. A `--llm` report counts, in its `LLM-000` note, the script and config files
that did not fit the judge's excerpt. On the corpus 3.6% of benign skills and 41% of benign servers gain the note.

`rules` `6ed8b90f6b4f`, `judge-prompt` `9cd57da1a4bd` and `judge-excerpt` 10 are all unchanged from v0.39.0
(`rulesEpoch` stays 30). The weight P-150 changes is applied by the tool after the model has answered, and neither
judge identifier covers it: only `tool_version` tells a v0.40.0 judge reading from a v0.39.0 one.

## Changelog

`CHANGELOG.md`, entry **v0.40.0 (2026-11-26)**. The two entries under `## Unreleased` move under the version as
written, each with its author and day (P-141). The release adds a headline, a summary paragraph and an upgrade note for
CI gates. `## Unreleased` stays, empty.

## What changed where

| Place | Before | After |
|---|---|---|
| `plugin/.claude-plugin/plugin.json` `version` | `0.39.0` | `0.40.0` |
| `.claude-plugin/marketplace.json` plugin entry `version` | `0.39.0` | `0.40.0` |
| `CHANGELOG.md` | two entries under `## Unreleased`; range up to v0.39.0 | `## Unreleased` empty; range up to v0.40.0, the entry above first |
| Index rows 149 and 150 and their Done | `pending release`; `Released: pending` | `v0.40.0`; `Released: v0.40.0`; their merge dates |
| Index: a row for this record | — | added |
| git tag `v0.40.0` | — | on the `main` commit this PR's merge produces |

## After the tag

The release workflow publishes the six npm packages and the GitHub release. Check that all six reach `0.40.0` and that
the release lists `bas-guard-*`, `aguard-*` and `SHA256SUMS.txt`.

P-150 committed the folded files of one judge run, `baselines/results/aguard/2026-11-25-llm-glm-5.3-servers-s3/`, and
said its raw outputs go on the release that carries the change. Attach them to this release once the workflow has
published it: `aguard-judge-raw-2026-11-p150.tar.gz`, 802 files under `2026-11-25-llm-glm-5.3-servers-s3/raw/`, sha256
`9ad108453929ffbb8f3a3359c22fdf5e14d8e27a5e931d5b8ced6e71c920e107`. The archive names no path of the machine the run
was made on: those read `<workspace>/…` and `<home>/…`, and the tar headers carry no owner. `replay.py` in that result
directory, run on the unpacked archive, prints the reading `compare.txt` records. P-149 made no judge run and has no
archive.

## Done

```
Merged: PR #178 (find the date and the sha with git log --grep P-151 after the merge)
Released: v0.40.0
Evidence: make verify: all gates passed on the branch
Evidence: bas-guard version on main 4d873d1 before this branch: rules=6ed8b90f6b4f judge-prompt=9cd57da1a4bd judge-excerpt=10, the three v0.39.0 prints
Evidence: the two entries under v0.40.0 are byte for byte the entries main 4d873d1 held under Unreleased
Evidence: of what a user installs or runs, v0.39.0..4d873d1 touches internal/judge only (git diff --stat v0.39.0 4d873d1 -- cmd internal plugin npm hack/github-action.yml)
Evidence: aguard-judge-raw-2026-11-p150.tar.gz: 803 members, 802 files; replay.py on the unpacked archive prints malicious 91 → 101 and benign 29 → 32, nothing open
```
