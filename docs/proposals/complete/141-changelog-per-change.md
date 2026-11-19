<!-- SPDX-License-Identifier: MIT -->
# 141 — The changelog is written once per release, from memory of what merged, and no entry says who made the change

- **Source**: the maintainer, 2026-11-19 ("a changelog file, synced on every feature update, with four facts: version,
  time, content, author"), decided as suggested the same day
- **Depends on**: none
- **Branch**: `p/141-changelog-per-change`

## Problem

`CHANGELOG.md` has a version, a date and the content of each release. It is written when a release is cut, in the
release record's pull request, from the proposals that release includes. Three things follow:

- A change that has merged and not shipped is nowhere in it. On 2026-11-19 that was P-103 (PR #128) and P-106 (PR #130),
  both merged after the v0.38.0 tag.
- No entry names its author. The repository has more than one, and `git log --grep` is the only way to ask.
- Nothing checks any of it. A change whose author did not think of the changelog reaches a release only if whoever writes
  the release record remembers it.

## Initial direction

An `## Unreleased` section that every change to shipped code adds its own entry to, in its own pull request, with the
author and the day in the entry; a release moves the entries under its version. A check in `make verify` and CI that
fails when the entry is missing.

## Done criteria

- [x] `TestCheck` (`hack/changelog-check`, table-driven): a change to a shipped path with no new entry under
  `## Unreleased` is a problem, including when `CHANGELOG.md` was edited somewhere else and when the section already
  holds another change's entry; a new entry passes; a release that moves the entries under a new version line passes
- [x] The same table pins the entry format: an entry without `@login`, without a day, or with a day that is not a date
  is a problem whether or not the change touched shipped code
- [x] The opt-out is tested as three inputs, not one: `Changelog: none — <reason>` on a line of its own passes; the same
  line without a reason is a problem and does not opt out; a `Changelog:` line that says something else, and the words
  inside a sentence, do not opt out
- [x] Reverse assertion: a change to tests, docs, `hack/`, `baselines/`, CI or a data file needs no entry (`TestShipped`
  and the "tests, docs and tooling" row), and a released bullet without an author is never read as unreleased
  (`TestUnreleased_StopsAtTheNextSection`)
- [x] `go run ./hack/changelog-check` exits 1 on this branch with one line appended to `cmd/bas-guard/main.go`, 0 with
  the same line appended to a test file, 2 when the base ref does not exist
- [x] `make verify` green, with the check as one of its steps

## Out of scope

- **Authors for the entries up to v0.38.0.** Their proposal numbers sit in different places in each entry, 161 of the
  204 headline bullets have none on their first line, and P-001 to P-041 of the former repository overlap this
  repository's numbers, so a lookup by number names the wrong person for some of them. A wrong name is worse than none.
  The changelog's header says where to ask instead. `git diff` shows no line below `## v0.1.0` changed.
- **Who merged a change, and when.** The entry carries who wrote it and the day it was written; the merge is in
  `git log`.
- **Rewording an entry at release time.** The entries move as written.
- **A hook that writes the entry.** The author writes it, in the change; the check only refuses a change without one.
- No file under `cmd/`, `internal/`, `plugin/` or `npm/` changes: the binary, the plugin and the package are byte for
  byte what `main` builds.

## Must not claim

- Not "every change is in the changelog": a change that touches no shipped path, or that opts out with a reason, is not,
  by design.
- Not "the check verifies the author": it checks that an entry names a GitHub login and a real day, not that the login
  is the person who wrote the change.
- Not "the changelog cannot fall behind": a change merged with the check red, or pushed to `main` directly, is not
  stopped; the `changelog` job runs on pull requests.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | The tests, failing | changelog: tests — a change to shipped code with no entry under Unreleased is not reported (P-141) |
| 2 | The check, in `make verify` and CI | changelog: a change to shipped code needs an entry under Unreleased, with its author and day (P-141) |
| 3 | The section, seeded with what merged since v0.38.0 | changelog: an Unreleased section, with the two changes merged since v0.38.0 (P-141) |
| 4 | The rule, where contributors and agents read it | docs: a change adds its own changelog entry; a release moves them as written (P-141) |
| 5 | This file and its index row | proposals: P-141 (P-141) |

## Open questions

1. Which paths count as shipped? Recommended: non-test Go under `cmd/` and `internal/`, all of `plugin/` and `npm/`,
   and `hack/github-action.yml`; one list, in `hack/changelog-check/check.go`.
   **Decided (2026-11-19)**: as recommended ("do it as you proposed").
2. What does a refactor do? Recommended: a commit-message line `Changelog: none — <reason>`, read by the check, with the
   reason required. **Decided (2026-11-19)**: as recommended.
3. Are the old entries given authors? Recommended: no, see Out of scope. Not yet put to the maintainer as its own
   question; raised in the pull request.

## Done

```
Merged: PR (fill in once opened; find the sha with git log --grep P-141 after the merge)
Released: (fill in after the release)
Evidence: TestCheck (hack/changelog-check/check_test.go), 20 rows; TestUnreleased_EntriesAreWholeBullets, TestUnreleased_StopsAtTheNextSection, TestShipped. Written first: the package did not build without Input and Check
Evidence: mutations, each run and reverted — any unreleased entry counts as new: "shipped code on top of somebody else's unreleased entry" fails; an opt-out without a reason counts: "opted out without a reason" fails; the section does not end at the next heading: TestCheck fails from its first row
Evidence: end to end on this branch, base HEAD — one line appended to cmd/bas-guard/main.go: exit 1, naming the file; the same line appended to cmd/bas-guard/main_test.go: exit 0; -base origin/nope: exit 2, naming the ref
Evidence: reverse — make verify green on macOS with the step in it; git diff origin/main --stat names no file under cmd/, internal/, plugin/ or npm/; go.mod's second line is go 1.23.5
```
