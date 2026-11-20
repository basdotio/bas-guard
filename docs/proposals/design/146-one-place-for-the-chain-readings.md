<!-- SPDX-License-Identifier: MIT -->
# 146 — "Where does this file's key go" is read three ways by three callers, and nothing shows the three together

- **Source**: the maintainer, 2026-11-20 ("可以先开始3吗"), on the third point of that day's architecture review ("the
  same question has several answers")
- **Depends on**: none. P-095, P-062, P-098 and P-117 are the proposals that set the readings this one puts side by side
- **Branch**: `p/146-one-reading-of-where-a-key-goes`

## Problem

The exfiltration chain is built in four places: the rules' scan loop, and three functions the judge calls to weigh a
`credential-read` vote (`CredentialGoesHome`, `CredentialGoesHomeAcross`, `CredentialSentElsewhere`). Each builds its
own chain with its own settings and, outside the scan loop, each carries its own copy of the loop that feeds a file's
lines to it. The settings differ on purpose: P-095 made a URL literal a send only in a script that can send, for the
rules alone; P-117 gave the judge's "sent elsewhere" a wider list of request calls, for the judge alone. But the
differences are written in three comments in two files, and one of them is wrong: `CredentialGoesHome` is documented
as "computed … by the same chain EXFIL-001 runs, so the two passes cannot disagree about where a key went", which has
not been true since P-095.

The lists of "a way to send" are in the same state. There are five (`networkActionRE`, `networkCapableRE`,
`requestLineRE`, and `HOOK-003`'s senders for Python and for Node), each read by a different question, never written
down together. A client added to one is a client nobody decided about in the other four.

The review that raised this said the same file "may be answered differently" by the rules and the judge. That was a
guess, and it is measured here before anything is changed.

**How often the readings disagree.** Every code file of the corpus's skill and server trees (8,162 files), the rules'
finding on the file from the static run of `main` at `9efe48c`, and the two judge-side answers computed on the same
bytes (`agent-guard-work/exfil-proto/zz_agree_test.go`, local):

| the rules' chain | judge: goes home | judge: sent elsewhere | files |
|---|---|---|---:|
| high | no | no | 169 |
| high | no | yes | 52 |
| high | **yes** | no | 5 |
| low | no | no | 6 |
| low | yes | no | 66 |
| none | no | no | 7,787 |
| none | no | **yes** | 48 |
| none | **yes** | no | 29 |

- Where the rules report a chain (298 files), the judge's readings never contradict it: no file the rules call home
  is "sent elsewhere" to the judge. The five that are high to the rules and home to the judge are all `EXFIL-003`,
  which takes no destination downgrade by design. The six that are low to the rules and not "home" are loopback
  chains with no named credential, which "home" does not answer for.
- On 77 files the judge's wider readings see a chain where the rules see none. They are read only when a vote cites
  the file, and they are what P-095 and P-117 decided.

So the answers do not conflict. What is wrong is that nobody can see that without running a survey.

## Initial direction

Structure only; no answer changes.

1. `internal/detect/chainreadings.go` holds the three readings as three named constructors (`rulesChain`,
   `homeChain`, `elsewhereChain`) under one table that says how they differ, why, and what the survey measured, and
   one `replay` loop. The scan loop and the three functions use them. The wrong sentence is corrected.
2. Two tests put the readings and the lists against each other: one file per row with what the rules report and what
   each judge question answers; one spelling per row with which of the five lists knows it. A change to a reading or
   a list changes a cell, and the row asks what the others do.

No `rulesEpoch`, no `ExcerptVersion`, no changelog entry: nothing a user runs or reads changes.

## Done criteria

- [x] `TestChainReadings_SideBySide` (`internal/detect/chainreadings_test.go`): seven files, the rules' finding and
  both judge answers on each, every difference across the columns named by the proposal that set it
- [x] `TestNetworkClients_WhichListKnowsWhich`: 28 spellings against the five lists
- [x] Reverse assertion, the judge's helpers: `CredentialGoesHome`, `CredentialSentElsewhere` and
  `CredentialOverreach` on the 8,162 files, `main` against the branch: the output is byte-identical
- [x] Reverse assertion, the rules: static on the corpus (5,272 samples, every artifact's findings compared in full:
  evidence, text and order), the fresh skills (412) and the held-out set (totals and a count of samples that differ):
  no finding differs
- [x] Every existing test green without a character changed in what it asserts
- [ ] `make verify` green, read from its own exit code

## Out of scope

- **Making the three readings one.** It would move the 77 answers above and the benign votes they lower. A reading
  changes the way it was set: with a measurement.
- **`HOOK-003`'s senders.** They are in the table of lists; their reader follows arguments and is another mechanism.

## Must not claim

- Not "the rules and the judge give one answer". They give three, on purpose, and now in one place.
- No finding, score, vote or benchmark number changes.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | The readings and the replay loop in one file, used by the scan loop and the three functions; the two tests | `detect: the three readings of the exfiltration chain in one place (P-146)` |
| 2 | Done, the index, `complete/` | `proposals: P-146 done (P-146)` |

## Open questions

1. **Structure only?** Recommended: **yes.** The survey says the readings do not conflict where both answer, and that
   merging them moves 77 files' answers for no finding gained.

## Done

Filled in at stage 4.
