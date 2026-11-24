<!-- SPDX-License-Identifier: MIT -->
# 149 — The judge is not shown the scripts past its excerpt budget, and no report says so

- **Source**: the maintainer, 2026-11-24 ("好" to: measure, for the SkillHarm trees the judge missed, whether it was
  shown the payload; then "先做提案和实现"). P-037 named this limit and left it for a proposal of its own
- **Depends on**: P-037 (`boundedNote`, the note this one joins); P-027 (`llm preview`, which carries `shortened`).
  P-070 (rejected) is the measurement this proposal does not repeat
- **Branch**: `p/149-scripts-left-out-are-counted`

## Problem

The intent pass (`LLM-001`, skills) and the server-source pass (`LLM-010`) read a tree's script and config files through
one walker: files by name, each cut to 2,000 bytes, until 6,000 bytes are spent. Then the walk stops. The files after
that point are not sent, and nothing in the report or in `llm preview` says they exist.

Every other field the judge cuts says what it left out: named documents, decoded payloads, digest lines, MCP
configuration lines, triage items (P-037, P-065, P-068). P-037 recorded the exception:

> Two judge limits are still silent, as on the base: the intent pass leaves out files past its 6,000-byte budget, and the
> deobfuscation pass blobs past its eighth. Disclosing them adds a note to many large skills, so it is its own proposal.

**What it looks like.** One of the 240 SkillHarm trees is the PDF skill with a ninth script added,
`scripts/prepare_pdf_environment.py`, and two lines in `SKILL.md` telling the agent to run it before anything else.
The tree's nine scripts sort `check_…`, `convert_…`, `create_…`, `extract_…`, `fill_…`, `prepare_…`; the excerpt holds
the first five. On the full run of 2026-11-04 that tree is 100/100, the judge made 12 calls and reported nothing, and
its only `LLM-000` is about two named documents. A reader of that report has no way to tell that the one script the
skill says to run was not among the files read.

**How often, on SkillHarm.** For the 69 trees static and the judge both miss (11-04 judge run, today's rules), the
upstream's `metadata.json` says which file each attack adds or changes, and `llm preview --json` says which lines each
request carries. 12 of the 69 payloads are in no request at all: 8 are a script past the budget (the case above; all in
trees of 8 to 14 scripts), 4 are a document named by a named document (P-065's recorded one-level rule). The release
of 11-04 and v0.39.0 show the judge the same lines on all 240 trees.

**What this proposal does not do, and why.** The obvious fix — send the scripts `SKILL.md` names first — is P-070,
measured live in two variants on 2026-10-17 and rejected: the named scripts got in, the unnamed files that carry
SkillHarm's `executable_code` and `import_new_helper` payloads were pushed out (178 → 174 caught), and giving the named
files a budget of their own caught no more than the run band (178 → 173) while the benign list went 62 → 68. A
visibility-only recheck on 2026-11-24 with a prototype of the first variant (reordering only where the files do not
fit, names taken from `SKILL.md` and from the documents it names) agrees without a judge call: of the 240 trees, 6 see
more of their payload and 8 see less. The order is not changed here.

## Initial direction

The walker goes on where it stopped and counts the script and config files it would have reached, without opening
them. The count is the call's `shortened` — `6 of 9 script or config file(s) past the 6000-byte excerpt not sent` — which
`llm preview` already prints and `boundedNote` already turns into the run's one `LLM-000` (`fitsByUnits` gains the
intent and server modes). A file cut to its cap, or to the room left, is not counted: its text carries the omission
marker.

No request changes by a byte. The first file with no room ends the excerpt as before; a later file with a shorter name
is not tried, so no fragment that was not sent is sent now. `ExcerptVersion` and `PromptVersion` stay; `rulesEpoch`
stays (no static finding changes).

## Done criteria

The corpus lines were written while the comparison was running, before its result was read.

- [x] `TestBehaviorExcerpt_SaysHowManyFilesItLeftOut`: eleven rows in pairs — five and nine scripts, a config file past
  the budget, a directory only the skill pass reads; and what is not a file left out: three that fill the excerpt
  exactly, three small ones, one file of 50 KB, a third cut to the room left, a document, a vendored directory, a
  directory the server pass skips
- [x] `TestBehaviorExcerpt_SendsWhatTheStoppedWalkSent`: five trees against the walker as it was (kept in the test as the
  reference), for both passes; one tree in which a later, shorter-named file would have had room, with that
  precondition asserted. Run with the walk trying every later file: red
- [x] `TestRun_ScriptsLeftOutAreDisclosed`: a skill of nine scripts and a server of six modules each produce one
  `LLM-000` naming the artifact and the count, and the same words as the planned call's `shortened`; a skill of three
  and a server of one produce none; the nine-script skill's intent request is the reference walker's bytes, and the
  script its `SKILL.md` says to run is still not in it
- [x] `TestExcerptVersion_IsPinnedWithItsGolden` unchanged and green: the fixture's planned excerpts, its `shortened`
  values and its grounding results are the pinned digest, at `ExcerptVersion` 10
- [x] Planned requests, v0.39.0 against the branch, by `llm preview --json` on every corpus sample (5,272 at
  `c314e4d9`): **no sample** has a request whose pass, rule, call count, payload or sources differ; no other pass's
  `shortened` differs; 0 preview errors on either side
- [x] The same on the held-out set, totals only: 0 differ
- [x] The count of samples that gain the note, per class, for the intent pass and for the server pass, with the number
  asked — reported, whatever it is (P-037's "many large skills")
- [x] `go test -count=1 ./baselines/cmd/judgefold/` green, goldens untouched
- [x] Docs: `docs/llm-judge.md` and `.zh-CN.md`, `docs/architecture.md` and `.zh-CN.md`, the intent row of the spec's pass
  table, `.claude/rules/judge.md` (three things not to change), `CHANGELOG.md`
- [x] `make verify` green from its own exit code

No judge run is needed: the requests are the same bytes.

## Measured

`llm preview --json` of v0.39.0 (`e25e3ab`) against the branch, corpus `c314e4d9`, 2026-11-24. No network, no key.

| | samples | a request differs | another pass's `shortened` differs | preview errors |
|---|---:|---:|---:|---:|
| corpus | 5,272 | 0 | 0 | 0 |
| held-out (totals only) | 459 | 0 | 0 | 0 |

Who gains the note:

| pass | class | asked | gain the note | files left out: median, most |
|---|---|---:|---:|---|
| intent (skills) | benign | 2,909 | 105 (3.6%) | 9, 51 |
| intent (skills) | malicious | 473 | 43 (9.1%) | 5, 16 |
| server source | benign | 629 | 258 (41.0%) | 7, 63 |
| server source | malicious | 180 | 30 (16.7%) | 8, 19 |
| intent, held-out | benign / malicious | 216 / 243 | 0 / 16 | — |

Samples whose plan carries some `shortened`: 420 before, 741 after. For skills the note is rare; for servers it is
four in ten, because a server's source is larger than three files' worth: on those trees the judge has been reading
the first few modules by name all along, and the report now says so.

End to end, a nine-script skill against a local endpoint that answers "not flagged" to everything, `check --llm
--fail-on-llm high`: v0.39.0 prints `Judge: checked 1 skill, nothing to add` and exits 0; the branch prints the same
line, then `Not checked — 1 coverage note(s), highest low [LLM-000]`, and exits 0. `--verbose` reads `the judge saw a
shortened excerpt for skill:skill (6 of 9 script or config file(s) past the 6000-byte excerpt not sent). What was left
out was not judged; the static findings are unaffected.`

## Out of scope

- **Showing the judge those files.** Not by reordering (P-070, and the recheck above). Not by a larger budget or a
  further question per tree: P-070's second variant put six of thirteen unseen payloads in view without taking
  anything away, and the model caught no more of them than the run band; P-114 added text to the server pass and
  benign escalations went 60 → 96. Either would need a paid run on a benign list first, and P-070's reading is that a
  stronger model comes before a larger excerpt.
- **A document named by a named document** (4 of the 12). P-065's one-level rule, recorded in `.claude/rules/judge.md`.
- **The deobfuscation pass's blobs past the eighth**: P-037's other silent limit. Counting them means decoding past the
  cap; its own change.
- **`--fail-on-llm`**: a shortened excerpt is an answer, not a gap (P-026). The exit code does not read this note.
- **Which files were left out.** The note is a count. `llm preview <path>` lists the files each call carries.

## Must not claim

- No benchmark number moves, with the judge or without: no request changes, so no vote does.
- Not "the judge now reads every script". It reads what it read. A skill can still be written so that the script that
  matters is past the budget; after this change the report says files were left out, and the static rules read all of
  them as before.
- The 8 SkillHarm payloads past the budget are still past it.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | The walker counts the files past the budget; the intent and server calls carry it as `shortened`; tests; docs; changelog; rules notes | `judge: say how many script files the excerpt left out (P-149)` |
| 2 | Done, the index, `complete/` | `proposals: P-149 done (P-149)` |

## Open questions

1. **A note on every large tree: acceptable?** Recommended: **yes.** It is one `LLM-000` per run, listing the first
   three artifacts and counting the rest, beside the notes the run already carries; invariant #5 asks for it; and the
   alternative is a report that reads as if nine scripts were judged when three were. Measured: 3.6% of benign skills
   and 41% of benign servers gain it. A `check` of such a server now ends with a "Not checked" line where it ended
   with none.

## Done

```
Merged: PR #176 (find the date and the sha with git log --grep P-149 after the merge)
Released: pending
Evidence: internal/judge/excerpt.go: behaviorExcerptSkipping goes on after the first file with no room and counts the script and config files it reaches, unopened; shortened "N of M script or config file(s) past the 6000-byte excerpt not sent"; planFor sets it on the intent and server calls; fitsByUnits gains both modes, so boundedNote writes the LLM-000
Evidence: TestBehaviorExcerpt_SaysHowManyFilesItLeftOut: eleven rows; five and nine scripts "2 of 5" and "6 of 9", a config file "1 of 4"; three that fill the excerpt, three small, one of 50 KB, a third cut to the room left, a document, node_modules, .github under the server pass: no note
Evidence: TestBehaviorExcerpt_SendsWhatTheStoppedWalkSent: five trees, both passes, byte for byte the walker as it was; with the walk trying every later file (the mutation was run) the test is red on the shorter-name tree
Evidence: TestRun_ScriptsLeftOutAreDisclosed: skill of nine "skill:forms (6 of 9 …)", server of six "server:status (3 of 6 …)", each one LLM-000 and the planned call's shortened; a skill of three and a server of one: none; the nine-script intent request is the reference walker's bytes and does not hold scripts/s9.py
Evidence: TestExcerptVersion_IsPinnedWithItsGolden green and untouched: {10, 09dc6a6f222ab23f}
Evidence: llm preview --json, v0.39.0 against the branch: corpus 5,272 samples, 0 with a differing request, 0 with another pass's shortened differing, 0 preview errors; held-out 459, totals only, 0 / 0 / 0
Evidence: the note, corpus: intent benign 105 of 2,909, malicious 43 of 473; server benign 258 of 629, malicious 30 of 180; held-out intent benign 0 of 216, malicious 16 of 243
Evidence: end to end against a local endpoint: check --llm --fail-on-llm high on a nine-script skill exits 0 on v0.39.0 and on the branch; the branch adds one LLM-000
Evidence: visibility recheck of P-070's first variant (prototype, not in the branch): 240 SkillHarm trees, 6 see more of their payload, 8 see less
Evidence: go test -count=1 ./baselines/cmd/judgefold/ ok, goldens untouched; make verify: all gates passed
```
