<!-- SPDX-License-Identifier: MIT -->
# 150 — A server whose tool description says "optional privilege escalation" and then edits `/etc/sudoers` is weighed medium: on the server pass a behaviour the descriptions mention is one step lower

- **Source**: the maintainer, 2026-11-26 ("先查", then "写提案草稿"; "都按推荐" to the five open questions), after
  glm-5.3 was measured as the judge on the server pass (2026-11-25) and the largest block of its remaining misses
  turned out to be findings this step had lowered; P-115's "Considered and left out"; `issues/028`
- **Depends on**: none
- **Branch**: `p/150-server-pass-no-disclosure-step`

## Problem

Since P-041 the tool, not the model, sets a judge finding's severity, from the category the model names. Two passes
carry one more field in the reply, `disclosed`: true when the declared side itself states the behaviour. When it is
true the tool takes the row's severity one step down, high to medium (`severityFor`; `software-source` is exempt).
P-041 introduced the step for skills, where the declared side is the skill's description. P-053 carried it to the
server pass (`LLM-010`) together with the rest of the intent table; there the declared side is each tool's name and the
first line of its docstring. Since P-115 a lowered finding says `[disclosed: one step lower]`.

A medium finding is not a judge high: `--fail-on-llm high` does not stop on it and the benchmark's judge column does
not count it. So on the server pass three samples can agree on what a tool does, name the right row, and the finding
is medium because the server's own docstring mentions it. Two of Cisco's evaluation servers, read by glm-5.3:

- `mal-mcp-ci-file_permission_manipulation_privilege_escalation`: "The tool changes permissions on files like
  /etc/sudoers and /usr/bin/sudo (adding SUID) to escalate privileges, which the description only vaguely discloses as
  'optional privilege escalation'." `[disclosed: one step lower] [3 of 3 samples agreed] … [categories: privilege,
  privilege, privilege] [tool: medium]`
- `mal-mcp-ci-cloud_metadata_credential_extraction`: "The tool fetches IAM security credentials from cloud metadata
  endpoints, which the description discloses but which reads credentials." `[disclosed: one step lower] [2 of 3 samples
  agreed] … [categories: credential-read, credential-read] [tool: medium]`

How often this happens is a property of the model, not of the server. The question already tells the model not to
flag what a description states ("A tool that does exactly what its description says … is NOT a finding"), so the step
acts only on answers where the model flagged anyway and set the field. gpt-4.1-mini almost never gives that answer;
glm-5.3 gives it for about one malicious finding in ten.

The step is applied by the tool after the model has answered, and the prompt says nothing about it beyond asking for
the field. So what a stored run would have read without it can be worked out from the stored output, with no model
call. On the 802 Python server trees of corpus `c314e4d9` (179 malicious, 623 benign), `samples: 3`:

| stored run | escalating `LLM-010` findings whose first vote was lowered | malicious servers at judge high, now → without the step | benign, now → without the step |
|---|---|---:|---:|
| gpt-4.1-mini, 2026-11-16 (`…-p118-py-base-s3`; judge prompt `9cd57da1a4bd`, the one `main` sends today) | 1 of 148 malicious, 2 of 120 benign | 135 → **136** | 38 → **40** |
| glm-5.3 (`reasoning_effort: low`), v0.39.0, 2026-11-25 | 14 of 137 malicious, 3 of 42 benign | 91 → **101** | 29 → **32** |
| glm-5.3, v0.39.0 plus P-118's `code-execution` row (a measurement build; the row is not on `main`) | 10 of 141 malicious, 2 of 34 benign | 120 → **129** | 25 → **27** |

Every malicious server that comes back on glm-5.3 is one gpt-4.1-mini already reports high: they are 10 of the 51
servers the default model flags and glm-5.3 does not (9 of 25 with the row). By row: `credential-read`,
`file-deletion`, `privilege`, `safety-disable`, `concealed-directive`.

The benign servers that come back with them are, by the model's own sentences, ones that do the thing and say so. On
gpt-4.1-mini: two that run caller-supplied code as their stated job (`seer-mcps`, a sandbox runner; `hetzner-mcp`, an
`eval()` over an SDK client; both `remote-execution`). On glm-5.3: two that write themselves into an IDE's or the
agent's startup configuration (`amx-mcp`, `pc-control`; `persistence`), `hetzner-mcp` again, and one
`concealed-directive`.

On the default model alone this is one malicious server for two benign ones. P-115 looked at the same step (two and
two at the time) and left it: "changing it buys nothing on this corpus". That reading stands for gpt-4.1-mini. What
is new is the second model, and two things the table shows about the step itself:

1. **It is the one place on this pass where the artifact's own text lowers the weight of a behaviour the model
   flagged.** `severity.go` says of the table that "no row is low (the one-step disclosure rule on the intent pass is
   the only way down)"; the comment predates P-053 and describes the state this proposal returns to. The declared side
   of a server is written by the server's author and read mostly by the agent that calls the
   tool, not by a person deciding whether to install it. `issues/028` measured the neighbouring idea (lower
   `remote-execution` when the tool's name or docstring declares execution): 10 of Cisco's servers lost for 2 benign
   ones, and its conclusion was that on this pass "declared" does not mean "safe".
2. **It leaves one boolean of the weight in the model's hands.** P-041 took the severity word away from the model: a
   one-word self-rating on a scale no prompt defined. `disclosed` is what is left of it on this pass, and two models
   set it at very different rates on the same servers (first vote of an escalating finding: 3 of 268 against 17 of
   179).

## Initial direction

`severityFor` takes the disclosure step on the intent pass only. The server prompt is not touched: it still asks for
behaviour the descriptions do not disclose, and still asks for the `disclosed` field. So `PromptVersion` does not move,
the stored answers remain the answers `main` would be given, and no new model call is needed to know what the change
does. A server finding whose first vote set the field keeps a mark in its reason, as text. Touches
`internal/judge/severity.go`, `judge.go` (the mark), the tests that pin the step, the docs pair and
`.claude/rules/judge.md`.

## What the design read added to the problem

Read on the stored runs on 2026-11-26, before writing what follows. The replay is
`agent-guard-work/disclosure-step/replay.py`.

- **What a stored output can and cannot answer.** A finding's reason is the first agreeing vote's reason, so the
  disclosure mark and the `category not shown by the text` marks are known for that vote only. `[categories: …]` lists
  every agreeing vote's category and `[tool: …]` the severity the finding ended with. The finding takes the severity of
  the first vote in the majority category, or the lowest among the votes when no category has a majority. On this pass
  a vote in a high row is medium for one of two reasons only: the disclosure step, or one of the two `credential-read`
  downgrades (own service, P-062; own configuration, P-098), which stay. So each escalating finding below high is one
  of *lifts* (the deciding vote is known to be lowered by the step alone), *stays* (a medium row, a `credential-read`
  downgrade on the deciding vote, or no majority with a medium-row vote) or *open* (the deciding vote is a later
  `credential-read` vote whose reason is not stored, or no majority among high rows). **Nothing is open on the three
  Python runs above**, so their numbers are exact for those answers.
- **The change cannot alter how many samples a question gets.** P-103 settles a question early only when its first
  answers are clean; a flagged question is always asked in full.
- **The stored gpt-4.1-mini run is on the build P-118 branched from** (`929bd8a`, P-117 included). Its judge prompt and
  excerpt versions (`9cd57da1a4bd`, 10) are what `main` prints today. What merged since leaves the server pass's
  request and its severity rules as they were: P-103 stops asking once a question's first answers are clean, which
  leaves outcomes unchanged by construction, and P-149 adds a note.
- **TypeScript and JavaScript trees** (P-116's measurement build, 17 malicious, 220 benign; not recognised as servers on
  `main`), gpt-4.1-mini: malicious 9 → 9, benign 24 → 24 or 25 (one finding open).
- **The 30 hand-written servers added to the corpus on 2026-11-25**, glm-5.3: 28 → 28. Their harm is written as words
  to the agent, which no description discloses.
- **The intent pass, replayed the same way** (no `credential-read` downgrade exists there, so nothing is open). The
  full-corpus gpt-4.1-mini run of 2026-11-04: malicious samples at `LLM-001` high 115 → 115, benign 35 → 36 (one
  `persistence`). glm-5.3 on SkillHarm's 240 and 212 benign skills (2026-11-24): 64 → 64 and 0 → 0. On skills the step
  holds back no malicious sample on either model, so nothing argues for touching it there.
- **`other` with `disclosed` is low today and would be medium**: five findings on the glm-5.3 run, none on
  gpt-4.1-mini. No count above depends on it.
- **A narrower version exists** (open question 2): keep the step for `remote-execution` and `persistence`, the two rows
  where a server's stated job can be the behaviour (a shell tool, an installer). On the stored runs it brings back the
  same malicious servers (1, 10, 9) and fewer benign ones (0, 1, 0). The split was drawn after reading which rows the
  benign servers sit in.

## Done criteria

Code (judge package):

- [x] `TestSeverityFor_ServerTakesNoDisclosureStep` pins: on the server pass every high row is high with
  `disclosed: true`, `other` and an unknown name are medium, not low.
- [x] Reverse assertion, `TestSeverity_IntentDisclosedIsOneStepLower`, green without an edit: on the intent pass a
  disclosed high row is still medium, `software-source` still high, `other` still low.
- [x] Reverse assertion: the two `credential-read` downgrades still lower a server vote, with `disclosed` true or
  false, and the reason still names which one; a file that reaches past its own configuration stays high either way
  (`TestRun_ServerCredentialReadDowngradesHoldWhenDisclosed`; the existing P-062 and P-098 tests green without an
  edit).
- [x] The existing assertions the proposal reverses, named in the commit: `TestRun_ServerSourceGetsLLM010`'s
  `disclosed: true` case now expects high; `TestSeverityFor_NewRows`' two disclosed server rows are high; and
  `TestDisclosedLowering_IsAnnotated`'s server row carries no "one step lower". *Written as one assertion; the
  step was pinned in three places.* With the old rule put back, these three and the four new tests fail.
- [x] `TestTally_ServerDisclosedVotes` pins the three shapes the replay classifies (the first vote decides; a later
  vote decides; no majority, with and without a medium-row vote; a catch-all majority), so the replay's rules and the
  code's are the same rules.
- [x] The mark (open question 3): a server finding whose first vote set the field says `[disclosed]` and never
  `[disclosed: one step lower]`; an intent finding is annotated exactly as today (`TestServerDisclosed_IsMarkedNotLowered`
  and `TestDisclosedLowering_IsAnnotated`, both directions).
- [x] `PromptVersion` and `ExcerptVersion` do not move: `TestPromptVersion_*` and `excerpt_version_test.go` green
  without an edit, and `bas-guard version` prints `judge-prompt=9cd57da1a4bd · judge-excerpt=10` as on `main`.
- [x] `go test -count=1 ./baselines/cmd/judgefold/` green; no golden moved.
- [x] A `CHANGELOG.md` entry under `## Unreleased`; `make verify` green, read from its own exit code.

Replay (no model call). These are the readings already taken, written here before the change exists; they are not
predictions. The criterion is that the replay reproduces them from the stored outputs:

- [x] gpt-4.1-mini (`baselines/results/aguard/2026-11-16-llm-gpt-4.1-mini-p118-py-base-s3/`, raw archive on the
  v0.39.0 release): malicious 135 → 136 of 179, benign 38 → 40 of 623, nothing open.
- [x] glm-5.3, v0.39.0: malicious 91 → 101, benign 29 → 32, nothing open.
- [x] Every server that changes is listed by name with its row and the model's sentence (3 on gpt-4.1-mini, 13 on
  glm-5.3), so the reading can be checked by eye.
- [x] Where the readings live, per open question 5: `baselines/results/aguard/2026-11-25-llm-glm-5.3-servers-s3/`
  holds the glm-5.3 run's folded files, `replay.py` and `compare.txt` (both readings and the local ones as totals).
  It has no `run.yaml`: the run was made in two parts and the first was stopped before its driver wrote one;
  `compare.txt` says how it was made. **Still owed: its raw archive, scrubbed, on the next release.**

Docs:

- [x] `docs/llm-judge.md` and `docs/llm-judge.zh-CN.md` (the pair): the step is the intent pass's; the `LLM-010` row
  says a described behaviour is not lowered and why. Also one clause in `docs/spec/spec.zh-CN.md` (the P-041 bullet) and a closing
  section in `issues/028`.
- [x] `.claude/rules/judge.md`: what not to change. Do not put the step back on this pass without replaying both
  models. Do not drop `disclosed` from the server prompt: that moves `PromptVersion`, and the mark is the only record
  of how often a model sets it. Do not carry this to the intent pass on these numbers.
- [x] `.claude/rules/invariants.md` #4 already says only the intent pass's step reaches low; it reads true as
  written, no edit.

## Out of scope

- **The intent pass** (`LLM-001`): same step, untouched, its `software-source` exemption included. The reverse
  assertion above is the proof.
- **The server prompt**: `serverTask`, the category table and the sentence asking for `disclosed` are byte-identical;
  the pinned prompt version is the proof.
- **The two `credential-read` downgrades** (P-062, P-098) and `categoryShown`.
- **P-118's `code-execution` row** (rejected on gpt-4.1-mini). Its run appears above as a reading only.
- **Which model the judge uses by default.** This change is the same code for any model.
- **The other servers glm-5.3 misses** (votes filed under `other`, or no vote at all).
- **TypeScript and JavaScript servers** (P-116, rejected), the excerpt, the vote count, the threshold, triage, the
  static rules (no `rulesEpoch` change).

## Must not claim

- Not "nine (or ten) more malicious servers caught". Those are Cisco's evaluation servers read by a model that is not
  the default, and each is one the default model already reports. On the default model the reading is one.
- Not a held-out rate. Every server number here is on the development corpus; no held-out server pool exists.
- Not "disclosure no longer matters on the server pass". The question still asks for undisclosed behaviour, and a
  model that follows it does not flag what a description states. Only answers that flagged and set the field change.
- Not "glm-5.3 is level with gpt-4.1-mini on servers". 129 comes with a row that is not on `main` and was rejected on
  the default model; without it the reading is 101 against 136. The "level with gpt" line of the 2026-11-25
  measurement (128) was set for that run's own question, and this change was chosen after reading its result, so 129
  does not pass it.
- The replay is exact for the stored answers, not for the next run: each row above is one run, and the totals move
  between reruns (P-100, P-115). glm-5.3's run-to-run variation on servers has not been measured.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | `severityFor` takes the step on the intent pass only; the server mark; the tests above; the changelog entry | `judge: the server pass does not lower a finding for being described (P-150)` |
| 2 | Docs pair and `.claude/rules/judge.md` | `docs: the disclosure step is the intent pass's (P-150)` |
| 3 | The replay and its readings, where open question 5 puts them | `baselines: P-150 replayed on the stored server runs (P-150)` |
| 4 | The "Done" section and `git mv` to `complete/` | `proposals: P-150 done (P-150)` |

## Open questions

All asked at once. Each has a recommended answer.

1. **On the default model this is one malicious server for two benign ones. Worth doing?** The gain is on a second
   model and in what the step is (the two numbered points in Problem). Recommended: **yes**. The cost is two servers
   in 623 that do what the model says they do, the tool stops weighing a server by its own description, and the
   server pass's reading no longer depends on how readily a model sets one field. If the answer is no, this file goes
   to `rejected/` with the replay as its record, so the question is not measured a third time.
   **Decided (2026-11-26)**: yes.
2. **Every row, or all but two?**
   - **(A), recommended:** no step on the server pass at all. One rule, nothing chosen from the samples just read, and
     no row left where a description still lowers the weight.
   - **(B):** keep the step for `remote-execution` and `persistence`. On the stored runs the same malicious servers
     come back and fewer benign ones (gpt-4.1-mini +1 / +0; glm-5.3 +10 / +1, and +9 / +0 with the row). It can never
     bring back more benign servers than (A). But it was drawn from five benign servers, and it keeps the step on
     `remote-execution`, the row where `issues/028` found Cisco's servers declaring what they do.
   **Decided (2026-11-26)**: (A), every row.
3. **The mark.** Recommended: a server finding whose first vote set the field says `[disclosed]`. It changes no
   severity. It tells a reader looking at a high on an honest server that the model saw the description say so, and it
   is the only record from which the step's effect can be replayed later, as was done here.
   **Decided (2026-11-26)**: yes, `[disclosed]`.
4. **A fresh run?** Recommended: **no**. The prompt is byte-identical, so a new run measures rerun variation, not this
   change; the tests cover the code path through the real pipeline with a scripted client. If an end-to-end reading is
   wanted anyway, one gpt-4.1-mini round on the 802 trees is about US$3–4 (the stored round: 2,834 calls, 5.5M prompt
   tokens, 1.1M completion). A second glm-5.3 round would answer a different question (that model's variation).
   **Decided (2026-11-26)**: no fresh run.
5. **Where the readings live.** The gpt-4.1-mini run is already in `baselines/results/` with its raw archive on
   v0.39.0. The glm-5.3 runs are local. Recommended: commit the result directory of the plain v0.39.0 glm-5.3 run, with
   its raw archive (scrubbed) on the next release; leave the row-build run as a local measurement mentioned here, since
   its build is not on `main`. The replay script goes into the result directory beside `compare.txt`.
   **Decided (2026-11-26)**: as recommended.

## Done

```
Merged: PR #177 (find the date and the sha with git log --grep P-150 after the merge)
Released: pending
Evidence: internal/judge/severity.go: severityFor takes the step when the pass is the intent pass only; internal/judge/judge.go: finding() appends "[disclosed]" to a server finding whose vote set the field and "[disclosed: one step lower]" to an intent finding as before; the server prompt still asks for the field
Evidence: TestSeverityFor_ServerTakesNoDisclosureStep; TestServerDisclosed_IsMarkedNotLowered; TestTally_ServerDisclosedVotes: five vote shapes through finding() and tally(); TestRun_ServerCredentialReadDowngradesHoldWhenDisclosed: own service, own configuration, reaches past, each with the field false and true
Evidence: reversed: TestRun_ServerSourceGetsLLM010's disclosed case expects high; TestSeverityFor_NewRows' two disclosed server rows are high; TestDisclosedLowering_IsAnnotated's server row carries no "one step lower"; with the old rule put back (the mutation was run) these three and the four new tests are red
Evidence: green without an edit: TestSeverity_IntentDisclosedIsOneStepLower, the four TestPromptVersion_* tests, TestExcerptVersion_IsPinnedWithItsGolden; bas-guard version prints judge-prompt=9cd57da1a4bd · judge-excerpt=10, as on main
Evidence: replay.py on the stored answers, 802 Python server trees (179 malicious, 623 benign), no model call: gpt-4.1-mini malicious 135 → 136, benign 38 → 40; glm-5.3 (v0.39.0) malicious 91 → 101, benign 29 → 32; nothing open on either run, and the "high now" column equals judge.jsonl's own count on both
Evidence: every malicious server that lifts on glm-5.3 is one gpt-4.1-mini reports high in its stored run; compare.txt lists each changed server (3 on gpt-4.1-mini, 13 on glm-5.3) with its row and the model's sentence
Evidence: baselines/results/aguard/2026-11-25-llm-glm-5.3-servers-s3/: judge.jsonl, ledger.jsonl, verdicts.jsonl (802 lines each), per-kind-rule.txt, replay.py, compare.txt; no run.yaml (a two-part run, said in compare.txt); baselines/judgefold/schema_test.go counts 103 files and 52,265 lines
Evidence: other readings, local runs, totals only: glm-5.3 with P-118's row malicious 120 → 129, benign 25 → 27; gpt-4.1-mini on the 237 TypeScript and JavaScript trees 9 → 9 and 24 → 24 or 25 (one finding open); glm-5.3 on the 30 hand-written servers 28 → 28; the intent pass, which keeps the step: gpt-4.1-mini 115 → 115 and 35 → 36, glm-5.3 64 → 64 and 0 → 0
Evidence: docs/llm-judge.md and docs/llm-judge.zh-CN.md, the P-041 bullet of docs/spec/spec.zh-CN.md, .claude/rules/judge.md, a closing section in issues/028
Evidence: go test -count=1 ./baselines/cmd/judgefold/ ok, goldens untouched; make verify: all gates passed
Owed: the glm-5.3 run's raw archive, scrubbed, on the release that carries this change
```
