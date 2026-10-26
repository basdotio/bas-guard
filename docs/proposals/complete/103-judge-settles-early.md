<!-- SPDX-License-Identifier: MIT -->
# 103 — At `samples: 3` every judge question is asked a third time, even when its first two answers were clean and the third cannot change the outcome

- **Source**: the maintainer, 2026-10-26 (how many calls the judge makes); reading the committed `samples: 3` runs
- **Depends on**: P-080 (one nonce per question, and the dispatch queue that decides which call a free worker takes)
- **Branch**: `p/103-judge-settles-early`

## Problem

With `samples: n` every judge question is queued n times (`buildTasks`), and all n go out: the dispatch queue (P-080)
releases a question's other samples as soon as its first has finished, whatever that first said. A finding escalates
only with a majority, `majority(n) = n/2+1` votes (`tally`), and the barrier finding (LLM-007) is voted on the same way.
So once the first `n − majority(n) + 1` answers of a question are all clean — no flag, no barrier, nothing claimed that
could not be quoted — the remaining samples cannot reach the bar between them, and nothing they say can make the question
escalate. At `samples: 3` that is the third sample after two clean ones; at `samples: 5`, the last two after three.

`samples: 3` is not a corner case: it is what `--fail-on-llm` requires (P-046), and every committed judge reading uses it.
On those readings most questions come back clean on all three samples. Counted from the committed `judge.jsonl` of the
v0.31.0 held-out readings and the P-100 MCP reading (gpt-4.1-mini, `judge-prompt=b851dfd5412b`, `judge-excerpt=9`; a
question is clean when no vote names it; a sample with an LLM-005 note or an LLM-007 vote is counted as having no clean
question, which keeps the figure a lower bound):

| Reading | Samples | Judge calls | Questions | Clean on all three | Calls the third sample of a clean question made |
|---|---|---|---|---|---|
| held-out benign skills (`v031-asmben`) | 215 | 1,960 | 643 | 633 (98.4%) | 633 (32.3%) |
| fresh held-out benign skills (`v031-fresh216`) | 215 | 1,955 | 645 | 637 (98.8%) | 637 (32.6%) |
| held-out malicious skills (`v031-asmmal`) | 122 | 1,178 | 365 | 303 (83.0%) | 303 (25.7%) |
| SkillHarm (`v031-sh120`) | 120 | 1,313 | 426 | 308 (72.3%) | 308 (23.5%) |
| held-out MCP servers (`p100-mcp-heldout`) | 468 | 1,494 | 468 | 422 (90.2%) | 422 (28.2%) |

A quarter to a third of the calls those runs made could not have changed any escalation.

## Initial direction

Split a question's samples in the dispatch queue. The first `n − majority(n) + 1` are *needed* and go out as today. The
rest are *conditional*: they go out only after one of the needed samples came back not clean, and are dropped, as
*settled*, once every needed sample came back clean. A settled call is neither skipped nor failed: the judge block counts
it on its own line, and nothing that reads `skipped` or `failed` (the LLM-000 notes, `--fail-on-llm`'s exit 4, the
benchmark fold) counts it as a gap.

## Done criteria

- [x] `TestSettle_OutcomeEqualsAskingAll` (`internal/judge`, table-driven over every answer sequence): for `samples`
  1–5 and every sequence of answers drawn from {clean, grounded flag, ungrounded flag, barrier, flag and barrier, failed},
  the verdict finding and the LLM-007 finding of a ballot cast only from the answers the queue would have sent have the
  same `Escalates`, rule, severity and `[k of n samples agreed]` text as a ballot cast from all n, or are both absent;
  the only difference allowed is a finding below the consensus bar that only an unsent sample would have produced
- [x] `TestSchedule_DispatchQueue` gains cases: a conditional sample is never taken by an idle worker; it is released by
  a needed sample that came back not clean (failed included); it is never taken once its question settled;
  `samples: 2` needs one sample, `samples: 5` three; triage and `samples: 1` are unchanged
- [x] `TestRun_SettledCallsAreCounted` (real `NewHTTP` over `httptest`, `samples: 3`): clean replies → calls are
  two thirds of the plan, `Stats.Settled` the other third, `Skipped` and `Failed` 0, no LLM-000 note; replies that flag
  → every planned call is made and `Settled` is 0
- [x] The judge block carries `settled` (`internal/model`, absent when 0), the terminal summary and the stderr usage
  line name it, the usage log and the Downloads totals carry it, and `judgeGap` (exit 4) does not read it:
  `TestFailOnLLM_*` unchanged and green (its "ran fully, found nothing" case now settles questions and still exits 0),
  plus `TestE2E_SettledCallsAreNotAGap`
- [x] `baselines/judgefold` counts a settled call as asked when it derives `questions` (`(calls + settled − triage) /
  samples`); the ledger row and `judge_usage` sums carry `settled`
- [x] Reverse: `TestRun_ConcurrencyDoesNotChangeOutput`, `TestRun_DeadlineSkipsAreReported`, every `Concurrency: 1`
  scripted test and every consensus test whose replies flag pass unchanged; `bas-guard llm preview --json` on a fixed
  fixture is byte-identical before and after; `judge-prompt=` and `judge-excerpt=` in `bas-guard version` do not move
- [x] Measured: the same benign and malicious skill lists at `samples: 3`, main and this branch side by side: calls,
  settled, tokens, findings at 2 of 3, and the median wall time of one `check`
- [x] Docs: spec §5.2.1 ②, §8, §16.8; `docs/llm-judge.md` / `.zh-CN.md`; `docs/architecture.md` / `.zh-CN.md` where they
  describe the queue; `.claude/rules/judge.md`; `baselines/README.md` where it derives questions from calls
- [x] `make verify` green with `go version` go1.23.5 and no toolchain switch; `head -3 go.mod` line 3 `go 1.23.5`

## Out of scope

- Stopping a question whose needed samples all flagged. Its escalation is decided, but the severity is a vote over the
  category every sample named (P-041) and the `[k of n]` text reports how many agreed; a third answer can still move
  both. Only clean questions settle.
- The consensus bar, the `samples` default, the sampling temperature, triage (asked once already), which passes run, the
  prompt and the excerpts. No request byte changes.
- `llm.max_calls`: it still cuts the planned table before the run, so a settled call frees no budget for a later one.
- Anything priced: the tool records calls and the tokens the endpoint reported, and computes no cost.

## Must not claim

- Never that a run "costs less", by how much, or at what price. Only: calls that could not change an escalation are not
  made, and the judge block says how many.
- Never that the report is unchanged in every respect. Escalations, `overall_effective`, both gates and every finding
  that reaches the consensus bar are unchanged for the same first answers. A finding *below* the bar that only the third
  sample would have produced is not shown any more, the LLM-005 count can be one lower for the same reason, and any
  any-vote count read off a run (single votes, `judge_any`) is not comparable with runs before this change.
- Never that a single `check` is faster. A question that needs its third sample now waits one more round trip for it.
- Never that the samples are fewer or less independent where it matters: a question that is not clean is still asked
  all n times.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | The proposal | `P-103: the proposal — a judge question is asked n times even when its first answers settle it` |
| 2 | The queue holds a question's conditional samples until a needed one is not clean, and settles them once the needed ones are clean; tests written first in the same commit (the new tests do not compile without the new queue) | `P-103: a question stops when its remaining samples cannot change the outcome` |
| 3 | `settled` in the judge block, the summary and usage lines, the usage log, the Downloads totals and the preview header | `P-103: the judge block counts the calls a settled question did not need` |
| 4 | The benchmark fold and ledger count settled calls as asked | `P-103: baselines — a settled call is asked, not missing` |
| 5 | Documentation | `P-103: docs — a question settles when its remaining samples cannot change the outcome` |
| 6 | Done | `P-103: done — evidence, and the proposal moves to complete` |

## Open questions

1. Stop only clean questions, or also those whose needed samples all flagged? Recommended: only clean. A flagged question's
   escalation is decided, but its severity and its `[k of n]` text are not (out of scope above).
   **Decided (2026-10-26)**: as recommended.
2. What is a clean answer? Recommended: the call answered (a re-ask included), produced no finding, no barrier, and no
   claim that failed to ground. A failed call, an ungrounded claim and a barrier are each not clean, so the question is
   asked in full: the cases where the model is struggling keep every sample.
   **Decided (2026-10-26)**: as recommended.
3. May an idle worker take a conditional sample, as P-080 lets it take a waiting one? Recommended: no. The wait is the
   point here; P-080 refused an unconditional wait that saved nothing, while this one saves the call. A `check` of one
   skill still sends every needed sample at once.
   **Decided (2026-10-26)**: as recommended.
4. How is a settled call reported? Recommended: `settled` in the judge block, apart from `skipped`, absent when 0. Absent
   reads the same as a report from before the count (nothing settled), so no information is lost, and a `samples: 1`
   block stays byte-identical. The terminal summary and the stderr usage line name it when it is not 0; the progress
   counter's total drops by the calls a question settled, so a terminal counter ends at its total; `llm preview` says
   "up to" for a sampled plan.
   **Decided (2026-10-26)**: absent when 0 (first drafted as always present like `reasked`; changed during
   implementation for the byte-identical `samples: 1` block).
5. A setting to turn it off? Recommended: no. For the same first answers no escalation, score or gate can differ; what
   differs is a below-the-bar finding nobody weighs, and the judge block says how many calls were settled.
   **Decided (2026-10-26)**: as recommended.
6. Do `PromptVersion` or `ExcerptVersion` move? Recommended: no. No request body changes, and `ExcerptVersion` names which
   passes run and how excerpts are cut, not how many times a question is sent; `tool_version` identifies the build, as
   for P-080.
   **Decided (2026-10-26)**: as recommended.

## Done

```
Merged: PR #128 (find the sha with git log --grep P-103 after the merge)
Released: (fill in after the release)
Evidence: TestSettle_OutcomeEqualsAskingAll (internal/judge/settle_test.go): samples 1–5, all 6^n answer sequences (9,330 in all), each driven through the real dispatch queue one call at a time and all at once; every question asked in full ends exactly as asking all n, every settled one sent only n−majority(n)+1 clean samples and asking all n escalates nothing. Mutations: stopping after one clean sample, and a clean() that ignores barrier and ungrounded answers, each fail it
Evidence: TestSchedule_DispatchQueue, 16 cases (6 kept from P-080, the one where free workers took every sample now takes the needed ones): settle at samples 2/3/5, a needed sample that is not clean releases the rest, idle workers never take a conditional sample, a group the budget cut short settles nothing, questions settle independently. Mutation (every sample needed): it fails, with TestRun_FewQuestionsAreNotSerialized, TestPlan_BudgetAndSamplesMatchRun and TestRun_SettledCallsAreCounted
Evidence: TestRun_SettledCallsAreCounted (real NewHTTP over httptest): clean replies → calls 2/3 of the plan, settled 1/3, skipped/failed 0, no LLM-000, progress ends at its total; replies that flag → every planned call, settled 0. TestE2E_SettledCallsAreNotAGap: samples 3 → settled > 0, judgeGap empty, the usage line carries it; samples 1 → no settled key
Evidence: reverse — TestFailOnLLM_ExitCodesWhenTheJudgeIsBlind unchanged and green (its "ran fully, found nothing" case now settles questions and still exits 0); TestRun_ConcurrencyDoesNotChangeOutput, TestRun_DeadlineSkipsAreReported, every Concurrency: 1 scripted test and every consensus test unchanged; TestPlan_BudgetAndSamplesMatchRun and TestRun_UsageByPass keep their exact assertions with replies that are not clean, and the plan test adds: with clean ones, calls + skipped + settled = planned. judge-prompt=b851dfd5412b and judge-excerpt=9 on both builds
Evidence: baselines — TestJudgefold_Golden regenerated, the only change: four skill samples whose intent question the scripted endpoint answers clean make 8 calls with 1 settled instead of 9; questions, votes, escalated rules and verdicts identical; the header gains "settled 4". go test -race -count=3 ./internal/judge green
Evidence: measured, corpus 850fc546, 100 benign + 100 malicious skills drawn by seed 20261026, gpt-4.1-mini-2025-04-14, samples 3, concurrency 8, main (cf26ecb) and this branch interleaved, every check complete on both. Benign: calls 955 → 650 (305 settled), prompt tokens 1,691,009 → 1,133,664, completion tokens 446,186 → 294,836; 9 samples at the judge verdict on both, none different. Malicious: calls 1,060 → 824 (236 settled), prompt tokens 1,725,379 → 1,324,332, completion tokens 380,328 → 277,798; judge verdicts 76 → 74, 10 samples different (6 lost, 4 gained). A second run of the branch on the same 100: 829 calls (231 settled), 78 verdicts, 6 samples different from its first run and 8 from main — run-to-run variance of the model, in both directions, not the stop (3 of the 6 lost had the deciding question asked in full on the branch, 1 of 3 votes where main had 3 of 3)
Evidence: one check at a time on 5 benign + 5 malicious of the same skills, main and branch alternating: median wall time 7.5 s (main) → 8.2 s (benign 12.9 → 12.6 s, malicious 6.2 → 6.7 s)
Evidence: make verify: all gates passed; go version go1.23.5 darwin/arm64, no toolchain switch; go.mod line 3 "go 1.23.5"
```
