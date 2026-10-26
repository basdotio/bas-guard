<!-- SPDX-License-Identifier: MIT -->
# 106 — The result question (LLM-011) is asked of every skill at about a third of the judge's calls, and only output-manipulation attacks need it: it becomes opt-in

- **Source**: the maintainer, 2026-10-26 (how many calls the judge makes): "make the result pass optional, off by default, and
  measure recall and false positives again"
- **Depends on**: P-068 (the result pass)
- **Branch**: `p/106-result-pass-optional`

## Problem

P-068 added a fourth question for every skill — does a required step change what the user gets (LLM-011) — sent over the
whole instruction text, the SKILL.md body and the documents it names. It is the largest question the judge asks of a
skill. On the v0.31.0 held-out readings (gpt-4.1-mini, `samples: 3`, `judge-prompt=b851dfd5412b`), read from the
committed ledgers' `usage_by_pass`:

| Reading | Result-pass calls | Share of the reading's prompt tokens | Share of its completion tokens |
|---|---|---|---|
| held-out benign skills (`v031-asmben`) | 642 of 1,969 (32.6%) | 40.1% | 34.6% |
| fresh held-out benign skills (`v031-fresh216`) | 648 of 1,964 (33.0%) | 40.0% | 33.8% |
| held-out malicious skills (`v031-asmmal`) | 366 of 1,187 (30.8%) | 38.8% | 38.7% |
| SkillHarm (`v031-sh120`) | 360 of 1,313 (27.4%) | 32.2% | 21.3% |

What it buys is concentrated in one class. The question is asked independently of every other, so each committed
`samples: 3` run on this judge prompt can be read again without it exactly: the same draws, with LLM-011 votes left
out of the judge predicate (static ≥ high, or an escalated LLM finding ≥ high whose rule is not LLM-009):

| Reading | Samples | At the judge verdict | Without LLM-011 |
|---|---|---|---|
| SkillHarm (`v031-sh120`) | 120 malicious | 81 | 69 (−12) |
| `p089-main` | 240 malicious | 174 | 155 (−19) |
| `p089-branch` | 239 malicious | 171 | 156 (−15) |
| held-out malicious (`v031-asmmal`) | 122 malicious | 68 | 68 |
| held-out benign (`v031-asmben`) | 215 benign | 8 | 6 (−2) |
| fresh held-out benign (`v031-fresh216`) | 215 benign | 11 | 11 |
| every other committed run on this prompt (P-087, P-088, P-090, P-098, P-100; skills, hooks, MCP, servers) | 2,630 | — | no verdict changes |

Read without it, the judge keeps every verdict on the held-out malicious skills and loses a tenth of SkillHarm — the
output-manipulation set P-068 was built against — while one held-out benign set loses two false positives.

## Initial direction

Ask the result question only when `llm.result_pass: true`. Off by default: a run that does not ask it says so in its
judge block (`passes_off: ["result"]`) and in the identity line, so a reading is never compared with one that asked it
without the difference being visible.

## Done criteria

- [x] `TestPlan_ResultPassIsOptIn` (`internal/judge`): with default options no skill is asked the result question; with
  `ResultPass` the plan is the plan before this change, payload for payload
- [x] `config`: `result_pass` defaults to false and reads `true` from YAML; `judgePlanOptions` carries it, so
  `llm preview` and the run plan the same questions (`TestLLMPreview_MatchesWhatScanAndCheckSend` green)
- [x] The judge block carries `passes_off: ["result"]` when the question is off and no key when it is on; the identity
  line names it; the usage log copies it; a block from a run without the judge configured carries neither
- [x] `ExcerptVersion` moves with its golden (`excerpt_version_test.go`): which passes run by default changed
- [x] Reverse: with `ResultPass` on, `TestRun_UsageByPass`, the preview fixture, `TestJudgefold_Golden` (its config
  turns the pass on) and the steering tests are unchanged; `PromptVersion` does not move (no request byte changes)
- [x] Measured: the counterfactual above, and a live run of this build against main on the same skills
- [x] Docs: `docs/llm-judge.md` / `.zh-CN.md`, spec §5.2 and the config block, `config.example.yaml`,
  `docs/architecture.md` / `.zh-CN.md` where they list the passes, `.claude/rules/judge.md`
- [x] `make verify` green with `go version` go1.23.5 and no toolchain switch; `head -3 go.mod` line 3 `go 1.23.5`

## Out of scope

- The result question itself: its wording, its categories and its excerpt are unchanged.
- Any other pass. Making intent, injection or triage optional is not proposed.
- `--fail-on-llm`: a gate does not require the result pass. Someone who gates on the judge and cares about output
  manipulation turns it on; the docs say so.
- Anything priced.

## Must not claim

- Never that recall is unchanged. Off, the judge loses 12 of 120 SkillHarm samples on the committed reading; say so
  wherever the default is described.
- Never a cost or a saving in money. Only: the question is about a third of the judge's calls on skills, and a run
  without it says so.
- Never that the result pass is unsound or rejected: it is the question that catches output manipulation, kept and
  available.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | The proposal | `P-106: the proposal — the result question is a third of a skill's calls and only output manipulation needs it` |
| 2 | `llm.result_pass` (default false) and `Options.ResultPass`; the plan drops the result question unless it is on | `P-106: the result question is asked only when llm.result_pass is true` |
| 3 | `passes_off` in the judge block, the identity line and the usage log | `P-106: a run that does not ask the result question says so` |
| 4 | Documentation | `P-106: docs — the result pass is opt-in` |
| 5 | Done | `P-106: done — evidence, and the proposal moves to complete` |

## Open questions

1. Off or on by default? The maintainer asked for off (2026-10-26). The measurement above is the price of that default:
   −12 of 120 SkillHarm and −19/−15 of ~240 P-089 malicious at the judge verdict, nothing on the held-out malicious
   skills, two fewer false positives on one held-out benign set, and about a third of a skill's calls.
   **Decided (2026-10-26)**: off, by the maintainer.
2. The setting's name? Recommended: `llm.result_pass: true`, a boolean beside `samples`. A list of passes would invite
   turning off injection, which the spec keeps unconditional.
   **Decided (2026-10-26)**: as recommended.
3. How does a report say the question was not asked? Recommended: `passes_off: ["result"]` in the judge block, absent
   when every pass was asked. An older report without the key asked every pass, so absence reads correctly on both
   sides of this change. The identity line adds `· result pass off`.
   **Decided (2026-10-26)**: as recommended.
4. `ExcerptVersion`? Recommended: 12. 10 names the rejected P-070 branch's committed excerpts and P-104 (#129) takes 11;
   whichever of the two merges second keeps its own number above the other's.
   **Decided (2026-10-26)**: as recommended.

## Done

```
Merged: PR to be opened (find the sha with git log --grep P-106 after the merge)
Released: (fill in after the release)
Evidence: TestPlan_ResultPassIsOptIn (internal/judge/result_pass_test.go): default options plan planFor's menu without the result question, payload for payload; ResultPass plans the full menu. TestLoad_ResultPassIsOptIn: default false, `result_pass: true` read. TestE2E_ResultPassOffIsInTheBlock: off → passes_off ["result"] in the block and the usage line; on → no key and more calls; a judge not configured names no pass. TestJudgeIdentityLine_NamesAPassOff; TestJudgeUsage_PassesOffReachTheRow (ledger row)
Evidence: reverse — with ResultPass on, TestRun_UsageByPass, the re-ask, budget, slow-call, grounding and steering tests keep their assertions; TestJudgefold_Golden unchanged (its config turns the pass on); TestE2E_UncachedEndpointBlockUnchanged with passes_off set aside like usage_by_pass. judge-prompt=b851dfd5412b on main and here; ExcerptVersion 9 → 12 with the fixture digest 9b48519aaa7b6b16 → cbb3db8b81b93515
Evidence: counterfactual on the committed runs on this judge prompt (the table under Problem): SkillHarm 81 → 69 of 120, p089-main 174 → 155 of 240, p089-branch 171 → 156 of 239, held-out malicious 68 → 68 of 122, held-out benign 8 → 6 of 215, fresh held-out benign 11 → 11, no verdict change in the 2,630 samples of every other run
Evidence: counterfactual on 100 benign + 100 malicious corpus skills (corpus 850fc546, seed 20261026, gpt-4.1-mini-2025-04-14, samples 3), three runs of the same skills: benign false positives 9 → 8 (two runs); malicious at the judge verdict 76 → 71, 74 → 72, 78 → 76, every loss among the SkillHarm-derived `sh-` samples
Evidence: live, this build (result_pass unset) against main on the same skills, 199 complete on both (one sample was no longer in the corpus checkout when this build ran; the other 199 trees are byte-identical between the two runs): benign calls 955 → 655, prompt tokens 1,691,009 → 1,043,515, completion tokens 446,186 → 279,998, false positives 9 → 8; malicious calls 1,050 → 756, prompt tokens 1,705,757 → 1,153,070, completion tokens 374,182 → 276,739, at the judge verdict 75 → 72; LLM-011 in 0 of this build's reports (39 findings in main's), passes_off ["result"] on all 199
Evidence: make verify: all gates passed; go version go1.23.5 darwin/arm64, no toolchain switch; go.mod line 3 "go 1.23.5"
```
