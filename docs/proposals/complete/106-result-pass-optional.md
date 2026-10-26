<!-- SPDX-License-Identifier: MIT -->
# 106 — The result question (LLM-011) is asked of every skill at about a third of the judge's calls, and only output-manipulation attacks need it: it can be turned off

- **Source**: the maintainer, 2026-10-26 (how many calls the judge makes): "make the result pass optional, off by default, and
  measure recall and false positives again"; then, the same day, after the measurement: "on by default — whoever wants to
  save turns it off"
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

Keep asking the result question by default, and let `llm.result_pass: false` skip it. A run that skips it says so in its
judge block (`passes_off: ["result"]`) and in the identity line, so a reading is never compared with one that asked it
without the difference being visible.

## Done criteria

- [x] `TestPlan_ResultPassCanBeTurnedOff` (`internal/judge`): by default the plan is planFor's full menu, as before this
  change; with `SkipResult` it is that menu without the result question, payload for payload
- [x] `config`: the result question is asked by the defaults, by a config that never mentions `result_pass` and by an
  `LLMConfig` built without it (`*bool`, read through `AsksResultPass`); `result_pass: false` turns it off;
  `judgePlanOptions` carries it, so `llm preview` and the run plan the same questions
  (`TestLLMPreview_MatchesWhatScanAndCheckSend` green)
- [x] The judge block carries `passes_off: ["result"]` when the question is off and no key when it is asked; the identity
  line names it; the usage log and the ledger row copy it; a block from a run without the judge configured carries neither
- [x] `ExcerptVersion` does not move: the default plan is the plan before this change byte for byte
  (`excerpt_version_test.go` unchanged, digest 9b48519aaa7b6b16)
- [x] Reverse: every test of `internal/judge` other than the new one, `TestJudgefold_Golden` and the cmd judge-block
  tests are byte-identical to `main`'s and green; `PromptVersion` does not move (no request byte changes)
- [x] Measured: the counterfactual above, and a live run with the result pass off against main on the same skills
- [x] Docs: `docs/llm-judge.md` / `.zh-CN.md`, spec §5.2 and the config block, `config.example.yaml`,
  `docs/architecture.md` / `.zh-CN.md` where they list the passes, `.claude/rules/judge.md`
- [x] `make verify` green with `go version` go1.23.5 and no toolchain switch; `head -3 go.mod` line 3 `go 1.23.5`

## Out of scope

- The result question itself: its wording, its categories and its excerpt are unchanged.
- Any other pass. Making intent, injection or triage optional is not proposed.
- `--fail-on-llm`: a gate does not require the result pass. Someone who gates on the judge and cares about output
  manipulation leaves it on; the docs say so.
- Anything priced.

## Must not claim

- Never that turning it off keeps recall. Off, the judge loses 12 of 120 SkillHarm samples on the committed reading; say so
  wherever the setting is described.
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
| 6 | The maintainer's second decision: on by default (`*bool` config, `Options.SkipResult`, filtered in `schedule`); the tests W2 had turned on go back to `main`'s, `ExcerptVersion` back to 9 | `P-106: the result question stays on by default; llm.result_pass: false turns it off` |
| 7 | Documentation for it | `P-106: docs — the result pass is on by default and can be turned off` |
| 8 | This file | `P-106: the proposal — on by default, off on request` |

## Open questions

1. Off or on by default? The maintainer asked for off (2026-10-26). The measurement above is what that default gives up:
   −12 of 120 SkillHarm and −19/−15 of ~240 P-089 malicious at the judge verdict, nothing on the held-out malicious
   skills, two fewer false positives on one held-out benign set, and about a third of a skill's calls.
   **Decided (2026-10-26)**: off, by the maintainer; then, the same day, after reading the measurement, **on** by the
   maintainer — `result_pass: false` is for whoever wants those calls back and accepts the SkillHarm loss.
2. The setting's name? Recommended: `llm.result_pass`, a boolean beside `samples`. A list of passes would invite
   turning off injection, which the spec keeps unconditional. Defaulting to true, it is a `*bool` read through
   `AsksResultPass`: a plain bool's zero value would turn the pass off in every `LLMConfig` a caller builds by hand.
   **Decided (2026-10-26)**: as recommended.
3. How does a report say the question was not asked? Recommended: `passes_off: ["result"]` in the judge block, absent
   when every pass was asked. An older report without the key asked every pass, so absence reads correctly on both
   sides of this change. The identity line adds `· result pass off`.
   **Decided (2026-10-26)**: as recommended.
4. `ExcerptVersion`? With the default off it had to move (drafted as 12: 10 names the rejected P-070 branch's committed
   excerpts and P-104, #129, takes 11). With the default on it does not: the default plan is the plan before this change
   byte for byte, and a run that turns the pass off says so in `passes_off`.
   **Decided (2026-10-26)**: unchanged at 9.

## Done

```
Merged: PR #130 (find the sha with git log --grep P-106 after the merge)
Released: (fill in after the release)
Evidence: TestPlan_ResultPassCanBeTurnedOff (internal/judge/result_pass_test.go): default options plan planFor's full menu; SkipResult plans it without the result question, payload for payload. TestLoad_ResultPassIsOnUnlessTurnedOff: Default(), LLMConfig{}, no key and `result_pass: true` ask it, `result_pass: false` does not. TestE2E_ResultPassOffIsInTheBlock: `result_pass: false` → passes_off ["result"] in the block and the usage line and fewer calls; default → no key; a judge not configured names no pass. TestJudgeIdentityLine_NamesAPassOff; TestJudgeUsage_PassesOffReachTheRow (ledger row). Mutations: AsksResultPass true only when set, and schedule not filtering, each fail their test
Evidence: reverse — every internal/judge test but result_pass_test.go, TestJudgefold_Golden and TestE2E_UncachedEndpointBlockUnchanged are byte-identical to main's and green; judge-prompt=b851dfd5412b and judge-excerpt=9 on main and here (excerpt_version_test.go unchanged)
Evidence: counterfactual on the committed runs on this judge prompt (the table under Problem): SkillHarm 81 → 69 of 120, p089-main 174 → 155 of 240, p089-branch 171 → 156 of 239, held-out malicious 68 → 68 of 122, held-out benign 8 → 6 of 215, fresh held-out benign 11 → 11, no verdict change in the 2,630 samples of every other run
Evidence: counterfactual on 100 benign + 100 malicious corpus skills (corpus 850fc546, seed 20261026, gpt-4.1-mini-2025-04-14, samples 3), three runs of the same skills: benign false positives 9 → 8 (two runs); malicious at the judge verdict 76 → 71, 74 → 72, 78 → 76, every loss among the SkillHarm-derived `sh-` samples
Evidence: live, the result pass off (the build before W6 with result_pass unset, which asked what `result_pass: false` asks now) against main on the same skills, 199 complete on both (one sample was no longer in the corpus checkout when this build ran; the other 199 trees are byte-identical between the two runs): benign calls 955 → 655, prompt tokens 1,691,009 → 1,043,515, completion tokens 446,186 → 279,998, false positives 9 → 8; malicious calls 1,050 → 756, prompt tokens 1,705,757 → 1,153,070, completion tokens 374,182 → 276,739, at the judge verdict 75 → 72; LLM-011 in 0 of this build's reports (39 findings in main's), passes_off ["result"] on all 199
Evidence: make verify: all gates passed; go version go1.23.5 darwin/arm64, no toolchain switch; go.mod line 3 "go 1.23.5"
```
