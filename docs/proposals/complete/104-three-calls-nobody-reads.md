<!-- SPDX-License-Identifier: MIT -->
# 104 — Two judge calls whose answers nobody can use: the intent question asked of a skill with no behaviour file, and triage sending every repeat of a rule under a verdict schema it does not use

- **Source**: The maintainer, 2026-10-26 (how many calls the judge makes)
- **Depends on**: P-054 (a quote of the declared purpose is not evidence of a behaviour), P-027 (the preview shares the run's plan), P-031 (the two judge versions)
- **Branch**: `p/104-three-calls-nobody-reads`

## Problem

Measured with `bas-guard llm preview --json` (no key, no network; `samples: 3`) over every layer-1 sample of the corpus at
`9d22d9ce` that the benchmark adapter stages for `scan` or hands to `check` on the server-source route — 4,815 samples —
`main` plans 42,827 calls. Two groups of them return answers no number, gate or label reads:

1. **The intent question is asked of every skill, behaviour file or not.** The spec (§5.2) and `docs/llm-judge.md` say intent
   is gated on a static finding or an unknown reputation; `planFor` never gated it. A skill with no script or config file the
   walker reads is shown `[ACTUAL BEHAVIOR] (no readable behavior found)`, and the only text the model can quote is the
   description — which since P-054 is not evidence of a behaviour, so the verdict is dropped. The question cannot yield an
   `LLM-001`. 2,731 of the 3,283 skill artifacts in the measured set have no behaviour file (2,531 of 2,879 benign skill
   samples, 191 of 393 malicious ones): 8,193 planned calls. In the committed judge runs (the 29 held-out runs not
   read), samples whose every skill has no behaviour file carry 12,761 rows in the 19 runs before P-054, with 23
   `LLM-001` votes — by today's walker the description is the only unit such a question grounds in — and 2,063 rows in
   the 25 runs with P-054, with **0** `LLM-001` votes; samples with a scripted skill carry 880 in those 25 runs.
2. **Triage sends every finding, repeats included, under the judge's verdict schema.** It asks for one label per distinct
   rule id, and the report joins that label to every finding of the rule (`report.Aggregate`, by id), but the call carries
   every finding of the artifact — up to 40 items of up to 1,000 bytes — so the tenth `EXEC-001` of a tree adds bytes and no
   label. Its system message is `triageTask + barrierRule(nonce)`, and `barrierRule` ends with the verdict format
   (`{"flagged": …, "evidence": …}`), which contradicts the `{"labels": …}` format `triageTask` asks for. 1,379 triage
   calls carry 484,681 bytes of payload; in 212 of the 1,202 samples with a triage call some rule has more than three
   findings.

## Initial direction

Ask intent only when `behaviorExcerpt` returns text. Send triage at most three findings of each rule, in table order, before
its cap of 40, under the trust rule without the verdict schema. No judge-pass prompt changes a byte; the two versions move
as their rules say.

## Done criteria

- [x] `TestPlan_IntentNeedsABehaviourFile`, `TestRun_ScriptlessSkillAsksNoIntent`: no intent question without a behaviour
  file; the injection and result questions unchanged
- [x] `TestRun_ScriptlessSkillDescriptionStillGroundsABarrier`: on a skill with no behaviour file, a description that
  addresses the analyzer still grounds an escalated `LLM-007` at `SKILL.md:1`; an `LLM-003` quoting only the description
  does not ground; a skill with a script keeps its injection units
- [x] `TestTriageSent_AtMostThreePerRule`, `TestRun_TriageLabelReachesEveryFindingOfItsRule`,
  `TestTriage_SystemMessageIsTheTrustRuleWithoutTheVerdictSchema`, `TestPlan_TriageShortenedSaysBoth`
- [x] `TestPromptVersion_EveryInputIsDecided`: the triage shape passes both of its caps;
  `TestPromptVersion_HashesWhatTheClientSends` byte-exact
- [x] `TestExcerptVersion_IsPinnedWithItsGolden` with a script-less skill in the fixture; `ExcerptVersion` 9 → 11
- [x] `TestJudgefold_Golden` regenerated: calls and question counts only, no verdict changed
- [x] Reverse: `TestPlan_PayloadsAreWhatTheClientSends`, the zero-dial tests, the `--fail-on` tests,
  `TestMCPConfig_NeverCarriesWeight`, `TestConsensus_*` green; every judge-pass request body byte-identical to `main`
- [x] Measured: planned calls, script-less skills and triage bytes before and after, on the same sample list
- [x] Docs: `docs/llm-judge.md` / `.zh-CN.md`, `docs/architecture.md` / `.zh-CN.md`, spec §5.2, `.claude/rules/judge.md`
- [x] `make verify` green with `go version` go1.23.5 and no toolchain switch; `head -3 go.mod` line 3 `go 1.23.5`

## Out of scope

- **Asking the MCP configuration question (`LLM-009`) once whatever `samples` is.** It was in this proposal and was dropped
  by the maintainer (2026-10-26). `LLM-009` never carries weight, but asked once, an `LLM-007` that pass raises could not
  reach the consensus bar at `samples: 2` or more, so an escalation could change — and this round's premise is that none
  does. P-103 (a question stops after two clean answers at `samples: 3`) takes most of those calls without that change.
  `LLM-009` is asked `samples` times, as before.
- Any judge pass's prompt, category table, excerpt caps, samples or temperature.
- The consensus bar, `majority`, `advisoryOnly` and every gate.
- What triage asks and how its label renders; only which items it carries and the barrier around them.

## Must not claim

- Never that a run "costs less", by how much, or anything priced. Only: the plan has fewer calls and triage fewer bytes,
  counted by `llm preview` on a named sample list.
- Never that no escalation can move between questions. A description-borne `LLM-007` of a skill with no behaviour file is
  now grounded by the injection question instead of the intent question: the same text, the same `SKILL.md:1`, another
  question's draws. Measured live once on the corpus's script-less malicious skills (see Done), not on a benign set.
- Never that the intent question never found anything on a script-less skill: before P-054 it escalated 18 times on such
  samples in committed runs, each on the description, which P-054 ruled out as evidence.
- Never that triage labels improved or that the model reads the new triage message better: not measured. Triage is
  display-only; no finding, score or gate reads it.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | The proposal | `P-104: the proposal — two judge calls whose answers nobody can use` |
| 2 | Intent only with a behaviour file; the injection question grounds a description barrier of such a skill | `P-104: a skill with no behaviour file is not asked the intent question; ExcerptVersion 9 → 11` |
| 3 | Triage: three findings per rule, the trust rule without the verdict schema | `P-104: a triage call carries at most three findings of a rule and the trust rule without the verdict schema; PromptVersion b851dfd5412b → 20799ea92626` |
| 4 | Documentation | `P-104: docs — intent needs a behaviour file, triage carries three findings per rule` |
| 5 | Done | `P-104: done — evidence, and the proposal moves to complete` |

## Open questions

1. A skill with no behaviour file loses the one question whose grounding units held its description, and one committed
   malicious sample hides its whole directive there (`mal-skill-sg-ignore-previous-instructions`, `LLM-007` 3 of 3 in the
   P-054 and P-088 runs). Recommended: the injection question of such a skill carries the description as a `declaration`
   unit, so a barrier quote of it grounds at `SKILL.md:1` as before, while its verdict (`LLM-003`) grounds in the body
   alone, as before. Skills with a behaviour file are untouched.
   **Decided (2026-10-26)**: as recommended, after the live check in Done.
2. Which number does `ExcerptVersion` take? Recommended: 11, not 10. Ten is in committed results already, naming the
   excerpts of the rejected P-070 branch (`results/aguard/2026-10-17-llm-gpt-4.1-mini-p070-*`); reusing it would let two
   reports claim the same excerpts while the judge was shown different text.
   **Decided (2026-10-26)**: as recommended.
3. How many findings of one rule does triage keep? Recommended: three, in table order — enough to show a pattern, and the
   label covers the rest. The per-artifact cap of 40 applies after, so rules that fell past it before can now be labelled.
   **Decided (2026-10-26)**: as recommended.

## Done

```
Merged: PR #129 (find the sha with git log --grep P-104 after the merge)
Released: (fill in after release)
Evidence: llm preview --json, samples 3, no network, corpus 9d22d9ce, the 4,815 samples the adapter stages or routes to the server pass, main cf26ecb against this branch: planned calls 42,827 → 34,634 (−8,193, 19.1%); benign 38,001 → 30,408, malicious 4,685 → 4,091; benign skill samples 27,444 → 19,851
Evidence: intent 9,849 → 1,656 calls (2,731 of 3,283 skill artifacts have no behaviour file: 2,531 of 2,879 benign skill samples, 191 of 393 malicious); mcp-config 1,176 either way; triage 1,379 calls either way, payload 484,681 → 359,879 bytes (25.7% fewer), items 4,387 → 3,315, fewer in 212 of 1,202 samples
Evidence: committed runs, held-out runs (29) not read: on samples whose every skill has no behaviour file, 23 LLM-001 votes in 12,761 rows of the 19 runs before P-054, 0 in 2,063 rows of the 25 runs with it (880 on samples with a scripted skill)
Evidence: open question 1, live (the maintainer, 2026-10-26; gpt-4.1-mini-2025-04-14, samples 3, corpus 850fc546), a build with this change against main cf26ecb: sg-ignore-previous-instructions, the one script-less malicious skill whose description carries a directive, LLM-007 at SKILL.md:1, 3 of 3, escalated, in 3 of 3 runs on both builds, calls 10 → 7; eight other script-less malicious skills whose descriptions carry directive-like words, one run each: every escalation the same on both builds except one LLM-011 (the result pass, untouched here) 2/3 → 1/3, sampling noise; calls 3 fewer each (the intent question)
Evidence: bas-guard version, main → this branch: judge-prompt b851dfd5412b → 20799ea92626, judge-excerpt 9 → 11, rules 717ada4c680b both; the 80 judge-pass request shapes hash to ecf67659008f on main and here (every judge-pass body byte-identical; only the triage shape moved)
Evidence: new tests TestPlan_IntentNeedsABehaviourFile, TestRun_ScriptlessSkillAsksNoIntent, TestRun_ScriptlessSkillDescriptionStillGroundsABarrier (intent_gate_test.go); TestTriageSent_AtMostThreePerRule, TestTriage_SystemMessageIsTheTrustRuleWithoutTheVerdictSchema, TestRun_TriageLabelReachesEveryFindingOfItsRule, TestPlan_TriageShortenedSaysBoth (triage_cap_test.go)
Evidence: reverse — TestPlan_PayloadsAreWhatTheClientSends, TestPromptVersion_HashesWhatTheClientSends, TestZeroDial_*, TestFailGate*, TestMCPConfig_NeverCarriesWeight, TestConsensus_*, TestPlan_BudgetAndSamplesMatchRun green unchanged; changed for the new behaviour: captureServer (triage's trust rule), four fixtures given a script (reask ×3, plugin child), the judgefold golden regenerated (calls and question counts only)
Evidence: make verify: all gates passed; go version go1.23.5 darwin/arm64, no toolchain switch; go.mod line 3 "go 1.23.5"
```
