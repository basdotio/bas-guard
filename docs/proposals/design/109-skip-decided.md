<!-- SPDX-License-Identifier: MIT -->
# 109 — An artifact whose deterministic findings already reach high is asked every judge question, though no answer can change its verdict or a gate: it is skipped unless `llm.judge_decided` is true

- **Source**: the maintainer, 2026-10-27 (how many calls the judge makes): "skip the judge for what static already rated high";
  default chosen by the maintainer: skip
- **Depends on**: none
- **Branch**: `p/109-skip-decided`

## Problem

The judge asks its questions of every artifact of a judged kind, whatever the deterministic rules already found. When an
artifact already carries a deterministic finding at high or critical:

- `--fail-on` reads deterministic findings only, so its answer is fixed before the judge runs.
- `--fail-on-llm` reads the deterministic findings and the escalated LLM ones; the deterministic high already reaches
  every threshold up to high, and a judge finding is clamped at high (`clampSeverity`), so it can never reach critical.
- The benchmark predicate (static ≥ high, or an escalated LLM finding ≥ high) is already true.

The answers still cost their calls. Read from the committed ledgers' `usage_by_pass` (judge questions, triage left out of
the numerator), the share of the judge's calls spent on samples whose deterministic findings were already high:

| Reading | Samples | Already high | Judge calls on them | Their share of the tokens |
|---|---|---|---|---|
| held-out benign skills (`v031-asmben`) | 216 | 6 | 54 of 1,969 (2.7%) | 2.9% |
| fresh held-out benign skills (`v031-fresh216`) | 216 | 9 | 81 of 1,964 (4.1%) | 4.7% |
| held-out malicious skills (`v031-asmmal`) | 123 | 68 | 612 of 1,187 (51.6%) | 51.1% |
| SkillHarm (`v031-sh120`) | 120 | 12 | 120 of 1,313 (9.1%) | 9.7% |
| held-out MCP servers (`p100-mcp-heldout`) | 697 | 94 | 102 of 1,501 (6.8%) | 7.9% |
| benign servers (`p098-benign-servers-main`) | 543 | 93 | 264 of 1,845 (14.3%) | 18.7% |
| Cisco malicious servers (`p098-cisco-servers-main`) | 127 | 22 | 66 of 436 (15.1%) | 16.5% |

What those calls can still change is not a verdict: the LLM leads shown on that artifact (an explanation of what static
already flagged), an `LLM-007` if the artifact also addressed the analyzer, and `overall_effective`, which a judge
escalation can lower further.

## Initial direction

When the run plans its calls, leave out every judge question of an artifact whose deterministic findings include one at
high or above; keep its triage call (one call, and it is the explanation of exactly those findings). On by default;
`llm.judge_decided: true` asks those artifacts every question as before. The judge block counts the artifacts left out
(`decided`), the summary line names them, and the preview plans the same calls the run makes.

## Done criteria

- [ ] `TestPlan_DecidedArtifactsAreNotAsked` (`internal/judge`): with `SkipDecided`, an artifact with a deterministic high
  or critical finding gets no judge question and keeps its triage call; one with medium, with only an LLM finding, or
  with a high note (dimension 0) is asked as before; without `SkipDecided` the plan is unchanged
- [ ] `config`: `judge_decided` defaults to false and reads `true`; `judgePlanOptions` carries it, so `llm preview` and the
  run plan the same calls
- [ ] The judge block carries `decided` (absent when 0), the summary line names it, the usage log copies it; `--fail-on`
  and `--fail-on-llm` exit codes unchanged on a decided artifact (`TestE2E_DecidedArtifactIsNotAGap`)
- [ ] Reverse: every `internal/judge` test uses the zero `Options` and is unchanged; `judge-prompt=` and `judge-excerpt=`
  do not move (no request changes; which artifacts are asked is configuration, recorded in `decided`)
- [ ] Measured: the counterfactual above, and the calls `llm preview` plans before and after on the corpus
- [ ] Docs: `docs/llm-judge.md` / `.zh-CN.md`, spec §5.2 and §8, `config.example.yaml`, `.claude/rules/judge.md`,
  `baselines/README.md` (a reading of per-rule judge rates sets `judge_decided: true`)
- [ ] `make verify` green with `go version` go1.23.5 and no toolchain switch; `head -3 go.mod` line 3 `go 1.23.5`

## Out of scope

- A threshold other than high: a judge finding is clamped at high, so high is where nothing it says can move a verdict.
- Skipping triage.
- Any change to what is asked of an artifact that is not decided.
- Anything priced.

## Must not claim

- Never that the report is unchanged: a decided artifact shows no LLM leads and no `LLM-007`, and its
  `overall_effective` is what the deterministic findings give. Only that no verdict at the high threshold and no gate exit
  code changes.
- Never a cost or a saving in money.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | The proposal | `P-109: the proposal — an artifact already high is asked every judge question` |
| 2 | `llm.judge_decided`, `Options.SkipDecided`; the plan leaves out a decided artifact's judge questions | `P-109: an artifact whose deterministic findings reach high is not asked the judge's questions` |
| 3 | `decided` in the judge block, summary line, usage log and ledger row | `P-109: the judge block counts the decided artifacts it did not ask` |
| 4 | Documentation | `P-109: docs — decided artifacts are not judged unless llm.judge_decided` |
| 5 | Done | `P-109: done — evidence, and the proposal moves to complete` |

## Open questions

1. On or off by default? The maintainer chose on (2026-10-27): no verdict at the high threshold and no gate exit code can
   change. **Decided (2026-10-27)**: skip by default; `judge_decided: true` asks them.
2. Keep triage on a decided artifact? Recommended: yes. One call, and its labels are the reading of exactly the findings
   that decided it. **Decided (2026-10-27)**: as recommended.
3. Does `ExcerptVersion` move? Recommended: no. What an asked question is shown is unchanged; which artifacts are asked
   depends on their findings and the configuration, and the judge block counts the ones left out.
   **Decided (2026-10-27)**: as recommended.

## Done

```
Merged: PR to be opened (find the sha with git log --grep P-109 after the merge)
Released: (fill in after the release)
Evidence: (filled in by W5)
```
