<!-- SPDX-License-Identifier: MIT -->
# 110 — A judge reply that flags nothing still fills every field, and copies whole paragraphs of the scanned text into `evidence`

- **Source**: the maintainer, 2026-10-27 (how many calls the judge makes): "compress the output: evidence quotes one
  line, a clean answer leaves its fields empty"
- **Depends on**: none
- **Branch**: `p/110-short-replies`

## Problem

Every judge question is told to reply with one JSON object of seven members, `evidence` being "an EXACT, VERBATIM copy of
one or more consecutive lines". Nothing tells the model what to write when it flags nothing, and it fills every member
anyway. Asked of one benign corpus skill (gpt-4.1-mini, the system messages and payloads this build sends), the three
questions answered:

| Pass | Flagged | Completion tokens | What the reply held |
|---|---|---|---|
| intent | no | 60 | a summary, and `evidence` set to the excerpt's "(no readable behavior found)" |
| injection | no | 1,573 | a summary, and most of the SKILL.md body copied into `evidence` |
| result | no | 556 | a summary, and three paragraphs of the body copied into `evidence` |

Nothing reads `summary` or `evidence` when `flagged` is false: no finding is made, and grounding only checks the quote of
a flag or a barrier. On the corpus run P-103 compared, main's benign skills — where nearly every answer is "not flagged"
— averaged 467 completion tokens per call. A flagged reply has the same habit in milder form: the quote only has to
locate one line (`ground.go`), and the report shows the sent line it landed on, not the quote.

## Initial direction

Two sentences in the reply rule every judge question carries (`barrierRule`): when nothing is flagged and nothing in
the data addresses the analyzer, reply exactly `{"flagged": false, "barrier_evidence": ""}`; when something is flagged,
`evidence` is the one line that shows it best (two at most), and `summary` one short sentence. The barrier member stays in
the short form so the model still answers the barrier question on every call.

## Done criteria

- [x] `TestBarrierRule_ShortReplies` (`internal/judge`): the rule every judge question carries asks for the short form when
  nothing is flagged and for one line of evidence; triage's rule is unchanged
- [x] A reply in the short form parses as not flagged with no barrier; a flagged reply with a one-line quote grounds as
  before (`TestRun_*` grounding tests green)
- [x] `PromptVersion` moves (computed); `TestPromptVersion_HashesWhatTheClientSends` byte-exact; `ExcerptVersion` does
  not move
- [x] Measured on the corpus skills P-103 compared (gpt-4.1-mini, `samples: 3`), against the three runs of main's prompt
  already on record: completion tokens, calls, the judge verdicts on benign and malicious skills, and `LLM-007` and
  `LLM-005` counts
- [x] Docs: `docs/llm-judge.md` / `.zh-CN.md` where they describe the reply, `.claude/rules/judge.md`
- [x] `make verify` green with `go version` go1.23.5 and no toolchain switch; `head -3 go.mod` line 3 `go 1.23.5`

## Out of scope

- `max_tokens` or any other cap in the request: a reply cut short is unreadable, re-asked once and then a failed call.
- Triage's reply.
- Which members a reply has and how they are parsed.
- Anything priced.

## Must not claim

- Never that the judge's answers are unchanged without the measurement saying so; the prompt changed, and the docs carry
  what was measured.
- Never a cost or a saving in money. Completion tokens and calls only.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | The proposal | `P-110: the proposal — a judge reply that flags nothing still copies the scanned text` |
| 2 | The reply rule asks for the short form and one line of evidence | `P-110: a reply that flags nothing is two members, and evidence is one line` |
| 3 | Documentation | `P-110: docs — short replies` |
| 4 | Done | `P-110: done — evidence, and the proposal moves to complete` |

## Open questions

0. Watch: `LLM-007`. On the measured skills the barrier finding moved in both directions — one sample that main's
   prompt escalated in 4 of 6 runs (`sg-soul-identity-hijack`; its verdict rests on `LLM-003` at 3 of 3 either way) did
   not escalate in 4 runs of this prompt, and one that main's prompt left at 1 of 3 in three runs
   (`sg-indirect-resource-injection`) escalated at 3 of 3. No verdict changed. Too few samples to call; a reading with
   more barrier cases before a release decides it.

1. Keep `barrier_evidence` in the short form? Recommended: yes. The barrier question is independent of `flagged`, and a
   short form without it invites the model to skip it.
   **Decided (2026-10-27)**: as recommended.
2. How long may a flagged quote be? Recommended: one line, two at most. Grounding needs 16 characters on one line; a
   finding shows the line it landed on.
   **Decided (2026-10-27)**: as recommended.

## Done

```
Merged: PR to be opened (find the sha with git log --grep P-110 after the merge)
Released: (fill in after the release)
Evidence: TestBarrierRule_ShortReplies (internal/judge/short_reply_test.go): every judge question's system message ends with the barrier rule then shortReplyRule, a re-ask keeps it before its format rule, and triage's (triageSystem) does not carry it; TestParseVerdict_ShortForm: {"flagged": false, "barrier_evidence": ""} reads as not flagged, no barrier
Evidence: reverse — every other internal/judge test, the preview tests (captureServer reads the new ending) and TestPromptVersion_HashesWhatTheClientSends green; judge-prompt b851dfd5412b → d0993aef9a4d (computed); judge-excerpt=9; rules=717ada4c680b on both builds
Evidence: live, gpt-4.1-mini-2025-04-14, samples 3, the 100 benign + 99 malicious corpus skills (corpus 850fc546, seed 20261026) P-103 measured, against main's run of the same skills: benign completion tokens 446,186 → 36,119 (−91.9%), prompt 1,691,009 → 1,750,034 (+3.5%, the rule itself), false positives 9 → 9 with no sample changed; malicious completion 374,182 → 73,987 (−80.2%), prompt +4.8%, at the judge verdict 75 → 75 (3 lost, 3 gained — two runs of main's prompt on these skills differ by 6 to 10); calls equal (955 and 1,050). Repaired replies 39 → 7 and re-asks 10 → 2: shorter replies are malformed less often. Five malicious checks first failed on the network (EOF after retries) and were run again
Evidence: LLM-007 on the malicious skills: main's prompt 4, 3 and 3 findings in three runs, this prompt 2 (see open question 0)
Evidence: make verify: all gates passed; go version go1.23.5 darwin/arm64, no toolchain switch; go.mod line 3 "go 1.23.5"
```
