<!-- SPDX-License-Identifier: MIT -->
# 107 — The judge cannot pass a vendor's own request members, so a model that thinks by default always thinks: `llm.request_options` adds them to every request

- **Source**: the maintainer, 2026-10-26 (how many calls the judge makes): "add llm.request_options so that a model like
  GLM can turn its thinking off, and measure recall and false positives again"
- **Depends on**: none
- **Branch**: `p/107-request-options`

## Problem

The judge sends exactly three members — `model`, `messages`, `temperature` — and nothing else. Several OpenAI-compatible
endpoints decide how the model works through members of their own: Zhipu's GLM models think before answering unless the
request says `thinking: {"type": "disabled"}`; reasoning models elsewhere take `reasoning_effort`; some endpoints cap a
reply with `max_tokens`. None of these can be set today, so a model that thinks by default always does, and its
thinking is billed as completion tokens on every call the judge makes — calls whose answer is a short JSON verdict.

Measured on 40 benign + 40 malicious corpus skills (corpus 850fc546, the first 40 of each class of the seed-20261026 draw
P-103 used) with `glm-5.3-flash` at `samples: 3`, the same build asked with and without
`thinking: {"type": "disabled"}`:

| | Thinking on | Thinking off |
|---|---|---|
| benign: completion tokens | 278,912 | 30,279 (−89%) |
| malicious: completion tokens | 666,583 | 54,618 (−92%) |
| prompt tokens, calls | 1,334,211 · 804 | 1,334,148 · 804 |
| median wall time of one `check` | 110 s | 15 s |
| benign at the judge verdict | 4 of 40 | 4 of 40 |
| malicious at the judge verdict | 33 of 40 | 32 of 40 (one LLM-001 lost) |

Nine tenths of what this model writes for the judge is thinking; the verdict it then writes is a few dozen tokens.

## Initial direction

`llm.request_options`: a map in the config whose members are added, as written, to every request body the judge sends
— every question, triage, and `llm test`. The members the judge sets itself, and the two that change the shape of the
reply it reads (`stream`, `n`), are refused when the config loads. With no options the request body is byte for byte
what it is today. The options change what the model does, so a report records them beside the model.

## Done criteria

- [x] `TestLoad_RequestOptions` (`internal/config`): nested maps are read as written; each of `model`, `messages`,
  `temperature`, `stream`, `n` is refused at load, the error naming it; a value with no JSON form is refused; no key, no
  options
- [x] `TestHTTP_RequestOptionsJoinEveryRequest` (`internal/judge`, real `NewHTTP` over `httptest`): a judge question and
  `Ping` both end with the options in key order, and the rest of each body is byte-identical to a client without options
- [x] `TestRequestOptions_ReservedCoversTheRequest`: every member `chatRequest` sends is in
  `config.ReservedRequestOptions` (one list), and `SetRequestOptions` refuses each
- [x] `TestE2E_RequestOptionsReachTheEndpointAndTheBlock`: `scan`, `check` and `llm test` all send them; the judge block,
  the usage line and `llm preview` record them; without them nothing new is sent or recorded
- [x] The identity line and the baselines ledger row carry them (`TestJudgeIdentityLine_NamesTheRequestOptions`,
  `TestJudgeUsage_RequestOptionsReachTheRow`)
- [x] Reverse: `TestPromptVersion_HashesWhatTheClientSends` and every other client test unchanged and green;
  `judge-prompt=` and `judge-excerpt=` do not move; zero-dial tests unchanged
- [x] Measured: a thinking model with and without `thinking: {"type": "disabled"}` on the same skills — completion
  tokens, calls, and the judge's verdicts on benign and malicious skills
- [x] Docs: `docs/llm-judge.md` / `.zh-CN.md` (config table, a section on thinking models), `config.example.yaml`,
  spec config block and §8, `.claude/rules/judge.md`
- [x] `make verify` green with `go version` go1.23.5 and no toolchain switch; `head -3 go.mod` line 3 `go 1.23.5`

## Out of scope

- Knowing any vendor's members. The tool passes what the config says; the docs give the GLM example and say where other
  vendors document theirs. No preset turns anything on.
- Headers. Only body members.
- Validating that an endpoint accepts a member: an endpoint that refuses one answers with an error, which `llm test`
  shows before a scan and a run reports as `LLM-000`.
- Changing the default model or any preset's model.
- Anything priced.

## Must not claim

- Never that turning thinking off keeps the judge's answers unchanged, unless the measurement says so for that model;
  the docs carry the measured difference.
- Never a cost or a saving in money. Only completion tokens and calls as the endpoint reported them.
- Never that an option is checked against the vendor's API: it is passed as written.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | The proposal | `P-107: the proposal — the judge cannot pass a vendor's own request members` |
| 2 | `llm.request_options` in config, refused members, the client adds them to every request | `P-107: llm.request_options join every request the judge sends` |
| 3 | The judge block, identity line, usage log, ledger row and preview record them | `P-107: a report names the request options its judge sent` |
| 4 | Documentation | `P-107: docs — request options, and turning a model's thinking off` |
| 5 | Done | `P-107: done — evidence, and the proposal moves to complete` |

## Open questions

1. A free map or named switches (`thinking: off`)? Recommended: a free map. Each vendor names its members differently and
   changes them; a switch would put vendor names in the tool, which `config.Presets` avoids ("nothing else in the tool
   knows a vendor's name").
   **Decided (2026-10-26)**: as recommended.
2. Which members are refused? Recommended: the three the judge sets (`model`, `messages`, `temperature`) and `stream`,
   `n`, which change the shape of the reply. Everything else is the operator's choice — `max_tokens` included, which can
   cut a verdict short (an unreadable reply is re-asked once and then reported, P-069).
   **Decided (2026-10-26)**: as recommended.
3. Do the options enter `PromptVersion`? Recommended: no. They are configuration, like the model name, and are recorded
   beside it in the judge block (`request_options`), the identity line, the usage log and the ledger row.
   **Decided (2026-10-26)**: as recommended.

## Done

```
Merged: PR #132 (find the sha with git log --grep P-107 after the merge)
Released: (fill in after the release)
Evidence: TestLoad_RequestOptions (internal/config): nested maps read as written and recorded as {"max_tokens":800,"thinking":{"type":"disabled"}}; model, messages, temperature, stream and n each refused at load, the error naming it; a map keyed by a number refused; no key, no options
Evidence: TestHTTP_RequestOptionsJoinEveryRequest (real NewHTTP over httptest): a judge question and Ping both end with ,"max_tokens":800,"thinking":{"type":"disabled"}} and are otherwise byte-identical to a client without options (HTML left unescaped, as before). TestRequestOptions_ReservedCoversTheRequest: every chatRequest member is in config.ReservedRequestOptions, and SetRequestOptions refuses each
Evidence: TestE2E_RequestOptionsReachTheEndpointAndTheBlock: scan, check and llm test send them; judge block, usage line and llm preview record {"thinking":{"type":"disabled"}}; a config without them sends and records nothing new. TestJudgeIdentityLine_NamesTheRequestOptions; TestJudgeUsage_RequestOptionsReachTheRow
Evidence: reverse — TestPromptVersion_HashesWhatTheClientSends and TestPromptVersion_EveryInputIsDecided (Extra declared a stand-in) green; judge-prompt=b851dfd5412b and judge-excerpt=9 unchanged; zero-dial tests unchanged; the client-only commit passes every package on its own
Evidence: live, glm-5.3-flash: `llm test` answered with the option (26 in / 11 out, against 26 / 28 with thinking on); one benign and one malicious skill, thinking on → off: completion tokens 7,769 → 680 and 15,717 → 1,068, wall time 81 s → 14 s and 171 s → 25 s
Evidence: measured, the 80 corpus skills under Problem, every check complete on both: benign completion tokens 278,912 → 30,279, false positives 4 → 4; malicious completion tokens 666,583 → 54,618, at the judge verdict 33 → 32 (one sample lost its LLM-001); prompt tokens and calls unchanged (1,334,211 → 1,334,148, 804 both); median check 110 s → 15 s
Evidence: make verify: all gates passed; go version go1.23.5 darwin/arm64, no toolchain switch; go.mod line 3 "go 1.23.5"
```
