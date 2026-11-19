<!-- SPDX-License-Identifier: MIT -->
# 113 — The nonce sits inside the system message, so questions about different artifacts never share a cached prefix: move it to the end

- **Source**: the maintainer, 2026-10-27 (how many calls the judge makes): "move the nonce to the end of the system
  prompt so different skills share the cache"; measured on 2026-10-27 (OpenAI) and 2026-10-29 (GLM, once its quota reset)
- **Depends on**: P-080 (one nonce per question; the repeats of a question already share their whole request)
- **Branch**: `p/113-nonce-last` (this record only; no code was written)
- **Rejected**: 2026-10-29 — neither endpoint the judge has been measured on could serve the moved prefix from a cache.
  See Measured.

## Problem

Every judge question's system message is the pass's task text, then the barrier rule, which names the question's nonce
about two thirds of the way in. P-080 made the k samples of one question byte-identical, so an endpoint can serve the
repeats from its cache. Two questions of the same pass about different artifacts share only the system message up to the
nonce; the rest of it — the rest of the barrier rule and the reply schema, the same text in every question — comes after
a value that differs, so no prefix cache can reach it.

## Initial direction

Put the nonce last: the barrier rule names "the fence line given at the end of this message", and the message ends with
that line. Every question of a pass would then share its whole system message, whatever artifact it is about.

## Measured

**What would become shareable.** The system messages this build sends, counted with `tiktoken` (`o200k_base`, the
encoding of the OpenAI models the judge has been measured with):

| Pass | Whole system message | Before the nonce today | After it |
|---|---|---|---|
| result | 959 | 640 | 309 |
| server | 923 | 604 | 309 |
| intent | 902 | 583 | 309 |
| injection | 866 | 547 | 309 |
| capability | 762 | 443 | 309 |
| deobfuscation | 639 | 320 | 309 |
| collusion | 589 | 270 | 309 |
| mcp-config | 474 | 155 | 309 |
| triage | 471 | 152 | 309 |

OpenAI documents a 1,024-token minimum for a cached prefix. Every system message is under it, so with the nonce moved
to the very end the prefix two different questions share is still too short to be cached: nothing changes on OpenAI.

**GLM (`glm-5.3-flash`, open.bigmodel.cn, thinking off, 2026-10-29).** Direct calls, the second sent 2–15 s after the
first, `usage.prompt_tokens_details.cached_tokens` read from the second:

| First and second call share | Shared prefix | Cached on the second |
|---|---|---|
| the system message only (different user messages), five lengths | ~300 to ~2,000 tokens | 0 every time |
| the system message only, 15 s apart | ~2,400 tokens | 0 |
| the system message only, thinking on | ~2,400 tokens | 0 |
| the whole request (system and user identical) | 2,653 tokens | 2,624 |
| the whole request, thinking on | 2,654 tokens | 2,624 |

GLM served a repeat of an identical request from its cache and never served a shared system message under a different
user message, at any length tried. The cache share the GLM judge runs report comes from P-080's identical repeats; moving
the nonce would add nothing to it.

**Reading.** On OpenAI the prefix is too short to be cached; on GLM no prefix shorter than the whole request is. The
change would cost a reworded barrier rule (a new `PromptVersion`, and a recall and false-positive reading to show the
barrier still holds) and buy nothing on either.

What would reopen it: a system message that grows past 1,024 tokens on its own (a pass whose categories or task text get
longer), or an endpoint the judge is run against that caches shared prefixes across requests below the length of the
whole request. Padding the message to reach 1,024 tokens is not proposed: every first call of a pass would pay for the
padding, and the text the model reads would change for a reason that has nothing to do with the question.

## Done

```
Rejected: 2026-10-29 — every system message is under OpenAI's 1,024-token cache minimum; GLM caches identical requests only
Evidence: system-message token counts above, o200k_base, from this build's systemPrompt and triage message (nonce 32 hex digits)
Evidence: GLM probe above, glm-5.3-flash with thinking off and on, 2026-10-29, nine call pairs
```
