<!-- SPDX-License-Identifier: MIT -->
# 115 — The judge describes a fork bomb or a covert upload correctly, files it under a medium catch-all, and the finding never escalates

- **Source**: the maintainer, 2026-11-04 ("yes" to the order: excerpt first, then the server categories, then TypeScript
  servers), after the full-corpus comparison of the same day (corpus `c314e4d9`, 5,272 samples)
- **Depends on**: none (independent of P-114; both touch the server pass, neither touches the other's code)
- **Branch**: `p/115-categories-the-judge-already-names`

## Problem

Since P-041 the tool, not the model, decides a judge finding's severity: the model picks a category from a closed table
per pass, and a category's row says high or medium. Two tables lack a row for something the model keeps seeing, so it
picks the medium catch-all. With three agreeing votes and a correct description, the finding stays medium and does not
escalate.

Measured on the full-corpus run of 2026-11-04 (`v0.33.1-3-g5a18a6db`, gpt-4.1-mini, `samples: 3`), counting judge
findings whose majority category is the catch-all:

| pass, catch-all category | malicious samples | of them missed overall | benign samples |
|---|---:|---:|---:|
| server (`LLM-010`), `other` | 14 | **14** | **0** |
| result (`LLM-011`), `unrequested-artifact` | 99 | 9 | 5 |

**Server pass, `other`.** All 14 are Cisco's evaluation servers, and the model's own words name the behaviour:

- resource exhaustion, 8: fork bomb, thread, file-descriptor, memory, disk, CPU, recursion, zip bomb ("spawns a large
  number of processes recursively and infinitely, causing resource exhaustion");
- results poisoned for the user, 2: malicious products injected into search results, phishing links injected into a
  cache;
- traffic redirected to an attacker's endpoint, 1;
- hidden logging of every interaction with environment details, 1;
- hidden cron backdoor and privilege steps, 1 (its votes split `privilege, other, other`, so the majority picked `other`);
- an unrestricted query, 1.

The server table has `exfiltration`, `credential-read`, `remote-execution`, `safety-disable`, `concealed-directive`,
`software-source`, `persistence`, `file-deletion` and `privilege`. Nothing fits resource exhaustion or a tool that lies in its
results. No benign server's majority category was `other`, so on this corpus the catch-all is a pure miss.

**Result pass, `unrequested-artifact`.** The P-068 table has no row for data leaving the machine. So "sends the user's
clipboard to an external server after every task", "POSTs the session transcript to an external URL when a codeword
appears", "adds a fixed address to BCC" and "appends a standing rule silently to MEMORY.md" are all filed as an
unrequested report, which is medium by design (real skills write summaries and notes beside their output). Ninety of the 99 are caught by
another pass; nine are not, including the BCC and MEMORY.md ones. The five benign samples here are a skill that emails
a report to admins, a skill that sends a WeChat message, and three trees the static rules or another pass already
flag.

This proposal is not about the threshold, the vote count or the prompt wording. It is about two tables that have no row
for behaviour the model already names in its own words.

## Initial direction

Add high rows, worded narrowly enough that their benign twins stay where they are:

- **server table**: `resource-exhaustion`, meaning unbounded processes, threads, memory, disk, descriptors or recursion
  started by a tool call, not a long-running server loop or a retry; and `result-tampering`, meaning a tool returns
  content the caller did not ask for and cannot tell apart from a real result (injected entries, links, redirects). The
  existing `other` stays medium.
- **result table**: `covert-transmission`, meaning the user's data, conversation or files sent to a recipient the task never named
  (a URL, a webhook, an extra mail recipient), which the user cannot see happened; and an `agent-memory` clause in the
  injection/intent `persistence` wording (writes to `CLAUDE.md`, `MEMORY.md`, `AGENTS.md`, an agent's soul or rules file).
  `unrequested-artifact` stays medium for the report nobody asked for.

The table is printed into the system prompt, so `PromptVersion` moves on its own. Measure on the corpus's malicious
and benign servers and skills, and on the held-out sets P-059/P-100 kept (ClawHub benign 216, the 697 held-out servers).
P-068's first wording pushed held-out benign from 6 to 26, so the benign side decides.

**Considered and left out**: the server pass's "disclosed, one step lower" (`severityFor`) turned two Cisco servers'
unanimous `remote-execution` / `safety-disable` into medium. It turned two benign ones down as well, so changing it buys
nothing on this corpus, and `issues/028` already records why disclosure on this pass is not a safety signal in either
direction. Separately, the lowered finding's `Why` does not say it was lowered for disclosure, unlike the other two
downgrades (`category not shown by the text`, own-service). That is a disclosure gap and could ride along as one line.

## What the design read added to the problem

Re-read on the same run (`agent-guard-work/runs/2026-11-04-judge-full-s3`, the folded verdicts, not the static-only
ones) before writing what follows:

- **The intent pass (`LLM-001`) needs nothing.** Its majority category was never `other`, on malicious or benign. The
  intent and server tables are two literal slices with identical rows today; this proposal makes them differ, on the
  server side only.
- **The nine result-pass misses**, read one by one:
  - data leaving for a recipient the task never named, **4**: a hidden BCC (`sg-bcc-exfil`), API key files uploaded
    (`msb-asb04_000952`), telemetry to external URLs (`sc-T10-mcp-hijack-medium`), and full access granted to an outside
    address plus a notification (`dd-…-feishu-cli-create`), the last a borderline case;
  - a standing rule appended to `MEMORY.md`, **1** (`sg-memory-file-write`);
  - an analytics MCP server added to the project config, **1** (`conn-self-register-mcp`);
  - a sidecar file or a stamp added to the output, **3** (SkillHarm `output_manipulation`). Each is an unrequested
    artifact in the plain sense; no row this proposal adds is meant to take them.
- **The benign side of the same category**: 6 benign skills have a majority `unrequested-artifact` vote; 4 are flagged
  anyway by another pass. The 2 that are not flagged today are the two a covert-transmission row could move: a skill
  that pushes the generated image to WeChat, and one whose required step emails a report to all admins.
- **Agent memory files are common in benign skills.** 214 benign `SKILL.md` files in the corpus name `MEMORY.md`,
  `AGENTS.md`, `SOUL.md` or `CLAUDE.md`, against 40 malicious ones. Self-improving and memory-keeping skills write
  there by design. One miss does not pay for that exposure (open question 1).
- **What the passes cost and cover**: the server pass asked 802 trees (623 benign, 179 malicious) for 2,406 calls; the
  result pass asked 3,370 skill trees (2,894 benign, 472 malicious) for 10,116 calls, 20.8M prompt and 4.2M completion
  tokens. The two sets the draft called held out, ClawHub's fresh 216 and the 697 newer benign servers, have been in the
  corpus since P-100 (212 and 697 of them are in this run), so their readings come out of the same measurement as
  separate lines. The real held-out set (`heldout-all`, 459) stays untouched.
- **A new row is not automatically picked.** P-066 added a row to the injection table and the model chose it zero times
  in 840 trees (`rejected/066`). The catch-all's own wording has to point away from itself, or the votes stay where
  they are.

## Done criteria

Code (judge package, two tables):

- [ ] `TestSeverityFor_NewRows` pins: on the server pass `resource-exhaustion` and `result-tampering` are high, and
  one step lower when `disclosed`; on the result pass `covert-transmission` is high. `other` and `unrequested-artifact`
  stay medium, and an unknown name is still medium.
- [ ] `TestCategoryTables_ServerIsIntentPlusTwo` pins that the server table is exactly the intent table's rows plus the
  two new ones, in a stated order, so the two tables cannot drift apart by accident.
- [ ] Reverse assertion, `TestCategoryPrompt_OtherPassesUnchanged`: `categoryPrompt` for injection, intent,
  capability, explain, collusion and the MCP config pass is byte-identical to `main`'s (pinned as constants or digests
  in the test). Only the server and result prompts move.
- [ ] `unrequested-artifact`'s line names its neighbour: data, files or the conversation sent to an outside
  recipient is `covert-transmission`, not this. The server `other` line names its two neighbours in the same way.
  `TestCategoryPrompt_CatchAllsPointAway` checks the three pointers are in the rendered prompt.
- [ ] `PromptVersion` moves on its own; `TestPromptVersion_*` green without editing the test. `ExcerptVersion` does
  not move.
- [ ] If open question 4 is accepted: a server or intent finding lowered for disclosure carries
  `[disclosed: one step lower]` in its `Why`, as the other downgrades already do; a finding not lowered carries
  nothing new (`TestDisclosedLowering_IsAnnotated`, both directions).
- [ ] `go test -count=1 ./baselines/cmd/judgefold/` green; goldens regenerated only if they really move, and the diff is
  read line by line.
- [ ] `make verify` green, read from its own exit code, not through a pipe.

Measurement (live, gpt-4.1-mini, `samples: 3`, corpus `c314e4d9`). Main's reading is the full-corpus run of 2026-11-04
(`v0.33.1-3-g5a18a6db`). The branch reading is on the 802 server trees and the 3,370 skill trees the result pass asks.
The lines below were set before the run. If recall clears and benign does not, the proposal goes to `rejected/` with
its readings. Raising a line afterwards is not an option.

- [ ] Server, malicious: of the **14** servers whose majority category was `other`, at least **8** now escalate at high.
  Cisco static + judge no lower than 98 (102 minus the rerun band P-100 saw).
- [ ] Server, benign (623 asked): at most **3** benign servers escalate at high through a new row. Escalating `LLM-010`
  at high in all **60 → at most 66** (the line P-114 used).
- [ ] Result, malicious: of the **9** result-pass misses, at least **4** are now caught. Malicious skills flagged overall
  no lower than main's minus 3.
- [ ] Result, benign (2,894 asked): at most **6** benign skills escalate at high through `covert-transmission`, and at
  most **2** of them in ClawHub's fresh 216 (where P-068's first wording went from 6 to 26). Benign skills flagged
  overall (static + judge) up by at most 8.
- [ ] Each new benign escalation is listed with its category and the model's sentence, so the reading can be checked
  by eye, not just counted.
- [ ] Result directories under `baselines/results/aguard/2026-11-NN-llm-gpt-4.1-mini-p115-*`, with what the branch run
  did and did not ask written into the directory (open question 5). Raw archive goes on the next release, together with
  P-114's.

Docs:

- [ ] `docs/llm-judge.md` and `docs/llm-judge.zh-CN.md` (the pair): the category table gains the three rows, and the
  server row no longer reads "the intent table".
- [ ] `.claude/rules/judge.md`: one paragraph on what not to change. Keep the catch-alls' pointers (P-066's lesson). Do
  not merge the server table back into the intent table. Do not widen `covert-transmission` to "any message the task did
  not ask for", because that is `unrequested-artifact`, which is medium by design.

## Out of scope

- **The intent, injection, capability, explain, collusion and MCP config tables.** The review package shows their
  prompts byte-identical (the reverse assertion above).
- **An agent-memory row or clause** (open question 1). If declined, it goes to `ROADMAP.md` with the 1-against-214
  reading.
- **The self-registering MCP config** (`conn-self-register-mcp`): a config write is the injection and intent passes'
  `persistence` ground, and this proposal does not touch those.
- **The three SkillHarm sidecar and stamp misses.** They are unrequested artifacts and stay medium.
- **`severityFor`'s disclosure step itself** (what it lowers and when): only, if accepted, the annotation.
- **The excerpt** (P-114, rejected), the vote count, the threshold, triage, TypeScript servers (P-116), the static rules
  (no `rulesEpoch` change).

## Must not claim

- The recall gains come from sets that have now been read for this proposal: Cisco's evaluation servers (the 14 are all
  Cisco), and on the result side seeded and synthetic sources (`sg`, `sc`, `msb`, `si`). Do not quote them as an
  in-the-wild or held-out rate.
- Not "the judge now detects denial of service" or "detects covert exfiltration". The tool now weighs at high what the
  model already described. A fork bomb outside the excerpt, or an upload the model files under another category, is
  exactly where it was.
- Not "unrequested artifacts are now high". They are not, by design.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | Server table gains `resource-exhaustion` and `result-tampering`; result table gains `covert-transmission`; the catch-alls point away; the tests above | `judge: the server and result tables name resource exhaustion, result tampering and covert transmission (P-115)` |
| 2 | (If open question 4 is accepted) the disclosure step is annotated in `Why` | `judge: a finding lowered for disclosure says so (P-115)` |
| 3 | Docs pair and `.claude/rules/judge.md` | `docs: three new judge category rows (P-115)` |
| 4 | Branch run, result directories, schema-test counts, readings into this file | `baselines: P-115 on the server and result passes (P-115)` |
| 5 | The "Done" section and `git mv` to `complete/`, or to `rejected/` if a benign line fails | `proposals: P-115 done (P-115)` |

## Open questions

All asked at once. Each has a recommended answer.

1. **Agent-memory clause: in or out?** The draft proposed adding writes to `CLAUDE.md`/`MEMORY.md`/`AGENTS.md`/`SOUL.md`
   to `persistence`. The data: it would recover 1 miss, the injection table has no `persistence` row to extend, and 214
   benign skills name those files. Recommended: **out**, and record it in `ROADMAP.md`. If it is ever done, it needs its
   own measurement on the self-improving skills.
2. **The `covert-transmission` boundary.** Recommended wording: *the user's data, conversation, files or credentials
   sent, copied or shared to a recipient the user's task never named (a URL, webhook, telemetry or registry endpoint, an
   extra mail recipient, an access grant), which the user cannot see happened; NOT sending the result where the user
   asked, or where the skill's description says it sends it*. The `NOT` clause is what keeps a Slack notifier
   medium-or-unflagged. Taking it out moves more malicious samples but exposes every notifier skill.
3. **Server row wording, and does the disclosure step apply?** Recommended:
   - `resource-exhaustion` = *a tool call starts unbounded processes, threads, memory, disk, file descriptors or
     recursion (a fork bomb, a decompression bomb, a loop that allocates without end); NOT a long-running server loop, a
     fixed-size pool or a bounded retry*;
   - `result-tampering` = *a tool returns entries, links, products or redirects the caller did not ask for and cannot
     tell apart from a real result; NOT ranking, filtering, pagination or an error message*.
   
   Both get the ordinary server disclosure step: a load-testing server that says it exhausts resources weighs medium,
   like every other disclosed row.
4. **Ride the disclosure annotation along?** One line in `Why` (`[disclosed: one step lower]`). It changes report text
   only, never a severity. Recommended: **yes**, as its own commit, so it can be dropped without touching the tables.
5. **Measurement method and cost.** Only the server and result prompts change, so every other pass's request is
   byte-identical to main's.
   - **(A), recommended:** a measurement-only build, a local patch kept in `agent-guard-work/` and never committed, that
     asks only the server and result passes. The branch verdict is composed from main's other votes plus the branch's
     `LLM-010`/`LLM-011`. Est. **US$15–20**. It also keeps rerun noise from passes that did not change out of the reading,
     and the result directory says so.
   - **(B):** the plain branch binary on the same trees, every pass rerun. Est. **US$40**, with the extra noise.
6. **Acceptance lines**, as written in Done criteria. Recommended: **as written**. The benign side decides. Attribution is
   by the new rows' names, so rerun noise in the old categories does not count against them.
