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
