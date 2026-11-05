<!-- SPDX-License-Identifier: MIT -->
# 116 — A malicious MCP server written in TypeScript or JavaScript is a plain directory: the judge asks it nothing

- **Source**: the maintainer, 2026-11-04 ("yes" to the order: excerpt first, then the server categories, then TypeScript
  servers), after the full-corpus comparison of the same day (corpus `c314e4d9`, 5,272 samples); P-053 recorded
  TypeScript as the recogniser's second language ("TypeScript's `server.tool(` later")
- **Depends on**: P-114 and P-115 in practice, not in code (see Initial direction)
- **Branch**: `p/116-typescript-servers`

## Problem

`collect.LooksLikeServerSource` (P-053) recognises a server by a Python file that imports `mcp`/`fastmcp` and declares
a tool. A TypeScript or JavaScript server, which is how most npm-distributed MCP servers ship, falls through to
`KindDirectory`. The static rules read the whole tree, but the judge has no pass for a directory (`issues/023`,
direction C): no question, no call.

On the full-corpus run of 2026-11-04 (`v0.33.1-3-g5a18a6db`, gpt-4.1-mini, `samples: 3`), the trees that are
TypeScript/JavaScript MCP servers by content (`@modelcontextprotocol/sdk`, `McpServer(`) and were collected as
`directory`:

| | trees | flagged by BAS Guard (static only, the judge never asked) | flagged by cc-audit 3.23.9 |
|---|---:|---:|---:|
| malicious | 18 | 7 | — |
| … of which BAS Guard misses | 11 | — | 10 |
| benign | 234 | static flags only | — |

The 11 misses are **seven real malicious npm packages from DataDog's in-the-wild set** (environment-variable and
exchange-credential exfiltration, a self-propagating worm in two variants, a hidden `eval`, a wallet drain, a knowledge-graph
exfiltration bundle) and four synthetic TypeScript servers (arbitrary file write, cloud metadata probe, dynamic code
execution in a tool body, resource exhaustion). The seven are a large part of why the corpus's in-the-wild row reads 35
of 65 for BAS Guard with the judge against cc-audit's 42.

`check <ts-server> --llm --fail-on-llm` already exits 4 for these (P-038), so a gate configured that way is not silently
green. A plain `scan --llm`, and every report, reads them as judged when they were not.

## Initial direction

Teach `LooksLikeServerSource` the TypeScript/JavaScript shape. It needs both halves, like the Python one: an import of
`@modelcontextprotocol/sdk` (or a known framework such as `fastmcp` for TS), and a tool declaration (`server.tool(`,
`registerTool(`, `setRequestHandler(CallToolRequestSchema`). Teach `serverDeclared` the TS description position (the
string argument of `server.tool("name", "description", …)` and the `description` member of a tool object). The server
pass and its table then apply unchanged. Bundled single-file output (`dist/index.js`, `bundle.js`) needs a decision:
recognise it, or disclose it as unread.

**The benign side is the risk.** The 234 benign TS/JS servers would start receiving `LLM-010`. At today's Python rate (60
of 621 benign servers escalate, 9.7%, 104 of the 142 escalating votes on `credential-read`), that is about 20 new benign
flags against at most 11 recovered. Hence the ordering: P-114 and P-115 change what the server pass sees and how it
weighs it, and this proposal inherits both, so it is measured after them; and the server pass's benign `credential-read`
(P-062/P-098's territory) is read again on the TS population before this lands. Measure on the 18 + 234, and on P-100's 227
held-out TypeScript/JavaScript servers, which no measurement has touched.

**Not this**: SkillFortifyBench's four `mcp.json` trees (no leading dot) also arrive as directories. Claude Code does not
load a file of that name, so it is a corpus placement question, not a collection gap; cc-audit flags none of them either.
OpenClaw's `.claw/skill.yaml` skills (11 more misses) are a scope decision for the maintainer, not part of this proposal.

## What the design read added to the problem

Re-read on the same run (`agent-guard-work/runs/2026-11-04-judge-full-s3`, folded verdicts), with a recogniser written
for this read (`agent-guard-work/p116/find-ts-servers.py`: a `.ts`/`.js`/`.mjs`/`.cjs`/`.mts`/`.cts` file that imports
`@modelcontextprotocol/sdk` or `fastmcp`, and a file that builds a server or declares a tool, in a tree collected as
`directory`). It reads text only and never runs anything.

- **The population is 236 trees, not 252**: 17 malicious, 219 benign. The draft's count used a looser match.
- **Of the 17 malicious, 7 are caught by the static rules already and 10 are not.** The draft's eleventh miss is the
  draft's eighteenth tree, which this recogniser does not count as a TS server.
- **All 10 misses have their server code where the rules and the judge read.** Seven trees keep a server file under
  `dist/`, four of the misses only there (`knowledge-graph-workflow-exfil`, `redhat-kessel-mcp-worm`,
  `squawk-mcp-router-worm`, `todo-wallet-exfil`). `dist/` is left out of the HASH (`collect.ExcludeFromHash`, frozen) but
  READ by the rules and the judge (`collect.ExcludeFromScan` is the smaller list, by design, ROADMAP "Evasions"), and the
  recogniser walks the scan list. *The first version of this read used the hash list by mistake and said the four were
  unreadable; open question 1 was asked on that wrong premise (see the correction under it).*
- **Checked with the branch binary, not only the script**: `check` on every tree main collected as `directory` (301)
  reads 233 as `server` — all 17 malicious, 216 benign. Four benign trees the script counts keep the import and the
  tool in different files; one benign tree the script missed is recognised. `llm preview` on the 233: every one has a
  non-empty declared side. Two excerpts to read the results against: `iflow`'s 6,000 bytes fill with `.eslintrc.cjs`,
  `.github/` workflows and `bin/` before `src/` (the walker's order, the same for Python), and `kessel`'s spend part of
  the budget on `.d.ts` files. Neither is changed here (excerpt caps and order are out of scope).
- **Four declaration forms cover every readable tree but three benign ones**: `server.tool("name", …)` (6 malicious, 63
  benign), `registerTool(` (73 benign), the low-level `setRequestHandler(CallToolRequestSchema` with a
  `ListToolsRequestSchema` handler returning `[{ name, description, inputSchema }]` (5 malicious, 84 benign), and
  TypeScript fastmcp's `addTool(` (`iflow`, one benign). A tool's description is the second string argument of
  `server.tool`, the `description` member of `registerTool`'s second argument, and the `description` member of each tool
  object in the other two.
- **No server file in the 236, `dist/` included, is a minified bundle** (average line length over 500 bytes: none), so
  the draft's bundled-output question needs no answer here.
- **The benign side starts high already**: 61 of the 219 benign TS servers are flagged by the static rules on main (28%).
  The judge's flags land on top of that.
- **P-100's 227 held-out TypeScript/JavaScript servers are the same population**: 203 of the 219 benign here are in that
  re-harvest. There is no second, untouched TS set in the corpus. The real held-out set (`heldout-all`) stays untouched.
- **What the server pass already handles for TypeScript**: `behaviorExcerpt` reads `.ts`/`.js`/`.mjs`/`.cjs`; the
  P-062/P-098 credential checks (`CredentialGoesHome`, `CredentialOverreach`, `CredentialSentElsewhere`) parse `.js`/`.ts`
  as C-style and know `process.env`. What is Python-only is the recogniser (`LooksLikeServerSource`) and the declared side
  (`serverDeclared`). The static rules treat `server` and `directory` alike (`detect.go`), so the static reading does not
  move, and the benchmark adapter routes by the same recogniser, so a recognised TS tree goes to `check --llm` with no
  adapter change.
- **Where this reaches a user**: `check <dir>` on a server's source (a CI job on an MCP server repository, a downloaded
  package). A `scan` collects MCP servers from configuration, not from source, and is unchanged.
- **Cost of the reading**: on the 802 Python server trees the server pass cost about US$3.7 at `samples: 3`; 236 trees is
  about US$1–2.

## Done criteria

Code:

- [ ] `LooksLikeServerSource` recognises a TS/JS server: within the same probe bounds, a `.ts`/`.mts`/`.cts`/`.js`/`.mjs`/`.cjs`
  file (not `.d.ts`) that imports `@modelcontextprotocol/sdk` or `fastmcp` AND, in the same file, builds a server
  (`new McpServer(`, `new Server(`, `new FastMCP(`) or declares a tool (the four forms). Both halves, like the Python one:
  a client (`new Client(`) or an SDK type import is not a server. Table test with a fixture per form, and the reverse
  cases (client-only, types-only, the import in a comment or string, a `.d.ts`).
- [ ] `serverDeclared` reads the four forms' names and descriptions from TS/JS files. A tool whose description it cannot
  read (a variable, a template with `${…}`) is listed by name, like a Python tool without a docstring.
- [ ] Reverse assertion: on Python server trees the declared text and the behaviour excerpt are byte-identical to
  `main`'s. Offline, by `llm preview --json` with the two binaries over the 802 Python server trees (P-114's method):
  zero payload changes.
- [ ] `ExcerptVersion` 9 → 10 (the declared side's rendering changed), `excerpt_version_test.go` updated in the same
  commit; `PromptVersion` does not move (no prompt or table change).
- [ ] `check <ts-server> --llm --fail-on-llm` no longer exits 4 for being unasked (P-038); the zero-dial table is
  unchanged (`check` is already a judge path).
- [ ] `go test -count=1 ./baselines/cmd/judgefold/` green; `make verify` green, read from its own exit code.

Measurement (live, gpt-4.1-mini, `samples: 3`, corpus `c314e4d9`), on the 236 trees. Main is the full-corpus run of
2026-11-04 refolded on them (static only: the judge asked them nothing). The branch is the plain branch binary: for these
trees the only judge question it adds is the server pass. Lines set before the run, not raised after it:

- [ ] Malicious: of the **10** misses, at least **7** caught (open question 5). The 7 caught on main stay caught.
- [ ] Benign (219): at most **20** escalate `LLM-010` at high (9%, the rate the Python servers show: 53–61 of 623).
  Benign flagged overall (static + judge) **61 → at most 81**.
- [ ] Each new benign escalation listed with its category and the model's sentence.
- [ ] Result directories under `baselines/results/aguard/2026-11-NN-llm-gpt-4.1-mini-p116-*`; raw archive on the next
  release with P-114's and P-115's.

Docs:

- [ ] `docs/llm-judge.md` / `.zh-CN.md`: `LLM-010`'s row says TypeScript/JavaScript servers are asked and how they are
  recognised. `docs/architecture.md` pair if it names the recogniser.
- [ ] `.claude/rules/judge.md`: the recogniser needs both halves in one file; do not widen it to "any file that mentions
  the SDK"; it walks the scan list, not the hash list.

## Out of scope

- **What the scan or the hash leaves out** (`node_modules/`; `dist/` in the hash): unchanged.
- **The server pass's prompt and tables** (P-115 just changed them), the excerpt caps, the credential checks.
- **SkillFortifyBench's `mcp.json` trees and OpenClaw's `.claw/skill.yaml` skills**, as the draft says.
- **The static rules** (no `rulesEpoch` change).

## Must not claim

- Not "BAS Guard now judges npm MCP packages" in general: it judges a TS/JS server whose import and tool declaration
  sit in one readable file; a minified bundle, or a server split across files that way, is still a directory.
- The 4 synthetic servers and the benign 219 have been read for this proposal; do not quote either as a held-out rate.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | Recogniser learns the TS/JS shape, with the table test | `collect: a TypeScript or JavaScript MCP server is server source (P-116)` |
| 2 | Declared side reads the four TS forms; excerpt version 10 | `judge: the server pass reads a TypeScript tool's name and description (P-116)` |
| 3 | Docs pair and `.claude/rules/judge.md` | `docs: the server pass asks TypeScript and JavaScript servers (P-116)` |
| 4 | Python reverse check, branch run, result directories, schema-test counts | `baselines: P-116 on the TypeScript and JavaScript servers (P-116)` |
| 5 | The "Done" section and `git mv` to `complete/` or `rejected/` | `proposals: P-116 done (P-116)` |

## Open questions

All asked at once. Each has a recommended answer.

1. **`dist/` in or out?** Four of the ten misses (all in-the-wild) live only there. Reading it means the hash reads it
   too (a scan that reads what the hash skips lets an approved package swap its `dist/`), so every tree with a
   `dist/` rekeys: reputation entries and users' approvals for such plugins and skills, and the static rules start
   running over build output everywhere, not only on servers. Recommended: **out of P-116**, as its own proposal with its
   own measurement (benign static over all surfaces, the rekey count).
   **Decided (2026-11-05)**: out, as its own proposal. **Corrected the same day**: the premise was wrong — `dist/` is
   read by the rules and the judge already; only the hash leaves it out, which ROADMAP records as intended. P-116
   reaches all ten misses, and there is no separate `dist/` proposal to open.
2. **The recogniser's shape.** Recommended: both halves in one file, as above (`new McpServer(`/`new Server(`/
   `new FastMCP(` or one of the four tool forms, plus the SDK or fastmcp import), `.d.ts` excluded, the same probe
   bounds as Python.
   **Decided (2026-11-05)**: as recommended.
3. **Acceptance lines.** Recommended: as written — at least 4 of the 6 reachable misses; benign at most 20 escalating
   and at most 81 flagged overall. If the benign line fails, the proposal goes to `rejected/` with its readings.
   **Decided (2026-11-05)**: as written.
4. **Measurement.** Recommended: plain branch binary on the 236 trees (about US$1–2), plus the free `llm preview`
   two-binary check on the 802 Python server trees.
   **Decided (2026-11-05)**: as recommended, about US$1–2 approved.
5. **(Asked after the correction to 1, before the run.) The recall line, now that ten misses are reachable, not six.**
   **Decided (2026-11-05)**: at least 7 of 10, the decided line's proportion (4 of 6) on the new denominator.
