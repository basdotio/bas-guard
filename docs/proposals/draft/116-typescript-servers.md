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
