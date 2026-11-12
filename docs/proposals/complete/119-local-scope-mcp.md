<!-- SPDX-License-Identifier: MIT -->
# 119 — An MCP server added with `claude mcp add`'s default scope is never collected, and the environment scores 100

- **Source**: new finding, 2026-11-12, while checking the advice of a self-check list against `origin/main` (`aba37e8`)
  with Claude Code 2.1.107 on macOS; handed over with the brief "decide in the proposal" for the four questions below
- **Depends on**: P-021 and P-029 (an MCP entry is found by its key and its layout, never by the artifact name), P-009
  (the content hash of an MCP entry)
- **Branch**: `p/119-local-scope-mcp`

## Problem

`claude mcp add` has three scopes, and its own help says the default is `local`. Measured on 2.1.107 with a fresh
`HOME`, from inside `<tmp>/repo`:

| command | where the server is written |
|---|---|
| `claude mcp add demo-srv -- echo hi` | `~/.claude.json` → `projects["/private/tmp/…/repo"].mcpServers` |
| the same with `CLAUDE_CONFIG_DIR=<cfg>` | `<cfg>/.claude.json` → `projects["/private/tmp/…/repo"].mcpServers` |
| `claude mcp add -s user demo-user -- echo hi` | `~/.claude.json` → `mcpServers` (top level) |

The collector read only the top-level map of `.claude.json` (`collectMCP` and `RootMCPConfigs`, both through
`mcpServersFrom`). A server added the default way was therefore no artifact at all: no unit, no rule, no judge
question, not counted. The brief's repro, a fake `HOME` whose `.claude.json` is

```json
{"projects":{"/tmp/some-repo":{"mcpServers":{"local-notes":{"command":"npx","args":["-y","notes-mcp"],
 "env":{"NODE_OPTIONS":"--require /tmp/preload.js"}}}}}}
```

scanned with `bas-guard scan --root $HOME/.claude --inbox off`, gave **100/100, `mcp=0`, exit 0 under `--fail-on high`**.
Moving the same entry to the top-level `mcpServers` gives `EXEC-010` high, 69/100, exit 1. Claude Code starts the
local-scope server in every session in that directory, so the report said "looks safe" about a server that preloads an
arbitrary file into node on every start. Of the three scopes, the one users get without asking was the one never read.

## Initial direction

Read `projects[*].mcpServers` of every `.claude.json` the scan already reads, as artifacts of their own, and find each
entry through its key and its project in detect, the content hash and the judge, the way P-021/P-029 find a plugin's.

## Decisions

The brief asked for these four to be decided here. Each is open to the maintainer in review; nothing below is hard
to reverse.

1. **Which projects.** Every project's servers, whether or not its directory exists on this machine. Claude Code starts
   them whenever a session runs in that directory; a clone can bring a deleted directory back; and checking would mean
   stat-ing the user's directories outside the root, which the collector does nowhere else. A project keyed `""` is
   skipped: no session runs in it, and `MCPProject: ""` already means the top-level map.
2. **Name.** `<key> (project <dir>)`, the directory exactly as Claude Code wrote the key. The suffix keeps two projects'
   servers, and a project's server and a user-scope one under the same key, apart in a report; the full directory is
   what a reader needs to act (`claude mcp remove` runs from there). What reaches where:
   - **reports** print it as they print a plugin key in ` (plugin <key>)` and the encoded project directory in a memory
     artifact's name: names are outside `Redact` (invariant #3, P-085), and the human renderers pass them through
     `Sanitize` (invariant #7). JSON and SARIF carry the name as they carry those.
   - **the judge** never sends it: the artifact label is display-only (`Request.Artifact` is not sent), and the MCP
     excerpt is the entry alone, its unit named by the file's base name. `TestPlan_LocalScopeMCPServerGetsTheConfigPass`
     plants a distinctive directory name and asserts it is in no planned payload.
   - **lookups** never use the name: `MCPServer` holds the key and the new `MCPProject` the directory, and `mcpServerMap`
     reads `projects[MCPProject].mcpServers` for the rules, the content hash, `MCPServerKey`'s `""` check and the judge.
3. **Identity.** Unchanged definition: the content hash of an MCP entry is the entry alone (§8), with no name, path or
   directory in it. The same entry in local scope, in user scope, or in two projects is one identity — a reputation
   entry or an approval covers it wherever it is filed, and changing a byte of it re-keys it. The golden constants do not
   move. The gate's `SessionStart` scans the environment root, so a local-scope server with a blocking finding now
   appears there as a top-level one does, and `bas-guard approve` of that root stores its content hash.
4. **`CLAUDE_CONFIG_DIR/.claude.json`.** Read, both scopes. It was already read for its top-level servers through
   `RootMCPConfigs` (the root's own `.claude.json`); the same reader now covers its `projects`. When the root's
   `.claude.json` is the very file home's is, it is still read once.

Smaller choices: members are matched by their exact key (`projects`, `mcpServers`), as detect's `mcpServerMap` matches
them — a struct decode would match `Projects` or `MCPSERVERS` case-insensitively and collect servers detect then cannot
find. A `projects` member that is not an object, or a project whose `mcpServers` is not one, becomes a `PARSE-000`
artifact (`projects`, `mcpServers (project <dir>)`), and the file's other servers are still read. A project `.mcp.json`
has no `projects` member Claude Code reads, so none is read there.

## Done criteria

- [x] `TestCollect_LocalScopeMCPServers` (`internal/collect/localscope_test.go`), one row per layout: one project; the
  `CLAUDE_CONFIG_DIR` file; one key in two projects and at the top (four artifacts); projects with no servers, an empty
  map or `null` (none); a project keyed `""` (none); a `projects` member that is not an object (`PARSE-000`, the top level
  still read); one project whose servers are not an object (`PARSE-000`, the other project read); `projects` in a
  `.mcp.json` (none). `Env.MCPServers` counts what was collected. `TestCollect_LocalScopeMCPServersInOrder` pins the order.
- [x] `TestDetect_LocalScopeMCPServerIsFoundInItsProject` (`internal/detect/localscope_mcp_test.go`): for P-021's three
  servers and the `""` key, the local-scope artifact gets byte-identical findings and the same content hash as the same
  entry at the top level, while benign decoys sit under the same keys at the top level and in another project; the
  judge's `MCPConfigLines` is not empty.
- [x] **Reverse**, `TestDetect_TopLevelServerIsNotReadFromAProject`: the top-level artifact keeps its `EXEC-010` when a
  project holds a benign twin under the same key, the twin is clean, and the two hashes differ.
- [x] `TestPlan_LocalScopeMCPServerGetsTheConfigPass` (`internal/judge`): the config pass is planned with the top-level
  twin's excerpt, and the project directory is in no payload.
- [x] `TestScan_LocalScopeMCPServerGetsTheRulesAUserServerGets` (`cmd/bas-guard/local_scope_mcp_test.go`), through
  `scanEnv`, in `~/.claude.json` and in `$CLAUDE_CONFIG_DIR/.claude.json`: each of the four P-021 servers scores what it
  scores in user scope, with the user scope's hash; `TestScan_LocalScopePreloadFailsTheGate`: the brief's repro scores 69
  and fails `--fail-on high`; **reverse**, `TestScan_BenignLocalScopeMCPServersStayClean`: three real server shapes stay a
  clean 100.
- [x] Every test above failed on `main` before the change (collect: no artifact; detect: `null` findings and the
  decoy's hash, and the twin carried the top-level server's `EXEC-010`; judge: the excerpt was the decoy's
  `command=node`; scan: 0 MCP artifacts, overall 100).
- [x] `rulesEpoch` 9 → 10 (an input now yields findings it did not), `make docs`; `make verify` green; `go.mod` line 2 is
  still `go 1.23.5`.

## Out of scope

- `disabledMcpServers`, `enabledMcpjsonServers` and the other per-project switches: like the top level, a configured
  server is audited whether or not it is switched on.
- `check <file>` on a `.claude.json` and `check <dir>` reading a project's own configuration: P-120.
- Managed MCP configuration (`managed-mcp.json`), plugin manifests' inline `mcpServers`: unchanged.
- The hash definition, reputation data, the gate, `clean`, the judge's code and excerpt: untouched (`ExcerptVersion` does
  not move — no excerpt of an existing artifact changes).

## Must not claim

- Not "every MCP server Claude Code can start is now audited": managed configuration and plugin manifests' inline
  servers are still not collected (spec §4 says which).
- Not "the project directory is never written anywhere": it is in the artifact name, in every report format, as plugin
  keys and memory directories already are. It is kept out of what the judge sends.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | Collect local-scope servers from every `.claude.json` read, find them through `MCPProject`; tests written first | `collect: MCP servers added in local scope are collected and found in their project (P-119)` |
| 2 | README pair, architecture pair, spec §4, `.claude/rules/pipeline.md` and `detect.md` | `docs: both scopes of .claude.json are read (P-119)` |
| 3 | The proposal | `proposals: P-119 done, local-scope MCP servers are collected (P-119)` |

## Open questions

None left open by the brief; see Decisions, which the maintainer can overturn in review.

## Done

```
Merged: not yet — PR #145 (find the sha with git log --grep P-119 after the merge)
Released: (fill in after the release)
Evidence: TestScan_LocalScopePreloadFailsTheGate (cmd/bas-guard/local_scope_mcp_test.go); the brief's repro,
  `scan --root $HOME/.claude --inbox off --fail-on high`: 100/100, mcp=0, exit 0 → 69/100, EXEC-010, exit 1;
  reverse: TestDetect_TopLevelServerIsNotReadFromAProject, TestScan_BenignLocalScopeMCPServersStayClean
```
