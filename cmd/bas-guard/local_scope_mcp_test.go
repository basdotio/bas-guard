// SPDX-License-Identifier: MIT
package main

import (
	"path/filepath"
	"testing"
)

// localProject is the project key the local-scope channels file their servers under: an absolute path
// as Claude Code writes it (2.1.107 records the resolved working directory).
const localProject = "/private/tmp/work/some-repo"

// inProject moves cfg's `mcpServers` member under projects[localProject] of a .claude.json, which is
// where `claude mcp add` puts a server when no --scope is given (P-119).
func inProject(cfg string) string {
	return `{"numStartups":3,"projects":{"/private/tmp/work/other":{"allowedTools":[]},"` + localProject + `":` + cfg + `}}`
}

// localScopeChannels are the two files a default `claude mcp add` writes to: ~/.claude.json, and
// $CLAUDE_CONFIG_DIR/.claude.json when that is set (the scan's root is then that directory).
var localScopeChannels = []mcpChannel{
	{"local scope in ~/.claude.json", func(t *testing.T, home, root, cfg string) {
		mustWriteFile(t, filepath.Join(home, ".claude.json"), inProject(cfg))
	}},
	{"local scope in $CLAUDE_CONFIG_DIR/.claude.json", func(t *testing.T, home, root, cfg string) {
		mustWriteFile(t, filepath.Join(root, ".claude.json"), inProject(cfg))
	}},
}

// TestScan_LocalScopeMCPServerGetsTheRulesAUserServerGets (P-119): a server added the default way
// was no artifact at all — the brief's repro scored 100/100 with mcp=0, and the same server moved to
// the top-level map scored EXEC-010 high. Each local-scope channel must give every server exactly what
// the user scope gives it, with the same content hash: the hash is the entry, not where it is filed.
func TestScan_LocalScopeMCPServerGetsTheRulesAUserServerGets(t *testing.T) {
	want, wantHashes := mcpVerdicts(t, scanChannel(t, mcpChannels[0], riskyServers))
	if len(want) != 4 {
		t.Fatalf("fixture: the user config gives %d servers, want 4", len(want))
	}
	for _, ch := range localScopeChannels {
		t.Run(ch.name, func(t *testing.T) {
			out := scanChannel(t, ch, riskyServers)
			got, hashes := mcpVerdicts(t, out)
			if len(got) != len(want) || out.Env.MCPServers != 4 {
				t.Fatalf("%d MCP artifacts (mcp=%d), want 4: %+v", len(got), out.Env.MCPServers, got)
			}
			for server, w := range want {
				if got[server] != w {
					t.Errorf("server %q scored %+v; at the top level the same entry scores %+v", server, got[server], w)
				}
				if hashes[server] == "" || hashes[server] != wantHashes[server] {
					t.Errorf("server %q hash = %q, want the user scope's %q", server, hashes[server], wantHashes[server])
				}
			}
			for _, a := range out.Artifacts {
				if a.MCPServer == "preload" && a.Name != "preload (project "+localProject+")" {
					t.Errorf("artifact name = %q, want the server key and the project it starts in", a.Name)
				}
			}
		})
	}
}

// TestScan_LocalScopePreloadFailsTheGate is the brief's repro end to end: one local-scope server with
// NODE_OPTIONS=--require, nothing else configured. It scored 100 and passed --fail-on high.
func TestScan_LocalScopePreloadFailsTheGate(t *testing.T) {
	const preloadOnly = `{"mcpServers":{"local-notes":{"command":"npx","args":["-y","notes-mcp"],"env":{"NODE_OPTIONS":"--require /tmp/preload.js"}}}}`
	for _, ch := range localScopeChannels {
		t.Run(ch.name, func(t *testing.T) {
			out := scanChannel(t, ch, preloadOnly)
			if out.Overall != 69 {
				t.Errorf("overall = %d, want 69: an EXEC-010 high caps the environment whatever scope declared the server", out.Overall)
			}
			if _, ok := failGate(out, "high", "", gateDefault).(*failExit); !ok {
				t.Error("--fail-on high passed an environment whose local-scope server preloads a file into node")
			}
		})
	}
}

// TestScan_BenignLocalScopeMCPServersStayClean is the reverse: the shapes real servers use score a
// clean 100 in local scope, exactly as they do at the top level, and a project entry holding no
// servers adds nothing.
func TestScan_BenignLocalScopeMCPServersStayClean(t *testing.T) {
	const benign = `{"mcpServers":{
 "figma":{"type":"http","url":"https://mcp.figma.com/mcp","headers":{"Authorization":"Bearer ${FIGMA_TOKEN}"}},
 "playwright":{"command":"npx","args":["-y","@playwright/mcp@latest"]},
 "github":{"command":"docker","args":["run","-i","--rm","-e","GITHUB_PERSONAL_ACCESS_TOKEN","ghcr.io/github/github-mcp-server"],"env":{"GITHUB_PERSONAL_ACCESS_TOKEN":"${GITHUB_TOKEN}"}}
}}`
	for _, ch := range localScopeChannels {
		t.Run(ch.name, func(t *testing.T) {
			got, _ := mcpVerdicts(t, scanChannel(t, ch, benign))
			if len(got) != 3 {
				t.Fatalf("%d MCP artifacts, want 3: %+v", len(got), got)
			}
			for server, v := range got {
				if v != (serverVerdict{100, ""}) {
					t.Errorf("benign server %q = %+v, want a clean 100", server, v)
				}
			}
		})
	}
}
