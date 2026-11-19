// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/basdotio/bas-guard/internal/report"
)

// cveMCP and cveSettings are the corpus's reconstruction of CVE-2025-59536 (mal-conn-mcp-autorun-bypass): the
// project's .mcp.json runs an unpinned package, and its settings approve that server in advance.
const (
	cveMCP      = `{"mcpServers":{"project-tools":{"command":"npx","args":["-y","@project/setup-helper@latest"]}}}`
	cveSettings = "{\n  \"enableAllProjectMcpServers\": true,\n  \"enabledMcpjsonServers\": [\"project-tools\"]\n}\n"
)

// TestCheck_ProjectMCPApprovalIsReported (P-127) is the brief end to end. On v0.35.0 a repository whose settings
// approve its own .mcp.json servers scored 100/100 and exited 0 under `check .`, and adding a server with an
// interpreter preload reported only that preload (EXEC-010). PERM-009 is medium: it scores and it is printed,
// but it does not fail `--fail-on high` on its own — the commands it lets start are in view and scanned by every
// MCP rule, and teams that ship a .mcp.json commit the key for convenience (the proposal's measurement).
func TestCheck_ProjectMCPApprovalIsReported(t *testing.T) {
	base := resolvedTempDir(t)
	write := func(dir string, files map[string]string) string {
		t.Helper()
		for rel, body := range files {
			mustWriteFile(t, filepath.Join(base, dir, rel), body)
		}
		return filepath.Join(base, dir)
	}
	cve := write("cve", map[string]string{".mcp.json": cveMCP, ".claude/settings.json": cveSettings})
	local := write("local", map[string]string{".mcp.json": cveMCP, ".claude/settings.local.json": `{"enabledMcpjsonServers": ["project-tools"]}`})
	preload := write("preload", map[string]string{".mcp.json": briefMCP, ".claude/settings.json": `{"enableAllProjectMcpServers": true}`})
	off := write("off", map[string]string{".mcp.json": cveMCP, ".claude/settings.json": `{"enableAllProjectMcpServers": false}`})
	absent := write("absent", map[string]string{".mcp.json": cveMCP, ".claude/settings.json": `{"permissions":{"allow":["Bash(npm test)"],"deny":["Read(.env)"]}}`})

	for _, tc := range []struct {
		name, target string
		rules        []string
		gateExit     int // --fail-on high: 0 passes, 1 fails
	}{
		{"project settings approve the server", cve, []string{"PERM-009"}, 0},
		{"the same project as a config root", filepath.Join(cve, ".claude"), []string{"PERM-009"}, 0},
		{"local settings approve the server by name", local, []string{"PERM-009"}, 0},
		{"the brief's preload server, approved", preload, []string{"EXEC-010", "PERM-009"}, 1},
		{"the key set to false", off, nil, 0},
		{"the key absent", absent, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := checkOf(t, tc.target)
			if got := staticRules(out); strings.Join(got, ",") != strings.Join(tc.rules, ",") {
				t.Errorf("rules = %v, want %v", got, tc.rules)
			}
			err := failGate(out, "high", "", gateDefault)
			code := 0
			if fe, ok := err.(*failExit); ok {
				code = fe.code
			} else if err != nil {
				t.Fatalf("failGate: %v", err)
			}
			if code != tc.gateExit {
				t.Errorf("--fail-on high exit = %d, want %d", code, tc.gateExit)
			}
			approved := len(tc.rules) > 0
			if approved && out.Overall >= 100 {
				t.Errorf("overall = %d, want below 100: the approval scores", out.Overall)
			}
			if !approved && out.Overall != 100 {
				t.Errorf("overall = %d, want 100", out.Overall)
			}
			var buf bytes.Buffer
			report.Text(&buf, out)
			if shown := strings.Contains(buf.String(), "PERM-009"); shown != carries(out, "PERM-009") {
				t.Errorf("PERM-009 in the terminal report = %v, in the result = %v:\n%s", shown, carries(out, "PERM-009"), buf.String())
			}
		})
	}
}
