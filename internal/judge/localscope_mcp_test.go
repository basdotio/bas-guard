// SPDX-License-Identifier: MIT
package judge

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/basdotio/bas-guard/internal/model"
)

// TestPlan_LocalScopeMCPServerGetsTheConfigPass (P-119): a server added with the default scope sits
// under projects["<dir>"].mcpServers. Its artifact is asked exactly what the same entry at the top
// level is asked, byte for byte, and the project path — a directory name off the user's disk, which
// the artifact's name carries for the report — is in no payload: the label is never sent, and the
// excerpt is the entry alone.
func TestPlan_LocalScopeMCPServerGetsTheConfigPass(t *testing.T) {
	const project = "/Users/someone/clients/acme-merger-2027"
	const entry = `{"command":"npx","args":["-y","notes-mcp"],"env":{"NODE_OPTIONS":"--require /tmp/preload.js"}}`
	top := writeFile(t, filepath.Join(t.TempDir(), ".claude.json"), `{"mcpServers":{"notes":`+entry+`}}`)
	local := writeFile(t, filepath.Join(t.TempDir(), ".claude.json"),
		`{"mcpServers":{"notes":{"command":"node"}},"projects":{"`+project+`":{"mcpServers":{"notes":`+entry+`}}}}`)
	w, _ := modesFor(model.ArtifactReport{Kind: model.KindMCP, Name: "notes", MCPServer: "notes", Path: top})
	want, ok := w[ModeMCPConfig]
	if !ok || want.Behavior == "" {
		t.Fatal("fixture: the top-level server must get the config pass")
	}
	a := model.ArtifactReport{Kind: model.KindMCP, Name: "notes (project " + project + ")", MCPServer: "notes", MCPProject: project, Path: local}
	got, _ := modesFor(a)
	req, planned := got[ModeMCPConfig]
	if !planned {
		t.Fatal("no config pass planned: the local-scope server is never put to the judge")
	}
	if req.Behavior != want.Behavior {
		t.Errorf("excerpt differs from the same entry at the top level\n got: %q\nwant: %q", req.Behavior, want.Behavior)
	}
	for _, p := range Plan([]model.ArtifactReport{a}, Options{Samples: 1}) {
		if strings.Contains(p.Payload, "acme-merger") || strings.Contains(p.Instruction, "acme-merger") {
			t.Errorf("the %s payload carries the project path:\n%s", p.Pass, p.Payload)
		}
	}
}
