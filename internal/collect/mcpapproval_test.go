// SPDX-License-Identifier: MIT
package collect

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/basdotio/bas-guard/internal/model"
)

// approvalMCP declares two servers, so a row can show one approved and the other not.
const approvalMCP = `{"mcpServers":{"notes":{"command":"npx","args":["-y","notes-mcp"]},"other":{"command":"uvx","args":["other-mcp"]}}}`

// approvalView lists every MCP server of a result as "name", followed by "|<rule> <severity> <file>:<line> (<scope>)"
// for each piece of evidence of each finding, files relative to base, sorted.
func approvalView(res Result, base string) []string {
	var out []string
	for _, a := range res.Artifacts {
		if a.Kind != model.KindMCP {
			continue
		}
		var row strings.Builder
		row.WriteString(a.Name)
		for _, f := range a.Findings {
			for _, ev := range f.Evidence {
				rel, err := filepath.Rel(AnchorRoot(base), AnchorRoot(ev.File))
				if err != nil {
					rel = ev.File
				}
				fmt.Fprintf(&row, "|%s %s %s:%d (%s)", f.RuleID, f.Severity, rel, ev.Line, ev.Scope)
			}
		}
		out = append(out, row.String())
	}
	sort.Strings(out)
	return out
}

// TestCollect_ProjectMCPApprovals (P-127): a project's settings can approve the servers its .mcp.json declares —
// enableAllProjectMcpServers for all of them, enabledMcpjsonServers by name — and Claude Code then starts them
// once the folder is trusted without the per-server prompt that shows the user each command. v0.35.0 read the
// two files and said nothing: the corpus's reconstruction of CVE-2025-59536 scored 100/100. Each approved server
// now carries PERM-009, citing the settings line that approves it.
//
// Every row runs twice and must give the same answer: as `check <repo>` (the configuration a directory declares,
// P-120) and as `scan --root <repo>/.claude` (the project's config root, with its .mcp.json beside it). The
// precedence is Claude Code's settings reference: a disabledMcpjsonServers entry in any file rejects the server;
// enabledMcpjsonServers merges across files; for enableAllProjectMcpServers the highest-precedence file that
// sets it decides, and settings.local.json is above settings.json.
func TestCollect_ProjectMCPApprovals(t *testing.T) {
	const (
		project = "repo/.claude/settings.json"
		local   = "repo/.claude/settings.local.json"
	)
	quiet := []string{"notes", "other"}
	cases := []struct {
		name  string
		files map[string]string // beside repo/.mcp.json, relative to the fixture directory
		want  []string
	}{
		{"project settings approve every server",
			map[string]string{project: "{\n  \"enableAllProjectMcpServers\": true\n}\n"},
			[]string{"notes|PERM-009 medium " + project + ":2 (base)", "other|PERM-009 medium " + project + ":2 (base)"}},
		{"local settings approve every server",
			map[string]string{local: "{\n  \"permissions\": {\"allow\": [\"Bash(npm test)\"]},\n  \"enableAllProjectMcpServers\": true\n}\n"},
			[]string{"notes|PERM-009 medium " + local + ":3 (local)", "other|PERM-009 medium " + local + ":3 (local)"}},
		{"project settings approve one server by name",
			map[string]string{project: "{\n  \"enabledMcpjsonServers\": [\"notes\"]\n}\n"},
			[]string{"notes|PERM-009 medium " + project + ":2 (base)", "other"}},
		{"local settings approve one server by name, as Claude Code writes it when the user clicks approve",
			map[string]string{local: "{\"enabledMcpjsonServers\": [\"other\"]}"},
			[]string{"notes", "other|PERM-009 medium " + local + ":1 (local)"}},
		{"both keys, the CVE-2025-59536 shape, cite both lines",
			map[string]string{project: "{\n  \"enableAllProjectMcpServers\": true,\n  \"enabledMcpjsonServers\": [\"notes\"]\n}\n"},
			[]string{"notes|PERM-009 medium " + project + ":2 (base)|PERM-009 medium " + project + ":3 (base)", "other|PERM-009 medium " + project + ":2 (base)"}},
		{"a name listed in both files is cited in both",
			map[string]string{project: `{"enabledMcpjsonServers": ["notes"]}`, local: `{"enabledMcpjsonServers": ["notes"]}`},
			[]string{"notes|PERM-009 medium " + project + ":1 (base)|PERM-009 medium " + local + ":1 (local)", "other"}},
		{"local true over project false",
			map[string]string{project: `{"enableAllProjectMcpServers": false}`, local: `{"enableAllProjectMcpServers": true}`},
			[]string{"notes|PERM-009 medium " + local + ":1 (local)", "other|PERM-009 medium " + local + ":1 (local)"}},
		{"of two values for the key in one file the last decides, as JSON.parse reads it",
			map[string]string{project: "{\n  \"enableAllProjectMcpServers\": false,\n  \"enableAllProjectMcpServers\": true\n}\n"},
			[]string{"notes|PERM-009 medium " + project + ":3 (base)", "other|PERM-009 medium " + project + ":3 (base)"}},

		// Quiet rows: nothing approves the server.
		{"the key set to false", map[string]string{project: `{"enableAllProjectMcpServers": false}`}, quiet},
		{"the key absent", map[string]string{project: `{"permissions":{"allow":["Bash(npm test)"]}}`}, quiet},
		{"no settings at all", map[string]string{}, quiet},
		{"an empty list", map[string]string{project: `{"enabledMcpjsonServers": []}`}, quiet},
		{"a list naming a server the project does not declare", map[string]string{project: `{"enabledMcpjsonServers": ["notes-mcp"]}`}, quiet},
		{"local false over project true: a false in the higher file wins in a trusted folder",
			map[string]string{project: `{"enableAllProjectMcpServers": true}`, local: `{"enableAllProjectMcpServers": false}`}, quiet},
		{"of two values for the key in one file the last decides, false",
			map[string]string{project: `{"enableAllProjectMcpServers": true, "enableAllProjectMcpServers": false}`}, quiet},
		{"a rejection wins over approve-all",
			map[string]string{project: `{"enableAllProjectMcpServers": true, "disabledMcpjsonServers": ["notes"]}`},
			[]string{"notes", "other|PERM-009 medium " + project + ":1 (base)"}},
		{"a rejection in another file wins over an approval by name",
			map[string]string{project: `{"enabledMcpjsonServers": ["notes"]}`, local: `{"disabledMcpjsonServers": ["notes"]}`}, quiet},
		// Claude Code's settings schema types the key Boolean; a string is not the value that approves.
		{"the key set to the string \"true\"", map[string]string{project: `{"enableAllProjectMcpServers": "true"}`}, quiet},
		// Claude Code reads JSON with JSON.parse, whose keys are case-sensitive; Go's struct decoding is not.
		{"the key in another case", map[string]string{project: `{"EnableAllProjectMcpServers": true, "EnabledMcpjsonServers": ["notes"]}`}, quiet},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			mustWrite(t, filepath.Join(base, "repo", ".mcp.json"), approvalMCP)
			for rel, body := range tc.files {
				mustWrite(t, filepath.Join(base, rel), body)
			}
			check, err := CollectTarget(filepath.Join(base, "repo"))
			if err != nil {
				t.Fatal(err)
			}
			if got := approvalView(check, base); fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("check <repo>\n got: %q\nwant: %q", got, tc.want)
			}
			scan := CollectAll(filepath.Join(base, "repo", ".claude"))
			if got := approvalView(scan, base); fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("scan --root <repo>/.claude\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}

// TestCollect_ProjectMCPApprovalNeedsBothFilesInView pins where PERM-009 is NOT raised, each for its reason. The
// finding is about a server that starts unasked, so it needs the server and the settings of the same project in
// the same collection.
func TestCollect_ProjectMCPApprovalNeedsBothFilesInView(t *testing.T) {
	approveAll := `{"enableAllProjectMcpServers": true}`
	cases := []struct {
		name   string
		files  map[string]string
		target string // relative to the fixture directory; "scan <dir>" runs CollectAll on <fixture>/<dir> instead
		want   []string
	}{
		// A settings file holding only the key approves nothing it can be seen to approve, and adds no
		// artifact: the environment average is not diluted by a 100/100 entry for it either.
		{"settings without a .mcp.json, under check",
			map[string]string{"repo/.claude/settings.json": approveAll}, "repo", nil},
		{"settings without a .mcp.json, under scan",
			map[string]string{"repo/.claude/settings.json": approveAll}, "scan repo/.claude", nil},
		// check <repo> also reads <repo>/settings.json, for a config root with another name. Those settings
		// belong to the project ABOVE that root, whose .mcp.json is not this one.
		{"a config root's own settings do not approve the .mcp.json beside it",
			map[string]string{"repo/settings.json": approveAll, "repo/.mcp.json": approvalMCP}, "repo", []string{"notes", "other"}},
		// A file target reads that file and nothing beside it (P-120).
		{"a lone .mcp.json",
			map[string]string{"repo/.claude/settings.json": approveAll, "repo/.mcp.json": approvalMCP}, "repo/.mcp.json", []string{"notes", "other"}},
		{"a lone settings.json",
			map[string]string{"repo/.claude/settings.json": approveAll, "repo/.mcp.json": approvalMCP}, "repo/.claude/settings.json", nil},
		// A user's ~/.claude/settings.json approves the servers of every project, which a scan of ~/.claude does
		// not read. The one project it does read is home's own .mcp.json, whose servers it really does approve.
		{"user settings approve home's own .mcp.json",
			map[string]string{"home/.claude/settings.json": approveAll, "home/.mcp.json": approvalMCP}, "scan home/.claude",
			[]string{"notes|PERM-009 medium home/.claude/settings.json:1 (base)", "other|PERM-009 medium home/.claude/settings.json:1 (base)"}},
		{"user settings with no .mcp.json in home",
			map[string]string{"home/.claude/settings.json": approveAll}, "scan home/.claude", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			for rel, body := range tc.files {
				mustWrite(t, filepath.Join(base, rel), body)
			}
			var res Result
			if dir, ok := strings.CutPrefix(tc.target, "scan "); ok {
				res = CollectAll(filepath.Join(base, dir))
			} else {
				var err error
				if res, err = CollectTarget(filepath.Join(base, tc.target)); err != nil {
					t.Fatal(err)
				}
			}
			if got := approvalView(res, base); fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("servers\n got: %q\nwant: %q", got, tc.want)
			}
			for _, a := range res.Artifacts {
				for _, f := range a.Findings {
					if f.RuleID == "PERM-009" && a.Kind != model.KindMCP {
						t.Errorf("PERM-009 on %s %q: it belongs on the server it approves", a.Kind, a.Name)
					}
				}
			}
		})
	}
}

// TestCollect_ProjectMCPApprovalIsAPermissionFinding pins the finding's shape: dimension 2, medium, a permission
// finding, and a Why that names both keys and the way out (disabledMcpjsonServers), so the reader can act on it.
func TestCollect_ProjectMCPApprovalIsAPermissionFinding(t *testing.T) {
	base := t.TempDir()
	mustWrite(t, filepath.Join(base, "repo", ".mcp.json"), approvalMCP)
	mustWrite(t, filepath.Join(base, "repo", ".claude", "settings.json"), `{"enableAllProjectMcpServers": true}`)
	res, err := CollectTarget(filepath.Join(base, "repo"))
	if err != nil {
		t.Fatal(err)
	}
	var found []model.Finding
	for _, a := range res.Artifacts {
		for _, f := range a.Findings {
			if f.RuleID == "PERM-009" {
				found = append(found, f)
			}
		}
	}
	if len(found) != 2 {
		t.Fatalf("PERM-009 findings = %d, want one per server (2)", len(found))
	}
	f := found[0]
	if f.Dimension != 2 || f.Severity != model.SevMedium || f.Source != model.SrcPermission {
		t.Errorf("dimension %d, severity %s, source %s; want 2, medium, permission", f.Dimension, f.Severity, f.Source)
	}
	for _, word := range []string{"enableAllProjectMcpServers", "enabledMcpjsonServers", "disabledMcpjsonServers", "trust"} {
		if !strings.Contains(f.Why, word) {
			t.Errorf("Why does not mention %q: %s", word, f.Why)
		}
	}
	if got := f.Evidence[0].Snippet; got != `"enableAllProjectMcpServers": true` {
		t.Errorf("snippet = %q", got)
	}
}

// TestTopLevelKeyLines: the line a PERM-009 cites is the line of the settings file's own member, the last one when
// the key repeats (the value JSON.parse keeps), never a member of the same name inside a nested value.
func TestTopLevelKeyLines(t *testing.T) {
	cases := []struct {
		name, doc string
		want      int
	}{
		{"first line", `{"enableAllProjectMcpServers": true}`, 1},
		{"own line", "{\n  \"x\": 1,\n  \"enableAllProjectMcpServers\": true\n}", 3},
		{"after a nested member of the same name", "{\n  \"env\": {\"enableAllProjectMcpServers\": \"1\"},\n  \"enableAllProjectMcpServers\": true\n}", 3},
		{"before a nested member of the same name", "{\n  \"enableAllProjectMcpServers\": true,\n  \"hooks\": [{\"enableAllProjectMcpServers\": false}]\n}", 2},
		{"the last of two", "{\n  \"enableAllProjectMcpServers\": false,\n\n  \"enableAllProjectMcpServers\": true\n}", 4},
		{"CRLF line ends", "{\r\n  \"a\": [1, 2],\r\n  \"enableAllProjectMcpServers\": true\r\n}", 3},
		{"absent", `{"permissions": {"allow": []}}`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := topLevelKeyLines([]byte(tc.doc))[approveAllKey]; got != tc.want {
				t.Errorf("line = %d, want %d", got, tc.want)
			}
		})
	}
}
