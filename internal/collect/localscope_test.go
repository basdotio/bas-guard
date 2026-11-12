// SPDX-License-Identifier: MIT
package collect

import (
	"fmt"
	"path/filepath"
	"sort"
	"testing"

	"github.com/basdotio/bas-guard/internal/model"
)

// localView lists a collection's MCP artifacts as "Name|MCPServer|MCPProject|file", sorted, with
// parse-error artifacts marked by their rule.
func localView(res Result) []string {
	var out []string
	for _, a := range res.Artifacts {
		if a.Kind != model.KindMCP {
			continue
		}
		row := fmt.Sprintf("%s|%s|%s|%s", a.Name, a.MCPServer, a.MCPProject, filepath.Base(a.Path))
		for _, f := range a.Findings {
			row += "|" + f.RuleID
		}
		out = append(out, row)
	}
	sort.Strings(out)
	return out
}

// TestCollect_LocalScopeMCPServers (P-119): `claude mcp add` defaults to scope local, which writes the
// server to `projects["<dir>"].mcpServers` of the same .claude.json the user scope writes to the top
// of — ~/.claude.json, or $CLAUDE_CONFIG_DIR/.claude.json when that is set (measured on 2.1.107).
// Only the top level was read, so a server added the default way was no artifact at all: zero units,
// mcp=0, 100/100, while Claude Code started it in every session in that directory. Each row is one
// layout and what must be collected from it.
func TestCollect_LocalScopeMCPServers(t *testing.T) {
	const preload = `{"command":"npx","args":["-y","notes-mcp"],"env":{"NODE_OPTIONS":"--require /tmp/preload.js"}}`
	const node = `{"command":"node","args":["s.js"]}`
	cases := []struct {
		name string
		// where the document goes: "home" is <home>/.claude.json, "root" is <root>/.claude.json (a
		// CLAUDE_CONFIG_DIR's own file), "mcp" is <home>/.mcp.json.
		where, doc string
		want       []string
		count      int
	}{
		{"one project, one server", "home",
			`{"projects":{"/tmp/some-repo":{"mcpServers":{"local-notes":` + preload + `}}}}`,
			[]string{"local-notes (project /tmp/some-repo)|local-notes|/tmp/some-repo|.claude.json"}, 1},
		{"the CLAUDE_CONFIG_DIR file", "root",
			`{"projects":{"/private/tmp/w/repo":{"mcpServers":{"demo-cfg":` + node + `}}}}`,
			[]string{"demo-cfg (project /private/tmp/w/repo)|demo-cfg|/private/tmp/w/repo|.claude.json"}, 1},
		{"the same key in two projects and at the top", "home",
			`{"mcpServers":{"db":` + node + `},"projects":{"/w/b":{"mcpServers":{"db":` + node + `}},"/w/a":{"mcpServers":{"db":` + node + `,"cache":` + node + `}}}}`,
			[]string{
				"cache (project /w/a)|cache|/w/a|.claude.json",
				"db (project /w/a)|db|/w/a|.claude.json",
				"db (project /w/b)|db|/w/b|.claude.json",
				"db|db||.claude.json",
			}, 4},
		{"projects with no servers, an empty map, and other members", "home",
			`{"projects":{"/w/a":{"allowedTools":[],"hasTrustDialogAccepted":true},"/w/b":{"mcpServers":{}},"/w/c":{"mcpServers":null}}}`,
			nil, 0},
		{"a project keyed by the empty string is no directory Claude Code runs in", "home",
			`{"projects":{"":{"mcpServers":{"x":` + node + `}}}}`,
			nil, 0},
		{"a projects member that is not an object is said, and the top level is still read", "home",
			`{"mcpServers":{"top":` + node + `},"projects":["/w/a"]}`,
			[]string{"projects|||.claude.json|PARSE-000", "top|top||.claude.json"}, 1},
		{"one project whose servers are not an object is said, the others are read", "home",
			`{"projects":{"/w/a":{"mcpServers":["x"]},"/w/b":{"mcpServers":{"ok":` + node + `}}}}`,
			[]string{"mcpServers (project /w/a)|||.claude.json|PARSE-000", "ok (project /w/b)|ok|/w/b|.claude.json"}, 1},
		{"a project .mcp.json has no projects member Claude Code reads", "mcp",
			`{"projects":{"/w/a":{"mcpServers":{"x":` + node + `}}}}`,
			nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, root := newRoot(t)
			switch tc.where {
			case "home":
				write(t, home, ".claude.json", tc.doc)
			case "root":
				write(t, root, ".claude.json", tc.doc)
			case "mcp":
				write(t, home, ".mcp.json", tc.doc)
			}
			res := CollectAll(root)
			got := localView(res)
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("MCP artifacts\n got: %q\nwant: %q", got, tc.want)
			}
			if res.Env.MCPServers != tc.count {
				t.Errorf("Env.MCPServers = %d, want %d", res.Env.MCPServers, tc.count)
			}
		})
	}
}

// TestCollect_LocalScopeMCPServersInOrder: projects sorted, servers sorted inside each, after the
// file's top-level servers — so an unchanged environment lists its servers in one order every run.
func TestCollect_LocalScopeMCPServersInOrder(t *testing.T) {
	home, root := newRoot(t)
	write(t, home, ".claude.json", `{"projects":{"/z":{"mcpServers":{"b":{},"a":{}}},"/m":{"mcpServers":{"y":{}}}},"mcpServers":{"top":{}}}`)
	want := []string{"top", "y (project /m)", "a (project /z)", "b (project /z)"}
	for i := 0; i < 8; i++ {
		if got := byKind(CollectAll(root))[model.KindMCP]; fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("order = %q, want %q", got, want)
		}
	}
}
