// SPDX-License-Identifier: MIT
package collect

import (
	"bytes"
	"encoding/json"
	"sort"

	"github.com/basdotio/bas-guard/internal/model"
	"github.com/basdotio/bas-guard/internal/redact"
)

// Project MCP server approvals (P-127).
//
// Claude Code asks before it starts a server a project's .mcp.json declares; that prompt is the one place the
// user is shown the command. Three settings keys answer it in advance (Claude Code's settings reference):
//   - enableAllProjectMcpServers: true approves every server. The highest-precedence file that sets it decides,
//     so in a trusted folder a false in settings.local.json overrides a true in settings.json.
//   - enabledMcpjsonServers approves the servers it names; the lists of all files count.
//   - disabledMcpjsonServers rejects the servers it names, from any file, over both.
//
// A repository's own .claude/settings.json is ignored until the user accepts the workspace trust dialog; after
// that the servers it approves start with every session and nobody is asked again. CVE-2025-59536 was this pair
// of files honoured before the dialog. On v0.35.0 the corpus's reconstruction of it scored 100/100.
//
// The finding (PERM-009) goes on each SERVER the settings approve, not on the settings file: what is at stake is
// a command that starts unasked; a settings file holding only the key approves nothing a scan can see; and a
// settings file with nothing else in it is no artifact at all, so it has nothing to carry a finding. It is raised
// only where one collection reads both files of one project, the .mcp.json and the .claude beside it:
//   - a scan: the root's settings files with home's .mcp.json (CollectAll), for a project's .claude and for
//     ~/.claude alike. ~/.claude/settings.json approves the servers of every project; home's own are the ones a
//     scan of it can see;
//   - check <dir>: <dir>/.claude's settings files with <dir>/.mcp.json (withDeclared). Not <dir>'s own settings
//     files, which are a config root's whose project is the directory above.
//
// A lone .mcp.json or settings file is one file in view and stays quiet.
//
// Keys are read by their exact name: Claude Code parses settings with JSON.parse, which is case-sensitive, and
// Go's struct decoding is not (mcpServerMap takes MCP members by exact key for the same reason, P-119). Of two
// values for one key the last counts, as for JSON.parse. Only the JSON literals true and false set
// enableAllProjectMcpServers, which Claude Code types Boolean.

const (
	approveAllKey = "enableAllProjectMcpServers"
	approveKey    = "enabledMcpjsonServers"
	rejectKey     = "disabledMcpjsonServers"
)

// mcpApproval is what one settings file says about a project's .mcp.json servers. The zero value says nothing.
type mcpApproval struct {
	path         string
	all          *bool // approveAllKey, when the file sets it to true or false
	allLine      int
	approved     map[string]bool
	approvedLine int
	rejected     map[string]bool
}

// mcpApprovalFrom reads the approval keys of the settings file at path, whose bytes are b. A document that is not
// a JSON object says nothing; settingsFrom reports it as PARSE-000.
func mcpApprovalFrom(path string, b []byte) mcpApproval {
	var doc map[string]json.RawMessage
	if json.Unmarshal(b, &doc) != nil {
		return mcpApproval{}
	}
	lines := topLevelKeyLines(b)
	out := mcpApproval{path: path}
	switch string(bytes.TrimSpace(doc[approveAllKey])) {
	case "true":
		all := true
		out.all, out.allLine = &all, lines[approveAllKey]
	case "false":
		all := false
		out.all, out.allLine = &all, lines[approveAllKey]
	}
	if names := nameSet(doc[approveKey]); len(names) > 0 {
		out.approved, out.approvedLine = names, lines[approveKey]
	}
	out.rejected = nameSet(doc[rejectKey])
	return out
}

// nameSet decodes a JSON array of strings into a set; anything else is the empty set.
func nameSet(raw json.RawMessage) map[string]bool {
	var names []string
	if len(raw) == 0 || json.Unmarshal(raw, &names) != nil {
		return nil
	}
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return set
}

// topLevelKeyLines maps each member name of the JSON object b to the 1-based line its last occurrence starts on,
// counting only the object's own members: a member of the same name inside a nested value is not one.
func topLevelKeyLines(b []byte) map[string]int {
	lines := map[string]int{}
	dec := json.NewDecoder(bytes.NewReader(b))
	depth, wantKey := 0, false
	for {
		start := dec.InputOffset()
		tok, err := dec.Token()
		if err != nil {
			return lines
		}
		switch v := tok.(type) {
		case json.Delim:
			if v == '{' || v == '[' {
				depth++
				wantKey = depth == 1
			} else {
				depth--
				wantKey = depth == 1 // a nested value of a member ended
			}
		default:
			if depth != 1 {
				continue
			}
			if name, ok := v.(string); ok && wantKey {
				lines[name] = 1 + bytes.Count(b[:start], []byte("\n")) + leadingNewlines(b[start:])
			}
			wantKey = !wantKey
		}
	}
}

// leadingNewlines counts the newlines in the whitespace and separator that come before the next token in b:
// InputOffset stands before them.
func leadingNewlines(b []byte) int {
	n := 0
	for _, c := range b {
		switch c {
		case '\n':
			n++
		case ' ', '\t', '\r', ',', ':':
		default:
			return n
		}
	}
	return n
}

// approvalEvidence returns the settings lines that approve the server named name, file by file in approvals'
// order (lowest precedence first, as settingsScopes reads them) and by line within a file; nil when nothing
// approves it or any file rejects it.
func approvalEvidence(name string, approvals []mcpApproval) []model.Evidence {
	for _, a := range approvals {
		if a.rejected[name] {
			return nil
		}
	}
	decider := -1
	for i := len(approvals) - 1; i >= 0; i-- {
		if approvals[i].all != nil {
			decider = i
			break
		}
	}
	var out []model.Evidence
	for i, a := range approvals {
		var file []model.Evidence
		if i == decider && *a.all {
			file = append(file, approvalLine(a.path, a.allLine, `"`+approveAllKey+`": true`))
		}
		if a.approved[name] {
			file = append(file, approvalLine(a.path, a.approvedLine, `"`+approveKey+`" lists "`+name+`"`))
		}
		sort.SliceStable(file, func(x, y int) bool { return file[x].Line < file[y].Line })
		out = append(out, file...)
	}
	return out
}

func approvalLine(path string, line int, snippet string) model.Evidence {
	// The server name is a key out of the configuration; the snippet goes through the one redaction there is.
	return model.Evidence{File: path, Line: line, Snippet: redact.Secrets(snippet), Scope: ScopeFor(path)}
}

// withMCPApprovals returns the servers of one project's .mcp.json with PERM-009 on each that approvals, the
// project's settings files in precedence order, approve. Neither slice, nor any artifact's findings, is modified.
func withMCPApprovals(servers []model.ArtifactReport, approvals []mcpApproval) []model.ArtifactReport {
	out := make([]model.ArtifactReport, 0, len(servers))
	for _, s := range servers {
		// A .mcp.json that does not parse is one artifact with no MCPServer: there is no server to approve.
		if s.Kind == model.KindMCP && s.MCPServer != "" {
			if ev := approvalEvidence(s.MCPServer, approvals); len(ev) > 0 {
				s.Findings = append(append([]model.Finding{}, s.Findings...), mcpApprovalFinding(ev))
			}
		}
		out = append(out, s)
	}
	return out
}

// mcpApprovalFinding is PERM-009. Medium, not high (P-127): the command it lets start is in view and every MCP
// rule reads it, and teams that ship a .mcp.json commit the key for convenience: of the 62 benign corpus samples
// that are a project's .claude/settings.json approving servers, 38 come from a repository with a .mcp.json at its
// top level at the same commit. High would fail `check --fail-on high` on most of those for a setting, not for
// anything the server does.
func mcpApprovalFinding(ev []model.Evidence) model.Finding {
	return model.Finding{
		RuleID: "PERM-009", Dimension: 2, Severity: model.SevMedium, Source: model.SrcPermission,
		Title: "Project MCP server approved without a prompt",
		Why: "Claude Code asks before it starts a server a project's .mcp.json declares, and that prompt is where the " +
			"command is shown to the user. This project's settings answer it in advance (enableAllProjectMcpServers, " +
			"or enabledMcpjsonServers naming the server), so once the folder is trusted the server starts with every " +
			"session and nobody is asked. When the settings came with the repository, the repository decided that its " +
			"command runs on your machine; Claude Code also writes these keys into settings.local.json when you approve " +
			"a server yourself. Read the server's command before you trust the folder; disabledMcpjsonServers rejects " +
			"it over both keys.",
		Evidence: ev,
	}
}
