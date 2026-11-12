// SPDX-License-Identifier: MIT
package collect

import (
	"encoding/json"
	"path/filepath"
	"sort"

	"github.com/basdotio/bas-guard/internal/model"
	"github.com/basdotio/bas-guard/internal/safeio"
)

// claudeJSONName is the file Claude Code keeps its global config in: ~/.claude.json, or
// $CLAUDE_CONFIG_DIR/.claude.json when that is set (measured on 2.1.107). It is the one MCP config
// with a `projects` member.
const claudeJSONName = ".claude.json"

// rootMCPServers reads one of RootMCPConfigs: a .claude.json in both its scopes (the root's own is
// $CLAUDE_CONFIG_DIR's global config), a .mcp.json as the project file it is.
func rootMCPServers(path string, env *model.EnvSummary) ([]model.ArtifactReport, []model.Finding) {
	if filepath.Base(path) == claudeJSONName {
		return claudeJSONServers(path, env)
	}
	return mcpServersFrom(path, "", env)
}

// claudeJSONServers reads a .claude.json's servers in both scopes it holds: the user scope at the
// top level, then the local scope under each project (localScopeServersFrom).
func claudeJSONServers(path string, env *model.EnvSummary) ([]model.ArtifactReport, []model.Finding) {
	out, notes := mcpServersFrom(path, "", env)
	return append(out, localScopeServersFrom(path, env)...), notes
}

// localScopeServersFrom yields an artifact per server a .claude.json declares in local scope (P-119):
// `projects["<dir>"].mcpServers`, where `claude mcp add` writes a server when no --scope is given, and
// which Claude Code starts in every session run in <dir>. Only the top level was read before, so a
// server added the default way was no artifact at all — mcp=0 and 100/100 for a NODE_OPTIONS preload
// that scored EXEC-010 high when the same entry sat at the top.
//
// Every project is read, whether or not its directory still exists here: Claude Code starts the
// servers whenever a session runs there, a clone can bring a deleted directory back, and asking would
// mean stat-ing the user's directories outside the root. A project keyed "" is skipped: no session
// runs in it, and MCPProject "" is the top-level map.
//
// The artifact is named "<key> (project <dir>)" so two projects' servers, and a project's server and
// a user-scope one under the same key, stay apart in a report; MCPServer and MCPProject hold the
// lookup, which detect, the content hash and the judge all go through (mcpServerMap). The directory
// is a key out of the config, printed as the report prints a plugin key (invariant #3 leaves names
// outside Redact); the judge never sends a name, and its excerpt is the entry alone.
//
// Members are matched exactly, as detect's mcpServerMap matches them: decoding into a struct would
// match "Projects" or "MCPSERVERS" case-insensitively and collect servers detect then cannot find.
// A file collect cannot read or parse at all is already said by mcpServersFrom on the same file.
func localScopeServersFrom(path string, env *model.EnvSummary) []model.ArtifactReport {
	b, err := safeio.ReadFile(path, safeio.MaxConfigBytes)
	if err != nil {
		return nil
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(b, &top) != nil {
		return nil
	}
	raw, ok := top["projects"]
	if !ok {
		return nil
	}
	var projects map[string]json.RawMessage
	if json.Unmarshal(raw, &projects) != nil {
		return []model.ArtifactReport{withParseError(model.KindMCP, "projects", path)}
	}
	dirs := make([]string, 0, len(projects))
	for dir := range projects {
		if dir != "" {
			dirs = append(dirs, dir)
		}
	}
	sort.Strings(dirs)
	var out []model.ArtifactReport
	for _, dir := range dirs {
		suffix := " (project " + dir + ")"
		var project map[string]json.RawMessage
		var servers map[string]json.RawMessage
		if json.Unmarshal(projects[dir], &project) != nil || json.Unmarshal(orNull(project["mcpServers"]), &servers) != nil {
			out = append(out, withParseError(model.KindMCP, "mcpServers"+suffix, path))
			continue
		}
		names := make([]string, 0, len(servers))
		for name := range servers {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			a := artifact(model.KindMCP, name+suffix, path, "")
			a.MCPServer = name
			a.MCPProject = dir
			out = append(out, a)
			env.MCPServers++
		}
	}
	return out
}

// orNull is raw, or JSON null when the member is absent, so an absent member decodes to nothing.
func orNull(raw json.RawMessage) json.RawMessage {
	if raw == nil {
		return json.RawMessage("null")
	}
	return raw
}
