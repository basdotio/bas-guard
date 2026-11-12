// SPDX-License-Identifier: MIT
package detect

import (
	"encoding/json"

	"github.com/basdotio/bas-guard/internal/model"
	"github.com/basdotio/bas-guard/internal/safeio"
)

// mcpServerMap is the server map an MCP artifact's entry sits in: the document's `mcpServers` member;
// the document itself for a plugin file collect read without the wrapper (MCPUnwrapped, P-029 — Claude
// Code reads a plugin MCP file as `doc.mcpServers || doc`); or projects[MCPProject].mcpServers of a
// .claude.json for a server added in local scope, the default of `claude mcp add` (P-119). Collect
// decides the layout once and records it; the rule units, MCPServerKey's "" check and the content hash
// all pick the map here, so the three cannot be reading different entries. A member that is not an
// object reads as an empty map, as it always did.
func mcpServerMap(doc map[string]json.RawMessage, a model.ArtifactReport) map[string]json.RawMessage {
	if a.MCPUnwrapped {
		return doc
	}
	if a.MCPProject != "" {
		var projects map[string]json.RawMessage
		if raw, ok := doc["projects"]; !ok || json.Unmarshal(raw, &projects) != nil {
			return map[string]json.RawMessage{}
		}
		var project map[string]json.RawMessage
		if raw, ok := projects[a.MCPProject]; !ok || json.Unmarshal(raw, &project) != nil {
			return map[string]json.RawMessage{}
		}
		doc = project
	}
	servers := map[string]json.RawMessage{}
	if raw, ok := doc["mcpServers"]; ok {
		_ = json.Unmarshal(raw, &servers)
	}
	return servers
}

// mcpEntry reads a.Path and returns the entry under key in a's server map.
func mcpEntry(a model.ArtifactReport, key string) (json.RawMessage, bool) {
	b, err := safeio.ReadFile(a.Path, safeio.MaxConfigBytes)
	if err != nil {
		return nil, false
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(b, &doc) != nil {
		return nil, false
	}
	raw, ok := mcpServerMap(doc, a)[key]
	return raw, ok
}

// artifactMCPEntry is the entry an MCP artifact stands for.
func artifactMCPEntry(a model.ArtifactReport) (json.RawMessage, bool) {
	return mcpEntry(a, MCPServerKey(a))
}

// mcpUnits are the rule units of an MCP artifact's entry: its string values, and its env block as
// KEY=VALUE lines.
func mcpUnits(a model.ArtifactReport) []unit {
	raw, ok := artifactMCPEntry(a)
	if !ok {
		return nil
	}
	return append(jsonStrings(a.Path, raw), entryEnvUnit(a.Path, raw)...)
}

// MCPConfigLines renders an MCP artifact's entry the way ConfigLines renders section[name]: the
// view the LLM judge's MCP config pass sends. Exported so the judge finds the entry where the rules
// and the content hash find it, wrapped or not.
func MCPConfigLines(a model.ArtifactReport) []string {
	raw, ok := artifactMCPEntry(a)
	if !ok {
		return nil
	}
	return entryLines(raw)
}
