// SPDX-License-Identifier: MIT
package detect

import "testing"

// TestUnderCommands (P-120): a .md under a tree's commands/ (a plugin's) or .claude/commands/ (a
// project's, which Claude Code loads in every session run there) is a slash command and runs the
// command rules; a document that only mentions commands in its path does not.
func TestUnderCommands(t *testing.T) {
	for rel, want := range map[string]bool{
		"commands/deploy.md":             true,
		"commands/ops/deploy.md":         true,
		".claude/commands/deploy.md":     true,
		".claude/commands/ops/deploy.md": true,
		"docs/commands/deploy.md":        false,
		".claude/agents/reviewer.md":     false,
		".claude/commandsx/deploy.md":    false,
		"x/.claude/commands/deploy.md":   false,
		"deploy.md":                      false,
		".claude":                        false,
	} {
		if got := underCommands(rel); got != want {
			t.Errorf("underCommands(%q) = %v, want %v", rel, got, want)
		}
	}
}
