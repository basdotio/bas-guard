// SPDX-License-Identifier: MIT
package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/basdotio/bas-guard/internal/model"
)

// noteTitled returns the scan-level note with this title.
func noteTitled(notes []model.Finding, title string) (model.Finding, bool) {
	for _, n := range notes {
		if n.Title == title {
			return n, true
		}
	}
	return model.Finding{}, false
}

// TestUnowned_ProjectDirIsNamed: a .claude directory under the root is where a project keeps its
// agent files, and a root one level above it reads none of them (P-105). It used to be one more name
// in the unowned note — a deliberate skip, so the headline said "looks safe" and a --fail-on gate
// exited 0 over a project whose skills nobody read. It now raises its own note, out of the unowned
// list. A .claude that is a FILE is not a project's layout and stays where it was.
func TestUnowned_ProjectDirIsNamed(t *testing.T) {
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "claude-dotfiles", "skills", "x", "SKILL.md"), "---\nname: x\n---\n")

	for _, tc := range []struct {
		name     string
		rootName string // the root's own name; "proj" when empty
		build    func(t *testing.T, root string)
		named    bool // the project-dir note is raised
		listed   bool // ".claude" is still in the unowned note
		empty    bool // the empty-root note is raised too
	}{
		{"a .claude directory and nothing else", "", func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, ".claude", "skills", "demo", "SKILL.md"), "---\nname: demo\n---\n")
		}, true, false, true},
		{"a .claude directory next to a README", "", func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, ".claude", "settings.json"), `{"permissions":{"allow":["Bash(git *)"]}}`)
			writeFile(t, filepath.Join(root, "README.md"), "# project\n")
		}, true, false, false},
		{"a .claude symlink to a directory outside the root", "", func(t *testing.T, root string) {
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(outside, "claude-dotfiles"), filepath.Join(root, ".claude")); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(root, "README.md"), "# project\n")
		}, true, false, false},
		// Reverse: a FILE named .claude is no project's layout; it stays in the unowned list.
		{"a .claude file", "", func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, ".claude"), "not a directory\n")
			writeFile(t, filepath.Join(root, "README.md"), "# project\n")
		}, false, true, false},
		// Reverse: a .claude inside a config root is no project above it. Claude Code writes
		// ~/.claude/.claude/settings.local.json when it runs from inside ~/.claude (found on a real
		// machine by review); a scan of ~/.claude must not tell its user to point --root one level down.
		{"a .claude inside ~/.claude", ".claude", func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, "settings.json"), `{"permissions":{"allow":["Bash(ls)"],"deny":[]}}`)
			writeFile(t, filepath.Join(root, ".claude", "settings.local.json"), `{"permissions":{"allow":[]}}`)
		}, false, true, false},
		{"a .claude next to a repository's skills/", "", func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, "skills", "x", "SKILL.md"), "---\nname: x\n---\n")
			writeFile(t, filepath.Join(root, ".claude", "rules", "style.md"), "# style\n")
		}, false, true, false},
		{"a .claude in a config root with another name", "claude-config", func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, "settings.json"), `{}`)
			writeFile(t, filepath.Join(root, ".claude", "settings.local.json"), `{}`)
		}, false, true, true},
		// Reverse: no .claude, nothing new.
		{"no .claude", "", func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, "README.md"), "# project\n")
		}, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := tc.rootName
			if name == "" {
				name = "proj"
			}
			root := filepath.Join(t.TempDir(), name)
			tc.build(t, root)
			res := CollectAll(root)

			n, named := noteTitled(res.Notes, ProjectDirNoteTitle)
			if named != tc.named {
				t.Fatalf("project-dir note raised = %v, want %v (notes: %+v)", named, tc.named, res.Notes)
			}
			if named {
				if n.RuleID != "COV-000" || n.Dimension != 0 {
					t.Errorf("the note must be a dimension-0 COV-000, got %s dim %d", n.RuleID, n.Dimension)
				}
				if len(n.Evidence) == 0 || n.Evidence[0].File != filepath.Join(AnchorRoot(root), ".claude") {
					t.Errorf("the note must point at <root>/.claude, got %+v", n.Evidence)
				}
				if !strings.Contains(n.Why, "--root .claude") {
					t.Errorf("the note must name the flag that reads it, got %q", n.Why)
				}
				if leaves := strings.Contains(tc.name, "symlink"); leaves != strings.Contains(n.Evidence[0].Snippet, "symlink leaves the root") {
					t.Errorf("a .claude linked out of the root must still say so, and only then; got %q", n.Evidence[0].Snippet)
				}
			}
			un, _ := noteTitled(res.Notes, UnownedNoteTitle)
			if listed := strings.Contains(un.Why, ".claude"); listed != tc.listed {
				t.Errorf(".claude in the unowned note = %v, want %v (Why: %q)", listed, tc.listed, un.Why)
			}
			if _, empty := noteTitled(res.Notes, EmptyRootNoteTitle); empty != tc.empty {
				t.Errorf("empty-root note raised = %v, want %v", empty, tc.empty)
			}
			if got, ok := UnauditedRoot(res.Notes); ok != (tc.named || tc.empty) {
				t.Errorf("UnauditedRoot = %v, want %v", ok, tc.named || tc.empty)
			} else if ok && tc.named && got.Title != ProjectDirNoteTitle {
				t.Errorf("UnauditedRoot must prefer the project-dir note, which names the fix; got %q", got.Title)
			}
		})
	}
}
