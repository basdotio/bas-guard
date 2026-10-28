// SPDX-License-Identifier: MIT

package aguard

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/basdotio/bas-guard/internal/model"
)

// TestLocator_InvertsEveryPlacement pins the mapping on the path shapes aguard actually
// reports, copied from the 2026-10 raw/ of a full run — one per artifact kind — rather than on
// shapes the adapter would like it to report. The evidence path's base differs per kind (config
// root, home, work directory, the artifact's own file, the staged session directory), which is
// the reason this is a marker inversion and not a filepath.Rel.
func TestLocator_InvertsEveryPlacement(t *testing.T) {
	id := "ben-skill-md-acidsound-acidapps-screenshot-generator"
	loc := Locator{ID: id}
	cases := []struct {
		name, art, ev, want string
	}{
		{"skill: evidence relative to the config root",
			"<work>/" + id + "/home/.claude/skills/" + id,
			"skills/" + id + "/SKILL.md", "SKILL.md"},
		{"skill: a script inside the tree keeps its sub-path",
			"<work>/" + id + "/home/.claude/skills/" + id,
			"skills/" + id + "/scripts/install.sh", "scripts/install.sh"},
		{"skill: an absolute staged path on the machine that ran it",
			"/private/tmp/w/" + id + "/home/.claude/skills/" + id,
			"/private/tmp/w/" + id + "/home/.claude/skills/" + id + "/forms.md", "forms.md"},
		{"hook: evidence relative to the home",
			"<work>/ben-hook/home/.claude/settings.json", ".claude/settings.json", ".claude/settings.json"},
		{"permission: evidence is the artifact's own file name",
			"<work>/ben-hook/home/.claude/settings.json", "settings.json", ".claude/settings.json"},
		{"hook: the referenced script is relative to the config root, not to settings.json",
			"<work>/mal-hook/home/.claude/settings.json", "hooks/docs.py", ".claude/hooks/docs.py"},
		{"connector: the staged session file is the sample's tools.json",
			"<work>/ben-mcp/home/Library/Application Support/Claude/claude-code-sessions/corpus/sample/local_0.json",
			"sample/local_0.json", "tools.json"},
		{"project mcp config: evidence relative to the work directory",
			"<work>/mal-conn/home/.mcp.json", "home/.mcp.json", ".mcp.json"},
		{"instruction inside a .claude tree keeps its path",
			"<work>/x/home/.claude/CLAUDE.md", ".claude/CLAUDE.md", ".claude/CLAUDE.md"},
		{"a judge label is not a file", "<work>/x/home/.claude/skills/x", "skill:x", ""},
		{"empty", "<work>/x/home/.claude/skills/x", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := loc.SampleFile(tc.art, tc.ev); got != tc.want {
				t.Errorf("SampleFile(%q, %q) = %q, want %q", tc.art, tc.ev, got, tc.want)
			}
		})
	}
}

// TestLocator_LooseInstructionGetsItsOwnNameBack: 113 malicious samples in the corpus are one
// loose .md file, staged as CLAUDE.md. aguard reports `.claude/CLAUDE.md`; the label's evidence
// names the file the tree holds, and only Stage knows which that was.
func TestLocator_LooseInstructionGetsItsOwnNameBack(t *testing.T) {
	loc := Locator{ID: "mal-instr-x", Loose: "payload.md"}
	if got := loc.SampleFile("<work>/mal-instr-x/home/.claude/CLAUDE.md", ".claude/CLAUDE.md"); got != "payload.md" {
		t.Errorf("got %q, want the loose file's own name", got)
	}
	plain := Locator{ID: "mal-instr-x"}
	if got := plain.SampleFile("<work>/mal-instr-x/home/.claude/CLAUDE.md", ".claude/CLAUDE.md"); got != ".claude/CLAUDE.md" {
		t.Errorf("without Loose, got %q; the file really is at .claude/CLAUDE.md in that tree", got)
	}
}

// TestLocator_CheckRouteIsRelativeToTheTree: `check <tree>` reports against the tree itself,
// relative or absolute; both come back tree-relative.
func TestLocator_CheckRouteIsRelativeToTheTree(t *testing.T) {
	tree := "/corpus/malicious/mcp/ci-x"
	loc := Locator{ID: "mal-mcp-ci-x", Tree: tree}
	for ev, want := range map[string]string{
		"x.py":             "x.py",
		tree + "/src/x.py": "src/x.py",
	} {
		if got := loc.SampleFile(tree, ev); got != want {
			t.Errorf("SampleFile(tree, %q) = %q, want %q", ev, got, want)
		}
	}
}

// TestLocatorFor_ReadsTheLooseFileTheWayStageDoes: the judge fold has no staged copy, so it asks
// the tree; the answer must be Stage's.
func TestLocatorFor_ReadsTheLooseFileTheWayStageDoes(t *testing.T) {
	loose := t.TempDir()
	if err := os.WriteFile(filepath.Join(loose, "inject.md"), []byte("# x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := Stage(loose, "s", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := LocatorFor(loose, "s"); got.Loose != st.Loose || got.Loose != "inject.md" {
		t.Errorf("LocatorFor.Loose = %q, Stage.Loose = %q, want both inject.md", got.Loose, st.Loose)
	}

	skill := t.TempDir()
	for _, f := range []string{"SKILL.md", "README.md"} {
		if err := os.WriteFile(filepath.Join(skill, f), []byte("# x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := LocatorFor(skill, "s"); got.Loose != "" {
		t.Errorf("a tree of two files is not a loose instruction file; Loose = %q", got.Loose)
	}
}

// TestFlaggedFiles_OnlyTheFindingsThatCarriedTheFlag: files are attribution for the verdict, so
// a finding below the threshold, or a judge note, names nothing; duplicates collapse; the order
// is sorted so two runs diff cleanly; none is nil, not an empty list.
func TestFlaggedFiles_OnlyTheFindingsThatCarriedTheFlag(t *testing.T) {
	art := "<work>/s/home/.claude/skills/s"
	ev := func(f string) []model.Evidence { return []model.Evidence{{File: "skills/s/" + f, Line: 1}} }
	res := model.ScanResult{Artifacts: []model.ArtifactReport{{Kind: model.KindSkill, Path: art, Findings: []model.Finding{
		{RuleID: "EXFIL-001", Dimension: 3, Severity: model.SevHigh, Source: model.SrcStatic, Evidence: ev("scripts/run.sh")},
		{RuleID: "EXEC-001", Dimension: 4, Severity: model.SevHigh, Source: model.SrcStatic, Evidence: ev("SKILL.md")},
		{RuleID: "EXEC-002", Dimension: 4, Severity: model.SevHigh, Source: model.SrcStatic, Evidence: ev("SKILL.md")},
		{RuleID: "SUP-003", Dimension: 5, Severity: model.SevLow, Source: model.SrcStatic, Evidence: ev("package.json")},
		{RuleID: "LLM-003", Dimension: 1, Severity: model.SevHigh, Source: model.SrcLLM, Evidence: ev("forms.md")},
	}}}}
	got := FlaggedFiles(res, Locator{ID: "s"}, flaggingAt(model.SevHigh))
	if want := []string{"SKILL.md", "scripts/run.sh"}; !reflect.DeepEqual(got, want) {
		t.Errorf("FlaggedFiles = %v, want %v", got, want)
	}
	if got := FlaggedFiles(res, Locator{ID: "s"}, flaggingAt(model.SevCritical)); got != nil {
		t.Errorf("nothing flagged at critical, want nil, got %v", got)
	}
}
