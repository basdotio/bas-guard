// SPDX-License-Identifier: MIT
package main

import (
	"strings"
	"testing"
)

const header = "# Changelog\n\nIntro.\n\n"

// changelog builds a CHANGELOG.md with the given Unreleased body and released version lines.
func changelog(unreleased string, released ...string) string {
	var b strings.Builder
	b.WriteString(header)
	b.WriteString("## Unreleased\n\n")
	b.WriteString(unreleased)
	b.WriteString("\n## v0.1.0\n\n- The baseline.\n\n## v0.2.0 – v0.38.0\n\n")
	for _, r := range released {
		b.WriteString(r)
		b.WriteString("\n\n")
	}
	return b.String()
}

const (
	entryA   = "- **A question stops early** (P-103, @alice, 2026-11-19). The judge stops asking\n  when the remaining samples cannot change the outcome.\n"
	entryB   = "- **The result pass can be turned off** (P-106, @bob-2, 2026-11-19). One config key.\n"
	v038     = "**v0.38.0 (2026-11-19) — something.**\n\n- **Old** (P-138). Text."
	v039     = "**v0.39.0 (2026-11-20) — the next one.**\n\n" + entryA
	codeFile = "internal/judge/plan.go"
	testFile = "internal/judge/plan_test.go"
)

func TestCheck(t *testing.T) {
	base := changelog("", v038)
	tests := []struct {
		name string
		in   Input
		want []string // one substring per expected problem, in order; empty means no problem
	}{
		{
			name: "nothing changed",
			in:   Input{Base: base, Head: base},
		},
		{
			name: "shipped code with a new entry",
			in:   Input{Changed: []string{codeFile, "CHANGELOG.md"}, Base: base, Head: changelog(entryA, v038)},
		},
		{
			name: "shipped code and the changelog was not touched",
			in:   Input{Changed: []string{codeFile}, Base: base, Head: base},
			want: []string{"no new entry under \"## Unreleased\""},
		},
		{
			// The file was touched, which is what a "did CHANGELOG.md change" check would accept.
			name: "shipped code and the changelog only reworded an old release",
			in: Input{
				Changed: []string{codeFile, "CHANGELOG.md"},
				Base:    base,
				Head:    changelog("", strings.Replace(v038, "Text.", "Other text.", 1)),
			},
			want: []string{"no new entry"},
		},
		{
			name: "shipped code on top of somebody else's unreleased entry",
			in: Input{
				Changed: []string{codeFile},
				Base:    changelog(entryA, v038),
				Head:    changelog(entryA, v038),
			},
			want: []string{"no new entry"},
		},
		{
			name: "a second entry next to an existing one",
			in: Input{
				Changed: []string{codeFile, "CHANGELOG.md"},
				Base:    changelog(entryA, v038),
				Head:    changelog(entryB+entryA, v038),
			},
		},
		{
			name: "a release moves the entries under a new version",
			in: Input{
				Changed: []string{"npm/package.json", "plugin/.claude-plugin/plugin.json", "CHANGELOG.md"},
				Base:    changelog(entryA, v038),
				Head:    changelog("", v039, v038),
			},
		},
		{
			name: "tests, docs and tooling need no entry",
			in: Input{
				Changed: []string{testFile, "docs/architecture.md", "hack/gen-rules/main.go", "baselines/cmd/baseline/main.go", "Makefile", "internal/reputation/data/known.json"},
				Base:    base, Head: base,
			},
		},
		{
			name: "each shipped surface asks for an entry",
			in: Input{
				Changed: []string{"cmd/bas-guard/scan.go", "plugin/hooks/hooks.json", "npm/install.js", "hack/github-action.yml"},
				Base:    base, Head: base,
			},
			want: []string{"cmd/bas-guard/scan.go, plugin/hooks/hooks.json, npm/install.js, hack/github-action.yml"},
		},
		{
			name: "opted out with a reason",
			in: Input{
				Changed:  []string{codeFile},
				Base:     base,
				Head:     base,
				Messages: "judge: rename a helper (P-141)\n\nChangelog: none — a rename, nothing a user can observe\n",
			},
		},
		{
			name: "opted out without a reason",
			in: Input{
				Changed:  []string{codeFile},
				Base:     base,
				Head:     base,
				Messages: "judge: rename a helper\n\nChangelog: none\n",
			},
			want: []string{"gives no reason", "no new entry"},
		},
		{
			name: "a trailer that says something other than none",
			in: Input{
				Changed:  []string{codeFile},
				Base:     base,
				Head:     base,
				Messages: "judge: rename a helper\n\nChangelog: later, in the release\n",
			},
			want: []string{"no new entry"},
		},
		{
			name: "the opt-out words inside a sentence are not a trailer",
			in: Input{
				Changed:  []string{codeFile},
				Base:     base,
				Head:     base,
				Messages: "docs: say that `Changelog: none — reason` opts out\n",
			},
			want: []string{"no new entry"},
		},
		{
			name: "an entry without an author",
			in:   Input{Changed: []string{codeFile}, Base: base, Head: changelog("- **Thing** (P-141, 2026-11-19). Text.\n", v038)},
			want: []string{"- **Thing** (P-141, 2026-11-19). Text."},
		},
		{
			name: "an entry without a date",
			in:   Input{Changed: []string{codeFile}, Base: base, Head: changelog("- **Thing** (P-141, @alice). Text.\n", v038)},
			want: []string{"- **Thing** (P-141, @alice). Text."},
		},
		{
			name: "an entry whose date is not a day",
			in:   Input{Changed: []string{codeFile}, Base: base, Head: changelog("- **Thing** (@alice, 2026-13-40). Text.\n", v038)},
			want: []string{"2026-13-40 is not a date"},
		},
		{
			name: "author and date alone are enough",
			in:   Input{Changed: []string{codeFile}, Base: base, Head: changelog("- **Thing** (@alice, 2026-11-19). Text.\n", v038)},
		},
		{
			// Format is checked whether or not this change touched shipped code: the entry is
			// somebody's, and a release would carry it as written.
			name: "a malformed entry already on the base",
			in:   Input{Base: changelog("- No tag at all.\n", v038), Head: changelog("- No tag at all.\n", v038)},
			want: []string{"- No tag at all."},
		},
		{
			name: "the section is gone",
			in:   Input{Base: base, Head: header + "## v0.1.0\n\n- The baseline.\n"},
			want: []string{"has no \"## Unreleased\" section"},
		},
		{
			name: "the section is gone and shipped code changed",
			in:   Input{Changed: []string{codeFile}, Base: base, Head: header + "## v0.1.0\n\n- The baseline.\n"},
			want: []string{"has no \"## Unreleased\" section", "no new entry"},
		},
		{
			name: "the base has no section yet",
			in:   Input{Changed: []string{codeFile}, Base: header + "## v0.1.0\n", Head: changelog(entryA, v038)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Check(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("Check() = %d problems %q, want %d %q", len(got), got, len(tt.want), tt.want)
			}
			for i, w := range tt.want {
				if !strings.Contains(got[i], w) {
					t.Errorf("problem %d = %q, want it to contain %q", i, got[i], w)
				}
			}
		})
	}
}

func TestUnreleased_EntriesAreWholeBullets(t *testing.T) {
	md := changelog("Nothing yet is not an entry.\n\n"+entryA+"- **Second** (@bob, 2026-11-19).\n  - a nested point\n  more text\n", v038)
	got, ok := unreleased(md)
	if !ok {
		t.Fatal("unreleased() did not find the section")
	}
	want := []string{
		"- **A question stops early** (P-103, @alice, 2026-11-19). The judge stops asking when the remaining samples cannot change the outcome.",
		"- **Second** (@bob, 2026-11-19). - a nested point more text",
	}
	if len(got) != len(want) {
		t.Fatalf("unreleased() = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// The section ends at the next "## " heading: a released bullet is never read as unreleased,
// or every old entry without an author would be reported.
func TestUnreleased_StopsAtTheNextSection(t *testing.T) {
	got, ok := unreleased(changelog("", v038))
	if !ok || len(got) != 0 {
		t.Fatalf("unreleased() = %q, %v; want no entries and true", got, ok)
	}
}

func TestShipped(t *testing.T) {
	tests := map[string]bool{
		"cmd/bas-guard/scan.go":           true,
		"internal/detect/detect.go":       true,
		"internal/detect/detect_test.go":  false,
		"internal/reputation/data/x.json": false,
		"plugin/skills/scan/SKILL.md":     true,
		"npm/package.json":                true,
		"hack/github-action.yml":          true,
		"hack/pre-commit":                 false,
		"cmdx/main.go":                    false,
		"docs/rules.md":                   false,
		"CHANGELOG.md":                    false,
		"baselines/cmd/baseline/main.go":  false,
		".github/workflows/ci.yml":        false,
	}
	for path, want := range tests {
		if got := shipped(path); got != want {
			t.Errorf("shipped(%q) = %v, want %v", path, got, want)
		}
	}
}
