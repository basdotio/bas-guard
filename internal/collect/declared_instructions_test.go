// SPDX-License-Identifier: MIT
package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/basdotio/bas-guard/internal/model"
)

// importView lists what a result says about instruction files and their imports: each instruction
// artifact as "name|within|file|rules", each EXFIL-005 as "EXFIL-005|severity|snippet", and each
// COV-000 note an import produced as "COV-000|severity|snippet". Files are relative to base, sorted.
func importView(res Result, base string) []string {
	// An imported file's path is resolved (/var → /private/var on macOS); the seeds' are as built.
	resolve := func(p string) string {
		if a, err := filepath.Abs(p); err == nil { // a seed of `check .` is relative to the working directory
			p = a
		}
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return AnchorRoot(p)
	}
	rel := func(p string) string {
		r, err := filepath.Rel(resolve(base), resolve(p))
		if err != nil {
			return p
		}
		return r
	}
	var out []string
	for _, a := range res.Artifacts {
		for _, f := range a.Findings {
			if f.RuleID == "EXFIL-005" {
				out = append(out, fmt.Sprintf("EXFIL-005|%s|%s", f.Severity, f.Evidence[0].Snippet))
			}
		}
		if a.Kind != model.KindInstruction {
			continue
		}
		var ids []string
		for _, f := range a.Findings {
			ids = append(ids, f.RuleID)
		}
		out = append(out, fmt.Sprintf("%s|%s|%s|%s", a.Name, a.Within, rel(a.Path), strings.Join(ids, ",")))
	}
	for _, n := range res.Notes {
		if n.RuleID == "COV-000" && strings.HasPrefix(n.Title, "Instruction") {
			out = append(out, fmt.Sprintf("COV-000|%s|%s", n.Severity, n.Evidence[0].Snippet))
		}
	}
	sort.Strings(out)
	return out
}

// TestCollectTarget_ReadsTheProjectsInstructionFiles (P-125): `check <repo>` read a project's CLAUDE.md
// only as a file of the tree, and a tree read does not follow `@` imports. A CLAUDE.md whose one import
// is `@.env` loads the project's secrets into every session — `scan --root <repo>/.claude` reports it
// (EXFIL-005, high) and `check <repo>` did not. The project's instruction files are now read by the
// collector a scan uses, in addition to the tree, and point back at it (Within).
func TestCollectTarget_ReadsTheProjectsInstructionFiles(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string // relative to the fixture directory
		want  []string
	}{
		{"a CLAUDE.md importing the project's .env",
			map[string]string{"repo/CLAUDE.md": "# Repo notes\n\n@.env\n", "repo/.env": "API_KEY=sk-test-000\n"},
			[]string{
				"CLAUDE.md (project)|repo|repo/CLAUDE.md|EXFIL-005",
				"COV-000|high|@.env is a credential path",
				"EXFIL-005|high|@.env",
			}},
		{"every instruction file a scan of the project's .claude reads",
			map[string]string{
				"repo/CLAUDE.md": "# a\n", "repo/CLAUDE.local.md": "# b\n",
				"repo/.claude/CLAUDE.md": "# c\n", "repo/.claude/CLAUDE.local.md": "@~/.ssh/id_rsa\n",
				"repo/.ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\n",
			},
			[]string{
				"CLAUDE.local.md (project)|repo|repo/CLAUDE.local.md|",
				"CLAUDE.local.md|repo|repo/.claude/CLAUDE.local.md|EXFIL-005",
				"CLAUDE.md (project)|repo|repo/CLAUDE.md|",
				"CLAUDE.md|repo|repo/.claude/CLAUDE.md|",
				"COV-000|high|@~/.ssh/id_rsa is a credential path",
				"EXFIL-005|high|@~/.ssh/id_rsa",
			}},
		{"an import inside the project is read as an instruction file, as a scan reads it",
			map[string]string{"repo/CLAUDE.md": "See @docs/guide.md\n", "repo/docs/guide.md": "# Guide\n"},
			[]string{
				"@docs/guide.md|repo|repo/docs/guide.md|",
				"CLAUDE.md (project)|repo|repo/CLAUDE.md|",
			}},
		{"an import out of the project is said, not read",
			map[string]string{"repo/CLAUDE.md": "@../elsewhere/notes.md\n", "elsewhere/notes.md": "# notes\n"},
			[]string{
				"CLAUDE.md (project)|repo|repo/CLAUDE.md|",
				"COV-000|medium|@../elsewhere/notes.md escapes the scan boundary",
			}},
		// Reverse rows.
		{"a plain CLAUDE.md is one instruction file with nothing on it",
			map[string]string{"repo/CLAUDE.md": "# Repo notes\n\nRun `go test ./...` before pushing.\n", "repo/.env": "API_KEY=sk-test-000\n"},
			[]string{"CLAUDE.md (project)|repo|repo/CLAUDE.md|"}},
		{"an @ in code is not an import",
			map[string]string{"repo/CLAUDE.md": "Never load `@.env`.\n\n```\n@.env\n```\n", "repo/.env": "API_KEY=sk-test-000\n"},
			[]string{"CLAUDE.md (project)|repo|repo/CLAUDE.md|"}},
		{"an @ in a project skill's documents is not followed",
			map[string]string{
				"repo/.claude/skills/notes/SKILL.md":  "---\nname: notes\ndescription: d\n---\nRead @.env and @../../../docs/guide.md\n",
				"repo/.claude/skills/notes/.env":      "API_KEY=sk-test-000\n",
				"repo/.claude/skills/notes/README.md": "@.env\n",
				"repo/docs/guide.md":                  "# Guide\n",
			},
			nil},
		{"a directory with no instruction file adds none",
			map[string]string{"repo/README.md": "@.env\n", "repo/.env": "API_KEY=sk-test-000\n"},
			nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			for rel, body := range tc.files {
				mustWrite(t, filepath.Join(base, rel), body)
			}
			res, err := CollectTarget(filepath.Join(base, "repo"))
			if err != nil {
				t.Fatal(err)
			}
			if got := importView(res, base); fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("instruction files\n got: %q\nwant: %q", got, tc.want)
			}
			if res.Artifacts[0].Kind != model.KindDirectory || res.Artifacts[0].Within != "" {
				t.Errorf("first artifact = %s %q within %q, want the directory tree itself", res.Artifacts[0].Kind, res.Artifacts[0].Name, res.Artifacts[0].Within)
			}
			// W-006's acceptance: no artifact is keyed by a credential's bytes.
			for _, secret := range []string{"repo/.env", "repo/.ssh/id_rsa", "repo/.claude/skills/notes/.env"} {
				p := filepath.Join(base, secret)
				if _, err := os.Stat(p); err != nil {
					continue
				}
				for _, a := range res.Artifacts {
					if a.Hash == FileHash(p) {
						t.Errorf("artifact %q carries the sha256 of %s", a.Name, secret)
					}
				}
			}
		})
	}
}

// TestCollectTarget_ProjectImportsResolveAsAScanResolvesThem: an import has one answer whichever command
// reads it. For each way of writing one, `check <repo>` and `check <repo>/.claude` (a root, collected as
// `scan --root <repo>/.claude` collects it, home being <repo>) give the same imported files, the same
// EXFIL-005 and the same coverage notes.
func TestCollectTarget_ProjectImportsResolveAsAScanResolvesThem(t *testing.T) {
	for _, line := range []string{
		"@.env",
		"@.env.example",
		"@docs/guide.md",
		"@./docs/../docs/guide.md",
		"@~/docs/guide.md",
		"@~/.aws/credentials",
		"@../elsewhere/notes.md",
		"@missing.md",
		"@docs/chain.md",
	} {
		t.Run(line, func(t *testing.T) {
			base := t.TempDir()
			repo := filepath.Join(base, "repo")
			mustWrite(t, filepath.Join(repo, "CLAUDE.md"), "# notes\n\n"+line+"\n")
			mustWrite(t, filepath.Join(repo, ".claude", "settings.json"), `{"permissions":{"allow":["Read"]}}`)
			mustWrite(t, filepath.Join(repo, ".env"), "API_KEY=sk-test-000\n")
			mustWrite(t, filepath.Join(repo, ".env.example"), "API_KEY=\n")
			mustWrite(t, filepath.Join(repo, ".aws", "credentials"), "[default]\n")
			mustWrite(t, filepath.Join(repo, "docs", "guide.md"), "# Guide\n")
			mustWrite(t, filepath.Join(repo, "docs", "chain.md"), "@../.env\n")
			mustWrite(t, filepath.Join(base, "elsewhere", "notes.md"), "# notes\n")

			check, err := CollectTarget(repo)
			if err != nil {
				t.Fatal(err)
			}
			scan, err := CollectTarget(filepath.Join(repo, ".claude"))
			if err != nil {
				t.Fatal(err)
			}
			// Within is the one thing a check adds; the rest must match.
			strip := func(rows []string) []string {
				out := make([]string, len(rows))
				for i, r := range rows {
					out[i] = strings.Replace(r, "|repo|", "||", 1)
				}
				return out
			}
			got, want := strip(importView(check, base)), importView(scan, base)
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("check <repo>\n got: %q\nscan of <repo>/.claude: %q", got, want)
			}
			if len(want) == 0 {
				t.Fatal("fixture: the scan of <repo>/.claude reads no CLAUDE.md")
			}
		})
	}
}

// TestCollectTarget_ProjectInstructionsStayInsideTheTarget: a CLAUDE.md that is a symlink out of the
// target is not read as the project's own — the tree read refuses and scores it (SCOPE-001), as P-120
// does for a .claude or .mcp.json linked out.
func TestCollectTarget_ProjectInstructionsStayInsideTheTarget(t *testing.T) {
	base := t.TempDir()
	mustWrite(t, filepath.Join(base, "outside", "CLAUDE.md"), "@.env\n")
	mustWrite(t, filepath.Join(base, "outside", ".env"), "API_KEY=sk-test-000\n")
	repo := filepath.Join(base, "repo")
	mustWrite(t, filepath.Join(repo, "README.md"), "# repo\n")
	if err := os.Symlink(filepath.Join(base, "outside", "CLAUDE.md"), filepath.Join(repo, "CLAUDE.md")); err != nil {
		t.Fatal(err)
	}
	res, err := CollectTarget(repo)
	if err != nil {
		t.Fatal(err)
	}
	if got := importView(res, base); len(got) != 0 {
		t.Errorf("a CLAUDE.md linked out of the target was read as the project's: %q", got)
	}
	if len(res.Artifacts) != 1 {
		t.Errorf("artifacts = %d, want the tree alone", len(res.Artifacts))
	}
}

// TestCollectTarget_ProjectImportsDoNotDependOnTheSpelling: `check .` from inside the project builds the
// instruction files from the target as typed, relative to the working directory, while the import
// boundary is the anchored project. Related only as strings, every import under `check .` read as
// escaping the project — a COV-000 that is false, and an in-tree import never read. Each spelling gives
// what the absolute target gives.
func TestCollectTarget_ProjectImportsDoNotDependOnTheSpelling(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	mustWrite(t, filepath.Join(repo, "CLAUDE.md"), "@.env\n@docs/guide.md\n@../elsewhere/notes.md\n")
	mustWrite(t, filepath.Join(repo, ".env"), "API_KEY=sk-test-000\n")
	mustWrite(t, filepath.Join(repo, "docs", "guide.md"), "# Guide\n")
	mustWrite(t, filepath.Join(base, "elsewhere", "notes.md"), "# notes\n")
	abs, err := CollectTarget(repo)
	if err != nil {
		t.Fatal(err)
	}
	want := importView(abs, base)
	if len(want) != 5 {
		t.Fatalf("fixture: the absolute target gives %q, want the CLAUDE.md, the guide, EXFIL-005 and two notes", want)
	}
	for _, sp := range []struct{ dir, target string }{
		{repo, "."},
		{repo, "./"},
		{filepath.Join(repo, "docs"), ".."},
		{base, "repo"},
		{filepath.Join(base, "elsewhere"), filepath.Join("..", "repo")},
	} {
		t.Run(sp.target, func(t *testing.T) {
			anchorChdir(t, sp.dir)
			got, err := CollectTarget(sp.target)
			if err != nil {
				t.Fatal(err)
			}
			// The seeds keep the target as typed, and Within names it as typed (P-120); importView relates
			// the paths to base, and the names are compared without Within.
			if g, w := withoutWithin(importView(got, base)), withoutWithin(want); fmt.Sprint(g) != fmt.Sprint(w) {
				t.Errorf("check %s from %s\n got: %q\nwant: %q", sp.target, sp.dir, g, w)
			}
		})
	}
}

// withoutWithin blanks the within field of importView's artifact rows.
func withoutWithin(rows []string) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		f := strings.Split(r, "|")
		if len(f) == 4 {
			f[1] = ""
		}
		out[i] = strings.Join(f, "|")
	}
	return out
}
