// SPDX-License-Identifier: MIT
package judge

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/basdotio/bas-guard/internal/collect"
	"github.com/basdotio/bas-guard/internal/detect"
	"github.com/basdotio/bas-guard/internal/model"
)

// code returns a script body of about n bytes: numbered lines, none a comment, so condense keeps them
// all and the per-file cap is what cuts it.
func code(tag string, n int) string {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, "%s_%04d = compute(%d)\n", tag, i, i)
	}
	return b.String()
}

// tree writes files under a fresh directory and returns it.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		writeFile(t, filepath.Join(dir, filepath.FromSlash(rel)), body)
	}
	return dir
}

// third returns a script body that, under its `# <rel>` header, takes exactly a third of the excerpt:
// three such files fill it to the byte, so a fourth has no room and no fragment of it is sent.
func third(rel string) string {
	n := maxExcerptBytes/3 - len("# "+rel+"\n") - 2
	var b strings.Builder
	for b.Len()+50 < n {
		b.WriteString(strings.Repeat("v", 49) + "\n")
	}
	b.WriteString(strings.Repeat("w", n-b.Len()) + "\n")
	return b.String()
}

// thirds maps each name to a body that takes a third of the excerpt.
func thirds(names ...string) map[string]string {
	m := map[string]string{}
	for _, n := range names {
		m[n] = third(n)
	}
	return m
}

// TestBehaviorExcerpt_SaysHowManyFilesItLeftOut (P-149): the behaviour excerpt takes files by name until
// 6,000 bytes are spent. The files after that were never shown and nothing said so — P-037 named it as
// one of two judge limits still silent. The rows come in pairs: what is left out is counted, and what is
// not a file left out is not.
func TestBehaviorExcerpt_SaysHowManyFilesItLeftOut(t *testing.T) {
	with := func(m map[string]string, rel, body string) map[string]string {
		m[rel] = body
		return m
	}
	for _, c := range []struct {
		name  string
		files map[string]string
		skip  map[string]bool
		sent  int
		want  string
	}{
		{"five scripts, three fill the excerpt",
			thirds("a.py", "b.py", "c.py", "d.py", "e.py"), nil, 3,
			"2 of 5 script or config file(s) past the 6000-byte excerpt not sent"},
		{"nine, as a document-tooling skill ships them, the one to run first sorting last",
			thirds("s/a.py", "s/b.py", "s/c.py", "s/d.py", "s/e.py", "s/f.py", "s/g.py", "s/h.py", "s/prepare_environment.py"), nil, 3,
			"6 of 9 script or config file(s) past the 6000-byte excerpt not sent"},
		{"a config file past the budget is a file left out too",
			with(thirds("a.py", "b.py", "c.py"), "z.yaml", "run: make\n"), nil, 3,
			"1 of 4 script or config file(s) past the 6000-byte excerpt not sent"},
		{"three that fill it exactly: no note",
			thirds("a.py", "b.py", "c.py"), nil, 3, ""},
		{"three small scripts: no note",
			map[string]string{"a.sh": "echo a\n", "b.sh": "echo b\n", "c.sh": "echo c\n"}, nil, 3, ""},
		{"one script of 50 KB is cut to its cap, not left out",
			map[string]string{"a.py": code("a", 50000)}, nil, 1, ""},
		{"the third is cut to the room left, not left out",
			with(thirds("a.py", "b.py"), "c.py", code("c", 2500)), nil, 3, ""},
		{"a document past the budget is not a script",
			with(thirds("a.py", "b.py", "c.py"), "z.md", strings.Repeat("prose\n", 500)), nil, 3, ""},
		{"a vendored directory is not walked, so not counted",
			with(thirds("a.py", "b.py", "c.py"), "node_modules/x/index.js", code("x", 2500)), nil, 3, ""},
		{"a directory the server pass skips is not counted",
			with(thirds("a.py", "b.py", "c.py"), "z/.github/workflows/z.yml", "on: push\n"), serverSkipDirs, 3, ""},
		{"and is counted by the skill pass, which reads it",
			with(thirds("a.py", "b.py", "c.py"), "z/.github/workflows/z.yml", "on: push\n"), nil, 3,
			"1 of 4 script or config file(s) past the 6000-byte excerpt not sent"},
	} {
		t.Run(c.name, func(t *testing.T) {
			text, units, shortened := behaviorExcerptSkipping(tree(t, c.files), egress{}, c.skip)
			if shortened != c.want {
				t.Errorf("shortened = %q, want %q", shortened, c.want)
			}
			if len(units) != c.sent {
				t.Errorf("%d unit(s), want %d", len(units), c.sent)
			}
			for _, u := range units {
				if !strings.Contains(text, "# "+u.file+"\n"+u.text) {
					t.Errorf("the unit of %s is not in the text sent", u.file)
				}
			}
			if len(text) > maxExcerptBytes {
				t.Errorf("excerpt is %d bytes, over the %d-byte cap", len(text), maxExcerptBytes)
			}
		})
	}
}

// stoppedWalk is the behaviour excerpt as it was before P-149, kept here as the reference: the walk
// stops (SkipAll) at the first file with no room, and nothing is counted.
func stoppedWalk(dir string, eg egress, skip map[string]bool) string {
	var files, texts []string
	total := 0
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if collect.ExcludedFromScan(d.Name()) || (p != dir && skip[d.Name()]) {
				return filepath.SkipDir
			}
			return nil
		}
		if collect.FileReach(dir, p).Kind != collect.Read || !behaviorExts[strings.ToLower(filepath.Ext(p))] {
			return nil
		}
		raw := readAtMost(p, maxFileRead)
		if raw == nil {
			return nil
		}
		red, lm := condense(p, eg.redact(string(raw)), true)
		red, lm = capHeadTail(red, lm, maxFileBytes)
		rel, _ := filepath.Rel(dir, p)
		header := "# " + detect.Redact(rel) + "\n"
		room := maxExcerptBytes - total - len(header) - 2
		if room <= 0 {
			return filepath.SkipAll
		}
		red, _ = capHeadTail(red, lm, room)
		files, texts = append(files, detect.Redact(rel)), append(texts, red)
		total += len(header) + len(red) + 2
		return nil
	})
	text, _, _ := fitUnits(texts, maxExcerptBytes, headed(files))
	return text
}

// TestBehaviorExcerpt_SendsWhatTheStoppedWalkSent (P-149): counting the files past the budget means the
// walk goes on where it used to stop, and it must send the same bytes. The row that would differ: after
// the first file with no room, a later file with a shorter name has room for a fragment. The stopped
// walk never tried it; a walk that only counts must not either.
func TestBehaviorExcerpt_SendsWhatTheStoppedWalkSent(t *testing.T) {
	short := map[string]string{
		"a.py": code("a", 2500), "b.py": code("b", 2500), "c.py": code("c", 2500),
		"d_" + strings.Repeat("long_name_", 8) + ".py": code("d", 400),
		"e.py": code("e", 400),
	}
	for name, files := range map[string]map[string]string{
		"a later, shorter name": short,
		"nine scripts": {"s/1.py": code("a", 900), "s/2.py": code("b", 3000), "s/3.sh": code("c", 700), "s/4.js": code("d", 2600),
			"s/5.py": code("e", 100), "s/6.py": code("f", 5000), "s/7.py": code("g", 10), "s/8.py": code("h", 2000), "s/9.py": code("i", 2000)},
		"all fit":      {"a.sh": "echo a\n", "lib/b.sh": "echo b\n", "c.json": "{\"k\": 1}\n"},
		"an empty one": {"a.py": code("a", 2500), "pkg/__init__.py": "", "z.py": code("z", 2500)},
		"none":         {"README.md": "# readme\n"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := tree(t, files)
			for _, skip := range []map[string]bool{nil, serverSkipDirs} {
				got, _, _ := behaviorExcerptSkipping(dir, newEgress("/home/none"), skip)
				if want := stoppedWalk(dir, newEgress("/home/none"), skip); got != want {
					t.Errorf("the excerpt changed:\n got %d bytes …%q\nwant %d bytes …%q", len(got), tailOf(got, 80), len(want), tailOf(want, 80))
				}
			}
		})
	}
	// The row above is only a test if the shorter name did have room.
	text, _, shortened := behaviorExcerptSkipping(tree(t, short), egress{}, nil)
	if room := maxExcerptBytes - len(text) - len("# e.py\n") - 2; room <= 0 {
		t.Fatalf("precondition: e.py must have had room after the excerpt ended (room %d)", room)
	}
	if strings.Contains(text, "# e.py") || shortened != "2 of 5 script or config file(s) past the 6000-byte excerpt not sent" {
		t.Errorf("e.py must be left out and counted with the file before it: shortened %q", shortened)
	}
}

// TestRun_ScriptsLeftOutAreDisclosed (P-149): what the excerpt left out reaches the report as one LLM-000
// naming the artifact (invariant #5), for a skill's intent pass and a server's source pass, and reaches
// `llm preview` as the call's shortened. Reverse: a tree that fits produces no note — a note on every
// scan would teach the reader to skip it.
func TestRun_ScriptsLeftOutAreDisclosed(t *testing.T) {
	skill := func(name string, scripts int) model.ArtifactReport {
		files := map[string]string{"SKILL.md": "---\nname: " + name + "\ndescription: Fills PDF forms.\n---\nRun `python scripts/s9.py` first.\n"}
		for i := 1; i <= scripts; i++ {
			rel := fmt.Sprintf("scripts/s%d.py", i)
			files[rel] = third(rel)
		}
		return model.ArtifactReport{Kind: model.KindSkill, Name: name, Path: tree(t, files)}
	}
	// The modules sort before server.py, so with five of them the file that declares the tools is one
	// of the three left out; the declared side is read from it all the same (serverDeclared).
	server := func(name string, modules int) model.ArtifactReport {
		files := map[string]string{"server.py": serverSource}
		for i := 1; i <= modules; i++ {
			rel := fmt.Sprintf("lib/m%d.py", i)
			files[rel] = third(rel)
		}
		return model.ArtifactReport{Kind: model.KindServer, Name: name, Path: tree(t, files), Findings: []model.Finding{}}
	}
	for _, c := range []struct {
		name string
		art  model.ArtifactReport
		mode Mode
		want string // "" = no note
	}{
		{"a skill of nine scripts", skill("forms", 9), ModeIntent, "skill:forms (6 of 9 script or config file(s) past the 6000-byte excerpt not sent)"},
		{"a skill of three", skill("small", 3), ModeIntent, ""},
		{"a server of six modules", server("status", 5), ModeServer, "server:status (3 of 6 script or config file(s) past the 6000-byte excerpt not sent)"},
		{"a server of one", server("one", 0), ModeServer, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			mode := c.mode
			calls := planOf(c.art, &mode)
			if len(calls) != 1 {
				t.Fatalf("want one call of the pass, got %d", len(calls))
			}
			if got := calls[0].Shortened; (c.want == "") != (got == "") || !strings.Contains(c.want, "("+got+")") && got != "" {
				t.Errorf("the call's shortened = %q, want the part in parentheses of %q", got, c.want)
			}
			notes, _ := Run(context.Background(), &fakeClient{}, []model.ArtifactReport{c.art}, Options{})
			var got []string
			for _, n := range notes {
				if n.RuleID == "LLM-000" && n.Dimension == 0 && strings.Contains(n.Why, "script or config file(s)") {
					got = append(got, n.Why)
				}
			}
			switch {
			case c.want == "" && len(got) != 0:
				t.Errorf("a tree that fits must not produce the note, got %q", got)
			case c.want != "" && (len(got) != 1 || !strings.Contains(got[0], c.want) || !strings.Contains(got[0], "was not judged")):
				t.Errorf("want one LLM-000 saying %q and that it was not judged, got %q", c.want, got)
			}
		})
	}

	// The plan of a tree is the same calls as before, the count beside them: the nine-script skill's
	// intent request is the stopped walk's bytes under the declared purpose.
	art := skill("forms", 9)
	mode := ModeIntent
	got := planOf(art, &mode)[0].Behavior
	if want := stoppedWalk(art.Path, egress{}, nil); got != want {
		t.Errorf("the intent request changed: %d bytes, the stopped walk sends %d", len(got), len(want))
	}
	// Must not claim: the script SKILL.md says to run first is among the six, and is still not shown.
	if strings.Contains(got, "scripts/s9.py") {
		t.Errorf("s9.py is past the budget and must not be in the request; the note is what changed, not the order")
	}
}
