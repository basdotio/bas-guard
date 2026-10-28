// SPDX-License-Identifier: MIT

package aguard

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/basdotio/bas-guard/internal/model"
	"github.com/basdotio/bas-guard/internal/score"
)

// Locator maps a path aguard reported back onto the sample tree it was staged from.
//
// The corpus's verdict record has an optional `files` field: which files the scanner flagged,
// relative to the sample tree. On a caught malicious sample whose label quotes the deciding line
// the scorer then asks whether one of them is the file the quote came from — caught for the
// right reason, as opposed to flagged the tree. Without the field the location line reads "no
// data", which is what every aguard run before this reported.
//
// aguard cannot be asked for sample-relative paths, because it never sees the sample tree: Stage
// copies the tree into a fake home, by content, and the binary reports paths from there. What it
// reports is also not relative to any one base — a skill's evidence is relative to the config
// root (`skills/<id>/SKILL.md`), a hook's to the home (`.claude/settings.json`), a project MCP
// config's to the work directory (`home/.mcp.json`), a permission's to its own file
// (`settings.json`), a tool catalogue's to the staged session directory (`sample/local_0.json`),
// measured on the 2026-10 raw/ of 3,539 samples. So the mapping does not resolve against a base;
// it looks for the markers Stage itself laid down and inverts them.
//
// It is a pure function of strings plus what Stage knew, on purpose: Rebuild must produce the
// row Scan produced from raw/ bytes whose work directory has been scrubbed to `<work>` and on a
// machine whose staging directory is elsewhere, so nothing here may touch the file system or the
// adapter's Work.
type Locator struct {
	// ID is the sample id; a SKILL.md-placed tree sits under skills/<base(ID)>.
	ID string
	// Loose is the one instruction file staged as CLAUDE.md when placement was loose (see
	// StagedRoot.Loose), and "" otherwise.
	Loose string
	// Tree is the absolute sample tree, for the `check` route, where aguard reports paths
	// against the tree itself. "" when unknown; a relative evidence path then passes through.
	Tree string
}

// labelRE is the shape of judge.artifactLabel, `kind:name`.
var labelRE = regexp.MustCompile(`^[a-z_]+:`)

// LocatorFor is the Locator Stage would have produced for tree, without staging it: the same
// loose-instruction test Stage applies, read from the tree's top level. The judge fold uses it,
// because it folds from raw/ long after the staged copy is gone.
func LocatorFor(tree, id string) Locator {
	loc := Locator{ID: id, Tree: tree}
	entries, err := os.ReadDir(tree)
	if err != nil || len(entries) != 1 {
		return loc
	}
	e := entries[0]
	if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ".md") {
		loc.Loose = e.Name()
	}
	return loc
}

// SampleFile maps one evidence path, reported against the artifact at artPath, to a path
// relative to the sample tree. It returns "" when the path names nothing in the tree — a judge
// finding's pre-grounding `kind:name` label, or an empty path.
func (l Locator) SampleFile(artPath, evFile string) string {
	p := slash(evFile)
	if p == "" {
		return ""
	}
	// A judge finding carries its artifact label (`skill:x`) as its file until grounding
	// replaces it with a real location; the label is not a path.
	if !strings.Contains(p, "/") && labelRE.MatchString(p) {
		return ""
	}
	if l.Tree != "" {
		t := slash(l.Tree)
		if strings.HasPrefix(p, t+"/") {
			return strings.TrimPrefix(p, t+"/")
		}
		// detect.relPath resolves the root's symlinks before Rel and, when that makes Rel
		// fail (a tree under macOS /var, which is /private/var), falls back to a two-segment
		// tail `<dir>/<base>` — the tree's own name and the file. That is the `check` route on
		// a temp-dir corpus, not a sub-directory of the sample.
		if parts := strings.Split(p, "/"); len(parts) == 2 && parts[0] == path.Base(t) {
			return parts[1]
		}
	}
	// Absolute or scrubbed-absolute: everything before the staged home is machine, not sample.
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "<work>/") {
		if i := strings.Index(p, "/home/"); i >= 0 {
			p = p[i+len("/home/"):]
		}
	}
	if out, ok := l.invert(p); ok {
		return out
	}
	// No marker in the evidence path itself: it is relative to the artifact, and the artifact's
	// own path carries the marker (a permission finding says `settings.json` against
	// `<home>/.claude/settings.json`).
	a := slash(artPath)
	if i := strings.Index(a, ".claude/"); i >= 0 {
		q := a[i:]
		if q != p && !strings.HasSuffix(q, "/"+p) {
			// A hook or permission artifact IS a file (`.claude/settings.json`), and the
			// script it references is reported relative to the config root, so the join
			// starts from the file's directory — the first bench run named
			// `.claude/settings.json/hooks/docs.py`. A skill artifact is a directory.
			if base := path.Base(q); strings.HasSuffix(base, ".json") || strings.HasSuffix(base, ".md") {
				q = path.Dir(q)
			}
			q = path.Join(q, p)
		}
		if out, ok := l.invert(q); ok {
			return out
		}
	}
	return p
}

// invert undoes one of Stage's placements when p carries its marker.
func (l Locator) invert(p string) (string, bool) {
	// SKILL.md placement: the whole tree was copied to <root>/skills/<base(id)>/.
	if l.ID != "" {
		marker := "skills/" + path.Base(slash(l.ID)) + "/"
		if i := strings.Index(p, marker); i >= 0 {
			return p[i+len(marker):], true
		}
	}
	// tools.json placement: the catalogue was rewritten as a desktop session file.
	if p == "local_0.json" || strings.HasSuffix(p, "/local_0.json") {
		return "tools.json", true
	}
	// .mcp.json placement: copied beside the config root.
	if p == ".mcp.json" || strings.HasSuffix(p, "/.mcp.json") {
		return ".mcp.json", true
	}
	// .claude placement: the directory was copied as the config root, so a path from `.claude/`
	// on IS the sample-relative path — except the loose instruction file, which Stage renamed.
	if i := strings.Index(p, ".claude/"); i >= 0 {
		q := p[i:]
		if l.Loose != "" && q == ".claude/CLAUDE.md" {
			return l.Loose, true
		}
		return q, true
	}
	return "", false
}

// FlaggedFiles is the sample-relative files of the findings keep selects, deduplicated and
// sorted, nil when there are none (so the field is omitted from the ledger JSON rather than
// written as an empty list).
func FlaggedFiles(res model.ScanResult, loc Locator, keep func(model.Finding) bool) []string {
	seen := map[string]bool{}
	for _, art := range res.Artifacts {
		for _, f := range art.Findings {
			if !keep(f) {
				continue
			}
			for _, ev := range f.Evidence {
				if p := loc.SampleFile(art.Path, ev.File); p != "" {
					seen[p] = true
				}
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// flaggingAt selects the deterministic findings that carry the flag at threshold — the same
// predicate fill uses for the verdict, so the files named are the files that decided it.
func flaggingAt(threshold model.Severity) func(model.Finding) bool {
	return func(f model.Finding) bool {
		return score.Deterministic(f) && f.Severity.Rank() >= threshold.Rank()
	}
}

func slash(p string) string {
	return strings.TrimSuffix(filepath.ToSlash(p), "/")
}
