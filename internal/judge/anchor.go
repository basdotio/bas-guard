// SPDX-License-Identifier: MIT
package judge

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/basdotio/bas-guard/internal/collect"
	"github.com/basdotio/bas-guard/internal/detect"
	"github.com/basdotio/bas-guard/internal/model"
	"github.com/basdotio/bas-guard/internal/score"
)

// Anchor windows (P-114): the server pass's behaviour excerpt is the head and tail of a few files in
// walk order (behaviorExcerpt). A payload spliced into the middle of a 50 KB server file, or into the
// sixteenth file of a tree, is never in front of the model, while the static rules may already have
// flagged the very line. The windows are a few lines around each such line, under a budget of their own:
//   - Their own budget, never a share of maxExcerptBytes. P-070 moved the shared budget toward named files
//     and pushed out as many payloads as it brought in; the walk-order excerpt here is not shortened by one
//     byte, and a tree with no anchoring finding sends exactly what it sent before.
//   - A neutral header (`# <file> (lines a-b)`): no rule ID and no "flagged". Telling the model a scanner
//     flagged a line primes it toward high on every benign subprocess call (issues/028).
//   - Server pass only. SkillHarm's misses were judgement, not visibility (P-070).
const (
	maxAnchorBytes = 2000 // all windows of one artifact together
	maxAnchors     = 4    // windows per artifact, after merging overlaps
	anchorRadius   = 6    // condensed lines either side of the anchoring line
)

// anchorLine is one (file, line) a deterministic finding points at, with the weight that orders it.
type anchorLine struct {
	path string // absolute
	rel  string // relative to the artifact root, not redacted
	line int
	rank int
}

// anchorsOf returns the lines worth a window: deterministic findings (score.Deterministic, the one
// predicate), medium or above, not advisory, with a line. Low and advisory findings (RES-001 on every
// `while True:`, SUP-003 on imports) sit on every benign server and would spend the budget on noise.
// Highest severity first, then path and line, so the order never depends on the engine's.
func anchorsOf(dir string, findings []model.Finding) []anchorLine {
	seen := map[string]bool{}
	var out []anchorLine
	for _, f := range findings {
		if !score.Deterministic(f) || f.Advisory || f.Severity.Rank() < model.SevMedium.Rank() {
			continue
		}
		for _, e := range f.Evidence {
			if e.Line <= 0 || e.File == "" {
				continue
			}
			p := e.File
			if !filepath.IsAbs(p) {
				p = filepath.Join(dir, p)
			}
			rel, err := filepath.Rel(dir, p)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				continue
			}
			key := fmt.Sprintf("%s:%d", rel, e.Line)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, anchorLine{path: p, rel: rel, line: e.Line, rank: f.Severity.Rank()})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].rank != out[j].rank {
			return out[i].rank > out[j].rank
		}
		if out[i].rel != out[j].rel {
			return out[i].rel < out[j].rel
		}
		return out[i].line < out[j].line
	})
	return out
}

// anchorWindow is one window before it is fitted: condensed lines [from, to) of a file.
type anchorWindow struct {
	a        anchorLine
	from, to int
}

// anchorWindows renders the windows for an artifact whose walk-order excerpt is shown: the text to append
// to the behaviour field, its units for grounding, and what was left out (for boundedNote). A window is
// cut from the file AFTER the whole file is redacted (invariant #3), opened only through
// collect.FileReach (invariant #2), condensed as behaviorExcerpt condenses, and dropped when the
// anchoring line is already in what the walk-order excerpt sent for that file.
func anchorWindows(dir string, findings []model.Finding, shown []sourceUnit, eg egress) (string, []sourceUnit, string) {
	anchors := anchorsOf(dir, findings)
	if len(anchors) == 0 {
		return "", nil, ""
	}
	seenLines := map[string]map[int]bool{} // redacted file → original lines already sent
	for _, u := range shown {
		m := seenLines[u.file]
		if m == nil {
			m = map[int]bool{}
			seenLines[u.file] = m
		}
		// capHeadTail maps its omission marker to the first line it left out: that line was not sent.
		lines := strings.Split(u.text, "\n")
		for k, n := range u.lineMap {
			if k < len(lines) && isOmissionMarker(lines[k]) {
				continue
			}
			m[n] = true
		}
	}

	type fileView struct {
		text      []string
		lm        []int
		goesHome  bool
		overreach bool
		ok        bool
	}
	views := map[string]*fileView{}
	view := func(a anchorLine) *fileView {
		if v, ok := views[a.path]; ok {
			return v
		}
		v := &fileView{}
		views[a.path] = v
		if collect.FileReach(dir, a.path).Kind != collect.Read {
			return v
		}
		raw := readAtMost(a.path, maxFileRead)
		if raw == nil {
			return v
		}
		code := behaviorExts[strings.ToLower(filepath.Ext(a.path))]
		text, lm := condense(a.path, eg.redact(string(raw)), code)
		v.text, v.lm, v.ok = strings.Split(text, "\n"), lm, true
		if len(v.lm) != len(v.text) { // defensive, as capHeadTail is: a map that does not fit is worse than none
			v.ok = false
		}
		v.goesHome = detect.CredentialGoesHome(a.rel, string(raw))
		v.overreach = detect.CredentialOverreach(a.rel, string(raw)) || detect.CredentialSentElsewhere(a.rel, string(raw))
		return v
	}

	var wins []anchorWindow
	for _, a := range anchors {
		if seenLines[detect.Redact(a.rel)][a.line] {
			continue
		}
		v := view(a)
		if !v.ok {
			continue
		}
		// The anchoring line may have been condensed away (a comment): take the first kept line at or after it.
		at := sort.SearchInts(v.lm, a.line)
		if at >= len(v.lm) {
			at = len(v.lm) - 1
		}
		from, to := max(0, at-anchorRadius), min(len(v.lm), at+anchorRadius+1)
		merged := false
		for k := range wins {
			w := &wins[k]
			if w.a.path == a.path && from <= w.to && to >= w.from {
				w.from, w.to = min(w.from, from), max(w.to, to)
				merged = true
				break
			}
		}
		if !merged {
			wins = append(wins, anchorWindow{a: a, from: from, to: to})
		}
	}
	if len(wins) == 0 {
		return "", nil, ""
	}
	dropped := 0
	if len(wins) > maxAnchors {
		dropped = len(wins) - maxAnchors
		wins = wins[:maxAnchors]
	}

	headers := make([]string, len(wins))
	texts := make([]string, len(wins))
	units := make([]sourceUnit, len(wins))
	for k, w := range wins {
		v := views[w.a.path]
		text, lm := capHeadTail(strings.Join(v.text[w.from:w.to], "\n"), append([]int(nil), v.lm[w.from:w.to]...), maxAnchorBytes)
		file := detect.Redact(w.a.rel)
		headers[k] = fmt.Sprintf("%s (lines %d-%d)", file, lm[0], lm[len(lm)-1])
		texts[k] = text
		units[k] = sourceUnit{file: file, firstLine: 1, lineMap: lm, goesHome: v.goesHome, overreach: v.overreach}
	}
	field, sent, left := fitUnits(texts, maxAnchorBytes, headed(headers))
	units = units[:len(sent)]
	for k := range sent {
		units[k].text = sent[k]
	}
	shortened := ""
	if n := left + dropped; n > 0 {
		shortened = fmt.Sprintf("%d of %d window(s) around lines the rules flagged past the %d-byte budget not sent",
			n, len(texts)+dropped, maxAnchorBytes)
	}
	return field, units, shortened
}

// serverBehavior is the server pass's behaviour field: the walk-order excerpt exactly as behaviorExcerpt
// builds it, then the anchor windows. The joined field is held to the same last step as every field
// (a fixed point of Redact, P-037); if joining moved a redaction, the windows are left out and said so,
// rather than sending a field grounding cannot read back.
func serverBehavior(dir string, findings []model.Finding, eg egress) (string, []sourceUnit, string) {
	behavior, units := behaviorExcerpt(dir, eg)
	windows, wunits, shortened := anchorWindows(dir, findings, units, eg)
	if windows == "" {
		return behavior, units, shortened
	}
	joined := behavior + windows
	if fixRedact(joined) != joined {
		return behavior, units, fmt.Sprintf("%d window(s) around lines the rules flagged not sent", len(wunits))
	}
	return joined, append(units, wunits...), shortened
}
