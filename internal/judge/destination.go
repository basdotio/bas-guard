// SPDX-License-Identifier: MIT
package judge

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/basdotio/bas-guard/internal/collect"
	"github.com/basdotio/bas-guard/internal/detect"
	"github.com/basdotio/bas-guard/internal/model"
	"github.com/basdotio/bas-guard/internal/score"
)

// The destination question (P-142, spec §5.2.1).
//
// EXFIL-001 and EXFIL-003 report that one file reads a credential and sends something; their own
// text calls that "a suspicious-surface flag, not confirmed exfiltration", and they are on more
// benign samples than malicious ones because an API client is exactly that shape. Since P-142 the
// judge is asked, per such finding, where the credentials in that file go, and a majority that
// answers "its own service" takes the finding out of the judged score (score.Judged). The finding
// itself is never touched: it stays in the report at its severity, with the ruling beside it, and
// the deterministic score and --fail-on do not read the ruling.
//
// This is the one place the judge's answer can make a result count for LESS than the rules made
// it, so every rule below is on the side of not clearing:
//
//   - The question is about a finding the rules produced, of a rule in a closed set
//     (score.Unconfirmed). No other finding is asked about and no reply can name one.
//   - The model is shown the whole file, or every line the chain counted as a leg with the lines
//     around it (detect.ChainLines), or it is not asked. A ruling on part of a file would clear the
//     part the model did not see: the excerpt the other passes read is a file's head and tail, and a
//     send spliced into the middle of a large file is how the corpus's injected servers are built.
//   - Only a positive answer clears: a majority of at least three samples saying own-service, each
//     quoting a line that is located in what was sent, naming one destination between them, with no
//     sample reporting that the content addressed the analyzer. Silence, "unclear", a failed call,
//     a file that did not fit: nothing is cleared, and the result is what it is with the judge off.

// maxDestinationBytes is the question's own budget: what one file may send. It is not the
// behaviour excerpt's (maxExcerptBytes), which is shared by a whole tree and unchanged. Measured on
// the 424 corpus files that carry the finding: half are over 12,000 bytes, so sending whole files
// is not an option, while the lines the chain counted with their context fit 8,000 bytes on more
// than nine files in ten.
const maxDestinationBytes = 8000

// destinationContext is how many lines either side of a counted line are sent with it.
const destinationContext = 5

// minRulingSamples is the fewest samples a ruling is taken from. One draw must not clear a high
// finding (P-046's reasoning, in the other direction), so the question is asked at least this many
// times whatever llm.samples says; the default configuration asks every other question once.
const minRulingSamples = 3

// rulingSamples is how many times the destination question is asked at a run's sample count.
func rulingSamples(samples int) int {
	if samples < minRulingSamples {
		return minRulingSamples
	}
	return samples
}

// asksDestination reports whether the destination question is asked of artifacts of this kind: the
// two tree kinds the judge reads the code of. A plain directory, a plugin tree, a hook or an MCP
// entry is not asked, so a finding there keeps counting (P-142, Out of scope).
func asksDestination(k model.ArtifactKind) bool {
	return k == model.KindSkill || k == model.KindServer
}

// destinationQuestions returns one destination question per unconfirmed finding of artifact i whose
// file can be shown as the question requires, in the order of the findings. A finding whose file
// cannot be found, read whole or made to fit yields no question and so no ruling.
func destinationQuestions(i int, a model.ArtifactReport, label string, eg egress) []task {
	if !asksDestination(a.Kind) {
		return nil
	}
	var out []task
	for j, f := range a.Findings {
		if !score.Unconfirmed(f) || len(f.Evidence) == 0 {
			continue
		}
		text, unit, why := destinationExcerpt(a.Path, f, eg)
		if why != "" {
			continue
		}
		out = append(out, task{kind: taskJudge, artifact: i, label: label, target: j,
			req: Request{Artifact: label, Mode: ModeDestination, Behavior: text}, units: []sourceUnit{unit}})
	}
	return out
}

// destinationExcerpt is what the destination question about finding f is shown: the file the
// finding is in, redacted and condensed like any excerpt, whole when that fits maxDestinationBytes
// and otherwise cut down to the lines the chain counted (detect.ChainLines) with destinationContext
// lines around each. why is empty when there is something to ask. Otherwise nothing is asked and why
// says which bar was missed (the whyNot* values): the file is not found under root by the rules' own
// predicate, was not read whole, holds a line of the finding that the chain does not list (the file
// is not the one the rules read, or the two readings disagree), or does not fit even cut down.
func destinationExcerpt(root string, f model.Finding, eg egress) (text string, unit sourceUnit, why string) {
	path, rel, found := evidenceFile(root, f.Evidence[0].File)
	if !found {
		return "", sourceUnit{}, whyNotFound
	}
	raw := readAtMost(path, maxFileRead)
	if raw == nil || len(raw) >= maxFileRead {
		return "", sourceUnit{}, whyNotWhole // unread, or longer than the reader takes: not the whole file
	}
	legs, assigns := detect.ChainLines(rel, string(raw))
	counted := map[int]bool{}
	for _, n := range legs {
		counted[n] = true
	}
	for _, e := range f.Evidence {
		if e.File != f.Evidence[0].File || !counted[e.Line] {
			return "", sourceUnit{}, whyNotCounted
		}
	}
	for _, n := range assigns {
		counted[n] = true
	}

	// Redact before anything is cut (invariant #3). Redaction rewrites inside a line and never adds
	// or removes one, so the chain's line numbers, taken from the file as it is on disk, still name
	// the same lines.
	red, lm := condense(path, eg.redact(string(raw)), true)
	if len(red) > maxDestinationBytes {
		red, lm = aroundLines(red, lm, counted, destinationContext)
	}
	sent := map[int]bool{}
	for _, n := range lm {
		sent[n] = true
	}
	for n := range counted {
		if !sent[n] {
			return "", sourceUnit{}, whyNotSent // a counted line is not in what would be sent
		}
	}
	out := fixRedact(red)
	if out == "" || len(out) > maxDestinationBytes || strings.Count(out, "\n") != strings.Count(red, "\n") {
		return "", sourceUnit{}, whyTooLarge
	}
	return out, sourceUnit{file: detect.Redact(rel), text: out, firstLine: 1, lineMap: lm}, ""
}

// Why a finding's file yields no destination question (destinationExcerpt).
const (
	whyNotFound   = "the file the finding cites was not found in the artifact"
	whyNotWhole   = "the file could not be read whole"
	whyNotCounted = "the finding cites a line the chain does not count in that file"
	whyNotSent    = "a line the chain counts would not be in what is sent"
	whyTooLarge   = "the lines the chain counts do not fit the question's budget"
)

// evidenceFile finds the file a static finding cites inside the artifact rooted at root. The
// citation is relative to the scan's root, the artifact to wherever it was collected, so the file is
// the citation's longest path suffix that names a regular file the rules' predicate reads
// (collect.FileReach, invariant #2): `skills/x/scripts/a.py` under the skill x is `scripts/a.py`.
// rel is that suffix.
func evidenceFile(root, cited string) (path, rel string, ok bool) {
	segs := strings.Split(filepath.ToSlash(cited), "/")
	for k := range segs {
		rel = filepath.Join(segs[k:]...)
		if rel == "" || rel == "." || strings.HasPrefix(rel, "..") {
			continue
		}
		path = filepath.Join(root, rel)
		if collect.FileReach(root, path).Kind != collect.Read {
			continue
		}
		if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
			return path, rel, true
		}
	}
	return "", "", false
}

// aroundLines cuts condensed text down to the lines whose original number is within ctx of a line
// in keep, with an omission marker wherever lines were left out, and returns it with its line map.
// A marker maps to the first line it stands for, as capHeadTail's does.
func aroundLines(text string, lm []int, keep map[int]bool, ctx int) (string, []int) {
	lines := strings.Split(text, "\n")
	if len(lm) != len(lines) {
		return text, lm // a map that does not fit the text: leave it whole, the size check refuses it
	}
	near := make([]bool, len(lines))
	for i, n := range lm {
		if !keep[n] {
			continue
		}
		for k := i - ctx; k <= i+ctx; k++ {
			if k >= 0 && k < len(lines) {
				near[k] = true
			}
		}
	}
	var out []string
	var outLM []int
	for i := 0; i < len(lines); {
		if near[i] {
			out, outLM = append(out, lines[i]), append(outLM, lm[i])
			i++
			continue
		}
		j := i
		for j < len(lines) && !near[j] {
			j++
		}
		out, outLM = append(out, fmt.Sprintf(omittedLinesMarker, j-i)), append(outLM, lm[i])
		i = j
	}
	return strings.Join(out, "\n"), outLM
}

// rulingVote is one sample's answer to the destination question.
type rulingVote struct {
	answer string       // model.RulingOwnService, RulingElsewhere or RulingUnclear
	span   groundedSpan // where its quote was located in what was sent; set when located is
	// located says the quote was found. An own-service answer that cannot be located is not an
	// own-service answer (groundedRuling), so for that answer it is always true. quoted says the
	// sample quoted anything at all: a quote that could not be located is a sample that struggled,
	// which keeps every sample of its question in play (result.clean, as P-103 has it for findings).
	located, quoted bool
	// destination is what the tool read on the quoted line: its hosts, else the configuration name
	// a value is read from, else nothing.
	destination string
	// barrier says the sample reported that the content addressed the analyzer, whether or not it
	// could quote it. For a finding that is enough to say so only when quoted (LLM-007); for a
	// ruling the claim alone is a reason not to clear.
	barrier bool
}

// groundedRuling reads one sample's verdict as a vote on the destination question, and the LLM-007
// finding it carries when the content addressed the analyzer and the model could quote it.
//
// The answer is the tool's reading of the reply, on the side of not clearing: a category outside
// the closed list is unclear; own-service with flagged=true contradicts itself and is unclear;
// own-service whose quote cannot be located in what was sent is unclear, because a destination
// nobody can point at is not one. flagged=true with no usable category is elsewhere — the sample
// reported a problem and did not say which.
func groundedRuling(t task, v Verdict) (vote rulingVote, barrier *model.Finding) {
	vote.answer = model.RulingUnclear
	switch cat := categoryName(v); {
	case cat == model.RulingOwnService && !v.Flagged:
		vote.answer = model.RulingOwnService
	case cat == model.RulingElsewhere, v.Flagged && cat != model.RulingOwnService && cat != model.RulingUnclear:
		vote.answer = model.RulingElsewhere
	}
	vote.quoted = strings.TrimSpace(v.Evidence) != ""
	if s, ok := groundSpan(v.Evidence, t.units); ok {
		vote.span, vote.located = s, true
		vote.destination = destinationOf(s.text)
	} else if vote.answer == model.RulingOwnService {
		vote.answer = model.RulingUnclear
	}
	if quote := strings.TrimSpace(v.BarrierEvidence); quote != "" {
		vote.barrier = true
		if s, ok := groundSpan(quote, t.units); ok && !isBareName(s.text) {
			b := barrierFinding(t.req)
			b.Evidence[0] = s.evidence()
			barrier = b
		}
	}
	return vote, barrier
}

// configuredNameRE is a destination taken from configuration rather than written in the file: an
// environment variable read in Node or Python. The name is what the ruling can say about a
// destination that has no host in the source. A `$NAME` or `${NAME}` reference is deliberately not
// one: it is how a line USES a base URL set elsewhere (a shell variable, a template literal), and
// reading it as a destination of its own made a quote of the line that sets the host and a quote of
// the line that uses it name two different destinations.
var configuredNameRE = regexp.MustCompile(`process\.env\.([A-Za-z_][A-Za-z0-9_]*)|process\.env\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]` +
	`|os\.environ(?:\.get\(|\[)\s*["']([A-Za-z_][A-Za-z0-9_]*)["']|getenv\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']`)

// destinationOf is what the tool reads as the destination on a quoted line: the hosts it names
// (detect.DestinationHosts, the chain's own reading), sorted and joined, else the configuration
// name a value is read from, written `$NAME`, else "". It is the tool's reading of text located in
// the file, never the model's sentence.
func destinationOf(line string) string {
	if hosts := detect.DestinationHosts(line); len(hosts) > 0 {
		sort.Strings(hosts)
		return strings.Join(hosts, ", ")
	}
	if m := configuredNameRE.FindStringSubmatch(line); m != nil {
		for _, name := range m[1:] {
			if name != "" {
				return "$" + name
			}
		}
	}
	return ""
}

// rulingBallot collects the samples of one destination question.
type rulingBallot struct {
	artifact int
	target   int // index of the finding in the artifact's findings, as planned
	n        int // samples the question was planned at
	votes    []rulingVote
	barriers []model.Finding
}

func (b *rulingBallot) cast(r result) {
	if r.vote != nil {
		b.votes = append(b.votes, *r.vote)
	}
	if r.barrier != nil {
		b.barriers = append(b.barriers, *r.barrier)
	}
}

// ruling decides the question. cited is the file as the static finding names it, which is how the
// ruling's evidence names it too: the two are printed side by side.
//
// Clears is set only when every bar holds: own-service is the answer of a majority of at least
// minRulingSamples planned samples; no sample reported the content addressing the analyzer; and
// the agreeing samples name one destination between them — every destination the tool read from
// their quotes is the same one, or, when none of the quoted lines names a destination, they all
// quoted the same line. Two samples that say "own service" about two different hosts have not
// agreed on where the key goes.
func (b *rulingBallot) ruling(cited string) model.Ruling {
	count := map[string]int{}
	veto := false
	for _, v := range b.votes {
		count[v.answer]++
		veto = veto || v.barrier
	}
	r := model.Ruling{Answer: model.RulingUnclear, K: count[model.RulingUnclear], N: b.n}
	for _, a := range []string{model.RulingOwnService, model.RulingElsewhere} {
		if count[a] >= majority(b.n) {
			r.Answer, r.K = a, count[a]
		}
	}
	if r.Answer == model.RulingUnclear {
		return r
	}
	destinations, lines := map[string]bool{}, map[int]bool{}
	first := true
	for _, v := range b.votes {
		if v.answer != r.Answer || !v.located {
			continue
		}
		if first {
			first = false
			r.Evidence = []model.Evidence{{File: cited, Line: v.span.line, Snippet: capBytes(detect.Redact(v.span.text), maxSnippetBytes)}}
		}
		lines[v.span.line] = true
		if v.destination != "" {
			destinations[v.destination] = true
		}
	}
	if len(destinations) == 1 {
		for d := range destinations {
			r.Destination = capBytes(detect.Redact(d), maxSnippetBytes)
		}
	}
	oneDestination := len(destinations) == 1 || (len(destinations) == 0 && len(lines) == 1)
	r.Clears = r.Answer == model.RulingOwnService && b.n >= minRulingSamples && !veto && oneDestination
	return r
}
