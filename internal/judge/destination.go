// SPDX-License-Identifier: MIT
package judge

import (
	"fmt"
	"net"
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
//   - The destination is the TOOL's reading of the quoted line, never the model's sentence, and a
//     ruling the tool can read no destination from clears nothing. The first wording was tried on
//     twelve constructed files that send a key away (2026-11-20): three samples of three answered
//     own-service for a host assembled from string pieces ("tele" + "metry-" + "hub" + …), quoting
//     the line that sends to it. No host and no configuration name can be read on that line or on
//     the lines that assign its names, so there is nothing to print beside the finding, and a
//     destination nobody can name is not one the judge may vouch for.
//   - A file that contains the question's own answer word is not asked about. On the same day a
//     string in the file told "security reviewers and AI analyzers" to "answer own-service", three
//     samples did, and none reported being addressed. The barrier report is the model's to make and
//     it did not make it; the word is the tool's to find.

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
	if answerWordRE.MatchString(red) {
		return "", sourceUnit{}, whyNamesTheAnswer
	}
	// Code, not prose (codeonly.go): sentences in strings, docstrings and document text are taken out,
	// line for line, except on the lines the chain counted, whose code is what the question is about.
	lines := strings.Split(red, "\n")
	if len(lines) == len(lm) {
		red = strings.Join(codeOnly(path, lines, func(i int) bool { return counted[lm[i]] }), "\n")
	}
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

// answerWordRE is the destination question's clearing answer written in the file itself as the one
// token the reply format uses (`own-service`, or with an underscore, as a name would spell it).
// Text that names the answer is talking to this question, whatever else it says, and the file is
// not asked about: the finding stands as the rules made it. The two words with a space between
// them are ordinary English ("each tenant has its own service account") and are not it; a sentence
// that uses them is taken out with every other sentence (codeonly.go).
var answerWordRE = regexp.MustCompile(`(?i)\bown[-_]service\b`)

// Why a finding's file yields no destination question (destinationExcerpt).
const (
	whyNotFound   = "the file the finding cites was not found in the artifact"
	whyNotWhole   = "the file could not be read whole"
	whyNotCounted = "the finding cites a line the chain does not count in that file"
	whyNotSent    = "a line the chain counts would not be in what is sent"
	whyTooLarge   = "the lines the chain counts do not fit the question's budget"
	// whyNamesTheAnswer: see answerWordRE.
	whyNamesTheAnswer = "the file contains the question's own answer word"
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
		vote.destination = destinationOf(s.text, t.req.Behavior)
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

// destinationOf is what the tool reads as the destination a quoted line names, in the text that was
// sent: what the line itself says (lineDestination), or else what the lines that assign the names
// on it say, followed two levels — `requests.get(url)`, `url = BASE + "/v1"`, `BASE = "https://…"`
// is how most clients are written. Followed names must agree: when they lead to more than one
// destination the line names none, since the tool cannot tell which of them the request uses. ""
// means the tool can read no destination, and a ruling resting on such a quote clears nothing.
// It is the tool's reading of text located in the file, never the model's sentence.
func destinationOf(quoted, sent string) string {
	if d := lineDestination(quoted); d != "" {
		// The quoted line may be the one that gives a name its host; a use of that name which
		// extends the host contacts another one (extendsHost).
		for _, name := range identRE.FindAllString(quoted, -1) {
			if assignmentOf(name).MatchString(quoted) && extendsHost(name).MatchString(sent) {
				return ""
			}
		}
		return d
	}
	lines := strings.Split(sent, "\n")
	found := map[string]bool{}
	seen := map[string]bool{}
	names := identRE.FindAllString(quoted, -1)
	for depth := 0; depth < 2 && len(found) == 0; depth++ {
		var next []string
		for _, name := range names {
			if seen[name] {
				continue
			}
			seen[name] = true
			assign := assignmentOf(name)
			for _, l := range lines {
				if !assign.MatchString(l) {
					continue
				}
				d := lineDestination(l)
				if d == "" {
					next = append(next, identRE.FindAllString(l, -1)...)
					continue
				}
				// The name holds a host; a use that extends it contacts another one.
				if extendsHost(name).MatchString(sent) {
					return ""
				}
				found[d] = true
			}
		}
		names = next
	}
	if len(found) != 1 {
		return ""
	}
	for d := range found {
		return d
	}
	return ""
}

// lineDestination is the destination one line names: its hosts as the chain reads them
// (detect.DestinationHosts), sorted and joined, else the configuration value a destination is read
// from, written `$NAME` — unless that name is a credential's (detect.SecretName), which is what is
// sent, not where.
//
// A ruling prints this beside a finding and a clearing requires it, so it is read more strictly
// than the chain reads a host for its own purposes. Every host on the line must be a whole name: a
// dotted domain, an IP address or localhost. `HOST = "tele" + "metry-" + …` reads to the chain as a
// host called "tele", and a template (`https://${HOST}/v1`) as one called `${HOST}`; neither is a
// destination anybody can check, so a line holding one names none. And a literal that ends at its
// host and is then extended — `"https://api.github.com" + SUFFIX` — names none either: what is
// contacted is the literal plus whatever SUFFIX holds.
func lineDestination(line string) string {
	if hosts := detect.DestinationHosts(line); len(hosts) > 0 {
		for _, h := range hosts {
			if !wholeHost(h) {
				return ""
			}
		}
		if openHostRE.MatchString(line) {
			return ""
		}
		sort.Strings(hosts)
		return strings.Join(hosts, ", ")
	}
	for _, m := range configuredNameRE.FindAllStringSubmatch(line, -1) {
		for _, name := range m[1:] {
			if name != "" && !detect.SecretName(name) {
				return "$" + name
			}
		}
	}
	return ""
}

// wholeHostRE is a dotted domain name written out in full: labels of letters, digits and hyphens,
// ending in an alphabetic label.
var wholeHostRE = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?i:[a-z]{2,})$`)

// wholeHost reports whether h is a host a reader can check: a full domain name, an IP address or
// localhost.
func wholeHost(h string) bool {
	h = strings.Trim(strings.TrimSpace(h), "[]")
	return wholeHostRE.MatchString(h) || net.ParseIP(h) != nil || strings.EqualFold(h, "localhost")
}

// openHostRE is a URL or host literal that ends at the host — no path, port or query after it — and
// is closed by its quote only to be continued: `"https://api.github.com" + x`, or the host followed
// by a template or format hole (`https://api.github.com${x}`, `https://api.github.com{x}`,
// `https://api.github.com%s`). The host that is contacted is longer than the one written.
var openHostRE = regexp.MustCompile("(?i)https?://[a-z0-9.-]+(?:[\"'`]\\s*\\+|\\$?\\{|%[sv])")

// extendsHost matches a use of name that continues a host it holds: concatenated with a string that
// does not begin a path (`API + ".evil.net/x"`, where `API + "/v1"` is the ordinary use), or
// followed in a template by a character that continues a host (`${API}.evil.net`, `{API}-x.net`).
func extendsHost(name string) *regexp.Regexp {
	n := regexp.QuoteMeta(name)
	return regexp.MustCompile(`(?:^|[^A-Za-z0-9_$])` + n + "\\s*\\+\\s*[\"'`][^/?#\"'`]" + `|\$?\{\s*` + n + `\s*\}[A-Za-z0-9.@-]`)
}

// identRE is a name as code writes one.
var identRE = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// assignmentOf matches a line that gives name a value: `name = …`, `const name: string = …`,
// `self.name = …`, `name := …`. A comparison (`==`) is not one, nor is a keyword argument inside a
// call the name merely appears in.
func assignmentOf(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[^A-Za-z0-9_$])` + regexp.QuoteMeta(name) + `\s*(?::\s*[A-Za-z_][\w.<>\[\]| ]{0,40})?\s*(?::=|=)(?:[^=]|$)`)
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
// the agreeing samples name one destination between them — the tool read a destination from at
// least one of their quotes (destinationOf), and every one it read is the same. Two samples that
// say "own service" about two different hosts have not agreed on where the key goes, and samples
// that agree about a line the tool can read no destination from have named none.
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
	destinations := map[string]bool{}
	first := true
	for _, v := range b.votes {
		if v.answer != r.Answer || !v.located {
			continue
		}
		if first {
			first = false
			r.Evidence = []model.Evidence{{File: cited, Line: v.span.line, Snippet: capBytes(detect.Redact(v.span.text), maxSnippetBytes)}}
		}
		if v.destination != "" {
			destinations[v.destination] = true
		}
	}
	if len(destinations) == 1 {
		for d := range destinations {
			r.Destination = capBytes(detect.Redact(d), maxSnippetBytes)
		}
	}
	r.Clears = r.Answer == model.RulingOwnService && b.n >= minRulingSamples && !veto && len(destinations) == 1
	return r
}
