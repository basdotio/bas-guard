// SPDX-License-Identifier: MIT
package detect

import (
	"path"
	"regexp"
	"strings"

	"github.com/basdotio/bas-guard/internal/model"
)

// INJ-005's parts (P-121). The rule is "the agent is made to fetch a remote file and do what it says": the
// author can change what the agent does from a server, after install, and nobody reviewed that text. Before
// P-121 the rule saw one spelling of it — curl/wget/fetch of a URL whose file is NAMED like instructions — so
// renaming steps.md to guide.txt, or writing the same order as a sentence, scored 100. It now reads the
// order itself, in two halves:
//
//   - a line half (in the rule's pattern): a verb that brings a remote file to the agent, a URL and an
//     obedience phrase in ONE sentence ("download https://… and follow the steps it lists"), or an obedience
//     phrase pointed at a URL ("follow the steps in https://…");
//   - a file-level half (remoteOrders): a download kept at a path, and another line telling the agent to
//     obey that path — the code block `curl … -o /tmp/guide.txt` then "read /tmp/guide.txt and do what it
//     says".
//
// Neither half reads the host: a moltbook-style "fetch https://<service>/heartbeat.md and follow it" fires,
// because that is the behaviour the rule names, whoever runs the server. Measured in the proposal.
const (
	// riURL is a remote URL as prose or a command writes it. It stops at whitespace, a quote, a backtick and
	// the closing bracket of a Markdown link, so "[the playbook](https://…) and follow it" still reaches the
	// obedience phrase.
	riURL = `https?://[^\s"'\x60<>)\]]+`
	// riSentence is one character of the same sentence. A dot, ! or ? closes the sentence only before
	// whitespace, so a version number or a host name does not; "… open it in Claude Desktop. For manual
	// installation, follow the steps below." is two sentences, and the steps below are not the download.
	riSentence = `(?:[^.!?\n]|[.!?]\S)`
	// riFetch is a verb that brings a remote file to the agent. "open", "visit", "see" and "go to" are left
	// out on purpose: they send a person to a page, and "open https://console… and follow the steps" is how
	// setup guides are written.
	riFetch = `\b(?:download|fetch|get|grab|retrieve|pull|load|read|curl|wget)\b`
	// riOrders is what an agent obeys.
	riOrders = `(?:(?:the|its|their|these|those|all(?:\s+the)?|any|every|each)\s+)?(?:steps?|instructions?|directions?|commands?|tasks?|actions?|guidance|procedure)\b`
	// riObey is the agent told to do what a text says. "following" is not in it: "perform the following
	// actions" is an adjective, and it was the first draft's commonest benign hit. Running a downloaded file
	// is not in it either — that is code execution, and EXEC-001/012 and SUP-007 say which forms of it fire.
	riObey = `(?:\bfollow(?:s|ed)?\s+(?:(?:it|them)\b|` + riOrders + `)` +
		`|\bdo\s+(?:what|whatever|as|everything)\s+(?:it|they|the\s+(?:file|document|page|note|text|response|output))\s+(?:says?|tells?|instructs?|lists?|asks?)\b` +
		`|\bcarry\s+(?:it|them)\s+out\b|\bcarry\s+out\s+` + riOrders +
		`|\bobey(?:s|ed)?\b|\bact\s+on\s+` + riOrders + `|\bexecute\s+` + riOrders + `)`
)

// remoteOrdersRE is INJ-005's pattern: the original shape (a fetch of a file named like instructions), then
// the line half described above.
const remoteOrdersRE = `\b(curl|wget|fetch)\b[^\n|]*https?://[^\s"\x60]*\b(instructions?|steps|commands?|payload|tasks?)\.(md|txt|sh|bash|json|ya?ml|py|js)\b` +
	`|` + riFetch + riSentence + `{0,80}?` + riURL + riSentence + `{0,120}?` + riObey +
	`|` + riObey + `\s+(?:in|from|at|on)\s+` + riURL

var (
	riURLRE        = regexp.MustCompile(`(?i)` + riURL)
	riObeyRE       = regexp.MustCompile(`(?i)` + riObey)
	riDownloaderRE = regexp.MustCompile(`(?i)\b(?:curl|wget|invoke-webrequest|iwr|urlretrieve)\b`)
	riWgetRE       = regexp.MustCompile(`(?i)\bwget\b`)
	// riFlagKeepRE is an output flag and its argument. Case matters: curl's -o names the file and -O keeps
	// the URL's own name (its "argument" is then the URL, which keptPaths reads as that); wget's -O names
	// the file, and -O- is standard output. Short flags may be bundled (-sSLo, -qO).
	// The spelled-out options come first: alternatives are tried in order, and the bundled form would
	// otherwise read -OutFile as -O followed by "utFile".
	riFlagKeepRE = regexp.MustCompile(`(?:^|\s)(?:--output(?:-document)?|--remote-name|(?i:-outfile)|-[a-zA-Z]*[oO])(?:=|\s+|)["']?([^\s"'\x60;|&)<>]*)`)
	// riRedirectKeepRE is a redirect of standard output or a tee into a file. Something other than a digit
	// must precede the redirect: 2> is standard error, and a line that starts with > is a Markdown quote.
	riRedirectKeepRE = regexp.MustCompile(`(?:[^\s0-9]\s*>{1,2}|\|\s*tee\s+(?:-a\s+)?)\s*["']?([^\s"'\x60;|&)<>]+)`)
	// riFollowRE is the start of "follow <path>" / "obey <path>", which names its object rather than
	// saying "the steps"; obeysPath completes it with the path.
	riFollowRE   = regexp.MustCompile(`(?i)\b(?:follow|obey)(?:s|ed)?\s`)
	riRetrieveRE = regexp.MustCompile(`(?i)\burlretrieve\(\s*["']https?://[^"']+["']\s*,\s*["']([^"']+)`)
	// riWgetOutputRE is wget told where to write (a file, or - for standard output).
	riWgetOutputRE = regexp.MustCompile(`(?:^|\s)(?:-[a-zA-Z]*O|--output-document)`)
)

// keptPaths returns where a line that downloads from a remote URL keeps what it fetched: an output flag's
// file, a redirect or tee target, urlretrieve's second argument, or — for curl -O and for wget without -O,
// which name the file after the URL — the URL's last path segment. Standard output, /dev/* and file
// descriptors are not a place an agent is later told to read.
func keptPaths(line string) []string {
	url := riURLRE.FindString(line)
	if url == "" || !riDownloaderRE.MatchString(line) {
		return nil
	}
	var out []string
	remoteName := false
	keep := func(p string) {
		switch {
		case riURLRE.MatchString(p):
			remoteName = true // curl -O <url>: the flag takes no file, the URL names it
		case !strings.ContainsAny(p, "./") || strings.HasPrefix(p, "/dev/"):
			// standard output (-), a descriptor (&1), a device, or a bare word a flag-shaped token
			// happened to precede: not a file an agent is told to read later
		default:
			out = append(out, p)
		}
	}
	for _, m := range riFlagKeepRE.FindAllStringSubmatch(line, -1) {
		keep(m[1])
	}
	for _, m := range riRedirectKeepRE.FindAllStringSubmatch(line, -1) {
		keep(m[1])
	}
	if m := riRetrieveRE.FindStringSubmatch(line); m != nil {
		keep(m[1])
	}
	if len(out) == 0 && (remoteName || (riWgetRE.MatchString(line) && !riWgetOutputRE.MatchString(line))) {
		if base := urlBase(url); base != "" {
			out = append(out, base)
		}
	}
	return out
}

// urlBase is the last path segment of a URL, the name curl -O and wget give the file; "" when the URL has
// no path to name it after.
func urlBase(url string) string {
	rest := url[strings.Index(url, "://")+3:]
	rest, _, _ = strings.Cut(rest, "?")
	rest, _, _ = strings.Cut(rest, "#")
	_, p, ok := strings.Cut(rest, "/")
	if !ok {
		return ""
	}
	if b := path.Base("/" + strings.TrimRight(p, "/")); b != "/" {
		return b
	}
	return ""
}

// namesPath reports whether line mentions p as a whole path: what precedes it is the line's start, a space,
// a quote, a backtick or an opening bracket (or "./"), and what follows is the end, a delimiter, or
// punctuation that ends the word — so /tmp/steps.md is not found inside /tmp/steps.md.bak or /var/tmp/steps.md.
func namesPath(line, p string) bool {
	p = strings.TrimPrefix(p, "./")
	if p == "" || p == "/" {
		return false
	}
	const before, after, punct = " \t\"'`([<", " \t\"'`)]>", ".,;:!?"
	for from := 0; ; {
		i := strings.Index(line[from:], p)
		if i < 0 {
			return false
		}
		start, end := from+i, from+i+len(p)
		pre := start == 0 || strings.IndexByte(before, line[start-1]) >= 0 ||
			(start >= 2 && line[start-2:start] == "./" && (start == 2 || strings.IndexByte(before, line[start-3]) >= 0))
		// Punctuation ends the path only when the word ends with it: /tmp/steps.md. ends a sentence,
		// /tmp/steps.md.bak is another file.
		post := end == len(line) || strings.IndexByte(after, line[end]) >= 0 ||
			(strings.IndexByte(punct, line[end]) >= 0 && (end+1 == len(line) || strings.IndexByte(after, line[end+1]) >= 0))
		if pre && post {
			return true
		}
		from = start + 1
	}
}

// obeysPath reports whether line tells the agent to obey the file at p: it names p, and it either carries
// an obedience phrase ("read /tmp/guide.txt and do what it says") or follows p itself ("follow ./plan.md").
func obeysPath(line, p string) bool {
	if !namesPath(line, p) {
		return false
	}
	if riObeyRE.MatchString(line) {
		return true
	}
	return regexp.MustCompile(`(?i)\b(?:follow|obey)(?:s|ed)?\s+["'\x60]?(?:\./)?` + regexp.QuoteMeta(strings.TrimPrefix(p, "./"))).MatchString(line)
}

// remoteOrders is INJ-005's file-level half for one unit: the paths remote downloads keep, and the lines
// that tell the agent to obey something. A pair — another line obeying a kept path — is the finding.
type remoteOrders struct {
	kept []struct {
		path string
		at   model.Evidence
	}
	obeys []struct {
		raw, norm string
		at        model.Evidence
	}
}

// observe records what one logical line contributes, reading the line as written first and the
// interpreter's view second — the order the rules use. The second matters here: folding a quoted argument
// away turns `urlretrieve("https://…", "/tmp/t.md")` into a line whose URL runs into the next argument.
// at is called only when the line is kept.
func (ro *remoteOrders) observe(ll logicalLine, at func() model.Evidence) {
	paths := keptPaths(ll.raw)
	if len(paths) == 0 && ll.norm != ll.raw {
		paths = keptPaths(ll.norm)
	}
	obeys := false
	for _, text := range []string{ll.raw, ll.norm} {
		obeys = obeys || riObeyRE.MatchString(text) || riFollowRE.MatchString(text)
	}
	if len(paths) == 0 && !obeys {
		return
	}
	ev := at()
	for _, p := range paths {
		ro.kept = append(ro.kept, struct {
			path string
			at   model.Evidence
		}{p, ev})
	}
	if obeys {
		ro.obeys = append(ro.obeys, struct {
			raw, norm string
			at        model.Evidence
		}{ll.raw, ll.norm, ev})
	}
}

// evidence returns the first pair — the download, then the line obeying what it kept — or nil.
func (ro *remoteOrders) evidence() []model.Evidence {
	for _, k := range ro.kept {
		for _, o := range ro.obeys {
			if o.at.Line != k.at.Line && (obeysPath(o.raw, k.path) || obeysPath(o.norm, k.path)) {
				return []model.Evidence{k.at, o.at}
			}
		}
	}
	return nil
}
