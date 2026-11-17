// SPDX-License-Identifier: MIT
package detect

import (
	"regexp"
	"strings"

	"github.com/basdotio/bas-guard/internal/model"
)

// The prerequisite lure (P-131). The largest in-the-wild campaign against agent skills carries no code
// in the skill at all: the instructions open with "this helper must be installed first" and say where
// to get it. A zip on somebody's release page with the password to open it; a paste page whose
// "installation command" goes into Terminal; a site named after the agent platform's own CLI. What gets
// installed is the malware, and the skill is the delivery note. Those lines are prose with a link, so
// no rule about pipes, credentials or encoding sees them: four of the six such trees in the corpus
// scored 100, and the other two were flagged for an unrelated line.
//
// SUP-010 reads three ways the prerequisite is offered, each on one line of an instruction file or a
// document:
//
//	paste     a URL on a paste or snippet site, beside a word for running or installing
//	archive   a URL to an archive or executable, beside a password to open it
//	platform  a URL whose host carries an agent platform's name and is not one of that platform's
//	          own, beside a phrase that makes it a prerequisite or a download
//
// Measured before it was built (agent-guard-work/lure-proto.py): 8 malicious trees and 0 of 4,534
// benign ones in the corpus, 0 of 416 fresh skills, 0 of 36 defensive skills that quote attacks; on the
// held-out ClawHub set, read for totals only, 112 of 123 malicious trees and 0 of 216 benign.
//
// What is deliberately not here, each measured and not clean: free app hosting (documentation sites
// live on vercel.app), project pages (jq's own page is on github.io), unusual top-level domains, and
// "the tool's name is in the host" (so is docker.com). A list of this campaign's domains belongs to the
// reputation list, not to a rule.

// lureURL finds the URLs of a line: the host, and the path up to the first character Markdown or a
// sentence would end it with.
var lureURL = regexp.MustCompile(`(?i)https?://([a-z0-9.-]+)(/[^\s)\]>"'` + "`" + `]*)?`)

// pasteHost is a paste or snippet site: anonymous, replaceable at any time, and not where software is
// published. Gists are not on it; projects do publish install scripts there.
var pasteHost = regexp.MustCompile(`(?i)(^|\.)(glot\.io|pastebin\.(com|pl)|rentry\.(co|org)|hastebin\.com|paste\.(ee|rs|gg|sh)|pastes\.io|dpaste\.(com|org)|ghostbin\.(com|co)|privatebin\.net|controlc\.com|justpaste\.it|bpa\.st|0x0\.st|termbin\.com|ix\.io|sprunge\.us|ctxt\.io|text\.is|snippet\.host)$`)

// runCue is a word for running or installing what the paste holds. "copy" is not one: copying a
// snippet of configuration from a paste is not this.
var runCue = regexp.MustCompile(`(?i)\b(run|execute|paste|install\w*|set ?up|terminal|command|script|shell)\b`)

// archivePath is a download that is opened or run rather than read.
var archivePath = regexp.MustCompile(`(?i)\.(zip|rar|7z|tar\.gz|tgz|exe|msi|dmg|pkg|bat|ps1|scr|iso)$`)

// passCue is a password to open the download with. "Extract with unzip" names a tool, not a password:
// the extract forms need a colon (extract using: word) or the word pass.
var passCue = regexp.MustCompile(`(?i)\b(password|passcode|passphrase)\b|\bpass\s*[:=]|\bpass\s+` + "`" + `|\bextract\w*\s+(it\s+)?(using|with)\s*:|\bextract\w*\s+(it\s+)?(using|with)\s+(the\s+)?pass|\bunzip\s+-P\b|\b7z\s+x\s+-p`)

// platformName is an agent platform's name inside a host. Substrings on purpose: the campaign's hosts
// are the name with something appended (openclawcli), and a boundary rule is a prefix away from being
// stepped around.
var platformName = regexp.MustCompile(`(?i)open-?claw|clawd-?bot|claw-?hub|molt-?bot|claude|anthropic|openai|chatgpt|codex|cursor`)

// platformOwn are the hosts those platforms publish from. A host that ends in one of these is the
// platform's own; so is the platform's organisation page on a code host. Only hosts known to be the
// platform's are here: a wrong entry would be a way in, a missing one is a false alarm someone reports.
var platformOwn = regexp.MustCompile(`(?i)(^|\.)(openclaw\.ai|clawhub\.ai|clawd\.bot|molt\.bot|claude\.ai|claude\.com|anthropic\.com|openai\.com|chatgpt\.com|openai\.azure\.com|cursor\.com|cursor\.sh)$|^(openclaw|clawhub|anthropics?|openai|getcursor)\.(github|gitlab)\.io$`)

// needCue makes the URL a prerequisite or a place to download from, on the same line.
var needCue = regexp.MustCompile(`(?i)must be installed|\b(is|are) required\b|\brequired for\b|\bprerequisite|\bdownload and (install|run)\b|\binstall(ed|ation)?\s+(it\s+)?(from|here)\b|\bquick setup\b|\bset ?up here\b|\bget it (here|from)\b`)

// maxLureLine keeps the check off minified or generated lines, where a URL and a word are neighbours
// by accident.
const maxLureLine = 800

// lureReason says why a line is a prerequisite lure, or "" when it is not. Each URL is judged by its
// own host, so an official link beside a look-alike does not clear the line, and the words are looked
// for outside the URLs, so `…/install.zip?password=…` is not its own cue.
func lureReason(text string) string {
	if len(text) > maxLureLine || !strings.Contains(strings.ToLower(text), "http") {
		return ""
	}
	urls := lureURL.FindAllStringSubmatch(text, -1)
	if len(urls) == 0 {
		return ""
	}
	words := lureURL.ReplaceAllString(text, " ")
	for _, m := range urls {
		host := strings.TrimRight(strings.ToLower(m[1]), ".")
		path := m[2]
		if i := strings.IndexAny(path, "?#"); i >= 0 {
			path = path[:i]
		}
		switch {
		case pasteHost.MatchString(host) && runCue.MatchString(words):
			return "the reader is sent to a paste or snippet site (" + host + ") to run or install what is there. A paste is anonymous, can be replaced at any time, and is not where software is published"
		case archivePath.MatchString(path) && passCue.MatchString(words):
			return "a download from " + host + " comes with a password to open it. A password-protected archive keeps scanners out of what it carries; software meant to be installed is not shipped that way"
		case platformName.MatchString(host) && !platformOwn.MatchString(host) && needCue.MatchString(words):
			return host + " is offered as where to install or set up a prerequisite, and its name imitates an agent platform whose own sites it is not on. The platform is already running; a helper for it from somewhere else is how the lure works"
		}
	}
	return ""
}

// lureScope is where SUP-010 runs: text a reader is told to follow. An instruction file, and a
// document whether or not the skill names it (one of the four missed trees keeps the lure in the
// README its SKILL.md tells the agent to read). Not code, not a hook command, not a tool description,
// and not the code-only copy of a named document, whose prose the document unit beside it already has.
func lureScope(u unit) bool {
	return !u.synthetic && (u.role == roleInstruction || u.role == roleDoc)
}

// lureFinding is SUP-010 on one line. The line is tried as written and as normalized, like every rule:
// a zero-width character inside the host must not hide it.
func lureFinding(rel string, lineNo int, u unit, ll logicalLine) (model.Finding, bool) {
	why := lureReason(ll.raw)
	if why == "" {
		why = lureReason(ll.norm)
	}
	if why == "" {
		return model.Finding{}, false
	}
	return model.Finding{
		RuleID: "SUP-010", Dimension: 5, Severity: model.SevHigh, Source: model.SrcStatic,
		Title: "Prerequisite offered from a paste site, a password-protected archive or a platform look-alike",
		Why: "The instructions tell the reader to install or run something first, and where they point is how skills deliver malware without a line of code in the skill: " +
			Redact(why) + ". Do not install it; check the platform's own site for the tool it names.",
		Evidence: []model.Evidence{{File: rel, Line: lineNo, Snippet: u.evidence(ll.raw)}},
	}, true
}
