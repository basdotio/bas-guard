// SPDX-License-Identifier: MIT
package detect

import (
	"regexp"
	"sort"
	"strings"
)

// What the judge's destination question is shown of a file (P-142).
//
// EXFIL-001 and EXFIL-003 say that a file reads a credential and sends something. They cannot say
// where the credential goes, and since P-142 the judge is asked. A ruling on a file the judge saw
// part of is a ruling on that part, so the question has to be shown every line the rules counted —
// and a file is often too large to send whole. This file answers "which lines": it is not a rule,
// it produces no finding and no rule reads it.

// ChainLines returns the lines of a file the destination question must be shown to rule on an
// EXFIL-001 or EXFIL-003 finding in it, as sorted 1-based line numbers of the file:
//
//   - legs: every line the chain counts as a leg (chain.legs, the definition observe records
//     from), read at the widest setting any caller uses — a URL literal is a send
//     (literalIsEgress), and so is a request through a client only the judge's list names
//     (requestLineRE). The rules' own chain over the same file counts a subset of these, never a
//     line outside them, so a file whose every listed line was sent was sent every line the finding
//     rests on. Wider is the safe direction here: a send the rules did not count is still shown.
//   - assigns: lines that assign a name a sending line uses as its destination (`fetch(url)`,
//     `curl "$API/x"`, `BASE + "/v1"`), found the way resolvedHosts finds the names. A destination
//     held in a variable is where most real clients keep it, and the line that sets it is often
//     far from the line that uses it.
//
// Comment-only lines are never listed: an interpreter does not read them and the judge is not sent
// them (condense).
func ChainLines(path, text string) (legs, assigns []int) {
	lang := langForFile(path)
	comments := commentOnlyLines(lang, text)
	c := chain{literalIsEgress: true, requestLine: requestLineRE}
	names := map[string]bool{}
	for _, ll := range logicalLines(lang, text, comments) {
		if ll.comment {
			continue
		}
		cred, enc, net := c.legs(ll.raw, ll.norm)
		if !cred && !enc && !net {
			continue
		}
		legs = append(legs, ll.start)
		if net {
			for _, re := range []*regexp.Regexp{urlVarDollarRE, urlVarBraceRE, urlVarArgRE, urlVarConcatRE} {
				for _, m := range re.FindAllStringSubmatch(ll.raw, -1) {
					names[m[1]] = true
				}
			}
		}
	}
	if len(names) == 0 {
		return legs, nil
	}
	isLeg := map[int]bool{}
	for _, n := range legs {
		isLeg[n] = true
	}
	perName := map[string]int{}
	for i, line := range strings.Split(text, "\n") {
		n := i + 1
		if comments[n] || isLeg[n] {
			continue
		}
		for _, m := range assignedNameRE.FindAllStringSubmatch(line, -1) {
			if names[m[1]] && perName[m[1]] < maxAssignsPerName {
				perName[m[1]]++
				assigns = append(assigns, n)
				break
			}
		}
	}
	sort.Ints(assigns)
	return legs, assigns
}

// maxAssignsPerName bounds how many assignments of one name are listed: a name reassigned in every
// branch of a long file is not a destination's definition, and the question's budget is small.
const maxAssignsPerName = 4

// assignedNameRE is a name being given a value, in the spellings a destination is set in: `NAME=`,
// `NAME = `, `const NAME: string =`, `self.NAME =`, `NAME := `, and a key or keyword argument
// (`baseURL: `, `base_url=`). The value is not read — the judge reads it.
var assignedNameRE = regexp.MustCompile(`(?:^|[^A-Za-z0-9_$])([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[A-Za-z_][\w.<>\[\]| ]{0,40})?\s*(?::=|=|:)(?:[^=]|$)`)

// SecretName reports whether a name reads as a credential's (secretNamePat, the credential leg's own
// list): GITHUB_TOKEN does, GITEA_URL does not. The judge uses it so that a ruling never names the
// credential's own variable as the place the credential is sent (P-142).
func SecretName(name string) bool { return secretNameRE.MatchString(name) }

// DestinationHosts returns the hosts a line names as a destination, as the chain reads them
// (networkHosts): the host of each http(s) URL, a /dev/tcp host, a quoted host or hostname value.
// A host the chain cannot read is left out, so an empty result means the line names none it can
// read. The judge uses it to say which destination a ruling's quoted line names (P-142); it weighs
// nothing here.
func DestinationHosts(line string) []string {
	var out []string
	for _, h := range networkHosts(line) {
		if h != "?" {
			out = append(out, h)
		}
	}
	return out
}
