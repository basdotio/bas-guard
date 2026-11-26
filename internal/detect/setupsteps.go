// SPDX-License-Identifier: MIT
package detect

import (
	"regexp"
	"strings"

	"github.com/basdotio/bas-guard/internal/collect"
	"github.com/basdotio/bas-guard/internal/model"
)

// Setup steps written in plain text (P-152). Eleven SkillHarm trees carry their one bad act as a
// "required preflight": a shell command in a fenced block of the SKILL.md, of a script, or of a
// document the SKILL.md names, with a paragraph on why the skill needs it. Nothing is hidden,
// encoded or fetched, and every one of them left `check` at exit 0.
//
// Three shapes are read, each measured before it was built (agent-guard-work/textharm-proto.py over
// the corpus, the fresh skills and the held-out lists; textharm-skillmd.py over the 138,133 SKILL.md
// files of SkillMD-138K):
//
//	FS-006   chmod gives group or others read on a file that holds a secret (this file)
//	FS-007   a shell startup file is truncated and rewritten (a table rule, rules_data.go)
//	SUP-006  pip's second index points at a host that is not a registry's own (shape.go)
//
// FS-006 is structural rather than a table rule because the target is asked of collect's
// credential list, not of a second list written as a pattern, and each path of the line is judged
// on its own: `chmod 644 ~/.ssh/id_ed25519.pub ~/.ssh/id_ed25519` opens one key, not none.
//
// What is deliberately not read, each counted and not clean: the credential directory itself
// (`chmod 755 ~/.ssh`: the real skills that write it quote it as what not to do), a .pem (usually a
// public certificate), and the public files of .ssh (nine real skills tell the reader to chmod 644 a
// public key). A mode set from code, or a path the line does not spell, is not seen.

// chmodRE finds a chmod command on a line: its options, its mode (octal, or symbolic clauses) and
// what follows up to the end of the command. `\b` keeps fchmod and lchmod out; a call such as
// os.chmod( has no space after the name and is not a command.
var chmodRE = regexp.MustCompile(`\bchmod\s+((?:-[A-Za-z-]+\s+)*)([0-7]{3,4}|[ugoa]*[+=-][rwxXst]*(?:,[ugoa]*[+=-][rwxXst]*)*)\s+([^;&|\n]+)`)

// maxChmodLine keeps the check off minified or generated lines, as maxLureLine does.
const maxChmodLine = 800

// opensToOthers reports whether a chmod mode gives group or others read. An octal mode does when
// the group digit or the other digit has the read bit (644, 640, 755, 0644; not 600, 400, 700). A
// symbolic mode does when a clause adds or sets r for g, o, a, or for nobody named (`+r` is "all,
// minus the umask", and the usual umask keeps read). Removing is never opening.
func opensToOthers(mode string) bool {
	if mode != "" && mode[0] >= '0' && mode[0] <= '7' {
		d := mode[len(mode)-3:]
		return (d[1]-'0')&4 != 0 || (d[2]-'0')&4 != 0
	}
	for _, clause := range strings.Split(mode, ",") {
		i := strings.IndexAny(clause, "+=-")
		if i < 0 || clause[i] == '-' || !strings.Contains(clause[i+1:], "r") {
			continue
		}
		who := clause[:i]
		if who == "" || strings.ContainsAny(who, "goa") {
			return true
		}
	}
	return false
}

// chmodTarget cleans one word after the mode into the path it spells: quotes and backticks off, and
// the punctuation a sentence or a Markdown span puts after a path.
func chmodTarget(word string) string {
	word = strings.Trim(word, "\"'`")
	return strings.TrimRight(word, ",.;:)\"'`")
}

// openedSecret returns the first credential file a chmod on the line opens to group or others, and
// the mode that does it. Each path is judged on its own; an option, a tightening mode, or a path
// that is not a secret (collect.HoldsSecret) yields nothing.
func openedSecret(line string) (path, mode string, ok bool) {
	if len(line) > maxChmodLine || !strings.Contains(line, "chmod") {
		return "", "", false
	}
	for _, m := range chmodRE.FindAllStringSubmatch(line, -1) {
		if !opensToOthers(m[2]) {
			continue
		}
		for _, word := range strings.Fields(m[3]) {
			if strings.HasPrefix(word, "-") {
				continue
			}
			if p := chmodTarget(word); p != "" && collect.HoldsSecret(p) {
				return p, m[2], true
			}
		}
	}
	return "", "", false
}

// setupStepScope is where FS-006 runs: wherever the table rules of its dimension run (roleAllows for
// a dimension-9 rule): scripts, hook commands, instruction files and the code of a named document.
// Not bundled prose and not a tool description, where a command is described rather than run.
func setupStepScope(u unit) bool {
	return u.role != roleDoc && u.role != roleToolDesc
}

// openedSecretFinding is FS-006 on one line. The line is tried as written and as normalized, like
// every rule: a quote that only splits the command name must not hide it.
func openedSecretFinding(rel string, lineNo int, u unit, ll logicalLine) (model.Finding, bool) {
	path, mode, ok := openedSecret(ll.raw)
	if !ok && ll.norm != ll.raw {
		path, mode, ok = openedSecret(ll.norm)
	}
	if !ok {
		return model.Finding{}, false
	}
	return model.Finding{
		RuleID: "FS-006", Dimension: 9, Severity: model.SevHigh, Source: model.SrcStatic,
		Title: "Credential file made readable by other users",
		Why: "chmod " + mode + " gives group or others read on " + Redact(path) + ", a file that holds a secret. Such a file is " +
			"kept owner-only so that no other user or process on the machine can read it, and the tool that needs it runs as " +
			"its owner, so no setup needs this step. Once it is done, anything that runs later with fewer rights can take the " +
			"credential. A reason given beside the command does not change what the command does.",
		Evidence: []model.Evidence{{File: rel, Line: lineNo, Snippet: u.evidence(ll.raw)}},
	}, true
}
