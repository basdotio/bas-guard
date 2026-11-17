// SPDX-License-Identifier: MIT
package detect

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/basdotio/bas-guard/internal/model"
)

// Install-time scripts (P-129). npm runs a package's `preinstall`, `install` and `postinstall`
// scripts on the installing machine, with no prompt, before any of the package's own code is used:
// an MCP server configured as `npx -y <package>` gets them on its first launch, and a skill that
// tells the agent to `npm install` in a directory it ships gets them when the agent obeys. It is how
// the npm worms in the corpus start, and no rule read those scripts: `node bundle.js` matches
// nothing, and the file it names is built to be unreadable. Three of the four in-the-wild trees
// this was measured on run one line of 2 to 4 MB, over the read cap, where the only thing the
// report said was a COV-000 note that does not move the score. One of them scored 100.
//
// The check is the hook audit's shape (hooks.go): the script is followed one level into the file
// it runs, and "it runs something that was not read" is a risk, not only a coverage note
// (HOOK-002's reasoning). It asks the tree walk what it already knows about each file and opens
// nothing itself, so every boundary the walk holds (collect.FileReach, the size cap, the regular-
// file guard) holds here by construction.
//
//	SUP-008 (high)   the script runs a file that was not read, a file with a line too long to
//	                 review, a file that both reaches the network and starts a process, or inline
//	                 interpreter code that does more than print
//	SUP-009 (medium) any other install-time script
//
// One finding per script, never both. Measured on the corpus at c314e4d9: ten malicious trees have
// an install-time script and all ten are SUP-008 (five were not flagged before); four of 163 benign
// trees with a package.json have one and all four are SUP-009.

// treeFiles is what the tree walk learned about each file it saw, kept so a check that follows a
// reference from one file of the tree to another never opens a file again.
type treeFiles struct {
	text     map[string]string // every file the walk read, by path; a byte-identical copy is here too
	present  map[string]bool   // every regular file inside the boundary, read or not
	oversize map[string]bool   // present and over the read cap
}

func newTreeFiles() treeFiles {
	return treeFiles{text: map[string]string{}, present: map[string]bool{}, oversize: map[string]bool{}}
}

// installHooks are the lifecycle names npm runs when a package is installed as a dependency or by
// npx. `prepare` and `prepublish` are not here on purpose: npm runs them on publish and on a git or
// local install, and 54 benign trees in the corpus carry `prepare` for their build.
var installHooks = []string{"preinstall", "install", "postinstall"}

// unreviewableLineBytes is the line length at which a file is packed or minified code that neither
// a reviewer nor a line rule reads. Over 151 files run by scripts of any name in benign trees the
// longest line is 466 bytes; the shortest of the malicious install targets' is 13,051.
const unreviewableLineBytes = 4096

// fileTooLargeTitle is the COV-000 title readCapped gives a file over the cap; the walk reads it to
// tell that note from the not-a-regular-file one.
const fileTooLargeTitle = "File too large, content scan skipped (incomplete coverage)"

// scriptInterpreters are the programs whose next word is the file they run. The eval flags are the
// ones that make the next word code instead.
var scriptInterpreters = map[string][]string{
	"node": {"-e", "--eval", "-p", "--print"}, "nodejs": {"-e", "--eval", "-p", "--print"},
	"bun": {"-e", "--eval", "-p", "--print"}, "deno": {"-e", "--eval", "-p", "--print"},
	"tsx": {"-e", "--eval"}, "ts-node": {"-e", "--eval", "-p", "--print"},
	"python": {"-c"}, "python2": {"-c"}, "python3": {"-c"},
	"ruby": {"-e"}, "perl": {"-e", "-E"}, "php": {"-r"},
	"sh": {"-c"}, "bash": {"-c"}, "zsh": {"-c"}, "dash": {"-c"},
}

// shells are the interpreters whose eval flag takes a command line, not code in another language:
// `sh -c "node x.js"` is read as the command it wraps.
var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true}

// packageRunners map `npm run <name>` and its relatives to another script of the same file. The
// second word may be left out for yarn and pnpm (`yarn build`).
var packageRunners = map[string]bool{"npm": true, "yarn": true, "pnpm": true, "bun": true}

// inlineTouches is inline code that does more than print: it loads a module, or names a file,
// network, environment, process or eval API. Case-sensitive on purpose: a printed notice saying
// "IMPORTANT: set your API key" is not an import. One list for JavaScript and one for the others,
// because `import x` is a statement only outside JavaScript's -e.
var (
	inlineTouchesJS    = regexp.MustCompile(`\brequire\s*\(|\bimport\s*\(|\bprocess\.(env|binding|dlopen|argv)|child_process|\bfs\.|\b(read|write|append)File|createWriteStream|\bexec(File)?(Sync)?\s*\(|\bspawn(Sync)?\s*\(|\bfetch\s*\(|XMLHttpRequest|\bhttps?\.(get|request)|\bnet\.|\bdgram\.|\beval\s*\(|\bFunction\s*\(|\bBuffer\.from|\batob\s*\(|\bBun\.|\bDeno\.`)
	inlineTouchesOther = regexp.MustCompile(`\bimport\s+\w|\bfrom\s+\w+\s+import\b|__import__|\brequire\b|\bopen\s*\(|\bsystem\s*\(|\bexec\w*\s*\(|\beval\s*\(|\bsubprocess\b|\bsocket\b|\burllib\b|\brequests\.|\bos\.|\bFile\.|\bIO\.|\bNet::|\bfile_(get|put)_contents|\bcurl_|\bfopen\s*\(|` + "`")
)

// spawnRule is EXEC-004, the rule table's own "starts a process" pattern, so reason 3 has no second
// word list to drift from it.
var spawnRule = sync.OnceValue(func() Rule {
	for _, r := range builtinRules() {
		if r.ID == "EXEC-004" {
			return r
		}
	}
	panic("detect: EXEC-004 is gone from the rule table; the install-script check reads its pattern")
})

// installReason is one thing that makes an install-time script SUP-008.
type installReason struct {
	text string
	at   *model.Evidence
}

// installScriptFindings judges the install-time scripts of every package.json the walk read. dir is
// the tree's root; evidence is named relative to it, as the walk's other structural findings are.
func installScriptFindings(dir string, tf treeFiles) []model.Finding {
	var pkgs []string
	for p := range tf.text {
		if filepath.Base(p) == "package.json" {
			pkgs = append(pkgs, p)
		}
	}
	sort.Strings(pkgs)
	var out []model.Finding
	for _, pkg := range pkgs {
		out = append(out, packageInstallFindings(dir, pkg, tf)...)
	}
	return out
}

func packageInstallFindings(dir, pkg string, tf treeFiles) []model.Finding {
	// Members are taken by exact key through maps: decoding into a struct matches `Scripts` and
	// `SCRIPTS` too, which npm does not read (the reason mcpServerMap does the same).
	var doc map[string]json.RawMessage
	if json.Unmarshal([]byte(tf.text[pkg]), &doc) != nil {
		return nil
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(doc["scripts"], &raw) != nil {
		return nil
	}
	scripts := map[string]string{}
	for k, v := range raw {
		var s string
		if json.Unmarshal(v, &s) == nil {
			scripts[k] = s
		}
	}
	keys := make([]string, 0, len(scripts))
	for k := range scripts {
		if installHookName(k) != "" && strings.TrimSpace(scripts[k]) != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var out []model.Finding
	for _, key := range keys {
		out = append(out, installFinding(dir, pkg, key, scripts, tf))
	}
	return out
}

// installHookName is the npm lifecycle name a scripts key equals ignoring case, or "".
func installHookName(key string) string {
	for _, h := range installHooks {
		if strings.EqualFold(key, h) {
			return h
		}
	}
	return ""
}

func installFinding(dir, pkg, key string, scripts map[string]string, tf treeFiles) model.Finding {
	cmd := scripts[key]
	pkgRel := treeRel(dir, pkg)
	// The script itself, then one hop through `npm run <name>` to another script of this file.
	type step struct{ cmd, via string }
	steps := []step{{cmd, ""}}
	for _, body := range shellBodies(cmd) {
		steps = append(steps, step{body, ""})
	}
	for _, st := range steps[:len(steps):len(steps)] {
		for _, name := range runScriptNames(st.cmd, scripts) {
			if name != key {
				steps = append(steps, step{scripts[name], name})
			}
		}
	}
	var reasons []installReason
	var absent []string
	seenFile := map[string]bool{}
	for _, st := range steps {
		via := ""
		if st.via != "" {
			via = " (through the `" + Redact(st.via) + "` script)"
		}
		if inlineCodeTouches(st.cmd) {
			reasons = append(reasons, installReason{text: "the script" + via + " is inline code that loads a module or touches files, the network, the environment or processes"})
		}
		for _, ref := range installRefs(st.cmd) {
			file, ok := resolveInTree(dir, filepath.Dir(pkg), ref, tf)
			if !ok {
				absent = append(absent, ref)
				continue
			}
			if seenFile[file] {
				continue
			}
			seenFile[file] = true
			reasons = append(reasons, fileReasons(dir, file, via, tf)...)
		}
	}

	line, lineText := scriptLine(tf.text[pkg], key)
	if lineText == "" {
		lineText = fmt.Sprintf("%q: %q", key, cmd)
	}
	ev := []model.Evidence{{File: pkgRel, Line: line, Snippet: redactClip(lineText)}}
	when := fmt.Sprintf("`%s` in %s runs `%s` when the package is installed: on the installing machine, with no prompt, before any of the package's own code is used.",
		Redact(key), Redact(pkgRel), redactClip(cmd))
	if hook := installHookName(key); hook != key {
		when += fmt.Sprintf(" npm runs only the lowercase name `%s`: as written this script does not run on install, and one letter changes that.", hook)
	}
	if len(reasons) == 0 {
		why := when + " Nothing it runs was found unread or unreviewable; read what it does before installing."
		if len(absent) > 0 {
			why += " Not in this tree, so not read: " + Redact(strings.Join(dedupeStrings(absent), ", ")) + "."
		}
		return model.Finding{
			RuleID: "SUP-009", Dimension: 5, Severity: model.SevMedium, Source: model.SrcStatic,
			Title: "Package runs a script at install time", Why: why, Evidence: ev,
		}
	}
	texts := make([]string, 0, len(reasons))
	for i, r := range reasons {
		texts = append(texts, r.text)
		if r.at != nil && i < 3 {
			ev = append(ev, *r.at)
		}
	}
	return model.Finding{
		RuleID: "SUP-008", Dimension: 5, Severity: model.SevHigh, Source: model.SrcStatic,
		Title:    "Install-time script runs unread, packed, inline or self-fetching code",
		Why:      when + " Here: " + strings.Join(texts, "; ") + ".",
		Evidence: ev,
	}
}

// fileReasons is what makes one file an install-time script runs a SUP-008 reason: it was not read,
// it has a line nobody reviews, or it both reaches the network and starts a process.
func fileReasons(dir, file, via string, tf treeFiles) []installReason {
	rel := treeRel(dir, file)
	name := "`" + Redact(rel) + "`" + via
	text, read := tf.text[file]
	if !read {
		why := "it is not a text file this scan reads"
		if tf.oversize[file] {
			why = "it is over the 1 MiB cap"
		}
		return []installReason{{text: name + " was not read: " + why, at: &model.Evidence{File: rel, Line: 0, Snippet: "not read"}}}
	}
	var out []installReason
	if n, at := longestLine(text); n >= unreviewableLineBytes {
		out = append(out, installReason{
			text: fmt.Sprintf("%s has a line of %d bytes, packed or minified code that neither a reviewer nor a line rule reads", name, n),
			at:   &model.Evidence{File: rel, Line: at, Snippet: fmt.Sprintf("a line of %d bytes", n)},
		})
	}
	if ll, ok := fetchesAndRuns(file, text); ok {
		out = append(out, installReason{
			text: name + " both reaches the network and starts a process, so it can fetch code and run it during the install",
			at:   &model.Evidence{File: rel, Line: ll.start, Snippet: redactClip(ll.raw)},
		})
	}
	return out
}

// fetchesAndRuns reports whether a file names a way to send (networkCapable, the EXFIL chain's own
// answer) and a non-comment line of it starts a process (EXEC-004's pattern), and returns that line.
func fetchesAndRuns(file, text string) (logicalLine, bool) {
	comments := commentOnlyLines(langForFile(file), text)
	if !networkCapable(unit{file: file, text: text, role: roleScript}, comments) {
		return logicalLine{}, false
	}
	r := spawnRule()
	for _, ll := range logicalLines(langForFile(file), text, comments) {
		if !ll.comment && r.matches(ll) {
			return ll, true
		}
	}
	return logicalLine{}, false
}

// longestLine is the byte length of the longest line of text and its 1-based number.
func longestLine(text string) (n, at int) {
	line := 1
	for len(text) > 0 {
		l := text
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			l, text = text[:i], text[i+1:]
		} else {
			text = ""
		}
		if len(l) > n {
			n, at = len(l), line
		}
		line++
	}
	return n, at
}

// installRefs are the local files a script's command runs: a word with a script extension
// (scriptRefs, the hook audit's tokeniser), a `./` or `../` word, and the word after an interpreter
// unless an eval flag made it code. Words holding a variable, a glob or a URL are not paths anyone
// can resolve without guessing, and are left out.
func installRefs(cmd string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(w string) {
		if w == "" || seen[w] || strings.Contains(w, "://") || strings.ContainsAny(w, "$*?`") {
			return
		}
		seen[w] = true
		out = append(out, w)
	}
	words := shellWords(cmd)
	inline := inlineCodeWords(words)
	for _, r := range scriptRefs(cmd) {
		if !inline[r] {
			add(r)
		}
	}
	for i, w := range words {
		if inline[w] {
			continue
		}
		if strings.HasPrefix(w, "./") || strings.HasPrefix(w, "../") {
			add(w)
			continue
		}
		if _, ok := scriptInterpreters[filepath.Base(w)]; !ok {
			continue
		}
		for j := i + 1; j < len(words); j++ {
			next := words[j]
			if next == "run" && filepath.Base(w) == "bun" {
				continue
			}
			if strings.HasPrefix(next, "-") {
				if isEvalFlag(filepath.Base(w), next) {
					break // the word after it is code, not a file
				}
				continue
			}
			if !inline[next] {
				add(next)
			}
			break
		}
	}
	return out
}

func isEvalFlag(interp, flag string) bool {
	for _, f := range scriptInterpreters[interp] {
		if f == flag {
			return true
		}
	}
	return false
}

// inlineCodeWords are the words of a command that are code handed to an interpreter's eval flag.
func inlineCodeWords(words []string) map[string]bool {
	out := map[string]bool{}
	for i, w := range words {
		interp := filepath.Base(w)
		if _, ok := scriptInterpreters[interp]; !ok {
			continue
		}
		for j := i + 1; j+1 < len(words) && strings.HasPrefix(words[j], "-"); j++ {
			if isEvalFlag(interp, words[j]) {
				out[words[j+1]] = true
				break
			}
		}
	}
	return out
}

// inlineCodeTouches reports whether a command hands an interpreter inline code that does more than
// print. `node -e "console.log('installed')"` is a notice; reading `.env` two directories up is not.
func inlineCodeTouches(cmd string) bool {
	words := shellWords(cmd)
	for i, w := range words {
		interp := filepath.Base(w)
		if _, ok := scriptInterpreters[interp]; !ok {
			continue
		}
		for j := i + 1; j+1 < len(words) && strings.HasPrefix(words[j], "-"); j++ {
			if !isEvalFlag(interp, words[j]) {
				continue
			}
			if shells[interp] {
				break // a command line, read as its own step (shellBodies), not as code
			}
			re := inlineTouchesOther
			switch interp {
			case "node", "nodejs", "bun", "deno", "tsx", "ts-node":
				re = inlineTouchesJS
			}
			if re.MatchString(words[j+1]) {
				return true
			}
			break
		}
	}
	return false
}

// shellBodies are the command lines a command hands to a shell's -c, one level.
func shellBodies(cmd string) []string {
	var out []string
	words := shellWords(cmd)
	for i, w := range words {
		if !shells[filepath.Base(w)] {
			continue
		}
		for j := i + 1; j+1 < len(words) && strings.HasPrefix(words[j], "-"); j++ {
			if words[j] == "-c" {
				out = append(out, words[j+1])
				break
			}
		}
	}
	return out
}

// runScriptNames are the other scripts of the same package.json a command runs through a package
// runner: `npm run x`, `yarn x`, `pnpm run x`, `bun run x`. One hop: what those run is not chased.
func runScriptNames(cmd string, scripts map[string]string) []string {
	var out []string
	words := shellWords(cmd)
	for i, w := range words {
		if !packageRunners[filepath.Base(w)] || i+1 >= len(words) {
			continue
		}
		name := words[i+1]
		if (name == "run" || name == "run-script") && i+2 < len(words) {
			name = words[i+2]
		} else if w == "npm" || w == "bun" {
			continue // `npm install`, `bun install`: a subcommand, not a script
		}
		if _, ok := scripts[name]; ok {
			out = append(out, name)
		}
	}
	return dedupeStrings(out)
}

// resolveInTree turns a reference from a script into a file the walk saw, or reports that there is
// none: outside the tree, absent, or not a regular file. Node's own fallbacks are tried after the
// exact path. Nothing is opened or stat'ed: the walk's record is the only answer, so a path that
// leaves the tree is never touched.
func resolveInTree(dir, base, ref string, tf treeFiles) (string, bool) {
	if filepath.IsAbs(ref) || strings.HasPrefix(ref, "~") {
		return "", false
	}
	p := filepath.Join(base, filepath.FromSlash(ref))
	rel, err := filepath.Rel(dir, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	for _, cand := range []string{p, p + ".js", p + ".mjs", p + ".cjs", filepath.Join(p, "index.js")} {
		if tf.present[cand] {
			return cand, true
		}
	}
	return "", false
}

// scriptLine finds the line of a package.json that holds a scripts key, preferring one after the
// "scripts" member opens; 0 and "" when the file is not laid out one member per line.
func scriptLine(text, key string) (int, string) {
	want := regexp.MustCompile(`^\s*"` + regexp.QuoteMeta(key) + `"\s*:`)
	first, firstText, inScripts := 0, "", false
	for i, l := range strings.Split(text, "\n") {
		if !inScripts && strings.Contains(l, `"scripts"`) {
			inScripts = true
		}
		if want.MatchString(l) {
			if inScripts {
				return i + 1, l
			}
			if first == 0 {
				first, firstText = i+1, l
			}
		}
	}
	return first, firstText
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
