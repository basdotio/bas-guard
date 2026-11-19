// SPDX-License-Identifier: MIT
package detect

import (
	"regexp"
	"strings"
	"unicode"
)

// The shell lexing HOOK-003's command half needs (P-128): where a list splits into commands, a pipeline
// into stages, a stage into words and redirections, and where a `$(…)` ends. TOKENISATION ONLY, like
// shellWords — nothing here expands a variable or runs anything (spec §16.1). It keeps quotes and
// substitutions inside the words it returns, because the reader asks what a word would expand to.

// shStep consumes one token of rs at i under the open contexts in st (' " ` ( {) and returns where the next
// token starts and the contexts after it. An escape is one token; `$(` and `${` open a context as one token.
func shStep(rs []rune, i int, st []byte) (int, []byte) {
	r := rs[i]
	var top byte
	if len(st) > 0 {
		top = st[len(st)-1]
	}
	if top == '\'' {
		if r == '\'' {
			return i + 1, st[:len(st)-1]
		}
		return i + 1, st
	}
	if r == '\\' && i+1 < len(rs) {
		return i + 2, st
	}
	opens := r == '$' && i+1 < len(rs) && (rs[i+1] == '(' || rs[i+1] == '{')
	switch top {
	case '"':
		switch {
		case r == '"':
			return i + 1, st[:len(st)-1]
		case opens:
			return i + 2, append(st, byte(rs[i+1]))
		case r == '`':
			return i + 1, append(st, '`')
		}
		return i + 1, st
	case '`':
		switch r {
		case '`':
			return i + 1, st[:len(st)-1]
		case '\'', '"':
			return i + 1, append(st, byte(r))
		}
		return i + 1, st
	}
	switch {
	case r == '\'' || r == '"' || r == '`':
		return i + 1, append(st, byte(r))
	case opens:
		return i + 2, append(st, byte(rs[i+1]))
	case r == '(':
		return i + 1, append(st, '(')
	case r == ')' && top == '(', r == '}' && top == '{':
		return i + 1, st[:len(st)-1]
	}
	return i + 1, st
}

// shSplit cuts s at every top-level position where sep reports a separator of that many runes.
func shSplit(s string, sep func(rs []rune, i int) int) []string {
	rs := []rune(s)
	var out []string
	var st []byte
	start := 0
	for i := 0; i < len(rs); {
		if len(st) == 0 {
			if n := sep(rs, i); n > 0 {
				out = append(out, string(rs[start:i]))
				i += n
				start = i
				continue
			}
		}
		i, st = shStep(rs, i, st)
	}
	return append(out, string(rs[start:]))
}

// shCommands splits a list at `;`, newlines, `&&`, `||` and a backgrounding `&` (not the `&` of `2>&1`,
// `&>` or `|&`).
func shCommands(s string) []string {
	return shSplit(s, func(rs []rune, i int) int {
		next := func(c rune) bool { return i+1 < len(rs) && rs[i+1] == c }
		switch rs[i] {
		case ';', '\n':
			return 1
		case '&':
			switch {
			case next('&'):
				return 2
			case next('>'), i > 0 && strings.ContainsRune("<>|", rs[i-1]):
				return 0
			}
			return 1
		case '|':
			if next('|') {
				return 2
			}
		}
		return 0
	})
}

// shStages splits one command into pipeline stages (`|` and `|&`).
func shStages(cmd string) []string {
	return shSplit(cmd, func(rs []rune, i int) int {
		if rs[i] != '|' {
			return 0
		}
		if i+1 < len(rs) && rs[i+1] == '&' {
			return 2
		}
		return 1
	})
}

// shWordsKept splits a stage at top-level blanks, keeping each word's quotes and substitutions.
func shWordsKept(stage string) []string {
	var out []string
	for _, w := range shSplit(stage, func(rs []rune, i int) int {
		if unicode.IsSpace(rs[i]) {
			return 1
		}
		return 0
	}) {
		if w != "" {
			out = append(out, w)
		}
	}
	return out
}

// shSubstEnd returns the index of the `)` (or closing backtick) that ends the substitution whose body
// starts at start, given the context that opened it; -1 if the text never closes it.
func shSubstEnd(rs []rune, start int, open byte) int {
	st := []byte{open}
	for i := start; i < len(rs); {
		next, after := shStep(rs, i, st)
		if len(after) == 0 {
			return i
		}
		i, st = next, after
	}
	return -1
}

// reservedWords open or close a compound command; the reader looks at the command they wrap.
var reservedWords = map[string]bool{
	"!": true, "{": true, "}": true, "then": true, "do": true, "else": true, "elif": true, "if": true,
	"while": true, "until": true, "time": true, "fi": true, "done": true, "esac": true,
}

// stripReserved takes compound-command keywords off the front of a command (`then curl …` → `curl …`) and
// drops the ones that are only a keyword. `for` and `case` heads are not commands and come back empty.
func stripReserved(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	for {
		f := strings.Fields(cmd)
		if len(f) == 0 || !reservedWords[f[0]] {
			break
		}
		cmd = strings.TrimSpace(strings.TrimPrefix(cmd, f[0]))
	}
	if f := strings.Fields(cmd); len(f) > 0 && (f[0] == "for" || f[0] == "case" || f[0] == "select") {
		return ""
	}
	return strings.TrimSpace(strings.TrimSuffix(cmd, "}"))
}

// redirect is one redirection of a stage: its operator and its target word (quotes kept).
type redirect struct{ op, target string }

var redirectRE = regexp.MustCompile(`^(?:[0-9]*|&)(>>|>\||>&|>|<<<|<<-|<<|<&|<>|<)(.*)$`)

// splitRedirects separates a stage's words into arguments and redirections. A redirection's target is
// the rest of its word or, when that is empty, the next word. `<(` is a process substitution, not one.
func splitRedirects(words []string) (args []string, redirs []redirect) {
	for i := 0; i < len(words); i++ {
		w := words[i]
		m := redirectRE.FindStringSubmatch(w)
		if m == nil || strings.HasPrefix(w, "<(") || strings.HasPrefix(w, ">(") {
			args = append(args, w)
			continue
		}
		target := m[2]
		if target == "" && i+1 < len(words) {
			i++
			target = words[i]
		}
		redirs = append(redirs, redirect{op: m[1], target: target})
	}
	return args, redirs
}

// dequote is a word with its quoting removed and nothing expanded: what the patterns compare against.
func dequote(w string) string {
	var b strings.Builder
	var q rune
	rs := []rune(w)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case q == 0 && (r == '\'' || r == '"'):
			q = r
		case q != 0 && r == q:
			q = 0
		case r == '\\' && q != '\'' && i+1 < len(rs):
			i++
			b.WriteRune(rs[i])
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// knownTools are the commands the shell reader dispatches on (hookegress_shtools.go).
var knownTools = map[string]bool{"curl": true, "wget": true, "jq": true, "gojq": true, "nc": true, "ncat": true,
	"socat": true, "cat": true, "base64": true, "http": true, "xh": true}

// toolName is cmdName, except that a command run through a variable named for a tool it knows — `"$CURL"`,
// `${JQ_BIN}` — is that tool: the name is the script's own statement of what the variable holds.
func toolName(w string) string {
	d := cmdName(w)
	if !strings.HasPrefix(d, "$") {
		return d
	}
	n := strings.ToLower(leadingName(strings.TrimPrefix(strings.TrimPrefix(d, "$"), "{")))
	for _, suffix := range []string{"_bin", "_cmd", "_path", "_exe"} {
		n = strings.TrimSuffix(n, suffix)
	}
	if knownTools[n] {
		return n
	}
	return d
}

// cmdName is the base name of a command word: `/usr/bin/curl` and `"curl"` are curl.
func cmdName(w string) string {
	d := dequote(w)
	if i := strings.LastIndexByte(d, '/'); i >= 0 {
		d = d[i+1:]
	}
	return d
}
