// SPDX-License-Identifier: MIT
package detect

import (
	"regexp"
	"strings"

	"github.com/basdotio/bas-guard/internal/model"
)

// The shell reader of HOOK-003's command half (P-128): a hook command line, or a .sh/.bash/.zsh script a
// hook runs. Its stdin is the event. Each logical line is split into commands, pipelines and stages
// (hookegress_shlex.go); what flows through a pipeline, what a name was assigned, and what a `$(…)`
// prints are tracked as a hookFlow, forward, through the one file. A send is a sender stage — curl,
// wget, nc, socat, httpie, or an output redirection to /dev/tcp — that is handed a sendable flow.

// shellEval is the state of one read: the names assigned so far and the sends found.
type shellEval struct {
	unit    int
	assigns map[string]string // NAME -> host, the file's URL assignments (P-061)
	vars    map[string]taint
	files   map[string]taint // literal paths this file wrote the payload to (redirectOut)
	sends   []hookSend
	line    int
	at      model.Evidence
	heredoc taint // what the current line's here-document expands to
	depth   int
	steps   int
	// cond counts the if/case/loop bodies the current line is inside. There an assignment is one branch of
	// several, so it adds to what the name may hold instead of replacing it: `case` arms that set a message
	// to a fixed text must not erase the arm that set it to the command being run.
	cond int
}

// maxShellDepth bounds nesting (`$(… $(… ))`, `bash -c`, xargs) and maxShellSteps the stages one read
// visits: a file built to nest deeper, or to make a word be read twice at every level, is read that far
// and no further, rather than recursing on attacker-chosen text.
const (
	maxShellDepth = 16
	maxShellSteps = 200_000
)

func shellSends(rel string, idx int, u unit, lines []logicalLine, view func(logicalLine) string) []hookSend {
	e := &shellEval{unit: idx, assigns: urlAssignments(u.text), vars: map[string]taint{}, files: map[string]taint{}}
	stdin := taint{flow: flowEvent}
	for i := 0; i < len(lines); i++ {
		ll := lines[i]
		if ll.comment {
			continue
		}
		lineNo := ll.start
		if u.synthetic {
			lineNo = 0
		}
		e.line, e.at = i, model.Evidence{File: rel, Line: lineNo, Snippet: u.evidence(ll.raw)}
		text := view(ll)
		// A line that ends in `|`, `&&` or `||` continues on the next one: `jq -n … |` above `curl -d @- …`
		// is one pipeline whose curl reads jq's output, not the hook's stdin.
		for continuesPipeline(text) && i+1 < len(lines) {
			i++
			text += " " + view(lines[i])
		}
		e.heredoc, i = e.heredocBody(lines, i, text, view, stdin)
		e.list(text, stdin)
	}
	return e.sends
}

// continuesPipeline reports whether a line ends in an operator that takes its right side from the next line.
func continuesPipeline(line string) bool {
	t := strings.TrimRight(line, " \t\r")
	if i := strings.LastIndex(t, " #"); i >= 0 && !strings.ContainsAny(t[i:], "'\"") {
		t = strings.TrimRight(t[:i], " \t")
	}
	return strings.HasSuffix(t, "|") || strings.HasSuffix(t, "&&")
}

// heredocRE is a here-document operator and its delimiter (not `<<<`).
var heredocRE = regexp.MustCompile(`(?:^|[^<])<<(-?)\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)['"]?`)

// heredocBody reads the here-document a line opens, if any: what its body expands to, and the index of
// its last line (the delimiter), so the caller does not read the body as commands. A quoted delimiter
// expands nothing. Only an operator outside quotes opens one, and one whose delimiter never comes skips
// nothing: otherwise `echo "<<EOF"` would hide every line after it from this reader.
func (e *shellEval) heredocBody(lines []logicalLine, i int, text string, view func(logicalLine) string, stdin taint) (taint, int) {
	loc := heredocRE.FindStringSubmatchIndex(text)
	if loc == nil || !topLevelAt(text, loc[0]) {
		return taint{}, i
	}
	dash, quoted, delim := text[loc[2]:loc[3]] == "-", loc[5] > loc[4], text[loc[6]:loc[7]]
	var body []string
	for j := i + 1; j < len(lines); j++ {
		l := view(lines[j])
		if dash {
			l = strings.TrimLeft(l, "\t")
		}
		if strings.TrimRight(l, " \t\r") == delim {
			if quoted {
				return taint{}, j
			}
			return e.expand([]rune(strings.Join(body, "\n")), stdin, true), j
		}
		body = append(body, view(lines[j]))
	}
	return taint{}, i
}

// topLevelAt reports whether byte offset at of s lies outside every quote and substitution.
func topLevelAt(s string, at int) bool {
	rs := []rune(s[:at])
	var st []byte
	for i := 0; i < len(rs); {
		i, st = shStep(rs, i, st)
	}
	return len(st) == 0
}

// list reads a command list; its flow is what the list prints.
func (e *shellEval) list(text string, in taint) taint {
	var out taint
	for _, cmd := range shCommands(text) {
		e.track(cmd)
		if c := stripReserved(cmd); c != "" {
			out = out.or(e.pipeline(c, in))
		}
	}
	return out
}

// track follows how deep in if/case/loop bodies the reader is, from the keywords that open and close them.
func (e *shellEval) track(cmd string) {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return
	}
	switch f[0] {
	case "if", "case", "while", "until", "for", "select":
		e.cond++
	case "fi", "esac", "done":
		if e.cond > 0 {
			e.cond--
		}
	}
}

// pipeline feeds each stage the previous stage's output; the first stage reads in.
func (e *shellEval) pipeline(cmd string, in taint) taint {
	flow := in
	for _, st := range shStages(cmd) {
		flow = e.stage(strings.TrimSpace(st), flow)
	}
	return flow
}

// stage reads one simple command (or a parenthesised group) given its stdin, and returns its stdout.
func (e *shellEval) stage(st string, in taint) taint {
	if e.depth >= maxShellDepth || e.steps >= maxShellSteps || st == "" {
		return taint{}
	}
	e.steps++
	e.depth++
	defer func() { e.depth-- }()
	if strings.HasPrefix(st, "(") && strings.HasSuffix(st, ")") && !strings.HasPrefix(st, "((") {
		return e.list(st[1:len(st)-1], in)
	}
	args, redirs := splitRedirects(shWordsKept(st))
	if len(args) > 0 && casePatternRE.MatchString(args[0]) {
		args = args[1:] // `Stop) body="…"`: the command is what follows a case pattern
	}
	in = e.redirectIn(redirs, in)
	args = e.assignments(args, in)
	if len(args) == 0 {
		for _, r := range redirs {
			if r.op == "<" {
				return in // `$(< file)` prints the file
			}
		}
		return taint{}
	}
	args = stripWrappers(args)
	if len(args) == 0 {
		return taint{}
	}
	argT := make([]taint, len(args))
	for i, w := range args {
		argT[i] = e.word(w, in)
	}
	out := e.command(st, args, argT, in)
	e.redirectOut(st, redirs, out)
	return out
}

var casePatternRE = regexp.MustCompile(`^\(?[^()\s]+\)$`)

// redirectIn applies a stage's input redirections to its stdin.
func (e *shellEval) redirectIn(redirs []redirect, in taint) taint {
	for _, r := range redirs {
		switch r.op {
		case "<":
			in = e.fileTaint(r.target, e.word(r.target, in), in)
		case "<<<":
			in = e.word(r.target, in)
		case "<<":
			in = e.heredoc
		case "<&":
			if dequote(r.target) != "0" {
				in = taint{}
			}
		}
	}
	return in
}

// devNetRE is bash's network pseudo-file: an output redirection to it is a send.
var devNetRE = regexp.MustCompile(`^/dev/(?:tcp|udp)/([^/\s]+)/`)

var varRefRE = regexp.MustCompile(`^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$`)

// redirectOut handles a stage's output redirections: to /dev/tcp or /dev/udp it is a send; to a file, when
// the output is sendable, that file now holds the payload, so whatever later reads it — `cat "$TMP"`,
// `curl -d @/tmp/e.json` — reads the payload. The file is remembered by the name that holds its path, or by
// its literal path.
func (e *shellEval) redirectOut(st string, redirs []redirect, out taint) {
	if !out.flow.sendable() {
		return
	}
	for _, r := range redirs {
		if r.op != ">" && r.op != ">>" && r.op != ">|" {
			continue
		}
		target := dequote(r.target)
		at := e.at
		switch m := devNetRE.FindStringSubmatch(target); {
		case m != nil:
			e.record(out, destinationLocal(st, e.assigns, []string{m[1]}))
		case varRefRE.MatchString(target):
			e.vars[varRefRE.FindStringSubmatch(target)[1]] = taint{flow: flowPath, src: &at}
		case target != "" && !strings.ContainsAny(target, "$`") && !strings.HasPrefix(target, "/dev/"):
			e.files[target] = taint{flow: flowPath, src: &at}
		}
	}
}

// fileTaint is what reading the file a word names yields: the stream itself for `-` and /dev/stdin, the
// transcript for a word that holds its path, nothing for any other file.
func (e *shellEval) fileTaint(word string, wt, stdin taint) taint {
	switch d := dequote(word); {
	case d == "-" || d == "/dev/stdin" || d == "/dev/fd/0":
		return stdin
	case wt.flow == flowPath:
		return taint{flow: flowTranscript, src: wt.src}
	case e.files[d].flow == flowPath:
		return taint{flow: flowTranscript, src: e.files[d].src}
	}
	return taint{}
}

var (
	assignWordRE = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)(\+?=)(.*)$`)
	declBuiltins = map[string]bool{"export": true, "local": true, "declare": true, "readonly": true, "typeset": true}
)

// assignments takes the NAME=VALUE words off the front of a stage and records them; what is left is the
// command they prefix (nothing, for an assignment statement). `export`/`local`/… lines are all assignments.
func (e *shellEval) assignments(args []string, in taint) []string {
	decl := len(args) > 0 && declBuiltins[args[0]]
	if decl {
		args = args[1:]
	}
	for len(args) > 0 {
		if decl && strings.HasPrefix(args[0], "-") {
			args = args[1:]
			continue
		}
		m := assignWordRE.FindStringSubmatch(args[0])
		if m == nil {
			if decl {
				args = args[1:] // `export NAME`: no value
				continue
			}
			return args
		}
		t := e.word(m[3], in)
		if t.flow != flowNone {
			at := e.at
			t.src = &at
		}
		if m[2] == "+=" || e.cond > 0 {
			t = e.vars[m[1]].or(t) // the line cited stays the one that put the payload in
		}
		e.vars[m[1]] = t
		args = args[1:]
	}
	return nil
}

// wrapperFlags are the options of a wrapper command that take a value.
var wrapperFlags = map[string]map[string]bool{
	"sudo":    {"-u": true, "-g": true, "-C": true, "-h": true, "-p": true},
	"env":     {"-u": true, "-C": true, "-S": true},
	"timeout": {"-s": true, "-k": true, "--signal": true, "--kill-after": true},
	"nice":    {"-n": true},
}

// wrappers only run another command: the reader looks at that one.
var wrappers = map[string]bool{"nohup": true, "exec": true, "time": true, "command": true, "builtin": true,
	"sudo": true, "env": true, "timeout": true, "nice": true, "stdbuf": true}

// stripWrappers takes nohup, exec, sudo, env, timeout, nice, stdbuf, time, command and builtin off the
// front of a command, with their options.
func stripWrappers(args []string) []string {
	for len(args) > 0 && wrappers[cmdName(args[0])] {
		args = skipWrapperOptions(cmdName(args[0]), args[1:])
	}
	return args
}

func skipWrapperOptions(name string, args []string) []string {
	for len(args) > 0 {
		d := dequote(args[0])
		switch {
		case wrapperFlags[name][d]:
			args = args[min(2, len(args)):]
		case strings.HasPrefix(d, "-"), name == "env" && assignWordRE.MatchString(d):
			args = args[1:]
		case name == "timeout":
			return args[1:] // its duration
		default:
			return args
		}
	}
	return args
}

// command dispatches a stage on its command name.
func (e *shellEval) command(st string, args []string, argT []taint, in taint) taint {
	switch name := toolName(args[0]); name {
	case "cat", "tac", "head", "tail", "base64", "gzip", "xz", "bzip2", "zstd", "xxd":
		return e.fileOrStdin(args, argT, in)
	case "tee":
		return in
	case "jq", "gojq":
		return e.jq(args, argT, in)
	case "echo", "printf":
		var out taint
		for _, t := range argT[1:] {
			out = out.or(t)
		}
		return out
	case "read":
		e.read(args, in)
	case "bash", "sh", "zsh", "dash", "ksh":
		for i := 1; i+1 < len(args); i++ {
			if dequote(args[i]) == "-c" {
				return e.list(dequote(args[i+1]), in)
			}
		}
	case "eval":
		return e.list(dequote(strings.Join(args[1:], " ")), in)
	case "xargs":
		return e.xargs(args, in)
	default:
		if sent, extra, ok := e.sent(name, args, argT, in); ok && sent.flow.sendable() {
			e.record(sent, destinationLocal(st, e.assigns, extra))
		}
	}
	return taint{}
}

// record files a send at the current line.
func (e *shellEval) record(t taint, local bool) {
	e.sends = append(e.sends, hookSend{unit: e.unit, line: e.line, at: e.at, src: t.src, local: local})
}

// word is what a shell word expands to.
func (e *shellEval) word(w string, in taint) taint { return e.expand([]rune(w), in, false) }

// expand reads the expansions in rs — `$NAME`, `${NAME…}`, `$(…)`, backticks — and returns the most
// any of them holds; a `$(…)` reads in as its stdin. Single quotes expand nothing, unless quotes are
// literal (a here-document body).
func (e *shellEval) expand(rs []rune, in taint, literalQuotes bool) taint {
	var t taint
	inSingle, inDouble := false, false
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case !literalQuotes && inSingle:
			inSingle = r != '\''
		case !literalQuotes && r == '\'' && !inDouble:
			inSingle = true
		case !literalQuotes && r == '"':
			inDouble = !inDouble
		case r == '\\':
			i++
		case r == '`', r == '$' && i+1 < len(rs) && rs[i+1] == '(':
			open, from := byte('`'), i+1
			if r == '$' {
				open, from = '(', i+2
			}
			end := shSubstEnd(rs, from, open)
			if end < 0 {
				end = len(rs)
			}
			t = t.or(e.list(string(rs[from:end]), in))
			i = end
		case r == '$' && i+1 < len(rs) && rs[i+1] == '{':
			end := shSubstEnd(rs, i+2, '{')
			if end < 0 {
				end = len(rs)
			}
			t = t.or(e.vars[leadingName(string(rs[i+2:end]))])
			i = end
		case r == '$':
			name := leadingName(string(rs[i+1:]))
			t = t.or(e.vars[name])
			i += len(name)
		}
	}
	return t
}

var leadingNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*`)

func leadingName(s string) string { return leadingNameRE.FindString(s) }
