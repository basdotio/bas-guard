// SPDX-License-Identifier: MIT
package detect

import (
	"regexp"
	"sort"
	"strings"

	"github.com/basdotio/bas-guard/internal/model"
)

// The Python and Node reader of HOOK-003's command half (P-128). A script is read as STATEMENTS: a line
// that starts one (outside any open bracket, or directly inside a block brace) with the lines that
// continue it, so a call spread over several lines is one send. Names are followed forward through the
// file the way the shell reader follows them: an assignment whose right side holds the payload whole
// passes it on; a field selected out of the event passes on what that field is (fieldFlow).

type codeLang struct {
	stdin  *regexp.Regexp // reads the whole of stdin; every match ends inside the call that reads
	sender *regexp.Regexp // a statement whose first line matches sends a request
	shell  *regexp.Regexp // a subprocess call: a send only when it runs curl or wget
	node   bool
}

var (
	pythonLang = codeLang{
		stdin:  regexp.MustCompile(`sys\.stdin(?:\.buffer)?\.read(?:lines|line)?\(|json\.load\(\s*sys\.stdin(?:\.buffer)?|\bjoin\(\s*sys\.stdin|\bopen\(\s*(?:0\b|['"]/dev/stdin['"])|\bfileinput\.input\(|(?:^|[^\w.])input\(`),
		sender: regexp.MustCompile(`\brequests\.(?:post|put|patch|request)\(|\bhttpx\.(?:post|put|patch|request|stream)\(|\b(?:session|client|sess|http|conn)\.(?:post|put|patch|request)\(|\b\w+\.post\(|\burlopen\(|\bRequest\(|\.sendall\(|\bsock\w*\.send\(`),
		shell:  regexp.MustCompile(`\bsubprocess\.(?:run|Popen|call|check_output|check_call)\(`),
	}
	nodeLang = codeLang{
		stdin:  regexp.MustCompile(`readFileSync\(\s*(?:0\b|['"]/dev/stdin['"]|process\.stdin\.fd)|\b(?:get|read)Stdin\w*\(|\bBun\.stdin\.(?:text|json)\(`),
		sender: regexp.MustCompile(`\bfetch\(|\baxios(?:\.(?:post|put|patch|request))?\(|\bgot(?:\.(?:post|put|patch))?\(|\bhttps?\.(?:request|get)\(|\b\w+\.post\(|\bsendBeacon\(`),
		shell:  regexp.MustCompile(`\b(?:spawn|exec|execFile)(?:Sync)?\(`),
		node:   true,
	}

	// nodeChunkRE: the parameter a stdin data callback, a `for await` over stdin, or a readline line
	// handler binds — each one a piece of the event, accumulated into a name the reader then follows.
	nodeChunkRE = regexp.MustCompile(`process\.stdin\.on\(\s*['"]data['"]\s*,\s*(?:async\s+)?(?:function\s*\w*\s*)?\(?\s*([A-Za-z_$][\w$]*)|for\s+await\s*\(\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s+of\s+process\.stdin`)
	// readlineStdinRE: a readline interface over stdin, whose line handler's parameter is then a piece of it.
	readlineStdinRE = regexp.MustCompile(`input\s*:\s*process\.stdin`)
	nodeLineRE      = regexp.MustCompile(`\.on\(\s*['"]line['"]\s*,\s*(?:async\s+)?(?:function\s*\w*\s*)?\(?\s*([A-Za-z_$][\w$]*)`)
	pyStdinLoopRE   = regexp.MustCompile(`\bfor\s+([A-Za-z_]\w*)\s+in\s+sys\.stdin\b`)
	accumulateRE    = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*(?:\+=\s*|\.push\(\s*)([A-Za-z_$][\w$]*)\b`)
	codeAssignRE    = regexp.MustCompile(`^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*(?::\s*[^=]+?)?\s*(\+?=)([^=>][\s\S]*)$`)
	pyWithRE        = regexp.MustCompile(`^\s*(?:async\s+)?with\s+([\s\S]+?)\s+as\s+([A-Za-z_]\w*)\s*:`)
	jsDestructRE    = regexp.MustCompile(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*([\s\S]+)$`)
	requestObjRE    = regexp.MustCompile(`\bhttps?\.request\(|\bnet\.(?:connect|createConnection)\(|\btls\.connect\(|\bnew\s+WebSocket\(|\bRequest\(|\bHTTPS?Connection\(`)
	requestUseRE    = regexp.MustCompile(`^\s*(?:await\s+)?([A-Za-z_$][\w$]*)\.(?:write|end|send|request)\(|\burlopen\(\s*([A-Za-z_]\w*)\s*[,)]`)
	shellSendRE     = regexp.MustCompile(`\b(?:curl|wget)\b`)
)

// codeEval is the state of one read.
type codeEval struct {
	lang    codeLang
	unit    int
	assigns urlTable
	vars    map[string]taint
	reqs    map[string][]string // request objects (https.request, Request(…)) -> the hosts their constructor names
	sends   []hookSend
	stdin   hookFlow // what stdin holds: the event for a hook, the session status for a status line (P-133)
}

func pythonSends(rel string, idx int, u unit, lines []logicalLine, view func(logicalLine) string) []hookSend {
	return codeSends(pythonLang, rel, idx, u, lines, view)
}

func nodeSends(rel string, idx int, u unit, lines []logicalLine, view func(logicalLine) string) []hookSend {
	return codeSends(nodeLang, rel, idx, u, lines, view)
}

func codeSends(lang codeLang, rel string, idx int, u unit, lines []logicalLine, view func(logicalLine) string) []hookSend {
	e := &codeEval{lang: lang, unit: idx, stdin: stdinFlow(u), assigns: urlAssignments(u.text), vars: map[string]taint{},
		reqs: map[string][]string{}}
	readline := lang.node && readlineStdinRE.MatchString(u.text)
	for _, s := range codeStatements(lines, view, lang.node) {
		at := model.Evidence{File: rel, Line: lines[s.idx].start, Snippet: u.evidence(lines[s.idx].raw)}
		e.bind(s, at, readline)
		e.maybeSend(s, at)
	}
	return e.sends
}

// bind records what a statement assigns.
func (e *codeEval) bind(s codeStmt, at model.Evidence, readline bool) {
	set := func(name string, t taint) {
		if t.flow != flowNone {
			a := at
			t.src = &a
		}
		e.vars[name] = t
	}
	// A stdin callback's parameter is a piece of the event only inside that callback, which is this
	// statement's own text: a response handler further down that also calls its parameter `chunk` is not.
	chunks := map[string]bool{}
	for _, m := range nodeChunkRE.FindAllStringSubmatch(s.text, -1) {
		chunks[m[1]+m[2]] = true
	}
	if readline {
		for _, m := range nodeLineRE.FindAllStringSubmatch(s.text, -1) {
			chunks[m[1]] = true
		}
	}
	if m := pyStdinLoopRE.FindStringSubmatch(s.first); m != nil && !e.lang.node {
		set(m[1], taint{flow: e.stdin})
	}
	for _, m := range accumulateRE.FindAllStringSubmatch(s.text, -1) {
		if chunks[m[2]] {
			set(m[1], taint{flow: e.stdin})
		}
	}
	for _, name := range paramNames(s.text, e.lang.node) {
		delete(e.vars, name) // a parameter is whatever the caller passes, not the file's value of that name
	}
	switch {
	case !e.lang.node && pyWithRE.MatchString(s.first):
		m := pyWithRE.FindStringSubmatch(s.first)
		set(m[2], e.expr(m[1]))
	case e.lang.node && jsDestructRE.MatchString(s.text):
		m := jsDestructRE.FindStringSubmatch(s.text)
		e.destructure(m[1], e.expr(m[2]), set)
	default:
		m := codeAssignRE.FindStringSubmatch(s.text)
		if m == nil {
			return
		}
		t := e.expr(m[3])
		if m[2] == "+=" {
			t = e.vars[m[1]].or(t)
		}
		set(m[1], t)
		if requestObjRE.MatchString(m[3]) {
			e.reqs[m[1]] = append(networkHosts(m[3]), resolvedHosts(m[3], e.assigns)...)
		}
	}
}

// destructure binds `const { prompt, transcript_path: tp } = input` the way a selection would.
func (e *codeEval) destructure(pattern string, from taint, set func(string, taint)) {
	for _, part := range strings.Split(pattern, ",") {
		key, alias, found := strings.Cut(part, ":")
		key = strings.TrimSpace(key)
		name := key
		if found {
			name = strings.TrimSpace(strings.SplitN(alias, "=", 2)[0])
		}
		if key != "" && leadingName(name) == name {
			set(name, selected(from, "."+key))
		}
	}
}

// maybeSend records a send when the statement's first line calls a sender (or a request object it made)
// and the statement hands it something sendable.
func (e *codeEval) maybeSend(s codeStmt, at model.Evidence) {
	var hosts []string
	viaObject := false
	if m := requestUseRE.FindStringSubmatch(s.first); m != nil {
		hosts, viaObject = e.reqs[m[1]+m[2]]
	}
	if !viaObject && !e.lang.sender.MatchString(s.first) &&
		!(e.lang.shell.MatchString(s.first) && shellSendRE.MatchString(s.text)) {
		return
	}
	t := e.expr(s.text)
	if !t.flow.sendable() {
		return
	}
	local := destinationLocal(s.text, e.assigns, nil)
	if viaObject {
		local = len(hosts) > 0
		for _, h := range hosts {
			local = local && loopbackHost(h)
		}
	}
	e.sends = append(e.sends, hookSend{unit: e.unit, line: s.idx, at: at, src: t.src, local: local})
}

// expr is the most a piece of code holds: stdin read in place, a name that holds the payload (whole or
// through a selection), or the transcript read through a name that holds its path. String contents are
// not code, except interpolations (`f"{x}"`, `${x}`).
func (e *codeEval) expr(text string) taint {
	masked, inStr := maskStrings(text)
	var t taint
	for _, loc := range e.lang.stdin.FindAllStringIndex(text, -1) {
		if !inStr[loc[0]] {
			t = t.or(use(taint{flow: e.stdin}, text[afterCall(text, loc[1]):]))
		}
	}
	names := make([]string, 0, len(e.vars))
	for n, v := range e.vars {
		if v.flow != flowNone {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		for _, at := range identAt(masked, n) {
			t = t.or(e.mention(text, at, at+len(n), e.vars[n]))
		}
	}
	return t
}

// fallbackRE is an empty default closing a parenthesised value — `(payload or {})`, `(input || {})`, `(x ?? {})` —
// after which a selection still selects out of the value.
var fallbackRE = regexp.MustCompile(`^\s*(?:or|\|\||\?\?)\s*(?:\{\s*\}|\[\s*\]|None|null|undefined|""|'')\s*\)`)

// use is what a value contributes where it is followed by rest: a selection out of it, or itself whole.
func use(v taint, rest string) taint {
	if m := fallbackRE.FindString(rest); m != "" {
		rest = rest[len(m):]
	}
	if sel := selectorAfter(rest); sel != "" {
		return selected(v, sel)
	}
	return v
}

// mention is what one occurrence of a name contributes: a path is read (the transcript) or nothing; any
// other value is selected from, or used whole.
func (e *codeEval) mention(text string, start, end int, v taint) taint {
	if v.flow == flowPath {
		if readsPath(text[:start], text[end:]) {
			return taint{flow: flowTranscript, src: v.src}
		}
		return taint{}
	}
	return use(v, text[end:])
}

var (
	readerBeforeRE = regexp.MustCompile(`(?:\bopen|readFileSync|readFile|createReadStream|Bun\.file)\(\s*(?:os\.path\.expanduser\(\s*)?$`)
	pathCtorRE     = regexp.MustCompile(`\bPath\(\s*$`)
	readAfterRE    = regexp.MustCompile(`^\s*\.(?:read_text|read_bytes|open|read)\(`)
	ctorReadRE     = regexp.MustCompile(`^\s*\)\s*\.(?:read_text|read_bytes|open)\(`)
)

// readsPath reports whether a name holding the transcript's path is opened or read at this occurrence.
func readsPath(before, after string) bool {
	return readerBeforeRE.MatchString(before) || readAfterRE.MatchString(after) ||
		pathCtorRE.MatchString(before) && ctorReadRE.MatchString(after)
}

var (
	subscriptRE = regexp.MustCompile(`^\s*\[\s*["']([A-Za-z_]\w*)["']\s*\]`)
	getCallRE   = regexp.MustCompile(`^\s*\.get\(\s*["']([A-Za-z_]\w*)["']`)
	propertyRE  = regexp.MustCompile(`^\s*\??\.\s*([A-Za-z_$][\w$]*)\s*(\(?)`)
)

// selectorAfter is the field selector right after a value (`["prompt"]`, `.get("cwd"`, `.prompt`), written
// as `.field`, or "" when the value is used whole — a method call (`raw.encode()`) uses it whole.
func selectorAfter(rest string) string {
	if m := subscriptRE.FindStringSubmatch(rest); m != nil {
		return "." + m[1]
	}
	if m := getCallRE.FindStringSubmatch(rest); m != nil {
		return "." + m[1]
	}
	if m := propertyRE.FindStringSubmatch(rest); m != nil && m[2] == "" {
		return "." + m[1]
	}
	return ""
}

// afterCall returns the offset past the call a stdin match sits inside, and past any calls closing
// around it, so what follows is what is done with the result.
func afterCall(text string, pos int) int {
	depth := 1
	_, inStr := maskStrings(text)
	i := pos
	for ; i < len(text) && depth > 0; i++ {
		if inStr[i] {
			continue
		}
		switch text[i] {
		case '(':
			depth++
		case ')':
			depth--
		}
	}
	for i < len(text) && (text[i] == ')' || text[i] == ' ') {
		i++
	}
	return i
}

// identAt returns the offsets where name occurs as a value: not part of a longer name, not an attribute of
// something else, not a keyword argument or object key (`data=…`, `data: …`), and not a string prefix —
// `f` in `f"…"` is Python's f-string, not a variable named f.
func identAt(masked, name string) []int {
	var out []int
	for off := 0; ; {
		i := strings.Index(masked[off:], name)
		if i < 0 {
			return out
		}
		at, end := off+i, off+i+len(name)
		off = end
		if at > 0 && isIdentByte(masked[at-1]) || at > 0 && masked[at-1] == '.' || end < len(masked) && isIdentByte(masked[end]) {
			continue
		}
		if end < len(masked) && strings.IndexByte("\"'`", masked[end]) >= 0 {
			continue
		}
		rest := strings.TrimLeft(masked[end:], " \t")
		if strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, "==") || strings.HasPrefix(rest, ":") && !strings.HasPrefix(rest, "::") {
			continue
		}
		out = append(out, at)
	}
}

func isIdentByte(b byte) bool {
	return b == '_' || b == '$' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= 0x80
}

// maskStrings blanks the contents of string literals (byte for byte, so offsets hold), keeping the
// interpolations inside them (`{…}` of an f-string or a template literal), and reports which bytes were
// inside a string.
func maskStrings(text string) (string, []bool) {
	b := []byte(text)
	in := make([]bool, len(b))
	var q byte
	interp := 0
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case q == 0 && (c == '"' || c == '\'' || c == '`'):
			q = c
		case q == 0:
		case interp > 0:
			switch c {
			case '{':
				interp++
			case '}':
				interp--
			}
		case c == '\\':
			in[i] = true
			b[i] = ' '
			if i+1 < len(b) {
				i++
				in[i] = true
				b[i] = ' '
			}
		case c == q:
			q = 0
		case c == '{':
			interp = 1
		default:
			in[i] = true
			b[i] = ' '
		}
	}
	return string(b), in
}

// codeStmt is one statement: the logical line it starts on, that line, and its text with continuations.
type codeStmt struct {
	idx   int
	first string
	text  string
}

// maxStmtLines bounds how far a statement is joined: a file with an unbalanced bracket costs a bounded
// join per line, and the statements that matter are a call and its arguments.
const maxStmtLines = 40

// codeStatements returns the statements of a script. A line starts one when no bracket is open, or the
// innermost open one is a block brace (after `)`, `=>`, else/try/finally/do) rather than an object or a
// call's argument list — so `json=data,` inside a call is never read as an assignment.
func codeStatements(lines []logicalLine, view func(logicalLine) string, node bool) []codeStmt {
	var out []codeStmt
	var stack []byte
	for i, ll := range lines {
		if ll.comment {
			continue
		}
		line := view(ll)
		if len(stack) == 0 || stack[len(stack)-1] == 'b' {
			out = append(out, codeStmt{idx: i, first: line, text: joinStatement(lines, i, view, node)})
		}
		stack = pushBrackets(stack, line, node)
	}
	return out
}

func joinStatement(lines []logicalLine, i int, view func(logicalLine) string, node bool) string {
	text := view(lines[i])
	bal := len(pushBrackets(nil, text, node))
	for j := i + 1; bal > 0 && j < len(lines) && j-i < maxStmtLines; j++ {
		if lines[j].comment {
			continue
		}
		t := view(lines[j])
		text += "\n" + t
		bal = len(pushBrackets(make([]byte, bal), t, node))
	}
	return text
}

var blockOpenerRE = regexp.MustCompile(`(?:\)|=>|\belse|\btry|\bfinally|\bdo)\s*$`)

// pushBrackets applies one line's brackets to the open stack: '(' and '[' push 'p', '{' pushes 'b' for a
// block or 'o' for an object literal; strings and line comments (`#` in Python, `//` in Node — in Python
// `//` is floor division) are skipped.
func pushBrackets(stack []byte, line string, node bool) []byte {
	masked, _ := maskStrings(line)
	for i := 0; i < len(masked); i++ {
		c := masked[i]
		switch {
		case !node && c == '#', node && c == '/' && i+1 < len(masked) && masked[i+1] == '/':
			return stack
		case c == '(' || c == '[':
			stack = append(stack, 'p')
		case c == '{':
			kind := byte('o')
			if blockOpenerRE.MatchString(masked[:i]) {
				kind = 'b'
			}
			stack = append(stack, kind)
		case (c == ')' || c == ']' || c == '}') && len(stack) > 0:
			stack = stack[:len(stack)-1]
		}
	}
	return stack
}

var (
	pyDefRE     = regexp.MustCompile(`^\s*(?:async\s+)?def\s+\w+\s*\(([\s\S]*?)\)\s*(?:->[^:]*)?:`)
	pyLambdaRE  = regexp.MustCompile(`\blambda\s+([^:]*):`)
	jsFuncRE    = regexp.MustCompile(`\bfunction\b\s*\*?\s*[\w$]*\s*\(([^)]*)\)`)
	jsArrowRE   = regexp.MustCompile(`\(([^()]*)\)\s*=>|\b([A-Za-z_$][\w$]*)\s*=>`)
	paramNameRE = regexp.MustCompile(`^[\s*.{\[]*([A-Za-z_$][\w$]*)`)
)

// paramNames are the parameters a statement declares (a def, a lambda, a function, an arrow): inside it
// those names hold what a caller passes, so the reader forgets what the file assigned them elsewhere.
func paramNames(text string, node bool) []string {
	var lists []string
	if node {
		for _, m := range jsFuncRE.FindAllStringSubmatch(text, -1) {
			lists = append(lists, m[1])
		}
		for _, m := range jsArrowRE.FindAllStringSubmatch(text, -1) {
			lists = append(lists, m[1]+m[2])
		}
	} else {
		if m := pyDefRE.FindStringSubmatch(text); m != nil {
			lists = append(lists, m[1])
		}
		for _, m := range pyLambdaRE.FindAllStringSubmatch(text, -1) {
			lists = append(lists, m[1])
		}
	}
	var out []string
	for _, l := range lists {
		for _, p := range strings.Split(l, ",") {
			if m := paramNameRE.FindStringSubmatch(p); m != nil {
				out = append(out, m[1])
			}
		}
	}
	return out
}
