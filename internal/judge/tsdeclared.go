// SPDX-License-Identifier: MIT
package judge

import (
	"regexp"
	"sort"
	"strings"
)

// The declared side of a TypeScript or JavaScript MCP server (P-116): the name and description a
// client is shown for each tool, read from the four forms the corpus's TS/JS servers use —
//
//	server.tool("name", "description", schema, handler)
//	server.registerTool("name", { title, description, inputSchema }, handler)
//	{ name: "x", description: "…", inputSchema: {…} }      in a ListTools handler's tools array
//	{ name: "x", description: "…", parameters, execute }    a fastmcp addTool argument
//
// It is a reader, not a parser: one pass that knows strings, template literals, comments and
// bracket nesting, enough to tell an object literal's own keys from its nested ones. A description
// it cannot read as a plain string (a variable, a template with ${…}) leaves the tool listed by name
// alone, as a Python tool without a docstring is. What it reads is the artifact author's text, like
// a docstring: it goes through declaredPurpose (redacted, capped) before it is sent.

// tsToolCall is `.tool("name"` with an optional plain-string description as the next argument.
var tsToolCall = regexp.MustCompile("\\.tool\\s*\\(\\s*(?:'([^'\\n]+)'|\"([^\"\\n]+)\"|`([^`$]+)`)\\s*(,\\s*)?")

// tsRegisterTool is `.registerTool("name", {`: the object whose own `description` is the tool's.
var tsRegisterTool = regexp.MustCompile("\\.registerTool\\s*\\(\\s*(?:'([^'\\n]+)'|\"([^\"\\n]+)\"|`([^`$]+)`)\\s*,\\s*\\{")

// tsToolObjectKeys mark an object literal as a tool definition rather than any {name, description}:
// a server's own `new McpServer({ name, version })`, a prompt or a resource has neither.
var tsToolObjectKeys = []string{"inputSchema", "input_schema", "parameters", "execute", "handler"}

// tsObject is one object literal: where its `{` is, its own keys, and the plain-string values of
// those keys.
type tsObject struct {
	start int
	has   map[string]bool
	str   map[string]string
}

// tsDeclared returns "name: first description line" (or the name alone) for every tool src
// declares, in source order.
func tsDeclared(src string) []string {
	objs, inert := tsObjects(src)
	byStart := make(map[int]*tsObject, len(objs))
	for i := range objs {
		byStart[objs[i].start] = &objs[i]
	}
	type entry struct {
		pos  int
		line string
	}
	var out []entry
	add := func(pos int, name, desc string) {
		line := name
		if d := firstLine(desc); d != "" {
			line += ": " + d
		}
		out = append(out, entry{pos, line})
	}
	for _, m := range tsToolCall.FindAllStringSubmatchIndex(src, -1) {
		if inert.covers(m[0]) {
			continue
		}
		name := pick(src, m, 1, 2, 3)
		desc := ""
		if m[8] >= 0 { // a comma follows the name: is the next argument a plain string?
			if v, _, ok := tsString(src, m[9]); ok {
				desc = v
			}
		}
		add(m[0], name, desc)
	}
	for _, m := range tsRegisterTool.FindAllStringSubmatchIndex(src, -1) {
		if inert.covers(m[0]) {
			continue
		}
		desc := ""
		if o := byStart[m[1]-1]; o != nil {
			desc = o.str["description"]
		}
		add(m[0], pick(src, m, 1, 2, 3), desc)
	}
	for _, o := range objs {
		name, ok := o.str["name"]
		if !ok || !o.has["description"] {
			continue
		}
		tool := false
		for _, k := range tsToolObjectKeys {
			tool = tool || o.has[k]
		}
		if tool {
			add(o.start, name, o.str["description"])
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].pos < out[j].pos })
	lines := make([]string, len(out))
	for i, e := range out {
		lines[i] = e.line
	}
	return lines
}

// pick returns the first matched group of m among gs.
func pick(src string, m []int, gs ...int) string {
	for _, g := range gs {
		if m[2*g] >= 0 {
			return src[m[2*g]:m[2*g+1]]
		}
	}
	return ""
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

// tsString reads the string literal at src[i:] (after any spaces). ok is false when there is no
// literal there or it is a template that interpolates; end is past what was consumed either way.
func tsString(src string, i int) (val string, end int, ok bool) {
	for i < len(src) && (src[i] == ' ' || src[i] == '\t' || src[i] == '\n' || src[i] == '\r') {
		i++
	}
	if i >= len(src) {
		return "", i, false
	}
	q := src[i]
	if q != '\'' && q != '"' && q != '`' {
		return "", i, false
	}
	var b strings.Builder
	plain := true
	j := i + 1
	for j < len(src) {
		c := src[j]
		switch {
		case c == '\\' && j+1 < len(src):
			b.WriteByte(unescape(src[j+1]))
			j += 2
			continue
		case c == q:
			return b.String(), j + 1, plain
		case q != '`' && c == '\n':
			return "", j, false // an unterminated quote: not a literal
		case q == '`' && c == '$' && j+1 < len(src) && src[j+1] == '{':
			plain = false
			j = skipInterpolation(src, j+2)
			continue
		}
		b.WriteByte(c)
		j++
	}
	return "", j, false
}

func unescape(c byte) byte {
	switch c {
	case 'n':
		return '\n'
	case 't':
		return '\t'
	}
	return c
}

// skipInterpolation returns the index past the `}` closing a template's ${ … } that starts at i,
// stepping over the strings inside it.
func skipInterpolation(src string, i int) int {
	depth := 1
	for i < len(src) && depth > 0 {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
		case '\'', '"', '`':
			_, e, _ := tsString(src, i)
			if e <= i {
				e = i + 1
			}
			i = e
			continue
		}
		i++
	}
	return i
}

// spans are the byte ranges [start, end) of src that are comments or string literals, in order:
// a `.tool(` the pattern finds in one of them is text, not a call.
type spans [][2]int

func (s spans) covers(pos int) bool {
	k := sort.Search(len(s), func(i int) bool { return s[i][1] > pos })
	return k < len(s) && s[k][0] <= pos
}

// tsObjects finds every object literal in src with its own keys, in one pass, and the comments and
// strings it stepped over. A bracket frame is an object ({), or anything else (( and [) whose commas
// do not start a key of the enclosing object.
func tsObjects(src string) ([]tsObject, spans) {
	type frame struct {
		obj       bool
		o         tsObject
		expectKey bool
		pending   string // the key whose value comes next
	}
	var stack []frame
	var out []tsObject
	var inert spans
	top := func() *frame {
		if len(stack) == 0 {
			return nil
		}
		return &stack[len(stack)-1]
	}
	isIdentStart := func(c byte) bool {
		return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	isIdent := func(c byte) bool { return isIdentStart(c) || (c >= '0' && c <= '9') }
	nextNonSpace := func(i int) int {
		for i < len(src) && (src[i] == ' ' || src[i] == '\t' || src[i] == '\n' || src[i] == '\r') {
			i++
		}
		return i
	}
	i := 0
	for i < len(src) {
		c := src[i]
		f := top()
		switch {
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			start := i
			for i < len(src) && src[i] != '\n' {
				i++
			}
			inert = append(inert, [2]int{start, i})
			continue
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			start := i
			if e := strings.Index(src[i+2:], "*/"); e >= 0 {
				i += e + 4
			} else {
				i = len(src)
			}
			inert = append(inert, [2]int{start, i})
			continue
		case c == '\'' || c == '"' || c == '`':
			v, e, ok := tsString(src, i)
			if e <= i {
				e = i + 1
			}
			inert = append(inert, [2]int{i, e})
			if f != nil && f.obj {
				if f.expectKey {
					if k := nextNonSpace(e); k < len(src) && src[k] == ':' {
						f.o.has[v] = true
						f.pending, f.expectKey = v, false
						i = k + 1
						continue
					}
					f.expectKey = false
				} else if f.pending != "" {
					if ok {
						f.o.str[f.pending] = v
					}
					f.pending = ""
				}
			}
			i = e
			continue
		case c == '{':
			if f != nil {
				f.pending, f.expectKey = "", false
			}
			stack = append(stack, frame{obj: true, expectKey: true, o: tsObject{start: i, has: map[string]bool{}, str: map[string]string{}}})
		case c == '(' || c == '[':
			if f != nil {
				f.pending, f.expectKey = "", false
			}
			stack = append(stack, frame{})
		case c == '}' || c == ')' || c == ']':
			if f != nil {
				if f.obj {
					out = append(out, f.o)
				}
				stack = stack[:len(stack)-1]
			}
		case c == ',':
			if f != nil && f.obj {
				f.expectKey, f.pending = true, ""
			}
		case isIdentStart(c):
			j := i
			for j < len(src) && isIdent(src[j]) {
				j++
			}
			if f != nil && f.obj {
				if f.expectKey {
					word := src[i:j]
					if k := nextNonSpace(j); (word == "async" || word == "get" || word == "set") && k < len(src) && isIdentStart(src[k]) {
						i = j // a method modifier: the key is the next word
						continue
					}
					f.o.has[word] = true // a key, a shorthand property or a method
					f.expectKey = false
					if k := nextNonSpace(j); k < len(src) && src[k] == ':' {
						f.pending = word
						i = k + 1
						continue
					}
				} else if f.pending != "" {
					f.pending = ""
				}
			}
			i = j
			continue
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
		default:
			if f != nil && f.obj && f.pending != "" {
				f.pending = ""
			}
		}
		i++
	}
	sort.Slice(out, func(a, b int) bool { return out[a].start < out[b].start })
	return out, inert
}
