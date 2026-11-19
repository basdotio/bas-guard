// SPDX-License-Identifier: MIT
package detect

import (
	"regexp"
	"strings"
)

// The commands HOOK-003's shell reader knows (P-128): the stream tools that pass the payload on (cat, head,
// base64, jq, read, xargs), and the senders — what each one sends, given its arguments, their flows and
// its stdin. A sender stage that sends nothing sendable is not a send; whether it reaches a remote host
// is decided by the caller from the stage's text.

// sent reports, for a sender command, what it sends and any destination host it names outside a URL
// (nc's host argument). ok is false for a command that is not a sender.
func (e *shellEval) sent(name string, args []string, argT []taint, in taint) (sent taint, hosts []string, ok bool) {
	switch name {
	case "curl":
		return e.curlSent(args, argT, in), nil, true
	case "wget":
		return e.wgetSent(args, argT, in), nil, true
	case "nc", "ncat", "netcat", "telnet":
		sent, hosts = ncSent(args, in)
		return sent, hosts, true
	case "socat":
		sent, hosts = socatSent(args, in)
		return sent, hosts, true
	case "http", "https", "xh", "xhs":
		sent, hosts = httpieSent(args, argT, in)
		return sent, hosts, true
	}
	return taint{}, nil, false
}

var (
	// curlStdinRE: a curl data, form or upload argument that reads curl's stdin — `@-` (-d, --data-binary,
	// --json, --data-urlencode `name@-`), a form field `name=@-` or `name=<-`, attached `-d@-`.
	curlStdinRE = regexp.MustCompile(`^(?:-[dF])?@-$|^[^=@<\s]*=[@<]-$|^[A-Za-z0-9_.-]+@-$`)
	// curlFileRE: the same arguments naming a file instead: `@FILE`, `name=@FILE`, `name=<FILE`, `name@FILE`.
	curlFileRE = regexp.MustCompile(`^(?:-[dF])?(?:[^=@<\s]*=)?[@<](.+)$|^[A-Za-z0-9_.-]+@(.+)$`)
)

// curlSent: stdin through `@-` and friends or `-T -`, the transcript through `@FILE` or `-T FILE` when FILE
// holds its path, and any argument whose own value is sendable (`-d "$INPUT"`, a header, the URL).
func (e *shellEval) curlSent(args []string, argT []taint, in taint) taint {
	var sent taint
	for i := 1; i < len(args); i++ {
		d := dequote(args[i])
		if p := dequote(args[i-1]); p == "-T" || p == "--upload-file" {
			sent = sent.or(e.fileTaint(args[i], argT[i], in))
			if d == "." {
				sent = sent.or(in)
			}
			continue
		}
		if curlStdinRE.MatchString(d) {
			sent = sent.or(in)
		} else if m := curlFileRE.FindStringSubmatch(d); m != nil {
			target := m[1] + m[2]
			sent = sent.or(e.fileTaint(target, e.word(target, in), taint{}))
		}
		if argT[i].flow.sendable() {
			sent = sent.or(argT[i])
		}
	}
	return sent
}

// wgetSent: --post-file/--body-file reading stdin or the transcript, and any sendable argument.
func (e *shellEval) wgetSent(args []string, argT []taint, in taint) taint {
	var sent taint
	for i := 1; i < len(args); i++ {
		d := dequote(args[i])
		for _, f := range []string{"--post-file", "--body-file"} {
			switch {
			case d == f && i+1 < len(args):
				sent = sent.or(e.fileTaint(args[i+1], argT[i+1], in))
			case strings.HasPrefix(d, f+"="):
				v := d[len(f)+1:]
				sent = sent.or(e.fileTaint(v, e.word(v, in), in))
			}
		}
		if argT[i].flow.sendable() {
			sent = sent.or(argT[i])
		}
	}
	return sent
}

// ncValueFlags are nc/ncat/telnet options that take a value, so the host is not mistaken for one.
var ncValueFlags = map[string]bool{"-w": true, "-p": true, "-s": true, "-x": true, "-X": true, "-q": true,
	"-i": true, "-W": true, "-T": true, "-O": true, "-I": true, "-e": true, "-c": true, "-b": true}

// ncSent: nc and its kin send their stdin, unless they listen or only scan. The host is their first operand.
func ncSent(args []string, in taint) (taint, []string) {
	var hosts []string
	for i := 1; i < len(args); i++ {
		d := dequote(args[i])
		switch {
		case ncValueFlags[d]:
			i++
		case d == "--listen" || strings.HasPrefix(d, "-") && !strings.HasPrefix(d, "--") && strings.ContainsAny(d, "lz"):
			return taint{}, nil
		case strings.HasPrefix(d, "-"):
		case hosts == nil:
			hosts = []string{d}
		}
	}
	return in, hosts
}

var socatHostRE = regexp.MustCompile(`(?i)^(?:tcp[46]?|udp[46]?|openssl|ssl|tcp-connect|udp-sendto|tcp4-connect|tcp6-connect):([^:,]+)`)

// socatSent: socat sends its stdin when one of its addresses is stdin (`-`, STDIN, STDIO).
func socatSent(args []string, in taint) (taint, []string) {
	var sent taint
	var hosts []string
	for _, a := range args[1:] {
		d := strings.ToUpper(dequote(a))
		if d == "-" || strings.HasPrefix(d, "STDIN") || strings.HasPrefix(d, "STDIO") || strings.HasPrefix(d, "-,") {
			sent = in
		}
		if m := socatHostRE.FindStringSubmatch(dequote(a)); m != nil {
			hosts = append(hosts, m[1])
		}
	}
	return sent, hosts
}

var httpMethods = map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true}

// httpieSent: httpie (and xh) send their stdin as the body when it is not a terminal — a hook's always
// is — unless told to ignore it, plus any sendable request item. Its URL may omit the scheme, and
// `:3000/x` is localhost.
func httpieSent(args []string, argT []taint, in taint) (taint, []string) {
	sent := in
	var hosts []string
	for i := 1; i < len(args); i++ {
		d := dequote(args[i])
		switch {
		case d == "--ignore-stdin" || d == "-I":
			return argsSendable(argT), hosts
		case strings.HasPrefix(d, "-") || httpMethods[strings.ToUpper(d)]:
		case hosts == nil && strings.HasPrefix(d, ":"):
			hosts = []string{"localhost"}
		case hosts == nil && !strings.Contains(d, "://"):
			if f := strings.FieldsFunc(d, func(r rune) bool { return r == '/' || r == ':' }); len(f) > 0 {
				hosts = []string{f[0]}
			}
		case hosts == nil:
			hosts = []string{urlHost(d)}
		}
	}
	return sent.or(argsSendable(argT)), hosts
}

func argsSendable(argT []taint) taint {
	var t taint
	for _, a := range argT {
		if a.flow.sendable() {
			t = t.or(a)
		}
	}
	return t
}

// valueFlags are the options of a stream tool that take a separate value (`head -n 5`, `base64 -w 0`).
var valueFlags = map[string]bool{"-n": true, "-c": true, "--lines": true, "--bytes": true, "-w": true, "-b": true, "-l": true, "-s": true}

// fileOrStdin is a tool that prints its file arguments, or its stdin when it has none.
func (e *shellEval) fileOrStdin(args []string, argT []taint, in taint) taint {
	var out taint
	files := 0
	for i := 1; i < len(args); i++ {
		d := dequote(args[i])
		if valueFlags[d] {
			i++
			continue
		}
		if strings.HasPrefix(d, "-") && d != "-" {
			continue
		}
		files++
		out = out.or(e.fileTaint(args[i], argT[i], in))
	}
	if files == 0 {
		return in
	}
	return out
}

// read: `read [-r] [-d delim] … NAME…` assigns its stdin to the names.
func (e *shellEval) read(args []string, in taint) {
	for i := 1; i < len(args); i++ {
		d := dequote(args[i])
		switch {
		case d == "-d" || d == "-p" || d == "-t" || d == "-n" || d == "-N" || d == "-u":
			i++
		case strings.HasPrefix(d, "-"):
		default:
			t := in
			if t.flow != flowNone {
				at := e.at
				t.src = &at
			}
			e.vars[d] = t
		}
	}
}

var (
	jqWholeRE   = regexp.MustCompile(`^\.?(?:\|?(?:tojson|@json|@base64|@text|@uri|@sh))?$`)
	jqBareDotRE = regexp.MustCompile(`(?:^|[\s,:({\[|+])\.(?:$|[\s,)}\]|+])`)
)

// jqEmbed is a shell value a jq program receives through --arg, --argjson, --rawfile or --slurpfile.
type jqEmbed struct {
	name string
	t    taint
}

// jqCall is one jq command line: its filter, the indexes of its file arguments, what it embeds, and -n.
type jqCall struct {
	filter string
	files  []int
	embeds []jqEmbed
	null   bool
}

func (e *shellEval) parseJQ(args []string, argT []taint, in taint) jqCall {
	var c jqCall
	filterSet := false
	for i := 1; i < len(args); i++ {
		d := dequote(args[i])
		switch {
		case (d == "--arg" || d == "--argjson") && i+2 < len(args):
			c.embeds = append(c.embeds, jqEmbed{dequote(args[i+1]), argT[i+2]})
			i += 2
		case (d == "--rawfile" || d == "--slurpfile") && i+2 < len(args):
			c.embeds = append(c.embeds, jqEmbed{dequote(args[i+1]), e.fileTaint(args[i+2], argT[i+2], in)})
			i += 2
		case d == "--indent" || d == "-f" || d == "--from-file":
			i++
		case d == "--null-input" || (strings.HasPrefix(d, "-") && !strings.HasPrefix(d, "--") && strings.ContainsRune(d, 'n')):
			c.null = true
		case strings.HasPrefix(d, "-"):
		case !filterSet:
			c.filter, filterSet = d, true
		default:
			c.files = append(c.files, i)
		}
	}
	return c
}

// jq: its input (stdin, or its file arguments), selected by its filter; plus any shell value the filter
// embeds through --arg. An identity filter (`.`, `tojson`, `{event: .}`) passes the event on whole.
func (e *shellEval) jq(args []string, argT []taint, in taint) taint {
	c := e.parseJQ(args, argT, in)
	var out taint
	for _, em := range c.embeds {
		if strings.Contains(c.filter, "$"+em.name) {
			out = out.or(em.t)
		}
	}
	input := in
	if c.null || len(c.files) > 0 {
		input = taint{}
	}
	for _, i := range c.files {
		input = input.or(e.fileTaint(args[i], argT[i], in))
	}
	f := strings.Join(strings.Fields(c.filter), "")
	if input.flow == flowEvent && (f != "" && jqWholeRE.MatchString(f) || jqBareDotRE.MatchString(c.filter)) {
		return out.or(input)
	}
	return out.or(selected(input, c.filter))
}

// xargs runs its command with what it reads appended (or put where -I's string stands); that input is
// bound to a name for the run so every reader above sees it like any other value.
func (e *shellEval) xargs(args []string, in taint) taint {
	repl, i := "", 1
loop:
	for ; i < len(args); i++ {
		d := dequote(args[i])
		switch {
		case d == "-I" || d == "--replace":
			if i+1 < len(args) {
				i++
				repl = dequote(args[i])
			}
		case strings.HasPrefix(d, "-I"):
			repl = d[2:]
		case d == "-i":
			repl = "{}"
		case d == "-n" || d == "-L" || d == "-P" || d == "-d" || d == "-s" || d == "-E" || d == "-a":
			i++
		case strings.HasPrefix(d, "-"):
		default:
			break loop
		}
	}
	if i >= len(args) {
		return taint{}
	}
	const bound = "__aguard_xargs_input"
	words := append([]string(nil), args[i:]...)
	for k := range words {
		if repl != "" {
			words[k] = strings.ReplaceAll(words[k], repl, "${"+bound+"}")
		}
	}
	if repl == "" {
		words = append(words, `"${`+bound+`}"`)
	}
	e.vars[bound] = in
	defer delete(e.vars, bound)
	return e.stage(strings.Join(words, " "), taint{})
}
