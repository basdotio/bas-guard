// SPDX-License-Identifier: MIT
package detect

import (
	"path"
	"regexp"
	"strings"
)

// The reader behind EXEC-014 and SUP-011 (P-132): one command Claude Code runs on invocation, split
// with the shell lexer HOOK-003 uses (hookegress_shlex.go). TOKENISATION ONLY — nothing is expanded or
// run. It follows the files curl and wget keep through the rest of the command and asks whether a
// later stage runs one, and it follows a download written to stdout down its pipeline to an
// interpreter that reads its program from stdin.

// shellRead is what one command runs that P-132 reports: the first download it runs and the first
// registry package it runs at a moving version. Offsets are bytes into the text read.
type shellRead struct {
	fetchRun *fetchRun
	runner   *runnerUse
}

type fetchRun struct {
	fetchAt, runAt int
	how            string
}

type keptFile struct {
	path string
	at   int
}

// maxSkillShellDepth bounds `sh -c "…"` nesting; the reader stops there rather than recurse on
// attacker-chosen text.
const maxSkillShellDepth = 3

// readSkillShell reads one command (an inline command, or a ```! block as one script).
func readSkillShell(text string, depth int) shellRead {
	var r shellRead
	var kept []keptFile
	cursor := 0
	for _, cmd := range shCommands(text) {
		pipeFetch := -1 // where a download written to stdout entered this pipeline
		for _, st := range shStages(cmd) {
			stAt := locate(text, st, &cursor)
			words := shWordsKept(stripReserved(st))
			args, redirs := splitRedirects(words)
			args = stripWrappers(dropAssignments(args))
			if len(args) == 0 {
				continue
			}
			name := cmdName(args[0])
			if name == "curl" || name == "wget" {
				paths, toStdout := fetchOutputs(name, args[1:], words)
				for _, p := range paths {
					kept = append(kept, keptFile{p, stAt})
				}
				if toStdout && pipeFetch < 0 {
					pipeFetch = stAt
				}
				continue
			}
			if r.fetchRun == nil {
				r.fetchRun = runsDownload(name, args, redirs, kept, pipeFetch, stAt, depth)
			}
			if r.runner == nil {
				if rn, ok := packageRunner(args); ok {
					rn.at = stAt
					r.runner = &rn
				}
			}
			if prog, ok := interpreterProgram(name, args[1:]); ok && prog.code != "" && depth < maxSkillShellDepth && shellFamily[name] {
				inner := readSkillShell(dequote(prog.code), depth+1)
				if r.fetchRun == nil && inner.fetchRun != nil {
					r.fetchRun = &fetchRun{fetchAt: stAt, runAt: stAt, how: inner.fetchRun.how}
				}
				if r.runner == nil && inner.runner != nil {
					rn := *inner.runner
					rn.at = stAt
					r.runner = &rn
				}
			}
		}
	}
	return r
}

// locate is the offset of piece in text at or after *cursor, moving the cursor past it. The lexer's
// pieces are substrings of text in order, so this finds each where it is.
func locate(text, piece string, cursor *int) int {
	p := strings.TrimSpace(piece)
	if p == "" || *cursor > len(text) {
		return min(*cursor, len(text))
	}
	i := strings.Index(text[*cursor:], p)
	if i < 0 {
		return *cursor
	}
	at := *cursor + i
	*cursor = at + len(p)
	return at
}

// dropAssignments takes NAME=VALUE words off the front of a stage.
func dropAssignments(args []string) []string {
	for len(args) > 0 && assignWordRE.MatchString(dequote(args[0])) {
		args = args[1:]
	}
	return args
}

// runsDownload reports whether a stage runs a file the command downloaded, or a download piped to it.
func runsDownload(name string, args []string, redirs []redirect, kept []keptFile, pipeFetch, stAt, depth int) *fetchRun {
	if prog, ok := interpreterProgram(name, args[1:]); ok {
		if prog.stdin {
			for _, rd := range redirs {
				if rd.op == "<" {
					prog = progSource{file: rd.target}
				}
			}
		}
		switch {
		case prog.file != "" && isURL(dequote(prog.file)):
			return &fetchRun{fetchAt: stAt, runAt: stAt, how: name + " runs a program straight from a URL"}
		case prog.file != "":
			if k, ok := keptAs(kept, prog.file); ok {
				return &fetchRun{fetchAt: k.at, runAt: stAt, how: "`" + dequote(prog.file) + "` is downloaded, then run with " + name}
			}
		case prog.stdin && pipeFetch >= 0:
			return &fetchRun{fetchAt: pipeFetch, runAt: stAt, how: "a download is piped into " + name}
		}
		return nil
	}
	if first := dequote(args[0]); strings.Contains(first, "/") {
		if k, ok := keptAs(kept, args[0]); ok {
			return &fetchRun{fetchAt: k.at, runAt: stAt, how: "`" + first + "` is downloaded, then run"}
		}
	}
	return nil
}

var braceVarRE = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// normShellPath is a path word as the comparison reads it: unquoted, ${X} as $X, no leading ./.
func normShellPath(w string) string {
	p := braceVarRE.ReplaceAllString(dequote(w), "$$$1")
	p = strings.TrimPrefix(p, "./")
	if p == "" || p == "-" || strings.HasPrefix(p, "/dev/") {
		return ""
	}
	return path.Clean(p)
}

// keptAs finds the kept file a word names: the same path, or the same name where one side is a bare
// name (`cd /tmp && curl -O …/i.sh && ./i.sh`).
func keptAs(kept []keptFile, word string) (keptFile, bool) {
	w := normShellPath(word)
	if w == "" {
		return keptFile{}, false
	}
	for _, k := range kept {
		p := normShellPath(k.path)
		if p == "" {
			continue
		}
		if p == w || ((!strings.Contains(p, "/") || !strings.Contains(w, "/")) && path.Base(p) == path.Base(w)) {
			return k, true
		}
	}
	return keptFile{}, false
}

func isURL(s string) bool {
	i := strings.Index(s, "://")
	return i > 0 && !strings.ContainsAny(s[:i], "/ \t")
}

var stdoutRedirectRE = regexp.MustCompile(`^(?:1|&)?(?:>>|>\||>)(.*)$`)

// stdoutTarget is the file a stage's standard output is redirected to, if any (not `2>`, not `>&2`).
func stdoutTarget(words []string) string {
	for i, w := range words {
		if strings.HasPrefix(w, ">(") {
			continue
		}
		m := stdoutRedirectRE.FindStringSubmatch(w)
		if m == nil {
			continue
		}
		t := m[1]
		if t == "" && i+1 < len(words) {
			t = words[i+1]
		}
		if !strings.HasPrefix(t, "&") {
			return t
		}
	}
	return ""
}

// curlShortValue and wgetShortValue are the single-letter options that take a value; in a cluster the
// value is the rest of the word or the next word.
const (
	curlShortValue = "AbcCdDeEFHKmoPQrTtuUwxXyYz"
	wgetShortValue = "OoaPtTweiUQlDARXIB"
)

var fetchLongValue = map[string]bool{
	"--data": true, "--data-raw": true, "--data-binary": true, "--data-urlencode": true, "--json": true,
	"--header": true, "--request": true, "--user": true, "--user-agent": true, "--referer": true,
	"--cookie": true, "--cookie-jar": true, "--form": true, "--form-string": true, "--upload-file": true,
	"--config": true, "--write-out": true, "--proxy": true, "--max-time": true, "--connect-timeout": true,
	"--retry": true, "--retry-delay": true, "--range": true, "--cert": true, "--key": true, "--cacert": true,
	"--resolve": true, "--dump-header": true, "--oauth2-bearer": true, "--limit-rate": true,
	"--output-file": true, "--append-output": true, "--tries": true, "--timeout": true, "--wait": true,
	"--post-data": true, "--post-file": true, "--body-data": true, "--body-file": true, "--method": true,
	"--password": true, "--http-user": true, "--http-password": true, "--input-file": true, "--base": true,
	"--execute": true, "--level": true, "--accept": true, "--reject": true, "--load-cookies": true,
	"--save-cookies": true, "--ca-certificate": true, "--certificate": true, "--private-key": true,
}

// fetchOutputs reads a curl or wget stage: the files it keeps and whether it writes the download to
// standard output. args are the words after the command name, redirections taken off; words are all of
// the stage's words, for the stdout redirection.
func fetchOutputs(tool string, args, words []string) (kept []string, toStdout bool) {
	short, outFlag, dirFlag := curlShortValue, "--output", "--output-dir"
	if tool == "wget" {
		short, outFlag, dirFlag = wgetShortValue, "--output-document", "--directory-prefix"
	}
	var outs, urls []string
	remote, dir := false, ""
	next := func(i *int) string {
		if *i+1 < len(args) {
			*i++
			return dequote(args[*i])
		}
		return ""
	}
	for i := 0; i < len(args); i++ {
		a := dequote(args[i])
		switch {
		case strings.HasPrefix(a, "--"):
			name, val, hasVal := strings.Cut(a, "=")
			if !hasVal && (name == outFlag || name == dirFlag || name == "--url" || fetchLongValue[name]) {
				val = next(&i)
			}
			switch name {
			case outFlag:
				outs = append(outs, val)
			case dirFlag:
				dir = val
			case "--url":
				urls = append(urls, val)
			case "--remote-name", "--remote-name-all":
				remote = true
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
		cluster:
			for j := 1; j < len(a); j++ {
				c := a[j]
				if c == 'O' && tool == "curl" {
					remote = true
					continue
				}
				if strings.IndexByte(short, c) < 0 {
					continue
				}
				v := a[j+1:]
				if v == "" {
					v = next(&i)
				}
				switch {
				case c == 'o' && tool == "curl", c == 'O' && tool == "wget":
					outs = append(outs, v)
				case c == 'P' && tool == "wget":
					dir = v
				}
				break cluster
			}
		case isURL(a):
			urls = append(urls, a)
		}
	}
	join := func(p string) string {
		if dir == "" || strings.HasPrefix(p, "/") {
			return p
		}
		return dir + "/" + p
	}
	for _, o := range outs {
		if o == "-" {
			toStdout = true
		} else if o != "" {
			kept = append(kept, join(o))
		}
	}
	switch {
	case tool == "curl" && remote:
		for _, u := range urls {
			if b := urlBase(u); b != "" {
				kept = append(kept, join(b))
			}
		}
	case tool == "wget" && len(outs) == 0:
		for _, u := range urls {
			b := urlBase(u)
			if b == "" {
				b = "index.html"
			}
			kept = append(kept, join(b))
		}
	case tool == "curl" && len(outs) == 0:
		toStdout = true
	}
	if toStdout {
		if t := stdoutTarget(words); t != "" {
			kept = append(kept, t)
			toStdout = false
		}
	}
	return kept, toStdout
}
