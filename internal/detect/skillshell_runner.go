// SPDX-License-Identifier: MIT
package detect

import (
	"regexp"
	"strings"
)

// Interpreters and package runners for EXEC-014 and SUP-011 (P-132).

// progSource is where an interpreter stage takes its program from: a file operand, its standard input,
// or an argument (-c, -e, …).
type progSource struct {
	file  string
	stdin bool
	code  string
}

// interp describes one interpreter's command line: the flags whose value is the program (code), whose
// value is a program file (file), that read the program from stdin, that take some other value, and
// that make it run a module rather than a file. cluster: single-dash flags combine (`bash -ec`), and a
// cluster holding c or s means code or stdin. sub: a subcommand before the file (`deno run`).
type interp struct {
	code, file, stdin, value, module map[string]bool
	cluster, fold                    bool
	sub                              string
}

func set(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

var (
	shellInterp = interp{code: set("-c"), stdin: set("-s"), value: set("-o", "+o", "-O", "+O", "--rcfile", "--init-file"), cluster: true}
	// shellFamily are the interpreters whose -c program is itself shell, which the reader follows.
	shellFamily  = set("sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "yash")
	interpreters = map[string]interp{
		"python": {code: set("-c"), module: set("-m"), value: set("-W", "-X")},
		"node":   {code: set("-e", "--eval", "-p", "--print"), value: set("-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions")},
		"deno":   {code: set("eval"), sub: "run", value: set("--config", "-c", "--import-map", "--lock", "--cert", "--location", "--env-file")},
		"bun":    {code: set("-e", "--eval", "-p", "--print"), sub: "run", value: set("-r", "--preload", "--cwd", "--env-file")},
		"perl":   {code: set("-e", "-E"), value: set("-I", "-M", "-m", "-x")},
		"ruby":   {code: set("-e"), value: set("-r", "-I", "-C", "-E")},
		"php":    {code: set("-r"), file: set("-f"), value: set("-c", "-d", "-z")},
		"pwsh": {code: set("-c", "-command", "-e", "-ec", "-encodedcommand"), file: set("-f", "-file"), fold: true,
			value: set("-executionpolicy", "-ep", "-ex", "-workingdirectory", "-wd", "-outputformat", "-of", "-inputformat", "-if", "-configurationname", "-settingsfile")},
		"source": {},
		".":      {},
	}
)

// interpreterOf is the table entry for a command name: python3.12 is python, nodejs is node, a shell
// is a shell.
func interpreterOf(name string) (interp, bool) {
	switch {
	case shellFamily[name]:
		return shellInterp, true
	case strings.HasPrefix(name, "python") || name == "py" || strings.HasPrefix(name, "pypy"):
		return interpreters["python"], true
	case name == "nodejs":
		return interpreters["node"], true
	case name == "powershell":
		return interpreters["pwsh"], true
	}
	in, ok := interpreters[name]
	return in, ok
}

// interpreterProgram reads an interpreter stage's arguments (after its name) for where its program comes
// from. ok is false when name is not an interpreter. A stage with no program operand reads its program
// from stdin; one that runs a module (`python -m`) runs neither a file nor stdin.
func interpreterProgram(name string, args []string) (progSource, bool) {
	in, ok := interpreterOf(name)
	if !ok {
		return progSource{}, false
	}
	if in.sub != "" && len(args) > 0 && dequote(args[0]) == in.sub {
		args = args[1:]
	}
	value := func(i int) string {
		if i+1 < len(args) {
			return args[i+1]
		}
		return ""
	}
	for i := 0; i < len(args); i++ {
		a := dequote(args[i])
		k := a
		if in.fold {
			k = strings.ToLower(a)
		}
		switch {
		case k == "--":
			if v := value(i); v != "" {
				return progSource{file: v}, true
			}
			return progSource{stdin: true}, true
		case k == "-" || k == "/dev/stdin" || in.stdin[k]:
			return progSource{stdin: true}, true
		case in.code[k]:
			return progSource{code: value(i)}, true
		case in.file[k]:
			return progSource{file: value(i)}, true
		case in.module[k]:
			return progSource{}, true
		case in.value[k]:
			i++
		case in.cluster && len(a) > 1 && (a[0] == '-' || a[0] == '+') && a[1] != '-':
			if strings.ContainsRune(a[1:], 'c') {
				return progSource{code: value(i)}, true
			}
			if strings.ContainsRune(a[1:], 's') {
				return progSource{stdin: true}, true
			}
		case strings.HasPrefix(a, "-"):
		default:
			return progSource{file: args[i]}, true
		}
	}
	return progSource{stdin: true}, true
}

// runnerUse is a registry package a command runs at a version that can change: where, the package as
// written, the runner, and what the version is.
type runnerUse struct {
	at                  int
	spec, tool, version string
}

var (
	exactSemverRE = regexp.MustCompile(`^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	fullShaRE     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	shortHexRE    = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
	ghShorthandRE = regexp.MustCompile(`^[\w.-]+/[\w.-]+(?:#.*)?$`)
	pepPinRE      = regexp.MustCompile(`^[A-Za-z0-9][\w.\[\],-]*===?\s*[0-9][\w.!+-]*$`)
	uvAtPinRE     = regexp.MustCompile(`^[A-Za-z0-9][\w.\[\],-]*@v?\d+(?:\.\d+)+[\w.+-]*$`)
	distTagRE     = regexp.MustCompile(`^[A-Za-z][\w.-]*$`)
)

// packageRunner reports whether a stage runs a registry package at a moving version. npx, npm exec and
// bunx may run a copy the project already installed, so they count only when the command asks for a
// download (-y, --package) or names a version that can move; pnpm/yarn dlx, uvx, uv tool run and pipx run
// always fetch; go run counts for a remote module at a branch or tag query.
func packageRunner(args []string) (runnerUse, bool) {
	name, rest := cmdName(args[0]), args[1:]
	sub := ""
	if len(rest) > 0 {
		sub = dequote(rest[0])
	}
	switch {
	case name == "npx":
		return npmRunner("npx", rest, false)
	case name == "npm" && (sub == "exec" || sub == "x"):
		return npmRunner("npm exec", rest[1:], false)
	case name == "bunx":
		return npmRunner("bunx", rest, false)
	case name == "bun" && sub == "x":
		return npmRunner("bunx", rest[1:], false)
	case name == "pnpx":
		return npmRunner("pnpx", rest, true)
	case (name == "pnpm" || name == "yarn") && sub == "dlx":
		return npmRunner(name+" dlx", rest[1:], true)
	case name == "uvx":
		return uvRunner("uvx", rest)
	case name == "uv" && sub == "tool" && len(rest) > 1 && dequote(rest[1]) == "run":
		return uvRunner("uv tool run", rest[2:])
	case name == "pipx" && sub == "run":
		return pipxRunner(rest[1:])
	case name == "go" && sub == "run":
		return goRunner(rest[1:])
	}
	return runnerUse{}, false
}

// npmRunner reads npx-style arguments. always: the runner fetches whatever is not pinned (dlx).
func npmRunner(tool string, args []string, always bool) (runnerUse, bool) {
	yes := false
	var pkgs []string
	spec := ""
	for i := 0; i < len(args) && spec == ""; i++ {
		a := dequote(args[i])
		switch {
		case a == "-y" || a == "--yes" || a == "--yes=true":
			yes = true
		case a == "--no" || a == "--no-install" || a == "--yes=false" || a == "--offline":
			return runnerUse{}, false
		case a == "-p" || a == "--package":
			if i+1 < len(args) {
				i++
				pkgs = append(pkgs, dequote(args[i]))
			}
		case strings.HasPrefix(a, "--package="):
			pkgs = append(pkgs, strings.TrimPrefix(a, "--package="))
		case a == "-c" || a == "--call":
			i++
		case a == "--" && i+1 < len(args):
			spec = dequote(args[i+1])
		case strings.HasPrefix(a, "-"):
		default:
			spec = a
		}
	}
	candidates := pkgs
	if len(candidates) == 0 && spec != "" {
		candidates = []string{spec}
	}
	for _, c := range candidates {
		version, explicit, local := npmVersion(c)
		if local || isPinnedNpm(version) {
			continue
		}
		if always || yes || len(pkgs) > 0 || explicit {
			return runnerUse{spec: c, tool: tool, version: describeVersion(version)}, true
		}
	}
	return runnerUse{}, false
}

// npmVersion is the version part of an npm package spec; explicit when the spec names one (or a git
// ref); local for a path. A git spec's version is its #ref.
func npmVersion(spec string) (version string, explicit, local bool) {
	switch {
	case spec == "" || strings.ContainsAny(spec[:1], "./~$") || strings.HasPrefix(spec, "file:"):
		return "", false, true
	case strings.Contains(spec, "://") || strings.HasPrefix(spec, "git+") || strings.HasPrefix(spec, "git@") ||
		strings.HasPrefix(spec, "github:") || strings.HasPrefix(spec, "gitlab:") || strings.HasPrefix(spec, "bitbucket:") ||
		(!strings.HasPrefix(spec, "@") && ghShorthandRE.MatchString(spec)):
		_, ref, _ := strings.Cut(spec, "#")
		return "#" + ref, true, false
	}
	spec = strings.TrimPrefix(spec, "npm:")
	at := strings.LastIndexByte(spec, '@')
	if at <= 0 {
		return "", false, false
	}
	return spec[at+1:], true, false
}

func isPinnedNpm(version string) bool {
	if ref, ok := strings.CutPrefix(version, "#"); ok {
		return fullShaRE.MatchString(ref)
	}
	return exactSemverRE.MatchString(version)
}

// describeVersion says what the version a runner resolves is, for the finding.
func describeVersion(version string) string {
	switch {
	case version == "":
		return "whatever version the registry serves when it runs"
	case strings.HasPrefix(version, "#"):
		return "a git ref that can move"
	case distTagRE.MatchString(version):
		return "the `" + version + "` tag, wherever it points when it runs"
	}
	return "the range `" + version + "`, whatever it resolves to when it runs"
}

// uvRunner reads uvx / uv tool run: the package is --from's value, else the command operand.
func uvRunner(tool string, args []string) (runnerUse, bool) {
	value := set("--with", "--with-editable", "--with-requirements", "--python", "-p", "--index", "--index-url",
		"--extra-index-url", "--default-index", "--find-links", "-f", "--constraints", "--overrides", "--directory",
		"--project", "--config-file", "--cache-dir", "--color", "--exclude-newer", "--refresh-package",
		"--reinstall-package", "--upgrade-package", "--build-constraints")
	from, spec := "", ""
	for i := 0; i < len(args) && spec == ""; i++ {
		a := dequote(args[i])
		k, v, hasV := strings.Cut(a, "=")
		switch {
		case k == "--from":
			if !hasV && i+1 < len(args) {
				i++
				v = dequote(args[i])
			}
			from = v
		case value[k]:
			if !hasV {
				i++
			}
		case strings.HasPrefix(a, "-"):
		default:
			spec = a
		}
	}
	if from != "" {
		spec = from
	}
	return pyRunner(tool, spec, uvAtPinRE)
}

// pipxRunner reads pipx run: the package is --spec's value, else the app operand.
func pipxRunner(args []string) (runnerUse, bool) {
	value := set("--python", "--pip-args", "--index-url", "-i")
	from, spec := "", ""
	for i := 0; i < len(args) && spec == ""; i++ {
		a := dequote(args[i])
		k, v, hasV := strings.Cut(a, "=")
		switch {
		case k == "--spec":
			if !hasV && i+1 < len(args) {
				i++
				v = dequote(args[i])
			}
			from = v
		case a == "--path":
			return runnerUse{}, false // runs a local file
		case value[k]:
			if !hasV {
				i++
			}
		case strings.HasPrefix(a, "-"):
		default:
			spec = a
		}
	}
	if from != "" {
		spec = from
	}
	return pyRunner("pipx run", spec, nil)
}

// pyRunner judges a Python package spec: pinned with ==/===, or with @<version> where the runner reads
// it (uvx); a local path or a git URL at a full commit is not moving either.
func pyRunner(tool, spec string, atPin *regexp.Regexp) (runnerUse, bool) {
	if spec == "" || strings.ContainsAny(spec[:1], "./~$") || pepPinRE.MatchString(spec) || (atPin != nil && atPin.MatchString(spec)) {
		return runnerUse{}, false
	}
	if strings.HasPrefix(spec, "git+") {
		if at := strings.LastIndexByte(spec, '@'); at > 0 && fullShaRE.MatchString(spec[at+1:]) {
			return runnerUse{}, false
		}
		return runnerUse{spec: spec, tool: tool, version: "a git ref that can move"}, true
	}
	version := ""
	if at := strings.LastIndexByte(spec, '@'); at > 0 && !strings.Contains(spec, "://") {
		version = spec[at+1:]
	}
	return runnerUse{spec: spec, tool: tool, version: describeVersion(version)}, true
}

// goRunner reads go run: a module query (path@version) whose path is remote (a dot in its first
// element) and whose version is not a release or a commit.
func goRunner(args []string) (runnerUse, bool) {
	value := set("-C", "-p", "-mod", "-modfile", "-overlay", "-pkgdir", "-tags", "-toolexec", "-exec", "-gcflags",
		"-ldflags", "-asmflags", "-gccgoflags", "-buildmode", "-compiler", "-installsuffix")
	for i := 0; i < len(args); i++ {
		a := dequote(args[i])
		if strings.HasPrefix(a, "-") {
			if k, _, hasV := strings.Cut(a, "="); value[k] && !hasV {
				i++
			}
			continue
		}
		mod, version, ok := strings.Cut(a, "@")
		first, _, _ := strings.Cut(mod, "/")
		if !ok || !strings.Contains(first, ".") || exactSemverRE.MatchString(version) || strings.HasPrefix(version, "v0.0.0-") || shortHexRE.MatchString(version) {
			return runnerUse{}, false
		}
		return runnerUse{spec: a, tool: "go run", version: describeVersion(version)}, true
	}
	return runnerUse{}, false
}
