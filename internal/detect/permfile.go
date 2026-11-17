// SPDX-License-Identifier: MIT
package detect

import (
	"regexp"

	"github.com/basdotio/bas-guard/internal/model"
)

// The write leg of PERM-007's file-level half (P-124). settingsFileRE and settingsReadRE, the
// naming leg, stay in rules_data.go beside the rule; this file holds what counts as a write.
var (
	// settingsWriteRE — a line that writes SOME file: Python's write_text/write_bytes and an open()
	// in a write or append mode, Node's writeFile/writeFileSync (fs.promises too), a shell redirect
	// to a path or a variable, tee. It does not say WHICH file; the naming leg does that.
	//
	// open() is read twice. The first form is the original: up to the first `)`, so a path built
	// by a call — open(os.path.join(…), "w"), open(str(p), "w") — ended at the call's own `)` and
	// was never a write. The second balances parentheses two levels deep inside open(), which
	// covers os.path.join(os.path.expanduser("~"), …) and leaves the mode at open()'s own level.
	settingsWriteRE = regexp.MustCompile(`(?i)\.(write_text|write_bytes)\(|\bwriteFile(Sync)?\(|open\([^)]*['"][wa]|open\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*['"][wa]|(^|[^>])>>?\s*["~./$]|\btee\s`)

	// streamSinkRE — a redirect or tee into a stream device writes no file: `2>/dev/null`,
	// `> /dev/stderr`, `| tee /dev/stderr`. They are taken off the line before the write leg reads
	// it. Without this, the one-line half would close on `cp ~/.claude/settings.json "$DIR/"
	// 2>/dev/null`, the commonest way a shell line both names the file and redirects anything.
	// /dev/shm and /dev/tcp are not here: the first is a file system, the second is the network.
	streamSinkRE = regexp.MustCompile(`(?i)(>>?|\btee\s+(-a\s+)?)\s*/dev/(null|stdout|stderr|tty|fd/\d+)\b`)
)

// writesAFile reports whether a line writes a file, by the write leg above with stream devices
// taken off first.
func writesAFile(line string) bool {
	return settingsWriteRE.MatchString(streamSinkRE.ReplaceAllString(line, ""))
}

// The name leg of PERM-007's file-level half (P-134). Before, a line that named a settings file without reading it and
// a line that wrote ANY file closed the finding: a status line that keeps `$HOME/.claude/settings.json` in a variable
// to read the model from it, and writes a cache file, was "rewriting the permission settings". On 1,100 public status
// line scripts that was 118 of 136 PERM-007 findings, every one read wrong; in the corpus, 17 of 21. So the half now
// asks whether the file written is the file named: the naming line assigns the path to a name, and a later line writes
// THROUGH that name — one level in the same file, as FS-005's file-level half follows a log's name (P-092). A name
// handed to a function that writes, copied into a second name, or a path a function returns is not followed
// (TestPERM007_OneLevelOnly).
var (
	// settingsAssignRE — a line that assigns to a name: shell `NAME=…` (export, local, readonly, declare), Python
	// `name = …` (an annotation allowed, `self.x = …` included), Node `const|let|var name = …`. The value is the
	// line's: the caller already knows it names a settings file.
	settingsAssignRE = regexp.MustCompile(`^\s*(?:export\s+|readonly\s+|local\s+|typeset\s+|declare\s+(?:-\w+\s+)*|const\s+|let\s+|var\s+)?([A-Za-z_][\w.]*)\s*(?::\s*[^=]+?)?=[^=]`)

	// redirectOrTeeRE — a shell redirection or tee and its target. The one-line closing reads the line without them:
	// a redirect INTO the settings file is the line rule's (PERM-007's pattern has `>`/`tee` right before the name), and
	// a redirect anywhere else writes another file — `echo "see ~/.claude/settings.json" >> "$LOG"` names the file in
	// the text it logs.
	redirectOrTeeRE = regexp.MustCompile(`(?:[0-9&]?>>?|>\|)\s*(?:"[^"]*"|'[^']*'|\S+)|\btee\s+(?:-a\s+|--append\s+)?(?:"[^"]*"|'[^']*'|\S+)`)
)

// writesItself reports whether a line that names a settings file also writes it, by a write in code (a write call
// whose path argument is on the line). Shell redirections and tee are left to the line rule.
func writesItself(line string) bool {
	return writesAFile(redirectOrTeeRE.ReplaceAllString(line, ""))
}

// writesName returns the pattern of a line that writes the file the name holds: a shell redirect, tee, mv, cp,
// install or sponge with the name as the target; Python's name.write_text/write_bytes, name.open("w"),
// open(name, "w"), os.replace/rename and shutil.move/copy onto it, x.replace(name); Node's writeFile, appendFile,
// createWriteStream (fs-extra's outputFile and writeJson too) of it, and rename/copyFile onto it. Case-sensitive: a
// shell's $s is not its $S.
func writesName(name string) *regexp.Regexp {
	n := regexp.QuoteMeta(name)
	shellRef := `["']?\$\{?` + n + `\}?["']?(?:\s|$|[;&|)<>])`
	return regexp.MustCompile(
		`(?:^|[^>0-9&])(?:>>?|>\|)\s*` + shellRef +
			`|\btee\s+(?:-a\s+|--append\s+)?` + shellRef +
			`|\b(?:mv|cp|install)\s+(?:-\S+\s+)*(?:"[^"]*"|'[^']*'|\S+)\s+` + shellRef +
			`|\bsponge\s+(?:-a\s+)?` + shellRef +
			`|\b` + n + `\.(?:write_text|write_bytes)\(` +
			`|\b` + n + `\.open\(\s*(?:mode\s*=\s*)?["'][wax+]` +
			`|\bopen\(\s*(?:str\(\s*)?` + n + `\s*\)?\s*,\s*(?:mode\s*=\s*)?["'][wax+]` +
			`|\b(?:os\.(?:replace|rename)|shutil\.(?:move|copy|copy2|copyfile))\(\s*[^,()]+,\s*(?:str\(\s*)?` + n + `\s*\)?\s*[,)]` +
			`|\.(?:replace|rename)\(\s*` + n + `\s*\)` +
			`|\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|outputFile|outputFileSync|writeJson|writeJsonSync|outputJson|outputJsonSync)\(\s*` + n + `\s*[,)]` +
			`|\b(?:rename|renameSync|copyFile|copyFileSync|move|moveSync)\(\s*[^,()]+,\s*` + n + `\s*[,)]`)
}

// settingsName is a name a line assigned a Claude settings path to, the pattern of a line that writes through it, and
// the assigning line.
type settingsName struct {
	write *regexp.Regexp
	at    model.Evidence
}
