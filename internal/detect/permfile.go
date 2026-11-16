// SPDX-License-Identifier: MIT
package detect

import "regexp"

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
