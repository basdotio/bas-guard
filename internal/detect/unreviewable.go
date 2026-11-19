// SPDX-License-Identifier: MIT
package detect

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/basdotio/bas-guard/internal/model"
)

// Two more shapes of a file (P-136), beside the ones in shape.go: arrangements that leave the dangerous
// part where no reviewer reads it. Both come from MCP servers captured on npm that scored 76 and 88.
//
//	OBF-008  a run of Unicode variation selectors: bytes written in characters that draw nothing
//	OBF-009  a script whose names an obfuscator replaced: a file prepared so that nobody reads it
//
// Measured (agent-guard-work/jsbody-proto.py, vs-runs-allfiles.py, npm-pool-run.py): neither shape occurs
// in any of 4,534 benign trees (391 of them with JavaScript, 4,046 files), 412 fresh skills, the held-out
// set (totals only), or the 1,890 npm packages installed on a developer machine, where not one source
// file holds an `_0x` name.

// selectorRunMin is how many variation selectors in a row stop being typography. A selector follows one
// character and picks how it is drawn (the emoji form of a symbol, a variant of an ideograph), so
// well-formed text never has two in a row. Text that is not well formed does: 149,654 files of every kind
// in the npm packages of a developer machine hold six runs, five of two and one of four (a contributors
// table in a README), and every one of them is U+FE0F repeated — an emoji selector stuttered by a tool.
// The carrier this was written from holds 9,123 on one line, 60 different ones.
//
// So a run counts when it is four or longer AND its selectors are not all the same (carrierRun). The
// first build asked for length only and flagged that README; a selector repeated says nothing, and it
// is the differences between selectors that carry the bytes.
const selectorRunMin = 4

// carrierRun reports whether a run of variation selectors can carry data: selectorRunMin or more of
// them, not all the same one.
func carrierRun(run []rune) bool {
	if len(run) < selectorRunMin {
		return false
	}
	for _, r := range run[1:] {
		if r != run[0] {
			return true
		}
	}
	return false
}

// isVariationSelector reports whether r is a variation selector: U+FE00–FE0F, or the supplement
// U+E0100–E01EF. 256 characters in all, which is why one of them can stand for a byte.
func isVariationSelector(r rune) bool {
	return (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF)
}

// selectorPrefixes are the leading UTF-8 bytes of every variation selector (EF B8 8x, F3 A0 84–87 xx):
// the cheap test in front of the walk, since nearly no file has any.
var selectorPrefixes = [2]string{"\xef\xb8", "\xf3\xa0"}

// selectorRun is OBF-008: a file holding a run of variation selectors that can carry data. The run is
// data nobody is shown — no editor, diff, terminal or rendered page draws it — and code that reads the
// characters back turns it into text or a program: the in-the-wild server decodes each selector to a
// byte and hands the result to eval, in a file that reads as an ordinary crawler. One finding per file,
// at the first run; the snippet names the run instead of quoting it, because quoting it shows nothing.
//
// It reports the carrier, not what it carries, and only a run: a payload spread one selector at a time
// between visible characters is not seen (P-136, Out of scope).
func selectorRun(rel, text string) (model.Finding, bool) {
	if !strings.Contains(text, selectorPrefixes[0]) && !strings.Contains(text, selectorPrefixes[1]) {
		return model.Finding{}, false
	}
	total, longest, runs := 0, 0, 0
	firstLine, firstText := 0, ""
	var run []rune
	for i, line := range strings.Split(text, "\n") {
		end := func() {
			if carrierRun(run) {
				total, runs = total+len(run), runs+1
				longest = max(longest, len(run))
				if firstLine == 0 {
					firstLine, firstText = i+1, line
				}
			}
			run = run[:0]
		}
		for _, r := range line {
			if isVariationSelector(r) {
				run = append(run, r)
				continue
			}
			end()
		}
		end()
	}
	if runs == 0 {
		return model.Finding{}, false
	}
	where := fmt.Sprintf("in one run at line %d", firstLine)
	if runs > 1 {
		where = fmt.Sprintf("in %d runs, the longest %d, the first at line %d", runs, longest, firstLine)
	}
	return model.Finding{
		RuleID: "OBF-008", Dimension: 6, Severity: model.SevHigh, Source: model.SrcStatic,
		Title: "Data hidden in a run of invisible variation selectors",
		Why: fmt.Sprintf("%s holds %d variation selectors, different ones, %s. A variation selector draws nothing: one "+
			"after an emoji or an ideograph picks how that character looks, and that is the only use it has. A run of "+
			"differing ones is data written where no editor, diff, terminal or rendered page shows anything — each can "+
			"stand for a byte — and "+
			"code that reads the characters back turns the run into text or a program. Look for what decodes it (a "+
			"codePointAt or ord() compared against 0xFE00 or 0xE0100) and read what it yields as part of this file; "+
			"nobody reviewing the file has seen it.", rel, total, where),
		Evidence: []model.Evidence{{File: rel, Line: firstLine, Snippet: redactClip(nameSelectorRuns(firstText))}},
	}, true
}

// nameSelectorRuns rewrites a line for a snippet: each carrier run becomes "[N variation selectors]".
// Every other selector is left as written, so an emoji keeps its own.
func nameSelectorRuns(line string) string {
	var b strings.Builder
	var run []rune
	flush := func() {
		if carrierRun(run) {
			fmt.Fprintf(&b, "[%d variation selectors]", len(run))
		} else {
			b.WriteString(string(run))
		}
		run = run[:0]
	}
	for _, r := range line {
		if isVariationSelector(r) {
			run = append(run, r)
			continue
		}
		flush()
		b.WriteRune(r)
	}
	flush()
	return b.String()
}

// obfuscatorNameRE is a name as an obfuscator writes it: `_0x` and four or more letters or digits.
// javascript-obfuscator's default generator emits `_0x` plus hexadecimal; the in-the-wild file this was
// written from imitates it by hand with letters past f (`_0x7g8h9i`), so the class is not hex only. The
// leading boundary keeps a hex literal (`0x1a2b3c`) and a longer name ending in `_0x…` out.
var obfuscatorNameRE = regexp.MustCompile(`\b_0x[0-9A-Za-z]{4,}\b`)

// obfuscatorNamesMin is how many DISTINCT such names make a file obfuscator output rather than a file
// that happens to hold one. The two measured files hold 85 and 6,315; no other measured file holds one.
const obfuscatorNamesMin = 20

// obfuscatorNames is OBF-009: a script whose identifiers were replaced by an obfuscator. Minified code
// is not this — a minifier shortens names to letters to save bytes and is everywhere; `_0x1a2b3c` is
// what a tool leaves when its purpose is that the file cannot be read. The rules still run on the file
// and find little: the in-the-wild one builds the file names it reads from String.fromCharCode lists.
// Scripts only: a document that quotes such code is describing it.
//
// One naming scheme, the default of the most used obfuscator. A file renamed to a, b, c reads as
// minified code and is left alone (P-136, Must not claim).
func obfuscatorNames(rel, text string) (model.Finding, bool) {
	if !strings.Contains(text, "_0x") {
		return model.Finding{}, false
	}
	locs := obfuscatorNameRE.FindAllStringIndex(text, -1)
	if len(locs) < obfuscatorNamesMin {
		return model.Finding{}, false
	}
	distinct := map[string]struct{}{}
	for _, l := range locs {
		distinct[text[l[0]:l[1]]] = struct{}{}
	}
	if len(distinct) < obfuscatorNamesMin {
		return model.Finding{}, false
	}
	first := locs[0][0]
	lineNo := 1 + strings.Count(text[:first], "\n")
	start := strings.LastIndexByte(text[:first], '\n') + 1
	end := len(text)
	if i := strings.IndexByte(text[first:], '\n'); i >= 0 {
		end = first + i
	}
	return model.Finding{
		RuleID: "OBF-009", Dimension: 6, Severity: model.SevHigh, Source: model.SrcStatic,
		Title: "Script with obfuscator-renamed identifiers",
		Why: fmt.Sprintf("%s uses %d distinct names of the form _0x1a2b3c. That is what an obfuscator leaves when it "+
			"renames every variable and function so the file cannot be read; minified code keeps short letters and is "+
			"not this. A file prepared so that nobody reviews it, shipped where an agent will run it, is the finding: "+
			"the rules read it and see little, because strings and names are built at run time. Ask for the source "+
			"it was made from, or do not install it.", rel, len(distinct)),
		Evidence: []model.Evidence{{File: rel, Line: lineNo, Snippet: redactClip(text[start:end])}},
	}, true
}
