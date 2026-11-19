// SPDX-License-Identifier: MIT
package detect

import (
	"regexp"
	"strings"
)

// Unicode tag characters (U+E0000–E007F, P-123). U+E0020–E007E mirror printable ASCII one for one, no
// terminal, editor or diff draws them, and a model reads each as the ASCII character it mirrors. A whole
// sentence written in them ("ASCII smuggling") is text the agent follows and no reviewer sees: before
// P-123 such a SKILL.md scored 100/100 with no finding, while the same sentence in ASCII was INJ-001.
//
// The one legitimate use left is the emoji flag. Unicode deprecated tags as language markup and reused
// them for emoji tag sequences (UTS #51): U+1F3F4 (black flag), a subdivision code in tag letters and
// digits, U+E007F (cancel tag). England, Scotland and Wales are 🏴 + gbeng / gbsct / gbwls + cancel, and
// any emoji list carries them, so "a tag character is present" is not a finding.
//
// Three readers, one definition each:
//   - normalizeForMatch decodes every tag character into the view the rules match (decodeTag), so a
//     smuggled sentence meets INJ-001, FS-001 and the rest as the model reads it;
//   - INJ-006 fires on a line holding a tag character outside a well-formed flag (hiddenTagPattern);
//   - report.Sanitize replaces tag characters in a string HidesTagText says hides text, so a file name
//     cannot carry a name the reader is not shown, while a flag in a name renders as a flag.

const (
	tagLow    = 0xE0000
	tagHigh   = 0xE007F
	tagCancel = 0xE007F
	// tagPrefix is the first two bytes of every tag character in UTF-8 (F3 A0 80 80 … F3 A0 81 BF): the
	// cheap test in front of the pattern, since nearly no string has any.
	tagPrefix = "\xf3\xa0"
)

// tagSpec is the class of tags a flag's subdivision code is written in: digits and lowercase letters.
const tagSpec = `\x{E0030}-\x{E0039}\x{E0061}-\x{E007A}`

// hiddenTagPattern matches a line holding a tag character that is not part of a well-formed flag, which
// is U+1F3F4, one to six tagSpec characters, U+E007F. RE2 has no lookaround, so "not part of" is spelled
// as the five ways to leave that shape:
//   - a tag outside tagSpec and not the cancel tag: space, capitals, punctuation, the language tag;
//   - seven or more tagSpec in a row: longer than any subdivision code (two-letter region, at most four);
//   - a tagSpec run not preceded by the flag or another tagSpec: letters with no flag of their own;
//   - a tagSpec run not followed by the cancel tag or another tagSpec: a flag that never ends;
//   - a cancel tag not preceded by a tagSpec: a cancel with no code before it.
//
// One to six, not exactly the three flags platforms draw: a well-formed code no platform draws
// (🏴 + usca + cancel) renders as a black flag, so the most it can hide is six letters a reader sees a
// flag in place of. Measured on 5,042 corpus samples, the held-out ClawHub set and the skills and plugins
// installed on a working machine: the only tag characters outside two attack samples are the three flags
// in zod's emoji test list, which this pattern leaves alone.
const hiddenTagPattern = `[\x{E0000}-\x{E002F}\x{E003A}-\x{E0060}\x{E007B}-\x{E007E}]` +
	`|[` + tagSpec + `]{7,}` +
	`|(?:^|[^\x{1F3F4}` + tagSpec + `])[` + tagSpec + `]` +
	`|[` + tagSpec + `](?:$|[^\x{E007F}` + tagSpec + `])` +
	`|(?:^|[^` + tagSpec + `])\x{E007F}`

var hiddenTagRE = regexp.MustCompile(hiddenTagPattern)

// HidesTagText reports whether s holds a tag character outside a well-formed emoji flag: the INJ-006
// predicate, exported for the report renderers so a name is cleaned by the same answer a file's contents
// are reported by.
func HidesTagText(s string) bool {
	return strings.Contains(s, tagPrefix) && hiddenTagRE.MatchString(s)
}

// IsTag reports whether r is a Unicode tag character, U+E0000–E007F.
func IsTag(r rune) bool { return r >= tagLow && r <= tagHigh }

// decodeTag returns the ASCII character a tag character mirrors (U+E0020–E007E), or -1 for the tags
// that mirror none (U+E0000–E001F, among them the language tag U+E0001, and the cancel tag).
func decodeTag(r rune) rune {
	if r >= tagLow+0x20 && r < tagCancel {
		return r - tagLow
	}
	return -1
}

// revealTags renders s with every run of tag characters decoded and set between ⟦ and ⟧: what INJ-006's
// explanation prints, so a reader learns where hidden text sits on the line and what it says. Nothing
// else in a report can tell them: evidence quotes the line as written, and the human renderers show each
// tag character as U+FFFD. A run that decodes to nothing still shows as ⟦⟧.
func revealTags(s string) string {
	var b strings.Builder
	open := false
	for _, r := range s {
		if !IsTag(r) {
			if open {
				b.WriteString("⟧")
				open = false
			}
			b.WriteRune(r)
			continue
		}
		if !open {
			b.WriteString("⟦")
			open = true
		}
		if c := decodeTag(r); c >= 0 {
			b.WriteRune(c)
		}
	}
	if open {
		b.WriteString("⟧")
	}
	return b.String()
}

// hiddenTagWhy is INJ-006's explanation for one line: the rule's own, then the line with its tag runs
// revealed. The decoded text came from the file, so it goes through redactClip like a snippet does
// (invariant 3): Redact sees the secret a tag run spelled out, then the clip bounds it.
func hiddenTagWhy(why, raw string) string {
	return why + " Decoded, with ⟦ ⟧ around the characters that do not show, the line reads: " + redactClip(revealTags(raw))
}
