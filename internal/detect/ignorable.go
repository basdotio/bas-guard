// SPDX-License-Identifier: MIT
package detect

// What a reader is shown nothing for, and what a reader is shown a blank for (P-138).
//
// The normalized view dropped the characters of invisible() and nothing else, and invisible() is a
// short table written by hand: zero-width characters, joiners, bidi controls. Everything else that
// draws nothing stayed in the line, between the letters of whatever word it was put in, and a rule
// reads letters:
//
//	Ignore all prev<U+FE00>ious instructions         a variation selector; the sentence scored 100
//	Ignore<U+00A0>all<U+00A0>previous instructions   no-break spaces; `\s` in a pattern is ASCII
//
// Every character Unicode says to display as nothing (Default_Ignorable_Code_Point) that the table
// does not hold did the first, and every space a pattern's \s does not read did the second. Two
// functions close it, both read by foldCharacters and by nothing else:
//
//	drawsNothing   dropped: the rest of Default_Ignorable_Code_Point
//	readsAsBlank   read as one ASCII space: Unicode's White_Space outside ASCII, the vertical tab,
//	               and five characters that are not spaces and draw a blank cell (the four Hangul
//	               fillers, default-ignorable on paper, and the braille blank)
//
// They are NOT added to invisible(), and the difference is the point. invisible() is one table with
// three readers: this view, report.Sanitize, which replaces each of its characters with U+FFFD in a
// name a person reads, and the judge's grounding and padding fold. A variation selector follows
// every emoji with a text twin (U+2714 U+FE0F), so in that table each one would be printed as a
// replacement character; and a payload written in selectors (OBF-008) would be folded out of what the
// judge is sent, as a tag sentence would have been (tags.go). Here the characters are only removed
// from the copy rules match against. The line as written is still what OBF-008 counts selectors in,
// what INJ-004 reports zero-width characters in and what evidence quotes.
//
// The ranges are written out, like invisible(), so that the behaviour can be read; and
// TestIgnorable_IsUnicodesList compares them, code point by code point, with the property as the
// toolchain's Unicode tables derive it, so a range mistyped here or a Unicode version that moved
// is a red test, not a quiet gap.
//
// CONTROL CHARACTERS ARE NOT DROPPED, and the first build of this did drop them. One inside a word
// hides it the same way (`prev<U+007F>ious`), but no Unicode property says a control character is
// displayed as nothing, an editor draws a placeholder for it, and source files hold tables of them: a
// lexer table in prettier's flow plugin opens `z0("<U+0001>\0<U+0001><U+0001>\0\0\0…`, thousands
// of escapes on one line. The quote fold reads the escapes as a run of zeros either way; with the
// control characters gone the run starts right after the opening quote, which is where OBF-002
// looks for a base64 blob, and three versions of an ordinary package gained a finding. Removing a
// character makes neighbours of what it stood between, so "stripping can only remove a match" holds
// for the rule that reports the character and for no other. Dropping them only inside a word leaves
// the end of a word open (`ignore<U+007F> all`), and dropping them wherever a word is next to them
// is the first build again. It needs its own answer, most likely by where the line is read (an
// instruction file has a model for a reader; a script has an interpreter, which does not run
// `cu<U+007F>rl` as curl).

// drawsNothing reports whether r is displayed as nothing and is not already handled: not in
// invisible(), not a tag character (decoded by foldCharacters before this is asked), not one of the
// characters readsAsBlank turns into a space. No control character is one.
func drawsNothing(r rune) bool {
	switch {
	case r == 0x034F, r == 0x061C: // combining grapheme joiner, Arabic letter mark
		return true
	case r == 0x17B4, r == 0x17B5: // Khmer inherent vowels
		return true
	case r >= 0x180B && r <= 0x180F: // Mongolian free variation selectors and vowel separator
		return true
	case r == 0x2065, r >= 0x206A && r <= 0x206F: // reserved; deprecated format characters
		return true
	case r >= 0xFE00 && r <= 0xFE0F: // variation selectors 1–16
		return true
	case r >= 0xFFF0 && r <= 0xFFF8: // reserved
		return true
	case r >= 0x1BCA0 && r <= 0x1BCA3: // shorthand format controls
		return true
	case r >= 0x1D173 && r <= 0x1D17A: // musical format controls
		return true
	case r >= 0xE0080 && r <= 0xE0FFF: // reserved, variation selectors 17–256 (U+E0100–E01EF), reserved
		return true
	}
	return false
}

// readsAsBlank reports whether r is drawn as a blank and is not whitespace a pattern's \s already
// reads (in Go that is tab, LF, FF, CR and the ASCII space, nothing else). The view writes one ASCII
// space in its place.
//
// The Hangul fillers are default-ignorable in Unicode's table and are a blank cell in every font
// that has them, which is what they are sold as on the pages that list "invisible characters"; the
// braille blank is the same cell and in no table. Between two words they separate them, so reading
// them as nothing would glue the words together and hide the sentence a second way.
func readsAsBlank(r rune) bool {
	switch {
	case r == '\v', r == 0x85, r == 0xA0, r == 0x1680: // vertical tab, next line, no-break space, ogham space mark
		return true
	case r >= 0x2000 && r <= 0x200A: // en quad … hair space
		return true
	case r == 0x2028, r == 0x2029, r == 0x202F, r == 0x205F, r == 0x3000: // line and paragraph separators, narrow no-break, mathematical and ideographic spaces
		return true
	case r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0: // Hangul fillers
		return true
	case r == 0x2800: // braille pattern blank
		return true
	}
	return false
}
