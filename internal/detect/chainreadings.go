// SPDX-License-Identifier: MIT
package detect

import "github.com/basdotio/bas-guard/internal/model"

// The readings of the exfiltration chain, in one place (P-146).
//
// "Does this file read a credential and send something, and where to" is asked three times, by
// three callers that want different things from the answer. Each reading was set by a measured
// proposal and left the others alone on purpose, so the differences are not drift; but they lived
// in three functions that each built their own chain and each copied the loop that feeds it, and
// one of them was documented as "the same chain EXFIL-001 runs", which stopped being true at P-095.
// The readings are below, side by side, and replay is the one loop.
//
//	                          a URL literal is a send   request calls beyond networkActionRE   who asks
//	rulesChain    (the rules)  in a script that can      no                                    scanUnits, for EXFIL-001/-003
//	                           send (P-095)
//	homeChain     (the judge)  always                    no                                    CredentialGoesHome, …Across: lower a
//	                                                                                           credential-read vote (P-062)
//	elsewhereChain (the judge) never                     yes, requestLineRE (P-117)            CredentialSentElsewhere: keep one high
//	                                                                                           (P-098)
//
// Why they differ. The rules must not call a usage string a request, so a literal counts only where
// a client exists (P-095: 217 of 522 benign findings sat in files that cannot send). The judge's
// "goes home" asks whether EVERY destination a file names is the credential's own, so it counts
// every literal: one foreign URL anywhere must be enough to refuse the downgrade. Its "sent
// elsewhere" asks the opposite — is there a REQUEST to a foreign host — so a literal that is not a
// request (a namespace, a licence link) must not count, and clients the rules' list does not name
// must (P-117: 44 benign votes were held high by such literals).
//
// What that amounts to, measured on the 8,162 code files of the corpus's skills and servers
// (2026-11-20): where the rules report a chain (298 files), the judge's readings never contradict
// it — no file the rules call home is "sent elsewhere" to the judge. Five files the rules hold at
// high read as home to the judge, all EXFIL-003, which takes no destination downgrade by design.
// On 77 files the judge's wider readings see a chain where the rules see none; they are read only
// when a vote cites the file. Making the three one reading would move those 77 answers, and the
// benign votes they lower with them. Do not merge them for tidiness: change a reading the way it
// was set, with a measurement, and say here which.

// rulesChain is the chain the rules feed one unit's lines to, and whether the rules read a chain
// in a unit of this role at all: bundled prose, a connector's tool descriptions and a document a
// SKILL.md names are not code, and no chain is read there.
func rulesChain(u unit, commentLines map[int]bool) (c chain, reads bool) {
	// A URL literal is egress only in a real script that can send (P-095): see networkCapableRE.
	c = chain{literalIsEgress: u.role == roleScript && !u.synthetic && networkCapable(u, commentLines)}
	reads = u.role != roleDoc && u.role != roleToolDesc && u.role != roleNamedDoc
	if reads {
		c.assigns = urlAssignments(u.text)
	}
	return c, reads
}

// homeChain is the judge's "does the key go only where it belongs" reading of a file.
func homeChain(text string) chain {
	return chain{literalIsEgress: true, assigns: urlAssignments(text)}
}

// elsewhereChain is the judge's "is there a request to a host that is not the key's" reading.
func elsewhereChain(text string) chain {
	return chain{assigns: urlAssignments(text), requestLine: requestLineRE}
}

// replay feeds every code line of a file to c, as the scan loop feeds the rules' chain, and returns
// what it saw. Comment-only lines are not code and are not fed. No evidence is kept: a caller of
// replay wants the chain's verdict, not a citation.
func replay(c chain, path, text string) chain {
	lang := langForFile(path)
	for _, ll := range logicalLines(lang, text, commentOnlyLines(lang, text)) {
		if ll.comment {
			continue
		}
		c.observe(ll.raw, ll.norm, func() model.Evidence { return model.Evidence{} })
	}
	return c
}
