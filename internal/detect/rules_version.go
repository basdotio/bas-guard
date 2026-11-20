// SPDX-License-Identifier: MIT
package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"regexp"
	"strconv"
	"sync"
)

// rulesEpoch is the part of the rules version that the rule table cannot see for itself (spec §5.1).
//
// The rules version covers DETERMINISTIC detection only: the findings overall is computed from,
// so that a report's overall can be recomputed against the rules that produced it. RulesVersion
// hashes builtinRules(), but a good share of deterministic detection lives outside that table:
// the structural and shape checks (the exfiltration chain, hooks, SUP-004/005/006,
// OBF-004/006/007), the role gate (roleAllows, roleForPath), the lexical layer (logical.go),
// comment handling, which files the reader opens, the credential-import check in
// internal/collect (EXFIL-005), the project MCP approval check there (PERM-009), and
// internal/permcheck.
//
// The LLM judge is outside the rules version, and so outside this epoch: nothing in
// internal/judge — prompts, grounding, consensus, severity clamping — is covered, and changing it
// does not bump this. The judge moves only overall_effective, and this value does not identify
// it: a --llm report names the judge in its own judge block — prompt_version and excerpt_version
// for the judge's code, model and samples for how it ran (P-031).
//
// BUMP IT, in the same commit, whenever a change outside builtinRules() alters — for some input —
// which deterministic findings are produced, or a finding's rule ID, dimension, severity or
// advisory flag. Do NOT bump it for titles, explanations, evidence formatting or score weights:
// those do not decide a finding, and a version that moves without the rules moving says "the
// rules changed" when they did not.
//
// Nothing enforces this mechanically. Hashing the source would move on every comment edit, which
// is the false alarm this value exists to avoid; the cost is that a forgotten bump lets two
// reports claim the same rules while different detection code produced them.
const rulesEpoch = 27 // 27: a destination variable is resolved to the host its base URL spells only where the line ends that host: a base that ends at its host (https://api.deepl.com) followed by anything but a path, a query, a port or the end of its string (${API}.evil.net, ${API}-x.net, ${API}evil.net, ${API}@evil.net, ${API}${S}, API + ".evil.net", API + name) is unreadable, for EXFIL-001's destination check and for HOOK-003's loopback reading alike; a base with a path resolves whatever follows (P-143); 26: SUP-010's prerequisite phrase takes the verb with its object ("install the Claude Code helper from", "download the helper from": install or download, up to six words with no sentence break, then from or here), and clawhub.com is one of ClawHub's own hosts (P-139); 25: the normalized view drops every character Unicode displays as nothing (Default_Ignorable_Code_Point: variation selectors, the grapheme joiner, reserved code points; not control characters), and reads every space but the ASCII one, the Hangul fillers and the braille blank as a space, so a word split by one, or a sentence spaced with no-break spaces, meets the rules (P-138); 24: an HTML comment in an instruction file or document, outside fenced code, that carries the header SYSTEM OVERRIDE or tells the agent to keep its instructions or an action from the user is INJ-007 (P-137); 23: a run of four or more variation selectors that are not all the same one is OBF-008, a script with 20 or more distinct obfuscator-style names (_0x…) is OBF-009, and a crypto-wallet key store (wallet.dat, a geth keystore, the Solana keypair, Electrum and Exodus wallets, the MetaMask and Phantom extension stores) is a credential leg of the exfiltration chain (P-136); 22: a line of an instruction file or document that offers a prerequisite from a paste site, a password-protected archive or a look-alike of an agent platform's host is SUP-010 (P-131); 21: the commands a settings file has Claude Code run on its own (apiKeyHelper, awsAuthRefresh, awsCredentialExport, gcpAuthRefresh, otelHeadersHelper, processWrapper, statusLine, fileSuggestion) are an artifact read with the script rules, the scripts they name followed, and a status line that sends the transcript is HOOK-003 (P-133); 20: PERM-007's file-level half follows the settings path one level: the line that names a Claude settings file assigns it to a name and a later line writes through that name, or one line names it and writes it in code; a script that reads the file and writes another no longer closes it (P-134); 19: a skill's or command's shell that Claude Code runs on invocation (!`cmd` and ```! blocks, in a SKILL.md or a command file) is read: a download it runs, or pipes into an interpreter, is EXEC-014, and a registry package it runs at a moving version (npx -y, a tag, dlx, uvx, pipx run, go run @branch) is SUP-011 (P-132); 18: a package.json's install-time scripts (preinstall, install, postinstall) are read and what they run is followed one level: SUP-008 when it was not read, is packed, fetches and runs, or is inline code that reads or writes files, the environment or the network, starts a process or evaluates code, else SUP-009 (P-129); 17: HOOK-003 also reports a command hook, or a script it runs, that hands a sender its stdin, a content field of the event or the transcript file (P-128); 16: a project's settings approving the servers of its .mcp.json (enableAllProjectMcpServers, enabledMcpjsonServers, minus disabledMcpjsonServers) is PERM-009 on each approved server, raised in internal/collect (P-127); 15: check on a directory reads the project's CLAUDE.md files with the scan's instruction collector, so their @ imports are followed and a credential import is EXFIL-005 (P-125); 14: PERM-007's file-level half closes on one line that both names a Claude settings file and writes, and its write leg reads open() around a call and takes stream devices off (P-124); 13: the normalized view decodes Unicode tag characters to the ASCII they mirror, so rules match a sentence written in them (P-123); 12: INJ-005 pairs a download kept at a path with another line telling the agent to obey that path (P-121); 11: check reads the Claude Code configuration a directory or file target declares, and a project's .claude/commands run the command rules in a tree (P-120); 10: an MCP server added in local scope (projects[dir].mcpServers of a .claude.json) is collected and scanned (P-119); 9: urllib.parse is not a network client, and a URL literal needs a host (P-099); 8: a URL literal is the network leg only in a script that can send (P-095); 7: EXEC-013 fires when one file writes the script it makes a shell startup file source (P-093); 6: FS-005 follows a log path assigned to a name to the line that erases the name (P-092); 5: a document the tree's SKILL.md names runs the instruction rules, not only the prose ones (P-091); 4: EXFIL-001 destination resolves a same-file base URL, matches the registrable label, and the credential leg drops JS template locals and child-env copies (P-061); 3: a symlinked SKILL.md is read where it loads, a refused file is scored (P-056); 2: plugin children (P-044)

// rulesVersionLen is how many hex digits of the sha256 the version keeps.
const rulesVersionLen = 12

// rulesVersionOnce caches the built-in table's version: builtinRules() compiles every pattern,
// and the load-time gate runs a whole analysis on each skill load.
var rulesVersionOnce = sync.OnceValue(func() string { return rulesVersion(builtinRules(), rulesEpoch) })

// RulesVersion names the rule table this build detects with: the first 12 hex digits of a sha256
// over everything in builtinRules() that decides whether a finding fires and how heavily, plus
// rulesEpoch. It is what `scan --json` reports as rules_version, what `bas-guard version` prints,
// and what the docs/rules.md header carries.
//
// Two values that differ mean the rules changed. Two values that agree mean the rule table is the
// same; the deterministic detection code around it is the same only as far as rulesEpoch has been
// kept, and the judge is not covered at all.
func RulesVersion() string { return rulesVersionOnce() }

// rulesVersion is RulesVersion over an arbitrary table, so tests can mutate one.
//
// What goes in is what changes a verdict: ID, dimension, severity, the advisory and *Only flags,
// and both patterns' source. Title, Why and Ref do not — they explain a finding, they do not
// decide one. Rules are taken in ENGINE order, not sorted: findings on one line are appended in
// rule order, so a reorder can change a report and should move the version. Every field is
// length-prefixed because a pattern may contain any byte, so no separator is safe.
func rulesVersion(rules []Rule, epoch int) string {
	h := sha256.New()
	writeField(h, strconv.Itoa(epoch))
	writeField(h, strconv.Itoa(len(rules)))
	for _, r := range rules {
		writeField(h, r.ID)
		writeField(h, strconv.Itoa(r.Dimension))
		writeField(h, string(r.Severity))
		writeField(h, flagBits(r.Advisory, r.HookOnly, r.ConnectorOnly, r.RawOnly, r.ScriptOnly))
		writeField(h, patternSource(r.re))
		writeField(h, patternSource(r.except))
	}
	return hex.EncodeToString(h.Sum(nil))[:rulesVersionLen]
}

// writeField appends one length-prefixed field; hash.Hash writes never fail.
func writeField(h hash.Hash, s string) {
	_, _ = fmt.Fprintf(h, "%d:%s;", len(s), s)
}

// flagBits renders the boolean flags in a fixed order as "0"/"1" digits.
func flagBits(flags ...bool) string {
	b := make([]byte, len(flags))
	for i, f := range flags {
		b[i] = '0'
		if f {
			b[i] = '1'
		}
	}
	return string(b)
}

// patternSource is a compiled pattern's source text, or "" for none (a rule without a veto).
func patternSource(re *regexp.Regexp) string {
	if re == nil {
		return ""
	}
	return re.String()
}
