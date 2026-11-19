// SPDX-License-Identifier: MIT
package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	// sectionHeading opens the part of CHANGELOG.md that holds what has merged and not shipped.
	sectionHeading = "## Unreleased"
	// maxListed bounds how many paths one problem line names.
	maxListed = 5
	// maxQuoted bounds how much of an entry a problem line quotes.
	maxQuoted = 100
	dateForm  = "2006-01-02"
)

var (
	// entryTagRE is the parenthesis every unreleased entry carries: optional references, then
	// the author's GitHub login and the day. A release moves the entry under its version as
	// written, so the four facts a reader asks for (version, day, content, author) are all there.
	entryTagRE = regexp.MustCompile(`\((?:[^()]*, )?@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?, (\d{4}-\d{2}-\d{2})\)`)
	// versionRE is the line a release opens with, as in "**v0.38.0 (2026-11-19) — …".
	versionRE = regexp.MustCompile(`(?m)^\*\*(v\d+\.\d+\.\d+) \(`)
	// optOutRE is a commit-message line of its own. The words inside a sentence do not match.
	optOutRE = regexp.MustCompile(`(?m)^Changelog:[ \t]*none\b(.*)$`)
)

// shippedDirs are the trees a user's install is built from.
var shippedDirs = []string{"plugin/", "npm/"}

// goDirs are the trees whose non-test Go files end up in the binary.
var goDirs = []string{"cmd/", "internal/"}

// shippedFiles are single files that are copied to users from outside those trees.
var shippedFiles = []string{"hack/github-action.yml"}

// Input is everything Check reads; main gathers it from git, tests write it by hand.
type Input struct {
	Changed  []string // paths that differ from the merge base
	Base     string   // CHANGELOG.md at the merge base
	Head     string   // CHANGELOG.md as it is now
	Messages string   // commit messages since the merge base
}

// Check returns one line per problem, none when the changelog is in step with the change.
func Check(in Input) []string {
	var problems []string
	entries, ok := unreleased(in.Head)
	if !ok {
		problems = append(problems, fmt.Sprintf("CHANGELOG.md has no %q section", sectionHeading))
	}
	for _, e := range entries {
		if p := entryProblem(e); p != "" {
			problems = append(problems, p)
		}
	}
	changed := shippedAmong(in.Changed)
	if len(changed) == 0 {
		return problems
	}
	optedOut, p := optOut(in.Messages)
	if p != "" {
		problems = append(problems, p)
	}
	if optedOut || hasNewEntry(in.Base, entries) || hasNewVersion(in.Base, in.Head) {
		return problems
	}
	return append(problems, fmt.Sprintf(
		"shipped files changed (%s) but CHANGELOG.md has no new entry under %q: add one as "+
			"\"- **What changed** (P-NNN, @login, YYYY-MM-DD). …\", or put a line "+
			"\"Changelog: none — <reason>\" in a commit message when no user can observe the change",
		list(changed), sectionHeading))
}

// unreleased returns the entries of the Unreleased section, each top-level bullet joined with
// its continuation lines, and whether the section exists. It stops at the next "## " heading.
func unreleased(md string) ([]string, bool) {
	var entries []string
	found, open := false, false
	for _, line := range strings.Split(md, "\n") {
		line = strings.TrimRight(line, " \t\r")
		switch {
		case !found:
			found = line == sectionHeading
		case strings.HasPrefix(line, "## "):
			return entries, true
		case strings.HasPrefix(line, "- "):
			entries = append(entries, line)
			open = true
		case line == "":
		case open && (line[0] == ' ' || line[0] == '\t'):
			entries[len(entries)-1] += " " + strings.TrimSpace(line)
		default:
			open = false
		}
	}
	return entries, found
}

// entryProblem says what an unreleased entry lacks, or "" when it names its author and day.
func entryProblem(entry string) string {
	m := entryTagRE.FindStringSubmatch(entry)
	if m == nil {
		return fmt.Sprintf("unreleased entry does not name its author and day as \"(…, @login, YYYY-MM-DD)\": %s", quote(entry))
	}
	if _, err := time.Parse(dateForm, m[1]); err != nil {
		return fmt.Sprintf("unreleased entry: %s is not a date: %s", m[1], quote(entry))
	}
	return ""
}

// optOut reports whether a commit message opts the change out, and the problem with an
// opt-out that gives no reason. Such a line does not count: the reason is what a reviewer reads.
func optOut(messages string) (bool, string) {
	matches := optOutRE.FindAllStringSubmatch(messages, -1)
	for _, m := range matches {
		if strings.Trim(m[1], " \t\r—–-:;,.()") != "" {
			return true, ""
		}
	}
	if len(matches) > 0 {
		return false, "a commit message says \"Changelog: none\" and gives no reason: write \"Changelog: none — <reason>\""
	}
	return false, ""
}

// hasNewEntry reports whether head has an unreleased entry the base did not have.
func hasNewEntry(base string, head []string) bool {
	before, _ := unreleased(base)
	seen := make(map[string]bool, len(before))
	for _, e := range before {
		seen[e] = true
	}
	for _, e := range head {
		if !seen[e] {
			return true
		}
	}
	return false
}

// hasNewVersion reports whether head opens a release the base did not have: a release moves
// the entries out of Unreleased instead of adding one.
func hasNewVersion(base, head string) bool {
	seen := make(map[string]bool)
	for _, m := range versionRE.FindAllStringSubmatch(base, -1) {
		seen[m[1]] = true
	}
	for _, m := range versionRE.FindAllStringSubmatch(head, -1) {
		if !seen[m[1]] {
			return true
		}
	}
	return false
}

// shipped reports whether a path is part of what a user installs or runs.
func shipped(path string) bool {
	for _, f := range shippedFiles {
		if path == f {
			return true
		}
	}
	for _, d := range shippedDirs {
		if strings.HasPrefix(path, d) {
			return true
		}
	}
	if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
		return false
	}
	for _, d := range goDirs {
		if strings.HasPrefix(path, d) {
			return true
		}
	}
	return false
}

func shippedAmong(paths []string) []string {
	var out []string
	for _, p := range paths {
		if shipped(p) {
			out = append(out, p)
		}
	}
	return out
}

func list(paths []string) string {
	if len(paths) <= maxListed {
		return strings.Join(paths, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(paths[:maxListed], ", "), len(paths)-maxListed)
}

func quote(entry string) string {
	r := []rune(entry)
	if len(r) <= maxQuoted {
		return entry
	}
	return string(r[:maxQuoted]) + "…"
}
