// SPDX-License-Identifier: MIT
// Command changelog-check fails when a change to shipped code has no changelog entry (P-141).
//
// CHANGELOG.md was written once per release, from memory of what had merged since the last
// one, and nothing said who made a change. Now every change to what a user installs or runs
// adds its own entry under "## Unreleased" in the same pull request, naming its author and
// day; a release moves those entries under its version. This command is what makes that a
// gate instead of a habit: `make verify` and CI run it against the merge base with main.
//
// It reads git and one file and writes nothing. The rules are in check.go and take their
// input as values, so the tests need no repository.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const changelogPath = "CHANGELOG.md"

func main() {
	base := flag.String("base", "origin/main", "the ref this change will merge into")
	flag.Parse()
	in, err := gather(*base)
	if err != nil {
		fmt.Fprintln(os.Stderr, "changelog-check:", err)
		os.Exit(2)
	}
	problems := Check(in)
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "changelog-check:", p)
	}
	if len(problems) > 0 {
		os.Exit(1)
	}
}

// gather reads the change from git: what differs from the merge base (the working tree
// included, so the check answers before the commit as well as after it), the changelog on
// both sides, and the commit messages in between.
func gather(base string) (Input, error) {
	mergeBase, err := git("merge-base", base, "HEAD")
	if err != nil {
		return Input{}, fmt.Errorf("no merge base with %s (fetch it, or pass -base): %w", base, err)
	}
	mergeBase = strings.TrimSpace(mergeBase)
	tracked, err := git("diff", "--name-only", mergeBase)
	if err != nil {
		return Input{}, err
	}
	untracked, err := git("ls-files", "--others", "--exclude-standard")
	if err != nil {
		return Input{}, err
	}
	messages, err := git("log", "--format=%B", mergeBase+"..HEAD")
	if err != nil {
		return Input{}, err
	}
	head, err := os.ReadFile(changelogPath)
	if err != nil {
		return Input{}, fmt.Errorf("read %s (run from the repository root): %w", changelogPath, err)
	}
	// A base without the file is a base without entries, not an error.
	before, _ := git("show", mergeBase+":"+changelogPath)
	return Input{
		Changed:  append(strings.Fields(tracked), strings.Fields(untracked)...),
		Base:     before,
		Head:     string(head),
		Messages: messages,
	}, nil
}

func git(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(exit.Stderr)))
		}
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}
