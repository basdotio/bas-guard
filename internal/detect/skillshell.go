// SPDX-License-Identifier: MIT
package detect

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/basdotio/bas-guard/internal/model"
	"github.com/basdotio/bas-guard/internal/parse"
)

// Skill shell commands (P-132). A skill's or custom command's body may carry shell that Claude Code
// runs itself, when the skill is invoked — typed as /name, or loaded by Claude on its own because its
// description fits — BEFORE Claude reads the content, and with no permission prompt: a command the
// permission rules allow runs (the skill's own allowed-tools count as allowed, even in `claude -p` in a
// folder nobody trusted), anything else aborts the invocation. Claude sees the output, not the command.
//
// The rules already read these lines like any other line, so `curl … | sh`, an env dump sent out or a
// base64 payload are reported where they are. What they deliberately do not report is a download that
// is kept and then run over https (P-094: 13 benign trees install a tool that way in prose a person
// reads) and a package run from a registry. On a `!` line neither is advice: it is a command that runs
// by itself on every invocation. So, only there:
//
//	EXEC-014 (high, dim 4)   the command downloads a file and runs it, or pipes a download into an
//	                         interpreter that reads its program from stdin — over https as much as http
//	SUP-011  (medium, dim 5) the command runs a registry package at whatever version is current:
//	                         npx/npm exec with -y or a tag, pnpm/yarn dlx, bunx with a tag, uvx,
//	                         uv tool run, pipx run, go run of a remote module at a branch
//
// Where Claude Code runs them is measured, not guessed: in 2.1.107 the body after the frontmatter of a
// skill (user, project or plugin) and of a command (commands/ of a project, the user or a plugin) goes
// through one function that runs every match of ```!\s*\n?([\s\S]*?)\n?``` and of (?<=^|\s)!`([^`]+)`
// (multiline), fences or not; an MCP prompt does not. CLAUDE.md, rules, subagents and bundled documents
// are never preprocessed, so the check runs on the SKILL.md and command units only.

// skillShellBlockRE and skillShellInlineRE are Claude Code's two patterns. RE2 has no lookbehind, so the
// inline one consumes the blank before the `!`, which changes nothing about what it finds: the blank is
// never part of a command.
var (
	skillShellBlockRE  = regexp.MustCompile("(?s)```!\\s*\\n?(.*?)\\n?```")
	skillShellInlineRE = regexp.MustCompile("(?m)(?:^|\\s)!`([^`]+)`")
)

// skillShellCmd is one command Claude Code would run on invocation: its text, trimmed as Claude Code
// trims it, and the byte offset in the file where that text starts.
type skillShellCmd struct {
	text  string
	start int
}

// skillShellCommands lists the commands of a skill or command file, in file order.
func skillShellCommands(text string) []skillShellCmd {
	off := parse.BodyOffset(text)
	body := text[off:]
	var out []skillShellCmd
	add := func(m []int) {
		raw := body[m[2]:m[3]]
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return
		}
		out = append(out, skillShellCmd{text: trimmed, start: off + m[2] + strings.Index(raw, trimmed)})
	}
	for _, m := range skillShellBlockRE.FindAllStringSubmatchIndex(body, -1) {
		add(m)
	}
	if strings.Contains(body, "!`") {
		for _, m := range skillShellInlineRE.FindAllStringSubmatchIndex(body, -1) {
			add(m)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].start < out[j].start })
	return out
}

// skillShellScope reports whether Claude Code preprocesses the unit's file: a SKILL.md, or a command
// (roleInstruction is given to exactly those and to CLAUDE.md, which it does not preprocess).
func skillShellScope(u unit) bool {
	return u.role == roleInstruction && !u.synthetic && !strings.EqualFold(filepath.Base(u.file), "CLAUDE.md")
}

// alreadyRunsDownloads are the line rules that report a download run in one step. A line one of them
// reported keeps that finding alone: EXEC-014 there would say the same thing again in the same dimension.
var alreadyRunsDownloads = map[string]bool{"EXEC-001": true, "EXEC-002": true, "EXEC-011": true, "EXEC-012": true}

const (
	skillShellFetchTitle  = "Skill shell command downloads code and runs it"
	skillShellFetchWhy    = "Claude Code runs this command itself when the skill or command is invoked — typed as /name or loaded by Claude on its own — before Claude reads the content, and without a prompt when the skill's allowed-tools or a permission rule allows it. What runs is whatever the server returns at that moment, over https as much as http, and nobody reviewing this skill has read it. Ship the script with the skill instead, where it is read and hashed with it."
	skillShellRunnerTitle = "Skill shell command runs a registry package at a moving version"
	skillShellRunnerWhy   = "Claude Code runs this command itself when the skill or command is invoked, before Claude reads the content and without a prompt when the skill's allowed-tools or a permission rule allows it. The package's code is not in this tree, so nothing that reviewed the skill read it, and its publisher can change what this version resolves to at any time. Pin an exact version (pkg@1.2.3, pkg==1.2.3), or ship what it does with the skill."
)

// skillShellFindings reads every command Claude Code would run from the unit and returns EXEC-014 and
// SUP-011, at most one of each per command. already holds the unit's findings so far.
func skillShellFindings(rel string, u unit, already []model.Finding) []model.Finding {
	if !strings.Contains(u.text, "!") {
		return nil
	}
	reported := map[int]bool{}
	for _, f := range already {
		if alreadyRunsDownloads[f.RuleID] {
			for _, ev := range f.Evidence {
				if ev.File == rel {
					reported[ev.Line] = true
				}
			}
		}
	}
	at := func(off int) model.Evidence {
		line := 1 + strings.Count(u.text[:off], "\n")
		begin := strings.LastIndexByte(u.text[:off], '\n') + 1
		end := len(u.text)
		if i := strings.IndexByte(u.text[off:], '\n'); i >= 0 {
			end = off + i
		}
		return model.Evidence{File: rel, Line: line, Snippet: u.evidence(strings.TrimRight(u.text[begin:end], "\r"))}
	}
	var out []model.Finding
	for _, c := range skillShellCommands(u.text) {
		r := readSkillShell(c.text, 0)
		if fr := r.fetchRun; fr != nil {
			ev := dedupeEvidence(at(c.start+fr.fetchAt), at(c.start+fr.runAt))
			if !reported[ev[0].Line] && !reported[ev[len(ev)-1].Line] {
				out = append(out, model.Finding{
					RuleID: "EXEC-014", Dimension: 4, Severity: model.SevHigh, Source: model.SrcStatic,
					Title: skillShellFetchTitle, Why: redactClip(fr.how) + ". " + skillShellFetchWhy, Evidence: ev,
				})
			}
		}
		if rn := r.runner; rn != nil {
			out = append(out, model.Finding{
				RuleID: "SUP-011", Dimension: 5, Severity: model.SevMedium, Source: model.SrcStatic,
				Title:    skillShellRunnerTitle,
				Why:      redactClip(fmt.Sprintf("`%s` runs through %s at %s.", rn.spec, rn.tool, rn.version)) + " " + skillShellRunnerWhy,
				Evidence: []model.Evidence{at(c.start + rn.at)},
			})
		}
	}
	return out
}
