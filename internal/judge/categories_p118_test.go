// SPDX-License-Identifier: MIT
package judge

import (
	"strings"
	"testing"

	"github.com/basdotio/bas-guard/internal/model"
)

// P-118: the server question asked for "executing shell or arbitrary code built from a parameter"
// and the table had no row for it, so the model filed a fixed program run with list arguments and
// a shell=True injection alike under remote-execution (a network download). These tests pin the
// row, its exemption from the disclosure step, that the step still applies to every other row,
// and the sentence the question gained.

// TestSeverityFor_CodeExecution: high whether or not the tools disclose it (issues/028: a tool
// that says it executes commands is what Cisco's malicious servers say too); remote-execution and
// the other server rows still take the step; the intent pass does not have the row.
func TestSeverityFor_CodeExecution(t *testing.T) {
	cases := []struct {
		mode      Mode
		category  string
		disclosed bool
		want      model.Severity
	}{
		{ModeServer, "code-execution", false, model.SevHigh},
		{ModeServer, "code-execution", true, model.SevHigh}, // exempt
		{ModeServer, " Code-Execution ", true, model.SevHigh},
		// Reverse assertions: the step still applies to the rest of the server table.
		{ModeServer, "remote-execution", true, model.SevMedium},
		{ModeServer, "remote-execution", false, model.SevHigh},
		{ModeServer, "credential-read", true, model.SevMedium},
		{ModeServer, "resource-exhaustion", true, model.SevMedium},
		{ModeServer, "software-source", true, model.SevHigh}, // still exempt
		// The intent table did not gain it: an unknown name there, so medium.
		{ModeIntent, "code-execution", false, model.SevMedium},
		{ModeIntent, "code-execution", true, model.SevLow},
		{ModeIntent, "software-source", true, model.SevHigh},
	}
	for _, c := range cases {
		got := severityFor(c.mode, Verdict{Flagged: true, Category: c.category, Disclosed: c.disclosed, Severity: "low"})
		if got != c.want {
			t.Errorf("mode %d %q disclosed=%v: got %s, want %s", c.mode, c.category, c.disclosed, got, c.want)
		}
	}
	if disclosureLowered(ModeServer, Verdict{Flagged: true, Category: "code-execution", Disclosed: true}) {
		t.Error("a disclosed code-execution vote must not be annotated as lowered")
	}
}

// TestCategoryPrompt_CodeExecutionSaysWhatItIsNot: the row offers itself with its NOT clauses — a
// fixed program with list arguments, and a network download (remote-execution) — and the server
// question carries the same exception where it asks for execution built from a parameter. The
// question does not ask for disclosed execution to be flagged: the exemption is the table's only.
func TestCategoryPrompt_CodeExecutionSaysWhatItIsNot(t *testing.T) {
	p := categoryPrompt(ModeServer)
	for _, want := range []string{
		"code-execution = a tool runs a shell command",
		"NOT a fixed program run with its arguments as a list and no shell",
		"which is remote-execution",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("server category prompt lacks %q", want)
		}
	}
	if !strings.Contains(serverTask, "built from a parameter (running a fixed program with its arguments passed as a list and no shell is not this)") {
		t.Error("serverTask lacks the fixed-program exception")
	}
	if strings.Count(serverTask, "EVEN WHEN") != 1 || !strings.Contains(serverTask, "EVEN WHEN a description discloses it, for code that changes where this machine gets software") {
		t.Error("serverTask's only flag-even-when-disclosed clause must stay the software-source one")
	}
	if strings.Contains(categoryPrompt(ModeIntent), "code-execution") {
		t.Error("the intent prompt must not offer code-execution")
	}
}
