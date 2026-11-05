// SPDX-License-Identifier: MIT
package judge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/basdotio/bas-guard/internal/model"
)

// P-115: the server and result tables gain the rows for behaviour the model already described
// correctly and filed under a medium catch-all. These tests pin the rows, that the server table
// is the intent table plus two, that every other pass's category prompt is byte-identical to what
// it was before, and that the catch-alls point at their new neighbours.

// TestSeverityFor_NewRows: the three new rows are high, the server two take the ordinary
// disclosure step, and the catch-alls beside them stay medium.
func TestSeverityFor_NewRows(t *testing.T) {
	cases := []struct {
		mode      Mode
		category  string
		disclosed bool
		want      model.Severity
	}{
		{ModeServer, "resource-exhaustion", false, model.SevHigh},
		{ModeServer, "resource-exhaustion", true, model.SevMedium}, // a load tester that says so
		{ModeServer, "result-tampering", false, model.SevHigh},
		{ModeServer, "result-tampering", true, model.SevMedium},
		{ModeServer, "other", false, model.SevMedium},
		{ModeServer, "denial-of-service", false, model.SevMedium}, // not in the table
		{ModeSteering, "covert-transmission", false, model.SevHigh},
		{ModeSteering, "covert-transmission", true, model.SevHigh}, // no disclosure step on this pass
		{ModeSteering, "unrequested-artifact", false, model.SevMedium},
		{ModeSteering, "exfiltration", false, model.SevMedium}, // another table's name
		// The intent table did not gain them: on that pass they are unknown names, so medium.
		{ModeIntent, "resource-exhaustion", false, model.SevMedium},
		{ModeIntent, "result-tampering", false, model.SevMedium},
	}
	for _, c := range cases {
		got := severityFor(c.mode, Verdict{Flagged: true, Category: c.category, Disclosed: c.disclosed, Severity: "low"})
		if got != c.want {
			t.Errorf("mode %d %q disclosed=%v: got %s, want %s", c.mode, c.category, c.disclosed, got, c.want)
		}
	}
}

// TestCategoryTables_ServerIsIntentPlusTwo: the server table is the intent table's behaviour rows,
// then resource-exhaustion and result-tampering, then its own `other` valve. Before P-115 the two
// were separate literals with identical rows; a row added to one could silently miss the other.
func TestCategoryTables_ServerIsIntentPlusTwo(t *testing.T) {
	intent, server := categoryTables[ModeIntent], categoryTables[ModeServer]
	if len(server) != len(intent)+2 {
		t.Fatalf("server table has %d rows, intent %d; want intent + 2", len(server), len(intent))
	}
	for i := 0; i < len(intent)-1; i++ {
		if server[i] != intent[i] {
			t.Errorf("row %d: server %q, intent %q", i, server[i].name, intent[i].name)
		}
	}
	n := len(intent) - 1
	for i, want := range []string{"resource-exhaustion", "result-tampering", "other"} {
		if got := server[n+i].name; got != want {
			t.Errorf("server row %d is %q, want %q", n+i, got, want)
		}
	}
	if v := intent[len(intent)-1]; v.name != "other" || v.sev != model.SevMedium {
		t.Errorf("intent's last row is %q %s, want the medium `other` valve", v.name, v.sev)
	}
}

// TestCategoryPrompt_OtherPassesUnchanged is the reverse assertion: only the server and result
// prompts move. The digests are of main's categoryPrompt before P-115 (v0.33.1-3-g5a18a6db).
func TestCategoryPrompt_OtherPassesUnchanged(t *testing.T) {
	want := map[Mode]string{
		ModeIntent:     "e3ab30b0cd3df92acd8ea5703d9b0affaa850f1a80bd6378cf8f3f732f8d11aa",
		ModeInjection:  "85bfc535009e1a6692e9ac7a8988e1d0bcd7d32c9904285896e6e6e98fbb6761",
		ModeExplain:    "871a8bfd62fef32ba6679e25f17eb3fe2f12981d594df7a3420a5664c7dfaab4",
		ModeCapability: "9c0557c5c24dc9464f7e1f6cdea78f0a43ac7662d1a2f4150fd74a744f8f4985",
		ModeMCPConfig:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // empty: no table
		ModeCollusion:  "8e14aa1e90eb81950ec528e22ce25ab91e19b1cd44a08c228ee0faf6b60ab589",
	}
	for m, d := range want {
		sum := sha256.Sum256([]byte(categoryPrompt(m)))
		if got := hex.EncodeToString(sum[:]); got != d {
			t.Errorf("mode %d: category prompt changed (%s); P-115 moves only the server and result tables", m, got)
		}
	}
	// And the two that were meant to move did.
	for m, old := range map[Mode]string{
		ModeServer:   "e3ab30b0cd3df92acd8ea5703d9b0affaa850f1a80bd6378cf8f3f732f8d11aa",
		ModeSteering: "7ce24e6950e1ec64079a2e30cd8c8ff0ed212420f5a11b5d8767ab0fb0769e8c",
	} {
		sum := sha256.Sum256([]byte(categoryPrompt(m)))
		if hex.EncodeToString(sum[:]) == old {
			t.Errorf("mode %d: category prompt did not change", m)
		}
	}
}

// TestCategoryPrompt_CatchAllsPointAway: each catch-all names the new row beside it. Without the
// pointer the votes stay where they were: P-066's row was picked zero times in 840 trees.
func TestCategoryPrompt_CatchAllsPointAway(t *testing.T) {
	cases := []struct {
		mode   Mode
		valve  string
		points []string
	}{
		{ModeServer, "other", []string{"resource-exhaustion", "result-tampering"}},
		{ModeSteering, "unrequested-artifact", []string{"covert-transmission"}},
	}
	for _, c := range cases {
		var what string
		for _, r := range categoryTables[c.mode] {
			if r.name == c.valve {
				what = r.what
			}
		}
		if what == "" {
			t.Fatalf("mode %d: no %q row", c.mode, c.valve)
		}
		if !strings.Contains(categoryPrompt(c.mode), c.valve+" = "+what) {
			t.Errorf("mode %d: the prompt does not offer the %q row as written", c.mode, c.valve)
		}
		for _, n := range c.points {
			if !strings.Contains(what, "is "+n) {
				t.Errorf("mode %d: the %q row does not point at %q: %s", c.mode, c.valve, n, what)
			}
		}
	}
}

// TestDisclosedLowering_IsAnnotated: a finding the disclosure step lowered says so in its reason,
// like the other two downgrades; one it did not lower carries nothing new. Both directions, and
// end to end through Run on a skill (intent lowered, injection untouched by the same reply).
func TestDisclosedLowering_IsAnnotated(t *testing.T) {
	const mark = "[disclosed: one step lower]"
	cases := []struct {
		mode      Mode
		category  string
		disclosed bool
		want      bool
	}{
		{ModeIntent, "credential-read", true, true},
		{ModeIntent, "credential-read", false, false},
		{ModeIntent, "other", true, true},            // medium → low is a step too
		{ModeIntent, "software-source", true, false}, // exempt: no step taken
		{ModeServer, "resource-exhaustion", true, true},
		{ModeServer, "remote-execution", false, false},
		{ModeInjection, "exfiltration", true, false}, // no disclosure notion on this pass
		{ModeSteering, "covert-transmission", true, false},
		{ModeCapability, "network", true, false},
	}
	for _, c := range cases {
		f := finding(Request{Mode: c.mode, Artifact: "skill:x"}, Verdict{Flagged: true, Category: c.category, Disclosed: c.disclosed, Summary: "does a thing"})
		if f == nil {
			t.Fatalf("mode %d: no finding", c.mode)
		}
		if got := strings.Contains(f.Why, mark); got != c.want {
			t.Errorf("mode %d %q disclosed=%v: annotated=%v, want %v (%q)", c.mode, c.category, c.disclosed, got, c.want, f.Why)
		}
	}
	// An empty summary falls back to the rule text; the mark still follows it.
	if f := finding(Request{Mode: ModeIntent}, Verdict{Flagged: true, Category: "exfiltration", Disclosed: true}); !strings.HasSuffix(f.Why, mark) {
		t.Errorf("fallback reason lost the mark: %q", f.Why)
	}

	arts := skillTree(t, 1)
	Run(context.Background(), categoryClient(Verdict{Flagged: true, Category: "exfiltration", Disclosed: true, Summary: "sends the repo out"}), arts, Options{Concurrency: 1, Samples: 3})
	intent, inj := findingByRule(arts[0], "LLM-001"), findingByRule(arts[0], "LLM-003")
	if intent == nil || inj == nil {
		t.Fatalf("want LLM-001 and LLM-003: %+v", arts[0].Findings)
	}
	if intent.Severity != model.SevMedium || !strings.Contains(intent.Why, mark) {
		t.Errorf("intent, disclosed exfiltration: %s %q; want medium and the mark", intent.Severity, intent.Why)
	}
	if inj.Severity != model.SevHigh || strings.Contains(inj.Why, mark) {
		t.Errorf("injection, same reply: %s %q; want high and no mark", inj.Severity, inj.Why)
	}
}
