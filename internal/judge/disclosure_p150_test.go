// SPDX-License-Identifier: MIT
package judge

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/basdotio/bas-guard/internal/model"
)

// P-150: the server pass asks for `disclosed` and no longer weighs it. These tests pin that every
// server row keeps its weight when the field is set, that the reason carries a text mark instead,
// that the two credential-read downgrades are untouched, and the three vote shapes the stored
// runs were replayed under — so the replay's rules and the code's are the same rules. The intent
// pass keeps the step: TestSeverity_IntentDisclosedIsOneStepLower is the reverse assertion.

// TestSeverityFor_ServerTakesNoDisclosureStep: every row of the server table weighs the same with
// the field set, `other` and an unknown name are medium and never low.
func TestSeverityFor_ServerTakesNoDisclosureStep(t *testing.T) {
	for _, r := range categoryTables[ModeServer] {
		got := severityFor(ModeServer, Verdict{Flagged: true, Category: r.name, Disclosed: true})
		if got != r.sev {
			t.Errorf("server %q disclosed: got %s, want the row's %s", r.name, got, r.sev)
		}
		if disclosureLowered(ModeServer, Verdict{Flagged: true, Category: r.name, Disclosed: true}) {
			t.Errorf("server %q: disclosureLowered says the step was taken", r.name)
		}
	}
	for _, name := range []string{"other", "denial-of-service", ""} {
		if got := severityFor(ModeServer, Verdict{Flagged: true, Category: name, Disclosed: true}); got != model.SevMedium {
			t.Errorf("server %q disclosed: got %s, want medium", name, got)
		}
	}
	// Reverse: the same rows on the intent pass still go one step down.
	if got := severityFor(ModeIntent, Verdict{Flagged: true, Category: "credential-read", Disclosed: true}); got != model.SevMedium {
		t.Errorf("intent credential-read disclosed: got %s, want medium", got)
	}
	if got := severityFor(ModeIntent, Verdict{Flagged: true, Category: "other", Disclosed: true}); got != model.SevLow {
		t.Errorf("intent other disclosed: got %s, want low", got)
	}
}

// TestServerDisclosed_IsMarkedNotLowered: a server finding whose vote set the field says
// `[disclosed]` and never `[disclosed: one step lower]`; one that did not set it says neither; an
// intent finding is annotated exactly as before.
func TestServerDisclosed_IsMarkedNotLowered(t *testing.T) {
	const lowered = "[disclosed: one step lower]"
	for _, c := range []struct {
		mode        Mode
		category    string
		disclosed   bool
		mark, lower bool
	}{
		{ModeServer, "privilege", true, true, false},
		{ModeServer, "other", true, true, false},
		{ModeServer, "privilege", false, false, false},
		{ModeIntent, "privilege", true, false, true},
		{ModeIntent, "software-source", true, false, false}, // exempt on the intent pass, and no new mark there
		{ModeInjection, "exfiltration", true, false, false},
	} {
		f := finding(Request{Mode: c.mode, Artifact: "server:x"}, Verdict{Flagged: true, Category: c.category, Disclosed: c.disclosed, Summary: "does a thing"})
		if f == nil {
			t.Fatalf("mode %d: no finding", c.mode)
		}
		if got := strings.Contains(f.Why, strings.TrimSpace(disclosedMark)); got != c.mark {
			t.Errorf("mode %d %q disclosed=%v: [disclosed] present=%v, want %v (%q)", c.mode, c.category, c.disclosed, got, c.mark, f.Why)
		}
		if got := strings.Contains(f.Why, lowered); got != c.lower {
			t.Errorf("mode %d %q disclosed=%v: lowered mark present=%v, want %v (%q)", c.mode, c.category, c.disclosed, got, c.lower, f.Why)
		}
	}
}

// TestTally_ServerDisclosedVotes: the vote shapes the stored runs were replayed under. A finding
// takes the severity of the first vote in the majority category, or the lowest among the votes
// when no category has one; with the step gone a vote that set the field weighs its row.
func TestTally_ServerDisclosedVotes(t *testing.T) {
	vote := func(category string, disclosed bool) Verdict {
		return Verdict{Flagged: true, Category: category, Disclosed: disclosed, Severity: "high", Summary: "does a thing"}
	}
	for _, c := range []struct {
		name  string
		votes []Verdict
		want  model.Severity
	}{
		{"the first vote decides", []Verdict{vote("privilege", true), vote("privilege", true), vote("privilege", false)}, model.SevHigh},
		{"a later vote decides", []Verdict{vote("other", false), vote("privilege", true), vote("privilege", true)}, model.SevHigh},
		{"no majority, every vote in a high row", []Verdict{vote("privilege", true), vote("exfiltration", true), vote("file-deletion", false)}, model.SevHigh},
		{"no majority, one vote in the catch-all", []Verdict{vote("privilege", true), vote("other", false), vote("exfiltration", false)}, model.SevMedium},
		{"the majority is the catch-all", []Verdict{vote("other", true), vote("other", true), vote("privilege", false)}, model.SevMedium},
	} {
		var votes []model.Finding
		var words []model.Severity
		var cats []string
		for _, v := range c.votes {
			votes = append(votes, *finding(Request{Mode: ModeServer, Artifact: "server:x"}, v))
			words = append(words, clampSeverity(v.Severity))
			cats = append(cats, categoryName(v))
		}
		f := tally(votes, words, cats, 3)
		if f.Severity != c.want || !f.Escalates {
			t.Errorf("%s: %s escalates=%v, want %s and escalating (%s)", c.name, f.Severity, f.Escalates, c.want, f.Why)
		}
	}
}

// TestRun_ServerCredentialReadDowngradesHoldWhenDisclosed: the two credential-read downgrades
// (own service, P-062; own configuration, P-098) are separate from the disclosure step and still
// lower a vote, with the field set or not; the reason still names which one. A file that reaches
// past its own configuration stays high either way.
func TestRun_ServerCredentialReadDowngradesHoldWhenDisclosed(t *testing.T) {
	head := "from mcp.server.fastmcp import FastMCP\nimport os, requests\nmcp = FastMCP(\"svc\")\n"
	ownService := head + "KEY = os.environ[\"WEATHER_API_KEY\"]\n\n@mcp.tool()\ndef forecast(city: str) -> str:\n    \"\"\"Return the forecast for a city.\"\"\"\n    r = requests.get(\"https://api.weather.com/v1/forecast\", params={\"q\": city}, headers={\"Authorization\": KEY})\n    return r.text\n"
	ownConfig := head + "\n@mcp.tool()\ndef run(q: str) -> str:\n    \"\"\"Run a query.\"\"\"\n    client = Client(os.getenv(\"ACME_API_KEY\"))\n    return client.query(q)\n"
	reaches := head + "\n@mcp.tool()\ndef run(q: str) -> str:\n    \"\"\"Run a query.\"\"\"\n    with open(\"/etc/passwd\") as f:\n        return f.read()\n"
	for _, c := range []struct {
		name, body, note string
		want             model.Severity
	}{
		{"own service", ownService, "the credential's own service", model.SevMedium},
		{"own configuration", ownConfig, "only the server's own configuration", model.SevMedium},
		{"past its own configuration", reaches, "", model.SevHigh},
	} {
		for _, disclosed := range []bool{false, true} {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "server.py"), c.body)
			arts := []model.ArtifactReport{{Kind: model.KindServer, Name: "svc", Path: dir, Findings: []model.Finding{}}}
			Run(context.Background(), categoryClient(Verdict{Flagged: true, Severity: "high", Category: "credential-read", Disclosed: disclosed, Summary: "reads a credential"}), arts, Options{Concurrency: 1})
			f := findingByRule(arts[0], "LLM-010")
			if f == nil {
				t.Fatalf("%s, disclosed=%v: no LLM-010: %+v", c.name, disclosed, arts[0].Findings)
			}
			if f.Severity != c.want {
				t.Errorf("%s, disclosed=%v: %s, want %s (%s)", c.name, disclosed, f.Severity, c.want, f.Why)
			}
			if c.note != "" && !strings.Contains(f.Why, c.note) {
				t.Errorf("%s, disclosed=%v: the reason lost its downgrade note: %s", c.name, disclosed, f.Why)
			}
			if got := strings.Contains(f.Why, strings.TrimSpace(disclosedMark)); got != disclosed {
				t.Errorf("%s, disclosed=%v: [disclosed] present=%v: %s", c.name, disclosed, got, f.Why)
			}
		}
	}
}
