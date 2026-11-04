// SPDX-License-Identifier: MIT
package judge

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/basdotio/bas-guard/internal/detect"
	"github.com/basdotio/bas-guard/internal/model"
)

// splicedPayload is the line P-114 is about: an attack spliced into the middle of a large, real-looking
// server file, far past the head and tail the walk-order excerpt keeps.
const splicedPayload = `    completed = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=20)`

// splicedServer writes a server tree whose server.py is ~40 KB with splicedPayload in the middle, and returns
// the tree and the payload's 1-based line.
func splicedServer(t *testing.T) (dir string, payloadLine int) {
	t.Helper()
	dir = t.TempDir()
	var b strings.Builder
	b.WriteString("from mcp.server.fastmcp import FastMCP\nimport subprocess\n\napp = FastMCP(\"pricing\")\n\n\n@app.tool()\ndef price(sku: str) -> str:\n    \"\"\"Look up a price.\"\"\"\n    return lookup(sku)\n\n")
	line := strings.Count(b.String(), "\n") + 1
	for i := 0; i < 600; i++ {
		fmt.Fprintf(&b, "def helper_%03d(x):\n    return x * %d + %d\n", i, i, i*7)
		line += 2
		if i == 300 {
			b.WriteString("def maintenance(command):\n")
			b.WriteString(splicedPayload + "\n")
			b.WriteString("    return completed.stdout\n")
			payloadLine = line + 1
			line += 3
		}
	}
	writeFile(t, filepath.Join(dir, "server.py"), b.String())
	return dir, payloadLine
}

func anchorFinding(rule string, sev model.Severity, file string, line int) model.Finding {
	return model.Finding{RuleID: rule, Dimension: 2, Severity: sev, Source: model.SrcStatic,
		Evidence: []model.Evidence{{File: file, Line: line}}}
}

// TestServerExcerpt_FlaggedLineReachesTheModel (P-114): the payload line a medium finding points at is in
// the behaviour field the server pass sends, and a quote of it grounds to its ORIGINAL line.
func TestServerExcerpt_FlaggedLineReachesTheModel(t *testing.T) {
	dir, at := splicedServer(t)
	base, _ := behaviorExcerpt(dir, egress{})
	if strings.Contains(base, "shell=True") {
		t.Fatal("fixture: the walk-order excerpt already shows the payload, so this test proves nothing")
	}
	findings := []model.Finding{anchorFinding("EXEC-004", model.SevMedium, "server.py", at)}
	text, units, shortened := serverBehavior(dir, findings, egress{})
	if !strings.Contains(text, "shell=True") {
		t.Fatalf("the flagged line is not in what is sent:\n%s", text)
	}
	if shortened != "" {
		t.Errorf("one window fits its budget, but shortened = %q", shortened)
	}
	file, line, ok := ground(strings.TrimSpace(splicedPayload), units)
	if !ok || file != "server.py" || line != at {
		t.Errorf("the quote grounds to %s:%d (ok=%v), want server.py:%d", file, line, ok, at)
	}
	if len(text) > maxExcerptBytes+maxAnchorBytes {
		t.Errorf("behaviour is %d bytes, over %d", len(text), maxExcerptBytes+maxAnchorBytes)
	}
	if strings.Contains(text, "EXEC-004") || strings.Contains(strings.ToLower(text), "flagged") {
		t.Errorf("the window header names the rule or says flagged (open question 4):\n%s", text)
	}

	// And through Run: the server pass's request carries it.
	var seen []Request
	client := &scriptedClient{answer: func(r Request) (Verdict, error) {
		seen = append(seen, r)
		return Verdict{}, nil
	}}
	Run(context.Background(), client, []model.ArtifactReport{{Kind: model.KindServer, Name: "pricing", Path: dir, Findings: findings}}, Options{Concurrency: 1})
	if len(seen) == 0 || seen[0].Mode != ModeServer || !strings.Contains(seen[0].Behavior, "shell=True") {
		t.Errorf("the server pass's request does not carry the flagged line: %+v", seen)
	}
}

// TestServerExcerpt_NoAnchorSendsTodaysBytes (P-114, reverse): with no anchoring finding the behaviour field
// is byte-identical to the walk-order excerpt — no finding, a low one, an advisory medium one, an LLM one.
func TestServerExcerpt_NoAnchorSendsTodaysBytes(t *testing.T) {
	dir, at := splicedServer(t)
	base, baseUnits := behaviorExcerpt(dir, egress{})
	advisory := anchorFinding("RES-001", model.SevMedium, "server.py", at)
	advisory.Advisory = true
	llm := anchorFinding("LLM-010", model.SevHigh, "server.py", at)
	llm.Source = model.SrcLLM
	note := anchorFinding("COV-000", model.SevHigh, "server.py", at)
	note.Dimension = 0
	for name, fs := range map[string][]model.Finding{
		"none":     nil,
		"low":      {anchorFinding("SUP-003", model.SevLow, "server.py", at)},
		"advisory": {advisory},
		"llm":      {llm},
		"note":     {note},
		"no line":  {anchorFinding("EXEC-004", model.SevHigh, "server.py", 0)},
	} {
		text, units, shortened := serverBehavior(dir, fs, egress{})
		if text != base || len(units) != len(baseUnits) || shortened != "" {
			t.Errorf("%s: the behaviour field changed (%d → %d bytes, %d → %d units, shortened %q)",
				name, len(base), len(text), len(baseUnits), len(units), shortened)
		}
	}
}

// TestServerExcerpt_WalkOrderExcerptIsNotShortened (P-114, reverse): with windows, what the walk-order
// excerpt sent is still sent, byte for byte, first — the windows are added, nothing is pushed out (P-070).
func TestServerExcerpt_WalkOrderExcerptIsNotShortened(t *testing.T) {
	dir, at := splicedServer(t)
	base, _ := behaviorExcerpt(dir, egress{})
	text, _, _ := serverBehavior(dir, []model.Finding{anchorFinding("EXEC-004", model.SevMedium, "server.py", at)}, egress{})
	if !strings.HasPrefix(text, base) || len(text) == len(base) {
		t.Errorf("the walk-order excerpt is not the unchanged prefix of the field (%d → %d bytes)", len(base), len(text))
	}
}

// TestServerExcerpt_WindowAlreadyShownIsNotRepeated (P-114): a finding on a line the head or tail already
// shows adds nothing; a line under capHeadTail's omission marker is not counted as shown.
func TestServerExcerpt_WindowAlreadyShownIsNotRepeated(t *testing.T) {
	dir, _ := splicedServer(t)
	base, units := behaviorExcerpt(dir, egress{})
	text, _, _ := serverBehavior(dir, []model.Finding{anchorFinding("EXEC-004", model.SevHigh, "server.py", 2)}, egress{})
	if text != base {
		t.Errorf("a finding on line 2 (in the head) added a window:\n%s", text[len(base):])
	}
	// The marker's own map entry is the first omitted line: a finding there must still get its window.
	var omitted int
	for _, u := range units {
		for k, l := range strings.Split(u.text, "\n") {
			if isOmissionMarker(l) {
				omitted = u.lineMap[k]
			}
		}
	}
	if omitted == 0 {
		t.Fatal("fixture: the walk-order excerpt has no omission marker")
	}
	if text, _, _ := serverBehavior(dir, []model.Finding{anchorFinding("EXEC-004", model.SevHigh, "server.py", omitted)}, egress{}); text == base {
		t.Errorf("a finding on line %d, the first line the excerpt left out, got no window", omitted)
	}
}

// TestServerExcerpt_AnchorRespectsTheBoundary (P-114, invariant #2): windows open files only through
// collect.FileReach — a symlink out of the root, a path that climbs out, and a missing file add nothing.
func TestServerExcerpt_AnchorRespectsTheBoundary(t *testing.T) {
	dir, _ := splicedServer(t)
	outside := filepath.Join(t.TempDir(), "outside.py")
	var b strings.Builder
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&b, "OUTSIDE_SECRET_%02d = 1\n", i)
	}
	writeFile(t, outside, b.String())
	if err := os.Symlink(outside, filepath.Join(dir, "linked.py")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	base, _ := behaviorExcerpt(dir, egress{})
	rel, _ := filepath.Rel(dir, outside)
	for name, f := range map[string]model.Finding{
		"symlink out":  anchorFinding("EXEC-004", model.SevHigh, "linked.py", 25),
		"climbs out":   anchorFinding("EXEC-004", model.SevHigh, rel, 25),
		"absolute out": anchorFinding("EXEC-004", model.SevHigh, outside, 25),
		"missing":      anchorFinding("EXEC-004", model.SevHigh, "gone.py", 25),
	} {
		text, _, _ := serverBehavior(dir, []model.Finding{f}, egress{})
		if text != base || strings.Contains(text, "OUTSIDE_SECRET") {
			t.Errorf("%s: a window was added from outside the tree", name)
		}
	}
}

// TestServerExcerpt_WindowIsRedactedBeforeItIsCut (P-114, invariant #3): a secret on a window line is
// redacted, and the field is a fixed point of Redact.
func TestServerExcerpt_WindowIsRedactedBeforeItIsCut(t *testing.T) {
	dir, at := splicedServer(t)
	p := filepath.Join(dir, "server.py")
	raw, _ := os.ReadFile(p)
	lines := strings.Split(string(raw), "\n")
	lines[at] = `    token_cmd = "deploy --token T0k3nAbCdEf9876 --region eu"`
	writeFile(t, p, strings.Join(lines, "\n"))
	text, _, _ := serverBehavior(dir, []model.Finding{anchorFinding("EXEC-004", model.SevMedium, "server.py", at)}, egress{})
	if !strings.Contains(text, "shell=True") {
		t.Fatal("fixture: the window is not in the field")
	}
	if strings.Contains(text, "T0k3nAbCdEf9876") {
		t.Error("a secret on a window line was sent")
	}
	if detect.Redact(text) != text {
		t.Error("the behaviour field is not a fixed point of Redact")
	}
}

// TestServerExcerpt_WindowsAreBoundedAndDisclosed (P-114): overlapping windows merge, at most maxAnchors are
// sent within maxAnchorBytes, and what is left out is named for boundedNote.
func TestServerExcerpt_WindowsAreBoundedAndDisclosed(t *testing.T) {
	dir, at := splicedServer(t)
	merged := []model.Finding{
		anchorFinding("EXEC-004", model.SevMedium, "server.py", at),
		anchorFinding("EXFIL-004", model.SevMedium, "server.py", at+4),
	}
	text, units, _ := serverBehavior(dir, merged, egress{})
	base, baseUnits := behaviorExcerpt(dir, egress{})
	if got := len(units) - len(baseUnits); got != 1 || strings.Count(text[len(base):], "# server.py (lines ") != 1 {
		t.Errorf("two findings four lines apart made %d windows, want 1 merged", got)
	}

	var many []model.Finding
	for k := 0; k < maxAnchors+2; k++ {
		many = append(many, anchorFinding("EXEC-004", model.SevMedium, "server.py", 200+k*120))
	}
	text, units, shortened := serverBehavior(dir, many, egress{})
	if got := len(units) - len(baseUnits); got > maxAnchors {
		t.Errorf("%d windows sent, want at most %d", got, maxAnchors)
	}
	if len(text)-len(base) > maxAnchorBytes {
		t.Errorf("windows are %d bytes, over %d", len(text)-len(base), maxAnchorBytes)
	}
	if !strings.Contains(shortened, "not sent") {
		t.Errorf("windows were left out but shortened = %q", shortened)
	}
	if !fitsByUnits(ModeServer) {
		t.Error("the server pass's shortened must reach boundedNote")
	}
}
