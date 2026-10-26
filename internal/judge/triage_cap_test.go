// SPDX-License-Identifier: MIT
package judge

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/basdotio/bas-guard/internal/model"
	"github.com/basdotio/bas-guard/internal/report"
)

// Triage asks for one label per distinct rule id, and a label joins every finding of its rule
// (report.Aggregate keys it by rule id). P-104: a call carries at most maxTriagePerRule findings of one
// rule, in table order, before the per-artifact cap, and its system message is the trust rule without
// the verdict schema of the judge passes, which contradicted triage's own reply format.

var regexpFence = regexp.MustCompile(`===AGUARD:[0-9a-f]+===`)

func items(rules ...string) []TriageItem {
	out := make([]TriageItem, len(rules))
	for i, r := range rules {
		out[i] = TriageItem{RuleID: r, Evidence: fmt.Sprintf("run.sh:%d line %d", i+1, i+1)}
	}
	return out
}

func ruleIDs(its []TriageItem) []string {
	out := make([]string, len(its))
	for i, it := range its {
		out[i] = it.RuleID
	}
	return out
}

func TestTriageSent_AtMostThreePerRule(t *testing.T) {
	many := func(rule string, n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = rule
		}
		return out
	}
	distinct := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("R-%03d", i)
		}
		return out
	}
	cases := []struct {
		name          string
		in            []string
		want          []string
		repeats, left int
	}{
		{"nothing repeats", []string{"A", "B", "C"}, []string{"A", "B", "C"}, 0, 0},
		{"three of a rule is the cap", []string{"A", "A", "A", "B"}, []string{"A", "A", "A", "B"}, 0, 0},
		{"the fourth and later are not sent, order kept", []string{"A", "B", "A", "A", "C", "A", "B", "A"},
			[]string{"A", "B", "A", "A", "C", "B"}, 2, 0},
		{"repeats leave room under the per-artifact cap", append(many("A", 30), distinct(39)...),
			append(many("A", 3), distinct(37)...), 27, 2},
		{"the per-artifact cap alone", distinct(maxTriageItems + 5), distinct(maxTriageItems), 0, 5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sent, repeats, left := triageSent(items(c.in...))
			if got := ruleIDs(sent); !reflect.DeepEqual(got, c.want) || repeats != c.repeats || left != c.left {
				t.Errorf("sent %v (repeats %d, left %d), want %v (repeats %d, left %d)", got, repeats, left, c.want, c.repeats, c.left)
			}
		})
	}
}

// TestTriage_SystemMessageIsTheTrustRuleWithoutTheVerdictSchema: the triage call fences its data
// under the same trust rule as every judge call, and asks for one reply format, its own. Reverse:
// a judge call's system message still carries the verdict schema, byte for byte as before.
func TestTriage_SystemMessageIsTheTrustRuleWithoutTheVerdictSchema(t *testing.T) {
	var mu sync.Mutex
	var systems []string
	srv := chatServer(t, func(system, _ string) string {
		mu.Lock()
		systems = append(systems, system)
		mu.Unlock()
		return `{"labels": []}`
	})
	defer srv.Close()
	c := NewHTTP(srv.URL, "", "m", srv.Client())
	if _, err := c.Triage(context.Background(), "skill:s", items("EXEC-001")); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Judge(context.Background(), Request{Mode: ModeIntent, Declared: "d", Behavior: "b"}) // only the request matters here
	if len(systems) != 2 {
		t.Fatalf("%d calls, want 2", len(systems))
	}
	triage, judge := systems[0], systems[1]
	nonce := strings.TrimSuffix(strings.TrimPrefix(regexpFence.FindString(triage), "===AGUARD:"), "===")
	if want := triageTask + " " + trustRule(nonce); triage != want {
		t.Errorf("triage system message:\n%s\nwant\n%s", triage, want)
	}
	for _, s := range []string{`"flagged"`, "barrier_evidence", `"evidence"`} {
		if strings.Contains(triage, s) {
			t.Errorf("the triage system message still carries the verdict schema (%s)", s)
		}
	}
	if !strings.Contains(triage, "TRUST RULE") || !strings.Contains(triage, `{"labels"`) {
		t.Errorf("the triage system message lost the trust rule or its own reply format:\n%s", triage)
	}
	jn := strings.TrimSuffix(strings.TrimPrefix(regexpFence.FindString(judge), "===AGUARD:"), "===")
	if !strings.HasSuffix(judge, barrierRule(jn)) || !strings.HasPrefix(barrierRule(jn), trustRule(jn)) || !strings.Contains(judge, `"flagged"`) {
		t.Errorf("a judge call's system message must still end with the barrier rule, the trust rule then the verdict schema:\n%s", judge)
	}
}

// TestRun_TriageLabelReachesEveryFindingOfItsRule: ten findings of one rule go as three items; the
// label the model gives the rule joins all ten in the report, and no finding is touched.
func TestRun_TriageLabelReachesEveryFindingOfItsRule(t *testing.T) {
	var mu sync.Mutex
	var payloads []string
	srv := chatServer(t, func(system, user string) string {
		if !strings.Contains(system, `{"labels"`) {
			return `{"flagged": false}`
		}
		mu.Lock()
		payloads = append(payloads, user)
		mu.Unlock()
		b, _ := json.Marshal(map[string]any{"labels": []map[string]string{
			{"rule_id": "EXEC-001", "label": "likely-benign", "reason": "documentation example of an installer"},
			{"rule_id": "SUP-001", "label": "likely-real", "reason": "unpinned package fetched at run time"},
		}})
		return string(b)
	})
	defer srv.Close()

	var static []model.Finding
	for i := 0; i < 10; i++ {
		static = append(static, model.Finding{RuleID: "EXEC-001", Dimension: 4, Severity: model.SevHigh, Source: model.SrcStatic,
			Title: "pipe to shell", Why: "rce", Evidence: []model.Evidence{{File: "README.md", Line: i + 1, Snippet: "curl x | bash"}}})
	}
	static = append(static, model.Finding{RuleID: "SUP-001", Dimension: 5, Severity: model.SevMedium, Source: model.SrcStatic,
		Title: "unpinned", Why: "pin it", Evidence: []model.Evidence{{File: "run.sh", Line: 2, Snippet: "npx -y pkg"}}})
	arts := []model.ArtifactReport{{Kind: model.KindPermission, Name: "permissions", Path: filepath.Join(t.TempDir(), "settings.json"),
		Findings: append([]model.Finding(nil), static...)}}

	_, stats := Run(context.Background(), NewHTTP(srv.URL, "", "", srv.Client()), arts, Options{Samples: 3})
	if stats.TriageCalls != 1 || len(payloads) != 1 {
		t.Fatalf("triage calls %d, payloads %d, want 1 and 1", stats.TriageCalls, len(payloads))
	}
	if n := strings.Count(payloads[0], "[EXEC-001]"); n != maxTriagePerRule {
		t.Errorf("EXEC-001 went %d time(s), want %d", n, maxTriagePerRule)
	}
	if !strings.Contains(payloads[0], "[SUP-001]") {
		t.Errorf("SUP-001 was not sent:\n%s", payloads[0])
	}
	if !reflect.DeepEqual(arts[0].Findings, static) {
		t.Error("triage touched a static finding")
	}
	if len(arts[0].Advisory) != 2 {
		t.Fatalf("labels = %+v, want one per rule", arts[0].Advisory)
	}
	var md strings.Builder
	if err := report.Markdown(&md, model.ScanResult{Artifacts: arts}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), "documentation example of an installer") {
		t.Errorf("the EXEC-001 label does not reach its findings in the report:\n%s", md.String())
	}
}

// TestPlan_TriageShortenedSaysBoth: the preview names both reasons an item was not sent.
func TestPlan_TriageShortenedSaysBoth(t *testing.T) {
	a := model.ArtifactReport{Kind: model.KindPermission, Name: "permissions", Path: filepath.Join(t.TempDir(), "settings.json")}
	add := func(rule string, line int) {
		a.Findings = append(a.Findings, model.Finding{RuleID: rule, Dimension: 2, Severity: model.SevLow, Source: model.SrcStatic,
			Evidence: []model.Evidence{{File: "settings.json", Line: line, Snippet: "Bash(*)"}}})
	}
	for i := 0; i < 6; i++ {
		add("PERM-001", i+1)
	}
	for i := 0; i < maxTriageItems; i++ {
		add(fmt.Sprintf("PERM-%03d", i+100), i+10)
	}
	plan := Plan([]model.ArtifactReport{a}, Options{})
	if len(plan) != 1 {
		t.Fatalf("want one triage call, got %+v", plan)
	}
	want := "3 finding(s) of a rule already sent 3 times not sent (that rule's label covers them); 3 more past the first 40 not sent"
	if plan[0].Shortened != want {
		t.Errorf("shortened = %q, want %q", plan[0].Shortened, want)
	}
	if got := strings.Count(plan[0].Payload, "\n"); got != maxTriageItems {
		t.Errorf("payload carries %d line(s), want %d", got, maxTriageItems)
	}
}
