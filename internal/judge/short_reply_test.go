// SPDX-License-Identifier: MIT
package judge

import (
	"strings"
	"testing"
)

// TestBarrierRule_ShortReplies (P-110): every judge question's system message ends with the short-reply rule — the
// two-member reply when nothing is flagged and nothing addresses the analyzer, one line of evidence when something
// is — and triage's system message does not carry it.
func TestBarrierRule_ShortReplies(t *testing.T) {
	nonce := strings.Repeat("ab", 16)
	for m := ModeIntent; m <= ModeSteering; m++ {
		sys := systemPromptFor(Request{Mode: m}, nonce)
		if !strings.HasSuffix(sys, " "+barrierRule(nonce)+" "+shortReplyRule) {
			t.Errorf("%s: the system message does not end with the barrier rule and then the short-reply rule", modeInfo(m).pass)
		}
		if re := systemPromptFor(Request{Mode: m, Reask: true}, nonce); !strings.HasSuffix(re, shortReplyRule+" "+reaskRule) {
			t.Errorf("%s: a re-ask lost the short-reply rule before its format rule", modeInfo(m).pass)
		}
	}
	for _, want := range []string{`{"flagged": false, "barrier_evidence": ""}`, "single line", "two consecutive lines at most"} {
		if !strings.Contains(shortReplyRule, want) {
			t.Errorf("the short-reply rule does not say %q", want)
		}
	}
	if strings.Contains(triageSystem(nonce), shortReplyRule) {
		t.Error("triage's system message carries the short-reply rule; its reply is labels")
	}
}

// TestParseVerdict_ShortForm (P-110): the short form reads as not flagged, with no barrier.
func TestParseVerdict_ShortForm(t *testing.T) {
	v, err := parseVerdict(`{"flagged": false, "barrier_evidence": ""}`)
	if err != nil || v.Flagged || v.BarrierEvidence != "" || v.Evidence != "" {
		t.Fatalf("short form read as %+v (%v)", v, err)
	}
}
