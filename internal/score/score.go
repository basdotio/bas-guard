// SPDX-License-Identifier: MIT
// Package score computes BAS Guard's risk score (spec §5.3). It produces TWO numbers from
// one formula, run over two different sets of findings:
//
//   - Overall          — deterministic sources only (static / permission / hygiene). The same
//     environment always scores the same, which is what makes it usable for --fail-on and for
//     an on-chain attestation a third party can recompute offline.
//   - OverallEffective — the same formula with qualified LLM findings folded in. This is the
//     number for a human and for CI to look at; it is NOT reproducible and never gates.
//
// The split exists because the two properties are irreconcilable: an LLM verdict is useful
// precisely because it sees things a regex can't, and useless as a stable identity because it
// is probabilistic. Rather than trade one for the other, they get a number each.
package score

import "github.com/basdotio/bas-guard/internal/model"

// Penalty weights (spec appendix A). Within a dimension only the max hit counts;
// across dimensions penalties add; final score is clamped to [0,100].
var penalty = map[model.Severity]int{
	model.SevCritical: 40,
	model.SevHigh:     25,
	model.SevMedium:   12,
	model.SevLow:      5,
}

// Level names for a score band (spec §5.3). Both numbers share one band table.
func Level(score int) string {
	switch {
	case score >= 85:
		return "Low"
	case score >= 70:
		return "Watch"
	case score >= 50:
		return "Elevated"
	default:
		return "High"
	}
}

// filter decides whether a finding feeds a score.
//
// Scoring and gating must agree about which findings count, and the two live in different
// packages. Keeping a copy in each would create the drift that fails silently in both
// directions — a gate that starts reacting to LLM output, or an escalation that quietly never
// fires, neither of which surfaces as a test failure on its own. So there is exactly ONE
// definition of each predicate, exported, and the report layer calls these rather than
// restating them.
type filter func(model.Finding) bool

// Deterministic reports whether a finding may touch the reproducible score and --fail-on: not
// LLM-sourced, and not a dimension-0 note (those describe the scan, not the artifact).
func Deterministic(f model.Finding) bool {
	return f.Source != model.SrcLLM && f.Dimension != 0
}

// Escalating: deterministic findings PLUS qualified LLM ones.
//
// Qualification is decided upstream and carried on the finding (Finding.Escalates): the judge
// sets it only after the evidence was located in what was actually sent AND enough independent
// samples agreed. An LLM finding that failed either bar still appears in the report — it is a
// lead, just not a weighted one — so this filter reads the flag rather than re-deriving it.
// Tier authorisation joins the bar in a later step; until then the number this produces is
// DISPLAY-ONLY and gates nothing (spec §5.2.1).
func Escalating(f model.Finding) bool {
	if f.Dimension == 0 {
		return false
	}
	return f.Source != model.SrcLLM || f.Escalates
}

// unconfirmedRules is the closed set of rules whose high finding the judge may rule on (P-142).
// They are the rules whose own text says "a suspicious-surface flag, not confirmed" and that fire on
// more benign samples than malicious ones (EXFIL-001: 214 and 65 of the corpus; EXFIL-003: 46 and
// 21). It is code, not configuration and not something a reply can name: adding a rule is a proposal
// with its own measurement, because every rule here is one whose finding a model's answer can take
// out of the judged score.
var unconfirmedRules = map[string]bool{"EXFIL-001": true, "EXFIL-003": true}

// Unconfirmed reports whether f is a finding the judge may rule on: deterministic, at high, of a
// rule in the closed set. The judge asks its destination question only about these, and Judged
// honours a ruling only on these.
func Unconfirmed(f model.Finding) bool {
	return Deterministic(f) && f.Severity == model.SevHigh && unconfirmedRules[f.RuleID]
}

// Cleared reports whether the judge's ruling takes f out of the judged score: f is Unconfirmed and
// carries a ruling that met every bar (Ruling.Clears). The rule is checked here as well as where the
// ruling is written, so a ruling that reached any other finding by any route changes nothing.
func Cleared(f model.Finding) bool {
	return f.Ruling != nil && f.Ruling.Clears && f.Ruling.Answer == model.RulingOwnService && Unconfirmed(f)
}

// Judged is what counts in the EFFECTIVE score and --fail-on-llm (P-142): Escalating, less the
// findings the judge cleared. With no ruling present it is Escalating, finding for finding.
func Judged(f model.Finding) bool { return Escalating(f) && !Cleared(f) }

// uncleared is Deterministic less the cleared findings: the ceiling the effective score keeps. It
// feeds no score of its own and no gate; --fail-on and Overall read Deterministic.
func uncleared(f model.Finding) bool { return Deterministic(f) && !Cleared(f) }

// artifactScore = clamp(100 − Σ_dimension max(severity penalty), 0, 100). Advisory static
// findings (dim 7/8) DO score, at their (low) severity.
func artifactScore(a model.ArtifactReport, keep filter) int { return findingsScore(a.Findings, keep) }

// findingsScore is the per-artifact formula over any set of findings — an artifact's, or a unit's.
func findingsScore(fs []model.Finding, keep filter) int {
	maxByDim := map[int]int{}
	for _, f := range fs {
		if !keep(f) {
			continue
		}
		if p := penalty[f.Severity]; p > maxByDim[f.Dimension] {
			maxByDim[f.Dimension] = p
		}
	}
	total := 0
	for _, p := range maxByDim {
		total += p
	}
	return clamp(100-total, 0, 100)
}

// overallScore is the environment number: the average UNIT score, then a leaky-bucket cap — any
// critical drags the whole environment to ≤49 (High), any high (no critical) to ≤69. A unit is an
// artifact, except that a plugin and its children are one (family.go, P-044): their findings are scored
// together, so a duplicate adds nothing and a clean child cannot dilute its plugin's.
func overallScore(units [][]model.Finding, keep filter) int { return breakdown(units, keep).Overall }

// Breakdown is overallScore's working, for a report to say why the number is what it is (P-058):
// how many units the mean ran over, the mean, the most severe counted finding and the ceiling it
// imposes. Overall is min(Mean, Ceiling), clamped — the number Apply sets, by construction, because
// overallScore returns this same struct's Overall.
type Breakdown struct {
	Units   int
	Mean    int
	Worst   model.Severity // "" when nothing counted
	Ceiling int            // 49 for a critical, 69 for a high, else 100
	Overall int
}

// Explain is the deterministic Breakdown of a result's artifacts — the working behind ScanResult.Overall.
func Explain(arts []model.ArtifactReport) Breakdown {
	return breakdown(Families(arts).units(), Deterministic)
}

// Points is the penalty one finding of this severity costs its dimension (spec appendix A).
func Points(s model.Severity) int { return penalty[s] }

func breakdown(units [][]model.Finding, keep filter) Breakdown {
	b := Breakdown{Mean: 100, Ceiling: 100}
	sum := 0
	for _, u := range units {
		sum += findingsScore(u, keep)
		b.Units++
		for _, f := range u {
			if keep(f) && f.Severity.Rank() > b.Worst.Rank() {
				b.Worst = f.Severity
			}
		}
	}
	if b.Units > 0 {
		b.Mean = sum / b.Units
	}
	switch b.Worst {
	case model.SevCritical:
		b.Ceiling = 49
	case model.SevHigh:
		b.Ceiling = 69
	}
	b.Overall = clamp(min(b.Mean, b.Ceiling), 0, 100)
	return b
}

// Apply sets both scores on every artifact and on the result (spec §5.3).
//
// The min() calls are the point of this function. Arithmetically they are redundant — adding
// findings can only add penalty — but they make "the LLM raised the score" an UNREPRESENTABLE
// state rather than a bug someone could introduce later. One-way-ness is a property of the
// shape here, not of an argument about the shape.
//
// Since P-142 the ceiling is the deterministic score WITHOUT the findings the judge cleared
// (uncleared), not Overall itself: a ruling on an unconfirmed finding is the one way the effective
// number may stand above the deterministic one, and by no more than that finding's weight. With
// nothing cleared, uncleared is Deterministic and Judged is Escalating, so both lines below are the
// ones they replaced. Score and Overall are computed from Deterministic alone, as before: no
// ruling, and nothing else a model wrote, reaches them.
func Apply(r *model.ScanResult) {
	for i := range r.Artifacts {
		a := r.Artifacts[i]
		r.Artifacts[i].Score = artifactScore(a, Deterministic)
		r.Artifacts[i].ScoreEffective = min(artifactScore(a, uncleared), artifactScore(a, Judged))
	}
	units := Families(r.Artifacts).units()
	r.Overall = overallScore(units, Deterministic)
	r.OverallEffective = min(overallScore(units, uncleared), overallScore(units, Judged))
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
