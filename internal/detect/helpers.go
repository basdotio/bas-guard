// SPDX-License-Identifier: MIT
package detect

import (
	"path/filepath"

	"github.com/basdotio/bas-guard/internal/collect"
	"github.com/basdotio/bas-guard/internal/model"
	"github.com/basdotio/bas-guard/internal/safeio"
)

// A settings file's helper commands (P-133): apiKeyHelper, statusLine and the others collect.SettingsHelpers lists.
// Claude Code runs each through a shell on its own, so each is read as a command, and a local script it names is
// read as a hook's is.
//
//   - The command line is a synthetic unit with the SCRIPT role: every rule a script gets, not the hook-only ones.
//     HOOK-001 (shell chaining) is a hook's question; the settings reference's own status line is a jq command, and
//     real ones are `input=$(cat); … | jq …`.
//   - Its evidence carries the line of the settings file its value starts on (unit.line), the line the tree read of
//     `check .` cites for the same text, so score.Families prints it once.
//   - A script it names is followed as a permission grant's is: resolveHookScript, inside the scan's home
//     (invariant #2), readCapped. One that does not resolve, resolves outside HOME or cannot be read is a COV-000
//     note and nothing else: unlike a hook's HOOK-002 it is not scored, because the reference's own examples keep
//     helpers in /bin and /opt.
//   - The status line's stages carry statusInput: their stdin is the session JSON, and statusLineEgress asks
//     HOOK-003's question of them with the transcript as the only payload.

// helperRefPrefix and helperRefNoteTitle are shared with coalesceCoverageNotes, as hookRefPrefix is.
const (
	helperRefPrefix    = "A settings helper command (apiKeyHelper, statusLine and the like) runs a local script that was NOT scanned because "
	helperRefNoteTitle = "Helper script not followed (incomplete coverage)"
)

// helperRefNote reports a script a helper names that the scan could not read. Dimension 0: a coverage gap. The
// helper's key and the reference are both copied out of the settings file, so both are redacted.
func helperRefNote(artifact, key, ref, why string) model.Finding {
	return model.Finding{
		RuleID: "COV-000", Dimension: 0, Severity: model.SevLow, Source: model.SrcStatic,
		Title:    helperRefNoteTitle,
		Why:      helperRefPrefix + why + ".",
		Evidence: []model.Evidence{{File: redactClip(artifact + " " + key), Line: 0, Snippet: redactClip(ref)}},
	}
}

// helperUnits returns the scannable text of a settings helpers artifact: each helper's command line, and each local
// script they name, once. A file that cannot be read back says nothing here: collect already reported it.
func helperUnits(root string, a model.ArtifactReport) ([]unit, []model.Finding) {
	b, err := safeio.ReadFile(a.Path, safeio.MaxConfigBytes)
	if err != nil {
		return nil, nil
	}
	// The scan's own home, never the ambient environment — the anchor hooks and grants use.
	home := filepath.Dir(root)
	var units []unit
	var notes []model.Finding
	followed := map[string]int{} // a reference already handled → its unit, or -1 when it was a note
	for _, h := range collect.SettingsHelpers(b) {
		status := h.Key == collect.StatusLineKey
		units = append(units, unit{file: a.Path, text: h.Command, role: roleScript, synthetic: true, line: h.Line, statusInput: status})
		for _, ref := range scriptRefs(h.Command) {
			if i, seen := followed[ref]; seen {
				if status && i >= 0 {
					units[i].statusInput = true // the status line runs it too
				}
				continue
			}
			followed[ref] = -1
			path, why := resolveHookScript(root, home, ref)
			switch {
			case why != "":
				notes = append(notes, helperRefNote(a.Name, h.Key, ref, why))
				continue
			case !inBoundary(home, path):
				notes = append(notes, helperRefNote(a.Name, h.Key, ref, "it resolves outside HOME and was not read (§16.2)"))
				continue
			}
			text, cov := readCapped(path, home)
			if cov != nil {
				notes = append(notes, *cov)
				continue
			}
			if text == nil {
				notes = append(notes, helperRefNote(a.Name, h.Key, ref, "it could not be read"))
				continue
			}
			followed[ref] = len(units)
			units = append(units, unit{file: path, text: string(text), role: roleForPath(path), statusInput: status})
		}
	}
	return units, notes
}

const statusLineSendsOffBoxWhy = "This status line command sends the session transcript — the file the transcript_path " +
	"of its stdin names, the whole conversation — to a host that is not loopback, or to one the file does not name. " +
	"Claude Code runs the status line at session start and after every assistant message, so the conversation leaves " +
	"the machine as it grows, as it would from a Stop hook. The rest of the status line's input (model, cost, " +
	"workspace, session_id) carries no conversation and is not reported."

const statusLineSendsLocalWhy = "This status line command sends the session transcript (the file its stdin's " +
	"transcript_path names) to a loopback address. The destination is on this machine, so the finding is a prompt to " +
	"confirm the local service, not a claim that data left."

// statusLineEgress is HOOK-003 for a status line (decision 5): units are the helpers artifact's (helperUnits); only
// the status line's stages are read, with the session status on stdin, so the one payload is the transcript.
func statusLineEgress(root string, a model.ArtifactReport, units []unit) []model.Finding {
	var sends []hookSend
	for i, u := range units {
		if u.statusInput {
			sends = append(sends, unitSends(root, i, u)...)
		}
	}
	found := hookEgressFinding(a, sends)
	if len(found) == 0 {
		return nil
	}
	f := found[0]
	f.Why = statusLineSendsOffBoxWhy
	if f.Severity == model.SevLow {
		f.Why = statusLineSendsLocalWhy
	}
	return []model.Finding{f}
}
