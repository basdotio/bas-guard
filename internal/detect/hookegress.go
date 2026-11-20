// SPDX-License-Identifier: MIT
package detect

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/basdotio/bas-guard/internal/model"
)

// HOOK-003's command half (P-128). Claude Code hands every hook the same JSON: an http hook gets it as
// the POST body, a command hook on stdin. An http hook to a host off this machine is HOOK-003 high; a
// command hook that runs `curl --data-binary @- https://…` sends the same bytes and used to score
// 100/100. So the question here is HOOK-003's question asked of a command: does a stage of this hook —
// the command line, or a script it runs — hand a SENDER the event, a content field of it, or the
// session transcript?
//
// What counts as the payload (hookFlow), and the decision the measurement made:
//   - the event as a whole: stdin read in place (`@-`, `$(cat)`, `-T -`, `cat |`), or into a name;
//   - a CONTENT field of it: prompt, tool_input, tool_response, tool_calls, last_assistant_message,
//     compact_summary, custom_instructions — the fields the hooks reference documents as carrying
//     the conversation;
//   - the transcript: the file transcript_path (or agent_transcript_path) names, uploaded or read.
//
// Everything else a hook can send stays quiet: a fixed message, and the NOTIFICATION fields (message,
// title, cwd, session_id, hook_event_name, tool_name, …). Posting those to ntfy or Slack is what the
// documentation shows Notification and Stop hooks for, and they carry no conversation. The transcript's
// path sent as text is a path, not the transcript.
//
// The destination is judged like the http half: loopback in both views is low (PermissionRequest
// excepted — whatever the hook prints is the allow/deny decision), anything else, including a
// destination the file never names, is high. One finding per hook, citing where the payload was
// taken and where it was sent.
//
// This is a reading of shell, Python and Node, not an interpreter: names are followed forward
// through one file (a name that holds the payload passes it on to a name assigned from it whole), a
// field taken out of it is classified by its first key, and nothing else is evaluated. Ruby, Perl and
// PowerShell stages are not read for this; a plugin's hook script is read under its plugin, not here.

// hookFlow is what a value holds, in increasing order of what it would cost to send it.
type hookFlow uint8

const (
	flowNone hookFlow = iota
	flowPath          // the PATH of a file holding the conversation (the transcript, or a file the hook wrote the payload to)
	// flowStatus is a status line's stdin as a whole (P-133): session metadata — model, cost, workspace, session_id —
	// and transcript_path. No conversation is in it, so it is not sendable; transcript_path selected out of it is a
	// path, as out of a hook's event.
	flowStatus
	flowContent    // a content field of the event, or anything selected out of one
	flowEvent      // the event JSON as a whole
	flowTranscript // the transcript's text, whole or in part
)

// sendable reports whether sending a value of this flow is what HOOK-003 reports.
func (f hookFlow) sendable() bool { return f >= flowContent }

// selected is the flow of a selection out of a value of flow from, sel being the selector (`.prompt`,
// `["cwd"]`). Out of the event, the field decides; out of a content field or the transcript, whatever is
// selected is still that text; out of a path or nothing, nothing.
func selected(from taint, sel string) taint {
	switch from.flow {
	case flowEvent:
		if f := fieldFlow(sel); f != flowNone {
			return taint{flow: f, src: from.src}
		}
		return taint{}
	case flowStatus:
		if fieldFlow(sel) == flowPath {
			return taint{flow: flowPath, src: from.src}
		}
		return taint{}
	case flowContent, flowTranscript:
		return from
	}
	return taint{}
}

// stdinFlow is what a stage's stdin holds: the event for a hook's stages, the session status for a status line's.
func stdinFlow(u unit) hookFlow {
	if u.statusInput {
		return flowStatus
	}
	return flowEvent
}

// taint is a value's flow and the line that last assigned it (nil when the value was read in place).
type taint struct {
	flow hookFlow
	src  *model.Evidence
}

func (t taint) or(u taint) taint {
	if u.flow > t.flow {
		return u
	}
	return t
}

// hookSend is one place a stage hands the payload to a sender. line is the logical-line index within its
// unit, the key the two views (raw and normalized) are merged on.
type hookSend struct {
	unit  int
	line  int
	at    model.Evidence
	src   *model.Evidence
	local bool
}

// contentFieldRE / pathFieldRE classify a field selection by its FIRST key, written as a selection —
// `.prompt`, `["tool_input"]`, `.get("prompt"`, `?.tool_response` — never as a bare word, so a fixed
// message that says "prompt" is not a field.
var (
	contentFieldRE = regexp.MustCompile(`^(?:prompt|tool_input|tool_response|tool_calls|last_assistant_message|compact_summary|custom_instructions)$`)
	pathFieldRE    = regexp.MustCompile(`^(?:agent_)?transcript_path$`)
	fieldSelRE     = regexp.MustCompile(`(?:\?\.|\.|\[\s*["']|\bget\(\s*["'])([A-Za-z_][A-Za-z0-9_]*)`)
)

// fieldFlow is the flow of a selection out of the event: the most any selector in sel reaches.
func fieldFlow(sel string) hookFlow {
	f := flowNone
	for _, m := range fieldSelRE.FindAllStringSubmatch(sel, -1) {
		switch {
		case contentFieldRE.MatchString(m[1]):
			return flowContent
		case pathFieldRE.MatchString(m[1]):
			f = flowPath
		}
	}
	return f
}

// hookPayloadEgress is the command half of HOOK-003 for one hook artifact. units are the hook's own
// (hookUnits): its command line and the scripts it runs, whose stdin is the event. root names evidence.
func hookPayloadEgress(root string, a model.ArtifactReport, units []unit) []model.Finding {
	var sends []hookSend
	for i, u := range units {
		sends = append(sends, unitSends(root, i, u)...)
	}
	return hookEgressFinding(a, sends)
}

// unitSends reads one stage in both views. A send either view sees counts; it is local only if every view
// that saw it found it local AND, where only the normalized view saw it, the raw line names no remote host:
// the normalized view folds homoglyphs, so `lоcalhost` with a Cyrillic о reads as localhost there.
func unitSends(root string, idx int, u unit) []hookSend {
	read := egressReader(u)
	if read == nil {
		return nil
	}
	rel := relPath(root, u.file)
	lang := langForFile(u.file)
	if commandLine(u) {
		lang = langHash // a command line is shell, whatever file it was stored in
	}
	lines := logicalLines(lang, u.text, commentOnlyLines(lang, u.text))
	// The second view is the interpreter's: for shell, logicalLines' norm; for Python and Node, the raw line
	// with characters folded but quotes kept, because there a quote inside a word is a string literal.
	second := func(ll logicalLine) string { return ll.norm }
	if !commandLine(u) && !isShellScript(u.file) {
		second = func(ll logicalLine) string { return foldCharacters(ll.raw) }
	}
	norm := read(rel, idx, u, lines, second)
	raw := read(rel, idx, u, lines, func(ll logicalLine) string { return ll.raw })
	rawAt := map[int]hookSend{}
	for _, s := range raw {
		if prev, ok := rawAt[s.line]; !ok || prev.local {
			rawAt[s.line] = s
		}
	}
	out := make([]hookSend, 0, len(norm)+len(raw))
	for _, s := range norm {
		if r, ok := rawAt[s.line]; ok {
			s.local = s.local && r.local
			delete(rawAt, s.line)
		} else if s.local && !hostsAllLoopback(lines[s.line].raw) {
			s.local = false
		}
		out = append(out, s)
	}
	for _, s := range raw {
		if _, ok := rawAt[s.line]; ok {
			out = append(out, s)
		}
	}
	return out
}

// egressReader picks the reader for a stage by its language; nil means the stage is not read for this.
func egressReader(u unit) func(rel string, idx int, u unit, lines []logicalLine, view func(logicalLine) string) []hookSend {
	if commandLine(u) || isShellScript(u.file) {
		return shellSends
	}
	switch strings.ToLower(filepath.Ext(u.file)) {
	case ".py":
		return pythonSends
	case ".js", ".mjs", ".cjs", ".ts":
		return nodeSends
	}
	return nil
}

// commandLine reports whether u is a command line stored in a config file — a hook's, or a status line's (P-133;
// its other stages are files, never synthetic) — which a shell runs.
func commandLine(u unit) bool {
	return u.role == roleHookCmd || (u.statusInput && u.synthetic)
}

func isShellScript(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".sh", ".bash", ".zsh":
		return true
	}
	return false
}

// hostsAllLoopback reports whether every host the line names is loopback (true when it names none).
func hostsAllLoopback(line string) bool {
	for _, h := range networkHosts(line) {
		if !loopbackHost(h) {
			return false
		}
	}
	return true
}

// destinationLocal decides one send's destination from the text that carries it: every host named there
// (or, when none is, every host its variables resolve to in the same file, P-061), plus any the caller
// parsed itself (nc's host argument), must be loopback, and at least one must be named. An unreadable
// destination is not local — the http half fails closed the same way.
func destinationLocal(text string, assigns urlTable, extra []string) bool {
	hosts := networkHosts(text)
	if len(hosts) == 0 {
		hosts = resolvedHosts(text, assigns)
	}
	hosts = append(hosts, extra...)
	if len(hosts) == 0 {
		return false
	}
	for _, h := range hosts {
		if !loopbackHost(h) {
			return false
		}
	}
	return true
}

const (
	hook003Title = "Hook forwards event payload over HTTP"

	hookSendsOffBoxWhy = "This command hook sends what Claude Code hands it — the event JSON on its stdin, a content " +
		"field of it (the prompt, a tool's input or output, the assistant's last message), or the session transcript " +
		"its transcript_path names — to a host that is not loopback, or to one the file does not name. That is what " +
		"an http hook to the same address does: the conversation leaves the machine with it. A hook that sends a " +
		"fixed message, or a notification field such as message or cwd, is not reported."
	hookSendsLocalWhy = "This command hook sends its event payload, a content field of it, or the session transcript " +
		"to a loopback address. The destination is on this machine, so the finding is a prompt to confirm the local " +
		"service, not a claim that data left."
	hookSendsLocalPermissionWhy = "This PermissionRequest hook sends the authorization request to a loopback address. " +
		"The destination is local, but what the hook prints is the allow/deny decision, so it is high — confirm the " +
		"local service is one you intend to grant that power."
)

// hookEgressFinding turns a hook's sends into at most one HOOK-003: the first off-box send if there is
// one, else the first local one.
func hookEgressFinding(a model.ArtifactReport, sends []hookSend) []model.Finding {
	if len(sends) == 0 {
		return nil
	}
	pick := sends[0]
	for _, s := range sends {
		if !s.local {
			pick = s
			break
		}
	}
	sev, why := model.SevHigh, hookSendsOffBoxWhy
	switch {
	case pick.local && a.Hook.Event == eventPermissionRequest:
		why = hookSendsLocalPermissionWhy
	case pick.local:
		sev, why = model.SevLow, hookSendsLocalWhy
	}
	ev := []model.Evidence{pick.at}
	if pick.src != nil && *pick.src != pick.at {
		ev = []model.Evidence{*pick.src, pick.at}
	}
	return []model.Finding{{
		RuleID: "HOOK-003", Dimension: 4, Severity: sev, Source: model.SrcStatic,
		Title: hook003Title, Why: why, Evidence: ev,
	}}
}
