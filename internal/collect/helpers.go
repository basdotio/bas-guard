// SPDX-License-Identifier: MIT
package collect

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/basdotio/bas-guard/internal/model"
)

// Helper commands (P-133).
//
// Besides hooks, a settings file names commands Claude Code runs itself, unasked: the credential helpers
// (apiKeyHelper, awsAuthRefresh, awsCredentialExport, gcpAuthRefresh), the telemetry header helper
// (otelHeadersHelper), the launcher every background process starts under (processWrapper), and two
// hook-shaped objects, statusLine (run after every assistant message, with the session JSON on stdin) and
// fileSuggestion (run as the user types @). From a project's settings they run once the workspace trust dialog
// is accepted, as hooks do. settingsFrom used to drop all of them, so a settings file holding only
// `"apiKeyHelper": "curl … | sh"` was no artifact and scanned 100/100.
//
// They become one artifact per settings file, SettingsHelpersName, beside "settings env": KindPermission, read by
// detect.helperUnits, not audited by permcheck. Not read: sshHostCommands (Claude Desktop only, run as argv
// without a shell, and only when the user creates a connection) and policyHelper (honoured only in managed
// settings, which no scan reads). processWrapper is honoured only in user and managed settings and is read from
// every file: a scan cannot tell a user root from a project root.
//
// Keys are read by their exact name, and of two members with one name the last counts, as for JSON.parse —
// the reason P-127 reads its keys that way.

// SettingsHelpersName is the artifact name for the helper commands of a settings file. Like SettingsEnvName it is
// a KindPermission artifact that is not a permissions list; detect, the content hash and the permission audit key
// on it.
const SettingsHelpersName = "settings helpers"

// PermissionList reports whether a is a settings file's permissions list: the KindPermission artifact that is neither
// its env block nor its helper commands, and the only one the permission auditor reads.
func PermissionList(a model.ArtifactReport) bool {
	return a.Kind == model.KindPermission &&
		!strings.HasPrefix(a.Name, SettingsEnvName) && !strings.HasPrefix(a.Name, SettingsHelpersName)
}

// helperKey is one settings key whose value is a command: the string itself, or the `command` of an object whose
// `type` is "command".
type helperKey struct {
	name   string
	object bool
}

// helperKeys, in the order SettingsHelpers returns them.
var helperKeys = []helperKey{
	{"apiKeyHelper", false},
	{"awsAuthRefresh", false},
	{"awsCredentialExport", false},
	{"gcpAuthRefresh", false},
	{"otelHeadersHelper", false},
	{"processWrapper", false},
	{"statusLine", true},
	{"fileSuggestion", true},
}

// StatusLineKey is the helper whose stdin is the session JSON (detect.statusLineEgress).
const StatusLineKey = "statusLine"

// Helper is one command a settings file has Claude Code run on its own: its key, the command line, and the line
// of the file its value starts on (0 when it cannot be placed).
type Helper struct {
	Key     string
	Command string
	Line    int
}

// SettingsHelpers returns the helper commands of the settings file whose bytes are b, in helperKeys' order. A file
// that is not a JSON object has none (settingsFrom reports it as PARSE-000). A command that is empty or only
// whitespace is no command. An object's command is read when its `type` is "command" or absent: the reference
// defines no other type, and reading when it is absent is the safe side of not knowing whether Claude Code refuses
// it.
func SettingsHelpers(b []byte) []Helper {
	var doc map[string]json.RawMessage
	if json.Unmarshal(b, &doc) != nil {
		return nil
	}
	var lines map[string]int
	var out []Helper
	for _, k := range helperKeys {
		raw, ok := doc[k.name]
		if !ok {
			continue
		}
		cmd, path := stringMember(raw), k.name
		if k.object {
			cmd, path = objectCommand(raw), k.name+".command"
		}
		if strings.TrimSpace(cmd) == "" {
			continue
		}
		if lines == nil {
			lines = memberValueLines(b)
		}
		out = append(out, Helper{Key: k.name, Command: cmd, Line: lines[path]})
	}
	return out
}

// stringMember is raw decoded as a JSON string, or "" when it is anything else.
func stringMember(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// objectCommand is the `command` string of a hook-shaped object whose `type` is "command" or absent, else "".
func objectCommand(raw json.RawMessage) string {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return ""
	}
	if t, ok := obj["type"]; ok && stringMember(t) != "command" {
		return ""
	}
	return stringMember(obj["command"])
}

// memberValueLines maps the dotted path of each member of the JSON object b ("apiKeyHelper",
// "statusLine.command") to the 1-based line its value starts on; of two members with one path the last counts.
// Members of an object inside an array have no path. It is how a helper's finding cites the line the tree read of
// `check .` cites for the same text, so the report prints that line once (P-133 decision 6).
func memberValueLines(b []byte) map[string]int {
	type frame struct {
		object  bool   // an object, not an array
		wantKey bool   // the next token of this object is a member name
		path    string // the container's own path: "" at the top, "-" inside an array
		key     string // the member name just read
	}
	lines := map[string]int{}
	dec := json.NewDecoder(bytes.NewReader(b))
	var stack []frame
	push := func(d json.Delim, path string) {
		stack = append(stack, frame{object: d == '{', wantKey: d == '{', path: path})
	}
	for {
		start := dec.InputOffset()
		tok, err := dec.Token()
		if err != nil {
			return lines
		}
		d, isDelim := tok.(json.Delim)
		n := len(stack)
		if n == 0 || !stack[n-1].object {
			// The top level, or an element of an array: no member here.
			switch {
			case isDelim && (d == '{' || d == '['):
				path := ""
				if n > 0 {
					path = "-"
				}
				push(d, path)
			case isDelim:
				stack = stack[:n-1]
			}
			continue
		}
		f := &stack[n-1]
		if f.wantKey {
			if isDelim { // '}': the object ended
				stack = stack[:n-1]
				continue
			}
			f.key, _ = tok.(string)
			f.wantKey = false
			continue
		}
		// tok starts the value of member f.key.
		f.wantKey = true
		path := "-"
		if f.path != "-" {
			path = strings.TrimPrefix(f.path+"."+f.key, ".")
			lines[path] = 1 + bytes.Count(b[:start], []byte("\n")) + leadingNewlines(b[start:])
		}
		if isDelim && (d == '{' || d == '[') {
			push(d, path)
		}
	}
}
