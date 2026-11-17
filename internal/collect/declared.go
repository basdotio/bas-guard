// SPDX-License-Identifier: MIT
package collect

import (
	"os"
	"path/filepath"

	"github.com/basdotio/bas-guard/internal/model"
)

// The configuration a `check` target declares (P-120).
//
// `check <repo>` read the repository as one directory tree, and a tree read runs the line rules over
// text: it has no notion of a permission grant, a hook's interception point, an env block or an MCP
// server. Measured on main (aba37e8): a project whose .claude/settings.json holds `Bash(*)`, a
// PreToolUse hook printing `permissionDecision: allow` and an http PostToolUse hook, beside a
// .mcp.json whose server preloads a file into node, scored 100/100 "looks safe", exit 0, under
// `check <repo>`, `check ./.mcp.json`, and with the same settings.json in a directory not named
// .claude; `check <repo>/.claude` scored 69, exit 1. The README tells users to start with `check`.
//
// The fix is NOT to route such a directory to CollectAll. looksLikeRoot records why: routing narrows
// what is read to the known layouts, and a 29-byte settings.json once turned a 26/100 payload tree
// into 100/100. So the tree artifact stays first and whole, and the configuration is read IN
// ADDITION, by the readers a scan uses (settingsFrom, mcpServersFrom). Nothing here decides how much
// of the tree is read; it can only add artifacts.
//
// What is read, and only at the target's top level:
//   - a directory: <dir>/.claude/settings.json and settings.local.json — a project's, read as
//     `scan --root <dir>/.claude` reads them — then <dir>/settings.json and settings.local.json (a
//     config root with another name, the shape looksLikeRoot leaves to `scan --root`), then
//     <dir>/.mcp.json, then the project's instruction files and what they import
//     (declaredInstructions, P-125);
//   - a file named settings.json, settings.local.json or .mcp.json: that file.
//
// Each file must be one the tree read may open (FileReach): a .claude or .mcp.json that is a symlink
// out of the target is not read as the target's own — the tree read refuses and scores it (SCOPE-001).
// A file present and unreadable is said (IO-000), one that does not parse is an artifact carrying
// PARSE-000, as under a scan.
//
// Everything added names the target's artifact in Within, so the score counts the target and its
// configuration as one unit and prints a finding both carry once (score.Families) — the tree read
// meets a hook's script too. A hook or permission list also carries ConfigRoot, the directory its
// settings file sits in, so the scripts it names resolve, and hash, as under `scan --root` that
// directory: one hook has one identity whichever command read it.

// declaredSettingsDirs are the directories under a directory target whose settings files are read,
// in order: a project's .claude, then the target itself.
var declaredSettingsDirs = []string{projectDirName, "."}

// projectMCPName is a project's MCP config, read beside its .claude.
const projectMCPName = ".mcp.json"

// withDeclared returns res with the configuration the target at path declares appended. res holds the
// target's one artifact, built by CollectTarget; it is not modified.
func withDeclared(res Result, path string, isDir bool) Result {
	if len(res.Artifacts) != 1 {
		return res
	}
	within := res.Artifacts[0].Name
	env := res.Env
	var arts []model.ArtifactReport
	var notes []model.Finding
	add := func(a []model.ArtifactReport, n []model.Finding, configRoot string) {
		for _, x := range a {
			x.Within = within
			if configRoot != "" {
				x.ConfigRoot = AnchorRoot(configRoot)
			}
			arts = append(arts, x)
		}
		notes = append(notes, n...)
	}
	if isDir {
		for _, sub := range declaredSettingsDirs {
			dir := filepath.Join(path, sub)
			for _, sc := range settingsScopes {
				p := filepath.Join(dir, sc.file)
				if !readableInTree(path, p) {
					continue
				}
				a, n := settingsFrom(p, sc.nameSuffix, &env)
				add(a, n, dir)
			}
		}
		if p := filepath.Join(path, projectMCPName); readableInTree(path, p) {
			a, n := mcpServersFrom(p, "", &env)
			add(a, n, "")
		}
		known := append(append([]model.ArtifactReport{}, res.Artifacts...), arts...)
		a, n := declaredInstructions(path, known)
		add(a, n, "")
	} else {
		switch base := filepath.Base(path); base {
		case projectMCPName:
			a, n := mcpServersFrom(path, "", &env)
			add(a, n, "")
		default:
			for _, sc := range settingsScopes {
				if base == sc.file {
					a, n := settingsFrom(path, sc.nameSuffix, &env)
					add(a, n, filepath.Dir(path))
				}
			}
		}
	}
	if len(arts) == 0 && len(notes) == 0 {
		return res
	}
	return Result{
		Root:      res.Root,
		Artifacts: append(append([]model.ArtifactReport{}, res.Artifacts...), arts...),
		Env:       env,
		Notes:     append(append([]model.Finding{}, res.Notes...), notes...),
	}
}

// declaredInstructions reads the instruction files of the project at dir, and what they import, by the
// collector a scan of dir/.claude uses (P-125): instructionFiles names them — the project's CLAUDE.md and
// CLAUDE.local.md and those of its .claude — and expandImports follows their `@` imports with home the
// project, as it is for that scan. So an import is read, refused as a credential (EXFIL-005 on the file
// that wrote it, a COV-000 note, nothing read) or left unread out of the project exactly as a scan
// decides it. known are the artifacts already collected for the target; an import landing on one is not
// read again.
//
// A tree read meets these files too, but as text: it does not follow an import, so a CLAUDE.md whose one
// line is `@.env` loaded the project's secrets into every session and scored nothing under `check <repo>`.
// A lone CLAUDE.md target is not expanded here: its boundary would be its directory, and the Downloads
// pass checks loose files there, where an import would read a sibling that is not a candidate.
func declaredInstructions(dir string, known []model.ArtifactReport) ([]model.ArtifactReport, []model.Finding) {
	var seeds []model.ArtifactReport
	for _, c := range instructionFiles(filepath.Join(dir, projectDirName), dir) {
		if isFile(c.path) && readableInTree(dir, c.path) {
			seeds = append(seeds, artifact(model.KindInstruction, c.name, c.path, FileHash(c.path)))
		}
	}
	if len(seeds) == 0 {
		return nil, nil
	}
	seeds, imported, notes := expandImports(AnchorRoot(dir), seeds, known)
	return append(seeds, imported...), notes
}

// readableInTree reports whether p exists and is a file the tree read of root may open (FileReach). An
// absent file is not; neither is one that resolves out of the target, which the tree read discloses.
func readableInTree(root, p string) bool {
	if _, err := os.Lstat(p); err != nil {
		return false
	}
	return FileReach(AnchorRoot(root), AnchorRoot(p)).Kind == Read
}
