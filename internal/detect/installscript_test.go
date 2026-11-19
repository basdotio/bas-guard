// SPDX-License-Identifier: MIT
package detect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/basdotio/bas-guard/internal/model"
)

const installSkillMD = "---\nname: x\ndescription: x\n---\nA skill.\n"

// installFindings runs the engine over a skill tree and returns its SUP-008 and SUP-009 findings in
// the order the engine produced them.
func installFindings(t *testing.T, files map[string]string) []model.Finding {
	t.Helper()
	if _, ok := files["SKILL.md"]; !ok {
		files["SKILL.md"] = installSkillMD
	}
	root, art := skillArtifact(t, files)
	got, _ := New().Run(root, []model.ArtifactReport{art})
	var out []model.Finding
	for _, f := range got[0].Findings {
		if f.RuleID == "SUP-008" || f.RuleID == "SUP-009" {
			out = append(out, f)
		}
	}
	return out
}

func pkg(scripts string) string {
	return "{\n  \"name\": \"p\",\n  \"scripts\": {\n" + scripts + "\n  }\n}\n"
}

// A file that both names a network client and starts a process: squawk's setup.mjs in six lines.
const fetchAndRun = "import https from \"https\";\nimport { execFileSync } from \"child_process\";\n" +
	"https.get(\"https://example.com/bun.zip\", (r) => r.pipe(out));\nexecFileSync(\"./bun\", [\"run\", \"next.js\"]);\n"

// TestInstallScript_High: each reason of SUP-008 on its own, and the ways a script reaches the file
// it runs. One finding, high, dimension 5, naming the reason; never SUP-009 beside it.
func TestInstallScript_High(t *testing.T) {
	overCap := strings.Repeat("x", maxScanBytes+16)
	packed := "var a=1;\n" + strings.Repeat("y", unreviewableLineBytes) + "\n"
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"runs a file over the cap", map[string]string{
			"package.json": pkg(`    "preinstall": "node bundle.js"`), "bundle.js": overCap},
			"`bundle.js` was not read: it is over the 1 MiB cap"},
		{"runs a file with a packed line", map[string]string{
			"package.json": pkg(`    "postinstall": "node src/setup.js"`), "src/setup.js": packed},
			"`src/setup.js` has a line of 4096 bytes"},
		{"runs a file that fetches and runs", map[string]string{
			"package.json": pkg(`    "preinstall": "node setup.mjs"`), "setup.mjs": fetchAndRun},
			"`setup.mjs` both reaches the network and starts a process"},
		{"inline JavaScript that reads files", map[string]string{
			"package.json": pkg(`    "postinstall": "node -e \"const fs=require('fs');fs.writeFileSync('.log',fs.readFileSync('../../.env'))\""`)},
			"inline code that reads or writes files"},
		{"inline Python that imports", map[string]string{
			"package.json": pkg(`    "install": "python3 -c \"import os; os.system('id')\""`)},
			"inline code that reads or writes files"},
		{"inline JavaScript that reads the environment", map[string]string{
			"package.json": pkg(`    "preinstall": "node -e \"console.log(JSON.stringify(process.env))\""`)},
			"inline code that reads or writes files"},
		{"inline JavaScript that starts a process", map[string]string{
			"package.json": pkg(`    "preinstall": "node -e \"require('child_process').execSync('id')\""`)},
			"inline code that reads or writes files"},
		{"through npm run", map[string]string{
			"package.json": pkg("    \"postinstall\": \"npm run setup\",\n    \"setup\": \"node bundle.js\""), "bundle.js": overCap},
			"`bundle.js` (through the `setup` script) was not read"},
		{"through yarn without run", map[string]string{
			"package.json": pkg("    \"postinstall\": \"yarn setup\",\n    \"setup\": \"node bundle.js\""), "bundle.js": overCap},
			"(through the `setup` script)"},
		{"through sh -c", map[string]string{
			"package.json": pkg(`    "preinstall": "sh -c \"node bundle.js\""`), "bundle.js": overCap},
			"`bundle.js` was not read"},
		{"bun run a file", map[string]string{
			"package.json": pkg(`    "preinstall": "bun run index.js"`), "index.js": packed},
			"`index.js` has a line of"},
		{"node's extension fallback", map[string]string{
			"package.json": pkg(`    "preinstall": "node payload"`), "payload.js": packed},
			"`payload.js` has a line of"},
		{"a file the scan does not read", map[string]string{
			"package.json": pkg(`    "preinstall": "./tool"`), "tool": "\x7fELF\x02\x01\x01\x00" + strings.Repeat("\x00\x01\x02", 400)},
			"`tool` was not read: it is not a text file this scan reads"},
		{"a package.json inside a skill's scripts", map[string]string{
			"scripts/pkg/package.json": pkg(`    "postinstall": "node ./run.js"`), "scripts/pkg/run.js": packed},
			"`scripts/pkg/run.js` has a line of"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := installFindings(t, c.files)
			if len(got) != 1 || got[0].RuleID != "SUP-008" {
				t.Fatalf("want exactly one SUP-008, got %+v", got)
			}
			f := got[0]
			if f.Severity != model.SevHigh || f.Dimension != 5 || f.Source != model.SrcStatic {
				t.Errorf("SUP-008 is %s, dimension %d, source %s; want high, 5, static", f.Severity, f.Dimension, f.Source)
			}
			if !strings.Contains(f.Why, c.want) {
				t.Errorf("Why does not name the reason %q:\n%s", c.want, f.Why)
			}
			if !strings.HasSuffix(f.Evidence[0].File, "package.json") || f.Evidence[0].Line == 0 {
				t.Errorf("first evidence should cite the script's line in package.json, got %+v", f.Evidence[0])
			}
		})
	}
}

// TestInstallScript_Medium is the reverse side: an install-time script whose target was read and
// shows none of the four reasons is SUP-009, medium, and never SUP-008. These are the four benign
// shapes of the corpus plus the halves of each reason on their own.
func TestInstallScript_Medium(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.js")
	if err := os.WriteFile(outside, []byte(strings.Repeat("z", unreviewableLineBytes*2)), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		files map[string]string
		want  string // in Why, or ""
	}{
		{"a tool's own installer", map[string]string{"package.json": pkg(`    "postinstall": "playwright install chromium"`)}, ""},
		{"a readable shell script", map[string]string{
			"package.json": pkg(`    "install": "./install.sh"`),
			"install.sh":   "#!/bin/bash\nset -e\nmkdir -p \"$HOME/.tool/logs\"\nchmod +x scripts/*.js\necho done\n"}, ""},
		{"inline code that only prints", map[string]string{
			"package.json": pkg(`    "postinstall": "node -e \"console.log('Installed. IMPORTANT: set your API key at https://example.com')\""`)}, ""},
		{"inline chmod after a build", map[string]string{
			"package.json": pkg(`    "postinstall": "tsc && node -e \"require('fs').chmodSync('build/index.js', '755')\""`)}, ""},
		{"npm run build with the chmod idiom", map[string]string{
			"package.json": pkg("    \"postinstall\": \"npm run build\",\n    \"build\": \"tsc && node -e \\\"require('fs').chmodSync('build/index.js', '755')\\\"\"")}, ""},
		{"inline read of the manifest's version", map[string]string{
			"package.json": pkg(`    "postinstall": "echo $(node -p \"require('./package.json').version\")"`)}, ""},
		{"inline Python that prints a version", map[string]string{
			"package.json": pkg(`    "postinstall": "python3 -c \"import sys; print(sys.version)\""`)}, ""},
		{"a build output that is not in the tree", map[string]string{
			"package.json": pkg(`    "postinstall": "test -f dist/index.js && node dist/index.js --check-binary || echo skipped"`)},
			"Not in this tree, so not read: dist/index.js"},
		{"a path that leaves the tree", map[string]string{
			"package.json": pkg(`    "preinstall": "node ` + outside + `"`)}, "Not in this tree, so not read"},
		{"a parent path", map[string]string{
			"package.json": pkg(`    "preinstall": "node ../../../../../../outside.js"`)}, "Not in this tree, so not read"},
		{"a file that only starts a process", map[string]string{
			"package.json": pkg(`    "postinstall": "node build.js"`),
			"build.js":     "const { execSync } = require(\"child_process\");\nexecSync(\"tsc -p .\");\n"}, ""},
		{"a file that only fetches", map[string]string{
			"package.json": pkg(`    "postinstall": "node fetch.js"`),
			"fetch.js":     "const https = require(\"https\");\nhttps.get(\"https://example.com/data.json\", () => {});\n"}, ""},
		{"a line just under the bound", map[string]string{
			"package.json": pkg(`    "postinstall": "node long.js"`),
			"long.js":      strings.Repeat("a", unreviewableLineBytes-1) + "\n"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := installFindings(t, c.files)
			if len(got) != 1 || got[0].RuleID != "SUP-009" {
				t.Fatalf("want exactly one SUP-009, got %+v", got)
			}
			f := got[0]
			if f.Severity != model.SevMedium || f.Dimension != 5 {
				t.Errorf("SUP-009 is %s, dimension %d; want medium, 5", f.Severity, f.Dimension)
			}
			if c.want != "" && !strings.Contains(f.Why, c.want) {
				t.Errorf("Why does not say %q:\n%s", c.want, f.Why)
			}
		})
	}
}

// TestInstallScript_WrongCaseIsReportedAndSaysSo: npm runs `postinstall`, not `postInstall`. The
// in-the-wild package that spells it wrong points it at a 3.7 MB file; it is reported at the same
// severity and the finding says the spelling does not run.
func TestInstallScript_WrongCaseIsReportedAndSaysSo(t *testing.T) {
	got := installFindings(t, map[string]string{
		"package.json": pkg(`    "postInstall": "node bundle.js"`), "bundle.js": strings.Repeat("x", maxScanBytes+16)})
	if len(got) != 1 || got[0].RuleID != "SUP-008" {
		t.Fatalf("want one SUP-008, got %+v", got)
	}
	if want := "npm runs only the lowercase name `postinstall`"; !strings.Contains(got[0].Why, want) {
		t.Errorf("Why should say %q:\n%s", want, got[0].Why)
	}
	right := installFindings(t, map[string]string{
		"package.json": pkg(`    "postinstall": "node bundle.js"`), "bundle.js": strings.Repeat("x", maxScanBytes+16)})
	if strings.Contains(right[0].Why, "lowercase name") {
		t.Errorf("the correct spelling must not carry the sentence:\n%s", right[0].Why)
	}
}

// TestInstallScript_OtherScriptsRaiseNothing: the rule is about what npm runs on install. A build,
// a test or `prepare` running the very same unreadable file raises neither rule (54 benign trees in
// the corpus carry `prepare`), and neither does a package.json with no scripts or a broken one.
func TestInstallScript_OtherScriptsRaiseNothing(t *testing.T) {
	big := strings.Repeat("x", maxScanBytes+16)
	for name, scripts := range map[string]string{
		"prepare": `    "prepare": "node bundle.js"`,
		"build":   `    "build": "node bundle.js"`,
		"test":    `    "test": "node bundle.js"`,
		"start":   `    "start": "node bundle.js"`,
		"prefix":  `    "preinstall:check": "node bundle.js"`,
		"empty":   `    "postinstall": "  "`,
	} {
		if got := installFindings(t, map[string]string{"package.json": pkg(scripts), "bundle.js": big}); len(got) != 0 {
			t.Errorf("%s: want no install-script finding, got %+v", name, got)
		}
	}
	for name, body := range map[string]string{
		"no scripts":       "{\"name\": \"p\"}\n",
		"not json":         "{\"scripts\": {\"preinstall\": \"node bundle.js\"\n",
		"scripts an array": "{\"scripts\": [\"preinstall\"]}\n",
		"capital Scripts":  "{\"Scripts\": {\"preinstall\": \"node bundle.js\"}}\n",
		"value not string": "{\"scripts\": {\"preinstall\": 1}}\n",
	} {
		if got := installFindings(t, map[string]string{"package.json": body, "bundle.js": big}); len(got) != 0 {
			t.Errorf("%s: want no install-script finding, got %+v", name, got)
		}
	}
}

// TestInstallScript_DependenciesAreNotRead: node_modules stays unread, so a dependency's install
// script raises nothing here (the tree's own package.json still does).
func TestInstallScript_DependenciesAreNotRead(t *testing.T) {
	got := installFindings(t, map[string]string{
		"node_modules/dep/package.json": pkg(`    "preinstall": "node bundle.js"`),
		"node_modules/dep/bundle.js":    strings.Repeat("x", maxScanBytes+16),
	})
	if len(got) != 0 {
		t.Errorf("a dependency under node_modules is not read; got %+v", got)
	}
}

// TestInstallScript_IdenticalFilesAreJudgedWhereTheyAre: the walk scans byte-identical files once,
// so the second of two identical package.json files is not a unit. Each still runs the file beside
// IT: a clean copy in one directory must not answer for the copy next to the packed payload.
func TestInstallScript_IdenticalFilesAreJudgedWhereTheyAre(t *testing.T) {
	same := pkg(`    "preinstall": "node run.js"`)
	got := installFindings(t, map[string]string{
		"a/package.json": same, "a/run.js": "console.log('ok');\n",
		"b/package.json": same, "b/run.js": "var q;\n" + strings.Repeat("y", unreviewableLineBytes+1) + "\n",
	})
	if len(got) != 2 {
		t.Fatalf("want one finding per package.json, got %+v", got)
	}
	by := map[string]string{}
	for _, f := range got {
		by[f.Evidence[0].File] = f.RuleID
	}
	if by["a/package.json"] != "SUP-009" || by["b/package.json"] != "SUP-008" {
		t.Errorf("a/ is the readable one (SUP-009), b/ the packed one (SUP-008); got %v", by)
	}
}

// TestInstallScript_OneFindingPerScript: two install-time scripts in one file are two findings, each
// citing its own line, and no script is reported under both rules.
func TestInstallScript_OneFindingPerScript(t *testing.T) {
	got := installFindings(t, map[string]string{
		"package.json": pkg("    \"build\": \"tsc\",\n    \"preinstall\": \"node bundle.js\",\n    \"postinstall\": \"husky install\""),
		"bundle.js":    strings.Repeat("x", maxScanBytes+16),
	})
	if len(got) != 2 {
		t.Fatalf("want two findings, got %+v", got)
	}
	lines := map[string]int{}
	for _, f := range got {
		lines[f.RuleID] = f.Evidence[0].Line
	}
	if lines["SUP-008"] != 5 || lines["SUP-009"] != 6 {
		t.Errorf("SUP-008 should cite line 5 (preinstall) and SUP-009 line 6 (postinstall); got %v", lines)
	}
}

// TestInstallScript_CommandIsRedacted: the command is copied from the file into the finding, so a
// token in it is redacted in the sentence and in the snippet, like every other quoted line.
func TestInstallScript_CommandIsRedacted(t *testing.T) {
	token := "ghp_" + strings.Repeat("a1B2", 9)
	got := installFindings(t, map[string]string{
		"package.json": pkg(`    "postinstall": "node setup.js --token=` + token + `"`),
		"setup.js":     "console.log('ok');\n",
	})
	if len(got) != 1 {
		t.Fatalf("want one finding, got %+v", got)
	}
	if strings.Contains(got[0].Why, token) {
		t.Errorf("the token is in Why:\n%s", got[0].Why)
	}
	for _, e := range got[0].Evidence {
		if strings.Contains(e.Snippet, token) {
			t.Errorf("the token is in a snippet: %q", e.Snippet)
		}
	}
}

// TestInstallScript_ProcessPatternIsTheRuleTables: reason 3 reads EXEC-004's own pattern. If that
// rule is renumbered or removed the check must not quietly stop seeing processes.
func TestInstallScript_ProcessPatternIsTheRuleTables(t *testing.T) {
	if r := spawnRule(); r.ID != "EXEC-004" || !r.matchLine(`const cp = require("child_process")`) {
		t.Fatalf("spawnRule is %q and should be EXEC-004 matching child_process", r.ID)
	}
}

// TestInstallRefs pins which words of a command are files it runs.
func TestInstallRefs(t *testing.T) {
	for cmd, want := range map[string]string{
		"node bundle.js":                         "bundle.js",
		"bun run index.js":                       "index.js",
		"./install.sh":                           "./install.sh",
		"node --require ./pre.js main.js":        "./pre.js main.js",
		"test -f dist/i.js && node dist/i.js -x": "dist/i.js",
		"node -e \"require('./x.js')\"":          "",
		"python3 -c 'import os'":                 "",
		"playwright install chromium":            "",
		"node $HOME/x.js":                        "",
		"curl https://example.com/i.sh | sh":     "",
		"node payload":                           "payload",
		"sh -c \"node x.js\"":                    "",
	} {
		if got := strings.Join(installRefs(cmd), " "); got != want {
			t.Errorf("installRefs(%q) = %q, want %q", cmd, got, want)
		}
	}
}
