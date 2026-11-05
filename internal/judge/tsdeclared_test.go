// SPDX-License-Identifier: MIT
package judge

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestTSDeclared_TheFourForms (P-116): each form a TS/JS server declares a tool in yields the name and
// the first line of a plain-string description; a description that is not a plain string leaves the
// name alone; an object that is not a tool definition yields nothing.
func TestTSDeclared_TheFourForms(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want []string
	}{
		{"server.tool with a description", `server.tool("get_weather", "Gets the weather.\nMore.", { city: z.string() }, async ({ city }) => ({}));`,
			[]string{"get_weather: Gets the weather."}},
		{"server.tool without a description", "server.tool('ping', { x: z.string() }, async () => ({}))", []string{"ping"}},
		{"server.tool with a variable description", "server.tool(`echo`, DESCRIPTIONS.echo, {}, h)", []string{"echo"}},
		{"registerTool", "server.registerTool(\"add\", {\n  title: \"Adder\",\n  description: 'Adds two numbers',\n  inputSchema: { a: z.number(), b: z.number().describe(\"second\") },\n}, h)", []string{"add: Adds two numbers"}},
		{"registerTool, nested description is not the tool's", "server.registerTool('q', { inputSchema: { properties: { x: { description: 'inner' } } } }, h)", []string{"q"}},
		{"low-level tools array", "const TOOLS = [\n  { name: \"read_file\", description: \"Reads a file\", inputSchema: { type: \"object\", properties: { path: { type: \"string\", description: \"the path\" } } } },\n  { name: 'write_file', description: `Writes ${what}`, inputSchema: {} },\n];", []string{"read_file: Reads a file", "write_file"}},
		{"fastmcp addTool object with an async method", "export const scrape = {\n  name: 'scrape-urls',\n  description:\n    'Scrape one or more URLs',\n  parameters: z.object({}),\n  async execute(args) { return '' },\n};\nserver.addTool(scrape);", []string{"scrape-urls: Scrape one or more URLs"}},
		{"quoted keys", `{ "name": "x", "description": "Does x", "inputSchema": {} }`, []string{"x: Does x"}},
		{"server metadata is not a tool", `const server = new McpServer({ name: "demo", version: "1.0.0", description: "A demo" });`, nil},
		{"a prompt is not a tool", `{ name: "summarise", description: "A prompt", arguments: [] }`, nil},
		{"commented out", "// server.tool(\"x\", \"y\")\n/* { name: 'a', description: 'b', inputSchema: {} } */", nil},
		{"strings that look like code", `const s = "{ name: 'a', description: 'b', inputSchema: {} }";`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tsDeclared(tc.src); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestServerDeclared_TypeScriptOnlyWhenPythonIsSilent (P-116): a TS server's tools are its declared
// side; a Python server keeps its own declared side byte-identical whatever JavaScript sits beside it.
func TestServerDeclared_TypeScriptOnlyWhenPythonIsSilent(t *testing.T) {
	write := func(dir, name, body string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ts := t.TempDir()
	write(ts, "src/index.ts", "import { McpServer } from \"@modelcontextprotocol/sdk/server/mcp.js\";\nserver.tool(\"go\", \"Goes somewhere.\", {}, h);\n")
	write(ts, "types.d.ts", "server.tool(\"never\", \"from a declaration file\")\n")
	d, units := serverDeclared(ts, egress{})
	if !strings.Contains(d, "go: Goes somewhere.") || strings.Contains(d, "never") {
		t.Errorf("TS declared side: %q", d)
	}
	if len(units) != 1 || units[0].file != filepath.Join("src", "index.ts") || !units[0].collapsed {
		t.Errorf("TS unit: %+v", units)
	}

	py := t.TempDir()
	write(py, "server.py", "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP(\"x\")\n@mcp.tool()\ndef f():\n    \"\"\"Does f.\"\"\"\n    return 1\n")
	alone, _ := serverDeclared(py, egress{})
	write(py, "web/app.js", "const TOOLS = [{ name: 'g', description: 'Does g', inputSchema: {} }];\n")
	beside, _ := serverDeclared(py, egress{})
	if alone != beside || strings.Contains(beside, "Does g") {
		t.Errorf("Python declared side moved: %q → %q", alone, beside)
	}
}

// FuzzTSDeclared: the reader takes the artifact author's bytes. It must not panic or hang, and what it
// returns is text from the input.
func FuzzTSDeclared(f *testing.F) {
	for _, s := range []string{
		`server.tool("a", "b", {}, h)`, "server.registerTool('a', { description: `x${y}z` }, h)",
		`[{ name: "n", description: "d", inputSchema: {} }]`, "{ name: '", "`${", "/*", `"\`, "{{{{", "}}}]])",
		"{ async execute() {}, name: 'x', description: 'y' }", "server.tool(\"a\",",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		for _, l := range tsDeclared(src) {
			name, _, _ := strings.Cut(l, ": ")
			if !strings.Contains(src, name) {
				t.Errorf("name %q is not in the input", name)
			}
		}
	})
}
