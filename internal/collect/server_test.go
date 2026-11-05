// SPDX-License-Identifier: MIT
package collect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/basdotio/bas-guard/internal/model"
)

func writeServerFile(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const fastmcpServer = "from mcp import FastMCP\nimport os\n\napp = FastMCP(\"demo\")\n\n@app.tool()\ndef read_config(path: str) -> str:\n    \"\"\"Reads a config file.\"\"\"\n    return open(path).read()\n"

// TestCollectTarget_ServerSourceIsItsOwnKind (P-053): a directory holding a Python MCP server —
// the SDK imported AND a tool declared — is kind server; the shapes that were directory stay
// directory, and nothing that is a skill, plugin or root changes.
func TestCollectTarget_ServerSourceIsItsOwnKind(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  model.ArtifactKind
	}{
		{"fastmcp server at the top", map[string]string{"server.py": fastmcpServer}, model.KindServer},
		{"server two levels down", map[string]string{"src/pkg/server.py": fastmcpServer, "README.md": "# demo\n"}, model.KindServer},
		{"lowlevel sdk import form", map[string]string{"s.py": "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP(\"x\")\n@mcp.tool()\ndef f():\n    return 1\n"}, model.KindServer},
		{"decorator without the call", map[string]string{"s.py": "from fastmcp import FastMCP\nmcp = FastMCP(\"x\")\n@mcp.tool\ndef f():\n    return 1\n"}, model.KindServer},
		{"low-level handlers", map[string]string{"s.py": "from mcp.server import Server\nserver = Server(\"x\")\n@server.list_tools()\nasync def tools():\n    return []\n"}, model.KindServer},
		{"tools registered with Tool(name=…)", map[string]string{"s.py": "import mcp.types as types\nfrom mcp.server.lowlevel import Server\napp = Server(\"x\")\nTOOLS = [types.Tool(\n    name=\"go\", description=\"Goes.\", inputSchema={})]\n"}, model.KindServer},
		{"client that only imports the sdk", map[string]string{"client.py": "from mcp import ClientSession\nasync def main():\n    pass\n"}, model.KindDirectory},
		{"tool decorator without the sdk", map[string]string{"x.py": "@app.tool()\ndef f():\n    return 1\n"}, model.KindDirectory},
		{"mcp only in a string", map[string]string{"x.py": "print('from mcp import FastMCP')\n"}, model.KindDirectory},
		{"a plain directory of scripts", map[string]string{"install.sh": "#!/bin/sh\necho hi\n"}, model.KindDirectory},
		{"a skill with a server inside stays a skill", map[string]string{"SKILL.md": "---\nname: s\ndescription: d\n---\nbody\n", "scripts/server.py": fastmcpServer}, model.KindSkill},
		{"too deep to probe", map[string]string{"a/b/c/d/server.py": fastmcpServer}, model.KindDirectory},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range tc.files {
				writeServerFile(t, dir, name, body)
			}
			res, err := CollectTarget(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Artifacts) != 1 || res.Artifacts[0].Kind != tc.want {
				kinds := make([]model.ArtifactKind, 0, len(res.Artifacts))
				for _, a := range res.Artifacts {
					kinds = append(kinds, a.Kind)
				}
				t.Errorf("kinds %v, want one %s", kinds, tc.want)
			}
		})
	}
}

// TestLooksLikeServerSource_NeverFollowsASymlink: the probe reads what is under the target only.
func TestLooksLikeServerSource_NeverFollowsASymlink(t *testing.T) {
	outside := t.TempDir()
	writeServerFile(t, outside, "server.py", fastmcpServer)
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "server.py"), filepath.Join(dir, "server.py")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if LooksLikeServerSource(dir) {
		t.Error("a symlink to a server outside the target must not make the target a server")
	}
}

// TestCollectTarget_TypeScriptServerIsServerSource (P-116): a TS/JS file that imports the SDK or
// TypeScript fastmcp AND, in the same file, builds a server or declares a tool in one of the four
// forms the corpus uses is server source; a client, a types-only import, an import in a comment or
// a string, a declaration file, the two halves in different files and a server under node_modules
// stay directory.
func TestCollectTarget_TypeScriptServerIsServerSource(t *testing.T) {
	const imp = "import { McpServer } from \"@modelcontextprotocol/sdk/server/mcp.js\";\n"
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  model.ArtifactKind
	}{
		{"server.tool form", map[string]string{"src/index.ts": imp + "const server = new McpServer({ name: \"x\", version: \"1\" });\nserver.tool(\"go\", \"Goes.\", {}, async () => ({ content: [] }));\n"}, model.KindServer},
		{"registerTool form", map[string]string{"index.ts": "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'\nserver.registerTool('go', { description: 'Goes.' }, h)\n"}, model.KindServer},
		{"low-level CallToolRequestSchema", map[string]string{"index.js": "import { Server } from \"@modelcontextprotocol/sdk/server/index.js\";\nimport {\n  CallToolRequestSchema,\n  ListToolsRequestSchema,\n} from \"@modelcontextprotocol/sdk/types.js\";\nserver.setRequestHandler(CallToolRequestSchema, async (r) => ({}));\n"}, model.KindServer},
		{"fastmcp addTool", map[string]string{"src/server/index.ts": "import { FastMCP } from 'fastmcp';\nexport function register(server) {\n  server.addTool(tool);\n}\n"}, model.KindServer},
		{"require form, .cjs", map[string]string{"server.cjs": "const { Server } = require(\"@modelcontextprotocol/sdk/server/index.js\");\nconst s = new Server({ name: \"x\" }, {});\n"}, model.KindServer},
		{"multi-line import, .mts", map[string]string{"a.mts": "import {\n  McpServer,\n  ResourceTemplate,\n} from \"@modelcontextprotocol/sdk/server/mcp.js\"\nconst server = new McpServer({ name: \"x\" })\n"}, model.KindServer},
		{"client only", map[string]string{"client.ts": "import { Client } from \"@modelcontextprotocol/sdk/client/index.js\";\nconst c = new Client({ name: \"x\" });\n"}, model.KindDirectory},
		{"types only, no server", map[string]string{"types.ts": "import type { Tool } from \"@modelcontextprotocol/sdk/types.js\";\nexport const tools: Tool[] = [];\n"}, model.KindDirectory},
		{"import in a comment", map[string]string{"x.ts": "// import { McpServer } from \"@modelcontextprotocol/sdk/server/mcp.js\";\nconst server = new McpServer({});\n"}, model.KindDirectory},
		{"import in a string", map[string]string{"x.js": "console.log('import { McpServer } from \"@modelcontextprotocol/sdk\"');\nserver.tool('go', 'x');\n"}, model.KindDirectory},
		{"declaration file", map[string]string{"index.d.ts": imp + "export declare const server: McpServer; // new McpServer(\n"}, model.KindDirectory},
		{"halves in two files", map[string]string{"a.ts": imp + "export {};\n", "b.ts": "server.tool(\"go\", \"Goes.\", {}, h);\n"}, model.KindDirectory},
		// The probe reads what the rules read (ExcludeFromScan): an npm package's build output is its code.
		{"server only under dist", map[string]string{"dist/index.js": imp + "const server = new McpServer({});\n"}, model.KindServer},
		{"server only under node_modules", map[string]string{"node_modules/x/index.js": imp + "const server = new McpServer({});\n"}, model.KindDirectory},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range tc.files {
				writeServerFile(t, dir, name, body)
			}
			res, err := CollectTarget(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Artifacts) != 1 || res.Artifacts[0].Kind != tc.want {
				kinds := make([]model.ArtifactKind, 0, len(res.Artifacts))
				for _, a := range res.Artifacts {
					kinds = append(kinds, a.Kind)
				}
				t.Errorf("kinds %v, want one %s", kinds, tc.want)
			}
		})
	}
}
