<!-- SPDX-License-Identifier: MIT -->
# 129 — A package whose `preinstall` runs a 4 MB file the scanner did not read scores 88 to 100: no rule reads a `package.json`'s install-time scripts

- **Source**: the maintainer, 2026-11-17 ("进行其他的优化项目", after P-118's rejection); the per-sample comparison of
  today's misses against cc-audit on the full corpus (`c314e4d9`)
- **Depends on**: none
- **Branch**: `p/129-npm-install-scripts-unread`

## Problem

npm runs a package's `preinstall`, `install` and `postinstall` scripts on the installing machine, with no prompt, before
any of the package's own code is used. An MCP server configured as `npx -y <package>` gets them on its first launch; a
skill that tells the agent to `npm install` in a directory it ships gets them when the agent obeys. It is how the npm
worm families in the corpus start.

No rule reads those scripts. `package.json` is scanned as text, and a command like `node bundle.js` matches nothing. The
file it names is where the attack is, and in the wild that file is built to be unreadable: three of the four below are
one line of 2 to 4 MB, over the 1 MiB cap, so the only thing the report says is a `COV-000` note, which does not move
the score. The one file the package runs at install is the one file that was not read.

Static on `main` (`17d7bb0`, corpus `c314e4d9`, `agent-guard-work/runs/2026-11-17-static-main/`). All ten malicious
trees with an install-time script:

| sample | script | what it runs | today |
|---|---|---|---|
| `dd-npm-knowledge-graph-workflow-exfil` (wild) | `postInstall: node bundle.js` | 3.7 MB on one line | **100, no finding** |
| `dd-npm-redhat-kessel-mcp-worm` (wild) | `preinstall: node index.js` | 4.3 MB on one line, an `eval` wrapper | **88, nothing high** |
| `dd-npm-squawk-mcp-router-worm` (wild) | `preinstall: node setup.mjs` | 204 readable lines that download Bun and run a second file; the package ships a 2.3 MB one-line `router_init.js` | **83, nothing high** |
| `dd-npm-fixthis-exchange-exfil` (wild) | `postinstall: node src/utilities/setup_fixthis.js` | 13 KB on 3 lines, a hex-array string lookup | **76, nothing high** (`EXEC-004`, `BD-002` medium) |
| `sc-T9-supply-chain-easy` (fixture) | `postinstall: node -e "…"` | inline code: reads `.env*` two directories up and writes them to a log file | **95, nothing high** |
| `dd-npm-antv-mcp-chart-preinstall` (wild) | `preinstall: bun run index.js` | 0.5 MB on one line | high, by `EXFIL-001` in the file |
| `dd-npm-lanyer640-runcommand-revshell` (wild) | `preinstall: sh -i >& /dev/tcp/…` | the script is the reverse shell | high, by `BD-004` |
| `dd-npm-postman-mcp-shai-hulud` (wild) | `preinstall: node setup_bun.js` | a readable downloader | high, by `EXEC-001`/`EXFIL-001` |
| `dd-npm-namecheap-affiliate-injection` (wild) | `postinstall: node -e "console.log(…)"` | prints a notice | high, by `EXFIL-001` elsewhere |
| `sc-T9-supply-chain-medium` (fixture) | `postinstall: node -e "…"` | inline code reading credential paths | high, by `FS-001` |

Five of the ten are missed, four of them in the wild; the five that are caught are caught by something else in the
tree, not by the script.

The benign side is small. 163 benign trees carry a `package.json` (119 MCP servers, 44 skills) and four have an
install-time script: `playwright install chromium`; `test -f dist/index.js && node dist/index.js --check-binary || echo …`;
and `./install.sh` twice (one author, 76 and 87 readable lines: `mkdir`, `chmod`, a data file). `prepare` is on 54 benign
trees and 6 malicious ones and is not install-time for a consumer (npm runs it on publish and on a git install), so it
is not part of this.

Where it shows: the in-the-wild MCP row of the comparison is 5 of 12 today against cc-audit's 12 of 12, and four of the
seven misses are the first four rows above. The other three (`excluder`, `todo-wallet`, `iflow`) are in the JavaScript
server body and are not this proposal.

## Initial direction

A static rule on `package.json` install-time scripts, built like the hook audit: the script's command is its own unit
with the full rule set, and a local file it runs is followed one level. High when what it runs cannot be reviewed (over
the cap, or one very long line) or carries findings of its own, on `HOOK-002`'s reasoning that something run unread is
risk and not only a coverage note; medium for any other install-time script, reported and not gating. Touches
`internal/detect` (a unit builder, the rule, `rulesEpoch`) and `docs/rules.md`; measured on the static bench, which
costs nothing. The line to design: the five missed rows at high with none of the four benign ones.
