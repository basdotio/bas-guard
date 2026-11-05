<!-- SPDX-License-Identifier: MIT -->
# 118 — The server pass asks for "shell or code built from a parameter" and has no row for it, so a fixed program run with arguments lands in `remote-execution`

- **Source**: the maintainer, 2026-11-05 ("好" to direction 2 of P-117 as its own proposal; "好" to design after #141 merged)
- **Depends on**: P-115 (merged: the server pass's own table, which a server-only row needs). P-117 (PR #143): its
  code is in both measurement builds, and its runs are the readings for design
- **Branch**: `p/118-fixed-program-is-not-remote-execution`

## Problem

The server pass's question tells the model to flag "executing shell or arbitrary code built from a parameter"
(`serverTask`). Its category table has no row for that. The nearest high row is `remote-execution`, whose text is
another thing: "downloads code or instructions from the network and runs or follows them (a URL plus a shell or
interpreter); running a local script by name is NOT this". The model files every execution it sees there — an
injected `shell=True` and a `subprocess.run(["bazel", "build", target])` alike — and the row is high.

On P-117's runs (`baselines/results/aguard/2026-11-05-llm-gpt-4.1-mini-p117-{py-branch,ts-measure}-s3/`), samples
whose escalating vote is `remote-execution` and that nothing else holds:

| | asked | `remote-execution` at high | held by it alone |
|---|---:|---:|---:|
| Python benign servers | 623 | 22 | 18 |
| TS/JS benign servers (P-116's recognition) | 220 | 14 | 13 |
| Python malicious servers | 179 | 46 | **34** (32 Cisco) |

It is the pass's largest source of recall and, after P-117, its largest source of benign escalations. Read one by one:

- **The 34 malicious are injection shapes**: a shell string built from input (`shell=True`, `os.system`, a curl
  command concatenated from parameters), `eval`/`exec`/`compile` of input, a template rendered from a caller's string
  (Jinja2, Mako, Django, Cheetah, Tornado, format strings), `pickle`/`yaml.unsafe_load` of input, a module imported by a
  caller-supplied name, a hidden dispatcher.
- **The benign ones are two kinds** (P-117's read of the 35 benign findings):
  - **about 13 are servers whose purpose is running what they are sent** — `run_command`, `shell_command`, a
    terminal, kubectl, `eval_wolfram`. In code they are the same shape as Cisco's
    `subprocess_shell_command_injection` or `unrestricted_exec_arbitrary_code`; `issues/028` measured that telling
    them apart by name loses 10 Cisco samples. This proposal does not try.
  - **about 12 run a fixed program with arguments** — `adb`, `ffmpeg`, `bazel`, `xcodebuild`, Taskwarrior through
    `execFileSync`, `osascript`, an `npx` validator. The program is spelled in the code, the arguments go as a list, no
    shell parses them. That is not "shell or code built from a parameter", and it is not "downloads … and runs".

`issues/028` named this as the one thing worth trying again: "a question that can tell controlled execution (a
sandbox, an allowlisted command) from executing arbitrary input; that is the prompt's question, not the severity
table's".

## Initial direction

Give the server table the row its question already asks for, and tell the model what is not it:

- **A server-only high row**, e.g. `code-execution`: "a tool runs a shell command, code, a template or a serialized
  object built from its caller's input (a command string through a shell, eval/exec, a template rendered from a
  caller's string, pickle or an unsafe YAML load of input, a module imported by a caller's name); NOT a fixed program
  run with its arguments as a list and no shell".
- **`remote-execution` keeps its own meaning** (network download plus run), and its server line points away: running a
  caller's input is `code-execution`, running a fixed program with arguments is neither.
- The catch-alls point at the new row (P-066's lesson, kept by P-115).

Two things to decide in design, not here:

- **Disclosure.** The server table's rows take the "disclosed, one step lower" step. A terminal server that says
  "Executes a shell command" would weigh medium — and so would a Cisco sample whose docstring says the same. Exempting
  the row (as `software-source` is) keeps recall and the 13 terminal servers; taking the step trades some of each, and
  `issues/028` is the measurement of a cruder version of that trade.
- **Fixed program with an injected argument**: `subprocess.run(["git", "clone", url])` with a caller's `url` is a list,
  but an option-looking argument (`--upload-pack=…`) is still an injection. Whether the row's NOT clause needs a
  caveat, or whether that is left to the static rules.

Measure on Cisco's 127 first (where 32 of the 34 are), then the 623 Python and 220 TS/JS benign servers. A prompt and
table change moves `PromptVersion`; P-048 and P-066 are the record of wordings that did not move the model, and
P-115's `covert-transmission` is the record of a row the model did not pick even where its wording named the case.

**Not this**: the 13 arbitrary-execution servers (`issues/028`), `credential-read` (P-117), what the pass reads, the
static `EXEC-*` rules.

## Done criteria

Code:

- [ ] The server table gains one high row, `code-execution`: "a tool runs a shell command, code, a template or a
  serialized object built from its caller's input (a command string through a shell, eval/exec/compile, a template
  rendered from a caller's string, pickle or an unsafe YAML load of input, a module imported by a caller's name);
  NOT a fixed program run with its arguments as a list and no shell, and NOT downloading and running (that is
  remote-execution)". The intent table does not get it. `TestCategoryTables_ServerIsIntentPlusTwo` becomes
  `…PlusThree` and still requires the shared rows first, in order.
- [ ] The server table's `other` points at it ("running a caller's input as a shell command or code is
  code-execution"); `TestCategoryPrompt_CatchAllsPointAway` covers the new row.
- [ ] `code-execution` is exempt from the disclosure step, as `software-source` is (open question 1). Table test:
  `code-execution` disclosed → high; `remote-execution` disclosed on the server pass → medium (reverse assertion: the
  step still applies to every other row); `software-source` unchanged.
- [ ] `serverTask` says what is not execution built from a parameter: "running a fixed program with its arguments
  passed as a list and no shell is not this". It does **not** gain an "even when disclosed" clause for execution:
  the exemption is in the table only, so a server the model already leaves unflagged because its tools say they
  run commands stays unflagged.
- [ ] Reverse assertion: `TestCategoryPrompt_OtherPassesUnchanged` keeps every other pass's digest — only the server
  prompt moves. `PromptVersion` moves (computed); `ExcerptVersion` does not (no excerpt change).
- [ ] `go test -count=1 ./baselines/cmd/judgefold/` green; `make verify` green, read from its own exit code.

Measurement (live, gpt-4.1-mini, `samples: 3`, corpus `c314e4d9`). P-117's readings cannot be the baseline: they
predate P-115's server rows, which moved the prompt. Both runs are new:

- **Baseline**: main (P-115) plus P-117. **Branch**: the same plus this proposal.
- **Python**: the 802 server trees (`p114-servers.jsonl`), plain binaries.
- **TS/JS**: the 233 trees, measurement-only builds of both with P-116's reverted recogniser cherry-picked.

Lines set before the run:

- [ ] **Target**: of the nine benign servers that run a fixed program with list arguments and no shell — Python
  `fidelismm-shipstores-shipstores`, `microck-semrush-web-mcp-semrush-web-mcp`, `securityfortech-secops-mcp`,
  `shenghaiwang-xcodebuild-mcpxcodebuild`, `thefiredev-cloud-eufy-camera-mcp-eufy-cam-mcp`; TS
  `awwaiid-mcp-server-taskwarrior`, `rtuin-mcp-mermaid-validator-src`, `tidewave-ai-tidewave-js-src`,
  `zs-andy-lms-cli-src` (each `ben-mcp-gh-…`; read from the corpus, see "Readings for design") — **at least 5** have no
  escalating high `LLM-010` on the branch. A target sample that is not high on the baseline either does not count
  for or against.
- [ ] **Benign overall**: benign samples with an escalating high `LLM-010`, Python and TS together, branch **≤**
  baseline.
- [ ] **Malicious**: no malicious sample with an escalating high `LLM-010` on the baseline loses it on the branch
  **because its vote's severity fell** (on the branch at least 2 of 3 still flag it, and the tool's severity is
  medium); a Cisco (`mal-mcp-ci-*`) or in-the-wild (`mal-mcp-dd-*`) loss of that kind fails. Losses on the vote
  count alone (fewer than 2 of 3 agreed, the severity still high) are rerun noise, as P-117 question 7 decided, and
  are listed.
- [ ] **Read, not gated**: for the malicious high votes that were `remote-execution` on the baseline, how many are
  `code-execution` on the branch. If the model does not pick the row (P-115's `covert-transmission`), the readings
  say so even when the lines above pass.
- [ ] Each benign sample that stops or starts being flagged is listed with the model's sentence.

## Out of scope

- The ~13 servers whose purpose is running what they are sent (`run_command`, terminals, `kubectl`, `eval_wolfram`):
  `issues/028`. With the exemption they stay where they are.
- Option injection through a list argument (`git clone <url>` with `--upload-pack=…`): a known limit, open question 2.
- `remote-execution`'s own text (shared by the intent table; the intent pass does not move), `credential-read`
  (P-117), what the pass reads (P-114), TS/JS recognition (P-116), the static `EXEC-*` rules.

## Must not claim

- Not "the judge tells safe execution from unsafe". It is told one shape that is not execution of input; servers that
  build a shell string from input (`adb` with `shell=True`, `` exec(`cd ${cwd}`) ``, an `osascript` line with the
  caller's text in it) stay high, and should.
- The nine targets are a hand-read list from one run; a reading on them is not a benign rate.

## Work items

| W | In one sentence | Commit message |
|---|---|---|
| 1 | `code-execution` row, `other` pointer, disclosure exemption, `serverTask` sentence; table and prompt tests | `judge: the server pass names running a caller's input code-execution, and a fixed program with list arguments is not it (P-118)` |
| 2 | Docs pair `LLM-010` row and `.claude/rules/judge.md` | `docs: the server pass's code-execution row (P-118)` |
| 3 | Runs, result directories, schema-test counts, readings | `baselines: P-118 on the server trees (P-118)` |
| 4 | Done, and `complete/` or `rejected/` | `proposals: P-118 done (P-118)` |

## Open questions

All asked at once. Each has a recommended answer.

1. **Does `code-execution` take the disclosure step?** Recommended: **exempt it**, as `software-source` is. On P-117's
   runs the step almost never touched `remote-execution` (46 malicious high majorities, 0 lowered; benign 2) because a
   tool never says it downloads and runs code; a tool does say "Executes a shell command", and `issues/028` measured
   lowering on that: 10 Cisco lost for 2 benign. Exempt, the terminal servers stay where they are and the gain is
   only the fixed programs.
   **Decided (2026-11-05)**: exempt.
2. **Option injection through a list argument?** Recommended: **no caveat; a known limit**. No malicious sample held by
   `remote-execution` on P-117's runs has that shape; a caveat ("unless the caller can pass an option") is the
   sentence the model would read into every `ffmpeg` call with a parameter, which is the gain.
   **Decided (2026-11-05)**: no caveat, recorded here as a known limit.
3. **Measurement.** Recommended: baseline and branch both new, as above, about US$9 (P-117's two runs were US$3.4
   Python and US$1.1 TS each).
   **Decided (2026-11-05)**: as recommended, about US$9.

## Readings for design

From `agent-guard-work/runs/2026-11-05-p117-{py,ts}-s3/` (P-117's branch runs) and the corpus at `c314e4d9`:

- `remote-execution` majorities with at least 2 of 3 votes: Python malicious 46 high / 0 medium, benign 22 high / 2
  medium; TS malicious 2 high, benign 14 high. The disclosure step lowered none of the malicious ones.
- The benign samples held by `remote-execution` alone, read in the corpus: nine run a fixed program with list arguments
  (`subprocess.run([...])`, `execFileSync`, `spawn(cmd, args, {shell: false})`) — the target list; five build a shell
  string from input (`dabaigoose-mcp-wechat-adb-server` `Popen(command, shell=True)`,
  `noopstudios-interactive-feedback-mcp` `shell=True`, `hypermodel-labs-mcp-server-auto-commit`
  `` execAsync(`cd ${cwd}`) ``, `krasun-notes-mcp-src` `` execAsync(`osascript … ${script}`) ``, `namin-dafny-mcp`
  `os.system`); `tommelt-hpc-mcp-src` runs a binary the caller names; the rest are terminals, installers or network
  download-and-run (`0x7556-wolfshell`, `maximilianromer-onion-search-mcp`).
