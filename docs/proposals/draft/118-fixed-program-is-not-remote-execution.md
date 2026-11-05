<!-- SPDX-License-Identifier: MIT -->
# 118 — The server pass asks for "shell or code built from a parameter" and has no row for it, so a fixed program run with arguments lands in `remote-execution`

- **Source**: the maintainer, 2026-11-05 ("好" to direction 2 of P-117 as its own proposal)
- **Depends on**: P-117 (its runs are the baseline here). P-115 in practice: it gives the server pass its own table
  (`intentBehaviours` plus server rows), which a server-only row needs
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
