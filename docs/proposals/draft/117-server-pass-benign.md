<!-- SPDX-License-Identifier: MIT -->
# 117 — The server pass reads a server's own key and its own subprocess as an attack, and that cost blocked P-114 and P-116

- **Source**: the maintainer, 2026-11-05 ("好" to: before widening what the judge reads again, cut the server pass's
  benign escalations), after P-114 and P-116 were rejected on their benign lines and P-115 shipped only its server half
- **Depends on**: none in code. P-114 and P-116 are the reason: both recovered real misses (10 spliced servers; 5 TS/JS
  servers, two of them in-the-wild npm packages) and both failed on benign servers escalating at high
- **Branch**: `p/117-server-pass-benign`

## Problem

The server pass (`LLM-010`) escalates benign servers at a rate the gate cannot use, and the excess sits in two
categories. Measured on the full-corpus run of 2026-11-04 (`v0.33.1-3-g5a18a6db`, gpt-4.1-mini, `samples: 3`) for
Python servers, and on P-116's branch run for TS/JS servers (`baselines/results/aguard/2026-11-05-llm-gpt-4.1-mini-p116-branch-s3/`):

| | benign asked | escalating at high | `credential-read` | `remote-execution` | other |
|---|---:|---:|---:|---:|---:|
| Python servers | 623 | 61 (9.8%) | 29 | 20 | 12 |
| TS/JS servers (P-116) | 220 | 42 (19%) | 20 | 13 | 9 |

Of the 61 Python ones, 40 are flagged by nothing but this pass. The same two categories carry the pass's recall: of the
179 malicious Python servers, 91 are caught by the judge alone, 31 through `remote-execution` and 19 through
`credential-read`. Lowering either category as a whole buys precision with recall, which is what `issues/028` measured
and rejected (a `remote-execution` lowered by the tool's name: Cisco −10, benign −2).

**`credential-read`.** P-062 and P-098 already lower a server reading its own key: on these benign servers they lower
80 of 109 Python votes and 35 of 56 TS votes. Of the 49 benign high votes left, **44 stay high because of one check**,
`detect.CredentialSentElsewhere` ("the file sends to a host that is not the credential's own service"), run on the
file the vote cites (`agent-guard-work/p117/credprobe-main.go`, a local probe over the same three detect functions).
Against it, the malicious high votes that the same check holds are **6** (the other 20 malicious hold on
`CredentialOverreach`). The 44, read one by one:

- **18 hold credentials in a configuration object, not a named environment variable** (`settings.password`, a token
  field), so there is no service name to match, and any off-box host counts as elsewhere. Among those hosts are URL
  literals that are not destinations at all: `www.w3.org` (XML namespaces), `www.apache.org` (licence headers),
  `example.com`.
- **17 name a service the host does not spell**: `TMDB_API_KEY` → `api.themoviedb.org`, `GDRIVE_…`/`GSHEETS_…` →
  `www.googleapis.com`, `ENTRA_CLIENT_SECRET` → `login.microsoftonline.com`, `DD_APP_KEY` → `oapi.dingtalk.com`.
- **9 name their own host and one more** (`github.com` for a README badge or a release check, a second API) — the
  check requires every destination to match.

**`remote-execution`.** The 35 benign high findings whose votes name it (Python 21, TS 14; a few carry a second
category, so the counts above, by majority, are 20 and 13), read by the model's own sentence:

- **about 13: the tool's purpose is running arbitrary commands or code, and it says so** (`shell_command`,
  `run_command`, a terminal, `eval_wolfram`, kubectl, a sandboxed code runner). This is the case `issues/028` rejected:
  Cisco's malicious servers are written the same way. A server that runs any shell command it is sent is a risk to
  install, and an alert on it is arguably justified; the corpus has a marker for that (`alert_justified`, 67 samples),
  and no benign server carries it today.
- **about 12: a fixed program run with parameters** — `adb`, `ffmpeg`, `bazel`, Taskwarrior through `execFileSync`,
  `osascript`, `systemctl`, an `npx` validator. The model reads "a subprocess" as remote execution. `issues/028` names
  this as the question worth asking again: controlled execution (a fixed program, a list of arguments) against
  executing whatever input arrives.
- **about 7: the cited file is not the server running** — a GitHub Actions workflow (`npm-publish.yml`), a test
  runner, an installer, a `git clone` that fetches documentation, a setup script that edits Claude's settings.
- the other 3 are mixed: a PowerShell loader that runs encrypted .NET assemblies (worth a second look at its label),
  a self-updating binary, and a vote whose sentence describes credentials.

## Initial direction

Three changes, each measurable on its own, none of them a category lowered as a whole:

1. **`CredentialSentElsewhere` reads destinations, not every URL literal.** A namespace URI, a licence link or a
   documentation host in a string is not where a credential goes. Either count only hosts that reach a network call
   in the same file (the one-level resolution P-061 already does), or leave out a short list of non-destination URI
   prefixes (`www.w3.org/`, `www.apache.org/licenses/`, `example.com`/`.org`/`.net`, `json-schema.org`). The second is
   a list, which this repository is wary of; the choice is a design question.
2. **The server pass's question separates a fixed program from arbitrary execution.** A prompt change, so it moves
   `PromptVersion`, and wording changes have failed here before (P-048, P-066): measure on Cisco's 127 first, where the
   recall is.
3. **The server pass does not read files that do not run as the server**: `.github/` workflows at least (they run on
   GitHub, not on the machine that installs the server). Installers and setup scripts stay in: an install step is a
   real attack vector (npm `postinstall`), and P-116's worms are exactly that.

Separately, for the maintainer and the corpus, not this repository's code: whether benign servers whose declared purpose
is arbitrary execution should carry `alert_justified`, as the 67 samples that cross a boundary in the open already do.
That changes what counts as a false positive; it must be decided before a measurement, never after one.

**Measure** on the 623 Python and 220 TS/JS benign servers, Cisco's 127, the other malicious MCP samples, and the 17
TS/JS malicious ones (P-116's recognition, applied in a measurement-only build). Static checks (direction 1) can be
simulated offline on the existing raw first, at no cost. If the benign rate on TS/JS servers comes down near Python's,
P-114 and P-116 can be measured again, each against its own lines as written.

**Not this**: the category tables (P-115), the excerpt (P-114), what the server pass is asked of (P-116), the static
rules' own `EXFIL-001` destination check (`detect.go` shares the code; direction 1 must not change a static finding,
or it is a `rulesEpoch` change and a separate measurement).
