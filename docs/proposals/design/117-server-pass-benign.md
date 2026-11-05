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

## What the design read added to the problem

Offline, on the raw of the two runs above (no model calls), with a probe that runs the detect functions on the file
each high `credential-read` vote cites (`agent-guard-work/p117/`, never committed):

- **Why every URL literal is a destination.** `CredentialSentElsewhere` builds its chain with `literalIsEgress: true`,
  so any line holding an `http(s)://` literal counts as a send, and its host joins the destinations. The rules
  (`detect.go`) build their own chain per file role; this function is called from one place only, the judge's
  `behaviorExcerpt` (`overreach` on a server unit). Changing it moves no static finding (no `rulesEpoch`).
- **Four variants, vote level**, over the 76 high `credential-read` votes on servers (49 benign, 27 malicious):

  | variant | benign lowered | malicious lowered |
  |---|---:|---:|
  | V0, today | 1 | 1 |
  | V1, only lines that make a request count (`networkActionRE`), plus the same-file one-level resolution P-061 already does | **39** | **7** |
  | V2, today's lines less a non-destination list (`w3.org`, `apache.org`, `example.*`, `schema.org`) | 5 | 1 |
  | V3, both | 39 | 7 |

  V2 is a list and buys little; V1 is the change.
- **Sample level** (a sample stays flagged while anything else holds it at high):

  | | flagged today | V1 | `.github/` left out | both |
  |---|---:|---:|---:|---:|
  | Python benign servers (623) | 143 | 133 | 142 | 132 |
  | Python malicious servers (179) | 134 | 130 | 134 | 130 |
  | TS/JS benign servers (220, P-116's recognition) | 94 | 82 | 92 | 80 |
  | TS/JS malicious servers (17) | 12 | 12 | 12 | 12 |

- **The four malicious samples V1 loses were caught for the wrong reason.** All four are `mcp-variants` (synthetic,
  injected): two backdoors, a sandbox escape, a tool shadowing. In each, the escalating vote describes the server
  reading its own key ("reads Twitter username, email, and password from environment variables and uses them to login
  to Twitter"), not the attack, and the file it cites holds only the service's own URLs (Google OAuth scopes,
  `graph.facebook.com`, a test fixture's `test-logseq.com`, an `.invalid` mirror in a message string). The check held
  them high through the very literal-as-destination reading that holds the benign ones. No in-the-wild or Cisco
  sample is lost; the one DataDog sample whose vote flips (`namecheap-affiliate-injection`) stays flagged by others.
- **Direction 3 is small**: three benign samples, all through `.github/workflows/*.yml`, no malicious one.
- **Direction 2 cannot be simulated offline**: it changes the question.

## Done criteria

Code:

- [ ] `CredentialSentElsewhere` counts as destinations only lines that make a request (`networkActionRE`) and the
  same-file resolution of the variables those lines use; a URL literal on any other line is not a destination. Table
  test: a namespace URI, a licence link, an OAuth scope list, a message string — not elsewhere; a `requests.post` to an
  attacker host, a `fetch(BASE)` with `BASE` assigned an attacker host, a `curl` to one — elsewhere. Reverse assertion:
  the static `EXFIL-001`/`-003` findings on the corpus are byte-identical (the rules do not call it).
- [ ] (If open question 3 is accepted) the server pass's behaviour excerpt leaves out `.github/`; the skill passes do
  not. `ExcerptVersion` moves; the rules still read `.github/`.
- [ ] `go test -count=1 ./baselines/cmd/judgefold/` green; `make verify` green, read from its own exit code.

Measurement (live, gpt-4.1-mini, `samples: 3`, corpus `c314e4d9`), lines set before the run:

- [ ] Python, 802 server trees, plain branch binary (main: the 2026-11-04 run refolded). Benign flagged overall
  **143 → at most 135**. Malicious flagged **134 → at least 130**, and every malicious sample lost is one whose
  escalating votes on main were all `credential-read` describing the server's own key (the four above, or the same
  kind); a Cisco or in-the-wild loss fails the line.
- [ ] TS/JS, 237 trees, a measurement-only build of this branch plus P-116's reverted recogniser (open question 5): read
  and reported, not gated. It says whether P-116 is worth measuring again.
- [ ] Each benign sample that stops or starts being flagged is listed with the model's sentence.

## Out of scope

- The category tables (P-115), the excerpt caps (P-114), TS/JS recognition (P-116), `CredentialGoesHome` and
  `CredentialOverreach`, the static rules.
- **Service aliasing** (`TMDB` → `themoviedb.org`, `GDRIVE` → `googleapis.com`): a list of provider names; V1 already
  lowers most of those 17 because their URLs sit on non-request lines. Revisit only if the measurement leaves them.

## Must not claim

- Not "the judge no longer flags a server reading its own key". It flags fewer; a server that sends a request to a
  host its credential does not name stays high, which is the theft shape.
- The four lost malicious samples are a real recall loss on the scorecard, whatever the reason they were caught.

## Work items

| W | In one sentence | Commit message |
|---|---|---|
| 1 | `CredentialSentElsewhere` counts request lines only; table test and static reverse assertion | `detect: a credential goes elsewhere only where the file sends a request (P-117)` |
| 2 | (If accepted) the server pass leaves out `.github/`; excerpt version | `judge: the server pass does not read GitHub workflows as server source (P-117)` |
| 3 | Docs pair and `.claude/rules/judge.md` | `docs: what the server pass counts as a destination (P-117)` |
| 4 | Runs, result directories, schema-test counts, readings | `baselines: P-117 on the server trees (P-117)` |
| 5 | Done, and `complete/` or `rejected/` | `proposals: P-117 done (P-117)` |

## Open questions

All asked at once. Each has a recommended answer.

1. **Direction 1 as V1?** Recommended: **yes**. V2 (a non-destination list) is left out: a list this repository would
   have to maintain, for 4 more benign votes.
2. **The four malicious samples caught for the wrong reason.** Recommended: **accept losing them**, under the line
   above (only that kind may be lost). Keeping them means keeping a check that holds 39 benign votes high on the same
   mistake.
3. **Direction 3, `.github/` out of the server pass?** Recommended: **yes**, small and independent; workflows run on
   GitHub, not where the server is installed.
4. **Direction 2, the prompt separating a fixed program from arbitrary execution?** Recommended: **not in P-117**; its
   own proposal after this one is measured, measured on Cisco's 127 first. Wording changes failed twice (P-048, P-066).
5. **Measurement and cost.** Recommended: the plain branch binary on the 802 Python server trees (about US$4), and a
   measurement-only build with P-116's recogniser on the 237 TS/JS trees (about US$1), read but not gated.
6. **`alert_justified` on benign servers whose declared purpose is arbitrary execution?** Recommended: **not now**.
   It would change what a false positive is in the middle of this comparison; if wanted, it is a corpus change read
   on its own, before the next proposal measures.
