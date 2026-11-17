<!-- SPDX-License-Identifier: MIT -->
# 131 — A skill that says "install this first" and points at a paste site, a password-protected zip or a look-alike of the agent's own CLI scores 100: the lure is never read as one

- **Source**: the maintainer, 2026-11-17 ("先走第1条": the in-the-wild misses left after P-129, read sample by sample)
- **Depends on**: none
- **Branch**: `p/131-fake-prerequisite-lure`

## Problem

The largest in-the-wild campaign against agent skills works without a line of code in the skill. The skill's
instructions open with a prerequisite: a helper "must be installed before using this skill", and here is where to get
it. On Windows, a zip on somebody's GitHub release, with the password to open it. On macOS, a page on a paste site
whose "installation command" is to be run in Terminal. Or simply a site named after the agent platform's own CLI.
What is installed is the malware; the skill is the delivery note.

Nothing reads that as an attack. The lines are prose with a link: no pipe to a shell, no credential, no encoded blob.
The six such trees in the development corpus (DataDog's OpenClaw samples):

| sample | the lure | today |
|---|---|---|
| `dd-openclaw-hightower6eu-autoupdate` | a zip with "(extract using: …)" and "run the executable"; "Visit this page (a paste site) and execute the installation command in Terminal" | **100, no finding** |
| `dd-openclaw-stveenli-browserautomation-skill` | "… CLI must be installed before using this skill. Download and install from" a `vercel.app` site named after the platform's CLI, in the README the skill tells the agent to read | **100, no finding** |
| `dd-openclaw-stveenli-shieldphenix` | the same two lines in `SKILL.md` | **100, no finding** |
| `dd-openclaw-thiagoruss0-n8nsk` | "… is required for the skill to work properly. Quick setup here ->" a look-alike domain | **100, no finding** |
| `dd-openclaw-hightower6eu-clawhubcli` | the zip and the paste page | high, by `SUP-006` on an unrelated example line |
| `dd-openclaw-thiagoruss0-jirayb4nt` | the look-alike domain | high, by `EXFIL-001` on an unrelated API example |

Four are missed, and the two that are flagged are flagged for something else.

A prototype of three line-level signals (`agent-guard-work/lure-proto.py`, offline, Markdown files only):

1. **paste**: a line sends the reader to a paste or snippet site to run or install something;
2. **archive**: a line gives a download for an archive or executable together with a password to open it;
3. **platform**: a line says something must be installed or set up, with a URL whose host carries an agent
   platform's name and is not that platform's own.

| set | malicious with a signal | benign with a signal |
|---|---:|---:|
| development corpus (719 / 4,534) | 8, four of them missed today | 0 |
| fresh skills, two samples (416 benign) | — | 0 |
| defensive skills, the benign that quote attacks (36) | — | 0 |
| **held-out** (243 / 216), totals only, read once | **112** of the 123 ClawHub trees, **53 not flagged today** | **0** |

The held-out ClawHub set is 68 of 123 today. The prototype was run on it once, for totals, after the signals were
written from the six development trees; no held-out sample was read.

## Initial direction

One structural check on the lines of instruction files and bundled documents, high, in the supply-chain dimension,
with the three reasons above; each URL of a line is judged on its own host, so an official link on the same line does
not excuse a look-alike. Measured on the static bench, which costs nothing.

## Done criteria

Code:

- [ ] `SUP-010` (high, dimension 5), one finding per line, raised on instruction files and documents (`SKILL.md`,
  `CLAUDE.md`, a `README.md`, any bundled `.md`/`.txt`), not on scripts, hook commands or tool descriptions. The
  reason is named in the finding:
  1. **paste**: a URL on a paste or snippet host, and on the same line a word for running or installing (`run`,
     `execute`, `paste`, `install`, `set up`, `terminal`, `command`, `script`, `shell`);
  2. **archive**: a URL whose path ends in an archive or executable extension (`.zip`, `.rar`, `.7z`, `.tar.gz`,
     `.tgz`, `.exe`, `.msi`, `.dmg`, `.pkg`, `.bat`, `.ps1`, `.scr`, `.iso`), and on the same line a password to open
     it (`password`, `passcode`, `passphrase`, `pass:`, "extract using: …", `unzip -P`, `7z x -p`). "Extract with
     `unzip`" is not a password;
  3. **platform**: a URL whose host contains an agent platform's name (OpenClaw and its former names, ClawHub, Claude,
     Anthropic, OpenAI, ChatGPT, Codex, Cursor) and is not one of that platform's own hosts, and on the same line a
     phrase that makes it a prerequisite or a download ("must be installed", "is required", "prerequisite", "download
     and install", "install from", "quick setup", "set up here", "get it here").
- [ ] Each URL on a line is judged by its own host: an official link beside a look-alike does not clear the line.
- [ ] Rules see both the raw and the normalized line, as every rule does, so a zero-width character in the host does
  not hide it.
- [ ] Reverse assertions: an official install page (`https://docs.anthropic.com/…`, `https://openclaw.ai/install`)
  with "must be installed" raises nothing; "Install jq from https://stedolan.github.io/jq/" raises nothing; a zip
  download with "extract with `unzip`" raises nothing; a paste link with no word for running raises nothing; the same
  lure line in a `.py` or `.sh` file raises nothing.
- [ ] `rulesEpoch` 18 → 19, `make docs`, `TestEveryRuleIDIsDocumented` green; `make verify` green from its own exit
  code.

Measurement (static, threshold high, corpus `c314e4d9`, `main` at `1943194` against the branch). Lines set before
the run:

- [ ] **Target**: each of the four missed trees carries a high `SUP-010`: `dd-openclaw-hightower6eu-autoupdate`,
  `dd-openclaw-stveenli-browserautomation-skill`, `dd-openclaw-stveenli-shieldphenix`,
  `dd-openclaw-thiagoruss0-n8nsk`. Four of four.
- [ ] **Malicious**: no sample flagged on `main` is unflagged on the branch.
- [ ] **Benign**: no benign sample, alert-justified ones included, carries `SUP-010`; the samples flagged at high are
  the same as on `main`.
- [ ] **Hard negatives**: the same samples flagged as on `main`.
- [ ] **Held-out** (`heldout-all`, totals only): malicious flagged at least **40 more** than `main` (the prototype
  said 53; the built rule is tighter in three places, so the line is set below it); benign flagged at most one more
  than `main`.
- [ ] **Fresh benign skills** (`fresh216`, `fresh200`, 416 trees): none carries `SUP-010`.
- [ ] **Read, not gated**: a scan of the maintainer's own `~/.claude` on `main` and on the branch differs only by
  `SUP-010` findings, and their count is reported.

## Out of scope

- Any other host heuristic: free app hosting, unusual top-level domains, "the tool's name is in the host". Measured
  and not clean: `jq`'s own page is on `github.io`, and documentation sites live on `vercel.app`.
- A list of known-bad domains or hashes for this campaign (that is the reputation list's job).
- Fetching or reading what the link points at. The scan connects to nothing.
- Lures in scripts, hook commands, MCP tool descriptions, or spread over several lines.
- The judge.

## Must not claim

- Not "detects ClawHavoc" or any campaign by name, and not "detects malware delivery". It reads three ways a
  prerequisite is offered; a lure that names an ordinary-looking site with no password and no paste page is not seen.
- The held-out figure is one family: the 123 ClawHub trees are one collection and largely one campaign. It says the
  rule is not fitted to the six development trees; it does not say what share of future lures it sees.
- The platform names and their own hosts are a list. A platform that is not on it gets no look-alike protection, and
  a new official host has to be added.

## Work items

| W | In one sentence | Commit message |
|---|---|---|
| 1 | The line check, `SUP-010`, tests, epoch, generated rules doc | `detect: a prerequisite offered from a paste site, a password-protected archive or a platform look-alike is SUP-010 (P-131)` |
| 2 | `.claude/rules/detect.md` and the spec line | `docs: the prerequisite-lure check (P-131)` |
| 3 | Static runs, corpus and held-out and fresh skills, main and branch | `baselines: P-131 static runs, main and branch, corpus, held-out and fresh skills (P-131)` |
| 4 | Done, `complete/` or `rejected/`, the index row | `proposals: P-131 done (P-131)` |

## Open questions

Decided by the recommended answer unless the maintainer says otherwise (told on 2026-11-17 with the prototype's
figures):

1. **Severity.** High: the lure is the whole attack, and no benign tree in 5,202 measured carries a signal.
2. **Which platforms count for reason 3.** OpenClaw's family and the ones this tool's users run (Claude, Anthropic,
   OpenAI, ChatGPT, Codex, Cursor). The wider list was the one measured.
3. **Dimension.** Supply chain (5), beside `SUP-001` and `SUP-007`, but raised on documents too: the lure in one of
   the four trees is in the README its `SKILL.md` tells the agent to read.
