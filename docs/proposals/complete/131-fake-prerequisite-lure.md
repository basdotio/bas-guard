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

- [x] `SUP-010` (high, dimension 5), one finding per line, raised on instruction files and documents (`SKILL.md`,
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
- [x] Each URL on a line is judged by its own host: an official link beside a look-alike does not clear the line.
- [x] Rules see both the raw and the normalized line, as every rule does, so a zero-width character in the host does
  not hide it.
- [x] Reverse assertions: an official install page (`https://docs.anthropic.com/…`, `https://openclaw.ai/install`)
  with "must be installed" raises nothing; "Install jq from https://stedolan.github.io/jq/" raises nothing; a zip
  download with "extract with `unzip`" raises nothing; a paste link with no word for running raises nothing; the same
  lure line in a `.py` or `.sh` file raises nothing.
- [x] `rulesEpoch` 18 → 19, then 22 after the merge with P-132, P-134 and P-133 (which took 19, 20 and 21);
  `make docs`, `TestEveryRuleIDIsDocumented` green; `make verify` green from its own exit code.

Measurement (static, threshold high, corpus `c314e4d9`, `main` at `1943194` against the branch). Lines set before
the run:

- [x] **Target**: each of the four missed trees carries a high `SUP-010`: `dd-openclaw-hightower6eu-autoupdate`,
  `dd-openclaw-stveenli-browserautomation-skill`, `dd-openclaw-stveenli-shieldphenix`,
  `dd-openclaw-thiagoruss0-n8nsk`. Four of four.
- [x] **Malicious**: no sample flagged on `main` is unflagged on the branch.
- [x] **Benign**: no benign sample, alert-justified ones included, carries `SUP-010`; the samples flagged at high are
  the same as on `main`.
- [x] **Hard negatives**: the same samples flagged as on `main`.
- [x] **Held-out** (`heldout-all`, totals only): malicious flagged at least **40 more** than `main` (the prototype
  said 53; the built rule is tighter in three places, so the line is set below it); benign flagged at most one more
  than `main`.
- [x] **Fresh benign skills** (`fresh216`, `fresh200`, 416 trees): none carries `SUP-010`.
- [x] **Read, not gated**: a scan of the maintainer's own `~/.claude` on `main` and on the branch differs only by
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
| 3a | `main` merged after P-132, P-134 and P-133: `rulesEpoch` 22, `SUP-010` beside P-132's `SUP-011`; the eight static runs and the `~/.claude` reading repeated on the merged code | `Merge remote-tracking branch 'origin/main' into p/131-fake-prerequisite-lure` |
| 4 | Done, `complete/` or `rejected/`, the index row | `proposals: P-131 done (P-131)` |

## Open questions

Decided by the recommended answer unless the maintainer says otherwise (told on 2026-11-17 with the prototype's
figures):

1. **Severity.** High: the lure is the whole attack, and no benign tree in 5,202 measured carries a signal.
2. **Which platforms count for reason 3.** OpenClaw's family and the ones this tool's users run (Claude, Anthropic,
   OpenAI, ChatGPT, Codex, Cursor). The wider list was the one measured.
3. **Dimension.** Supply chain (5), beside `SUP-001` and `SUP-007`, but raised on documents too: the lure in one of
   the four trees is in the README its `SKILL.md` tells the agent to read.

## Readings

Static, threshold high, `main` at `1943194` (`rules=0352af8d2690`) against the branch at `aed5cbe`
(`rules=2997414a2a16`), both built 2026-11-17. Corpus `c314e4d9` (5,272 samples), the `heldout-all` list (459, layer 2,
not in the corpus) and two pools of fresh skills (212 and 200 trees; four of the 216 are no longer on disk):
`baselines/results/aguard/2026-11-17-p131-{corpus,heldout,fresh216,fresh200}-{main,changed}`. `compare.txt` in
`corpus-changed` has every line.

| line (set before the run) | main | branch | |
|---|---:|---:|---|
| the four missed trees carry a high `SUP-010` | 0 | **4** | 4 of 4 ✓ |
| malicious flagged, of 719; none lost | 231 | **235** | ✓ (the four targets, nothing else moved) |
| benign carrying `SUP-010`, of 4,534 | — | 0 | 0 ✓ |
| benign flagged at high, of 4,534 | 342 | 342 | same samples ✓ |
| hard negatives flagged, of 19 | 4 | 4 | same samples ✓ |
| **held-out malicious flagged, of 243** | 80 | **133** | at least 40 more ✓ (+53) |
| held-out benign flagged, of 216 | 6 | 6 | at most one more ✓ |
| fresh skills carrying `SUP-010`, of 412 | — | 0 | 0 ✓ |

**Held-out, by collection** (totals only; no held-out sample was read). The ClawHub trees: 68 → **121 of 123**;
`SUP-010` is on 112 of them, by reason archive 79, paste 35, platform 27 (a tree can carry more than one). The
SkillHarm trees: 12 → 12 of 120, none carries the rule. Benign: none carries it. The built rule is tighter than the
prototype in three places (the password cue, the paste cue without "copy", the prerequisite phrase on the same line)
and lands on the same 112 trees.

**Corpus.** Eight malicious trees carry the rule: the four targets; the two flagged before for an unrelated line
(`hightower6eu-clawhubcli`, `thiagoruss0-jirayb4nt`), which now have the lure as a reason; and two more DataDog trees
with a locked zip (`boomsystel…nanopdf`, `…yahoo-f…`), flagged before.

**Read, not gated: the maintainer's own `~/.claude`** (99 artifacts): the same 83 findings on both builds; the rule
does not fire.

**After the merge with P-132, P-134 and P-133** (`main` at `a66838b`, `rules=8cb81aaaae50`, against the branch at
`c9d91b8`, `rules=6e839a428eb8`, both built 2026-11-18): the eight runs repeated, and every line holds with the same
difference between the two sides. The merged proposals had moved `main`'s own figures on both sides alike (benign
flagged 342 → 337 of 4,534, the fresh skills flagged 34 → 33 of 412); nothing else moved. The four targets 0 → 4,
malicious 231 → 235 of 719 with none lost, benign 337 → 337 with `SUP-010` on none, hard negatives 4 → 4, held-out
malicious 80 → 133 of 243 (ClawHub 68 → 121 of 123, the rule on the same count of 112: archive 79, paste 35, platform
27) and held-out benign 6 → 6 of 216, fresh skills carrying the rule 0 of 412. The maintainer's `~/.claude` (100
artifacts): 83 findings on both builds, none of them `SUP-010`. Not committed as a second set of result directories.

## Done

The maintainer said to ship and merge it on 2026-11-18 ("好，发吧，合了"). The three open questions stand as
recommended: high, the platform list as written, documents read as well as `SKILL.md`.

```
Merged: PR #157 (find the date and sha with git log --grep P-131 after the merge)
Released: (fill in after the release)
Evidence: TestLureReason, TestLure_WhereItIsRead, TestLure_HiddenCharactersDoNotHideTheHost, TestLure_LineIsRedacted
  (internal/detect/lure_test.go); corpus c314e4d9 static, main 1943194 → branch aed5cbe: the four missed trees 0 → 4
  at high SUP-010, malicious 231 → 235 of 719 with none lost, benign 342 → 342 of 4,534 with SUP-010 on none, hard
  negatives 4 → 4 of 19; held-out, totals only: malicious 80 → 133 of 243 (ClawHub 68 → 121 of 123), benign 6 → 6 of
  216; fresh skills carrying SUP-010 0 of 412; the maintainer's ~/.claude 83 findings → 83, the rule on none
Evidence: after the merge with P-132, P-134 and P-133 (main a66838b → branch c9d91b8, rulesEpoch 22): the eight runs
  repeated, the same difference on every line (benign 337 → 337; P-134 had moved main's own figure)
Evidence: reverse: the benign twin of each reason in TestLureReason (the platform's own install page, a tool's own
  project page, a zip with an extraction tool, a paste link nobody is told to run), the code-file cases of
  TestLure_WhereItIsRead, TestLure_OrdinaryPrerequisitesRaiseNothing; make verify green
```
