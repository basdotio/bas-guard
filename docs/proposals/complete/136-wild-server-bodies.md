<!-- SPDX-License-Identifier: MIT -->
# 136 — Three in-the-wild npm MCP servers score 76 to 100: a payload written in invisible characters, a wallet file sent away, and a file run through an obfuscator

- **Source**: the maintainer, 2026-11-18 ("好": the small static blocks left after P-131); the in-the-wild misses
  read sample by sample
- **Depends on**: none
- **Branch**: `p/136-wild-server-bodies`

## Problem

Three MCP servers captured from npm (DataDog's malicious-packages dataset) are still read as ordinary code. Each
hides its one bad act a different way, and each way is a shape of the file, not a dangerous word on a line:

| sample | what it does | today |
|---|---|---|
| `dd-npm-iflow-watercrawl-hidden-eval` | `src/index.ts` holds **9,123 variation selectors on one line**: characters that draw nothing. Eight lines above, a function turns each back into a byte, and `eval` runs the result | 76; `EXEC-003` low on the `eval`, nothing on what it evaluates |
| `dd-npm-todo-wallet-exfil` | a working todo server whose `add_todo` globs `$HOME` for `wallet.dat`, base64-encodes it and POSTs it as the todo's text to a hard-coded address | **100, no finding** |
| `dd-npm-excluder-env-exfil` | `index.js` is obfuscator output (85 `_0x…` names; the file names it reads, `.env` and wallet key files, are built from `String.fromCharCode` lists) and hands what it reads to `utils.js`, which POSTs it | 88; `BD-002` medium, advisory |

Why nothing fires:

- **The selectors.** `INJ-004` knows zero-width and bidi characters and `INJ-006` knows tag characters. Variation
  selectors (U+FE00–FE0F and U+E0100–E01EF) are in neither: one after an emoji or an ideograph is ordinary text.
  A run of them is not text at all.
- **The wallet.** The exfiltration chain's credential leg knows `.ssh/`, `.aws/`, `/etc/passwd`, `id_rsa`, dotenv
  files read by a shell verb, and secret-named environment variables. A crypto wallet's key store is on no list, so
  "reads `wallet.dat`, encodes it, sends it" is a file with an egress leg and no credential leg.
- **The obfuscator.** No rule asks whether a file can be read by a person. Minified code is common and is left
  alone; identifiers renamed to `_0x1a2b3c` are a different thing, done so that nobody reviews the file.

A prototype of the candidate signals (`agent-guard-work/jsbody-proto.py`, `jsbody-npm-pool.py`; offline, reads
files, runs nothing):

| signal | malicious, of 719 | benign, of 4,534 | fresh skills, of 412 | held-out, totals only (243 / 216) | ordinary npm source, 103,003 files |
|---|---:|---:|---:|---:|---:|
| two or more variation selectors in a row | 1, missed today | 0 | 0 | 0 / 0 | 0 |
| a crypto-wallet store named, any text file | 1, missed today | 0 | 0 | 2 / 0 | 0 |
| 20 or more distinct `_0x…` identifiers in a code file | 2, one missed today | 0 | 0 | 0 / 0 | 0 |
| a request URL on a public IP address, code file | 4, two missed today | **3**, two not flagged today | 0 | 0 / 0 | not measured |
| cryptominer words (`xmrig`, `stratum+tcp://` …) | 5, two missed today | 0 | **1** | 0 / 0 | not measured |

The benign corpus holds 391 trees with JavaScript or TypeScript (4,046 files). The npm pool is the packages
installed on a developer machine (1,890 distinct name@version), unlabelled and read as ordinary code; in one of its
two halves (16,995 files) not a single `_0x…` identifier occurs, while 189 files call `String.fromCharCode` and 12
hold a lone variation selector, so the zeros are not a scan that read nothing.

The last two rows are not clean and are not built: three benign servers hard-code their own back end by address
exactly as the two malicious ones do, and a repository-auditing skill lists miner names as the patterns it looks for.

## Initial direction

Three small changes, each on the static side, measured on the static bench (free):

1. a file-level check for a run of variation selectors (`OBF-008`);
2. crypto-wallet key stores join the credential leg of the exfiltration chain, so `EXFIL-001` / `EXFIL-003` follow
   as they do for `.ssh/`;
3. a file-level check for obfuscator-renamed identifiers in a script (`OBF-009`).

## Done criteria

Code:

- [x] `OBF-008` (high, dimension 6): a file the scan reads holds **four or more variation selectors in a row**
  (U+FE00–FE0F, U+E0100–E01EF) **that are not all the same one**. One finding per file, at the line of the first
  run; it says how many selectors the runs hold and the longest run, and its snippet shows that line with each run
  replaced by a count, never the characters. Raised on code, instruction files and documents alike.
  *The words in the second bold were added after the first run: the rule as first written failed the npm line below
  (Readings, "Changed after a reading"). The measurement lines were not touched.*
- [x] Reverse: an emoji followed by its selector, a keycap sequence, an ideograph with one selector, a doubled
  selector, and one selector repeated four or forty times raise nothing.
- [x] The credential leg reads crypto-wallet key stores: `wallet.dat`, `.ethereum/keystore`, `keystore/UTC--`,
  `.config/solana/id.json`, `Electrum/wallets`, `exodus.wallet`, and the MetaMask and Phantom extension store ids.
  The chain rules are otherwise unchanged: the same loopback downgrade, the same cross-file `EXFIL-002`.
- [x] Reverse: a file that names a wallet store and has no egress leg gets no `EXFIL-001`/`EXFIL-003`; nor does a
  wallet API client or a Java `.keystore`.
- [x] `OBF-009` (high, dimension 6): a script file holds **20 or more distinct identifiers of an obfuscator's
  form** (`_0x` followed by four or more letters or digits). One finding per file, at the first line holding one; it
  says how many.
- [x] Reverse: a script with fewer than 20 such names, a Markdown document that quotes obfuscated code, minified
  code and a table of hex literals raise nothing.
- [x] `rulesEpoch` 22 → 23, `make docs`, `TestEveryRuleIDIsDocumented` green; `make verify` green from its own exit
  code.

Measurement (static, threshold high, corpus `c314e4d9`, `main` at `f28029f` against the branch). Lines set before
the run:

- [x] **Target**: each of the three trees is flagged at high for the reason above: `OBF-008` on
  `dd-npm-iflow-watercrawl-hidden-eval`, `EXFIL-001` or `EXFIL-003` on `dd-npm-todo-wallet-exfil`, `OBF-009` on
  `dd-npm-excluder-env-exfil`. Three of three.
- [x] **Malicious**: no sample flagged on `main` is unflagged on the branch.
- [x] **Benign**: no benign sample, alert-justified ones included, carries `OBF-008` or `OBF-009`; the samples
  flagged at high are the same as on `main`.
- [x] **Hard negatives**: the same samples flagged as on `main`.
- [x] **Held-out** (`heldout-all`, totals only): malicious flagged not fewer than on `main`; benign flagged not
  more than on `main`.
- [x] **Fresh benign skills** (`fresh216`, `fresh200`, 412 trees): none carries `OBF-008` or `OBF-009`; the trees
  flagged at high are the same as on `main`.
- [x] **Ordinary npm packages** (the 1,890 distinct packages installed on a developer machine, each given to
  `check` as a directory, on `main` and on the branch): none carries `OBF-008` or `OBF-009`, and none is flagged at
  high on the branch that is not on `main`.
- [x] **Read, not gated**: a scan of the maintainer's own `~/.claude` on `main` and on the branch; what differs is
  reported.

## Out of scope

- **One variation selector inside a word.** `Ignore all prev<U+FE00>ious instructions` in a `SKILL.md` scores 100
  with no finding, while the same sentence with a zero-width space is `INJ-001` and `INJ-004` (reproduced on
  `f28029f` while measuring this). That is a change to the view every rule matches, with its own measurement, and is
  a proposal of its own.
- Decoding what a run of selectors or a `String.fromCharCode` list spells, so that other rules read it.
- A request to a literal public IP address, and cryptominer words: measured above, not clean.
- Other naming schemes an obfuscator can be set to (mangled, dictionary), packers, hex-escaped strings.
- The judge.

## Must not claim

- Not "detects obfuscated JavaScript". `OBF-009` reads one naming signature, the default of the most used
  obfuscator; a file renamed to `a`, `b`, `c` reads as minified code and is left alone.
- Not "finds hidden payloads". `OBF-008` reports the carrier and how much it can hold; it does not decode it, and a
  payload spread one selector at a time between visible characters is not a run.
- Each rule is one or two samples on the malicious side. What was measured widely is the benign side.
- The wallet stores are a list. A wallet that keeps its keys somewhere else is not on it.

## Work items

| W | In one sentence | Commit message |
|---|---|---|
| 1 | `OBF-008`, the wallet stores in the credential leg, `OBF-009`, tests, epoch, generated rules doc | `detect: a run of variation selectors is OBF-008, obfuscator-renamed identifiers are OBF-009, and a wallet key store is a credential (P-136)` |
| 2 | `.claude/rules/detect.md` and the spec line | `docs: three shapes of a server body nobody can read (P-136)` |
| 1a | The lure test of P-131 held a literal zero-width character; written as an escape, as `logical.go` asks | `detect: the lure test writes its zero-width character as an escape (P-131)` |
| 1b | After the first run: a selector run counts only when its selectors differ | `detect: OBF-008 needs a run whose selectors differ; one selector repeated carries nothing (P-136)` |
| 3 | Static runs: corpus, held-out, fresh skills, the npm packages; main and branch | `baselines: P-136 static runs, main and branch (P-136)` |
| 4 | Done, `complete/` or `rejected/`, the index row | `proposals: P-136 done (P-136)` |

**Numbering.** This proposal was opened as P-135 on the same day the release record of v0.37.0 took that number (PR #161, opened first). It is P-136 from the commit `proposals: P-135 is the release record of v0.37.0, this proposal is P-136 (P-136)` on; the five commits before it that say `(P-135)` in their messages are this proposal's. Nothing was rewritten.

## Open questions

Decided by the recommended answer unless the maintainer says otherwise:

1. **`OBF-009` at high.** Recommended: high. A file made unreadable on purpose is the finding the tool exists for,
   and no benign file in 4,046 corpus files or 103,003 npm files carries the signature. The alternative is medium
   beside `BD-002`, which leaves `excluder` unflagged.
2. **The selector run's length.** Recommended: four. ~~No measured file has two in a row~~ — wrong: the prototype
   read source files only, and the engine reads every file. Read over every file, ordinary packages hold runs of two
   and one of four, all of them one selector repeated. Four stays, and the run must hold selectors that differ
   (Readings).
3. **Wallet stores that no sample shows.** Recommended: the list as written. It is the same kind of list as
   `.ssh/` and `.aws/`, and none of its names occurs in any benign tree measured; two held-out malicious trees name
   the extension ids.

## Readings

Static, threshold high, `main` at `f28029f` (`rules=6e839a428eb8`) against the branch at `9e8ab98`
(`rules=fbe3f98553bb`), both built 2026-11-18. Corpus `c314e4d9` (5,272 samples), the `heldout-all` list (459, layer
2, not in the corpus), two pools of fresh skills (212 and 200 trees), and the 1,890 distinct npm packages installed
on a developer machine, each given to `check` as a directory:
`baselines/results/aguard/2026-11-18-p136-{corpus,heldout,fresh216,fresh200}-{main,changed}`; `compare.txt` in
`corpus-changed` has every line, the npm one included (its per-package results name a machine's packages and are not
committed).

| line (set before the run) | main | branch | |
|---|---:|---:|---|
| the three trees flagged at high for the reason set | 0 | **3** | `OBF-008`, `EXFIL-003`, `OBF-009` ✓ |
| malicious flagged, of 719; none lost | 235 | **238** | ✓ (the three targets, nothing else moved) |
| benign carrying `OBF-008` or `OBF-009`, of 4,534 | — | 0 | 0 ✓ |
| benign flagged at high, of 4,534 | 337 | 337 | same samples ✓ |
| hard negatives flagged, of 19 | 4 | 4 | same samples ✓ |
| held-out malicious flagged, of 243 | 133 | 133 | not fewer ✓ |
| held-out benign flagged, of 216 | 6 | 6 | not more ✓ |
| fresh skills carrying either rule, of 412; flagged | — ; 33 | 0 ; 33 | same trees ✓ |
| npm packages carrying either rule, of 1,890; flagged at high | — ; 37 | 0 ; 37 | none newly flagged, no (rule, severity) pair differs ✓ |

One sample that was already flagged gains a reason: `dd-npm-antv-mcp-chart-preinstall` (6,315 obfuscator names) now
carries `OBF-009` beside its `SUP-008`. The held-out set gains nothing: the two held-out malicious trees that name a
wallet extension id were flagged on `main` already.

**Changed after a reading.** The first build (`5d40013`) raised `OBF-008` on four or more selectors in a row, as
the criterion then read, and **failed the npm line: one of 1,890 packages, `focus-trap@7.6.0`, carried the rule
and was newly flagged at high.** The contributors table of its README holds U+FE0F four times running before an
emoji. The prototype had read source files only; the engine reads every file. Read again over every file
(`agent-guard-work/vs-runs-allfiles.py`): 149,654 files in the npm pool hold six runs of two or more selectors,
five of length two and one of length four, **every one of them U+FE0F repeated**; the corpus and the fresh skills
hold none but the carrier, which is 9,123 selectors long and holds 60 different ones. A repeated selector carries
no data, so the rule now asks that the run's selectors differ (`9e8ab98`); the reverse test has the README's line.
Every branch-side run was repeated on that build and the table above is from it. No line was changed.

**The npm pool as a reading of `main`.** 37 of the 1,890 ordinary packages carry a high finding on `main` and on
the branch alike. That is not this proposal's to change; it is the first figure for how a `check` of an arbitrary
npm package reads, and it is recorded here because nothing else in the repository measures it.

**Read, not gated: the maintainer's own `~/.claude`** (100 artifacts): the same 83 findings on both builds; neither
rule fires.

## Done

The maintainer said to merge it on 2026-11-18 ("好，都合了"). The three open questions stand as recommended:
`OBF-009` at high, a run of four selectors that differ, the wallet list as written.

```
Merged: PR #163 (2026-11-17 UTC; find the sha with git log --grep P-136)
Released: v0.38.0
Evidence: TestSelectorRun_IsACarrier, TestObfuscatorNames, TestWalletStore_IsACredential
  (internal/detect/unreviewable_test.go); corpus c314e4d9 static, main f28029f → branch 9e8ab98 (rulesEpoch 23): the
  three missed trees 0 → 3 at high (OBF-008, EXFIL-003, OBF-009), malicious 235 → 238 of 719 with none lost, benign
  337 → 337 of 4,534 with neither rule on any, hard negatives 4 → 4 of 19; held-out, totals only: malicious 133 → 133
  of 243, benign 6 → 6 of 216; fresh skills carrying either rule 0 of 412; npm packages carrying either rule 0 of
  1,890, 37 flagged at high on both builds; the maintainer's ~/.claude 83 findings → 83, neither rule on any
Evidence: the first build (5d40013) failed the npm line on one package (focus-trap@7.6.0, U+FE0F four times running
  in a README); the rule was narrowed to selectors that differ, every branch-side run repeated, no line changed
  (Readings, "Changed after a reading")
Evidence: reverse: TestSelectorRun_OrdinaryTextRaisesNothing (emoji with their selectors, the README's repeated
  selector at four and at forty), the below-threshold, document and minified cases of TestObfuscatorNames, a wallet
  store named with nothing sent and a keystore of another kind in TestWalletStore_IsACredential; make verify green
```
