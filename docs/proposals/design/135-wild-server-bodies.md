<!-- SPDX-License-Identifier: MIT -->
# 135 — Three in-the-wild npm MCP servers score 76 to 100: a payload written in invisible characters, a wallet file sent away, and a file run through an obfuscator

- **Source**: the maintainer, 2026-11-18 ("好": the small static blocks left after P-131); the in-the-wild misses
  read sample by sample
- **Depends on**: none
- **Branch**: `p/135-wild-server-bodies`

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

- [ ] `OBF-008` (high, dimension 6): a file the scan reads holds **four or more variation selectors in a row**
  (U+FE00–FE0F, U+E0100–E01EF). One finding per file, at the line of the first run; it says how many selectors the
  runs hold and the longest run, and its snippet shows that line with each run replaced by a count, never the
  characters. Raised on code, instruction files and documents alike.
- [ ] Reverse: an emoji followed by its selector, a keycap sequence, an ideograph with one selector, and a doubled
  selector (two in a row, a copy-paste slip) raise nothing.
- [ ] The credential leg reads crypto-wallet key stores: `wallet.dat`, `.ethereum/keystore`, `keystore/UTC--`,
  `.config/solana/id.json`, `Electrum/wallets`, `exodus.wallet`, and the MetaMask and Phantom extension store ids.
  The chain rules are otherwise unchanged: the same loopback downgrade, the same cross-file `EXFIL-002`.
- [ ] Reverse: a file that names a wallet store and has no egress leg gets no `EXFIL-001`/`EXFIL-003`.
- [ ] `OBF-009` (high, dimension 6): a script file holds **20 or more distinct identifiers of an obfuscator's
  form** (`_0x` followed by four or more letters or digits). One finding per file, at the first line holding one; it
  says how many.
- [ ] Reverse: a script with fewer than 20 such names, and a Markdown document that quotes obfuscated code, raise
  nothing.
- [ ] `rulesEpoch` 22 → 23, `make docs`, `TestEveryRuleIDIsDocumented` green; `make verify` green from its own exit
  code.

Measurement (static, threshold high, corpus `c314e4d9`, `main` at `f28029f` against the branch). Lines set before
the run:

- [ ] **Target**: each of the three trees is flagged at high for the reason above: `OBF-008` on
  `dd-npm-iflow-watercrawl-hidden-eval`, `EXFIL-001` or `EXFIL-003` on `dd-npm-todo-wallet-exfil`, `OBF-009` on
  `dd-npm-excluder-env-exfil`. Three of three.
- [ ] **Malicious**: no sample flagged on `main` is unflagged on the branch.
- [ ] **Benign**: no benign sample, alert-justified ones included, carries `OBF-008` or `OBF-009`; the samples
  flagged at high are the same as on `main`.
- [ ] **Hard negatives**: the same samples flagged as on `main`.
- [ ] **Held-out** (`heldout-all`, totals only): malicious flagged not fewer than on `main`; benign flagged not
  more than on `main`.
- [ ] **Fresh benign skills** (`fresh216`, `fresh200`, 412 trees): none carries `OBF-008` or `OBF-009`; the trees
  flagged at high are the same as on `main`.
- [ ] **Ordinary npm packages** (the 1,890 distinct packages installed on a developer machine, each given to
  `check` as a directory, on `main` and on the branch): none carries `OBF-008` or `OBF-009`, and none is flagged at
  high on the branch that is not on `main`.
- [ ] **Read, not gated**: a scan of the maintainer's own `~/.claude` on `main` and on the branch; what differs is
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
| 1 | `OBF-008`, the wallet stores in the credential leg, `OBF-009`, tests, epoch, generated rules doc | `detect: a run of variation selectors is OBF-008, obfuscator-renamed identifiers are OBF-009, and a wallet key store is a credential (P-135)` |
| 2 | `.claude/rules/detect.md` and the spec line | `docs: three shapes of a server body nobody can read (P-135)` |
| 3 | Static runs: corpus, held-out, fresh skills, the npm packages; main and branch | `baselines: P-135 static runs, main and branch (P-135)` |
| 4 | Done, `complete/` or `rejected/`, the index row | `proposals: P-135 done (P-135)` |

## Open questions

Decided by the recommended answer unless the maintainer says otherwise:

1. **`OBF-009` at high.** Recommended: high. A file made unreadable on purpose is the finding the tool exists for,
   and no benign file in 4,046 corpus files or 103,003 npm files carries the signature. The alternative is medium
   beside `BD-002`, which leaves `excluder` unflagged.
2. **The selector run's length.** Recommended: four. No measured file has two in a row; two is what a doubled emoji
   selector looks like, and a payload needs dozens.
3. **Wallet stores that no sample shows.** Recommended: the list as written. It is the same kind of list as
   `.ssh/` and `.aws/`, and none of its names occurs in any benign tree measured; two held-out malicious trees name
   the extension ids.
