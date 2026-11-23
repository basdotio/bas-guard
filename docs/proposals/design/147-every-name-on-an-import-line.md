<!-- SPDX-License-Identifier: MIT -->
# 147 — A network client imported after another name on its line is not seen, and a key posted through it is no finding at all

- **Source**: P-146's survey of the chain's readings (2026-11-20), where it was found and held back until a fix could
  ship with it; the maintainer, 2026-11-24 ("合然后修")
- **Depends on**: P-146 (merged), whose side-by-side tests take this proposal's two rows. P-095 set the rule being
  corrected
- **Branch**: `p/147-every-name-on-an-import-line`

## Problem

Since P-095 a URL literal in a script is a network leg of the exfiltration chain only when the script can send, and
"can send" is one list (`networkCapableRE`): an outbound action, or a client imported, required or constructed anywhere
in the file. Its Python alternative knew a client as the **first** name after `import`.

| a script that reads `DEEPL_API_KEY` and posts it to `https://collect.example.net/x` through `httpx` | `main` |
|---|---|
| begins `import httpx` | `EXFIL-001` high, 69/100 |
| begins `import os, httpx` | **nothing, 100/100** |

100/100 passes `check`, the load-time gate and `--fail-on high`. A client whose calls the action list names
(`requests.get`, `requests.post`) is not affected: the call is a leg by itself. For a client the action list does not
name (`httpx`, `aiohttp`, `websockets`, `http.client`, a raw `socket`) the import is the file's only sign of it, and the
second place on a line is an ordinary place to write it.

**How often it is written.** In the 8,162 code files of the corpus's skill and server trees, 23 import a listed client
after another name: 18 benign files (16 samples) and 5 malicious (5 samples). In 19 of them the file shows another way
to send (an action, another import), so the rules already knew. In 4, all benign, it is the only sign.

**Why not the wider answer.** The judge has a list of request calls (`requestLineRE`, P-117) that reads `httpx.post(…)`
as a request wherever the destination comes from. Giving it to the rules was sized in P-146's survey on the same files:
34 benign samples gain a high for one malicious sample. P-117 kept that list judge-only for this reason, and it stays
so.

## Initial direction

One alternative of one pattern. After `import`, any number of `name` or `name as alias` followed by a comma, then a
listed client as a whole name. `import os, httpx`, `import os,httpx`, `import json as j, requests as r` and
`import os, http.client` are read; `import os, httpx_mock` and `import os, socketserver` are other modules and are not.
No client is added to any list and no other list changes. `rulesEpoch` 30.

## Done criteria

The lines below were written before the branch was run. A prototype of the same one-line change had been run on all
four sets on 2026-11-20, before this proposal was written, and read no change on any; the lines are that reading and
the branch must reproduce it.

- [ ] `TestNetworkCapable_ReadsEveryNameOnAnImportLine` (`internal/detect/importline_test.go`): 18 lines; the client
  first, later, with aliases, with no space; no client; whole names only
- [ ] `TestChain_AClientImportedAfterAnotherName`: two scripts that post a key through a client imported second,
  `EXFIL-001` high; the same to the key's own service, low; reverse: imports with no client and a link in a message,
  nothing. The first three fail on `main`
- [ ] The two rows P-146 held back, in `TestChainReadings_SideBySide` and `TestNetworkClients_WhichListKnowsWhich`
- [ ] The table above as a one-skill fixture: 100/100 → 69/100 with `EXFIL-001` high
- [ ] Static, corpus: malicious flagged at least 243 of 719 and none loses a high; no benign sample gains a high (341 of
  4,534); hard negatives 4
- [ ] Static, fresh skills: 33 of 412, none gains a high
- [ ] Static, held-out, totals only: malicious at least 134 of 243; benign at most 6 of 216
- [ ] Reverse assertion: no finding is lowered on any set
- [ ] `rulesEpoch` 30, `docs/rules.md` regenerated, `make verify` green from its own exit code

## Out of scope

- **A request whose destination is not written in the file.** With no URL literal and no action the list names, the
  rules see no leg; the judge's request list reads it. That is P-117's decision and the 34-for-1 above.
- **Other languages.** The Node, Ruby and PowerShell alternatives name a module or a class in its own call or string,
  one per statement.

## Must not claim

- No benchmark number moves: no corpus, fresh or held-out sample is written this way with a key and a destination.
  This closes a way to be missed; it does not find a known sample.
- Not "the rules know every client". The list is what it was.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | The import alternative reads the line to its last name; tests; epoch 30; changelog; rules notes | `detect: a client imported after another name on its line is a way to send (P-147)` |
| 2 | Done, the index, `complete/` | `proposals: P-147 done (P-147)` |

## Open questions

1. **Python's `import` line only?** Recommended: **yes.** It is the one alternative that reads a position; the others
   read a module's name wherever it is written.

## Done

Filled in at stage 4.
