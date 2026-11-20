<!-- SPDX-License-Identifier: MIT -->
# 144 — A Stripe key sent to `stripe.evil.net` is reported low: any label of a host may vouch for the credential's service

- **Source**: new finding (2026-11-20), while writing the adversarial files for P-142's trials; the maintainer, the same
  day ("要" to: fix it, and record it once fixed)
- **Depends on**: P-061, whose label rule this reverses in part
- **Branch**: `p/144-a-subdomain-is-not-the-service`

## Problem

`EXFIL-001` drops from high to a low advisory when every destination a file names belongs to the service of a
credential it reads (P-061): `DEEPL_API_KEY` sent to `api.deepl.com` is the key doing its job. "Belongs to" is
`hostMatchesService`: a label of the host equals a token of the credential's name.

P-061 let **any** label vouch. Its first draft allowed only the registrable label and turned three benign servers
high (`purdue.brightspace.com` for `PURDUE_PASSWORD`, `otx.alienvault.com` for `OTX_API_KEY`, `data-platform.mlit.go.jp`
for `MLIT_API_KEY`: a tenant, a product and a country's second level), so the shipped rule excludes two positions
only: a label followed by a TLD-like label short of the host's end (`api.openai.com.evil.net`), and a platform's own
label under a hosted suffix (`evil.github.io`).

Every label left of the registrable one is chosen by whoever holds the domain. Measured on `main` at `c96baf7`
(rules `64f57c6f747c`), a skill whose script reads `STRIPE_SECRET_KEY` and posts it:

| the host the key is sent to | whose it is | `EXFIL-001` on `main` |
|---|---|---|
| `api.stripe.com` | Stripe's | low (right) |
| `api.stripe.com.evil.net` | evil.net's | high (P-061's case) |
| `stripe.com-api.example.net` | example.net's | **low** |
| `stripe.example.net` | example.net's | **low** |
| `api.stripe.payments.example.net` | example.net's | **low** |
| `stripe.vercel.app`, `stripe.pages.dev` | whoever took the name first | **low** |

A low advisory does not gate: the file scores 95/100 and passes `check`, the load-time gate and `--fail-on high`,
while sending a named key to a host its author registered. The same function answers the judge's own-service
controls (P-062, P-089, P-098), which lower a `credential-read` vote on its word.

No sample in the corpus uses the spelling; the hole was found by reading the tool.

## Initial direction

Only the **registrable label** may vouch: the label directly left of the top-level domain, or of a country's second
level (`mlit.go.jp`, `coles.com.au`), which a short list of second-level labels decides (no dependency is added; the
public-suffix list is not vendored). Under a hosted platform's suffix nothing vouches: the platform's label is not the
party, and the label left of it is a name the platform gives to whoever asks.

This takes back two of P-061's three benign hosts, the tenant and the product; the third is kept by reading the
country second level properly. A machine named after a service on someone's tailnet (`reelql.tail6c0e2d.ts.net`,
P-061's own example) no longer vouches either. The measurement below says how many benign samples that is today.

`rulesEpoch` 26 → 27 (28 if P-143 lands first). No rule is added and no rule's text changes.

## Done criteria

Code:

- [x] `TestHostMatchesService` (`internal/detect/destination_test.go`): the registrable label vouches, under a plain
  TLD and under a country's second level; a subdomain named after the service, one dressed as its domain, a deeper
  one, a tenant, a product subdomain, any name under a hosted suffix, a lookalike, a homoglyph and a single label do
  not. **Red on `main`**: `stripe.evil.net`, `stripe.com-api.evil.net`, `api.stripe.payments.evil.net`,
  `stripe.vercel.app`, `stripe.pages.dev`
- [x] `TestChain_DestinationResolvesSameFileBaseURL`: a new row, `STRIPE_SECRET_KEY` to
  `stripe.com-api.example.net`, is `EXFIL-001` high; the tailnet row is high and says why it changed
- [x] Reverse assertions, green without a character changed in what they assert: every other row of that table (the
  own-service shapes that must keep downgrading), `TestChain_*`, the judge's `TestRun_*GoesHome*` rows
- [x] `rulesEpoch` 27, `make docs`, `.claude/rules/detect.md`, `CHANGELOG.md`
- [ ] `make verify` green, read from its own exit code

Measurement (static, free), `main` at `57ae417` (the 2026-11-19 runs; rules `64f57c6f747c`, as `c96baf7`) against
the branch (`agent-guard-work/runs/2026-11-20-p144-strict-*`). Lines written on 2026-11-20 before the branch runs
were read:

- [x] **Malicious, corpus (719)**: no sample loses a finding at high. Flagged 243 → at least 243. *243 → 243. One
  malicious sample has one more file at high: its original PubMed client, `NCBI_API_KEY` to
  `eutils.ncbi.nlm.nih.gov`.*
- [x] **Benign, corpus (4,534)**: at most **10** samples gain a high. *337 → 340: three, and no other finding of any
  benign sample differs.*

  | sample | credential | host | what the label was |
  |---|---|---|---|
  | `ben-mcp-gh-jalacloud-mcp-cti-otx` | `OTX_API_KEY` | `otx.alienvault.com` | a product subdomain (P-061's own example) |
  | `ben-skill-md-vm0-ai-vm0-skills-google-sheets` | a `GOOGLE_SHEETS_…` token | `sheets.googleapis.com` | a product subdomain |
  | `ben-skill-gh-tomascupr-reelql-reelql` | `REELQL_API_KEY` | `reelql.tail6c0e2d.ts.net` | a tailnet machine name (P-061's own example) |

- [x] **Fresh real skills (412)**: at most **3** trees gain a high. *0: no finding differs (24 of 200 and 9 of 212
  flagged, before and after).*
- [x] **Held-out, totals only**: malicious flagged not lower than 134 of 243; benign flagged at most 7 of 216.
  *134 and 6, as before.*
- [x] The four rows of the Problem table that read low on `main` read high; `api.stripe.com` stays low. *Each host as
  a skill of its own, both binaries: 95/100 → 69/100 on the five hosts of those four rows; `api.stripe.com` 95/100 on
  both; `stripe.xyz` 95/100 on both (Out of scope, first item).*

## Out of scope

- **The same name under another top-level domain.** `stripe.xyz` carries the registrable label `stripe` and still
  vouches, as `openai.com.cn` does today. Telling a vendor's real domain from its name under another suffix needs
  knowledge of vendors, which this rule does not have.
- **A reference carried on into another host** (`${API}.evil.net`, `API + ".evil.net"`): P-143.
- **The judge.** Its own-service controls call this function and move with it. No judge run is made for this
  proposal; a benign server whose `credential-read` vote was lowered through a subdomain label may weigh high again,
  and that is read on the next judge run, not claimed here.
- **A vendored public-suffix list.** A fourth dependency or a 200 KB table for a rule that needs "which label is the
  organisation's" on the hosts skills actually call.

## Must not claim

- Not "a key sent to its own service is never flagged". A service reached through a tenant or product subdomain of
  another registrable name (`otx.alienvault.com`) is flagged again, by decision.
- Not "a lookalike host cannot vouch". See Out of scope, first item.
- The benign samples that gain a high are false positives on the scorecard, whatever the reason.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | `hostMatchesService` reads the registrable label, with a country's second level, and nothing under a hosted suffix; tests | `detect: only a host's registrable label vouches for a credential's service (P-144)` |
| 2 | `rulesEpoch`, `docs/rules.md`, `.claude/rules/detect.md`, `CHANGELOG.md` | `detect: rules epoch for the label that may vouch (P-144)` |
| 3 | Runs, readings into this file | `proposals: P-144 measured (P-144)` |
| 4 | Done, the index, `complete/` | `proposals: P-144 done (P-144)` |

## Open questions

1. **Give up the tenant and the product subdomain?** Recommended: **yes.** P-061 kept them for two benign servers
   and the same sentence of the rule is what lets `stripe.evil.net` through; nothing in a host name separates the two.
   The benign line above is the bound on what that may cost.
   **Built under the recommendation (2026-11-20), not yet answered**: it costs the three benign samples in the table
   above, two of them through a product subdomain. This is the question the maintainer decides before it ships.
2. **A tailnet machine name.** Recommended: **does not vouch.** A tailnet's machine names are its owner's to choose,
   and a tailnet can be published.
   **Built under the recommendation (2026-11-20), not yet answered**: one of the three.
3. **The list of country second-level labels.** Recommended: **the sixteen in the code** (`co`, `com`, `org`, `net`,
   `gov`, `go`, `ac`, `edu`, `or`, `ne`, `mil`, `gob`, `gouv`, `govt`, `nom`, `sch`), applied only before a two-letter
   top-level domain. A label missing from it makes a real organisation's host read as not its own, which fails toward
   high.

## Done

Filled in at stage 4.
