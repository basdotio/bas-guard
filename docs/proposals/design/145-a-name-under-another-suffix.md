<!-- SPDX-License-Identifier: MIT -->
# 145 — A Stripe key sent to `stripe.xyz`, and a webhook secret sent to `webhook.site`, are reported low: a word vouches for a host, whatever suffix it stands under and whether or not it names a service

- **Source**: P-144's Out of scope ("the same name under another top-level domain still vouches"); the maintainer,
  2026-11-20 ("堵上")
- **Depends on**: P-144 (only the registrable label vouches), P-061
- **Branch**: `p/145-a-name-under-another-suffix`

## Problem

`EXFIL-001` drops from high to a low advisory when a named credential goes to its own service, and "its own" is one
comparison: a word of the credential's name equals the registrable label of the host (P-061, narrowed to that label by
P-144). Two things about that word are never asked.

**Which suffix the service uses.** The label is `stripe` in `stripe.com` and in `stripe.xyz`, and anyone may register
the second. **Whether the word names a service at all.** `SLACK_BOT_TOKEN` yields `slack` and `bot`;
`GITHUB_PERSONAL_ACCESS_TOKEN` yields `github` and `personal`; `WEBHOOK_SECRET` yields `webhook`. Any of them vouches
for a host of that name, and `webhook.site` is a host of that name: a public request bin.

Measured on `main` at `0894372` (rules `8f9eb54a33f2`), one skill per row, the key read from the environment and
posted to the host:

| key | host | whose host | `EXFIL-001` on `main` |
|---|---|---|---|
| `STRIPE_SECRET_KEY` | `api.stripe.com` | Stripe's | low (right) |
| `STRIPE_SECRET_KEY` | `stripe.xyz`, `api.stripe.io` | whoever registered it | **low** |
| `GITHUB_TOKEN` | `api.github.xyz` | the same | **low** |
| `OPENAI_API_KEY` | `api.openai.net` | the same | **low** |
| `AWS_SECRET_ACCESS_KEY` | `sts.aws.xyz` | the same; AWS's API is under `amazonaws.com` | **low** |
| `NPM_TOKEN` | `registry.npm.dev` | the same; npm's registry is `npmjs.org` | **low** |
| `SLACK_BOT_TOKEN` | `bot.xyz` | the same | **low** |
| `GITHUB_PERSONAL_ACCESS_TOKEN` | `personal.dev` | the same | **low** |
| `GCP_SERVICE_ACCOUNT_KEY` | `service.xyz` | the same | **low** |
| `WEBHOOK_SECRET`, `DISCORD_WEBHOOK_TOKEN` | `webhook.site` | a public request bin | **low** |

A low advisory does not gate: 95/100, past `check`, the load-time gate and `--fail-on high`.

A rule about suffixes cannot close the first half. Replaying the chain over every file that carries the finding
(corpus and fresh skills, 561 files; `agent-guard-work/exfil-proto/zz_vouch_test.go`, local), 82 are low because
their host is their credential's own, through 54 different services. Most appear once, and their suffixes are whatever
they found: `.com` 40, `.ai` 16, `.io` 14, `.dev` 4, then `.org`, `.tech`, `.app`, `.to`, `.services`, `.de`, `.us`,
`.net` and, for one real service on two domains, `.xyz`.

## Initial direction

Three narrowings of the same comparison. None of them makes a host vouch that did not before.

1. **A table of known services and their domains** (`internal/detect/servicedomains.go`). For a token the table
   lists, a host vouches only when its registrable *domain* is one of the service's: `stripe` → `stripe.com`. An empty
   entry says no host named after the token is the service's (`aws`, `gcp`, `npm`, `datadog`, `jira`, `xai`: their
   APIs live under a domain of another name). A token the table does not list is matched by its label under any
   suffix, as today. What belongs in it: a service whose key an attacker would send to a look-alike (clouds, code
   hosts and registries, model and search APIs, payment and exchange accounts, messaging and workspace accounts), with
   domains known beyond doubt. A missing domain costs a false alarm on one real client; a wrong one would be a host
   that vouches for a key it has no claim to, so the table holds only domains whose registrable label is the token
   itself, and a test holds it to that.
2. **A known service owns its key's name.** When a credential's name carries a token the table lists, only the listed
   tokens of that name count: `GITHUB_ENTERPRISE_TOKEN` is `github`'s, and `enterprise.<anything>` has no claim to it.
   A name with two listed services keeps both (`AZURE_OPENAI_API_KEY`).
3. **Words that describe a credential are not services.** `bot`, `user`, `client`, `service`, `account`, `personal`,
   `admin`, `webhook`, `signing`, `refresh`, `session`, `prod`, `test`, `live` and their like (40 words) join the
   generic tokens that `key`, `token` and `api` already are, for every name, listed or not.

`rulesEpoch` 28 → 29. No rule is added and no rule's text changes.

## Done criteria

Code:

- [x] `TestServiceDomains_OnlyNarrow`: for every entry, each listed domain carries the token as its registrable label
  and is not a hosted suffix; the service's own hosts vouch; the same name under `.xyz`, `.io`, `.net`, `.dev`, `.top`
  and `.co.uk` does not, unless the service uses that suffix; a credential named for the token yields the token
- [x] `TestHostMatchesService_AKnownServiceUnderItsOwnDomains`: 18 rows, the listed and the unlisted
- [x] `TestCredentialServiceTokens_WordsThatNameNoService`: 12 names
- [x] `TestChain_AWordIsNotTheService`: the eleven low rows of the Problem table are `EXFIL-001` high through the
  engine (**red on `main`**: all eleven low); five keys that do go home stay low, an unlisted service on `.xyz` among
  them
- [x] One pinned row changes and says so: `openai.com.cn` vouched for `openai` and no longer does; an unlisted name
  takes its place as the country-suffix example
- [ ] Reverse assertions, green without a character changed in what they assert: every other row of
  `TestHostMatchesService` and `TestChain_DestinationResolvesSameFileBaseURL`, `TestChain_DestinationConsistency`, the
  judge's own-service rows
- [ ] `rulesEpoch` 29, `make docs`, `.claude/rules/detect.md`, `CHANGELOG.md`
- [ ] `make verify` green, read from its own exit code

Measurement (static, free), `main` at `0894372` (the runs of 2026-11-20 on the same content) against the branch.
Lines written on 2026-11-20 before the branch runs were read:

- [ ] **Malicious, corpus (719)**: no sample loses a finding at high. Flagged 243 → at least 243.
- [ ] **Benign, corpus (4,534)**: at most **3** samples gain a high. Each is listed with its key and host; a listed
  service found on a domain of its own that the table lacks is added, with the reason, before the line is read again.
- [ ] **Fresh real skills (412)**: at most **1** tree gains a high.
- [ ] **Held-out, totals only**: malicious flagged not lower than 134 of 243; benign flagged at most 7 of 216 (6 today).
- [ ] **No finding is lowered anywhere**: on every set, no sample has a finding at a lower severity than on `main`.
- [ ] The eleven low rows of the Problem table read high; `api.stripe.com` and four other keys that go home stay low.

## Out of scope

- **A service the table does not list.** `ACME_API_KEY` sent to `acme.xyz` still reads as a key sent home. The table
  is where a service is added once its domains are known.
- **A host that is the service's and carries no word of the key's name** (`sheets.googleapis.com` for a Sheets token,
  `registry.npmjs.org` for `NPM_TOKEN`). They do not vouch today and the table does not make them: it only narrows.
  Letting a listed service vouch through a domain of another name is a widening, with its own measurement.
- **Code a tenant runs on the service's own domain** (an edge function under a project's `supabase.co` host): the
  host is the service's and vouches, as today.
- **The judge.** Its own-service controls call the same function and move with it. No judge run is made.

## Must not claim

- Not "a look-alike domain cannot vouch". It cannot for the services in the table; for every other service it can,
  exactly as before.
- Not "the table is complete", of services or of a service's domains. A real client of a listed service on a domain
  the table lacks is reported high until the domain is added.
- No benchmark number improves. What is shown is the rows that change and the absence, or the size, of a cost.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | The table, the matcher, the owner of a name, the descriptive words; tests | `detect: a known service vouches only under its own domains, and a word that names no service vouches for nothing (P-145)` |
| 2 | `rulesEpoch` 29, `docs/rules.md`, `.claude/rules/detect.md`, `CHANGELOG.md` | (with W1) |
| 3 | Runs, readings into this file | `proposals: P-145 measured (P-145)` |
| 4 | Done, the index, `complete/` | `proposals: P-145 done (P-145)` |

## Open questions

All asked at once. Each has a recommended answer; the code is built under the recommendations.

1. **A table at all?** Recommended: **yes.** Which suffix a service uses is a fact about the world, and no rule over
   host names can supply it: the corpus's own services are on fourteen suffixes, `.xyz` among them. The repository is
   wary of lists; this one is closed under one test (it can only narrow) and each line is a public fact.
2. **Which services?** Recommended: **the seventy-seven in the code**, chosen by what their key is worth to someone
   else, not by how often they appear here. Smaller and it protects less; the long tail cannot be listed and is not.
3. **Empty entries** (`aws`, `gcp`, `npm`, `datadog`, `jira`, `xai`). Recommended: **yes.** Their API is under a domain
   of another name, so a host called `aws.<anything>` is never AWS's; saying so costs nothing real and closes the most
   valuable key of all.
4. **Narrowing only.** Recommended: **yes, in this proposal.** The same table could let `sheets.googleapis.com` vouch
   for a Google key and give back two of the three benign samples P-144 cost. That adds hosts that vouch, on domains
   where tenants store data, and deserves its own lines.
5. **The descriptive words.** Recommended: **the forty in the code.** Each is a word for a kind, a holder or a
   place of use. A real service whose whole name is one of them (`live.com`) stops vouching for a key named after it,
   which fails toward high.

## Done

Filled in at stage 4.
