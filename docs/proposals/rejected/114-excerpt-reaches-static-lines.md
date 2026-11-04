<!-- SPDX-License-Identifier: MIT -->
# 114 — A server's injected payload sits on a line the rules already flagged, and the judge is never shown that line

- **Source**: the maintainer, 2026-11-04 ("yes" to the order: excerpt first, then the server categories, then TypeScript
  servers), after the full-corpus comparison of the same day (corpus `c314e4d9`, 5,272 samples)
- **Depends on**: none
- **Branch**: `p/114-excerpt-reaches-static-lines` (the code is reverted in the same branch; the measurement and this record stay)
- **Rejected**: 2026-11-05 — by the acceptance line decided in advance (open question 5). Recall cleared it: `mcp-variants` 32 → 42 of the
  52 server-kind trees. The benign side did not: escalating `LLM-010` on benign servers went 60 → 96 of about 620, against a line of 66.
  The rise is the windows, not the rerun: on the trees whose payload did not change it was 33 → 30. See Measured.

## Problem

The server pass (`LLM-010`, P-053) reads `behaviorExcerpt`: each file is condensed and cut to its first 2/3 and last 1/3
inside 2,000 bytes, and the whole tree stops at 6,000 bytes in walk order. A payload in the middle of a large file, or in
a file past the third, is never in front of the model.

The corpus's `mcp-variants` source (57 malicious servers, added 2026-11-02) is built in exactly that shape: a real
open-source MCP server with an attack spliced into it. On the full-corpus run of 2026-11-04 (`v0.33.1-3-g5a18a6db`,
gpt-4.1-mini, `samples: 3`):

- 21 of the 57 are missed by static + judge; on 14 of them the judge cast **no vote at all**.
- The spliced line is typically far from both ends: `claudemcp.py` 50 KB with the payload at byte ~30,800;
  `awslabs/iam_mcp_server/server.py` 55 KB at byte ~3,900, in a tree of 16 code files; `aws-pricing` 68 KB at ~8,000 in a
  tree of 26.
- **On 12 of 20 of those misses a static finding is already on the payload line or within ten lines of it**, mostly
  `EXEC-004` medium on `subprocess.run(command, shell=True, …)`, a few `EXFIL-004` medium. The scanner knows where to
  look; the excerpt does not use that.
- cc-audit 3.23.9 flags 48 of the 57; BAS Guard with the judge 36. This is one of the four sources where the static-only
  competitor is ahead of the judge.

The per-sample list of misses and the four-tool comparison are kept with the maintainer, not committed; the run's
verdicts can be regenerated with `baselines/cmd/baseline` and `judgefold` at the commits above.

**How this differs from P-070** (rejected): P-070 reordered which *files* the shared 6,000 bytes went to, for skills, by what
`SKILL.md` names; the payloads it pushed out cost as much as it gained, and on SkillHarm the misses turned out to be
judgement. Here the anchor is not a guess from prose but a deterministic finding's `file:line`. The window around it
would not compete with the existing budget, and the population is servers, where the payload is code.

## Initial direction

When an artifact going to the server pass (and possibly the skill intent pass, to be measured separately) has static
findings at medium or above, `behaviorExcerpt` adds a small window around each finding's line: a few lines either side,
condensed and redacted like any unit, with a `lineMap` so grounding cites the real line. The windows get a budget of their
own, so a tree with no static finding sends exactly the bytes it sends today, and the walk-order excerpt is not shortened.
This means no new call, no new question and no prompt change. `ExcerptVersion` goes 9 → 10.

Measure on the 57 `mcp-variants`, the 127 Cisco servers, and the 621 benign Python server trees in the corpus (the
development denominator of P-059 plus the 2026-10-21 re-harvest). Watch the benign side: a window around a benign
`subprocess.run` is exactly what might push `remote-execution` votes up (`issues/028`).

## Done criteria

Code (judge package, server pass only). Every item below was done and green (`make verify`), then reverted when the
measurement failed:

- [ ] `TestServerExcerpt_FlaggedLineReachesTheModel` pins the main case. The fixture is a server tree whose one 40 KB file
  holds a payload line in the middle, with a medium static finding on it. The payload line is in `Request.Behavior`, and a
  quote of it grounds to its **original** line number (through the window's `lineMap`).
- [ ] Reverse assertion, `TestServerExcerpt_NoAnchorSendsTodaysBytes`: a server tree with no anchoring finding sends
  `Behavior` byte-identical to `behaviorExcerpt` alone. Three variants are no anchor, a low finding, and an advisory
  finding.
- [ ] Reverse assertion, `TestServerExcerpt_WalkOrderExcerptIsNotShortened`: with anchors present, the walk-order part of
  `Behavior` is byte-identical to the anchorless one. The windows are added; nothing the judge saw before is pushed out
  (the way P-070 failed).
- [ ] `TestServerExcerpt_WindowAlreadyShownIsNotRepeated`: a finding whose window lies inside the head or tail
  `capHeadTail` already kept adds nothing.
- [ ] `TestServerExcerpt_AnchorRespectsTheBoundary`: the windows open files only through `collect.FileReach`
  (invariant #2). A finding whose evidence file is a symlink out of the root, or not in the tree, adds no window.
- [ ] Redaction before the cut (invariant #3): each window is cut from the file **after** `eg.redact` of the whole file.
  `FuzzPlanFields` gains static findings in its generated server trees, and checks the server `behavior` field against
  its new cap (`maxExcerptBytes + maxAnchorBytes`), UTF-8 validity and the `Redact` fixed point.
- [ ] `ExcerptVersion` 9 → 10, and `excerpt_version_test.go` pins the new pair. The fixture gains a server artifact
  with a finding past its head and tail.
- [ ] `go test -count=1 ./baselines/cmd/judgefold/` green; the goldens are regenerated only if they really move, and the
  diff is read line by line.
- [ ] `make verify` green.

Measurement (live, gpt-4.1-mini, `samples: 3`, corpus `c314e4d9`). The main reading is the full-corpus run of
2026-11-04 (`v0.33.1-3-g5a18a6db`, the same `main` this branches from); the branch is run on:

- [ ] the 57 `mcp-variants` servers: static + judge **36 → at least 41**;
- [ ] the 127 Cisco servers: no lower than today's 102 minus the run band (P-100 saw 103–107 across reruns, so ≥ 98);
- [ ] every benign tree the server pass asks (621 on 2026-11-04): escalating `LLM-010` **60 → at most 66** (one point of
  621). Each new escalation gets its category listed, so a `remote-execution` rise (`issues/028`) is visible as such.
- [ ] Judge usage of the branch run, against main's on the same trees: calls equal (no new question); prompt tokens up by
  the windows only.
- [ ] Result directories under `baselines/results/aguard/2026-11-NN-llm-gpt-4.1-mini-p114-*`, raw archive on the next
  release, as P-100 did.

Docs:

- [ ] `docs/llm-judge.md` and `docs/llm-judge.zh-CN.md` (the pair): the server pass's excerpt adds windows around
  medium-or-above static findings.
- [ ] `.claude/rules/judge.md`: one paragraph on what not to change, namely the separate budget (do not fold it into the
  6,000 bytes, P-070's failure), the neutral window header, and server pass only.

## Out of scope

- **The skill intent pass and every other pass.** `behaviorExcerpt` is shared, but the skill call site does not
  change; the review package shows `planFor`'s `KindSkill` branch untouched. SkillHarm's misses were judgement, not
  visibility (P-070), and that pass would need its own measurement.
- **The walk-order excerpt**: per-file 2,000, total 6,000, head two-thirds and tail one-third, walk order. None of it
  changes.
- **The prompt, the category tables, the vote count**: P-115's ground. `PromptVersion` must not move.
- **TypeScript servers** (P-116), triage, and the static rules (no `rulesEpoch` change).
- **Following imports or calls from the flagged line** into other files: the static chain's business (P-061).

## Must not claim

- Not "the judge reads the whole server". It reads the head and tail of a few files, plus a few lines around what the
  rules flagged at medium or above. A payload no rule flags, in the middle of a large file, is exactly as invisible as
  before.
- `mcp-variants` gains are on spliced synthetic servers from one source, and after this proposal that source has been
  looked at. Do not quote them as an in-the-wild or held-out rate.
- The window header must not say that a rule flagged the line, and no doc may describe the windows as "showing the judge
  the static findings". The model is shown code, not the scanner's opinion (see open question 4).

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | Anchor windows for the server pass: `anchorWindows` (own budget, `FileReach`, redact before cut, line map, de-duplicated against head/tail), appended after the walk-order excerpt; tests above | `judge: the server pass also sees the lines the rules flagged (P-114)` |
| 2 | `ExcerptVersion` 10 and the golden pair; `FuzzPlanFields` grows findings and the new cap | `judge: excerpt version 10 for the server pass's anchor windows (P-114)` |
| 3 | Docs pair and `.claude/rules/judge.md` | `docs: the server pass's anchor windows (P-114)` |
| 4 | Branch run on the three sets; result directories; readings into this file | `baselines: P-114 on mcp-variants, Cisco and the benign servers (P-114)` |
| 5 | The "Done" section, `git mv` to `complete/` (or `rejected/` if the benign line fails) | `proposals: P-114 done (P-114)` |

## Open questions

All asked at once. Each has a recommended answer.

1. **Server pass only, or the skill intent pass too?** Recommended: **server only.** P-070 measured the skill side, and its
   misses were judgement. Skills can get their own proposal with their own measurement if the server side works.
2. **Which findings anchor a window?** Recommended: **deterministic (`score.Deterministic`), medium or above, not
   advisory, with a line > 0**, de-duplicated by (file, line). Low and advisory findings (`RES-001`, `SUP-003`) sit on
   every benign server's `while True:` and import line; they would spend the budget on noise.
3. **Window size and budget.** Recommended: **±6 original lines, condensed the way `behaviorExcerpt` condenses, at most
   4 windows, at most 2,000 bytes for all of them (`maxAnchorBytes`)**, highest severity first, then path and line. The
   2,000 bytes match one file's cap today. Overlapping windows in one file merge. A window that does not fit is left out
   and disclosed through `boundedNote`, as other `fitUnits` fields are.
4. **What the window header says.** Recommended: **`# <file> (lines a–b)`, with no rule ID and no "flagged"**. Telling the
   model "a scanner flagged this" primes it toward high on every benign `subprocess.run`, which is the `issues/028` risk
   this proposal is most exposed to. If the neutral header shows no gain, a flagged header is a separate measurement,
   not a fallback inside this one.
5. **Acceptance lines.** Recommended as written in Done criteria: `mcp-variants` ≥ +5, Cisco ≥ 98, benign escalating ≤
   +6 of 621. If recall clears but benign does not, the proposal goes to `rejected/` with its readings. Raising the
   benign line after the fact is not one of the options.
6. **Measurement cost.** The branch run on about 800 server trees, est. **US$8–10** at gpt-4.1-mini. Main's reading is
   reused from the full-corpus run, so it costs nothing new. Recommended: go.

## Measured

Live, gpt-4.1-mini, `samples: 3`, corpus `c314e4d9`, 2026-11-04. The work list is every tree the server pass asks: 802
trees, 623 benign, 127 Cisco and 52 `mcp-variants` (five more `mcp-variants` trees are not server-kind, so this change
cannot affect them).

- Main: the full-corpus run of the same day (`v0.33.1-3-g5a18a6db`, `judge-excerpt=9`), folded again over the 802.
- Branch: `v0.33.1-9-g4aa11245`, `judge-excerpt=10`, with the same `rules` and `judge-prompt` hashes.
- Directories: `baselines/results/aguard/2026-11-04-llm-gpt-4.1-mini-p114-servers-{main,branch}-s3/`. Main's `run.yaml` is
  the full run's.
- Raw archive: `aguard-judge-raw-2026-11-p114.tar.gz`, 700,207 bytes, sha256 `316449b3…7647c`, both runs' `raw/` over
  the 802; it goes on the next release.

| | n | main | branch | line |
|---|---:|---:|---:|---|
| `mcp-variants`, static + judge | 52 | 32 | **42** | ≥ main + 5 ✅ |
| Cisco, static + judge | 127 | 102 | 104 | ≥ 98 ✅ |
| benign, escalating `LLM-010` ≥ high | ~620 | 60 | **96** | ≤ 66 ❌ |
| judge calls | 802 | 2,834 | 2,834 | equal ✅ |
| prompt tokens | 802 | 5.26 M | 5.46 M | windows only ✅ |

**The windows, not the rerun.** `bas-guard llm preview --json` was run with both binaries on every tree and the payloads
compared. The list is in the branch directory's `payload-changed.txt`. 235 trees' payloads changed and 567 were
byte-identical:

| | trees | benign `LLM-010` ≥ high, main → branch | malicious flagged, main → branch |
|---|---:|---:|---:|
| payload changed | 189 benign · 46 malicious | **28 → 69** (47 new, 6 gone) | 32 → 44 |
| payload identical | 434 benign · 133 malicious | 33 → 30 (4 new, 7 gone) | 102 → 102 |

On identical payloads the run band is a few trees either way. On changed ones the benign side rose by 41.

**By anchoring rule.** Counting the medium-or-above rules present on each changed tree; a tree can carry several:

| rule | benign trees with a window from it | new benign escalations among them | malicious gained among them |
|---|---:|---:|---:|
| `EXEC-004` | 108 | 28 | 11 |
| `EXFIL-001` | 67 | 16 | 0 |
| `EXFIL-004` | 27 | 8 | 1 |
| `OBF-001` | 46 | 8 | 1 |

The new benign escalations name `credential-read` (20, alone) and `remote-execution` (16, alone). Even a window from
`EXEC-004` alone, the rule on every recovered `mcp-variants` payload (`subprocess.run(command, shell=True, …)`), costs about
28 benign for 11 malicious. A benign server's `subprocess.run` shown to the model reads to it as remote execution. That is
`issues/028`'s observation from the other side: the judge cannot tell a tool that runs commands by design from a spliced
one by looking at the call.

**What this leaves.** The visibility problem the draft described is real, and the windows fix it: 11 of the 12 anchored
`mcp-variants` misses were recovered. What the model does with a `subprocess` line is the limit. Any later attempt needs a way
to separate the two on the benign side first, such as whether the command comes from a tool parameter. It should not
change what the model is shown. Not proposed here.

Cost of the branch run: 5.46 M prompt tokens (1.37 M cached), 0.96 M completion, about US$3.30 at gpt-4.1-mini list price.

