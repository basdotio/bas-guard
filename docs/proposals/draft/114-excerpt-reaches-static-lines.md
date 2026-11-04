<!-- SPDX-License-Identifier: MIT -->
# 114 — A server's injected payload sits on a line the rules already flagged, and the judge is never shown that line

- **Source**: the maintainer, 2026-11-04 ("yes" to the order: excerpt first, then the server categories, then TypeScript
  servers), after the full-corpus comparison of the same day (corpus `c314e4d9`, 5,272 samples)
- **Depends on**: none
- **Branch**: `p/114-excerpt-reaches-static-lines`

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
