#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""replay.py <result dir> --raw <dir of raw/*.json> [--intent] [--row] [--names]

P-150. What a stored judge run would have read if the server pass (LLM-010) did not take the
"disclosed, one step lower" step. No model call: the step was applied by the tool after the model
had answered, and the prompt is unchanged, so the stored answers are the answers.

<result dir> holds the run's folded judge.jsonl (a directory under baselines/results/aguard/, or a
local run's fold/). --raw is the run's raw outputs, one <sample>.json per sample: they are not in
the tree, a release carries them as an archive (see compare.txt for which).

What a stored output does and does not hold (internal/judge/run.go, tally and groundedFinding):
  - a finding's reason is the FIRST agreeing vote's reason, so "[disclosed: one step lower]" and
    "[category not shown by the text: ...]" are known for that vote only;
  - "[categories: a, b, c]" lists every agreeing vote's category, "[tool: X]" the severity the
    finding ended with;
  - the finding's severity is that of the first vote in the majority category, or the lowest
    among the votes when no category has a majority;
  - on the server pass a vote in a high row was medium for one of two reasons only: the
    disclosure step, or one of the two credential-read downgrades (the credential's own service,
    P-062; only the server's own configuration, P-098). categoryShown does not apply to the pass.

So each escalating LLM-010 finding that is not high falls into one of:
  lift    the deciding vote is known to be lowered by the step alone: high without it
  stays   the majority category is a medium row, or the deciding vote carries a credential-read
          downgrade, or there is no majority and some vote is in a medium row
  open    the deciding vote is not the first one and its category is credential-read (its reason
          is not stored: the step, or a credential-read downgrade), or there is no majority and
          every vote is in a high row
A sample counts once: high now, else lift, else open, else stays. The first column is checked
against judge.jsonl's own count; a mismatch is printed.

--intent  read the intent pass (LLM-001) instead: the same step on skills, which P-150 leaves in
          place. No credential-read downgrade exists there, so a high-row vote is medium by the
          step alone. Runs older than P-115 carry no mark; categories and [tool:] are enough.
--row     the run used a build with P-118's code-execution row (high, exempt from the step)
--names   list the samples that lift or stay open, with the first vote's sentence
"""
import collections
import json
import os
import re
import sys

HIGH = {"exfiltration", "credential-read", "remote-execution", "safety-disable", "concealed-directive",
        "software-source", "persistence", "file-deletion", "privilege", "resource-exhaustion",
        "result-tampering"}
MARK = "[disclosed: one step lower]"
VOTE = re.compile(r"\[(\d+) of (\d+) samples agreed\] \[severities: ([^\]]*)\] \[categories: ([^\]]*)\] \[tool: (\w+)\]")
ORDER = {"high": 3, "lift": 2, "open": 1, "stays": 0, "none": -1}


def classify(f, high_rows, intent):
    """One escalating finding -> (class, majority category or a note)."""
    why = f.get("why", "")
    if f.get("severity") == "high":
        return "high", "-"
    m = VOTE.search(why)
    if not m:
        return "stays", "?"          # one sample configured, or a shape this does not read
    n = int(m.group(2))
    cats = [c.strip() for c in m.group(4).split(",")]
    need = n // 2 + 1
    count = collections.Counter(cats)
    first_lowered = MARK in why
    first_downgraded = "[category not shown by the text:" in why
    decide = next((i for i, c in enumerate(cats) if count[c] >= need), -1)
    if decide < 0:
        if any(c not in high_rows for c in cats) or first_downgraded:
            return "stays", "(no majority)"
        return "open", "(no majority)"
    cat = cats[decide]
    if cat not in high_rows:
        return "stays", cat
    if intent:
        return "lift", cat           # no other downgrade exists on the intent pass
    if decide == 0:
        if first_downgraded:
            return "stays", cat
        if first_lowered:
            return "lift", cat
        return "stays", cat + " (not lowered, not high: unread shape)"
    if cat == "credential-read":
        return "open", cat
    return "lift", cat               # a high row other than credential-read was medium only by the step


def main():
    argv = sys.argv[1:]
    if "--raw" not in argv or len(argv) < 3:
        sys.exit(__doc__)
    raw = argv[argv.index("--raw") + 1]
    args = [a for i, a in enumerate(argv) if not a.startswith("--") and (i == 0 or argv[i - 1] != "--raw")]
    row, names, intent = "--row" in argv, "--names" in argv, "--intent" in argv
    rule = "LLM-001" if intent else "LLM-010"
    run = args[0]
    fold_path = os.path.join(run, "judge.jsonl")
    if not os.path.exists(fold_path):
        fold_path = os.path.join(run, "fold", "judge.jsonl")
    high_rows = HIGH | ({"code-execution"} if row else set())
    if intent:
        high_rows = HIGH - {"resource-exhaustion", "result-tampering"}
    fold = {}
    for line in open(fold_path):
        r = json.loads(line)
        fold[r["sample"]] = r
    per, sentence = {}, {}
    low_to_medium = collections.Counter()
    for s, r in fold.items():
        best, cat = "none", "-"
        try:
            d = json.load(open(os.path.join(raw, s + ".json")))
        except Exception:
            per[s] = ("none", "-")
            continue
        for a in d.get("artifacts") or []:
            for f in a.get("findings") or []:
                if f.get("rule_id") != rule or not f.get("escalates"):
                    continue
                c, k = classify(f, high_rows, intent)
                if f.get("severity") == "low" and MARK in f.get("why", ""):
                    low_to_medium[r["class"]] += 1
                if ORDER[c] > ORDER[best]:
                    best, cat = c, k
                    sentence[s] = f.get("why", "").split(" [", 1)[0]
        per[s] = (best, cat)
    label = os.path.basename(os.path.normpath(run))
    print(f"== {label}{' (code-execution row)' if row else ''}{' (intent pass)' if intent else ''}")
    for cls in ("malicious", "benign"):
        ss = [s for s, r in fold.items() if r["class"] == cls]
        if not ss:
            continue
        now_fold = sum(rule in fold[s]["escalated_rules"] for s in ss)
        c = collections.Counter(per[s][0] for s in ss)
        check = "" if c["high"] == now_fold else f"   !! judge.jsonl says {now_fold}"
        print(f"  {cls:9} n={len(ss):4}  {rule} high now {c['high']:3}{check}"
              f"   without the step {c['high'] + c['lift']:3}"
              + (f" to {c['high'] + c['lift'] + c['open']:3}" if c["open"] else "")
              + f"   (lift {c['lift']}, open {c['open']}, escalating and stays below high {c['stays']})"
              + (f"   low -> medium {low_to_medium[cls]}" if low_to_medium[cls] else ""))
        by = collections.Counter(per[s][1] for s in ss if per[s][0] == "lift")
        if by:
            print("            lift by category: " + ", ".join(f"{k} {v}" for k, v in by.most_common()))
        if names:
            for kind in ("lift", "open"):
                for s in sorted(ss):
                    if per[s][0] == kind:
                        print(f"            {kind:5} {s}  [{per[s][1]}]")
                        print(f"                  {sentence.get(s, '')}")


if __name__ == "__main__":
    main()
