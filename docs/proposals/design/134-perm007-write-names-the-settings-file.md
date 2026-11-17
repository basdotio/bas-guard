<!-- SPDX-License-Identifier: MIT -->
# 134 — `PERM-007` fired high on scripts that read a Claude settings file and write some other file: 118 of 136 findings on public status line scripts

- **Source**: P-133's measurement (PR #159), 2026-11-17; the maintainer decided that this lands before P-133's
  every-rule reading of the scripts settings helpers name (P-133 Open question 1)
- **Depends on**: none. Moves `rulesEpoch` 19 → 20 (P-133 also takes 20 on its branch and waits for this one)
- **Branch**: `p/134-perm007-write-names-the-settings-file`

## Problem

`PERM-007` ("Writes Claude Code's permission settings file", high) has two halves. The line half needs a write verb right
before the file name. The file-level half (P-016, widened by P-124) closes when a script has a line that **names** a
Claude settings file (`settings.json`, `settings.local.json` under `.claude`, or `.claude.json`) and is not a read
(`settingsReadRE`: `cat`, `jq`, `grep`, `<`, `.read_text(` …), and a line that **writes any file**. It does not ask
whether the file written is the file named.

P-133 measured what that costs on code that reads the settings to show them. 1,100 public status line scripts that
mention `transcript_path`, each placed where `main` reads it with every rule (`~/.claude/statusline.<ext>`, a loose
script under the root): 159 carry a high, and `PERM-007` accounts for 136 findings in 125 of them, 106 with no other
high. 118 of the 136 are the file-level half, and every one read is a status line that names a settings file in order
to read it — an assignment later only read, a `jq … "$HOME/.claude.json"` (the read pattern looks for the word
`settings`), a `for f in "$HOME/.claude/settings.json" …`, a help string — and writes a cache file somewhere else.
The other 18 are the line half on test files the search picked up, which write a fixture settings file.

The corpus shows the same shape. Of the 21 `PERM-007` findings on `main` (`5de9737`), 17 are the file-level half on
benign samples: a help string or a comment naming the file and an unrelated write, a `for` loop or a `return` naming it,
a parameter default. One is the malicious target the half was written for: `p = pathlib.Path.home() / ".claude" /
"settings.local.json"` then `p.write_text(…)`.

## Initial direction

Ask the half the question its title asks: is the named file the one written? Follow the name one level in the same
file, as `FS-005`'s file-level half does (P-092): the naming line assigns the path to a name, and a later line writes
through that name. One line that both names the file and writes stays as P-124 made it.

## Decisions

(design part: filled in with the tests and the measurement)
