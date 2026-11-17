<!-- SPDX-License-Identifier: MIT -->
# 029 — A project's `CLAUDE.md` importing `@~/.env` is not reported: `~` is read as the project, where no `.env` lives

- **Category**: coverage gap (覆盖缺口)
- **Severity**: medium (中)
- **Status**: `未修复` — found while P-125 was measured (2026-11-16)

## Problem

Claude Code expands `~/` in an `@` import against the user's home. The scanner expands it against the home of the scan
(`filepath.Dir(root)`, `resolveImport`), which keeps a run hermetic and honours `--root`, and never reads the process
environment. Under the default `scan` (root `~/.claude`) the two agree. Under a project-rooted run they do not: for
`scan --root <repo>/.claude` and, since P-125, `check <repo>`, the scan's home is `<repo>`, so `@~/.env` resolves to
`<repo>/.env`. `expandImports` checks existence before anything else (a missing target is a stale reference), so when the
project holds no `.env` the line is dropped without a word, while a session started in that project loads the user's
real `~/.env`.

## Reproduction

v0.34.0 and the P-125 branch give the same answers. A fake `HOME` holding `.env` and `.ssh/id_rsa`; a project
`$HOME/work/repo` with an empty `.claude/` and a `CLAUDE.md` of `# Repo notes`, a blank line and one import line; run from
the project with `--config` pointing at `{}`:

| import line | `check .` | `scan --inbox off --root ./.claude` |
|---|---|---|
| `@~/.env` | 100/100, no finding | 100/100, no finding |
| `@~/.ssh/id_rsa` | 69/100, `FS-001` (the line rule, not the import) | 69/100, `FS-001` |
| `@~/.aws/credentials` | 88/100, `FS-002` (the line rule) | 88/100, `FS-002` |

With a `.env` placed in the project as well, `check .` reports `EXFIL-005` for `@~/.env`, which shows the miss is the
resolution frame and not the credential list.

## Direction

Not decided. Two shapes, each with a cost:

- Refuse an import whose written path names a credential (`CredentialPath` on the resolved string) before the existence
  check, so `EXFIL-005` does not depend on the file being present in the scan's frame. This changes `scan` too, and turns
  a stale credential reference into a scored finding; measure the corpus for benign `CLAUDE.md` files that would carry it.
- Resolve `~/` against the user's home only for refusal (never to read), which needs the real home in a run that is
  meant to be hermetic — the property the current resolution exists to keep.

Either one moves `EXFIL-005`, so it bumps `rulesEpoch`.
