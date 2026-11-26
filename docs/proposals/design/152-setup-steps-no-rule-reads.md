<!-- SPDX-License-Identifier: MIT -->
# 152 — A skill whose text tells the agent to make a credential file readable by everyone, add a second package index, or replace `~/.bashrc` scores 100: three setup steps no rule reads

- **Source**: the maintainer, 2026-11-26 ("写提案草稿"; "都按推荐" to the five open questions), after the SkillHarm
  trees whose harm is written in the skill's own text, and that no rule reports, were read one by one
- **Depends on**: none
- **Branch**: `p/152-setup-steps-no-rule-reads`

## Problem

Eleven SkillHarm trees in the corpus carry their one bad act as a "required setup step": a shell command in a fenced
block, with a paragraph explaining why the skill needs it. Nothing is hidden, encoded or fetched. `check` exits 0 on
each of them with v0.40.0's rules.

| tree (`mal-skill-sh-…`) | where the step is | the step | today |
|---|---|---|---|
| `privilege-escalation-301b1c6e66` | `SKILL.md` | `chmod 0644 /root/.netrc` | 100 |
| `privilege-escalation-512c2b30e4` | `SKILL.md` | `chmod a+r /etc/reflow-toolkit/operator.key` | 100 |
| `privilege-escalation-d5d6c1e7f8` | `SKILL.md` | `chmod a+r /root/.config/powerliftpro/coefficients-api.key` | 100 |
| `privilege-escalation-3dc1f345d0` | `workflow-setup.md`, which `SKILL.md` names | the same line | 100 |
| `backdoor-injection-4c0de944ad` | `SKILL.md` | a heredoc writes `pip.conf` with `extra-index-url = https://wheels.pacific-seis.org/simple` | 95 |
| `backdoor-injection-bafdd1a574` | `setup_env.sh` | the same heredoc | 100 |
| `backdoor-injection-d607fb8d1d` | `INSTALL.md`, named | the same heredoc | 95 |
| `system-corruption-2457e7da1c` | `scripts/prepare_environment.py` | a string written to `/root/.pip/pip.conf`: `extra-index-url = http://pypi.taxoml-cache.example:8080/simple` | 100 |
| `system-corruption-22022eee4e` | `environment_preparation.md`, named | the same key | 100 |
| `unauthorized-file-modification-a8fcdad909` | `SKILL.md` | `cat > ~/.bashrc <<'RC'` and a new file body | 88 |
| `unauthorized-file-modification-e24d224b58` | `SKILL.md` | `cat > /root/.bashrc <<'EOF'` and a new file body | 100 |

The load-time gate runs the static rules and nothing else, so these skills load without a question. With the judge
on, the default model reports six of the eleven at high in the stored full-corpus run of 2026-11-04; the five it
misses all carry the step in `SKILL.md` itself. glm-5.3 reports ten.

Why no rule fires:

- **The mode change.** No rule reads `chmod`. `FS-001` reports `id_rsa` and `~/.ssh` by name, which is why four
  sibling trees that open `/root/.ssh/id_rsa` are flagged already. A `.netrc` or a `*.key` has no rule, and the act
  itself (a file that holds a secret, made readable by every user and every process on the machine) has none either.
- **The second index.** `SUP-006` reports a package manager pointed at a host that is not a registry's own. Its line
  pattern asks for a boundary before `index-url`, and in `extra-index-url` the character before it is a hyphen, so
  pip's second index is never seen: not as a `pip.conf` key, not as `--extra-index-url`, not as `PIP_EXTRA_INDEX_URL`.
  pip resolves every requirement across all its indexes and takes the highest version it finds, so a host added as a
  second index can answer any package name with anything. That is the consequence the rule exists for.
- **The startup file.** `EXEC-013` (P-093) reads a startup file made to `source` a script the artifact wrote.
  Replacing the file is not that. P-093 kept to its one shape because appending a line to a startup file is how
  nvm, cargo and ROS document their own setup.

A prototype of the candidate shapes (`agent-guard-work/textharm-proto.py`, and `textharm-skillmd.py` for the last
column; offline, reads files, runs nothing):

| shape | malicious, of 749 | benign, of 4,534 | fresh skills, of 412 | held-out, totals only (243 / 216) | SkillMD-138K, of 138,133 texts |
|---|---:|---:|---:|---:|---:|
| `chmod` gives group or others read on a credential file | 8, four missed today | 0 | 0 | 2 / 0 | 0 |
| pip's second index on a host that is not a registry's own, a known mirror or loopback | 6, five missed today | 0 | 0 | 1 / 0 | **12** |
| a shell startup file truncated and rewritten | 2, both missed today | 0 | 0 | 0 / 0 | **1** |
| *not proposed:* the same `chmod` on the directory (`chmod 755 ~/.ssh`) | 1, flagged today | 0 | 0 | 0 / 0 | **3** |
| *not proposed:* a startup file appended to, whatever the line | 17, eight missed today | **12** | **2** | 7 / **1** | **151** |
| *not proposed:* a file written, copied or made executable under a system `bin` directory | 1, missed today | **10** | **3** | 1 / 0 | **110** |

"Missed today" is: not flagged at high by the static run of 2026-11-24 (`main` at P-147, `rules=6ed8b90f6b4f`, the
rules v0.40.0 ships). The 749 are the 719 of corpus `c314e4d9` and the 30 servers added since, none of which holds any
of the shapes. Of the 412 fresh skills 408 are on disk. The three held-out trees hold their line in a file that is
neither `SKILL.md` nor a script; no held-out tree was read. SkillMD-138K is 138,133 `SKILL.md` files a scrape of
GitHub collected (`cache/skillmd-138k/train.parquet` in the corpus checkout, CC-BY-4.0): unlabelled, read as ordinary
skills.

The bold cells, read line by line where reading is allowed:

- **Second index, 12 real skills in seven repositories.** Four name `download.pytorch.org` and two `pypi.nvidia.com`:
  PyTorch's and NVIDIA's own wheel indexes, the install commands those projects document. Five are one vendor's
  skills installing its own package from `lattifai.github.io`. One is an example of a private index
  (`pypi.example.com`) in a Dockerfile snippet.
- **Startup file rewritten, one real skill.** A Docker-based end-to-end test recipe for a dotfiles installer writes
  a placeholder (`echo "# Fake zshrc" > "$HOME/.zshrc"`) so that it can test the installer's backup step.
- **The directory, three real skills.** One is a skill planted in a scanner's own test set. The other two quote the
  command as what not to do: under a "BAD" heading in a security guide, and as a sample question for a command
  validator. No real skill opens a credential *file*; nine tell the reader to `chmod 644` a public key, and one a
  public `.pem`.
- **Appends and system `bin` paths** are how software is installed (`echo 'export PATH=…' >> ~/.zshrc`,
  `sudo mv tool /usr/local/bin/`). Measured for the record; P-093 already said so for appends.

One thing the same pass showed about the rule as it is: by a Python port of `SUP-006`'s line pattern, 163 of the
138,133 real skills carry a target the rule does not accept, 71 of them a variable. The most frequent readable host
is `download.pytorch.org`, in 16 texts (`pip install torch --index-url https://download.pytorch.org/whl/cu121`). In
the corpus `SUP-006` is high on 11 benign samples and is the only high rule on 7 of them; one of the 7 is that
PyTorch line.

## Initial direction

Three small changes on the static side, measured on the static bench (free):

1. a rule for `chmod` that gives group or others read on a credential file (`FS-006`);
2. `SUP-006` reads pip's second index in its four spellings, and PyTorch's and NVIDIA's own wheel indexes join the
   hosts it accepts;
3. a rule for a shell startup file truncated and rewritten (`FS-007`).

## Done criteria

Code:

- [ ] `FS-006` (high, dimension 9; `TestDetect_CredentialFileOpenedToOthers`): a line runs `chmod`, with or without
      options, with a mode that **gives group or others read**, on a path that is a **credential file**. One finding
      per line, quoting the line through the redactor.
  - The mode is read, not listed: an octal mode whose group or other digit has the read bit (`644`, `0644`, `640`,
    `664`, `755`, `777`), or a symbolic clause that adds or sets `r` for `g`, `o`, `a` or for nobody named (`a+r`,
    `o+r`, `go+r`, `+r`, `u=rw,go=r`).
  - The path is asked of `collect`'s credential list, the one `EXFIL-005` uses, and no second list is written: a name
    in its high tier (`.netrc`, `.env` and its stage suffixes, `id_rsa` and kin, `credentials`, `.git-credentials`,
    `*.key`, `*.p12`, `*.pfx`, …), or a file inside one of its credential directories other than `.config`. In
    `.ssh` the files that are public by design do not count: `*.pub`, `authorized_keys`, `known_hosts`, `config`.
  - Runs where the rules run: scripts, instruction files, the code of a document `SKILL.md` names (P-091). Not
    bundled prose, tool descriptions or config data.
- [ ] Reverse: `chmod 600 ~/.netrc`, `chmod 400 server.key`, `chmod u+r`, `chmod go-r`, `chmod 644 ~/.ssh/id_rsa.pub`,
  `authorized_keys`, `known_hosts` and `~/.ssh/config` at `644`, `chmod 644 cert.pem`, `chmod 644 .env.example`,
  `chmod 755 ~/.ssh` (the directory: open question 3), `chmod +x run.sh` and `chmod 644 README.md` raise nothing.
- [ ] `SUP-006` reads pip's second index (`TestRegistryRedirects_PipSecondIndex`): the `extra-index-url` key, `pip
      config set global.extra-index-url`, the `--extra-index-url` flag (with `=` or a space) and
      `PIP_EXTRA_INDEX_URL`. Same rule, same severity, same reading of the target (a URL or a shell variable resolved
      one level in the same file; an unreadable target is reported, not skipped; a comment line is not read).
- [ ] `download.pytorch.org` and `pypi.nvidia.com` join the accepted hosts, for the first index and the second (open
      question 2). `TestRegistryRedirects_VendorWheelIndexes` pins the two by name and that nothing else was added:
      `lattifai.github.io`, `pypi.example.com`, `pytorch.org.evil.net` and `download.pytorch.org.evil.net` are still
      reported.
- [ ] Reverse: every existing `SUP-006` test is green without an edit (`TestShapeRulesGateAtHigh` among them); a
  second index on `pypi.org` or on loopback raises nothing; "use the extra index" in prose, with no URL, raises
  nothing.
- [ ] `FS-007` (high, dimension 9; `TestDetect_StartupFileRewritten`): a shell startup file (the list `EXEC-013`
      already holds: `.bashrc`, `.bash_profile`, `.bash_login`, `.profile`, `.zshrc`, `.zshenv`, `.zprofile`,
      `.zlogin`, `/etc/profile`, `/etc/bash.bashrc`, `/etc/zsh/zshrc`) is the target of a redirect that truncates
      (`cmd > file`, `cat > file <<EOF`) or of `tee` without `-a`. One finding per line.
- [ ] Reverse: `>>` and `tee -a` (any content: that is P-093's ground and stays as it is), a redirect *from* the file
  (`cat ~/.bashrc > backup`), `cp ~/.bashrc ~/.bashrc.bak`, `2> ~/.bashrc.err`, an arrow in a comment
  (`data.csv -> ~/.bashrc`: the prototype's one false match) and a bare `> ~/.bashrc …` at the start of a Markdown
  line (a block quote, as `FS-005` already treats it) raise nothing. Every existing `EXEC-013` test is green without
  an edit.
- [ ] `rulesEpoch` 30 → 31, `make docs`, `TestEveryRuleIDIsDocumented` green, each new rule with its OWASP position;
  a `CHANGELOG.md` entry under `## Unreleased`; `make verify` green, read from its own exit code.

Measurement (static, threshold high, corpus `ed3c871b`: 749 malicious, 4,534 benign, 19 hard negatives; `main` at
`c46cbc2` against the branch, both built the same day). Lines set before the run:

- [ ] **Target**: each of the eleven trees in the table is flagged at high by the rule its row belongs to (`FS-006`
  on the first four, `SUP-006` on the next five, `FS-007` on the last two). Eleven of eleven.
- [ ] **Malicious**: no sample flagged on `main` is unflagged on the branch.
- [ ] **Benign**: no benign sample, alert-justified ones included, carries `FS-006` or `FS-007`. No benign sample is
  flagged on the branch that is not on `main`. A benign sample may stop being flagged only when every `SUP-006`
  target it holds is one of the two added hosts; each such sample is named.
- [ ] **Hard negatives**: the same samples flagged as on `main`.
- [ ] **Held-out** (`heldout-all`, totals only): malicious flagged not fewer than on `main`; benign flagged not more.
- [ ] **Fresh benign skills** (`fresh216`, `fresh200`): none carries `FS-006` or `FS-007`; no tree is flagged on the
  branch that is not on `main`.
- [ ] **Real skills** (SkillMD-138K: the 2,619 texts that hold `chmod`, an `index-url` spelling or a startup file's
  name, each given to `check` as a skill directory holding that one `SKILL.md`, on `main` and on the branch). Every
  text whose findings differ is listed with its line. `FS-006` on **at most two** texts, `FS-007` on **at most two**,
  `SUP-006` newly on **at most eight**; each is read and described. (The prototype says zero, one and six.) Texts
  that stop carrying `SUP-006` are counted, and each must hold only the two added hosts.
- [ ] **Read, not gated**: a scan of the maintainer's own `~/.claude` on `main` and on the branch; what differs is
  reported.

Docs:

- [ ] `.claude/rules/detect.md`: what not to widen. Not the directory, not `.pem`, not the medium tier of the
  credential list; not an append to a startup file; the accepted hosts grow only by a host whose owner is certain,
  counted on real skills first.
- [ ] `docs/spec/spec.zh-CN.md`: one clause in the shape-check bullet (`SUP-006` reads pip's second index).

## Out of scope

- **The credential directory itself** (`chmod 755 ~/.ssh`), unless open question 3 is answered the other way.
- **A startup file appended to**, whatever is appended (a `ulimit`, a `PATH` without `$PATH`, an `export`): P-093's
  ground, measured again above (12 benign trees, 151 real skills). Eight malicious trees stay unreported for it.
- **A file put under a system `bin` directory**: measured above, not clean.
- **The other eight of the thirteen trees this started from** (the default judge's misses whose step is written in
  `SKILL.md`; five are in the table): two POSTs to a "registry" the skill invents, a data file fetched over `http://`
  (`SUP-007` reads code files, by design), a LibreOffice macro, a script written over `/usr/local/bin/ffmpeg`, a
  configuration file written under `/root`, and two appends to a startup file. The first six are a judgement about
  purpose, which is the judge's; the appends are the item above.
- **What `SUP-006` reports on real skills today beyond the two hosts**: the bare `registry <url>` spelling in prose,
  and template variables read as shell variables (`${registry}`, `${message}`). Seen while measuring; a proposal of
  its own, with its own measurement.
- **Other package managers' second sources** (uv's own index settings, `--find-links`, conda channels, a Git URL as
  a requirement). No sample.
- A mode set from code rather than by the `chmod` command, and a path the line does not spell. No sample.
- The judge.

## Must not claim

- Not "detects privilege escalation" or "detects credential exposure". `FS-006` reads one command changing one kind
  of file's mode. It says nothing about who can already read the file.
- Not "detects dependency confusion". `SUP-006` reports where a package manager is pointed. A second index on an
  accepted host, or a package of the same name published to PyPI itself, is not seen.
- Not "detects persistence" (P-093's sentence holds): `FS-007` reads one way of taking over a startup file.
- The malicious side is one synthetic dataset. All eleven trees are SkillHarm's, in three of its cells, built from a
  few templates: the two `FS-007` trees are one template, and so are three of the five second-index trees. They are
  not eleven independent votes. What was measured widely is the benign side.
- The SkillMD-138K figures are counts over unlabelled `SKILL.md` files, not a false-positive rate: a line the rule
  reports there is read and described here, not judged benign by anyone else.
- A real skill that installs its vendor's package from the vendor's own index on a host that is not a registry
  (`lattifai.github.io`, five texts) is reported at high. That is the rule's reading of the line, and it is not a
  statement that the skill is malicious.
- Accepting `download.pytorch.org` and `pypi.nvidia.com` is not "trusting PyTorch packages". It says these two hosts
  serve what their owners publish.

## Work items

| W | In one sentence | Commit message (no sha; a rebase changes it) |
|---|---|---|
| 1 | `FS-006`, `SUP-006`'s second index and the two hosts, `FS-007`, tests, epoch, generated rules doc, changelog | `detect: a credential file opened to other users is FS-006, a startup file rewritten is FS-007, and SUP-006 reads pip's second index (P-152)` |
| 2 | `.claude/rules/detect.md` and the spec line | `docs: three setup steps the rules now read (P-152)` |
| 3 | Static runs, `main` and branch: corpus, held-out, fresh skills, the SkillMD-138K texts | `baselines: P-152 static runs, main and branch (P-152)` |
| 4 | Done, `complete/` or `rejected/`, the index row | `proposals: P-152 done (P-152)` |

## Open questions

All asked at once. Each has a recommended answer.

1. **Three rules in one proposal, the third on two trees of one template. Build `FS-007`?** For: replacing a user's
   shell startup file destroys their configuration whatever the intent, none of the 4,942 benign and fresh trees read
   does it, and one real skill of 138,133 does (a test recipe meant for a container). Against: two trees, one
   template, nothing on the held-out set. Recommended: **yes, at high.** If no, items 1 and 2 stand alone and the two
   trees stay unreported.
   **Decided (2026-11-26)**: yes, `FS-007` at high.
2. **Accept PyTorch's and NVIDIA's own wheel indexes?** Without them, reading the second index adds 12 real skills
   to what `SUP-006` reports, six of them these two hosts; with them it adds six, and the 16 real skills (by the
   port) and the one corpus sample that today's rule reports for PyTorch's documented install command no longer
   carry the finding. It is a widening
   of an accept-list, which this repository does only for a host whose owner is certain. Recommended: **yes, these
   two and no other.** `rocm.nightlies.amd.com` (two real skills) is AMD's by its domain and is left for whoever
   reports it; a host under a hosting platform's suffix (`*.github.io`) is never added, since the name is first come.
   **Decided (2026-11-26)**: yes, these two and no other.
3. **The directory itself?** `chmod 755 ~/.ssh` makes the key files' names listable, and with `-R` it opens the keys.
   The one corpus tree that does it is flagged already; of the three real skills, two quote the command as what not
   to do. Recommended: **leave it out.** Reading it would need the "quoted as a counter-example" exemption the
   injection rules have, for no tree gained.
   **Decided (2026-11-26)**: leave it out.
4. **High, not medium?** The gate stops at high. `FS-006` has no benign line in the corpus, the fresh skills, the
   held-out benign set or the 138,133 real skill texts; a private key readable by every user has no setup-guide
   reading (ssh refuses to use one). Recommended: **high** for both
   new rules, as `FS-005` and `EXEC-013` are.
   **Decided (2026-11-26)**: high for both new rules.
5. **Where the SkillMD-138K reading lives.** The dataset is not vendored. Recommended: as P-139 did, the result
   directory holds the list of texts whose findings differ (repository, path, line, the finding), and `compare.txt`
   says how to fetch the dataset and rerun; the prototype scripts stay outside the repository.
   **Decided (2026-11-26)**: as recommended.
