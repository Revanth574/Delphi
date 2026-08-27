# Lane run 7 — procedure (branch `phase-3b/d0-readiness-contract`, HEAD `71fd898`)

**Why this run exists.** `runtime/src/**` has changed **three times** since run 6's clean
sheet, and none of it has executed at root:

| change | commit | what could bite at root and nowhere else |
|---|---|---|
| R10-12 mitigation — `--cap-drop ALL --cap-add CAP_SETUID --cap-add CAP_SETGID` on **every** credential-dropping action | `3e4a275` | the restriction applies to all root execution tests. 5b measured that `delphi-drop` still drops under it — **that is the helper only**, not the tools those tests run |
| R16/R17 remediation — `assemble_profile` extraction, probe/harness fixes | `4cfceb7`, `89a8b09` | the profile is now assembled through one function; a wrong branch shows only where creds exist |
| preview allowlist + arg marking | `53e9758` | pure string rendering, lowest risk of the three — listed so its absence from the failures is also recorded |

**There are ZERO expected REDs.** `.githooks/runtime-test-count-baseline` carries no `RED=`
lines — D0A-R9-02 closed 2026-08-22 — so **any failure is a result**, not a known pair to
match by name. Run 2's procedure says otherwise and is stale on this point; do not carry it
forward.

---

## 0. Preconditions — verify, do not assume

```bash
getent passwd delphi-tool
sha256sum /usr/libexec/delphi-drop installer/staging/delphi-drop
bwrap --version
md5sum /etc/pam.d/delphi-runtime > /tmp/pam-before.md5
scripts/check-free-space.sh
```

Expect `delphi-tool:x:997:972`. **The gid is 972, not 997** — D0A-R17-02 was exactly the
assumption that they coincide, and the check that missed it was looking at `Uid:` only. The
two helper digests must MATCH; a mismatch is a stale install, not a profile difference.

## 1. Build UNPRIVILEGED, then prove the binaries are this code

`sudo -E cargo` does not work here (sudoers drops `-E`; root has no rustup toolchain).

```bash
cd ~/Delphi && export CARGO_TARGET_DIR="$HOME/delphi-target"
cargo test -p delphi-runtime --tests --no-run 2>&1 | tail -3
```

**Do NOT check freshness by binary-mtime vs commit-time.** That rule mis-fired on
2026-08-22 — the pre-commit hook builds *before* the commit object exists, so a correct
binary always reads as stale. Force the question instead:

```bash
touch runtime/src/execute.rs && cargo test -p delphi-runtime --tests --no-run >/dev/null 2>&1
```

An unchanged set of hashes after a forced rebuild is the proof; unchanged hashes *without*
one prove nothing.

## 2. Enumerate the targets — all 17, from cargo, not by hand

```bash
cargo test -p delphi-runtime --tests --no-run --message-format=json 2>/dev/null \
  | python3 -c 'import sys,json
for l in sys.stdin:
    try: m=json.loads(l)
    except Exception: continue
    if m.get("executable") and m.get("profile",{}).get("test"): print(m["executable"])' \
  | sort -u > /tmp/targets.txt
wc -l < /tmp/targets.txt        # REFUSE to proceed if this is not 17
```

A count below 17 means the run would silently cover a subset — the exact defect
`scripts/test-count.sh` exists to prevent, so it must not be committed here either.

## 3. The run — every target, serial, one log

```bash
: > /tmp/root-run7.log
while read -r b; do
  echo "### $b" >> /tmp/root-run7.log
  sudo "$b" --nocapture --test-threads=1 >> /tmp/root-run7.log 2>&1
done < /tmp/targets.txt
```

Serial is not a preference: `--test-threads=1` is what makes SKIP markers land
deterministically at column 0 (parallel interleaving made the same tree count 17/18/19), and
CLAUDE.md §6's fork+PAM carve-out makes the serial run the authoritative one for this shape.

## 4. The count — through the extractor, never by summing

`test-count.sh` shells out to `cargo`, so it cannot run under `sudo` here. Use its
**parse-only** mode on the captured log, unprivileged:

```bash
DELPHI_TESTCOUNT_LOG=/tmp/root-run7.log scripts/test-count.sh
```

**VERIFIED, not assumed (2026-08-26, unprivileged dry run).** Running the 17 targets
separately and concatenating produces a log the extractor parses **identically** to the
normal cargo path — both `EXECUTED 148 / SKIPPED 25 / reported 173`. The concatenation is
not a shape the parser had been shown before, so it was checked rather than specified.

**This closes an open register item.** The root `EXECUTED` figure has deliberately never been
recorded, because deriving it as `reported − skips` is arithmetic, and arithmetic of that
shape is what put a withdrawn expectation in the baseline. If this prints cleanly, write it:

```bash
printf 'EXECUTED=%s\nSKIPPED=%s\n' <executed> <skipped> > .githooks/runtime-test-count-baseline.root
```

Only from the extractor's own output. Never by subtraction.

## 5. The three checks, BY NAME

```bash
grep -c '^test result: FAILED' /tmp/root-run7.log          # failures — expect 0
grep -E '^test .+ \.\.\. (SKIP|DEFER)' /tmp/root-run7.log  # skips — print them, do not count only
scripts/check-stale-test-sessions.sh                       # leaks
```

Run 6 reported **0 failures, 0 skips, 0 leaks**. A skip at root names its own blocker in its
message — quote it verbatim; a skip proves nothing, and "0 skips" is a claim that must be
read off the list, not assumed from a green.

## 6. After — prove the run did not mutate what it does not own

```bash
md5sum -c /tmp/pam-before.md5
scripts/check-stale-test-sessions.sh
```

Not ceremony: fixtures deleting the operator's installed `/etc/pam.d/delphi-runtime` is a
defect already paid for (`DEFECT_CLASSES` class 16), and it surfaced far away as unrelated
tests reporting "not installed".

## 7. The chain-gap demonstration — DIAGNOSIS DISCIPLINE (test not yet built)

When the composed test lands, its failures are ambiguous by default and must not be
diagnosed from the message alone.

**`execvp: No such file or directory` does not distinguish a missing fd from a missing
loader** — class 43, two misdiagnoses in this arc. Before concluding anything:

1. Print the **child's own stderr**, not the parent's error.
2. Print the derived bwrap argv, so a missing bind is visible rather than inferred.
3. Distinguish the four shapes explicitly — a **refusal** (`RuntimeError`, no exec), a
   **bwrap setup failure** (jail never built), an **env resolution miss** (the real
   `python3` ran, not the impostor), and a **marker-dir permission failure** (impostor ran,
   could not write, because the dir was not chowned to `997:972`).

The fourth is the one this arc's four Class 20 defects all took, and three of them presented
identically as an empty string.

## 8. Report

Paste the literal output. Per §13.5, **EXECUTED / SKIPPED, never a bare total**, and quote
the skip lines rather than reporting their count. If anything fails, the failure IS the
result — do not re-run to green (Iron Law #15).
