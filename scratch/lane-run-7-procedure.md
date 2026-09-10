# THE LANE RUN PROCEDURE — current and reusable (branch `phase-3b/d0-readiness-contract`)

**This is the sanctioned procedure for ANY lane run, not a record of runs 7–8** (D0A-R24-02:
it was still titled for them, so the reactivated runbook read as history rather than as the
current process). Set `RUN` once in §0b; every path below derives from it (D0A-R25-06).

## STEP −1 — DERIVE AND COMMIT THE EXPECTATION, ALONE, BEFORE ANYTHING ELSE

The steps below measure. **This one predicts, and it must be committed first or the
measurement proves only itself** (D0A-R21-07; R19-06 and R20-07 are the two runs whose figure
was right and whose explanation was reconstructed afterwards).

1. Derive `EXPECTED_EXECUTED` / `EXPECTED_SKIPPED` from the current unprivileged pair plus the
   root-gating of every test added or removed since the last run. **Verify root-gating by
   grep — a `geteuid` check, a `SKIP` branch, a `bwrap_available` guard — never from memory.**
2. Write it into `.githooks/runtime-test-count-baseline.expected` **with the derivation**, so
   the reasoning is checkable independently of whether the number matches.
3. **Commit that file ALONE.** A prediction committed beside a measurement establishes no
   ordering between them, and only commit order establishes that the prediction came first.
4. Then run the steps below, and commit the measured pair SEPARATELY afterwards.
5. **A mismatch is a RESULT.** Record which side was wrong; do not adjust the derivation until
   it agrees.

**D0A-R22-01 IS REOPENED AND FUTURE-OWNED.** Nothing enforces this ordering — `scripts/
lane-run.sh` did, for one run, and was reverted at D0A-R23 for dropping §0/§5/§6's checks.
So steps 1–5 are a CONVENTION a human follows, which is what runs 7–11 did. R23-01..R23-10
specify what a runner that enforced it without losing those checks would have to be.

---

## Historical notes

> **RUN 7 ran at `71fd898` and its numbers are SUPERSEDED.** D0A-R18-07: the chain-gap test
> landed later in `d4a741e`, so run 7 never exercised it, and the round-18 remediation
> changed the suite again. `.githooks/runtime-test-count-baseline.root` is marked stale in
> place.
>
> **RUN 8 has long since happened; runs 9-13 followed.** The note that used to sit here
> read as though run 8 were next (D0A-R25-06). What it recorded is still true and is why §3
> and §4 look as they do: they were amended after run 7 with the producer-status check and the
> expected-target gate (D0A-R18-04), closing a defect run 7 itself could have hidden.

> **THIS IS THE SANCTIONED PROCEDURE. A runner that superseded it was REVERTED (D0A-R23).**
> `scripts/lane-run.sh` was built to close D0A-R22-01 — the expectation protocol's ordering
> was enforced by nothing — and it worked: run 12's ordering is machine-checkable and that
> evidence survives its removal. But round 23 returned **8×P1 against the runner**, and
> D0A-R23-05 is the one that decided it: **the runner dropped five checks this procedure
> performs** — helper-digest, free-space, forced-freshness, stale-session, and PAM
> before/after. That is not a new tool with gaps; it is a REGRESSION IN SAFETY COVERAGE sold
> as an upgrade, on the path that produces every piece of root evidence this branch has, and
> class-16 PAM damage is a defect this project has already paid for once.
>
> **The ordering protocol therefore remains enforced by CONVENTION**, with §4's steps
> followed by hand — which is what runs 7–11 did — and with every check below intact.

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

## 0b. SET THE RUN NUMBER ONCE — every path below derives from it

```bash
export RUN=15                     # <- the only edit per run (14 was the last run)
export LOG=/tmp/root-run$RUN.log
export STATUS=/tmp/root-run$RUN.status
```

D0A-R25-06: the operative commands used to hard-code `root-run7` while the prose said to
substitute `N`, so following the document as written parsed the WRONG run's evidence. One
variable, derived paths, no literal run numbers below this line.

## 1. Build UNPRIVILEGED (the freshness PROOF is §2b, after enumeration)

`sudo -E cargo` does not work here (sudoers drops `-E`; root has no rustup toolchain).

```bash
cd ~/Delphi && export CARGO_TARGET_DIR="$HOME/delphi-target"
set -o pipefail                   # D0A-R25-05: `| tail` reports TAIL's status, not cargo's
cargo test -p delphi-runtime --tests --no-run 2>&1 | tail -3 ; echo "build rc=$?"
```

**Do NOT check freshness by binary-mtime vs commit-time.** That rule mis-fired on
2026-08-22 — the pre-commit hook builds *before* the commit object exists, so a correct
binary always reads as stale. Force the question instead.

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

## 2b. Prove the binaries are this code

**D0A-R25-05: THIS STEP MUST PRODUCE HASHES, AND UNTIL ROUND 25 IT DID NOT.** The text below
this block used to say "an unchanged set of hashes after a forced rebuild is the proof" while
the commands computed **no hashes at all** — the first printed artifact *paths* through
`tail -3`, and the forced rebuild sent everything to `/dev/null`. Run 13 was recorded as
"forced freshness proven" on the strength of that. It was not proven; it was asserted next to
a command that could not check it. It runs HERE, after §2, because its input is the enumerated target list:

**D0A-R26-05: THIS STEP MUST *ENFORCE*, NOT PRINT.** The first corrected version printed
`rebuild rc=$?` and `before=N after=N` and then compared anyway — so a FAILED rebuild would
compare two STALE hash sets and print `FRESH`, and two identically-SHORT lists would compare
equal. That is the same defect one level up: a step that displays a number instead of deciding
on it. Every check below `exit`s.

```bash
set -o pipefail
N=$(wc -l < /tmp/targets.txt)
[ "$N" -eq 17 ] || { echo "REFUSE: enumeration is $N, not 17"; exit 1; }

sha256sum $(cat /tmp/targets.txt) | sort -k2 > /tmp/hashes-before.txt
[ "$(wc -l < /tmp/hashes-before.txt)" -eq "$N" ] || { echo "REFUSE: hashed fewer than $N before"; exit 1; }

touch runtime/src/execute.rs
cargo test -p delphi-runtime --tests --no-run > /tmp/rebuild.log 2>&1 \
  || { echo "REFUSE: the forced rebuild FAILED — comparing stale hashes would print FRESH"; tail -20 /tmp/rebuild.log; exit 1; }

sha256sum $(cat /tmp/targets.txt) | sort -k2 > /tmp/hashes-after.txt
[ "$(wc -l < /tmp/hashes-after.txt)" -eq "$N" ] || { echo "REFUSE: hashed fewer than $N after"; exit 1; }

diff /tmp/hashes-before.txt /tmp/hashes-after.txt \
  || { echo "REFUSE: the executables CHANGED under a forced rebuild — the earlier set was stale"; exit 1; }
echo "FRESH: all $N executables identical after a forced rebuild (both sides hashed $N)"
```

`diff` returning 0 over the FULL enumerated set, **with both sides asserted to contain exactly
the enumerated count and the rebuild asserted to have succeeded**, is the proof. A path listing
is not a hash; three paths are not seventeen; and a comparison of two stale sets is not a
freshness check.

## 3. The run — every target, serial, one log

```bash
# D0A-R34: REFUSE ON UNSET VARIABLES. In a fresh shell `$LOG`/`$STATUS` are empty, so
# `: > ""` fails with `bash: : No such file or directory` and the chain stops — while LOOKING
# like the long-running loop it was supposed to start. Same shape as the §4b omission: a step
# that appears to run and does not. `${VAR:?}` names the missing variable instead.
: "${RUN:?set RUN first (§0b)}" "${LOG:?LOG unset — re-run §0b}" "${STATUS:?STATUS unset — re-run §0b}"
: > "$LOG" ; : > "$STATUS"
while read -r b; do
  echo "### $b" >> "$LOG"
  sudo "$b" --nocapture --test-threads=1 >> "$LOG" 2>&1
  printf '%s\t%s\n' "$?" "$b" >> "$STATUS"   # D0A-R18-04
done < /tmp/targets.txt

# Every producer's status, checked. A target that CRASHES before printing its summary
# vanishes from the count entirely — the loop used to discard `$?` and the parse could not
# see the gap, so a subset could become the "exact" baseline.
awk -F'\t' '$1 != 0 {print "TARGET FAILED rc="$1" "$2; bad=1} END {exit bad}' "$STATUS" \
  && echo "all producers exited 0"
```

Serial is not a preference: `--test-threads=1` is what makes SKIP markers land
deterministically at column 0 (parallel interleaving made the same tree count 17/18/19), and
CLAUDE.md §6's fork+PAM carve-out makes the serial run the authoritative one for this shape.

## 4. The count — through the extractor, never by summing

`test-count.sh` shells out to `cargo`, so it cannot run under `sudo` here. Use its
**parse-only** mode on the captured log, unprivileged:

```bash
DELPHI_TESTCOUNT_EXPECT_TARGETS=$(wc -l < /tmp/targets.txt) \
  DELPHI_TESTCOUNT_LOG="$LOG" scripts/test-count.sh ; echo "rc=$?"
```

**`DELPHI_TESTCOUNT_EXPECT_TARGETS` is not optional (D0A-R18-04).** Parse-only mode has no
producer status to inherit, so it now derives failure from the log (any `FAILED` summary →
rc 1) and refuses unless it finds exactly the number of summaries the caller enumerated
(→ rc 2). Verified against three cases: a fixture with one plausible summary refuses at
rc 2, a log containing `FAILED` exits 1, the real 17-target log exits 0. **Write the
baseline only after this rc is 0 AND the producer-status check above passed.**

**VERIFIED, not assumed (2026-08-26, unprivileged dry run).** Running the 17 targets
separately and concatenating produces a log the extractor parses **identically** to the
normal cargo path — both `EXECUTED 148 / SKIPPED 25 / reported 173`. The concatenation is
not a shape the parser had been shown before, so it was checked rather than specified.

**The root `EXECUTED` figure is recorded from the extractor, never by subtraction** —
deriving it as `reported − skips` is arithmetic, and arithmetic of that shape put a withdrawn
expectation in the baseline once already. Run 7 recorded it and D0A-R18-07 then found the
figure stale (measured before the chain-gap test existed), so **run 8 overwrites it**:

```bash
printf 'EXECUTED=%s\nSKIPPED=%s\n' <executed> <skipped> > .githooks/runtime-test-count-baseline.root
```

Only from the extractor's own output. Never by subtraction.

## 4b. THE MEMBERSHIP CHECK — identities, never counts (D0A-R27-04)

**Equal totals are not equal test sets.** Both lanes reporting the same `reported` number
cannot detect a compensating removal and addition, and the run-14/15 records cited exactly that
as proof the sets were identical. It happened to be true — a reviewer verified it independently
— but the evidence recorded did not establish it.

```bash
: "${RUN:?set RUN first (§0b)}" "${LOG:?LOG unset — re-run §0b}"
mkdir -p "scratch/lane-run-$RUN"          # RETAINED, in the repo — see below
python3 - <<'EOF'
import re,subprocess,os,collections
root=collections.Counter(); target=None
for line in open(os.environ["LOG"], errors="replace"):
    if line.startswith("### "): target=os.path.basename(line.strip()[4:]).rsplit("-",1)[0]
    m=re.match(r"^test (\S+) \.\.\. ", line)
    if m: root[(target,m.group(1))]+=1
unpriv=collections.Counter()
for exe in open("/tmp/targets.txt").read().split():
    t=os.path.basename(exe).rsplit("-",1)[0]
    for l in subprocess.run([exe,"--list"],capture_output=True,text=True).stdout.splitlines():
        if l.endswith(": test"): unpriv[(t,l[:-6])]+=1
only_root=root-unpriv; only_unpriv=unpriv-root
print(f"root {sum(root.values())} / unpriv {sum(unpriv.values())}")
print(f"IN ROOT NOT UNPRIV: {sum(only_root.values())}"); [print("  ",k) for k in only_root]
print(f"IN UNPRIV NOT ROOT: {sum(only_unpriv.values())}"); [print("  ",k) for k in only_unpriv]
# D0A-R34: WRITE THE INPUTS SOMEWHERE THAT SURVIVES. Run 20's membership result became
# INDEPENDENTLY UNAUDITABLE because both comparison inputs lived in /tmp and were gone by the
# time anyone tried to check it — so the record stood on the operator's report alone, and
# matching totals do not substitute for an identity-set comparison. These files are committed
# with the run record.
out = f"scratch/lane-run-{os.environ['RUN']}"
# D0A-R35-05: write COUNTS, not bare keys. Serializing `sorted(counter)` drops multiplicity,
# so {a:2,b:1} and {a:1,b:2} produce identical files AND identical totals — the multiset cannot
# be reconstructed, which is exactly what an identity-set comparison is for. Run 21 happened to
# have no duplicates, so the defect was invisible in its output.
with open(f"{out}/root-identities.txt", "w") as f:
    f.write("\n".join(f"{c}\t{t}::{n}" for (t, n), c in sorted(root.items())) + "\n")
with open(f"{out}/unpriv-identities.txt", "w") as f:
    f.write("\n".join(f"{c}\t{t}::{n}" for (t, n), c in sorted(unpriv.items())) + "\n")
with open(f"{out}/membership.txt", "w") as f:
    f.write(f"root {sum(root.values())} / unpriv {sum(unpriv.values())}\n")
    f.write(f"IN ROOT NOT UNPRIV: {sum(only_root.values())}\n")
    for k in only_root:
        f.write(f"  {k}\n")
    f.write(f"IN UNPRIV NOT ROOT: {sum(only_unpriv.values())}\n")
    for k in only_unpriv:
        f.write(f"  {k}\n")
print(f"identity lists retained in {out}/ — commit them with the run record")
raise SystemExit(0 if not only_root and not only_unpriv else 1)
EOF
echo "membership rc=$?"    # 0 = identical sets; ANY non-empty side is a RESULT
cp "$LOG" "scratch/lane-run-$RUN/root-run.log"   # the producer transcript, also retained

# D0A-R35-04: RETAIN EVERY ARTIFACT THE RECORD ASSERTS ABOUT. The lane record claims freshness,
# producer exits and hygiene results; until now only the membership inputs were kept, so those
# other claims were operator reports exactly like Part B's transcription was. Retention was
# fixed where the finding pointed and nowhere else — class 48 inside the remediation.
cp /tmp/hashes-before.txt /tmp/hashes-after.txt /tmp/rebuild.log "$STATUS" \
   "scratch/lane-run-$RUN/" 2>&1 | tee -a "scratch/lane-run-$RUN/retention-errors.txt"
{ echo "=== free space ==="; scripts/check-free-space.sh
  echo "=== stale sessions ==="; scripts/check-stale-test-sessions.sh
  echo "=== PAM ==="; md5sum -c /tmp/pam-before.md5
  echo "=== helper digests ==="; sha256sum /usr/libexec/delphi-drop installer/staging/delphi-drop
  echo "=== account ==="; getent passwd delphi-tool
  echo "=== bwrap ==="; bwrap --version
} > "scratch/lane-run-$RUN/hygiene.txt" 2>&1
ls -la "scratch/lane-run-$RUN/"
```

Counters, not sets — a duplicated `#[test]` inflated a count once already, and set arithmetic
would hide it. **A non-empty side is a result, not noise:** name the tests and explain each,
exactly as a count mismatch would be explained. If the tree has moved since the root run, the
delta must be exactly the tests added or removed since — verify that by name, not by number.

**RETAIN `$LOG`** until this has run. It is the only record of which tests actually executed.

## 4c. PART B — the assembly control, retained rather than transcribed

Part B rebuilds with `--features insecure-test-seams`, so it must run AFTER §2b's hashes.
**Tee it**: its `CONTROL OBSERVATION` line is the evidence D0A-R28-02's supplementary scan
rests on, and run 21's was only ever a terminal paste (D0A-R34's ruling: printing alone is not
durable storage).

```bash
: "${RUN:?set RUN first (§0b)}"
cargo test -p delphi-runtime --features insecure-test-seams --test b1_integration --no-run \
  --message-format=json 2>/dev/null | python3 -c 'import sys,json
for l in sys.stdin:
    try: m=json.loads(l)
    except Exception: continue
    if m.get("executable") and m.get("profile",{}).get("test"): print(m["executable"])' \
  | sort -u > /tmp/b1-seams.txt
sudo "$(cat /tmp/b1-seams.txt)" b1_daemon_bounds_an_ai --nocapture --test-threads=1 \
  2>&1 | tee "scratch/lane-run-$RUN/part-b-control.txt"
```

## 5. The three checks, BY NAME

```bash
grep -c '^test result: FAILED' "$LOG"          # failures — expect 0
grep -E '^test .+ \.\.\. (SKIP|DEFER)' "$LOG"  # skips — print them, do not count only
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

## 7. The chain-gap demonstration — DIAGNOSIS DISCIPLINE (test BUILT, `d4a741e`)

`chain_gap_approved_path_selects_the_impostor_and_the_preview_discloses_it` in
`b1_integration`. Its failures are ambiguous by default and must not be diagnosed from the
message alone. **This discipline has already paid once**: written before the test existed, it
turned the first run's `left: ""` into `coreutils: unknown program 'tool'` immediately —
the signature that had cost this arc three inferences on four occasions.

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
