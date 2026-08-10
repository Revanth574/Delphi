# Codex adversarial review — D0-A round 5

<!-- Invocation: codex review - < scratch/codex-d0a-round5-prompt.md
     All three range-selection flags reject a PROMPT positional; scope is carried here. -->

## Scope — pinned endpoint, stat regenerated at write time

Round 4 was **REVISE — 3×P1, 2×P2, 1×P2-low**. All six are fixed, plus six more found while
fixing them (R4-07 through R4-12).

**Target: `0f516b8..0f23c0a`.** Both ends are commits, so a later commit cannot move this scope.
`git diff --shortstat 0f516b8..0f23c0a`, regenerated as this was written: **9 files changed,
523 insertions(+), 38 deletions(-)**. Report a mismatch as a finding.

---

## THE PRIOR — read this before deciding where to spend budget

**The verification code in this increment has been wrong more often than the code it verifies.
Weight scrutiny accordingly. This is not a caveat; it is the base rate.**

- R4-03's merge-blocking test took **eight attempts to execute once**. **Seven of the eight
  failed on HARNESS defects. None failed on the wiring under test.** Four orphaned root daemons
  (a straight-line teardown a panic skipped); a service-keyed precondition tripping on a
  lingering `systemd --user`; a missing `DELPHI_AI_EXE`; an unbounded `waitpid` on a shell with
  nothing to wait for; a presence check reading stderr while the daemon logged to stdout.
- **Three of round 4's own six findings were in verification code**: the barrier harness racing
  the property it measures (R4-02), the same harness compiling and running as root from a
  guessable path (R4-01), and the ledger overstating what had been measured (R4-06).
- Every one was found **by inspection**, not by re-running. That is the only reason the count of
  leaked root daemons stopped at four.

So: **when something in this diff looks correct, ask what would have to be true for its
verification to be lying, before asking whether the subject is wrong.**

---

## LEAD 1 — a bias described in writing, then committed three more times

Round 4 added `DEFECT_CLASSES` **34: a deferral is an untested claim** — the observation that
"needs the lane" had meant something cheaper twice and something impossible once, always in the
same direction, because an expensive deferral is never falsified by the work stopping.

**In the same round, three further instances shipped**, in two files: `PROGRESS.md`'s unmarked
"OWED TO THE LANE", `logind.rs`'s module doc, and the barrier test's own comment — all still
asserting a **seated lane** for work that was **root-gated** and that this dev box settled with
`sudo`. All three are now superseded in place, with the mistaken framing kept visible.

**A bias stated in writing and then re-committed three times is stronger evidence for the bias
than the original three instances were.** *Is the corpus entry's foreclosing discipline — quote
the MEASURED blocker, never an environment category — actually enforceable, or does it need a
mechanism? Is there any check that could have caught these three?*

---

## LEAD 2 — Class 36, a new shape: mutual stabilisation

`DEFECT_CLASSES` **36** was added this round. R1-02's fixture returned
`SessionSnapshot::DENIED` — all three axes false — to model "the session stopped qualifying
during authentication". **That is an impossible session**: one that loses the seat's foreground
*keeps its seat*. The test was proving a transition that cannot occur.

Nothing surfaced it, because the assertion was pinned to a literal sentence that the impossible
shape happened to produce. **The wrong fixture and the literal assertion were mutually
stabilising — neither is detectable from the other — and only an unrelated wording change
(R4-04) disturbed the pair.** The obvious repair, swapping in the new literal, would have
restored the agreement and left the test green about an event that cannot happen.

**The question I most want answered: are there other literal assertions in this tree paired with
fixtures nobody has questioned?** The pair is invisible from either side, so it needs looking
for deliberately rather than encountering.

---

## LEAD 3 — a counter with no discriminating power

R1-02's first ≥30 attempt reported `30 0` and **measured nothing**.
`grep -cE '^test .* \.\.\. ok$'` returns 0 under `--nocapture` for any test that PRINTS, because
its own output pushes `ok` onto its own line. So `30 0` was **equally consistent with 30 passes
and 30 failures**. It was caught only because the result was checked against what it could
distinguish before it was read.

The re-run counts **executions reaching the assertion** — the shell's `approved + mint-confirm
sent` marker — rather than result lines, because a skip scores as a pass: `exec=1 skip=0 pass=1`
× 30, 0 daemons.

***How many other counters in this tree have no discriminating power?*** This one looked fine
until someone asked what it could tell apart. `scripts/test-count.sh`, the CI gate, the barrier
suite's `pass`/`fail` tallies and the stale-session checker are all in scope for that question.

---

## What was fixed

**R4-01** the harness compiled and ran `driver`/`resolve`/`preload.so` **as root** from
`/tmp/delphi-barrier-$$` via `mkdir -p`, which succeeds on a pre-created dir or symlink.
Demonstrated: the build landed in an attacker-owned directory. Now `mktemp -d` plus refusals on
symlink/owner/mode. **R4-02** the root leg never asserted the recycle landed on the victim's pid,
so a lost race left ESRCH looking correct for the wrong reason — and the teardown killed the raw
pid, which could kill an unrelated process and leak the impostor. Now asserted and fatal; race
rate **measured zero over 60 root runs**, with a live trigger to move into a pid namespace if it
ever fires. **R4-03** the production wiring now executes and **resolves**:
`Resolved { active: false, remote: false, seated: true }` — the assembly reaches logind and is
described, not merely denied. **R4-04** denial wording derived from the failing axes; the
foreground claim made only when `active` alone flipped. **R4-05** `classify_seat_rc` extracted as
a pure function, which **bites the weaken D0A-R2-04 recorded as unbitten**. **R4-06** three
superseded claims. **R4-07/08** the daemon leak and the lingering user manager. **R4-09/10/11/12**
the AI env, the unbounded reap, the wrong stream, the deadline mismatch, the impossible fixture.

---

## Verification boundary

lib 84/84; `EXECUTED 121 / SKIPPED 22`; b1_integration 14; barrier 5/5 unprivileged and 12/12
root with **60 root repetitions, 0 failures**; R1-02 **30 executions reaching the assertion**;
clippy rc=0 in both feature configurations and on the decoupled shell-host.

**No outstanding lane-gated or root-gated obligations.** Given that this claim has been wrong
three times on this branch, **check it rather than accept it**: grep the `SKIP`s, read
`PROGRESS.md`'s notes, and say if any deferral is still standing.

---

## Defect classes — attention allocation

**Pre-foreclosed:** 1, 10, 25, 22's applied-and-located rule, 34 (deferrals quote a measured
blocker), 35 (falsifiers pair with a positive control), 36 (assert properties, not sentences).

**Spend the budget here:** **36** — other literal/fixture pairs, per LEAD 2. **27** — R4-04's
wording change broke R1-02's proof one hour after landing, because the seam question was asked
of R4-04 against R4-05 and the deadline change but **not** against the tests its wording
underpins; the direction where a FIX invalidates a PROOF is the one that keeps being skipped.
**33** — the new axis-derived denial strings reach the operator and are unreviewed at that seam.

---

## Verdict

**APPROVE / REVISE / FAIL**; per finding: ID (`D0A-R5-NN`), severity, root cause, impact, fix
sketch.

Given the prior at the top: **a finding in the verification code is worth more here than a
finding in the subject**, because the subject has been checked eight times and the checkers
have not.
