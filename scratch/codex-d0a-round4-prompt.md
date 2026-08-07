# Codex adversarial review — D0-A round 4

<!-- Invocation: codex review - < scratch/codex-d0a-round4-prompt.md
     All three range-selection flags reject a PROMPT positional; scope is carried here. -->

## Scope — pinned endpoint, stat regenerated at write time

Round 3 was **REVISE — 1×P1, 4×P2**. All five are fixed.

**Target: `b2c0d58..9a5ad29`.** Both ends are commits (D0A-R2-07), so a later commit cannot move
the range underneath this prompt. `git diff --shortstat b2c0d58..9a5ad29` reports, regenerated as
this was written: **11 files changed, 358 insertions(+), 33 deletions(-)**. Report a mismatch as
a finding.

| commit | content |
|---|---|
| `e4c0c8e` | R3-01 harness + R3-02/03/04/05 |
| `14e2ff0` | R3-01 follow-up — the control fired the barrier it was controlling for |
| `5b9d83e` | R1-01 discharged; the delegation measured |
| `9a5ad29` | `DEFECT_CLASSES` 34 and 35 |

---

## LEAD — what is NOT proven, because that is where the remaining risk is

**1. THE PRODUCTION WIRING HAS NEVER EXECUTED. This is the largest gap in D0-A and it survived
three rounds.**

`LogindSource::for_pidfd` is constructed at exactly one site — `delphi-runtimed.rs:188` — and the
only test that runs the daemon binary, `b1_daemon_binary_runs_the_assembled_flow`, enables
`insecure-test-seams`, whose seam returns a `FixedVerdict` and **never reaches `LogindSource`**.
Every other test injects a source. So *`LogindSource` + a real `shell_pidfd` + a real logind
session* have never run together in a passing test. Each piece is proven; **the assembly is not.**

It survived three rounds because every round scoped itself to a fix rather than to the wiring —
the same reason D0-A's original three findings survived seven rounds before it.

*Is there a test shape that would exercise the real assembly without the `insecure-test-seams`
bypass? The blocker is that the seam exists precisely because the daemon-spawned shell's session
is what B2a's lane work is about — but R3-01 just showed a session can be arranged cheaply, so
please say whether that changes the answer.*

**2. The seat-axis collapse is UNBITTEN.** R2-04 separated a failed axis query from a genuine
"no seat". Two of three axes are covered by construction; making `sd_session_get_seat` fail with
something other than `-ENODATA` while the other two succeed needs a session whose seat query
errors, which I could not construct. Recorded in the test.

**3. The barrier depends on `fopen64`, and I asked about this last round and did not get an
answer.** `strace` prints `openat`; interposing `openat`, `openat64` and `__openat64_2` all
caught **nothing**. The live symbol is `fopen64`. If libsystemd is ever built differently, the
barrier **stops firing silently** — the exact failure shape it exists to prevent. The
`BARRIER MATCHED` assertion catches a total miss; is that sufficient, or does it need a guard
that fails when the expected read is never observed at all?

**4. R6 remains a bet.** `DEATH_GRACE = 250 ms` is calibrated on one box and one kernel; a
machine that misses it degrades to a **false READY**. Unchanged this round, still recorded.

**5. Producer-side tearing is acknowledged, not foreclosed** — `query_detailed` makes three
libsystemd calls and logind offers no atomic read.

---

## THE OBLIGATIONS LEDGER IS NOW EMPTY — please check this rather than accept it

D0-A carries **no lane-gated and no root-gated outstanding work**. That is a claim a reviewer
should test, not take: grep for `SKIP` in the runtime tests and ask whether each skip is covered
by something that ran, and check `PROGRESS.md`'s notes for any deferral I have left standing.

Both entries previously carried as "needs the lane" were **root-gated**, and one of those was
**unprovable as written**. Three instances, all in the same direction — recorded as
`DEFECT_CLASSES` **34: a deferral is an untested claim**. The mechanism: the *skip condition* and
the *ledger's deferral category* are different claims and only the first is ever checked; an
expensive deferral is never falsified by the work stopping, so the error is selected for.

---

## What was fixed, and the two results worth weighing

**R3-01 (P1) — the delegation is now MEASURED, not cited.** `sudo runtime/tests/pidfd-barrier.test.sh`
→ 12/12:

| run | configuration | result |
|---|---|---|
| control | victim in a real session, barrier inert | `rc=0 session=2` |
| barrier | **impostor** in the session, victim reaped and its pid recycled mid-call | `rc=-3` (ESRCH) |

`ENODATA` would mean the lookup returned before verification and told us nothing. `ESRCH` on a
**successful** lookup means the verification step ran and refused. The discriminating
configuration was derived from *your own boundary* — verification runs only on successful
session-returning paths, therefore the impostor goes in the session, not the victim
(`DEFECT_CLASSES` 35).

**The control caught my bug before it caught anything else:** its first version fired the barrier
it was controlling for, because the shim armed on an env var the driver always sets. A leg now
asserts the control shows no `FIRED` line.

**R1-02 discharged**, executed under sudo:

```
test b1_session_lost_during_pam_blocks_the_mint_d0a_r1_02 ... ok
[minimal-shell] approved + mint-confirm sent
Denied { reason: "logind: the shell session stopped being active+local+seated DURING
         authentication - the seat's foreground moved, ..." }
```

The ordering is the discriminating detail: **`approved + mint-confirm sent` precedes the
denial**, so the flow passed the pre-PAM gate, PAM and mint-confirm and was refused after. A
first-gate denial would show no approval at all.

**R3-02** the cause now reaches the response (`SessionSource` returns `SessionResolution`;
`Resolved` still carries a concrete snapshot, so R1-04's foreclosure is untouched). **R3-03** the
expected wording is named independently plus a no-doubled-spaces assertion — sharing a constant
forecloses drift but cannot verify correctness, which is how R2-05's garbled message passed.
**R3-04** the `CHANNEL_FD` literal closed. **R3-05** stale weakens marked superseded; **and the
same class was found one section up**, where A2 still described the `/proc/fdinfo` two-step —
a mechanism R1-01 replaced *because it was race-prone* — as current.

---

## Verification boundary

lib 83/83; `EXECUTED 120 / SKIPPED 20`; barrier 5/5 unprivileged and **12/12 under root**;
b1_integration 12; logind_gate 4/4; clippy rc=0 in both feature configurations and on the
decoupled shell-host.

---

## Defect classes — attention allocation

**Pre-foreclosed:** 1, 10, 25, 22's applied-and-located rule, and now **34** (deferrals quote a
measured blocker) and **35** (falsifiers pair with a positive control).

**Spend the budget here:** **Class 27** — R3-02 changed the trait's return type while R3-01
changed the harness; both touch how a verdict reaches a decision. **Class 26** — is anything else
in the tree asserting a present-tense claim its code cannot support? **Class 33** — R3-02's
`denial()` strings now reach the operator for the first time and are unreviewed at that seam.

---

## Verdict

**APPROVE / REVISE / FAIL**; per finding: ID (`D0A-R4-NN`), severity, root cause, impact, fix
sketch.

The judgement I most need: **item 1** — whether the unexercised production wiring is
merge-blocking or a documented gap for P4, given that D0-A's own three findings were exactly this
shape (each piece proven, the seam between them not). If it blocks, say what test shape would
close it.
