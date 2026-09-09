# Codex adversarial review — D0-A round 33 (the merge gate)

This prompt is `scratch/codex-d0a-round33-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff 05d89c6..5fca885`** — seven commits. Pinned to a SHA, not `..HEAD` (D0A-R18-09).

```
 18 files changed, 1261 insertions(+), 182 deletions(-)
```

The round-32 remediation (5×P2), the assembly positive control you asked for, EINTR coverage,
and lane run 20.

---

## Lead: TWO PROCESS FAILURES, and they are the round's content

Run 20's headline is a green — counts matched a prediction exactly, and the positive control
passed. **That is the weaker of the two outcomes that were available**, and it is not what this
round is about. Two process failures happened around it, both by the humans rather than the
mechanisms, and a good result is exactly when those get buried.

### 1. A PROCEDURE CHECK WENT MISSING BY HAND — WHILE CITING THE PRECEDENT AGAINST THAT

`scripts/lane-run.sh` was **REVERTED at D0A-R23-05** for a specific reason: *the runner dropped
five checks the procedure performs* — helper-digest, free-space, forced-freshness,
stale-session, PAM before/after. Eight P1s, and that finding is the one that decided it. The
conclusion drawn was that the ordering protocol stays **enforced by convention, with a human
following the procedure**.

In this range, I assembled the operator's run-20 command sequence *from that procedure* and
**omitted §4b, the identity membership check** — the step that exists because equal totals are
not equal test sets (D0A-R27-04). Run 19 carried it. Run 20's sequence did not. This happened
in the session that quoted the reversion.

It was closed after the fact — `/tmp/root-run20.log` and `/tmp/targets.txt` had survived, so the
check ran unprivileged afterwards and returned **227 identities each side, zero in either
direction, rc 0**. The result is sound. **But it is sound because artifacts happened to still be
on disk, which is luck about retention, not a property of the process.** Closed-after is not run.

**THE QUESTION, and it is about a decision I recommended and executed, so neither of us can
judge it:** does *"a human follows the procedure"* survive its own precedent? R23-05's reasoning
was that a script which reimplements a procedure drops checks. This instance says a human who
transcribes one drops checks too — **an argument the revert's reasoning did not make.**

The operator's own framing of the asymmetry, offered here because it cuts against the easy
answer: the runner's omissions were **systematic**, and therefore findable by inspecting the
runner once. A hand-assembled sequence **omits differently every time**, so there is nothing to
inspect. That is not an argument for restoring the runner — R23's eight P1s stand — but it does
mean "a human follows the procedure" was never the *stronger* half of that trade, only the
**better-scoped** one. Round 20 and round 24 were productive because they asked you to judge a
decision the asker was inside; this is the same shape.

Is there a third option that is neither the reverted runner nor unaided transcription — and if
the answer is "a checklist the human ticks", say why that is not just the same failure with
more steps?

### 2. A PRECONDITION FIRED AND THE RUN PROCEEDED

```
/home/revanth-aditya/delphi-target   1089M   floor 2048M   *** SHORT ***
"SHORT ON SPACE ... This is a PRECONDITION failure, not a build or test failure"
```

The free-space guard (D0A-R29-08) did exactly what it was built for. The operator overrode it
and ran anyway. Nothing observable went wrong — 17/17 producers exited 0, freshness proved,
counts matched — so this is **not** a claim the evidence is tainted.

It is the record that the run began from a state the procedure refuses, and that guard exists
*because its failure mode surfaces far away wearing another subsystem's name* (a full `/tmp`
once presented as a protoc build error in an unrelated crate). **A guard that is overridden has
spent its value whether or not the run got away with it.**

Note the shape both failures share: **the mechanism worked and the human did not.** §4b was in
the procedure and was not transcribed; the free-space check ran, printed a refusal, and was
stepped over. Is that a corpus class, or two unrelated lapses that happen to rhyme? The corpus
currently has no entry for *the check fired and was overridden* — 51 is about a false claim in a
trusted record, 49 about silence, and neither covers a refusal that was simply walked past.

---

## The strengthened register sentence — ATTACK IT

D0A-R28-02's row now reads:

> **The scanner was proven capable of seeing the daemon's own fork/exec'd child in its inherited
> process group, and no live group members remained before harness intervention; daemon reaping
> was not observed.**

The first clause is new at run 20. **The wording was fixed BEFORE the run**, in the committed
expectation (`fc22117`), together with what a failure would do — withdraw the closure rather
than the test. So the strengthening is constrained to what was predicted.

**But pre-commitment governs SCOPE, not CORRECTNESS.** A sentence written before the evidence
can still be the wrong sentence for the evidence that arrived. Specifically:

- The control proves the scanner saw the AI **alive at some point during the run**, by `comm`.
  The survivor sample happens **later**, at shutdown. Does capability-at-T1 license the
  inference about emptiness-at-T2, or is there a gap the sentence papers over?
- *"proven capable"* — of seeing **that** child, in **that** run. Is it entitled to the general
  form the sentence states?
- The probe returns as soon as it finds one match, so the census retained on a PASS is smaller
  than on a failure. Does the pass therefore retain enough to be re-read later?
- Is *"daemon reaping was not observed"* still doing its work now that a stronger clause sits in
  front of it, or does the new first clause make a reader skim past the disclaimer?

**I would rather be told this row overstates for the third consecutive round than discover it in
round 34.**

---

## The round-32 remediation — attack its sufficiency

| finding | fix | attack |
|---|---|---|
| **R32-01** | `/proc/<pid>/stat` read as BYTES; fields after the LAST `)`; an unreadable entry reported as `(pid,'?')` rather than skipped | absence must be proven, not inferred from a failed read. **Is the sentinel path right**, or does returning `vec![(-1,'?')]` when `/proc` cannot be enumerated create a member that no assertion expects? |
| **R32-03** | a real zombie: checked `waitid(WNOWAIT)`, `Z` read back from `/proc` **before** the scan | you ran the old fixture 30/30 with the exclusion deleted and it passed. It now fails **10/10**. Is 10 enough for a fixture whose whole job is exhibiting a condition? |
| **R32-02** | worker identity published; **sampled before `proc.wait()`** | **the identity fix alone was not sufficient and the weaken said so** — see below |
| **R32-04** | a dirty instrument is REFUSED; `--instrument-dirty-ok` RETAINS the executing bytes | refusal was chosen over re-exec deliberately. **Is retention-with-a-flag actually your third option**, or does an escape hatch reintroduce what refusal was for? |
| **R32-05** | lifetime `finally`; the `mkdtemp` parent collected; the guard reads the filesystem | 38 abandoned parents had accumulated **while a guard watched `git worktree list` and saw nothing.** Is there another resource in this harness whose guard watches the registration rather than the thing? |

### TWO FALSE GREENS IN MY OWN NEW GUARDS — both found by weakening, neither by review

This is the generalizable result of the round, and both are the shape you named in R32-02.

1. **The R32-04 guard asserted `returncode == 2`.** With the refusal turned into a warning the
   campaign proceeds, the stub baseline is not green, and **the BASELINE refusal returns 2 as
   well** — the same exit code by a different mechanism, so the assertion could not tell which
   world it was in. Now asserts the campaign BODY never ran (no `lane.json`, no checkout line).
2. **The R32-02 guard passed with the group killer replaced by a no-op.** Aiming it at the
   worker's identity was necessary and **not sufficient**: the sample sat after `proc.wait()`,
   and measured with the killer disabled the worker is alive at +0.2/+0.5/+1.0 s and gone by
   ~3 s, while `wait()` returns at ~3 s. The guard was measuring after the thing that erases the
   difference. **Sample where the two worlds differ** — R31-02's lesson, one level down.

Each weaken is now recorded with **the assertion it failed on**, because a weaken that fails
elsewhere proves nothing about the guard it targets:

```
C  R32-04 refusal   -> instrument: the campaign BODY never ran (no lane.json)
A  R32-05 mkdtemp   -> signal: no mkdtemp parent is left behind either
D  R32-05 lifetime  -> lifetime: the baseline refusal leaves no mkdtemp parent
B  R32-02 killpg    -> signal: the WORKER's group dies PROMPTLY, before the wait
```

**Is that discipline sufficient as stated, or does it need to be a mechanism?** It is currently
a thing I remembered to do.

---

## Lane run 20, and one derivation error worth judging

`221/6/227` at `fc22117`, predicted exactly, expectation committed **alone** beforehand.
Membership 227/227. Freshness enforced with both hash sides asserted at 17. PAM `md5sum -c` OK.

**The first enumeration of the derivation was WRONG.** It used `fn [a-z_]+` — no digits — so
every test with `b1` in its name was invisible, **including the assembly test the run existed
for**. Corrected to `[a-z0-9_]+` before the expectation was written. The procedure's rule is
"verify by grep, never from memory"; this is a grep that was itself wrong, and the rule as
written does not cover it. **Does that want a stronger formulation, or is it adequately covered
by the cross-check that caught it** (the unprivileged/root partition agreeing on the same six)?

## EINTR — now in the required suite

Constructed rather than waited for: SA_RESTART deliberately **absent** (with it the kernel
restarts `waitpid` and EINTR never reaches the code), `pthread_kill` aimed at the blocked thread
rather than the process. **The RED is the evidence, not the green** — deleting
`Err(EINTR) => continue` fails 10/10; had no interruption occurred, deleting the retry would
change nothing. 30/30 restored under default parallel settings.

By your own four categories this moves from *experimentally observed* to **regression guarded**.
Confirm or correct that classification.

## What remains open

R29-05's `Unreaped` is **UNCONSTRUCTED** and reaping is still **not observed**; `action.timeout`
enforced nowhere (R9-04, binding only); the pending store has no cap; the mutation campaign is
unprivileged-only and the six root-gated tests have never been mutation-tested; the suspend
divergence is unmeasured; **the production logind gate is blocked on a seated lane** (Part B
runs a seam-built binary and certifies nothing about it); R22-01 reopened; R21-01's
semantic-forgery half, R21-04 and R21-06 await the native-UI increment.

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per §13.9

**(a) Pre-foreclosed:** **10** (a skip reports `ok`); **43**; **44**.

**(b) Applicable and NOT foreclosed:**

- **48** (fix scoped to the named instance) — **two live instances this round.** `leader_is_shell.rs`
  guarded an unconditional `userdel` pre-clean and documented why; `b1_integration.rs` did not,
  and its noise landed in run 20's transcript. And R32-02's identity fix was scoped to the
  instance without the timing that made it bite.
- **45** (the totality claim) — this range asserts "the scanner was proven capable", "each
  weaken fails on the assertion it targets", "227 identities each side". **Audit all three.**
- **49** (silence ≠ coverage) — the passing control confirms rather than overturns; is that a
  49-shaped green?
- **51** (a false claim in a trusted document) — the register row is the venue, third round running.
- **41** (wrong altitude) — `live_group_members` and `comm_of` are hand-rolled `/proc` parsing
  standing in front of the closure, and R32-01 was a defect in exactly that.
- **NO CLASS COVERS** *a check that fired and was walked past*, or *a procedure step lost in
  transcription*. Both happened here. Say whether either is a class.

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Each finding: **ID** (`D0A-R33-nn`), **severity**, **root
cause**, **impact**, **fix sketch**.

**Most valuable returns:** (1) **whether "a human follows the procedure" survives R23-05's own
reasoning**, given that a human transcribing dropped a check the way a script reimplementing
did; (2) **a defect in the strengthened register sentence** — pre-commitment fixed its scope and
cannot fix its correctness; (3) a defect in the positive control, which is new, is now the
evidence for a closure restated three times, and passed on its first run; (4) a defect in a file
no prompt has named.
