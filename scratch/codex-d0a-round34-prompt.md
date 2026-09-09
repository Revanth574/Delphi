# Codex adversarial review — D0-A round 34 (the merge gate)

This prompt is `scratch/codex-d0a-round34-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff 04428d2..d94875d`** — two commits. Pinned to a SHA, not `..HEAD` (D0A-R18-09).

```
 12 files changed, 766 insertions(+), 45 deletions(-)
```

The round-33 remediation (4×P2) and your evidence directory retained.

---

## Lead 1: a diagnostic I wrote chose the answer that protected my own closure

The assembly positive control could fail two ways that present identically. Its failure message
resolved the ambiguity with a **rule**:

> census NON-EMPTY but no `sai` -> the scan reaches the group and the AI was not identified in
> it: a comm mismatch, or a window this probe missed. **That is a defect in the control, not
> evidence about the daemon.**

The other branch — census empty — was the one that would have withdrawn D0A-R28-02. So the rule
sent one shape to "my instrument is broken, the closure stands" and the other to "the closure
falls". **I wrote the rule, and I was the party whose closure was at stake.**

You constructed the case it gets wrong:

```
control_attribution: seen=[] census=[(9609, 'S', "sleep")] samples=22 ai_pgid=9608 exit=0
```

Two real daemon-fixture children, one inheriting the group, and **the correctly named AI in
another group** — a topology defect, receiving the diagnosis that preserves the closure.

**Why it survived a round is the part I want attacked.** The rule was only ever exercised
against the case it was written for. Nothing constructed its counterexample, and a rule run on
its intended input always agrees with its author. The general form is now corpus **class 53**
with a test that is answerable before any evidence exists — *if the rule had come out the other
way, would you have accepted it as readily?* — and a RED-proof shape: **construct the case the
rule gets wrong.**

**Is class 53 stated at the right altitude, or is it a special case of 45 wearing new clothes?**
And: **are there other decision procedures in this tree that pick between two causes?**
`run_suite`'s classifier (INFRASTRUCTURE / UNATTRIBUTED / PRECONDITION / CAUGHT / NOT CAUGHT)
maps evidence to cause by matching marker lists, and I have not audited it under 53.

### The fix, and the fact that NONE of it has run

The rule is gone. The probe samples the AI's real pid and pgid **system-wide while it is alive**
— a post-hoc lookup finds nothing, because the process is dead by the time the assertion fires —
and computes TOPOLOGY / SCAN / **UNRESOLVED** from identity, group membership and lifetime.

**Every one of those three branches is unexecuted.** They live inside an assertion that only
fires when the control FAILS, in a test that requires root plus `insecure-test-seams`, and there
has been no root run since the change. The verdict logic is compiled, type-checked, and never
evaluated. That is the same "compiled, linked, and run past rather than through" condition that
kept D0A-R28-02 open for three rounds, now reproduced one level down in the thing built to close
it. **What is the cheapest construction that exercises all three verdicts?**

---

## Lead 2: one lane run's membership claim is now unauditable by anyone

You could not verify run 20's 227/227 membership because `/tmp/root-run20.log` and
`/tmp/targets.txt` are both gone, and you correctly refused matching totals as a substitute —
which is the entire reason §4b exists.

So the record's membership line **stands on my report of having run it**. That is the second
edge of "closed-after is not run": the check was performed late AND its inputs were transient,
so **lateness became unverifiability**. The forward fix is recorded (a future §4b writes its
identity lists into the run's retained artifacts, not `/tmp`), but the standing fact is not
repairable — that run's membership is now unauditable, permanently.

**Does an unauditable check retain any value, or should the line be struck from the record?** I
have left it in with the caveat attached. The argument for striking it: a claim only I can
vouch for is exactly what the retained-artifact discipline exists to eliminate, and leaving it
with a caveat is how a weak claim survives. The argument for keeping it: it is true, and
deleting true records to look rigorous is its own failure. **Rule on it.**

---

## THE SAME ROW HAS NOW BEEN CORRECTED THREE TIMES — is the third one right?

| round | what was wrong |
|---|---|
| 31 | CLOSED on evidence that could not tell the daemon's cleanup from the harness's |
| 32 | restored, but "the daemon cleaned up" overstated what run 5 observed |
| 33 | prose corrected — and **the TABLE beneath it still said "the DAEMON cleaned up"**, plus a third outcome needing a post-intervention observation the test never retains. The `DaemonRun` doc comment carried a copy of the same table |

**A claim that needs correcting three times has a shape problem, and you are better placed than
either of us to say whether the current version still has it.** The row now reads:

> **In lane run 20, the scanner was observed finding the daemon's own fork/exec'd child alive in
> the daemon's process group, and no live members of that group remained before harness
> intervention; daemon reaping was not observed.**

with a table of what each retained value supports and does not support, and two outcomes rather
than three.

Specific things to press: is *"no live members remained"* still doing causal work it has not
earned? Does the scoping to run 20 actually bind, or is it decoration in front of a sentence a
reader will generalise anyway? **Is the right answer that this row should not exist at all until
reaping is observed?**

Note the mechanism of round 33's instance, because it is not the same as 31's or 32's: the
correction was applied **to the prose while the table beneath it kept the withdrawn claim**. A
table is not read as prose, so it survives a rewrite aimed at sentences. Is that worth a corpus
entry of its own, or is it class 48 (the fix scoped to the instance named) applied to a document?

---

## R33-02: MY PROOF WAS WORTHLESS AND THE FIX IS THEREFORE UNJUSTIFIED BY ME

Reported this way deliberately. The EINTR test's signal sender was cleaned up only on the normal
path, so a panic in the call under test — the exact weaken the test exists to fail under — left
it running.

**The two-factor weaken I ran to demonstrate impact gave `168 passed; 1 failed` in BOTH shapes,
10/10 identical.** By clause 2 that is worthless: FAIL/FAIL discriminates nothing.

Measuring the **mechanism** instead does discriminate — after the unwind, `DELIVERED` rises by
**50 in 300 ms** pre-fix and by **0** after. So the sender demonstrably survives the unwind. But
**the downstream contamination is undemonstrated by me**, and the fix is therefore defence in
depth rather than a proven impact. **Is that the correct scope, or does the leak have a
consequence I failed to construct?** The `pthread_kill` target is a thread that has finished
unwinding, which is a stale `pthread_t` — I did not chase whether that is merely `ESRCH` or
something worse.

## The rest of the round-33 remediation — attack its sufficiency

| finding | fix | attack |
|---|---|---|
| **R33-01** | returns bool; ownership RETAINED on failure; exit 4; **verdict from FINAL STATE** | my first version derived the verdict from `git worktree remove`'s exit code, which made the RETRY report failure — the first attempt had already pruned the registration, so the second legitimately errors while the removal succeeds. Guard uses your mode-000 reproduction. **Is exit 4 propagated everywhere it should be**, including the signal path? |
| **R33-04** | both copies of the table replaced; sentence scoped to run 20 | see above |
| **PASS-path retention** | the control's observation now prints on success | is `eprintln!` the right channel, given that this project has already been bitten by asserting against the wrong stream (class 52)? |

## What I did NOT build, and why — judge the deferral

Your third option — **one authoritative executable procedure, retained per-step evidence, and an
acceptance verifier that rejects missing, failed or misordered checks** — is accepted as the
right answer, and is materially different from the runner reverted at D0A-R23-05, because an
acceptance verifier is specifically the mechanism that catches silent check-dropping.

**It is not built.** The operator's reasoning: it is infrastructure, and this branch's history
with infrastructure-during-remediation is the argument against — `scripts/lane-run.sh` was
itself built mid-arc and returned eight P1s. So it is named as a next increment rather than
attempted here. **Is deferring it correct, or does every round it is deferred cost another
hand-assembled sequence with a different check missing?**

## What remains open

R29-05's `Unreaped` is UNCONSTRUCTED and reaping is still not observed; the three new control
verdicts are UNEXECUTED; `action.timeout` enforced nowhere (R9-04); the pending store has no
cap; the mutation campaign is unprivileged-only and the six root-gated tests have never been
mutation-tested; the suspend divergence is unmeasured; **the production logind gate is blocked
on a seated lane**; R22-01 reopened; R21-01's semantic-forgery half, R21-04 and R21-06 await the
native-UI increment.

**No root run, no PAM run and no lane run since run 20.** This range is unprivileged-verified
only: clippy clean in both feature configurations and in `shell-host`, 201/26/227 unchanged, 77
campaign guards, and the four weakens recorded with the assertion each failed on.

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per §13.9

**(a) Pre-foreclosed:** **10** (a skip reports `ok`); **43**; **44**.

**(b) Applicable and NOT foreclosed:**

- **53** (a rule resolving an ambiguity toward its author's preference) — **new this round, and
  its own first instance is in this range.** Audit whether the replacement genuinely reads
  evidence or merely relocates the preference into which data it collects.
- **45** (the totality claim) — this range asserts "both copies replaced", "the verdict is
  computed from final state", "the sender demonstrably survives the unwind". **Audit all three.**
- **48** (fix scoped to the named instance) — you cited one table; there were two. What else in
  this range was fixed only where you pointed?
- **49** (silence ≠ coverage) — the three verdict branches have never executed.
- **51** (a false claim in a trusted document) — third correction to the same register row.
- **41** (wrong altitude) — `processes_named` is now a THIRD hand-rolled `/proc` parser
  (`live_group_members`, `comm_of`, and this), and R32-01 was a defect in exactly that family.

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Each finding: **ID** (`D0A-R34-nn`), **severity**, **root
cause**, **impact**, **fix sketch**.

**Most valuable returns:** (1) **whether the register row is right on its third correction, or
should not exist until reaping is observed**; (2) **another decision procedure in this tree that
picks between two causes the way the control's rule did** — `run_suite`'s classifier is the
candidate I have not audited; (3) a defect in `processes_named`, which is new, hand-rolled, and
has never run; (4) a ruling on whether an unauditable check should stay in the lane record.
