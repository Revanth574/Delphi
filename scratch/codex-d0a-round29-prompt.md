# Codex adversarial review — D0-A round 29 (the merge gate)

This prompt is `scratch/codex-d0a-round29-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff 4607fc9..2c7dee0`** — seven commits. Pinned to a SHA, not `..HEAD` (D0A-R18-09).

```
 13 files changed, 1033 insertions(+), 232 deletions(-)
```

The round-28 remediation (2×P1, 4×P2), the mutation harness, and lane run 17.

---

## Lead: **R28-02's fix has never executed at root, and no test can reach its protection**

You found it: the daemon's exit path did an unconditional blocking `waitpid` on **both**
children, one of them the untrusted AI. An AI that takes its terminal response and simply does
not exit holds the ROOT daemon forever — so "B1 services one action and exits" was a property
that depended on the AI's cooperation, the one thing this boundary refuses to depend on
anywhere else.

The fix: `reap_within` + a 5 s grace + `SIGKILL` + bounded reap, with the reaper kept **armed**
across the wait instead of disarmed before it.

**And it is the least-exercised change in the round.** Three layers, and the third is the one I
want your judgement on:

1. **Its only root test SKIPS on this lane.** The code lives in `delphi-runtimed`, exercised at
   root solely by `b1_daemon_binary_runs_the_assembled_flow`, which requires
   `--features insecure-test-seams` — the lane procedure builds without it, so the test returns
   early and is scored a pass (`DEFECT_CLASSES` 10, foreclosed by the extractor, but it is
   still not *run*).
2. **Even unskipped, it would not reach the protection.** `delphi-minimal-ai` receives its
   terminal response and returns from `main` — it cooperates. So `reap_within` succeeds inside
   the grace period and the **`SIGKILL` branch is never taken**. The scenario the fix exists
   for — you named it: *"an AI that completes the protocol and deliberately stays alive"* —
   is not exercised by anything that exists.
3. **The feature-gated binary is not the production binary.** Running with
   `insecure-test-seams` compiled in tests a build whose logind gate can be bypassed. So
   "just run it with the feature" trades one honesty problem for another.

This was **predicted in the run-17 expectation before the run**, which is what makes it a
stated limitation rather than a discovery — but it is still a gap.

**So: what closes it?** My instinct is to extract the exit sequence out of `main` into a
testable function in the library, and drive it with a deliberately-surviving child — which
tests the logic without needing the daemon binary, the feature seam, or root. **But that tests
an extraction, not the daemon**, and I have been wrong this exact way before (R28-06: I proved
a check untested and then overstated what its absence allowed). Tell me whether that is the
right shape, a weaker substitute for a real root exercise, or whether the honest answer is that
this needs the seated lane.

---

## The mutation campaign, handed over as ARTIFACTS rather than a table

Round 28's central finding (R28-05) was not a wrong statement — it was that **the evidence
could not substantiate the table I handed you.** The retained harness reported PATCH-MISS for
the row it claimed a result for; the successful run had happened in an unretained shell
heredoc; "no test at any privilege level" was asserted from unprivileged runs only.

`scripts/mutation-campaign.py` is the fix, and the fix is **not "retain more"** — it is that a
campaign's output is the artifact set, not the table. Per experiment it records: the **applied**
diff (from `git diff` — the actual mutation, not the intended one), the compile result, the
commit and euid, the failing assertion text, and verification that the tree was restored.

**Re-run at `3593fa8`: 14/14 valid, 0 invalid, 12 CAUGHT, 2 NOT CAUGHT** (`pending_id`,
`timeout` — both since closed by binding tests). `euid=1000` recorded, with the explicit note
that other privilege levels are unsupported. Artifacts at `/tmp/mutation-r28/results.json`;
the harness reproduces them from a clean tree.

**The detail worth your attention: the harness REFUSED ITS OWN FIRST RUN**, because
`runtime/src` was dirty with the round-28 fixes. A campaign that starts from uncommitted
changes cannot attribute a result to its mutation. **Which means the previous campaign's
attribution was unverified in exactly that way — not merely unrecorded.** I had run it against
a tree I believed was clean and never checked.

**Attack the harness itself.** Its `INVALID` vs `NOT CAUGHT` distinction is the part I think
generalizes — a patch miss and a surviving mutant produce the same table cell and mean opposite
things, and only the artifact separates them. Is that distinction drawn correctly here? Is
there a third outcome it collapses? And does recording the *applied* diff actually close the
gap, or can a mutation still be misattributed some way this does not catch?

---

## The tier claim, narrowed twice — a method question, not a content one

- **Round 26** claimed: *no test in the crate had ever asserted that any tier meant anything.*
- **R27-05** corrected it: two tier-semantic tests existed at the base; the migration flipped a
  live assertion. Replaced with a three-phase account.
- **R28** corrected it *again*: still too broad. Pre-round-25 tests already asserted **digest
  and preview** consequences (`required_tier binds`, `tier rendered`). The claim is now narrowed
  on two axes — **authorization-boundary** assertions specifically, and *"not detected by the
  tests that existed"* rather than *"impossible to discover."*

**Each correction fixed the sentence in front of it and left the same overstatement one level
up.** The first narrowed *when* the assertions appeared without checking *what kind* they were.

**Is the third version finally narrow enough?** And the reason this is asked rather than
asserted: **the same two people who produced both overstatements are the ones judging the third
one.** That is the condition that produced the error twice; a third pass by the same parties is
not independent evidence that it is fixed.

---

## The round-28 fixes — attack their sufficiency

| finding | fix | attack |
|---|---|---|
| **R28-01** | `read_frame` undeadlined; daemon opts in via `read_frame_untrusted` | the bound now lives at the call site that knows its peer is untrusted. **Are all such call sites covered?** `arm_frame_liveness` is called at one accept path (`accept_requester`, which `accept_requester_within` delegates to). Is there any other stream `read_frame_untrusted` is or should be called on? |
| **R28-03** | deadline checked at acceptance, not only before each read | does the check now bound *blocking waits* by remaining time, or only reject afterwards? A read that blocks past the deadline still blocks |
| **R28-04** | the false "before the approval is consumed" claim corrected | you proposed an alternative: move representability validation *before* consumption. I corrected the message instead, preserving consume-on-attempt. **Was that the weaker choice?** |
| **R28-06** | three program-fd seal tests | the mutation is now CAUGHT and the RED is stronger than the finding — without the check both fds **reach exec**. But I originally claimed such an action "passes today" and it does not. **Is the new test asserting the right thing, or does it encode my misunderstanding?** |
| env/pending_id/timeout | digest-binding tests | `timeout`'s test name says it closes the BINDING half only; `action.timeout` is still enforced nowhere (R9-04). Is a binding test on an unenforced field worth having, or does it create the appearance of coverage? |

## Lane run 17

`EXECUTED 208 / SKIPPED 5 / reported 213`, rc 0, 17/17 producers exited 0. Predicted
`208/5/213` at `c3cca14`, committed alone before the run, matched exactly.

**The membership check did real work for the first time.** Run 16 introduced it on a tree where
nothing had changed between the lanes — it could not have been wrong there. Eight tests landed
between the runs, giving run 17 a genuine delta: `root 213 / unpriv 213`, zero in either
direction, `rc 0`.

Ordering held under convention for the fifth consecutive run. You said last round that four
such runs are evidence about those four runs, not enforcement of the next. **Five is the same
statement with a bigger number — is there any point at which convention accumulates into
something, or is the honest answer that it never does and R22-01 stays open until a mechanism
exists?**

## An operational item, flagged before it becomes a misattributed failure

**The lane consumes ~0.5 GiB of `$CARGO_TARGET_DIR` per run.** Run 16 read 3903M; run 17 read
3397M; the floor is 2048M. **That is three or four runs of margin.**

It is raised because of *how* it fails: a full filesystem surfaces as a **compiler error in an
unrelated crate**, which is the exact misattribution `scripts/check-free-space.sh` exists to
prevent — and run 15 reached **249M** of headroom before anyone looked. The check catches it at
the top of a run; what it cannot do is stop a mid-run exhaustion presenting as a build defect.
**Is a per-run reclaim step the right answer, or a higher floor, or something else?**

## What remains open

- **`action.timeout` is enforced nowhere** at execution (R9-04). Round 28 closed its digest
  binding only.
- **The pending store has no cap**, and the **abandoned read worker** is unbounded for repeated
  service — 30 s is an engineering choice, not a demonstrated bound.
- **The mutation campaign is unprivileged only.** The five root-gated tests have never been
  mutation-tested at all, and one of them is the only exercise of R28-02's code. The harness
  docstring records what a root campaign would require.
- **The suspend divergence is unmeasured**; the clock test prints its own delta and states it
  cannot distinguish the clocks on this lane.
- Dependent on the native-UI increment: R21-01's semantic-forgery half, R21-04, R21-06.
  Reopened: R22-01. Inherited: R23-01..R23-10.

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per §13.9

**(a) Pre-foreclosed:** **10** (a skip reports `ok` — but see the Lead: foreclosed in the
*count* and still not *run*); **43**; **44**.

**(b) Applicable and NOT foreclosed:**

- **49** (silence ≠ coverage) — `wire.rs` returned a P1 on its first naming and R28-01/03 were
  both in it. What is the next zero?
- **50** (the filter is not the mechanism) — applied raw again this round; a stale `180/25` in
  PROGRESS was caught by reviewing all 21 hits unfiltered.
- **48** (fix scoped to the named instance) — **five** consecutive catches.
- **45** (the totality claim) — this range asserts "14/14 valid", "membership identical",
  "all such call sites covered". **Audit all three**; the first is now backed by artifacts you
  can inspect rather than by my summary.
- **41** (wrong altitude) — the decoration grep was wrong on four of twelve; the timing grep
  matched a function *name*.
- **15** (Iron Law #15 clause 2) — every new test weaken-proven. **Verify the weakens
  discriminate rather than merely fail.**

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Each finding: **ID** (`D0A-R29-nn`), **severity**, **root
cause**, **impact**, **fix sketch**.

**Most valuable returns:** (1) what actually closes R28-02's coverage gap, given that all three
obvious routes are compromised; (2) a defect in the mutation harness — it is new, load-bearing
for every claim I make about coverage, and reviewed by nobody; (3) whether the thrice-stated
tier claim is finally right, from someone who did not produce the first two versions; (4) a
defect in a never-named file.
