# Codex adversarial review — D0-A round 21 (the merge gate)

This prompt is `scratch/codex-d0a-round21-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Lead: a normative amendment, and whether its cut is the right one

Round 20 (D0A-R20-01) found that restoring the preview's redaction — a reversal the operator
and I had both endorsed — was **not** conformance: with redaction, `DEPLOY=production` and
`DEPLOY=staging` produce an **identical preview** while their digests differ. §3's "two
different actions cannot share a preview" was false. One contract violation had been fixed
into another.

The resolution amends §3 on a distinction that had never been written down:

> **The renderer is untrusted as an ACTOR and trusted as an AUDIENCE.** It cannot manufacture
> a consent (R-2's native relay, `renderer-cannot-forge`, unchanged). It *does* see the
> approval content — it already receives the user's PAM password, typed into that realm and
> returned over `window.ipc`, and the full `argv`.

`preview()` therefore renders the complete action and carries no allowlist.

**Question 1 — is that the right cut?** Attack it directly:

- Is "cannot forge / does see" a real and stable separation in this architecture, or does
  something else in the design depend on the renderer *not* seeing content?
- The password argument is load-bearing. Verify it: `shell-host`'s `drive_consent` and
  `RendererMsg::Password`. If the password does **not** in fact transit the page realm, the
  amendment's central premise fails.
- Is the third position better-founded than the first two, or merely more recently argued?
  **Three positions in three rounds is a pattern, and the operator and I have now been wrong
  about this question in two different directions.**

## Question 2 — where superseded reasoning belongs, decided twice by default

The amendment first recorded all three positions **inside §3**, at the operator's request.
That contradicts **D0A-R15-02**, ratified in the same document five rounds earlier: superseded
narrative lives in `docs/CONFORMANCE_REGISTER.md`, §3 keeps a pointer, because a normative
document's one job is to let a reader tell what is required.

I complied with the request without flagging the contradiction. It has been relocated
(`52053a0`), so the tree is now consistent — **but the general question has been settled twice
by default and never once by decision**:

- Is the register the right home for superseded reasoning, with §3 carrying only live
  requirements plus pointers?
- Or does a normative document benefit from carrying its own reversal history inline, at the
  cost of a reader distinguishing live text from preserved-wrong text?
- **§3 has been amended four times in this arc.** Whichever answer, is the current shape
  actually readable by someone who has not followed the rounds?

A finding here is valuable because the failure mode is not hypothetical: this document is the
one everything else cites.

## Your target

**`git diff 90d597c..52053a0`** — four commits, pinned (D0A-R18-09 was the error of naming a
moving reference). Expect:

```
 8 files changed, 265 insertions(+), 123 deletions(-)
```

Report disagreement as a finding. **The 123 deletions matter**: two preview tests were
removed *again*, this time under a ratified amendment rather than against a live guard.
Confirm that distinction holds and is not a weakening dressed as a ratification.

## What else changed, with the rationale to attack

| finding | fix | attack |
|---|---|---|
| R20-02 | non-UTF-8 `cwd`/binds refused at the execute choke point | refusal was the cheapest of three options. Is refusing right, or does it hide that `sandbox.rs` still lossily converts paths that *are* valid UTF-8 in other ways? |
| R20-03 | a directly-built action with malformed env, refused before transport | does the test reach the guard for the reason claimed, or could it pass via an earlier check? |
| R20-05 | witness records `/proc/self/exe`; path asserted present before asserted-not-impostor | measured `py3\|/bin/python3.14`. Is presence-then-content the right order, and is `/proc/self/exe` trustworthy inside the jail? |
| R20-06 | §3 and the test corrected: the argument STRING is bound, any PROGRAM it names is not | is that now true for every argument shape? |
| R20-04 | §4's wire divergence opened as a register row | should it be ratified rather than left open? |
| R20-07 | the run 8→9 attribution corrected — **second consecutive attribution error** | run 10's figure was **predicted before the run** (173, all three new tests executing). Verify it |

## Lane evidence

Run 10 at the round-20 remediation: `EXECUTED 173 / SKIPPED 5 / reported 178`, rc 0, 0
failures, 0 leaks, PAM intact, all 17 producers exited 0. Verify the +2, and the
"overlapping sets, neither a superset" claim for 173 vs the unprivileged 153.

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per §13.9

**(a) Pre-foreclosed:**

- **10** (a skip reports `ok`) — extractor, exact baseline, `require_guard_executed`.
- **43** (one error string, two processes) — the demonstration prints the child's stderr.
- **44** (restore without precondition) — `trap` + `cmp`.

**(b) Applicable and NOT foreclosed:**

- **45** (the totality claim) — the amendment asserts what the renderer "already receives"
  and what a deployment "does not need". Audit both as claims.
- **22 / 37** (the fix inherits the class it closes) — R20-03 was R19-02's shape one round
  later, in the fix for R19-05. Check the round-20 fixes for the same recurrence.
- **25** (fixture unlike its subject) — the demonstration still sets `argv[0] = "env"`.
- **41** (wrong altitude) — twice in analyses this arc.

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Each finding: **ID** (`D0A-R21-nn`), **severity**,
**root cause**, **impact**, **fix sketch**.

**A finding that the actor/audience cut is wrong is the most valuable return** — it would
mean three consecutive positions on one question were all mistaken, and the operator and I
have endorsed each of them in turn.
