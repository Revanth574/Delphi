# Codex adversarial review — D0-A round 24 (the merge gate)

This prompt is `scratch/codex-d0a-round24-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff cd67081..cfb8ba3`** — three commits. Pinned, not `..HEAD` (D0A-R18-09).

```
 10 files changed, 124 insertions(+), 350 deletions(-)
```

**Note the shape: 350 deletions against 124 insertions.** This range REMOVES more than it
adds, which is unusual here and is the point — it is a revert plus two corrections.

## Lead: judge the REVERT, not its mechanics

Round 23 returned 8×P1 against `scripts/lane-run.sh`, the runner built one round earlier to
close D0A-R22-01. **I recommended removing it and the operator agreed.** Neither of us is
positioned to judge that call — it is the same conflict-of-interest shape that made round 20's
question productive, so it is handed over rather than defended.

**The question: was reverting right, or should the runner have been fixed?**

The case for reverting, as I argued it:

- **D0A-R23-05 decided it.** The runner dropped five checks the manual procedure performs —
  helper-digest, free-space, forced-freshness, stale-session, PAM before/after. That is a
  **regression in safety coverage sold as an upgrade**, on the path producing every piece of
  root evidence this branch has, and class-16 PAM damage is a defect already paid for once.
- The benefit was real but small and **already banked**: run 12's artifact binds expectation
  commit `c16c3e9` to tree `0330b46` and survives the revert.
- A convention a human follows **with** those checks beats a mechanism with eight open P1s
  **without** them.

**Attack that.** Specifically:

- Were the five dropped checks actually load-bearing, or is that argument doing more work than
  the evidence supports? Read `scratch/lane-run-7-procedure.md` §0/§5/§6 and judge.
- Eight P1s against ~200 lines is a high density. Does that indicate the design was wrong, or
  that a new script simply got a first thorough review and the findings were ordinary?
- **Is "revert" a disguised way of avoiding remediation?** The branch has been in
  remediation for eight rounds. A revert that removes the subject also removes the findings.
- Is the register's account honest, or does it flatter the decision? (`CONFORMANCE_REGISTER.md`,
  "THE LANE RUNNER — BUILT TO CLOSE D0A-R22-01, REVERTED AT D0A-R23".)

## The terminus claim, which is the other thing I cannot judge

The register records a sequence as the round's more important output: round 21's remediation
produced round 22's findings; round 22's produced the runner; the runner produced round 23's
eight P1s — **with the product surface unmoved throughout, every finding in that stretch being
verification infrastructure reviewing verification infrastructure.**

That is offered as the terminus shape the B2a composition sweep closed on. **Is it?** Or is it
a narrative that makes stopping feel principled? A reviewer with no stake in the answer is the
only one who can say.

## The two surviving fixes

| finding | fix | attack |
|---|---|---|
| R23-12 | `reached_the_anchor` narrowed to `"root-owned runtime directory"`, dropping the generic `"permission denied"` | the RESIDUAL is recorded, not closed: it is still a later-stage oracle. Is narrowing enough, or does this need the structured guard-passed witness the finding proposed? |
| R23-13 | the module flow transcribed from `serve_one_action` | check it against the function line by line — the previous two attempts both described intent |

**On R23-12 there is a methodological point worth pressing.** It falsified my sweep for
boundary-naming controls. That is the **third** wrong-altitude grep sweep in this arc, and all
three returned confident **negatives** — a false positive gets checked, a false negative closes
the question. Is there a further instance my narrowed predicate still misses?

## What remains open, by state

- **DEPENDENT on the native-UI increment** (decided, not implemented): R21-01's
  semantic-forgery half, R21-04, R21-06.
- **SCOPED ELSEWHERE by explicit decision**: §7's audit unwired, the tool's bounding set full,
  the socket refusal fixture-measured, R9-03/04/05/07/12.
- **INHERITED BY A FUTURE INCREMENT**: R23-01..R23-10, which together specify a lane runner
  worth having.

Round 22 falsified this partition once (R22-06 was neither). A third category found now is a
finding, and it will be the second time.

## Lane evidence

Run 12 remains the current root evidence: `EXECUTED 176 / SKIPPED 5 / reported 181`,
`status=RAN_MATCH`, tree `0330b46`. **The tree has moved since** (three commits, none touching
a Rust test — `git diff --stat 0330b46..cfb8ba3 -- runtime/` is documentation and one test
oracle). Judge whether that invalidates the evidence or whether the derivation covers it; this
is the same staleness question D0A-R18-07 raised about run 7.

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per §13.9

**(a) Pre-foreclosed:** 10 (a skip reports `ok`), 43 (child's own stderr), 44 (restore
precondition).

**(b) Applicable and NOT foreclosed:**

- **48** (the fix scoped to the named instance) — **four instances in this arc**, the largest
  being the runner replacing a procedure without enumerating its checks. Is the class stated
  well enough to have prevented that, or is it description after the fact?
- **45** (the totality claim) — this range asserts "the benefit is banked", "none touched a
  Rust test", "every finding in that stretch was infrastructure". Audit all three.
- **41** (wrong altitude) — three grep sweeps, all confident negatives.

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Each finding: **ID** (`D0A-R24-nn`), **severity**, **root
cause**, **impact**, **fix sketch**.

**A finding that the revert was wrong is the most valuable return** — it would mean I removed
working infrastructure to avoid remediating it, and both the operator and I would have
endorsed that.
