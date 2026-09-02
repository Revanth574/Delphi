# Codex adversarial review — D0-A round 23 (the merge gate)

This prompt is `scratch/codex-d0a-round23-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff fe1d2b7..a96c0e8`** — eight commits, the round-22 remediation plus the lane
runner it produced. Pinned, not `..HEAD`, because committing this prompt would move the
reference and invalidate the stat (D0A-R18-09).

```
 12 files changed, 671 insertions(+), 95 deletions(-)
```

Report any disagreement as a finding.

## Lead: the newest infrastructure gates everything, and every defect it had was found by USE

`scripts/lane-run.sh` (`74bf127`) is the least-reviewed thing on this branch and it now
**gates every lane run** — no root evidence can be produced without passing it. It shipped
with five RED-proven gates and a positive control.

**It then failed its first real use with three defects, and none was findable by a test of
its gates:**

| defect | why no first-run test could find it |
|---|---|
| no `sudo` priming | produced 17 instant producer failures; the gates all passed |
| the runner **self-blocked** — artifact written inside the tree dirtied it, so run TWO failed the cleanliness gate | requires a **second invocation**; one run is structurally blind to it |
| `match=NO` conflated *ran-and-disagreed* with *never-ran* | only matters once there is a failure to distinguish |

The RED-proofs exercised **the gates**, not **the runner being used**. A runner that passed
its own suite would have shipped all three.

**So the question for this round: what else here is only findable by use?** Not "is the code
correct" but "which properties does its test suite structurally cover, and which does it
merely appear to". Candidates worth pressing: the artifact path when `XDG_STATE_HOME` is set
oddly or unwritable; two runs in the same second (the artifact filename is
`lane-<UTC-to-seconds>-<tree7>.txt`); a target that hangs rather than fails; `sudo`
credentials expiring mid-run between targets.

## And specifically: does the positive control have siblings?

The lane-runner suite's positive control asserted the run reached **`build failed`** — true
until GATE 6 (sudo) landed **in front of** the build, at which point the control silently
stopped proving anything. It named a **boundary**, not a **property**, so a new gate ahead of
it invalidated it without any test going red.

I swept for the same shape — assertions keyed to a later stage's failure string rather than to
the property under test — across `scripts/`, `runtime/`, `.githooks/` and `installer/`, and
found **no other test-level instance**; the hits were prose and comments. **Treat that as a
bounded claim, not a clean bill:** the predicate was `grep`, and grep-based sweeps in this arc
have been wrong-altitude twice (the dead-code pass, the unreachable-block pass), both times
returning confident false results. **Check the method as well as the conclusion.**

## The rest of the range

| item | what to attack |
|---|---|
| `af46083` — seven round-22 findings | three were defects I had just fixed elsewhere; class 48 was written from them. Is the class right, or does it over-fit? |
| `7930052` — class 48 | written from three instances in one round. Does its discipline ("name the class without referring to the instance") actually discriminate? |
| `f198035` — gate refusals name themselves | the banner meant to make refusals legible contained a `printf` option bug that printed an error into the refusal. Are there other literals starting with `-` in these scripts? |
| `c16c3e9` / `a96c0e8` — the run-12 expectation and result | the expectation commit is **three commits behind** the tree it was measured against. Is that legitimate, or does a prediction need to name the tree it will be tested on? |
| the artifact's `status=` field | `DID_NOT_RUN` / `RAN_INCOMPLETE` / `RAN_MISMATCH` / `RAN_MATCH`. Is that partition complete and are the boundaries right? |

## What remains open, by state

- **DEPENDENT on the native-UI increment** (decided, not implemented): R21-01's
  semantic-forgery half — a compromised renderer displays a benign preview, collects the
  genuine password, and obtains a token for an unseen action, because the relay mints from its
  own held digest. Also R21-04, R21-06.
- **SCOPED ELSEWHERE by explicit decision**: §7's audit subsystem unwired, the tool's
  bounding set full, the socket refusal fixture-measured, R9-03/04/05/07/12.

Round 22 falsified this same partition once (R22-06 was neither), so **if you find something
that is neither, that is a finding** — and it will be the second time.

## Lane evidence

Run 12, the runner's first successful use: `status=RAN_MATCH`, expected 176/5, observed
176/5, `producer_failures=0`, `extractor_rc=0`, tree `0330b46`, expectation commit `c16c3e9`.
Artifact outside the repository. Verify the ordering claim is actually established by the
artifact rather than by the commit messages around it.

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per §13.9

**(a) Pre-foreclosed:**

- **10** (a skip reports `ok`) — extractor, exact baseline, `require_guard_executed`.
- **43** (one error string, two processes) — the demonstration prints the child's stderr.
- **44** (restore without precondition) — `trap` + `cmp`.

**(b) Applicable and NOT foreclosed:**

- **48** (the fix scoped to the named instance) — **newly written from three instances in one
  round**; the range is its first test.
- **47** (a documented flake is a hypothesis) — corrected in this range after over-generalising
  from one instance. Is the correction itself over-corrected?
- **45** (the totality claim) — the range asserts "no other instance of the boundary-naming
  shape" and "none touched a Rust test". Audit both.
- **41** (wrong altitude) — three times in analyses this arc, twice in grep sweeps.

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Each finding: **ID** (`D0A-R23-nn`), **severity**,
**root cause**, **impact**, **fix sketch**.

**The most valuable return is a property of the runner that only use would reveal** — because
that is the category its own test suite is structurally unable to cover, and it now gates
every piece of root evidence this branch can produce.
