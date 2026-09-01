# Codex adversarial review — D0-A round 22 (the merge gate)

This prompt is `scratch/codex-d0a-round22-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff e4356ad..fe1d2b7`** — seven commits, the round-21 remediation. Pinned, not
`..HEAD`: committing this prompt would otherwise move the reference and invalidate the stat
below (D0A-R18-09 was exactly that).

```
 11 files changed, 384 insertions(+), 35 deletions(-)
```

The base is round 21's own prompt commit. **A narrower base was nearly used and would have
silently dropped two of the seven** — the ordering fix (`d6fb698`) and class 47 (`4e95b09`).
Report any disagreement with the stat as a finding.

## Lead: attack the expectation protocol, because its one proving case has not happened

`.githooks/runtime-test-count-baseline.expected` is new infrastructure introduced by
D0A-R21-07, after **two consecutive lane runs had a correct figure and a wrong explanation**
(R19-06, R20-07 — the second occurring while claiming the first had made attribution
"checkable"). Its entire value rests on **commit ordering**: the expectation is committed
alone, before the run; the measurement is committed alone, after. `git log` on the two files
is the audit.

It has now been exercised twice — once where drift invalidated a prediction before it could be
measured (174/5 at `d6fb698`, re-derived rather than amended), and once where the prediction
**matched** (176/5 at `e400bae`, measured at `fe1d2b7`).

**Neither exercise proves the thing that matters.** A match is precisely the case where the
temptation to reconcile does not arise. **Nothing has tested that a MISMATCH would be recorded
as a result rather than quietly reconciled away** — and the protocol's own text is the only
thing currently standing between "a mismatch is a result" and "the derivation gets adjusted
until it agrees".

Attack that directly:

- Is there any mechanism — as opposed to prose — that would make a reconciled mismatch
  detectable to a later reader? If not, is the protocol worth what it claims?
- Could the expectation be committed after the run and still look correct in `git log`?
  What would betray it?
- The derivation is prose in a comment. Is a derivation nobody re-runs meaningfully different
  from the attributions R19-06 and R20-07 got wrong?
- Should a mismatch be enforced (a gate that refuses) rather than described?

## Also attack: class 47, which was written from one instance

`DEFECT_CLASSES` 47 says *a documented flake is a hypothesis with a name attached*. It was
written from a single near-miss: `terminal_contract_release_produces_eof_no_wedge` is
documented at ~7–10% under parallel execution, failed the gate, and was a **real regression**
from the change in that same commit — discriminated by the assertion message naming the
change, then 5/5 serially.

**One instance is how a class gets written too confidently.** Is the discipline right —
read the message, confirm serially, suspect the exemption most when the change is recent — or
does it over-fit that instance? Would it have caught a genuine flake failing for a genuine
timing reason, or does it just re-litigate every flake?

## The rest, with the rationale to attack

| finding | fix | attack |
|---|---|---|
| R21-01 (half) | gate runs before the preview is sent; a denied action discloses nothing | the adapted test dropped a `Rd::Data` assertion. Adaptation or weakening? The property was weaken-proven to still bite, but check the reasoning |
| R21-02 | §4 ratifies id-only | claimed to be a *different kind* of amendment — ratifying code that never changed, versus the four before it that changed a claim to match an argument. Is that distinction real or self-serving? |
| R21-03 | `preview_version` rendered from the bound field; canonicalize emits 3 | does version 3 correctly identify the complete-value format, and is anything still comparing previews across versions? |
| R21-05 | preview-size invariant before store and reply | is `32 + preview.len() <= 8192` the right bound, and are there other paths where a legal proposal becomes an unpresentable action? |

## What remains open on this branch, and in what state

**Distinguish these two — a decision made but not implemented is not the same as one not yet
made:**

- **DEPENDENT on the native-UI increment** (decided 2026-08-29, not implemented): R21-01's
  semantic-forgery half — a compromised renderer can display a benign preview, collect the
  genuine password, and obtain a token for an unseen action, because the relay mints from its
  own held digest. Also R21-04 and R21-06.
- **SCOPED ELSEWHERE by explicit decision**: §7's audit subsystem unwired end to end, the
  tool's bounding set still full, the socket refusal fixture-measured, R9-03/04/05/07/12.

**Every remaining open on this branch is now one of those two.** If you find something that
is neither, that is a finding.

## Lane evidence

Run 11 at the round-21 remediation: `EXECUTED 176 / SKIPPED 5 / reported 181`, rc 0, 0
failures, 0 leaks, PAM intact, all 17 producers exited 0. Verify the +3 accounting and the
"overlapping sets, neither a superset" claim for 176 vs the unprivileged 156.

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per §13.9

**(a) Pre-foreclosed:**

- **10** (a skip reports `ok`) — extractor, exact baseline, `require_guard_executed`.
- **43** (one error string, two processes) — the demonstration prints the child's stderr.
- **44** (restore without precondition) — `trap` + `cmp`.

**(b) Applicable and NOT foreclosed:**

- **47** (a documented flake is a hypothesis) — **newly written from one instance**; see above.
- **45** (the totality claim) — the range asserts "every remaining open is one of two kinds"
  and "each verified not root-gated". Audit both as claims.
- **22 / 37** (the fix inherits the class it closes) — the R21-02 ratification argues it is a
  different kind of amendment; check whether it repeats the shape it distinguishes itself from.
- **41** (wrong altitude) — three times in analyses this arc.

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Each finding: **ID** (`D0A-R22-nn`), **severity**,
**root cause**, **impact**, **fix sketch**.

**A finding that the expectation protocol does not do what it claims is the most valuable
return** — it is the newest thing here, it exists to fix a failure that recurred twice, and
its only real test is the case that has not occurred.
