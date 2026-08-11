# Codex adversarial review — D0-A round 8

<!-- Invocation: codex review - < scratch/codex-d0a-round8-prompt.md
     All three range-selection flags reject a PROMPT positional; scope is carried here. -->

## Scope — pinned endpoint, stat regenerated at write time

Round 7 was **REVISE — 3×P1, 5×P2**. All eight are fixed, plus R7-09 found by running them.

**Target: `0b846e4..921a13c`.** `git diff --shortstat`, regenerated as this was written:
**6 files changed, 157 insertions(+), 20 deletions(-)**. Report a mismatch as a finding.

---

## LEAD 1 — a new shape: a sound check whose report carries none of what it verified

R6-01 gave leg 1 a structured gate witness. The assertion is correct — absence panics on its own
named branch, and `Resolved { active: false, remote: false, seated: true }` is checked field by
field, so a `SessionSnapshot::DENIED` substitution fails on `seated: false`.

**The passing run printed `ok` and nothing else.** The test pipes the daemon's stdout into its
own sink, so the witness surfaces only inside a *failure* message. The evidence existed and was
invisible.

**Every prior entry in this corpus is a check that was WRONG. This is a check that was RIGHT and
unreadable** — and `ok` from a sound check is indistinguishable from `ok` from a skip, a vacuous
assertion, or a check that never ran. This project has shipped all three (Class 10's
skip-scored-as-pass; R6-01's cause-blind gate assertion; R5-05's pre-gate false pass). Recorded
as **Class 38**, with the discipline: print the *observed value*, not the assertion text.

*The asymmetry that makes it worth an entry: a wrong check fails loudly the first time its
subject changes; a silent-but-correct one never fails at all.* **Is that asymmetry real, or am I
over-promoting an ergonomics fix into a defect class?**

---

## LEAD 2 — the question I am worst placed to answer

**Round 7's findings drifted toward reporting and ergonomics rather than security properties.**
R7-04 (a panicking `println!`), R7-05 (a load-dependent false absence), R7-06 (an undrained
stderr), R7-08 (a claim defect, not a code defect), R7-09 (a silent report). The P1s were real —
a root harness signalling a recycled pid, an unbounded cleanup — but the centre of mass moved.

**Two readings, and I cannot judge between them:**

1. the security surface is converging and what remains is polish; or
2. the review is running out of places to look, and the remaining defects are somewhere the last
   several rounds have not been aiming.

**I have an obvious pull toward (1)** — it is the flattering reading and it ends the arc — so
please answer this directly rather than leaving it implied by the findings list. **If the honest
answer is (2), where should round 9 aim?** Candidates I would not have chosen myself: the
`consent_relay` path, the `execute`/sandbox boundary, `fdsec`, or the parts of `service.rs` that
no D0-A round has touched.

---

## LEAD 3 — the predictors were used AHEAD of a round for the first time, and held

Round 7's prompt stated two predictors with hit rates and asked you to use them. You reported
findings clustered in remediation and verification code, as predicted. **That is a different
claim from "we noticed a pattern seven times" — it is the pattern used as an instrument and
confirmed.** Class 37 now has **seven** in-round instances; R7-01 was a hole in my own R6-02 fix.

**So the question that follows: should this change what gets BUILT, not just where review
looks?** If remediation diffs are reliably the highest-yield place for the next defect, that
argues for a different discipline at *fix time* — something stronger than "be careful", applied
when writing a fix rather than when reviewing one. R7-01's fix suggests one candidate shape:
**do the irreversible thing last**, so a failure before it leaves nothing to misattribute
(publish the reap marker, verify it, *then* kill — rather than kill, then check). Is that
generalisable, or specific to that defect?

---

## What was fixed

**R7-01** — the reap marker was set with an unchecked `setenv` *after* the kill, so a failure
left the victim dead and the driver still believing it owned that pid, as root. Fixed by
ordering, not by checking: publish first, verify, bail before killing. **R7-02** — a `waitid`
error means the identity is UNKNOWN, not "exited"; the teardown no longer signals a group it
cannot prove it holds. **R7-03** — the deadline ended at the poll and the cleanup after it was
unbounded; the reader is now drained with a bound and detached, the reap goes through
`reap_within`. **R7-04/05/06** — a non-fatal witness write, a recompute after draining, a drained
stderr. **R7-07** — `reap_within` became `pub` in R6-03, which made `0` ("any child in my group")
and `-1` ("ANY child") reachable; RED: `reap_within(0) = false`, `(-1) = false`, `(1) = true`.
**R7-08** — corrected as a *claim* defect: "no AI exchange, no terminal EOF" was false, since
`launch()` forks the AI and the daemon keeps running after the witness. The true and sufficient
statement is that leg 1 no longer *depends* on either.

---

## Verification boundary — and a status change worth noting

**Both legs of R4-03 now pass at root ON THE CURRENT CODE** (2 passed, 2.45 s; before and after:
0 daemons, 2 sessions, 0 accounts, `/run/delphi` empty). That run converted **three rounds of
compile-verified changes into executed ones in a single shot** — leg 1's witness path had been
rewritten by R6-01 and again by R7-02/03/05/06 without ever running.

**The ledger qualification is therefore retired: the discharge rests on BOTH legs, not leg 2
alone.** It has carried that caveat for several rounds and no longer needs to.

lib 85/85; `EXECUTED 123 / SKIPPED 22`; barrier 5/5 unprivileged; clippy rc=0 in both feature
configurations. No lane-gated or root-gated obligations outstanding — a claim that has been
wrong three times on this branch, so **check it rather than accept it**.

---

## Defect classes

**Pre-foreclosed:** 1, 10, 22, 25, 34, 35, 36, 37, 38.

**Spend the budget here:** **37** applied to this diff, which is again almost entirely
fixes-to-fixes. **17** — five instances this arc. And per LEAD 2, **anything outside the paths
D0-A has been circling**, if you judge the answer to be (2).

---

## Verdict

**APPROVE / REVISE / FAIL**; per finding: ID (`D0A-R8-NN`), severity, root cause, impact, fix
sketch.

**The two judgements I need more than findings: is Class 38 a real class or an over-promoted
ergonomics fix, and is the drift toward reporting defects convergence or misdirection?** I am
poorly placed to answer either, and the second determines whether this arc is close to done.
