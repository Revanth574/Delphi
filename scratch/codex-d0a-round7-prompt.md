# Codex adversarial review — D0-A round 7

<!-- Invocation: codex review - < scratch/codex-d0a-round7-prompt.md
     All three range-selection flags reject a PROMPT positional; scope is carried here. -->

## Scope — pinned endpoint, stat regenerated at write time

Round 6 was **REVISE — 5×P1, 3×P2**. All eight are fixed, and your lead judgement was taken.

**Target: `a30ac42..6f2bf26`** — 4 commits. `git diff --shortstat`, regenerated as this was
written: **9 files changed, 293 insertions(+), 53 deletions(-)**. Report a mismatch as a finding.

---

## LEAD — two measured predictors. Please USE them rather than rediscover them.

These are not observations about the past. They have been tested every round since they were
written down, and they have not missed.

**1. The verification code is wrong more often than the code it verifies.** Round 5: 9 findings,
**7 in verification code**. Round 6: 8 findings, **6 in verification code**. The R4-03 test alone
took **five distinct harness fixes** to make one claim, none of them in the assembly under test.

**2. Class 37 — the highest-yield place to look for instance N+1 of any class is the diff that
fixed instance N.** It has now scored **six in-round instances across five rounds**:

| instance | appeared inside the fix for |
|---|---|
| R2-01c | R2-01b |
| barrier test sampling around the interval | a fix for sampling around the interval |
| R5-04 (pipe retention) | R5-01's guard, within a minute |
| R5-06 (untested mapping) | R4-05's classifier extraction |
| R5-02 (trusted parent) | R4-01's unpredictable name |
| **R6-06 (`.take()` before fallible work)** | **R6-01's fix — written while fixing the finding that reports it** |

**So the concrete instruction: read THIS diff's fixes as the likeliest home of the next
finding.** The fixes here are R6-01's witness plumbing, R6-05's `waitid(WNOWAIT)` reordering,
R6-03's shared `reap_within`, and R6-06/07/08's guard changes. Four of the six earlier instances
were in exactly that kind of code.

**A shape worth naming, because it has three instances in one week:** *release the handle, then
do something that can fail.* R5-01's fork guard reaped the victim then bailed without publishing;
R6-05's `try_wait` reaped then signalled the group; R6-06's `.take()` removed the child then did
fallible work. **Is there a fourth in this diff?**

---

## The lead judgement, taken

Leg 1 keeps its claim and drops the full-flow shape. It now waits for a **structured witness**
and tears the group down with bounded cleanup — no AI exchange, no terminal EOF, which removes
R5-11's coupling of a test binary to a production ordering guarantee.

**The witness is emitted from the value the decision consumes.** The daemon computes the
resolution, prints `DELPHI_GATE_WITNESS {resolution:?}`, and decides on that same value — so it
cannot exist unless the gate was evaluated, which is what makes absence structurally meaningful.
`println!` not `tracing`, because an `EnvFilter` can erase a log line and a witness a filter can
erase can go absent for reasons unrelated to the gate.

**Three failures, named separately**, since conflating them is what cause-blindness was:
absent-and-exited (a timing failure that says nothing about the gate); absent-and-alive (it ran
and never reached it); present-but-wrong (it resolved differently, with the actual quoted).

*Questions:* is the `Debug`-string parse the right coupling, given a unit test now pins the
format but the daemon and the test are still two crates agreeing by convention? And does the
witness leak anything a non-root reader should not see?

---

## What else was fixed

**R6-02** — my R5-01 fork guard made the driver kill a **recycled pid as root**: every early
return after the reap left the impostor variable unset, and the driver read unset as "the victim
is still ours". The reap is now published explicitly; ownership is never inferred from an
absence. **R6-05** — `try_wait()` reaps, so `kill_group` targeted a possibly-released group id;
now `waitid(WNOWAIT)` observes the exit, the group is killed while the identity is still
reserved, then it is reaped. **R6-03** — `ChildReaper`'s unbounded `waitpid` could wedge the
**production** daemon; `launcher::reap_within` already existed with that exact reasoning and is
now shared rather than reimplemented. **R6-04** — the privileged-parent mode check read only the
last octal digit, so 0775 passed. **R6-07** — an unreadable probe read as "free". **R6-08** —
every read error read as EOF.

---

## Verification boundary

lib + doctests: `EXECUTED 123 / SKIPPED 22`; b1_integration 14; barrier 5/5 unprivileged;
clippy rc=0 in both feature configurations.

**NOT RE-RUN AT ROOT SINCE R6-01's RESTRUCTURE.** Leg 1's new witness path — the poll, the
liveness branch, the group teardown — is **compile-verified only**. The previous root run
predates it. R4-03's discharge therefore rests on leg 2 (`Resolved` confirmed at root three
times, unchanged by this round) plus a leg 1 whose *shape* is new since it last executed.

**One process note, because it bears on how much the numbers above are worth:** the aggregate
`scripts/test-count.sh` has now twice caught failures that `--lib` and `--test <name>` both
passed — most recently a doctest I added in this diff. Per-target runs do not cover doctests.

---

## Defect classes

**Pre-foreclosed:** 1, 10, 22, 25, 34, 35, 36.

**Spend the budget here:** **37**, applied to this diff, per the LEAD. **17** — five instances
this arc; assume the reported instance is one of several. **27** — R6-01 and R6-05 both changed
how the guard observes and tears down the child; they were written in the same sitting.

---

## Verdict

**APPROVE / REVISE / FAIL**; per finding: ID (`D0A-R7-NN`), severity, root cause, impact, fix
sketch.

Two predictors are stated at the top with their hit rates. **If they are right, the findings
should cluster in this diff's own fixes and in verification code; if they are wrong, that is
itself worth saying**, because they are now steering where I look first.
