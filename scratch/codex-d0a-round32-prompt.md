# Codex adversarial review — D0-A round 32 (the merge gate)

This prompt is `scratch/codex-d0a-round32-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff 63af7f7..4a0a0b1`** — six commits. Pinned to a SHA, not `..HEAD` (D0A-R18-09).

```
 27 files changed, 1462 insertions(+), 72 deletions(-)
```

The round-31 remediation (1×P1, 5×P2), the withdrawal and then the re-closure of D0A-R28-02,
and your evidence directory committed as retained artifacts.

---

## Lead: five root runs, and the DANGEROUS one was the pass

| run | outcome | cause |
|---|---|---|
| 1 | FAIL | asserted the daemon's log against **stderr**; `tracing` writes to stdout |
| 2 | FAIL | asserted the **pre-extraction message text**, from memory |
| 3 | FAIL | asserted `child="ai"` against bytes carrying **ANSI escapes** |
| **4** | **PASS** | **on assertions the harness itself could satisfy** |
| 5 | PASS | with the survivor check first — the daemon's own cleanup observed |

**The product behaviour was correct throughout.** Every failure was the test being wrong about
the world. And **run 4 is the finding**: it looked like closure, I recorded it as closure, and it
rested on evidence that could not separate the daemon's cleanup from `DaemonGuard::wait()`'s
**unconditional `kill_group`**. Your counterfeit daemon — one that reports termination and leaves
its child alive — passed all nine assertions with `killed == false`.

Three red runs cost time. **The green cost a false entry in the conformance register**, which is
class 51's venue: a record exists so readers stop deriving, so an overstated closure propagates
by design. It was withdrawn at `13db641` and re-made at `4a0a0b1` only with an observation that
discriminates.

**The thing to attack: is run 5's evidence actually different in kind, or only in detail?**

---

## The vacuity check is what I claim makes this closure different — press on it

`wait()` now samples live members of the daemon's process group **immediately before**
`kill_group`, and a non-empty sample **fails the test as its first assertion** rather than being
logged. An intervention means the run proves nothing about the daemon, so passing with a caveat
would be the same defect one level down.

**But an empty sample is evidence only if a non-empty one is reachable**, and that was an
ARGUMENT: `DaemonGuard::spawn` uses `.process_group(0)` so the daemon leads its own group, and
neither `launcher.rs` nor `execute.rs` calls `setsid`/`setpgid`, so its forked children inherit
that pgid. After four rounds of assertions that could not match, an argument is not enough — so
`live_group_members_finds_a_survivor_and_ignores_zombies` demonstrates the scan finding a live
child and skipping a zombie.

**The question I cannot answer from inside: does that demonstration transfer?** It proves the
scan works against a fixture built with `.process_group(0)` in the test process. The assembly
run is a different shape — a real daemon, forked children, a pgid inherited across `execve`.
**Is the fixture demonstration sufficient, or does it prove the scan works in a fixture and
leave the assembly case still argued?** If the latter, what would settle it — an assembly run
with a deliberately non-cleaning daemon, or something cheaper?

---

## The residual, stated plainly rather than as a caveat

**Zombies are excluded from the survivor scan.** So a daemon that **killed a child but did not
reap it** is indistinguishable from one that did both: after the daemon exits, init collects the
corpse either way. The exclusion is deliberate — a `Z` after daemon exit is a race with init
rather than a child the daemon failed to terminate — but the consequence is that
**R29-05's `Unreaped` branch is invisible to the very check introduced to observe cleanup.**

The register therefore says the daemon **cleaned up**, not **reaped**. **Is that word doing
enough work, or is it a distinction a reader will not make?** I would rather be told the row
overstates again than discover it in round 33.

---

## The two branches, under your own standard

You ruled: retention makes an experiment reproducible; **a defined execution mechanism and
enforcing assertions make it an ongoing regression guard**; and committing a directory alone does
not change that distinction.

| branch | category, by your ruling |
|---|---|
| **R29-05 `Unreaped`** | **UNCONSTRUCTED.** Needs a child in uninterruptible sleep. You suggested deterministic syscall/clock injection to test the POLICY decision without claiming to reproduce real `D`-state. Nothing exists yet |
| **R29-06 EINTR** | **EXPERIMENTALLY OBSERVED.** Your probe is now committed here (`scratch/d0a-round31-review/eintr-probe.py`) with its evidence: 1 EINTR/panic/child-alive at `2c7dee0`, 81 EINTRs/no panic/child reaped at `63af7f7`. It observes real interrupted syscalls rather than fabricating errno — and it is **outside the required suite**, so by your own ruling it is not coverage |

**So the concrete question: what turns the EINTR probe into a guard?** It needs an execution
mechanism and enforcing assertions. The obvious move is to vendor it as a `#[test]` — but it
depends on delivering a signal inside a `waitpid` window, which is timing-shaped, and this
project's rule for timing-shaped tests is ≥30 iterations before they are offered as evidence
(CLAUDE.md §6). **Is that the right shape, or does a probe that cannot be made deterministic
belong permanently in "experimentally observed" with the register saying so?**

Note also your own observation that extracting `shutdown.rs` **did not move**
`ChildGuard::reap_status` — R29-06's fix still lives in `test_child_guard.rs`, untested.

---

## The round-31 remediation — attack its sufficiency

| finding | fix | attack |
|---|---|---|
| **R31-01** | mutations in an isolated `git worktree add --detach <SHA>` | the guard dirties the working tree first and asserts the marker does NOT appear in the checkout, so it is a checkout of the COMMIT rather than a copy. **Does the input-closure question really dissolve, or does the worktree share something that matters** — `.git`, hooks, a config? |
| **R31-03** | every child leads its own session; cancellation kills the GROUP first | found by measuring a hung run, not by reasoning: the handler ran and Python's teardown then blocked on a child it had never been told to stop. **Is killing the group before restoring the right order?** |
| **R31-02** | survivors sampled before the guard intervenes; unit tests verify reaping via `is_fully_gone` | your counterfeit now fails 2 of 10 by name. **Is `kill(pid, 0) == ESRCH` the right predicate**, or does it admit a pid that was recycled? |
| **R31-05** | `waitid` return checked; EINTR retried; `si_pid`/`si_code` verified | RED-proven by forcing an invalid idtype. **Is checking `si_code` against three terminal constants complete?** |
| **R31-04** | a REAL campaign, synchronised on the journal, a REAL SIGTERM, four properties | the old guard passed with a no-op `_install_signal_handlers`. `DELPHI_MUTATION_TEST_CMD` is a documented seam — **is a seam in the harness acceptable here**, given what seams have cost this project elsewhere? |
| **R31-06** | one machine-readable `PRECONDITION_TOKEN`, guarded at both ends | **is there a precondition site that still does not carry it?** |

**And a weaken of mine that was INVALID, recorded because reporting it would have been false.**
The first attempt at R31-04's RED sliced from `_install_signal_handlers` to the next `def` and
deleted `_ACTIVE_CHILD` with it, so the suite died on a `NameError` — a failure for the wrong
reason, which is exactly the `INVALID` vs `NOT CAUGHT` distinction the harness itself draws.
Redone against the function body alone. **Does the harness's own classification need to apply to
the weakens performed on it?**

## Corrections carried from round 31

Three claims of mine you found overstated, corrected in place: **nine assertions, not eight**;
**"the fixes are structural"** (the failure messages still printed raw `{stdout}`/`{stderr}` —
class 52's own prescription, violated by the change that wrote class 52); and **"a self-test that
could not fail"** (two checks were inert, the rest decided). Also your correction to me on
readiness, and mine to you on `ScaffoldEntry`, both recorded.

## What remains open

`action.timeout` enforced nowhere (R9-04, binding only); the pending store has no cap; the
mutation campaign is unprivileged-only and the five root-gated tests have never been
mutation-tested; the suspend divergence is unmeasured; **the production logind gate is blocked on
a seated lane**; R22-01 reopened; R21-01's semantic-forgery half, R21-04, R21-06 await the
native-UI increment.

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per §13.9

**(a) Pre-foreclosed:** **10** (a skip reports `ok`); **43**; **44**.

**(b) Applicable and NOT foreclosed:**

- **51** (a false claim in a trusted document) — **violated by the register in the same round it
  was written.** Is the class stated well enough to have prevented that?
- **52** (display vs bytes) — its own prescription was violated by the commit that wrote it.
- **49** (silence ≠ coverage) — run 4's PASS is 49's shape: a green that measured nothing.
- **48** (fix scoped to the named instance) — the input-closure list, admitted.
- **45** (the totality claim) — this range asserts "the daemon cleaned up", "the vacuity question
  was checked", "any one property failing fails the guard". **Audit all three.**
- **41** (wrong altitude) — `live_group_members` parses `/proc/<pid>/stat` by hand.

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Each finding: **ID** (`D0A-R32-nn`), **severity**, **root
cause**, **impact**, **fix sketch**.

**Most valuable returns:** (1) whether run 5's evidence is different in KIND from run 4's, or
whether I have moved the same weakness one layer down; (2) whether the vacuity demonstration
transfers from the fixture to the assembly; (3) whether "cleaned up" is doing enough work given
`Unreaped` is invisible to the check; (4) a defect in `live_group_members`, which is hand-rolled
`/proc` parsing standing in front of the closure.
