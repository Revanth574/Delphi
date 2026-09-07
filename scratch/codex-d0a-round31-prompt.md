# Codex adversarial review — D0-A round 31 (the merge gate)

This prompt is `scratch/codex-d0a-round31-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff 9fa4017..63af7f7`** — nine commits. Pinned to a SHA, not `..HEAD` (D0A-R18-09).

```
 20 files changed, 1347 insertions(+), 148 deletions(-)
```

The round-30 remediation (1×P1, 5×P2), **the assembly test you specified**, and two new corpus
classes.

---

## Lead: the assembly gap is closed — and why it was open for three rounds

`b1_daemon_bounds_an_ai_that_completes_the_protocol_and_stays_alive` **passes at root against
the real `delphi-runtimed` binary**, all eight assertions. The daemon's own log carries the
property with its timing:

```
20:12:02.361  INFO  served one action outcome=Completed
20:12:07.395  WARN  child outlived the grace period and was terminated (D0A-R28-02) child="ai"
```

5.03 seconds — grace expiring, `SIGKILL`, attributed to the AI by name. Your fifth assertion is
what makes this assembly coverage rather than outcome coverage, and it needs no special
construction: **without the bounded exit, `main` blocks in `waitpid`, `DaemonGuard` kills at the
deadline, and `!killed` fails.**

### The structural reason it sat unexercised, which is the part worth attacking

It needed a **new fixture**, and not for the reason given in round 30. Your note said the
existing binary-flow test still stages `delphi-minimal-shell` emitting `ScaffoldEntry` where the
daemon requires `SurfaceLive` — **that was already closed at D0A-R1-03**: under the feature the
minimal shell emits the surface marker. Measured, not assumed: the existing test skips for
`requires root`, not for readiness.

The real reason is sharper. **`delphi-minimal-ai` cooperates — it returns from `main` after its
terminal response — so it can never take the branch.** Every test that has ever driven the
daemon drove it down the path where `reap_within` succeeds inside the grace period. **The only
client that spoke the protocol also always exited**, so the `SIGKILL` branch had no reachable
caller in the entire suite. That is why three rounds of "the fix is in" produced no coverage:
not an oversight in the tests, a property of the only fixture available.

`delphi-stubborn-ai` speaks the identical protocol through the identical helpers and then
refuses to exit, so any behavioural difference is attributable to the one thing that differs.
**Attack whether that isolation actually holds** — is there anything else different between the
two fixtures that could explain the daemon's behaviour?

### The cost, and it is the useful half

**The product property passed on RUN ONE.** `!killed` is asserted first and cleared immediately:
the daemon bounded its wait against a stubborn AI the very first time it was asked. The next
three root runs were **my test being wrong about the world**:

| run | cause |
|---|---|
| 1 | asserted the daemon's log against **stderr**; `tracing_subscriber::fmt()` writes to stdout |
| 2 | asserted the **pre-extraction message text**, reconstructed from memory |
| 3 | asserted `child="ai"` against bytes that are `\x1b[3mchild\x1b[0m\x1b[2m=\x1b[0m"ai"` |
| 4 | PASS |

Recorded as **class 52**, and the fourth instance is what earned it: the failure output
**re-renders the escapes through the same terminal**, so the diagnostic channel has the same
lossiness as the original and looking harder cannot find it. Only `cat -v` could. The fixes are
structural — a shared `const` so wording cannot drift, a `strip_ansi` with its own test against
measured bytes, named streams — rather than three corrected literals.

---

## A STANDARD APPLIED TO ITSELF: the two unretained branches

You ruled: *an unretained external probe does not count as regression coverage*, with four
categories — **regression guarded / experimentally observed / unconstructed / blocked on this
lane** — and that *"unconstructible" needs evidence, not absence of a fixture*.

Applied honestly to the two branches still unexercised:

| branch | status under your own categories |
|---|---|
| **R29-05's `Unreaped`** | needs a child in uninterruptible sleep. **Unconstructed** — no fixture exists, and none has been shown impossible. You suggested deterministic syscall/clock injection to test the POLICY decision without claiming to reproduce real uninterruptible sleep |
| **R29-06's EINTR retry** | **UNRETAINED, not unconstructible — and you are the one who constructed it.** Your signal-injection probe reproduced `panicked=true, child after guard dropped=Ok(StillAlive)`. It is not in this tree |

**The question this round is whether the standard applies to its author.** By its own terms an
unretained probe is not coverage — so the EINTR condition is currently uncovered *even though it
has been demonstrated*, and the demonstration lives in your evidence directory rather than the
suite. Two readings:

1. **Importing your probe into the suite satisfies "experimentally observed"** — the artifact is
   retained, reproducible, and cited. Then the work is: vendor it, run it, record which category
   it lands in.
2. **A probe only counts when THIS PROJECT can re-run it as a matter of course** — i.e. it must
   become a test with an execution mechanism, or it stays "experimentally observed" forever and
   the register must say so.

**Which?** And note the sharper form: `scratch/d0a-round30-review/` is now committed to this
repository, so your probes are retained *here*. Does that change their category, or is
retention-without-execution still short of coverage?

Also: you noted that extracting `shutdown.rs` **did not move** `ChildGuard::reap_status`, so
R29-06's fix is still in `test_child_guard.rs` and untested. That is the concrete first step
whichever reading wins.

---

## READ A CLEAN VERDICT ON THIS TEST CAREFULLY

**This is the first round whose subject is a test that PASSES at root against the real binary.**
Every previous round reviewed code with unit coverage, and the recurring finding was the
assembly gap. That gap is now closed, so the shape of what is left has changed.

**If you find nothing in the assembly test itself, that is worth stating explicitly rather than
letting it read as convergence.** Round 25 is the precedent: four quiet rounds were offered as
possible convergence and turned out to be scope exhaustion, proven by three P1s in files no
prompt had named. A green subject is exactly when that mistake is easiest to repeat.

Specific things to press on the test rather than around it:

- **Is `!killed` sufficient for the fifth assertion?** It proves the daemon exited before the
  guard's deadline. Does it prove the daemon exited *through the policy*, or could some other
  path produce the same observation?
- **`strip_ansi` is now load-bearing for every assertion in that test.** It has one test against
  one measured line. What does it get wrong — OSC sequences, incomplete CSI at a buffer
  boundary, a `\x1b` that is data rather than an escape?
- **The stubborn AI sleeps 3600s by default.** If the daemon failed to kill it, does anything
  reap it, or does a failing run leak a process per invocation?
- The test asserts `out.status.success()`. Under D0A-R29-05 an unreaped child makes `main`
  return an error — so a cleanup failure fails the test. **Is that the right coupling**, or
  does it conflate "cleanup failed" with "the assembly is wrong"?

## The round-30 remediation — attack its sufficiency

| finding | fix | attack |
|---|---|---|
| **R30-01** | signal handlers + **journal-before-mutate** + restore verified against the CAPTURED sha | `finally` cannot cover SIGKILL, so the journal is the only evidence for an uncatchable kill. Is a journal line sufficient, or does the harness need the isolated checkout you asked for? |
| **R30-02** | one status-consuming wait; `ECHILD` never fabricated into an exit code | the classifier destroyed the module's headline property and **the test for that property passed anyway** because it raced. Two deterministic tests use `waitid(WNOWAIT)`. Is that the right construction? |
| **R30-03** | inputs widened to the installer PAM fixture and the stale-session script | **the list is not proven complete and says so.** Adding entries after each discovery is itself class 48 |
| **R30-04** | `PRECONDITION FAILURE` classification | are the markers right? Is there a third diagnostic shape that still reads as a detection? |
| **R30-05** | every guard is an assertion; 31 guards | the previous version printed `[FAIL]` and exited 0, so **every campaign result since it shipped rested on a self-test that could not fail.** Does the new one have a reporting path that does not decide? |
| **R30-06** | the PID-1 and signal-permission claims corrected in place | **class 51** was written from this |

## Two corpus classes, and one process defect worth judging

- **51** — *a false claim in a document whose function is to be trusted propagates by design.* A
  wrong statement in code is checked by whoever next reads it; a record exists so readers stop
  deriving. Severity comes from the **venue**. Is that distinct from 45, or a special case of it?
- **52** — *an assertion written from a rendered display cannot match the bytes.* Four instances,
  the fourth invisible in its own failure output.

**And a process defect from this range, recorded rather than rewritten:** commit `6d68c06`'s
message claims a register closure, a cost table and an observation. **Its diff contains only
`DEFECT_CLASSES.md`** — the edit script raised on a missing anchor and the commit ran anyway,
because they were separate shell commands. A *failed edit* produced a *successful commit
asserting the edit happened*. `63af7f7` carries what was described.

That is class 16's shape — the harness damaging the record it is operating on — moved from the
filesystem into the commit log. **Is "verify the diff before writing the message" the right
foreclosure, or does this want a mechanism?**

## Recorded, not fixed — for you to judge

The daemon emits **ANSI escapes to a non-terminal stdout**, which in production is journald.
Escapes in a system log are noise and can confuse downstream parsing. `.with_ansi(…)` gated on
`IsTerminal` would address it. Nobody raised it; it is a product question found while chasing
class 52, and it is handed over rather than changed unilaterally.

## What remains open

`action.timeout` enforced nowhere (R9-04, binding only); the pending store has no cap; the
mutation campaign is unprivileged-only and the five root-gated tests have never been
mutation-tested; the suspend divergence is unmeasured; **the production logind gate is blocked
on a seated lane** (the assembly test certifies the shutdown assembly and explicitly not the
gate); R22-01 reopened; R21-01's semantic-forgery half, R21-04, R21-06 await the native-UI
increment.

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per §13.9

**(a) Pre-foreclosed:** **10** (a skip reports `ok`); **43**; **44**.

**(b) Applicable and NOT foreclosed:**

- **52** (display vs bytes) — **new, and this range is its first application.**
- **51** (a false claim in a trusted document) — new.
- **49** (silence ≠ coverage) — see "read a clean verdict carefully" above.
- **48** (fix scoped to the named instance) — the input-closure list is an admitted instance.
- **45** (the totality claim) — this range asserts "all eight assertions pass", "the fixtures
  differ in exactly one thing", "the fixes are structural". **Audit all three.**
- **41** (wrong altitude) — `strip_ansi` is a hand-rolled parser standing in front of every
  assertion in the assembly test.

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Each finding: **ID** (`D0A-R31-nn`), **severity**, **root
cause**, **impact**, **fix sketch**.

**Most valuable returns:** (1) a defect **in the assembly test itself** — it is new,
security-relevant, and its green is now the evidence for a three-round gap being closed;
(2) the ruling on whether your own probe, now committed here, counts as coverage; (3) a defect in
`strip_ansi`, which is load-bearing and hand-rolled; (4) a defect in a file no prompt has named.
