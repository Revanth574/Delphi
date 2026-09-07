# Codex adversarial review — D0-A round 30 (the merge gate)

This prompt is `scratch/codex-d0a-round30-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff 2c7dee0..9fa4017`** — nine commits. Pinned to a SHA, not `..HEAD` (D0A-R18-09).

```
 14 files changed, 1310 insertions(+), 337 deletions(-)
```

The round-29 remediation (1×P1, 7×P2), **the R28-02 extraction you specified**, and lane runs
18 and 19.

---

## Lead: the gap is closed at the unit level — and the two things that look like they strengthen that, don't

D0A-R28-02's shutdown policy had been compiled, linked, and run **past** rather than **through**
for three rounds. `runtime/src/shutdown.rs` now owns it, with your named cases: a cooperating
child **with its exit status preserved**, a child that outlives grace (the `SIGKILL` branch
nothing had ever taken), an already-reaped child, a pid that is not ours, both children
**independently with per-child attribution**, and the `is_clean` boundary `main` branches on.
**Lane run 19 executed all eight at root.**

**The inflation is already removed, because the honest version is the useful one:**

- **The delegation guard passing at root adds NOTHING.**
  `the_daemon_delegates_shutdown_and_does_not_reap_by_hand` uses `include_str!` — a
  **compile-time source read**. It executes no process and touches no privilege, so running it
  as root re-checks a string that was already checked. What it establishes in *either* lane is
  real and was earned: it **caught** `ChildReaper::Drop` carrying a second copy of the policy on
  its first run. What it does not establish is anything lane-dependent.
- **The per-child attribution cases passed IDENTICALLY, which is not root COVERING them.** They
  spawn and reap their **own** children, and reaping your own child needs no privilege — so
  sameness was predicted and is the expected outcome. Root's extra power is over processes that
  are *not* its children: precisely the case the test does not construct.

So: **the extraction is real, its unit coverage is real, and root execution bought less than it
appears to.** Attack that framing if it is still too generous.

### The extraction caught two things on its first run, and one is a defect I introduced

1. **`shutdown_child` guarded `pid <= 0` inside the REAPER and fell through to
   `kill(Pid::from_raw(0), SIGKILL)`** — signalling the entire process group. It **SIGKILLed the
   test runner** (exit 137). D0A-R7-07's exact hazard, re-learned: *a guard on the WAIT side is
   not a guard on the SIGNAL side.* Guarded at the top; the test asserts the specific refusal.
2. **The delegation guard failed immediately** and caught `ChildReaper::Drop`'s second copy. It
   now calls the same implementation with a **ZERO grace**, which *is* the error-path semantics,
   so the two paths differ in an argument rather than in code.

**Judge whether the guard's shape is sound.** It is a source-text assertion — a weak instrument
in general (`DEFECT_CLASSES` 41) — used because the property is exactly "these tokens do not
appear". Is that the right tool, or does it invite a future evasion (a helper function, a
re-export) that satisfies the grep while restoring the duplicate?

---

## DECISION REQUESTED, not an open item: assembly coverage

Run 19 does **not** show that `main`'s branch is taken at root after a terminal outcome. You
named assembly coverage separately from the extraction, and it has now been carried three
rounds as "owed". **Carrying it a fourth is the thing to avoid**, so this asks you to pick
rather than to agree it is open.

| option | what it buys | what it costs |
|---|---|---|
| **A — feature-enabled integration test** | Assembly coverage: proof the daemon *invokes* the policy after a terminal outcome. Runnable today, on this lane, in CI. | It runs a binary built with `--features insecure-test-seams`, whose logind gate is bypassable. **It certifies nothing about the production gate**, and a green could be read as certifying more than it does — the exact over-read this arc keeps producing. |
| **B — declare it closable only on a seated lane** | Honesty: the gap is named, bounded, and not papered over with a seam-built binary. | The gap stays open indefinitely — **a seated lane is hardware nobody has**, and B2a's gate-POSITIVE has been blocked on that same shape since the composition. |

**Which, and why?** If **A**, say what the test must assert so its scope is unmistakable from
its own body — I would rather encode the limitation in the assertion than in a comment. If
**B**, say so plainly and it goes into the register as a bounded, dated limitation rather than
a recurring TODO.

---

## A STANDARD REQUESTED, not an answer: what counts as covered when the condition is hard to construct

Two branches shipped in round 29 and remain unexercised:

- **R29-05's `Unreaped`** — needs a child in **uninterruptible sleep**. Nothing in the tree
  constructs one. `only_an_unreaped_child_counts_as_failed_cleanup` constructs the *value*, not
  the *condition*.
- **R29-06's EINTR retry** — needs a signal delivered **inside the `waitpid` window**.

**You reproduced the second with a signal-injection probe.** So it is not unconstructible — it
is unconstructed *here*, and your probe is not in this tree.

That is `DEFECT_CLASSES` 49 one level down, and it is the question I actually want settled:
**an unconstructible condition and an unexamined one look identical from inside the test
suite.** Both are "no test covers it". So:

1. **Does a condition provable only by a probe outside the suite count as covered?** By this
   project's own rules an unretained experiment is indistinguishable from one that never
   happened (D0A-R28-05) — which suggests **no**, and that your probe, unretained, is by that
   standard the same as no probe.
2. If the answer is no, is the correct move to **retain** such probes (as
   `scripts/mutation-campaign.test.py` retains its guards), or to **declare the condition out of
   reach with the reasoning recorded**, so the register distinguishes *unconstructed* from
   *unconstructible*?

I am asking for the rule, not the verdict on these two branches — the rule is what stops this
recurring.

---

## Two predictions this range falsified — one from each of us

Recorded together because the symmetry is the point: in the same two rounds, each party made a
prediction the data refuted.

**Mine.** I reported the lane consumes **~0.5 GiB per run** and carried it into the round-29
prompt as an operational item. Readings: run 17 `3397M` → run 18 `3377M` (−20M) → run 19 `3375M`
(**−2M**). The −506M it rested on spanned **fourteen mutation-campaign rebuilds**. You had said
exactly this at R29 — *two readings cannot isolate per-lane consumption from intervening builds
and campaigns* — and I recorded the caution while carrying the figure anyway. **Lane runs are
cheap; campaigns are the expensive operation.**

**The operator's.** Run 19's two watch items — the delegation guard and the per-child attribution
cases — were requested **specifically because they were expected to discriminate at root**. Both
turned out **lane-independent by construction**: `include_str!` reads source at compile time, and
self-spawned children need no privilege to reap. The run falsified the prediction that root
would show anything different, and the correct record is *identical*, not *covered*.

**Neither error was caught by its author.** Mine was caught by a third data point; the
operator's by working out, while writing the expectation, what each test could actually show.
**Is there a shared shape here worth naming as a class**, or are these two unrelated mistakes
that happen to rhyme?

---

## The round-29 remediation — attack its sufficiency

| finding | fix | attack |
|---|---|---|
| **R29-01** | transactional harness; JSONL flushed per experiment; **restore VERIFIED with `git diff --quiet HEAD`** | is verification-against-HEAD sufficient, or can a mutation be misattributed some way this does not catch? |
| **R29-02** | INFRASTRUCTURE / UNATTRIBUTED / CAUGHT / NOT CAUGHT, full stdout+stderr retained | is the partition complete? `scripts/mutation-campaign.test.py` asserts six classifications including your disk-full case — check the markers list for gaps |
| **R29-03** | inputs widened **including the harness itself**; baseline run required | it refused its own uncommitted change on first invocation. Is the input set complete? |
| **R29-04** | assertion moved to `client_deadline_policy().is_none()` | this catches **any** finite bound where a timing test caught only bounds shorter than its own sleep. Weaken with the real 30 s now fails it. **Is asserting on policy rather than behaviour the right trade?** |
| **R29-05 / R29-06** | per-child terminal state; EINTR retried; disarm only after terminal | both shipped **without tests**, and both are now inside the extraction's scope — see the standard question above |
| **R29-07** | the tier claim stops being made; only what was measured is stated | third correction. Is stating measurements and letting a reader conclude actually the fix, or does it just relocate the inference? |
| **R29-08** | `cargo metadata` resolves the target dir | the guard checked nothing with `CARGO_TARGET_DIR` unset — reproduced fixed in both configurations. Any other guard with a silent no-op configuration? |

## Lane runs 18 and 19

**Run 18** (`208/5/213`, `3582db6`) — **identical counts to run 17 on a different tree**, the
first time figure and tree came apart. The expectation said before the run that the count check
had nothing to detect and the green would be nearly uninformative. It was.

**Run 19** (`216/5/221`, `c10810f`) — the first root execution of the shutdown policy.
Membership 221 identities each side, zero in either direction. Ordering held under convention
for the seventh consecutive run.

**A safety change was made before run 19, not after.** `a_pid_that_is_not_our_child` named
**pid 1**; the kill is unreachable so it passed, but a stray `kill(1, SIGKILL)` is `EPERM`
unprivileged and **init at root**. Changed to `pid_max` at `0cf555e`. The extraction had already
produced one reachable `kill(0, SIGKILL)`, so the reasoning calling it unreachable had just been
demonstrated fallible. **Was that the right call, or over-caution that removed a real case?**

## What remains open

`action.timeout` enforced nowhere (R9-04, binding only); the pending store has no cap; the
mutation campaign is unprivileged-only and the five root-gated tests have never been
mutation-tested; the suspend divergence is unmeasured; R22-01 reopened; R21-01's
semantic-forgery half, R21-04 and R21-06 await the native-UI increment; R23-01..R23-10 specify a
future lane runner.

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per §13.9

**(a) Pre-foreclosed:** **10** (a skip reports `ok`); **43**; **44**.

**(b) Applicable and NOT foreclosed:**

- **49** (silence ≠ coverage) — **the standard question above is 49 one level down**: an
  unconstructible condition and an unexamined one are indistinguishable from the suite.
- **50** (the filter is not the mechanism) — applied raw again; a stale unprivileged pair in
  PROGRESS was caught by reviewing all hits unfiltered.
- **48** (fix scoped to the named instance) — the delegation guard is an *automated* class-48
  check for one specific duplication. Does that generalise, or is it a one-off?
- **45** (the totality claim) — this range asserts "all eight ran at root", "membership
  identical", "lane runs are cheap". **Audit all three.**
- **41** (wrong altitude) — the delegation guard is a source grep, and this arc's greps have
  been wrong repeatedly. It is used here because the property is textual; say if that reasoning
  is self-serving.

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Each finding: **ID** (`D0A-R30-nn`), **severity**, **root
cause**, **impact**, **fix sketch**.

**Most valuable returns:** (1) **a decision on assembly coverage** — A or B, with A's assertion
scope or B's recorded limitation; (2) **the standard** for conditions provable only by an
external probe; (3) a defect in `shutdown.rs`, which is new, security-relevant, and reviewed by
nobody; (4) a defect in a file no prompt has named.
