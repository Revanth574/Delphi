# Codex adversarial review — D0-A round 35 (the merge gate)

This prompt is `scratch/codex-d0a-round35-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff 0ba5ddb..06eeea7`** — five commits. Pinned to a SHA, not `..HEAD` (D0A-R18-09).

```
 23 files changed, 2431 insertions(+), 274 deletions(-)
```

The round-34 remediation (5×P2), §4b's retention fix, and lane run 21.

---

## Lead 1: the control confirmed rather than overturned — for the second time

Run 21's Part B returned **`Reached`**. So did run 20's equivalent. `Reached` is the outcome
that leaves D0A-R28-02 exactly where it was; the three verdicts that would have changed
something — `Topology` (a finding about the assembly), `Scan` (a defect in the control),
`Unresolved` (report no cause) — **have never been produced at root.** They are unit-tested
against constructed records and nothing else.

**The question I cannot answer from inside: is this control accumulating evidence, or
accumulating agreement?**

The honest case for *evidence*: the observer was rebuilt between the two runs, so run 21 is not
a repeat — it re-validated with provenance and liveness gating after run 20's observer had been
found to identify by name and to count a zombie as a live sighting. Different instrument, same
answer.

The honest case for *agreement*: a control whose passing outcome is the one its author needs,
run twice, both times passing, with its discriminating outcomes never observed in the
environment they are meant to discriminate. `DEFECT_CLASSES` 49 says a region that stops
producing findings is either exhausted or unexamined and silence cannot tell you which. **Two
`Reached` verdicts are exactly that silence.**

**What would settle it?** A deliberately mis-assembled daemon — one whose child is put in
another process group — would produce `Topology` at root and prove the verdict is reachable in
the assembly rather than only in a unit test. That is a fixture, not a product change. **Is
that worth building, or is there a cheaper construction that produces a non-`Reached` verdict
in a real run?**

---

## Lead 2: I fixed the retention finding where it was pointed, and left the same defect one step along

Your ruling on run 20 was that its membership claim is independently unauditable because both
comparison inputs lived in `/tmp`. Fixed: §4b now writes `root-identities.txt`,
`unpriv-identities.txt`, `membership.txt` and the producer transcript into the repo, committed
with the run record. Run 21's membership is checkable by anyone — 229 lines each side, `diff`
empty, verified in-repo rather than taken from the operator's report.

**And Part B's `CONTROL OBSERVATION` — the evidence the supplementary scan actually rests on —
was still only a terminal paste.** I fixed the retention of the *check you named* and left the
retention of the *thing the check exists to support*. That is **class 48 operating inside the
remediation rather than inside the record**: the fix's scope was set by where the finding
pointed.

It is now `scratch/lane-run-21/part-b-control.txt`, with a header stating it was **TRANSCRIBED
FROM THE OPERATOR'S TERMINAL, NOT CAPTURED** — labelled so it cannot sit silently beside four
files the check wrote itself. The procedure now tees Part B from run 22 on.

**Two things to press.** Is a labelled transcription worth retaining at all, or does it launder
a terminal paste into something that looks like an artifact merely by being committed next to
real ones? And: **what else in this tree is retained by transcription rather than capture?** I
have not audited that, and the pattern of this finding says I would find it where the last fix
stopped.

---

## Lead 3: the census shows something the verdict cannot, and it is not asserted

Run 21's Part B:

```
CONTROL OBSERVATION: daemon pgid 30007, ai comm "sai", 20 samples
  matched in the daemon's group: [(30095, 'S', "sai")]
  census: [(30010, 'S', "delphi-runtimed"), (30095, 'S', "sai"), (30098, 'R', "unix_chkpwd")]
  verdict: Reached
```

The census returns **three** processes — the forked `delphi-runtimed` (the leader is excluded by
design) and `unix_chkpwd` in state `R`, the PAM helper caught mid-authentication. That is
evidence the scanner **enumerates the group** rather than matching a name and returning its own
target.

**Nothing asserts it.** A scanner that returned exactly one process, always the one it was asked
for, would pass every check in this tree: the control would say `Reached`, the survivor sample
would be empty, and the assembly test would be green. The property that makes the empty sample
meaningful is *enumeration*, and it is currently an observation a human happened to read.

**Should this be an assertion?** The candidate shape: require the census to contain at least one
process that is **not** the AI — the daemon's own forked child is always there — so a
degenerate "return only the target" scanner fails. **Is that the right assertion, or does it
encode an accident of this run's timing** (`unix_chkpwd` is transient; the forked
`delphi-runtimed` may not be, and I have not established which members are guaranteed)?

---

## The round-34 remediation — attack its sufficiency

| finding | fix | attack |
|---|---|---|
| **R34-01** | provenance: `ppid == daemon_pid` before any causal claim; name lookup is candidate discovery only | is `ppid` the right binding? The AI is forked by the daemon, but a reparented or intermediate process would not match. `starttime` is recorded and **not** used |
| **R34-02** | liveness: `state != 'Z'`; `Scan` needs the miss repeated across an overlapping window | is "two iterations" an overlapping window, or a longer way of assuming one? |
| **R34-03** | registration verified as well as the filesystem; unreadable list is a FAILURE; a lock is reported, never force-broken | your locked-worktree reproduction is now a guard. Is there a third resource the cleanup owns and does not check? |
| **R34-04** | one authoritative account; both tables replaced; provenance marked per observation | **fourth correction to this row.** The closure now rests on §4 boundedness explicitly, with reaping labelled a **self-report by the component under test** |
| **R34-05** | producer/test-output separation + line-anchoring; conflict yields UNATTRIBUTED | guards run **both** directions — the three marker-as-data counterexamples AND the genuine events — because a narrowing that deletes detection is not a fix. Is the section parser right? It ends a test region on `failures:`, `test result:` or `running ` |

Each weaken is recorded with the assertion it failed on: dropping provenance makes a NAMESAKE
decide `Topology`; dropping liveness makes a CORPSE decide `Scan`; dropping the window makes a
SINGLE MISS decide `Scan`; searching the whole blob makes an assertion expecting `"Killed"`
INFRASTRUCTURE; dropping line-anchoring makes the precondition token as data a PRECONDITION
FAILURE; skipping the registration check makes a LOCKED entry report success.

**Class 53 was retitled at your instruction** — *unsupported causal attribution* — and the entry
now records that **its own text contained an unsupported claim twice**: the title asserted
motive, and the body claimed "every individual statement was true" when *"this is a defect in
the control"* was false in your constructed case. **Is it right now, or does a class about
unsupported inference still contain one?**

**And the correction to my own scoping, recorded rather than quietly upgraded:** I called the
R33-02 sender fix "defence in depth, not a proven impact" because a two-factor weaken gave
`168 passed; 1 failed` in both shapes. That measurement was observing the wrong property. Your
`sender-probe.py` measured the mechanism — thread identity reused, 51/53/54 signals to the
successor with an unrelated `waitpid` returning EINTR, zero after. **An honest under-claim was
still an unsupported one**, and I had also guessed that a stale `pthread_t` yields `ESRCH` when
the behaviour is undefined.

## Lane run 21

`223/6/229` at `d1fa4fe`, predicted exactly, expectation committed alone. Membership 229/229
with **retained, independently verified inputs**. Freshness enforced with both hash sides
asserted at 17. PAM OK. No stale sessions. **Free space passed on its own** — run 20's refusal
was overridden; this one did not have to be.

**One process defect, and it was loud only by luck of position.** `$LOG`/`$STATUS` were unset in
a fresh shell, so `: > ""` failed with `bash: : No such file or directory` and the chain stopped
while looking like the long-running loop it should have started. It happened to be the chain's
**first** command; the same unset variable *inside* the loop would have written a log nobody
could find and produced a count from a stale file — appears to run, does not, leaves a plausible
artifact. Now `${VAR:?}`, which names the missing variable.

**That is the THIRD instance of a required check disconnected from acceptance** (run 20's
dropped §4b; run 20's overridden free-space refusal; this). **Your acceptance verifier —
one authoritative executable procedure, retained per-step evidence, and a verifier that rejects
missing, failed or misordered checks — has gained evidence in every round since it was
deferred, and the deferral was the operator's call.** It is still not built. **Say plainly
whether continuing to defer it is now unreasonable**, given that the argument for it is
strictly stronger than when you made it.

## What remains open

**Reaping is NEVER independently observed** — the only evidence is the daemon's own exit status,
a self-report by the component under test; R29-05's `Unreaped` is UNCONSTRUCTED. `Topology`,
`Scan` and `Unresolved` have never been produced at root. `action.timeout` enforced nowhere
(R9-04); the pending store has no cap; the mutation campaign is unprivileged-only and the six
root-gated tests have never been mutation-tested; the suspend divergence is unmeasured; **the
production logind gate is blocked on a seated lane**; R22-01 reopened; R21-01's semantic-forgery
half, R21-04 and R21-06 await the native-UI increment.

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per §13.9

**(a) Pre-foreclosed:** **10** (a skip reports `ok`); **43**; **44**.

**(b) Applicable and NOT foreclosed:**

- **48** (fix scoped to where the finding pointed) — **the retention asymmetry is this round's
  instance, and it is in the remediation rather than in the record.**
- **53** (unsupported causal attribution) — retitled this round; audit whether the rebuilt
  observer merely relocated the inference into `ppid` and `state`.
- **49** (silence ≠ coverage) — two `Reached` verdicts and three never-produced ones.
- **45** (the totality claim) — this range asserts "membership verified in-repo", "each weaken
  fails on the assertion it targets", "both directions guarded". **Audit all three.**
- **51** (a false claim in a trusted document) — the register row's fourth correction.
- **41** (wrong altitude) — `read_proc_record` replaced two hand-rolled parsers with one, but it
  is still hand-rolled `/proc` parsing in front of the closure.

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Each finding: **ID** (`D0A-R35-nn`), **severity**, **root
cause**, **impact**, **fix sketch**.

**Most valuable returns:** (1) **whether two `Reached` verdicts are evidence or agreement**, and
the cheapest construction that produces a non-`Reached` verdict in a real run; (2) **something
else retained by transcription rather than capture** — the pattern says it sits where the last
fix stopped; (3) whether the census property should be asserted, and with what assertion; (4) a
ruling on whether deferring the acceptance verifier is now unreasonable.
