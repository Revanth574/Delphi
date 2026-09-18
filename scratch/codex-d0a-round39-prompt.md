# Codex adversarial review — D0-A round 39 (the tool that already had the authority)

This prompt is `scratch/codex-d0a-round39-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff 715248a..c560cae`** — 7 commits. Pinned to a SHA, not `..HEAD` (D0A-R18-09).

```
 32 files changed, 2180 insertions(+), 156 deletions(-)
```

**Generated from the final pinned range, after the last commit in it** (D0A-R36-13).

Round 38's remediation: 5×P1, 4×P2, all nine. Nine product/procedure files; the rest is
`scratch/d0a-round38-review/`, your own retained evidence, unmodified.

---

## Lead: "unwired" was the wrong word, and the placement question you answered was the wrong question

Round 38's prompt told you the driver was **deliberately not wired into anything**, and asked
where the requirement should live. You answered: A+C plus a fourth mechanism — a structured
proof-publication gate, lane acceptance consuming the record, CI validating records credited
outside the lane, commit messages citing record IDs, the corpus denying credit to unsupported
prose. You added: *"Fix the demonstrated defects before granting this driver acceptance
authority, then land producer and consumer together."*

**That advice was given about a tool that had already been exercising the authority.**

The driver was never idle. It was the weaken mechanism for **every fix in round 38** — the
round whose subject was its own five P1s. Every "RED-proven" in the seven commits you are about
to review is a verdict this tool emitted, about fixes to this tool, while it carried defects
you had demonstrated. It is the weaken mechanism for this range too.

So "unwired" described the wrong property. **Two separable authorities:**

| authority | status when round 38's prompt called it "unwired" |
|---|---|
| **gating acceptance** — nothing refuses on its verdict | genuinely deferred, and still is |
| **deciding what counts as RED-proven** — every weaken claim in two rounds is its output | **never deferred. Exercised informally from the day it was written** |

Only the first was deferred. The prompt conflated them and I did not notice, which made the
class-54 framing ("a required check disconnected from acceptance") describe half the situation.

**The question is therefore not "should this tool have authority."** It has exercised authority
informally for two rounds, unrecorded and ungated, including over the evidence for its own
repairs. The question is **"should the authority it already has be written down and gated."**

**Does that change your fourth-placement recommendation?** Specifically:

- Your sequencing was "fix the defects, THEN grant acceptance authority." The defects are fixed
  (this range), but the *informal* authority was never granted and never withdrawn — it was
  simply used. Does a tool already deciding what counts as proof make the record MORE urgent,
  or does it argue for withdrawing the informal use until the record exists?
- The fourth mechanism needs an **authoritative record**. The driver does not produce one: it
  prints to stdout and returns an exit status. Nothing is persisted, nothing has an ID, and the
  "RED-proven" claims in these seven commit messages cite **nothing a reader can re-open**. That
  producer is deliberately not built in this range — you said producer and consumer land
  together, and they will — but it means every RED-proof claim in this range is exactly the
  "unsupported prose" your corpus rule would deny credit to.
- Is reviewing a range whose evidence was produced by the tool under review a problem you want
  addressed structurally, or is the recursion acceptable because the suites are independent?

---

## The round's best evidence for the tool is the three weakens it REFUSED — all three mine

Each was a weaken **I aimed**, believing it would demonstrate the fix. Each would have been read
as a red suite by any grep, and called proven.

**1. `WRONG_GUARD` — validity.** Deleting `_loads` outright to prove the import check also broke
the syntax guard, which runs earlier. The suite went red; the reason was not the one claimed.
The discriminating weaken is *reverting to `compile()`-only* — the exact pre-fix behaviour.

**2. `NOT_CAUGHT` — multiplicity.** Removing `count <= 0` from `lane-accept.py` changed no
outcome: `root_counter` values are all ≥1 by construction, so the multiset comparison refuses a
zero anyway. My guard had been passing for a reason it did not name. The check's real job is the
**message**, so the guard now asserts the message — the same disposition as the driver's anchor
predicate, and RED-proven the same way.

**3. `WRONG_GUARD` — process-group collection, and this is the sharpest.** Deleting the
`killpg` to prove the grandchild is collected made the driver **hang for the suite's full 60
seconds**, so its restoration landed *after* the grandchild's write and overwrote it. The weaken
destroyed the timing its own experiment depended on, and the defect it targeted was masked — by
the weaken. The precise weaken is `killpg` → `kill`: the child managed, the group not.

**Attack this claim, because it is the strongest one I am making:** *no reading rule catches a
weaken that invalidates its own experiment.* A grep sees a red suite. A human reads "the suite
failed under the weaken" and writes RED-proven. Only comparing **which guard** failed against
**which guard was expected** separates these — and case 3 shows a weaken can be wrong in a way
that has nothing to do with the predicate at all.

The counter-argument I cannot dismiss: all three were caught because the *expectation was
written down first*, and a disciplined human writing the expected guard name first would catch
them too. **Is the driver the mechanism here, or is `--expect` the mechanism and the driver
merely the thing that enforces writing it?** If the latter, the fourth placement could be much
smaller than a record-and-CI gate.

---

## Three deferred items. Attack the REASONING, not the deferral

All three are stated as honest limits, which is the shape most likely to be comfortable
reasoning wearing rigour's clothes. This arc produced exactly that shape in round 38 — two
written exemptions from weaken-proof, both plausible, both false, both **ratified**. Treat what
follows as the same kind of claim.

**1. The setsid escape — PINNED, not closed.** The suite runs in its own process group,
collected after every invocation. A descendant that calls `setsid` leaves the group and no
`killpg` reaches it. A guard asserts the escape **still works**, so closing it later fails that
guard and forces the register updated. *The reasoning to attack:* is "process-group management
is a guarantee about the group, not about the tree" a real boundary, or a comfortable place to
stop? A pinned-defect guard is also a way to make a hole permanent by making it look managed.

**2. The isolated checkout — DEFERRED with a reason.** You recommended it; it prevents where the
backup only recovers. Not done, because the driver cannot generically make an arbitrary suite
argv execute against a copy, and a whole-tree copy per weaken is a different tool (the campaign
has one). *The reasoning to attack:* the suites this driver actually drives are
`python3 scripts/*.test.py`, which resolve their repo root from `__file__` and would run
correctly with `cwd` set to a copy. "Cannot generically" may be true and irrelevant.

**3. `NOT_CAUGHT`'s ambiguity — IRREDUCIBLE WITH THIS INTERFACE.** It cannot separate "the check
is redundant" from `DEFECT_CLASSES` 58's "the condition was never arranged", and it says so in
its own `reason`. You wrote that this is "unavoidable with the current interface, but not
irreducible in principle — guard entry/completion events plus an independently asserted
precondition can distinguish many unarranged experiments." That was not built. *The reasoning to
attack:* the multiplicity case above was resolved as **measured redundancy** by argument (all
`root_counter` values are ≥1), not by observation. That argument may be right and is exactly the
species of argument that was wrong twice in round 38.

---

## The remediation, and one near-miss caught while writing it

**R38-06** — bytes end to end; restoration verified on **every** terminal path (it sat below the
success path, so early returns jumped it); `not_applied_because` records which predicate fired,
which is what finally gives the anchor check a discriminating case; a keyword-only `_restore`
seam for the one fault the digest check models. Both predicates RED-proven, **by the driver
against its own source**. The register records that both written exemptions were false, that
this is the third time "every check weaken-proven" has been false, and that both arguments
reasoned about values in memory and neither about the round trip through the filesystem.

**R38-04/05** — `_segments` splits stdout per test binary; names come from the **last**
`failures:` in a body, because the first heads the captured-output section the subject controls;
an unparseable summary is recorded as `None`, not skipped, since skipping merges one binary's
body into the next one's count. Attribution refuses on a per-segment mismatch, a nonzero or
signalled enumeration, and an empty listing from a successful one — and runs **only when
something is being attributed**, because placing it first preempted the no-names branch that
owns disk exhaustion. Verified against a real two-crate cargo package: `[([], 0),
(['genuine_guard'], 1)]`. Three fixtures were modelling a producer that does not exist — they
emitted `test result:` **before** `failures:` — and both stubs answered `--list` with the run
transcript, class 57 one collaborator on from R36-06.

**R38-01/03/09** — one restructure, because the three had one cause. `Invocation` keeps outcome
/ code / signal / labels / report apart; report paths are per invocation; validity is
established by **loading**, with the unmutated target as its own control (a target that never
loads is `BASELINE_NOT_GREEN` — the experiment's fault, not the mutation's). The docstring no
longer claims the verdicts are the design, and now states what the side channel does not buy.

**R38-02** — own process group, signal handlers, and a visible `<target>.weaken-backup` that
**refuses** the next run rather than being overwritten. **R38-08** — one strict parser both
sides; a dict is not a multiset. **R38-07** — `sudo env` at all three elevated sites, measured
(plain `sudo` → `<ABSENT>`), and the absence is now audible on the panicking path rather than a
capture that silently did not happen (class 49).

**THE NEAR-MISS, caught at write time and worth more than it cost.** The first R38-07 edit wrote
`SNAP="$D/failure-snapshots"` at procedure line 225 — where `$D` is not defined until line 378.
It would have expanded to `/failure-snapshots`: a snapshot directory nobody could find,
discovered only when a failure produced no evidence. **That is `DEFECT_CLASSES` 58 again, in the
fix for a class-58 instance, for the second time in two rounds.** It was caught by checking
where the variable was set — which is also how `$SNAPDIR` turned out to already exist in §0b,
exported and then dropped by `sudo`. Both halves came from the same check.

Guards: `lane-accept.test.py` **112** (was 101), `mutation-campaign.test.py` **108** (was 101),
`weaken-driver.test.py` **45** (was 17).

## What remains open — do not re-find these

Reaping never independently observed; R29-05 `Unreaped` UNCONSTRUCTED; `Scan`/`Unresolved` never
produced at root; the negative control's `Topology` awaits an accepted reproduction;
`action.timeout` enforced nowhere; the pending store has no cap; the campaign is
unprivileged-only; the production logind gate is blocked on a seated lane. Runs 22, 24, 25 were
REFUSED and recorded. **Not verified here:** that `DELPHI_FAILURE_SNAPSHOT_DIR` arrives in a
ROOT test process on a seated lane — root is password-gated on this box, the same limit you
stated for R38-07. The mechanism is measured on the same-user path; the root path is reasoned.

## Defect-class partition (`docs/DEFECT_CLASSES.md`, 58), per §13.9

**(a) Pre-foreclosed — do not spend budget re-hunting:**
10 (skip-as-pass — `scripts/test-count.sh`); 17 (defect propagated by copy — shared helpers);
50 + the empty-filter extension (the driver never greps — **conditional on the driver working,
which is the subject of this round**); 55 (producer/consumer format disagreement — the contract
guard); 57 (a double answering for a collaborator it does not model — closed AGAIN this range,
in `fake_sh` and the subprocess stub, for the enumeration).

**(b) Applicable and NOT foreclosed — concentrate here:**
**54** (a required check disconnected from acceptance — *reframed above: the acceptance half is
deferred, the proof-deciding half was never deferred at all. The most important item in this
round*); **58** (arranged but not verified arranged — TWO instances in two rounds inside fixes
for class 58, one of them caught only at write time); **16** (a fixture damaging the operator's
environment — the driver writes to the working tree; the backup and the group collection are
new and unreviewed); **22** (weaken blind spot — the driver is the foreclosing primitive and it
refused three of my own weakens this range); **49** (silence read as agreement — the snapshot
that did not happen); **12** (reject the invalid class, not the value — `MUTATION_INVALID` vs
`NOT_CAUGHT` is that distinction, and R38-03 is what happens when it collapses).

## Verdict format

**APPROVE / REVISE / FAIL.** Every finding: ID (`D0A-R39-NN`), severity (P1 → P2 → P3), root
cause, impact, fix sketch, and — where you assert a false accept or a false green — **the
reproduction**, on temporary copies, with the subject's actual outcome retained rather than
inferred from a missing filtered line.

Verify against the live tree via the CLI (`git show <SHA>`, read the files); do not reason from
this prompt's summary. If the diff stat disagrees with what you find, that is a finding.

**Run the tools.** All three suites are self-contained:
`python3 scripts/weaken-driver.test.py` (45), `python3 scripts/lane-accept.test.py` (112),
`python3 scripts/mutation-campaign.test.py` (108). **A weaken of any of them that leaves the
count unchanged is the finding I most expect**, and it was the correct expectation last round:
round 38's prompt predicted it, and both of that round's labelled exemptions fell to exactly
that test.
