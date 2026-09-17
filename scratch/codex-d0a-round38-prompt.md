# Codex adversarial review — D0-A round 38 (the weaken driver, and where its verdict belongs)

This prompt is `scratch/codex-d0a-round38-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff 0e2a384..aa0d0e1`** — 8 commits. Pinned to a SHA, not `..HEAD` (D0A-R18-09).

```
 24 files changed, 1215 insertions(+), 51 deletions(-)
```

**Generated from the final pinned range, after the last commit in it** (D0A-R36-13 — the drift
check catching its author; round 37's stat was generated correctly and you confirmed it).

Two things in the range: round 37's remediation (12 findings, 3×P1, 9×P2 — all of them), and
`scripts/weaken-driver.py` + `scripts/weaken-driver.test.py`, **built to your specification** in
round 37's "A mechanism for the empty-filter error."

---

## Lead: the design claim is about what the driver REFUSES, not about what it proves

`RED_PROVEN` is one of nine verdicts and it is the least interesting one. The mechanism is the
other eight, and the sharpest of those is this:

**When the suite fails and the side channel is silent, the verdict is `UNVERIFIABLE` — never
`RED_PROVEN`, and never `NOT_CAUGHT` either.** The driver has a real failure in hand. It could
attribute it. The only remaining way to attribute it would be to read text, and reading text is
the thing this exists to replace — so it refuses, and records that it refused.

That refusal is the whole design. The rest follows from it:

**Nine verdicts, because collapsing any two of them turns a non-measurement into a proof.** Each
pair below was a real wrong claim in this arc, and each is now a distinct verdict:

| the collapse | the wrong claim it produced |
|---|---|
| `MUTATION_INVALID` → `NOT_CAUGHT` | R36-06: a weaken referencing an unimported name died on `NameError`; read as "no bite" |
| `NOT_CAUGHT` → `RED_PROVEN` | R36-04: committed as RED-proven at `0fdabcc`, withdrawn at `2de53b8`; the suite had PASSED |
| `BASELINE_NOT_GREEN` → `NOT_CAUGHT` | the `b51bd8f` bisect: "only `b51bd8f` fails", from a binary that never reached the gate |
| `UNVERIFIABLE` → `RED_PROVEN` | the general form of all three: a failure with no identified cause, claimed as the intended one |
| `WRONG_GUARD` → `RED_PROVEN` | R2-03's mis-aimed RED: B-1's first draft passed under its own weaken |

**Attack the partition itself.** Are nine the right nine? Is any one of them two things wearing
one name — `NOT_CAUGHT` in particular says so about itself in its own `reason` field ("either
the check is redundant, or the condition it needs was never arranged — this driver cannot tell
those apart", `DEFECT_CLASSES` 58). Is any pair distinguishable in principle but not by anything
the driver actually observes?

### The attack I most want, because you already named it and I have not answered it

Round 37, ruling two: *"A side-channel path inherited through an environment variable is likewise
a report channel for trusted helpers, not intrinsically unforgeable evidence against arbitrary
subject code."*

That is correct and the driver does not fix it. `DELPHI_GUARD_FAILURE_REPORT` is inherited by the
whole subject process tree; anything in it can write any label to that path. The driver's
attribution is therefore **exactly as trustworthy as the suite being weakened**, and no more.

What I claim is narrower than "unforgeable": the channel is **a path the parent chooses per
invocation**, so a label cannot arrive from a stale file, a previous run, a hardcoded path, or
text that merely resembles a report — which is the failure mode that produced all three wrong
readings. What I do **not** claim is that it survives a hostile subject.

**Is the narrower claim load-bearing, or is it the comfortable reading again?** The subjects here
are this repo's own suites, so "trusted helper" is arguably the right threat model — but that is
an argument about the threat model, and round 36 is what happens when I make the comfortable
argument about a mechanism I recommended myself.

---

## The two checks in the driver that are NOT weaken-proven — labelled, not counted

R37-11 is the second time. I would rather label the exceptions where a reader meets them than
count them and be wrong a third time. **Both explanations below are plausible-sounding, and
"plausible-sounding explanation for why this check needs no test" is a shape that has been wrong
before in this arc — so attack both.**

**1. The anchor check** (`scripts/weaken-driver.py:107`, labelled in place at :101–106).

```python
if anchor not in original:
    ev["reason"] = "the anchor does not occur in the target"
    return MUTATION_NOT_APPLIED, ev
```

My reasoning: **removing it changes no outcome.** `str.replace` with a missing anchor returns the
string unchanged, so the digest comparison three lines below (`if _digest(target) == before`)
returns the same `MUTATION_NOT_APPLIED` verdict. It is kept for its *message* — it names the
anchor as the cause, where the digest can only say "nothing changed" — and it is defence in
depth by §6's own definition, not a sole defence.

**Where that could be wrong:** if a replacement can change the file's bytes without the anchor
occurring, or if the anchor can occur while the replacement leaves the digest unchanged, the two
checks are not redundant and one of them has no discriminating case. Guard 3 in the test file
(`a replacement identical to the anchor is MUTATION_NOT_APPLIED`) covers the second direction via
the digest, not via the anchor.

**2. The restore-digest check** (`scripts/weaken-driver.py:156`, labelled in place at :151–155).

```python
if ev["digest_restored"] != before:
    return RESTORE_FAILED, ev
```

My reasoning: **it is unreachable as written.** The `finally` block writes back `original` — the
exact bytes that produced `before` — so the digest necessarily matches. It fires only if the
filesystem returned success on a write that did not land. No discriminating case can be
constructed without faking the filesystem, so it is carried as an assertion about a condition
that should be impossible rather than as a checked predicate.

**Where that could be wrong:** `write_text` is not atomic and does not fsync; a short write, an
encoding round-trip, or a concurrent writer could all break "necessarily matches" — in which case
the check is reachable, is a real defence, and is untested. **This repository has now lost a
commit to exactly that class of event** (see the postscript), which is not proof the check is
reachable, but is a reason not to take "the filesystem does not do that" on my word.

`RESTORE_FAILED`'s *other* path — the suite still red after restoration — **does** have a
discriminating case (guard 15: a subject whose suite fails only on its third, post-restore
invocation).

**17 guards, one per verdict plus its discriminating detail; the positive control runs first.**
All nine verdicts have at least one case. Two checks do not. That is the honest count.

---

## The question I want answered more than any finding: WHERE SHOULD THE REQUIREMENT LIVE?

The driver is **deliberately not wired into anything.** Nothing calls it. No procedure step
requires it. That is `DEFECT_CLASSES` 54 — *a required check disconnected from acceptance is not
a check* — and I am leaving it open on purpose, because wiring a tool that decides what counts as
proof *before* anyone has attacked it makes every subsequent claim rest on it. Round 36 and round
37 are both what that costs.

**We have now been wrong about this in both directions**: I deferred building the acceptance
verifier when it should have been built (R35, one wrong deferral, four instances), and I was
about to wire this driver before its review when it should wait. That is why I am asking rather
than deciding.

Three placements. Their failure modes as I see them — correct me, or name a fourth:

| placement | what it would mean | how it fails |
|---|---|---|
| **A. A procedure step** — `scratch/lane-run-7-procedure.md` requires a driver verdict for any weaken cited as RED-proven | matches where §2b freshness and §4b membership already live; the artifact is retained and `lane-accept.py` can require it | it only binds the lane. Weakens are claimed in *commit messages*, all over this arc, with no lane run in sight. R37-04 is the standing proof that this procedure can require an artifact it does not produce |
| **B. A pre-commit refusal** — `.githooks/pre-commit` refuses a message claiming RED-proof without a driver verdict for it | binds the actual site where the claim is made, mechanically, at the moment it is made | it must parse intent from English to know a message is *claiming* RED-proof — a grep deciding what counts as a claim about a tool built because greps decide badly. Trivially bypassed with `--no-verify`, and hooks are per-clone opt-in (`core.hooksPath`), so it is absent by default on a fresh tree |
| **C. A corpus rule with no mechanism** — `DEFECT_CLASSES` says RED-proof requires a driver verdict; nothing enforces it | costs nothing, cannot false-refuse, applies everywhere including places A and B cannot reach | it is exactly the shape §13.4 says has failed every time a mechanism was available: *"a rule ('remember to pass `--nocapture` and look') is the shape that has failed every time a mechanism was available."* Class 54 with the serial numbers filed off |

**My weak preference is A+C** — the lane binds mechanically where it can, the corpus states the
rule where the lane cannot reach — with B rejected because a hook that must classify English is
the defect this tool exists to remove. **I do not trust that reasoning enough to act on it**, and
you are better placed than either of us to say which failure mode is the one that actually bites.

If your answer is "none of these, and here is the fourth," that is the most useful outcome of
this round.

---

## Round 37's remediation — all twelve, and what to check

**R37-01** (P1) — unprivileged membership compared as a **multiset**, both sides parsed into
`Counter`s and compared directly, so `membership.txt`'s printed zeroes are re-derived rather than
trusted. **R37-02** (P1) — both control `.status` files read and required to be zero and
consistent with their exact completed test; the root transcript checked for `test result: FAILED`.
**R37-03** (P1) — attribution now requires named failures to be members of the binary's own
`--list` set, with the count matching libtest's own summary; a fabricated `failures:` block names
a test the binary does not have and is rejected.

**R37-04** the contract guard now joins the procedure's *written* artifacts to the verifier's
*required* inputs; **R37-05** `_is_historical` treats unknown identity as CURRENT — historical
runs must declare via `PREDATES.txt`; **R37-06** `Setup::drop` captures session state on
`std::thread::panicking()` **before** its own cleanup; **R37-07** per-run snapshot directories,
no cross-run wildcard; **R37-08** final hygiene after both controls, before acceptance;
**R37-09** signalled builds (`returncode < 0`) separated from demonstrated compile-invalid;
**R37-10** the clock injected into the process actually executing `main`, every call required to
succeed; **R37-11** the positive fixture now creates `lane-run-27` so it exercises the **strict**
path; **R37-12** the register distinguishes runs 20/21 from 23/24 (`4343350` predates both).

`lane-accept.test.py` is now **101 guards** (82 at your last review), `mutation-campaign.test.py`
**101**, `weaken-driver.test.py` **17**.

## The remediation's own error rate — three, again, in a round about reading things wrongly

Round 37 found two of my corrections were themselves wrong (R37-11, R37-12). Fixing round 37
produced three more errors of my own, all caught before they shipped:

1. **The R37-03 narrowing deleted all real detection.** Binding a named failure to the binary's
   `--list` set, I truncated `genuine::test` with `split(":")[0]` → `genuine`, which matches
   nothing. Every real failure became UNATTRIBUTED. Caught by the guard asserting a REAL failure
   stays CAUGHT — the guard for the opposite direction of the finding being fixed.
2. **`fake_sh` answered for a collaborator it does not model** (class 57), intercepting the
   campaign's own `check-free-space.sh` measurement, so a correct classifier read as broken.
3. **The empty-filter error reproduced inside the harness built to end it** — class 22's shape,
   in the tool whose subject is that shape.

**I am reporting three and I have no denominator**, which by your own round-37 wording is not a
measured error rate. Take the three as recurrence, not as a rate.

## `DEFECT_CLASSES` 58 — new this range

*The harness arranged a condition it did not verify had been arranged.* Three instances in one
session from three unrelated mechanisms: R37-10's clock patch never reaching subprocesses; the
side-channel precondition file; the negative control's `exec` replacing `comm`. Distinguished
from class 50's empty-filter shape: there a result was produced and misread; here **no result was
ever produced**, and the pass is the absence of a measurement.

`NOT_CAUGHT`'s irreducible ambiguity is this class — please say whether naming it is genuinely
the most the driver can do, or whether a second observation (did the guard's condition hold under
the mutant at all?) would separate the two.

## What remains open — do not re-find these

Reaping never independently observed; R29-05 `Unreaped` UNCONSTRUCTED; `Scan`/`Unresolved` never
produced at root; the negative control's `Topology` awaits an accepted reproduction; `action.timeout`
enforced nowhere; the pending store has no cap; the campaign is unprivileged-only; the production
logind gate is blocked on a seated lane. Runs 22, 24, 25 were REFUSED and recorded as such.

## Defect-class partition (`docs/DEFECT_CLASSES.md`, now 58), per §13.9

**(a) Pre-foreclosed — do not spend budget re-hunting:**
10 (skip-as-pass — `scripts/test-count.sh`, no bare-total mode); 17 (defect propagated by copy —
the shared helpers); 22 (weaken blind spot — *the driver is the foreclosing primitive under
review; it is foreclosed only if it works*); 50 + its empty-filter extension (the driver never
greps — same caveat); 55 (producer/consumer format disagreement — the `verdict:` contract guard);
57 (a double answering for a collaborator it does not model — `fake_sh` now refuses).

**(b) Applicable and NOT foreclosed — concentrate here:**
**54** (a required check disconnected from acceptance — *the driver is disconnected on purpose;
this is the placement question above and the single most important item in this round*); **58**
(the harness arranged a condition it did not verify — `NOT_CAUGHT` reports this ambiguity rather
than resolving it); **49** (silence read as agreement — three `Reached` in a row); **16** (a
fixture damaging the operator's environment — the driver *writes to the working tree*, and its
`finally` is the only thing restoring it); **12** (reject the invalid class, not the value —
`MUTATION_INVALID` vs `NOT_CAUGHT` is that distinction).

## Verdict format

**APPROVE / REVISE / FAIL.** Every finding: ID (`D0A-R38-NN`), severity (P1 → P2 → P3), root
cause, impact, fix sketch, and — where you assert a false accept or a false green — **the
reproduction**, on temporary copies, with the subject's actual outcome retained rather than
inferred from a missing filtered line.

Verify claims against the live tree via the CLI (`git show <SHA>`, read the files); do not reason
from this prompt's summary of them. If the diff stat above disagrees with what you find, that is
a finding.

**Ground the driver's own claims by running it.** `python3 scripts/weaken-driver.test.py` is
self-contained (it builds a miniature subject and suite in a temp dir) and prints `17 guards
held`. A weaken of the driver that leaves all 17 green is the finding I most expect to exist.

---

## Postscript, because it bears on the restore-digest check above

Between `aa0d0e1` being committed and this prompt being written, **this machine lost power
mid-write and corrupted the repository**: four zero-byte loose objects (a commit, two trees, a
blob), the branch ref pointing at the dead commit, and the reflog's final entry a block of NULs.
The working tree survived byte-identical to `aa0d0e1` — including `runtime/src/wire.rs`,
`runtime/src/shutdown.rs`, `installer/pam/delphi-runtime` and `scripts/mutation-campaign.py`,
whose mtimes had moved, which is the campaign's and the driver's restore paths holding across a
crash-adjacent run. The only casualty was the first draft of this file, written 3ms before the
crash and recovered as zero bytes.

It is mentioned for one reason: **"the filesystem does not return success on a write that did not
land" is the assumption holding up the unreachability argument for the restore-digest check, and
this repository has a fresh counterexample to the general principle.** Weigh that when you judge
whether the check is unreachable or merely untested.
