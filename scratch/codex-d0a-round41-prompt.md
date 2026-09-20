# Codex adversarial review — D0-A round 41 (the inventory, the contract, and a P1 that went third)

This prompt is `scratch/codex-d0a-round41-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff c181eee..b58dc35`** — 6 commits. Pinned to a SHA, not `..HEAD` (D0A-R18-09).

```
 18 files changed, 2500 insertions(+), 37 deletions(-)
```

**Generated from the final pinned range, after the last commit in it** (D0A-R36-13).

Round 40's remediation, all six findings, plus the claim inventory your ruling required. Ten of
the eighteen files are ledger records; the subject is seven files and one new tool.

---

## Lead: the claim inventory, and whether its guard establishes completeness or only consistency

Your ruling was that a register note is quarantine, not disposition — inventory the affected
claims by commit and guard, then withdraw credit or link replacement evidence.

`docs/PROOF_CLAIM_INVENTORY.md` covers `aa0d0e1..3f5ac55` with three dispositions and nothing
else: `withdrawn`, `record:<id>`, `narrative`. **24 withdrawn, 0 with records, 4 narrative.** A
guard in `scripts/weaken-driver.test.py` joins the table to `git log`: every commit in the range
whose message matches `RED[-_ ]?PROV` must appear, every row must carry one of the three
dispositions, every cited record must resolve, and the table's stated counts must match its own
rows. Deleting a row fails it (RED-proven, record `ffa773f3b507a0a1`).

**The question I want ruled on: does that guard establish COMPLETENESS, or only CONSISTENCY?**

It enumerates commits whose messages *match a regex*. A claim phrased differently — "this test
is verified to bite", "proven to fail against the pre-fix code", "the weaken confirms it" — is
invisible to it, and the inventory would still report itself complete. **"The inventory is
complete" is a universal negative**, and this arc has been wrong about that shape repeatedly:
"every check weaken-proven" was false three times.

What I have is: every commit that *says* RED-proven is listed. What I claimed by implication is
that every proof claim is listed. Those are different statements and I did not distinguish them
when I wrote the file. If the honest disposition is that the guard proves consistency only, say
so and the file should say so too.

Two sub-questions I cannot answer from inside:

- Is there a formulation that would actually establish completeness, or is the right move to
  state the limit and stop claiming more?
- The covered range is FIXED (`aa0d0e1..3f5ac55`) and new commits fall outside it by design —
  the inventory is a historical disposition, the hook is the going-forward mechanism. Is that
  division sound, or does a fixed range become a place where claims quietly accumulate just
  past its endpoint?

---

## D0A-R40-02: attack the fix on the ground the finding was made

You found that gap from the ledger's own entries rather than from the schema — `a7c6e196` and
`7dc26d27` identical in instrument, subject, suite and expectation, carrying different verdicts,
with the deciding input recorded nowhere. That was the design test failing on its own first four
entries, and it is the sharpest finding this arc has produced against something I built.

**So the right question now is the same one, asked again, and it is answerable mechanically.**
`scripts/ledger-distinguishable.py` (new, tier 2, decides nothing) compares every pair of
records over the fields a reader would use to reconstruct an experiment — instrument, subject,
suite, expectation, execution, inputs — with timings excluded deliberately, because they always
differ and including them would make every pair look distinct.

Its answer on the live 14-record ledger:

```
  schema /1: 2    schema /2: 3    schema /3: 9
  INDISTINGUISHABLE: 7dc26d277ff82b0e (/2) vs a7c6e196e1d92f76 (/2) — DIFFERENT verdicts
  1 pair(s) share every recorded input.
```

The one collision is your pair, both pre-contract. All nine `/3` records are distinguishable.
**That is the honest shape of the fix — it works forward and does not repair history.**

**Run it yourself, and attack the comparison rather than the result.** Is "instrument, subject,
suite, expectation, execution, inputs" the right set? Excluding timings is defensible and is
also exactly how a comparison is made to pass. Does `digest_restored` belong on the outcome side
where I put it? And does distinguishability on nine records mean anything, or is it a property
that will only start failing once the ledger is large enough for it to matter?

I deliberately did **not** add a guard asserting no two records collide: on nine records it
passes near-vacuously, and the property it would defend — that every record binds its suite — is
already `REQUIRED` by the evidence contract. A second check that can only agree with the first
is not defence in depth. Rule on that too if you disagree.

---

## The P1 went third. Rule on whether the dependency was real or comfortable

D0A-R40-01 — the consumer gating a hash and a declared verdict, accepting
`{"id": ..., "verdict": "RED_PROVEN"}` with no experiment in it — was fixed **after** R40-02 and
R40-03, not first.

**The stated reasoning:** the validator has to be written against the field set it validates.
Writing it before R40-02/03 added `suite.sources`, `inputs.subject_original` and `execution`
meant writing it twice — which is the same "records from an unreviewed instrument may need
producing twice" argument you endorsed for deferring the reruns. And the delay was safe
*specifically* because credit was already suspended: nothing rested on the hook in the interim.

**The reason to distrust it:** that is precisely the shape of an argument that defers a P1. It
is internally coherent, it invokes a principle the reviewer already accepted, and it produces
the answer that postpones the hardest item. The operator endorsed it, which makes it the second
ordering this arc has ratified that served the work — and this arc's record on ratified
reasoning is two-for-two wrong (D0A-R37-11, and R38-06's two labelled exemptions).

**Was the dependency real?** A validator written against the pre-R40-02/03 fields would have
required `schema`, `id`, `verdict`, `expectation`, `instrument`, `subject`, `phases`,
`observations`, `limits` — and would have needed three paths added afterwards. That is an edit,
not a rewrite. I am no longer sure the argument survives being stated plainly, which is why it
is here rather than defended.

---

## The round's self-inflicted result: 0 → 2 → 4, and the middle state looked finished

D0A-R40-05 said `for rid in cited[:1]` still produced 8 passed, 0 failed — the loop's second
iteration was never load-bearing.

| state | guards failing under `cited[:1]` |
|---|---|
| as you found it | **0** |
| after my first fix (`8bb34a0`) | **2** |
| after auditing against your wording (`61ce08f`) | **4** |

The middle state existed, passed, and **would have been reported as complete.** I covered
*missing* and *wrong-verdict* in second position; your finding specified "missing, corrupted,
and wrong-verdict", and the hook actually distinguishes five refusal kinds because I added a
fifth in the same commit. Two of five were unproven at position two. That is the original
finding one level down: the iteration was load-bearing for some refusal kinds and not others,
which reads as covered.

**What found it was re-reading your wording against my implementation — a mechanism only in the
weak sense that I chose to do it.** No guard would have caught it; the suite was green at 16.
If there is a mechanism that makes "the fix covers what the finding specified" checkable rather
than conscientious, that is worth more than any of the six fixes in this range.

**And a second one, found by the gate refusing me.** `b58dc35`'s first draft named the two
verdict constants while *describing* a historical record. The hook's claim regex matched the
token and demanded a citation for a commit that proves nothing. **A gate that refuses legitimate
prose is what teaches people to reach for `--no-verify`** — named as the failure mode in the
hook's own docstring. The message was reworded awkwardly on purpose and the defect recorded
rather than worked around. Is fail-closed on a quoted verdict the right trade, or does it need
to distinguish an assertion from a citation of the token?

## The rest of the remediation

**R40-03** — `_loads` returns a structured observation (argv, exit, signal, timed_out,
launch_error, streams) carried on both validation phases; `TIMED_OUT` and `LAUNCH_FAILED` keep
the streams `_managed_run` had already collected, which they were dropping. **R40-04** — claims
are read from every line including comments (git's `default` cleanup keeps `#` lines under `-F`
and `-m`), citations only from non-comment lines, everything below the scissors line dropped;
verified through REAL commits, not hook invocations alone. **R40-06** — every hook-suite failure
reports its label to the side channel, which is what made R40-05's four cases provable *through
the driver* instead of by reading output.

**Two mechanisms caught their author inside this range, which is the only evidence I have that
they are load-bearing.** The R39-03 structural guard ("there is one way to start a process
here") fired on my own new `subprocess.run` calls for `git hash-object` — routed through
`_managed_run` rather than granted an exemption, because an absolute rule that yields the first
time it is inconvenient stops being one. And the inventory's completeness guard failed when I
annotated three rows *inside* the disposition cell, breaking the row regex so three
claim-bearing commits silently stopped counting as listed.

Guards: driver **103** (was 78), hook **18** (was 8), `lane-accept` **116**,
`mutation-campaign` **110**.

## What remains open — do not re-find these

The reruns are **still deferred**, now against a contract nobody has reviewed — that is this
round's subject, and the argument for deferring is unchanged and equally suspect. Reaping never
independently observed; R29-05 `Unreaped` UNCONSTRUCTED; `Scan`/`Unresolved` never produced at
root; the negative control's `Topology` awaits an accepted reproduction; `action.timeout`
enforced nowhere; the pending store has no cap; the campaign is unprivileged-only; the
production logind gate is blocked on a seated lane. Runs 22, 24, 25 REFUSED and recorded. The
`setsid` group escape is pinned, not closed. The isolated checkout is deferred with a reason.
Root delivery of `DELPHI_FAILURE_SNAPSHOT_DIR` is unverified — root is password-gated here.

## Defect-class partition (`docs/DEFECT_CLASSES.md`, 58), per §13.9

**(a) Pre-foreclosed — do not spend budget re-hunting:**
10 (skip-as-pass); 17 (defect propagated by copy — the consumer imports the producer's contract
and canonicalisation, holding no second copy); 25 (a copy is a different artifact — the hook
test reaches the real hook by symlink, and the fake repo now sets `core.hooksPath`, without
which its real-commit cases ran against no hook at all); 55 (producer/consumer format
disagreement — one `REQUIRED_PATHS`, imported).

**(b) Applicable and NOT foreclosed — concentrate here:**
**54** (a required check disconnected from acceptance — the hook gates the default path only;
`--no-verify` and per-clone `core.hooksPath` remain, and the false refusal above is a live
incentive to use them); **50** (the empty filter — "every cited record resolves" went VACUOUS
the moment no row cited one, which is why a counts guard was added; the distinguishability tool
has the same hazard at nine records); **22** (the fix inherits the class it was closing — the
0→2→4 progression is an instance); **58** (arranged but not verified arranged — the inventory
guard proves listing, which is not the same as proving the list is the right list); **16** (the
driver writes to the working tree and now also runs `git hash-object` against it).

## Verdict format

**APPROVE / REVISE / FAIL.** Every finding: ID (`D0A-R41-NN`), severity (P1 → P2 → P3), root
cause, impact, fix sketch, and — where you assert a false accept or a false green — **the
reproduction**, on temporary copies, with the subject's actual outcome retained rather than
inferred from a missing filtered line.

Verify against the live tree via the CLI (`git show <SHA>`, read the files); do not reason from
this prompt's summary. If the diff stat disagrees with what you find, that is a finding.

**Run all four.** `python3 scripts/weaken-driver.test.py` (103),
`.githooks/tests/commit-msg.test.sh` (18), `python3 scripts/lane-accept.test.py` (116),
`python3 scripts/mutation-campaign.test.py` (110); plus
`python3 scripts/ledger-distinguishable.py` for the ledger question above. **A weaken of any of
them that leaves the count unchanged is the finding I most expect** — it has been correct in
each of the last three rounds, and in this range it was correct twice about my own tests before
you saw them.
