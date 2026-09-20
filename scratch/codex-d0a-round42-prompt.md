# Codex adversarial review — D0-A round 42 (what would end the suspension, asked before deferring again)

This prompt is `scratch/codex-d0a-round42-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff 091ef0e..b071a2c`** — 6 commits. Pinned to a SHA, not `..HEAD` (D0A-R18-09).

```
 21 files changed, 2950 insertions(+), 95 deletions(-)
```

**Generated from the final pinned range, after the last commit in it** (D0A-R36-13).

Round 41's remediation, all eight findings. Thirteen of the twenty-one files are ledger
records; the subject is eight files.

---

## Lead: "wait until it has been reviewed" was never the criterion, and I should have noticed that two rounds ago

Authoritative proof credit has been suspended since D0A-R39. The stated reason for deferring
the re-runs, twice, was that records from an unreviewed instrument might need producing twice.

**That criterion has now been met and it changed nothing.** The empirical record:

| round | the gate's state | what the next round found in it |
|---|---|---|
| R39 | no gate; the driver decided informally | R40-01 (P1): the consumer required a hash and a declared verdict — `{"id": …, "verdict": "RED_PROVEN"}` was accepted |
| R40 | gate built, producer + consumer | R41-01 (P1): the contract required CONTAINERS, not evidence — records with no invocation results at all were accepted |
| R41 | contract checks the observations a claim rests on | **unknown — you are the next round** |

So the real criterion in operation has been **"wait until it stops producing P1s"**, which is a
different bar and possibly an unreachable one. Two rounds, two P1s in the gate itself, each
found only by the round after the one that built it.

**The question, asked in advance rather than deferred a third time: is there a criterion short
of zero-findings that makes a record trustworthy enough to cite?**

Candidates, including one of mine so you can attack it rather than infer it:

- **Zero findings in a round against the gate.** Clean, possibly unreachable, and it makes the
  suspension a function of review effort rather than of the artifact.
- **No P1s in the gate's decisions for N consecutive rounds**, where coverage findings do not
  count. Needs a principled line between "the gate decided wrongly" and "the gate's tests are
  thin", and R41-01 sat exactly on it.
- **Versioned credit instead of binary suspension** — my proposal, and the one I trust least
  because it is convenient. Records already carry `schema`; credit would be explicitly relative
  ("accepted under the contract as of `<sha>`") rather than absolute, so citation never claims
  more than the gate of its day. That converts an unreachable bar into a stated one. It also
  makes every claim permanently provisional, which may be honest or may be a way of never
  answering.
- **The suspension holds until the instrument stops changing.** Defensible, and it means the
  work of improving the gate indefinitely postpones the thing the gate exists for.

**Why I am asking you rather than deciding:** the operator and I have now concurred on
deferring twice. Two parties who both benefit from the answer have produced a concurring view,
not a checked one — and the last time this arc ratified that shape, D0A-R41's ruling was that
the reasoning had been "an implementation convenience, not a necessary dependency."

---

## A fixture that could not reach the code it tested, and read as coverage because it was red

The refusal-kind × citation-position matrix (D0A-R41-04) worked on its first run — it showed
two failures for the unreadable-JSON kind, exactly the gap the finding named.

**Both failed for a reason unrelated to malformed JSON.** My synthetic record id was 14 hex,
not 16, so it never matched the citation regex; the hook never opened the file; the *other*,
valid citation discharged the claim. The cases were red because the fixture could not reach the
code under test.

It looked like the finding reproducing. Red is not evidence any more than green is, and a
failing test that fails for the wrong reason is the mirror of `DEFECT_CLASSES` 50 — I have
spent this arc checking that green means what it says and did not apply the same question to a
red.

**What I want: the same question asked of the rest.** Are there guards in these suites that are
GREEN for the wrong reason, or cases that would be red for the wrong reason if they fired?
`scripts/weaken-driver.test.py` (141), `.githooks/tests/commit-msg.test.sh` (25),
`scripts/lane-accept.test.py` (116), `scripts/mutation-campaign.test.py` (110). The two I know
of are recorded — D0A-R38-08's multiplicity check and D0A-R41-01's sha256 half, both of which
came back `NOT_CAUGHT` because the fixture failed two predicates at once.

---

## A `NOT_CAUGHT` that is not `DEFECT_CLASSES` 58, and may want its own number

Proving the guard "every record cited as a disposition satisfies the evidence contract", I
aimed the weaken at that check's own code — disabling it. The driver returned `NOT_CAUGHT`, and
it was right:

> **A weaken that REMOVES a check cannot discriminate a guard whose failure requires that check
> to FIRE.** Disabling it makes the guard pass vacuously rather than fail. The discriminating
> weaken has to make the check *fire and be wrong* — here, pointing a `record:` row at a
> pre-contract record.

**Is that its own class, or a face of one the corpus has?** It is NOT class 58 — that is "the
harness arranged a condition it did not verify had been arranged", and here the condition was
arranged correctly and the *observer* was removed instead. It is adjacent to class 50 (a filter
that can silently invert a mechanism) and to class 22, but I do not think it is either.

If it is a class, it has a usable rule attached: **when a guard asserts that a check FOUND
something, weaken the thing the check looks at — not the check.** I would rather you rule on
whether that is new than mint number 59 on my own judgement, since the corpus's value is that
its classes are distinct.

---

## The round's methodological result, and it is narrower than I expected

Round 41's prompt asked whether "the fix covers what the finding specified" could be made
checkable rather than conscientious. Your answer was **an independently specified acceptance
matrix with a discriminating weaken for each obligation, where a matrix copied from the
implementation reproduces its omissions.**

Applied literally, with the axes' provenance written into the test file because that is what
goes invisible afterwards:

- **the KINDS come from the finding's own wording** — D0A-R41-04 names four kinds as covered
  and "unreadable JSON" as omitted. Five. Read from the finding, never from the hook.
- **the POSITIONS come from the loop's structure** — `for rid in cited` has a first iteration
  and a subsequent one. Two. Taking this axis from the finding would be impossible: a finding
  does not know a loop's shape.

The measurement across three attempts at one finding:

| attempt | guards failing under `for rid in cited[:1]` |
|---|---|
| as D0A-R40-05 found it | **0** |
| my first fix | **2** |
| after re-reading the finding's wording | **4** |
| the generated matrix | **5** — the entire second-position column |

**Only the last came from reading the finding's words rather than my own code**, and the
difference between 4 and 5 is exactly the omission a code-derived matrix reproduces.

It is a discipline about **where the matrix comes from**, not a tool — narrower than I expected
and, if it holds, more portable. **Attack it on that ground:** is provenance-splitting a real
method or a description of one lucky application? A finding's wording is prose, and reading
axes out of prose is the thing this arc distrusts everywhere else.

## The rest of the remediation

**R41-01** — the contract checks observations, not containers: each of baseline / weakened /
restored present and **exited**, controls green and the weakened one not; the weakened
invocation's OWN report naming the expected guard, because `observations.failing_guards` is a
summary and a summary is not the observation it summarises; per-phase process evidence; and
source references carrying a digest AND something to resolve it.

**R41-02** — closed by removing the collaborator. `git hash-object` applies filters: measured,
the blob content hashed to `9e26bf36…` against a recorded `eccc3933…`, and a clean filter
rewrote the target during the call, *after* restoration was verified. The blob id is now
computed from the bytes in hand, so no filter runs and the id matches by construction. **The
two exposure levels are kept separate** — eol normalisation LIVE (this repo's `.gitattributes`
sets it on the driver itself), arbitrary clean-filter execution LATENT (none configured).
`DEFECT_CLASSES` 27 gains its second instance and its first *across rounds*: this silently
withdrew D0A-R38-06's byte-exactness guarantee, two rounds later, in the same file.

**R41-03** — measured, not reasoned: git truncates at scissors ONLY when the message is edited,
so `--cleanup=scissors` under `-F` keeps it too. **The guard that asserted the hole is
inverted** — the R40-04 fix for a cleanup mismatch had encoded a new one as an invariant, which
defends the defect against the next reader. An explicit format replaces a regex pretending to
understand assertions: a backticked token is narrative, an unbackticked one asserts and must
cite.

**R41-05/06/08** — the inventory states what its guard establishes (regex-selected commit
coverage and internal consistency; **not** claim-level completeness, since deleting one of
`466c97f`'s two rows and decrementing the total passes); the transition gap is closed by
disposing of it rather than moving the line; the register points at the counts instead of
contradicting them. Rows were **generated from each record's own `expectation.guard`**.
**R41-07** — the comparator sees validation configuration and keeps ignoring results, with
thirteen sensitivity guards instead of a near-vacuous no-collision assertion.

Guards: driver **141** (was 103), hook **25** (was 18), `lane-accept` **116**,
`mutation-campaign` **110**.

## What remains open — do not re-find these

The re-runs, still deferred — the lead above is about that. Reaping never independently
observed; R29-05 `Unreaped` UNCONSTRUCTED; `Scan`/`Unresolved` never produced at root; the
negative control's `Topology` awaits an accepted reproduction; `action.timeout` enforced
nowhere; the pending store has no cap; the campaign is unprivileged-only; the production logind
gate is blocked on a seated lane. Runs 22, 24, 25 REFUSED and recorded. The `setsid` group
escape is pinned, not closed. The isolated checkout is deferred with a stated reason. Root
delivery of `DELPHI_FAILURE_SNAPSHOT_DIR` is unverified — root is password-gated here. The
ledger's one remaining collision is the historical `/2` pair; all 21 `/3` records are
distinguishable.

## Defect-class partition (`docs/DEFECT_CLASSES.md`, 58), per §13.9

**(a) Pre-foreclosed — do not spend budget re-hunting:**
10 (skip-as-pass); 17 (defect propagated by copy — one `REQUIRED_PATHS`, imported by the
consumer); 25 (a copy is a different artifact — the hook test reaches the real hook by symlink,
and its fake repo sets `core.hooksPath`); 55 (producer/consumer format disagreement — one
canonicalisation, one contract).

**(b) Applicable and NOT foreclosed — concentrate here:**
**27** (two independently-correct fixes whose interaction is unsound — a fresh instance this
range, and the seam was two rounds wide); **22** (the fix inherits the class it was closing —
R41-03's inverted guard is an instance that *certified* its inheritance); **50** (the filter is
not the mechanism — and its mirror, a red that is red for the wrong reason, is the 14-hex
fixture above); **58** (arranged but not verified arranged — distinguish it from the
`NOT_CAUGHT` shape above, which may want its own number); **54** (a required check disconnected
from acceptance — the hook still gates the default path only; `--no-verify` and per-clone
`core.hooksPath` remain); **16** (the driver writes to the working tree, and now computes blob
ids over it).

## Verdict format

**APPROVE / REVISE / FAIL.** Every finding: ID (`D0A-R42-NN`), severity (P1 → P2 → P3), root
cause, impact, fix sketch, and — where you assert a false accept or a false green — **the
reproduction**, on temporary copies, with the subject's actual outcome retained rather than
inferred from a missing filtered line.

Verify against the live tree via the CLI (`git show <SHA>`, read the files); do not reason from
this prompt's summary. If the diff stat disagrees with what you find, that is a finding.

**Run all five.** `python3 scripts/weaken-driver.test.py` (141),
`.githooks/tests/commit-msg.test.sh` (25), `python3 scripts/lane-accept.test.py` (116),
`python3 scripts/mutation-campaign.test.py` (110), and
`python3 scripts/ledger-distinguishable.py`. **A weaken of any of them that leaves the count
unchanged is the finding I most expect** — correct in each of the last four rounds, and in this
range correct three times about my own tests before you saw them.
