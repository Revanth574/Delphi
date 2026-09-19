# Codex adversarial review — D0-A round 40 (the record, and whether settling authority first changed anything)

This prompt is `scratch/codex-d0a-round40-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff c0b3c27..3f5ac55`** — 2 commits. Pinned to a SHA, not `..HEAD` (D0A-R18-09).

```
 9 files changed, 1009 insertions(+), 8 deletions(-)
```

**Generated from the final pinned range, after the last commit in it** (D0A-R36-13).

The producer (`scripts/weaken-driver.py --record-dir`), the consumer
(`.githooks/commit-msg`), their guards, and four records in `scratch/weaken-records/`.

---

## Lead: this is the first thing here built with the authority question settled BEFORE the code, and I cannot tell from inside whether that changed anything

Every previous piece of this infrastructure was built first and had its authority discovered
afterwards. R23's runner, R36's acceptance verifier, and the weaken driver itself — and twice
the discovery was **a reviewer finding the thing could not check what it claimed**. R36's
verifier came back with three P1s that all said that.

This one was designed against a settled ruling: proof publication already has a consumer, so
the record is needed now; producer and consumer land together; the consumer refuses rather
than advises. Four things are meant to show that difference in the artifact rather than in the
narration:

| claim | what is in the tree |
|---|---|
| the consumer landed with the producer | one commit, `41300be`, both files |
| it refuses by default | `.githooks/commit-msg` exits non-zero; four distinguishable failures, four messages |
| **it refused its own introducing commit** | the first attempt claimed RED-proof with no trailer and was rejected; the commit landed only after two weakens were re-run to produce `7e0137da` and `af42ed54` |
| the limits travel with the artifact | every record carries a `limits` array; a citation cannot shed them |
| a field existed before it was needed | `subject.is_the_instrument_file` — both of the first two records have it **true**, because both are self-weakens |

**What I want attacked is the claim, not the list.** Is that structurally different from R36's
verifier, or is it the same thing better narrated? R36's verifier also looked sound when it
landed. **Neither the operator nor I can make that judgement from inside**, and you are the
only party who has twice been the one to find otherwise. If "authority settled first" produced
nothing an adversary can detect, the right finding is that it is a story, not a method.

The honest counter-evidence, offered rather than waited for: **the second commit in this range
exists because the first shipped a false claim in source.** `build_record` carried the comment
*"Retained whole and deciding nothing"* over a `diagnostics` field that retained nothing at
all. That is D0A-R38-06's shape — a written claim the code does not honour — committed twenty
minutes after the round that corrected R38-06, by the process that was supposed to be
different. I found it while writing this prompt, not by a mechanism.

---

## A ruling I want, because the operator and I AGREE — which is the reason to distrust the answer

Rounds 38 and 39's RED-proof claims are marked **UNVERIFIED** in
`docs/CONFORMANCE_REGISTER.md` — not demonstrated false, but uncheckable, because the
instrument that produced them held the defects those rounds were fixing (D0A-R39-01 could
certify an invalid mutant; R39-02/03 could let a process damage the target after the driver's
last observation). Roughly a dozen weaken claims are affected. None has a record.

**Is a register note a sufficient disposition for claims from a suspended instrument?** Or is
something stronger owed — re-running them, withdrawing them, or marking the commits themselves?

And specifically: **would re-running them NOW be worth anything?** The producer in this range
has been reviewed by nobody.

**The operator's position, stated so you can attack it rather than infer it:** do not re-run
until the producer has been reviewed, because records produced by an unreviewed instrument may
need producing twice — which is R39 invalidating R38's evidence, one level up, and the exact
recursion this range was built to stop.

**I agree with it, and that is precisely why it needs an adversary.** Two parties who both
want the same answer have produced a concurring view, not a checked one — and the answer we
concur on is also the one that defers work. This arc has twice ratified a position that read
as diligence and was wrong (D0A-R37-11, and R38-06's two labelled exemptions, which the
operator endorsed at the time).

---

## The round's self-inflicted result: the prediction was right and the test of it was wrong

The operator predicted, before the code, that a content-addressed ID would need the canonical
body to **exclude the ID itself**, and that a self-referential hash "that happens to work on
the first record and breaks on the second is the kind of thing that ships." The prediction was
correct and the implementation honoured it — `canonical_body` drops `id`, and removing that
drop is RED-proven.

**The failure was one level over, in the test of that property.** The hook's test minted two
records with **identical bodies**, so they hashed to the same ID. The case named "a message
citing TWO records" cited one record twice. And the assertion that would have caught it —
`[ "$GOOD" != "$SECOND" ] && echo OK && pass=$((pass+1))` — was a bare `&&` chain, so on
collision it **skipped silently** instead of failing. A guard that cannot fail is not a guard.

Both are fixed. Carry the shape into the review: **the mechanism was right, its test was not,
and the assertion that would have caught the test was constructed so it could not fail.**

A second instance in the same range, found by the driver rather than by me: proving the
truncation marker returned **`UNVERIFIABLE`**, because my guard read
`big["stdout_truncated_from"]` — which evaluates *before* `check` is called, so under the
weaken it raised `KeyError` and the suite died reporting no label. That is the honest verdict
for an assertion that cannot reach its own side channel, and it is the third kind of refusal
this tool has given me after `WRONG_GUARD` and `NOT_CAUGHT`. Its record (`a7c6e196`,
`UNVERIFIABLE`) is retained in the ledger, because records are written for every verdict.

---

## The question only you are positioned to answer: what can this record NOT make re-openable?

The design test for every field was: **could a reader who was not here reconstruct the
experiment well enough to DISAGREE with its verdict?** A field that does not serve that is
decoration; a missing field that does is a gap.

**You are the first person to actually be that reader.** Neither the operator nor I can
evaluate that test from inside — we both know what happened.

Take a record (`7dc26d277ff82b0e` is the most recent, schema `/2`) and try to disagree with it.
Candidate gaps I already suspect, offered so you can dismiss or sharpen them rather than
rediscover them:

- **The suite's identity is `argv`, not digests.** A reader re-running gets whatever
  `scripts/weaken-driver.test.py` is *now*, not what it was. The instrument is digest-pinned;
  its suite is not.
- **The mutant bytes are not stored** — only `anchor`, `replacement`, and three digests. That
  reconstructs only if the reader can obtain the original bytes, which for an untracked
  temporary target they cannot.
- **The side-channel report files live in `/tmp`** and are gone. The record keeps each
  invocation's report *path* (which is the D0A-R38-01 evidence — the paths differ per
  invocation) but not its contents beyond the parsed labels.
- **No environment**: interpreter version, PATH, platform. Deliberate — but "deliberate" was
  also the word for the diagnostics comment above.
- **`observations` is a whitelist of keys copied from the evidence dict.** A verdict derived
  from something outside that whitelist would be unrecorded, and nothing checks the two lists
  against each other.

That last one is the one I would attack first if I were you.

## The mechanism, briefly

`--record-dir` writes one JSON record per run, whatever the verdict. `id` = first 16 hex of
sha256 over the canonical body with `id` removed. `phases[]` carries `started_at`,
`duration_s`, outcome, report path, and the subject's retained streams with an announced cap.
`expectation.registered_at` is 0.0 — before any invocation — which is what makes a mis-aimed
weaken visible as `WRONG_GUARD` rather than as a red suite.

`.githooks/commit-msg` refuses: a RED-proof claim with no `weaken-record:` trailer; a cited id
that is neither staged nor committed; a record whose bytes do not hash to its own id; a record
whose verdict is not `RED_PROVEN`. It **imports** the producer's canonicalisation — a second
copy is `DEFECT_CLASSES` 55 by construction.

**Stated limits, so a green commit is not read as more than it is:** `--no-verify` bypasses the
hook and `core.hooksPath` is per-clone opt-in, so this gates the default path and not a
determined author; content-addressing prevents post-hoc *editing* of a record, not
*fabrication* of one; and the hook checks that a claim is re-openable, never that it is true.
Repository-wide enforcement is CI — a later placement, not this one.

Guards: hook **8** (real hook via symlink, `DEFECT_CLASSES` 25), driver **78** (was 59),
`lane-accept` **116**, `mutation-campaign` **110**.

## Why the record exists at all

`DEFECT_CLASSES` 22's longest-running instance: validity established by **proxy**, three rounds
running — by text (R36-06), by compilation (R38-03), by an import that reads `__pycache__`
(R39-01). **A reviewer caught each one. Nobody here caught any of them.** An instrument's own
claims about itself are exactly what has to be independently re-openable, and rounds 38 and 39
were this driver making claims about this driver.

## What remains open — do not re-find these

Reaping never independently observed; R29-05 `Unreaped` UNCONSTRUCTED; `Scan`/`Unresolved`
never produced at root; the negative control's `Topology` awaits an accepted reproduction;
`action.timeout` enforced nowhere; the pending store has no cap; the campaign is
unprivileged-only; the production logind gate is blocked on a seated lane. Runs 22, 24, 25 were
REFUSED and recorded. The `setsid` group escape is pinned, not closed. The isolated checkout is
deferred with a stated reason. Root delivery of `DELPHI_FAILURE_SNAPSHOT_DIR` is unverified —
root is password-gated here.

## Defect-class partition (`docs/DEFECT_CLASSES.md`, 58), per §13.9

**(a) Pre-foreclosed — do not spend budget re-hunting:**
10 (skip-as-pass — `scripts/test-count.sh`); 17 (defect propagated by copy — the consumer
imports the producer's canonicalisation rather than holding a second copy); 25 (a copy is a
different artifact — the hook test reaches the real hook by symlink); 50 + the empty-filter
extension (the driver never greps — conditional on the driver working).

**(b) Applicable and NOT foreclosed — concentrate here:**
**54** (a required check disconnected from acceptance — *the whole point of this range; the
question is whether the connection is real or ceremonial*); **22** (the fix inherits the class
it was closing — the second commit here is an instance, and the class's own longest instance
took three rounds); **55** (producer/consumer format disagreement — mitigated by import, not
closed: the hook still decides which FIELDS matter); **16** (a fixture damaging the operator's
environment — the driver writes to the working tree and the record is written from the same
process); **58** (arranged but not verified arranged — `observations` is a whitelist nothing
cross-checks).

## Verdict format

**APPROVE / REVISE / FAIL.** Every finding: ID (`D0A-R40-NN`), severity (P1 → P2 → P3), root
cause, impact, fix sketch, and — where you assert a false accept or a false green — **the
reproduction**, on temporary copies, with the subject's actual outcome retained rather than
inferred from a missing filtered line.

Verify against the live tree via the CLI (`git show <SHA>`, read the files); do not reason from
this prompt's summary. If the diff stat disagrees with what you find, that is a finding.

**Run both tools.** `python3 scripts/weaken-driver.test.py` (78) and
`.githooks/tests/commit-msg.test.sh` (8) are self-contained. **A weaken of either that leaves
the count unchanged is the finding I most expect** — that expectation has been correct in each
of the last two rounds, and in this range it was correct about my own test before you saw it.
