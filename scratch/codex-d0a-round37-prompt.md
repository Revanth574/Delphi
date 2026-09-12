# Codex adversarial review — D0-A round 37 (the merge gate)

This prompt is `scratch/codex-d0a-round37-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff 98a9802..b4e0f74`** — 10 commits. Pinned to a SHA, not `..HEAD` (D0A-R18-09).

```
 21 files changed, 1034 insertions(+), 88 deletions(-)
```

**Generated from the final pinned range, after the last commit in it.** Last round's stat was
not, and disagreed by 13 insertions and 43 deletions — D0A-R36-13, the drift check catching its
author.

The round-36 remediation: 3×P1, 8×P2, 2×P3, all thirteen findings.

---

## Lead: the one accepted run was accepted by a gate that could not check what it claimed, via a path the procedure did not describe

Both halves were found in one round, and both are about the mechanism I recommended building
and then cited for three rounds as the thing that made acceptance real.

**The gate could not check what it claimed (R36-01/02/03).** Against run 23's REAL artifacts,
every one of these returned ACCEPTED before the fix:

| mutation | why it certified |
|---|---|
| `rebuild.log` replaced with `error: could not compile` | the file only had to EXIST; identical hashes are equally consistent with a rebuild that never ran |
| `root-identities.txt` emptied | the printed zeroes in `membership.txt` were trusted — "0 identities each side, zero either way" |
| `root-run.log` emptied, mtime preserved | the transcript was read only for its timestamp |
| 17 copies of ONE producer's status line | producers were COUNTED, never identified |
| the control's verdict followed by `FAILED. 0 passed` | the verdict prints BEFORE the survivor, deadline and shutdown assertions |

**The procedure could not produce what it certified (R36-08).** The only acceptance invocation
sat inside §4b, before Part B, and Part B named only the positive control. An operator
following the document in order was refused for an artifact it never told them to produce and
reached the end with no later invocation.

### BE PRECISE ABOUT WHAT SURVIVES, because the two claims are different

**Run 23 still ACCEPTS under every new check** — membership re-derived from its transcript
identity by identity (230), 17 distinct producers matching the hash manifest, the control
completed and passed. **The RUN was fine. The CERTIFICATION was not**, and the certification is
what had been carrying weight in three rounds of prompts, in the register, and in PROGRESS.

**What I want attacked: is that distinction doing honest work, or is it the comfortable
reading?** A gate that would have certified a fabricated run, applied to a run that happens to
be genuine, produces a true verdict by luck. The claim "run 23 was a good run" is now supported
by checks that did not exist when it was made.

---

## The remediation's own error RATE — three, in a round about a verifier that could not verify

Stated as a rate rather than as three anecdotes, because the rate is the finding:

1. **A false RED-proof claim, committed** (`0fdabcc`, withdrawn at `2de53b8`). The weaken did
   not bite; the guard refused under BOTH versions with the same message — PASS/PASS.
2. **An invalid weaken read as "no bite"** (`9148fc7`). The mutation referenced an unimported
   name, so the suite died on a `NameError` and produced no `GUARD FAILED` line.
3. **The `b51bd8f` bisect misread** from the previous session, same shape.

**All three are the same error: reading a filter's empty output as a result.** In a round whose
subject was a verifier that could not verify, the person fixing it made three claims from the
absence of a string. That is the same failure at two levels in one session, and it is why
class 50 was extended rather than a twin minted — a filter DELETING a signal and a filter's
SILENCE read as a signal are one misplaced trust.

**Is "read the subject's own summary" a sufficient foreclosure, or does this want a mechanism?**
I do not have one. Every instance was caught by a human re-reading, which is exactly the
property this project keeps finding insufficient.

---

## R36-06: is closing the channel RIGHT, or an over-rotation?

Three rounds narrowed it — section parser, line-anchoring, "stderr is the producer's" — and
each left a hole. The position now is strong and deliberate: **stdout and stderr are INPUTS
FROM THE SUBJECT UNDER TEST, and classifying on their text is trusting a self-report.** Cause
comes only from the build invocation's exit status, death by signal, a side-channel file named
per invocation, and the campaign's own free-space measurement.

**I checked what closing it would delete rather than assuming.** Disk exhaustion reached the
classifier only through text, so it is now a measurement the campaign takes itself — placed
ONLY in the ambiguous branch (nonzero exit, tests reported, no named failure), because gating
every nonzero exit on free space would reclassify real detections as INFRASTRUCTURE whenever
the disk was tight, and discarding a detection is the worse direction.

**But "treat all subject output as untrusted" is a strong position and I hold it after being
wrong three times about narrower ones.** Say whether it discards signal that matters in a case
neither of us has constructed. Candidates I can name and have not resolved: a linker OOM that
kills the compiler rather than the test process; a panic in a build script; an ICE. Each
currently lands as `result_lines == 0` → INFRASTRUCTURE by structure — which may be right, or
may be collapsing distinctions a reader needs.

---

## The owed reproduction is REACHABLE for the first time

The register records the negative control's `Topology` as an observation from a REFUSED run,
with accepted reproduction owed. **No prior run could have discharged that**, because until
R36-08 the procedure could not produce an accepted run at all: acceptance ran before the
controls existed, and the negative control was never invoked.

§4c now invokes BOTH controls with their exit statuses retained; §4d invokes acceptance last;
and a guard asserts the procedure writes every artifact the gate reads, before acceptance is
invoked. **Run 26 is the first run that can be accepted through the documented path**, and that
is what it exists to do.

**Attack the contract guard**, because it is new and it now stands between the procedure and
every future acceptance: it extracts required inputs from `lane-accept.py` by pattern
(`_read(d, "…")`, `d / "…"`, its globs). **A pattern-extracted contract is a grep standing in
for a specification** — the class this project has been wrong about most often. What does it
miss?

## The rest of the round-36 remediation

| finding | fix | attack |
|---|---|---|
| **R36-04** | a distinct `run-start.txt`, written once before the first producer | the transcript's mtime is its LAST write, so a mid-run rebuild read as "freshness proven before the run". Is a start event enough, or does freshness need to bracket the whole run? |
| **R36-05** | every capture created `O_EXCL`, never truncating | check-then-act plus one-second names destroyed the loser silently. Verified with a frozen clock: three same-second captures, three files |
| **R36-07** | `--exact`; the transcript must NAME the test; `ok. 0 passed` and `ignored` refused; summary must agree with exit status | a real libtest binary reporting `running 0 tests` scored PASS, so a revision NOT CONTAINING the test looked clean |
| **R36-09** | one capture shape at THREE moments — before, at a producer failure, after | a single snapshot cannot show what ACCUMULATED; every command's status is reported, because `loginctl \| wc -l` returns 0 both for "none" and for "failed" |
| **R36-10/12/13** | register scoped to the observer actually exercised; `DEATH_GRACE` calibration restored; diff stat regenerated | three false claims in cited records |

**R36-11 was a finding about MY claim and I checked its arithmetic before accepting it.** "Every
check weaken-proven" was false — but of the two ordering checks named, the freshness-before-run
one IS covered; only membership-after-run was not. The finding stands, one of its three
instances does not.

## What remains open

**Reaping is NEVER independently observed.** R29-05's `Unreaped` is UNCONSTRUCTED. `r4_03` is
unreproducible after a reboot cleared the conditions, and instrumented rather than diagnosed —
five hypotheses eliminated under conditions that differed from the failing ones. `Scan` and
`Unresolved` have never been produced at root. The negative control's `Topology` awaits accepted
reproduction. `action.timeout` enforced nowhere (R9-04); the pending store has no cap; the
mutation campaign is unprivileged-only; the production logind gate is blocked on a seated lane.

## Defect-class partition (`docs/DEFECT_CLASSES.md`, now 57), per §13.9

**(a) Pre-foreclosed:** **10** (a skip reports `ok`); **43**; **44**.

**(b) Applicable and NOT foreclosed:**

- **57** (a double answering for a collaborator it does not model) — **new**; its foreclosure is
  a discipline, not a mechanism.
- **55** (producer/consumer format) — the contract guard is its first FORECLOSURE rather than
  its third instance. Judge whether a pattern-extracted contract earns that word.
- **50** (extended: a filter's silence read as a result) — three instances this session, all
  mine, all in the remediation.
- **54** (a required check disconnected from acceptance) — R36-08 is this class at the level of
  the procedure that gates the gate.
- **45** (the totality claim) — this range asserts "every check weaken-proven INDIVIDUALLY this
  time", "run 23 still accepts under every new check", "nothing unique was lost" was itself a
  45 corrected this round. **Audit all three.**
- **41** (wrong altitude) — the contract guard is a grep standing in for a specification.

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Each finding: **ID** (`D0A-R37-nn`), **severity**, **root
cause**, **impact**, **fix sketch**.

**Most valuable returns:** (1) whether "the RUN was fine, the CERTIFICATION was not" is honest
or comfortable; (2) **whether closing the text channel discards signal that matters**, in a case
neither of us has constructed; (3) a defect in the CONTRACT GUARD, which is new, is a pattern
standing in for a specification, and now gates every future acceptance; (4) a mechanism for the
empty-filter error, which has produced three instances and is currently foreclosed only by
remembering.
