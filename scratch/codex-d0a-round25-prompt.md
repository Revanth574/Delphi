# Codex adversarial review — D0-A round 25 (the merge gate)

This prompt is `scratch/codex-d0a-round25-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff cfb8ba3..40d7fb7`** — five commits. Pinned to a SHA, not `..HEAD`, because
committing this prompt would move the reference and invalidate the stat below (D0A-R18-09).

```
 9 files changed, 302 insertions(+), 46 deletions(-)
```

One of those files is the round-24 prompt itself (112 of the 302 insertions). **The reviewable
surface is the other eight files, and it is the smallest since round 20.** There is no new
infrastructure in this range — no new script, no new gate, no new mechanism. It is seven
corrections, one environment note, and one lane run.

---

## Lead: four rounds without a product finding. Convergence, or scope exhaustion?

This is handed over for the same reason round 20's question was, and it is the same shape of
conflict: **I am the party that benefits from the answer being "converged".**

### The trace, stated so you can falsify it rather than take it

| round | what it found | product behaviour changed? |
|---|---|---|
| **21** | R21-01 (gate ordering vs preview send), R21-03 (hardcoded schema version), R21-05 (two limits that never had to agree) | **YES** — `d6fb698`, `298d4db` |
| **22** | eight findings; the remediation **produced `scripts/lane-run.sh`** | no |
| **23** | thirteen findings; **eight P1s, all against the runner** | no |
| **24** | seven findings; confirmed the revert, held the gate **closed** on record accuracy | no |

**The pinned claim, which you should check rather than accept: `298d4db` is the last commit on
this branch that changed executable product behaviour.** I verified it by diffing
`runtime/src/**` across every commit since and excluding comment-only lines. The one apparent
counter-example is `af46083` (round 22's remediation), which shows **9 non-comment changed
lines** in `runtime/src/service.rs` — all of them inside `#[cfg(test)]`, R22-07's replacement of
`unwrap_or(0)` with an `Interrupted`-retrying loop. **If that exclusion is wrong, the whole
trace is wrong**, so check it first.

### The two readings, both available

**Convergence.** The product surface was swept in rounds 16–21, the defects were found and
fixed, and the review correctly moved on to the records — which is where the remaining defects
actually were, and round 24 proves it by finding a real one (run 12 credited with hygiene it
never performed).

**Scope exhaustion.** The review drifted toward what is *cheap to check* — prose, records,
provenance, commit ordering — because the product surface is expensive to check with the tools
available, and the absence of product findings is evidence about the **method**, not about the
**code**. On this reading, rounds 22–24 reviewed verification infrastructure reviewing
verification infrastructure, and a product defect that this method structurally cannot reach
would look exactly like the last four rounds.

### What would discriminate them — and this is the actual ask

Do not answer this from the finding counts; the counts are consistent with both. **The
discriminating question is whether there is a region of `runtime/src/**` that the last four
rounds never looked at.** If the product surface is genuinely covered, name what covers it. If
there is an unexamined region, that is the finding, and it is worth more than everything else
in this range.

**A measurement, because I would rather hand you a number than an impression.** Across the
round-21 through round-24 prompts, I counted how many times each `runtime/src/**` file was named
by filename:

```
token.rs 0   store.rs 0   channel.rs 0   anchor.rs 0   canonicalize.rs 0
execute.rs 0   service.rs 0   action.rs 0   sandbox.rs 1
```

**One product source file named by filename, once, in four rounds of prompts.** That is
evidence for the scope-exhaustion reading and I am reporting it against my own interest.

**The honest qualifier, which cuts the other way: a prompt not naming a file is not proof a
reviewer did not read it.** You have the CLI and this project's prompts tell you to inspect the
live tree rather than trust the supplied diff, so prior rounds may well have covered files no
prompt mentioned. **Which means the number above bounds what I steered you toward, not what you
looked at — and you are the only party who can say which of those two it actually measures.**

So: `token.rs`'s minting and lifetime; `store.rs`'s persistence and failure modes;
`channel.rs`'s framing under a partial write; `anchor.rs`; and the interaction between
`execute.rs`'s validation choke point and `canonicalize.rs`'s `validate_env_delta` **when a
field passes one and not the other**. A handover that only offers the question is weaker than
one that also offers where to start.

**The disclosure, plainly: the reading that says "stop" is the one I would prefer to be true —
which is exactly why it should not rest on my judgement.** A finding that the branch is not
converged is more valuable to me than an APPROVE, and if the honest answer is "you have run out
of things you know how to look at, not out of defects", say that.

---

## Two specific things, each an inference I do not trust myself to make

### 1. The commit-order result under convention

D0A-R22-01 is **reopened**: the expectation-before-run ordering was enforced by
`scripts/lane-run.sh` for exactly one run, and the revert removed the enforcement. Run 13 was
the first run under **convention alone** — a human following STEP −1 of
`scratch/lane-run-7-procedure.md`.

**It held.** `feabc56` contains `.githooks/runtime-test-count-baseline.expected` and nothing
else; `40d7fb7` carries the measurement; `git log` on the two files is the only evidence that
the prediction preceded the measurement.

My stated inference: **one clean instance shows the failure is not guaranteed — not that
convention suffices.**

**Is that the right inference, or is one run being asked to carry more than it can?** Press
specifically on: does `git log` ordering on two files actually establish precedence, or only
correlate with it (a file can be written long before it is committed)? Is "the failure is not
guaranteed" a claim worth recording at all, or is it a null result dressed as evidence? And is
recording it in the register a way of banking credit for a mechanism that was removed?

### 2. The class-48 predicate catching its own class's recurrence

Class 48 is *the fix scoped to the named instance*. Before writing run 13's record I ran its
predicate mechanically over the tree, looking for files naming a current lane run. It found
four. **After I fixed the first reference in `PROGRESS.md`, re-running found a second one in the
same file.**

That is the **fourth** recurrence of class 48 in this arc, and the **first** caught before the
commit rather than by the next round.

**Is a predicate that catches its own class's recurrence evidence the class is closing, or
evidence it is still live and merely being caught earlier?** I can argue both and cannot
adjudicate: catching it earlier is real improvement, *and* the fact that there was a second site
to catch means the first fix was still scoped to the named instance — which is the class itself,
occurring inside the procedure written to prevent it.

Also worth attacking: is the predicate itself wrong-altitude (class 41)? Three grep sweeps in
this arc returned confident **negatives**, and a false negative closes the question silently.
Two `run 12` mentions remain in `PROGRESS.md`; both are deliberately historical (what run 13
supersedes; which run went through the reverted runner). **Judge whether they are actually
historical or whether I have exempted two instances by calling them so.**

---

## The seven round-24 fixes

| finding | fix | attack |
|---|---|---|
| **R24-01** (P1) | run 13, a single full-hygiene run, replacing the run-11/run-12 table | the evidence was split because run 11 was swapped for run 12 without recomputing which dimensions survived. Does one run genuinely close it, or does it just make the split invisible? |
| **R24-07** | the terminus claim narrowed to a pinned start (`298d4db`) | this is the trace in the Lead. If the exclusion of `af46083`'s test-only lines is wrong, this fix restates a false claim more precisely |
| **R24-05** | R23-11's contradiction six lines below its own correction | class 48 inside a fix for a provenance error. Is the surrounding text now consistent, or was this fix also scoped to the named lines? |
| **R24-03** | the module flow's AUDIT step removed; local comments renumbered 1–7 | `audit` appears nowhere in the module and `RuntimeAuditEntry::record` has no production caller. Check the transcription against `serve_one_action` line by line — **three prior attempts described intent instead** |
| **R24-04** | `reached_the_anchor_rejects_an_unrelated_permission_error` | R23-12's discrimination existed only in a commit message. Weaken-proven: under the weaken the NEW test fails while both existing integration legs stay green. Is the encoded predicate the right one, or does it admit a fourth error shape? |
| **R24-06** | PROGRESS's status block updated atomically | it was internally inconsistent — August 26 date, run-7 figures, rounds 16–17 as latest. Atomic rather than by-phrase because by-phrase is the sweep error R23-06 was supposed to have fixed. Is it consistent **now**? |
| **R24-02** | the runbook retitled current + STEP −1 + R22-01 recorded REOPENED | REOPENED is a **fourth** state in the open-items partition. Round 22 falsified that partition once already |

## The environment note (`10da6f7`)

Round 24's reviewer measured **EXECUTED 128 / SKIPPED 53 / reported 181** against this tree,
with three shell suites failing at `unshare … Operation not permitted`. I recorded that as a
**lane difference, not a discrepancy**: `reported 181` agrees exactly, and the extra 28 skips
are the userns/bwrap-gated tests.

**Attack the explanation, not the arithmetic.** Is "your lane lacks user namespaces" the actual
cause, or a plausible story that fits? Would a genuine regression producing 28 additional skips
be distinguishable from this, and by what? Note D0A-R15-04 measured 115/46 on an identical tree
in a restricted container — one prior instance is a precedent, not a law.

## Lane evidence — run 13

**`EXECUTED 177 / SKIPPED 5 / reported 182`**, rc 0, 0 failures, 17/17 producers exited 0.
Full hygiene, each check with its own captured output in
`.githooks/runtime-test-count-baseline.root`: helper digest `aba0f0ea…` matching between
installed and staged; `delphi-tool:x:997:972`; bwrap 0.11.1; forced-freshness proven by
identical executables after `touch runtime/src/execute.rs`; PAM `439c1d15…` → `md5sum -c` **OK**
after the run; no stale sessions before or after. Five skips, each quoting its own blocker.

Predicted 177/5 at `feabc56`, committed alone, before the run.

**Root and unprivileged are OVERLAPPING SETS, neither a superset** — root executes tests the
unprivileged run skips and skips three the unprivileged run executes. `177 > 157` read as
coverage is wrong in both directions.

## What remains open, by state

- **DEPENDENT on the native-UI increment** (decided, not implemented): R21-01's
  semantic-forgery half, R21-04, R21-06.
- **SCOPED ELSEWHERE by explicit decision**: §7's audit unwired, the tool's bounding set full,
  the socket refusal fixture-measured, R9-03/04/05/07/12.
- **INHERITED BY A FUTURE INCREMENT**: R23-01..R23-10, now a specification for a runner rather
  than a defect list against one.
- **REOPENED**: R22-01 — closed by mechanism, reopened by the revert, currently held by
  convention.

The fourth state is new this round. **A fifth found now is a finding**, and it will be the third
time this partition has failed to hold.

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per §13.9

**(a) Pre-foreclosed — do not spend budget re-hunting these:** **10** (a skip reports `ok` —
closed by the extractor, the exact baseline, and `require_guard_executed`); **43** (one error
string, two processes — the chain-gap demonstration prints the child's own stderr); **44**
(restore without precondition — `trap` + `cmp`).

**(b) Applicable and NOT foreclosed:**

- **48** (the fix scoped to the named instance) — four instances; this range contains both its
  first pre-commit catch and, arguably, another occurrence of it. See question 2.
- **45** (the totality claim) — this range asserts "no executable product behaviour has changed
  since `298d4db`", "run 13 covers both dimensions", "the extra 28 skips are userns-gated".
  **Audit all three; each is a universal stated from a bounded check.**
- **41** (wrong altitude) — the class-48 predicate is a grep. Three grep sweeps in this arc
  returned confident false negatives.
- **47** (a documented flake is a hypothesis) — no flake was invoked this round. Confirm that is
  true rather than assuming it.

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Each finding: **ID** (`D0A-R25-nn`), **severity**, **root
cause**, **impact**, **fix sketch**.

**The most valuable return is a product defect** — because four rounds without one is either
convergence or blindness, and a single finding in `runtime/src/**` settles which. Second most
valuable: a demonstration that a named region of the product has not been reviewed, even if you
find nothing wrong in it. An APPROVE that rests on "the records are now accurate" would be
answering a question I did not ask.
