# Codex adversarial review — D0-A round 28 (the merge gate)

This prompt is `scratch/codex-d0a-round28-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff aeafc69..4607fc9`** — five commits. Pinned to a SHA, not `..HEAD` (D0A-R18-09).

```
 12 files changed, 1183 insertions(+), 253 deletions(-)
```

The round-27 remediation (2×P1, 3×P2), two self-corrections, and lane run 16.

---

## Lead: **the method you prescribed, applied — and here are its results**

Round 27's verdict on my field check was that it "is useful for finding candidates, not
certifying enforcement", and that the way to certify is to **trace each field to its observable
effect and use mutations that remove that effect.** That is adopted, not patched. **I ran it
over all twelve `PendingAction` fields before writing this prompt**, so what follows is results
rather than a proposal.

Method: neutralise the field's effect at its consumption site, run `cargo test -p delphi-runtime
--lib --tests`, record whether anything fails. Tree restored between each.

| field | mutation applied | result |
|---|---|---|
| `argv` | drop everything after `argv[0]` from the child command line | CAUGHT |
| `cwd` | drop `--chdir` | CAUGHT |
| `env_delta` | pass `&[]` to `plan_env_transport` | CAUGHT |
| `fs_binds` | emit zero bind arguments | CAUGHT |
| `net_policy` | `--unshare-net` → `--share-net` | CAUGHT |
| `required_tier` | disable the `ENFORCED_TIER` refusal | CAUGHT |
| `script` | ignore the pinned interpreter, exec the program directly | CAUGHT |
| `executable_digest` | remove `require_digest_matches` | CAUGHT |
| `preview_version` | render a constant instead of the bound field | CAUGHT |
| **`executable_fd`** | **remove `require_exec_sealed` (the program-fd seal check)** | **NOT CAUGHT** |
| **`timeout`** | **hash `0` instead of the value — i.e. stop binding it** | **NOT CAUGHT** |
| **`pending_id`** | **hash a constant instead of the id** | **NOT CAUGHT** |

**Compare the two instruments on the same twelve fields.** The grep said `preview_version` was
decoration (it is enforced — CAUGHT), said `executable_fd` and `executable_digest` were
decoration (both wrong; one is genuinely untested but for a different reason), and said
`timeout` "decides" by matching the bare word inside `poll_timeout(remaining)`. **Four wrong out
of twelve.** The mutation method found three real gaps and misclassified none. Your verdict on
the method was right and the evidence is in this table.

### The finding I most want attacked: `require_exec_sealed` is untested, and it is the precondition for the check that IS tested

Removing the program-fd seal verification entirely breaks **no test at any privilege level**.

**It ships with its own control.** Its sibling `require_fully_sealed` — the same idea applied to
the *script* memfd — **is** covered: removing that one is CAUGHT (`unsealed_script_memfd_is_refused`,
`partial_seal_write_only_is_refused`). Two sibling checks, one tested, one not. So this is not
"the suite is thin here"; it is one specific check with no test.

**And it is load-bearing for a check that passes.** `execute.rs` two lines below it says so in
its own words: *"Hashing here is race-free ONLY BECAUSE the fd is sealed"*. `require_digest_matches`
is CAUGHT by the mutation table above — but the property that makes its result meaningful is the
one nothing tests. **Judge whether that is as serious as it looks to me, and what the right RED
is** (my instinct: an action carrying an *unsealed* program fd whose digest nonetheless matches
— which passes today).

### `timeout` and `pending_id`: what does an unbound-in-practice digest field mean?

- **`timeout`** — you already established it is **enforced nowhere** (`action.timeout` has no
  consumer; already open as R9-04). The mutation adds a second half: **its digest binding has no
  test either.** Two actions differing only in timeout hash identically under the mutant and
  nothing objects. So it is neither enforced nor binding-tested — carried as R9-04, not
  re-filed, but the second half is new.
- **`pending_id`** — hashing a constant breaks nothing. It is a real store key, so the *lookup*
  works regardless; the question is whether the digest needs to bind it at all, and if it does,
  why no test says so.

**Is the right response a test, or is one of these fields telling us the object carries
something it should not?**

---

## Two things you left explicitly open — carried as findings

1. **`action.timeout` is enforced nowhere.** Confirmed by you, not by our grep — which had
   classified it as enforced. Open as R9-04; the mutation result above extends it.
2. **The abandoned read worker is unbounded for repeated service.** B1 services one action and
   exits, which limits accumulation *within one invocation* and establishes nothing about a B2
   loop. **30 seconds is an engineering choice, not a demonstrated bound**, and the worker holds
   an fd and its buffer with nothing reaping it. Under repeated hostile proposals, is
   thread/fd exhaustion a worse denial than the wedge it replaced?

Also unchanged: the **pending store has no cap**, and `PRE_CONSENT_BUDGET_BYTES` (1 GiB) and the
8 GiB floor remain deployment assumptions. R27-01's defect was that the implementation did not
honour even the chosen budget; **the budget itself is still unvalidated.**

## `wire.rs` — class 49's strongest instance, and the question it raises

Six rounds never named it. One round named it. **One P1 in 109 lines of untrusted-protobuf
parsing** — a stalled or trickling peer holding the ROOT daemon before consent.

The class-49 count is contaminated by round 26's prompt naming the zeros *as data*, so
separating naming-as-**target** from naming-as-**data**, these remain at zero as targets across
all seven rounds: `audit.rs` (§7 unwired — a known-open row), `delphi-runtimed.rs` (the daemon
**entrypoint**), `pidfd.rs`, `scaffold_env.rs`, `wire.rs` *(now named — and it returned a P1)*,
`lib.rs`, `test_child_guard.rs`, and the minimal fixtures.

**Which remaining zero would you take first, and why that one?** I would take
`delphi-runtimed.rs` — R25-08 found a documentation defect in it only because a different
finding pointed nearby — but the `wire.rs` result suggests my ordering instinct is worth less
than the measurement.

## R27-05 — a false claim I recorded because the operator asked for it

Stated plainly, because the register now does. The claim was: *no test in the crate had ever
asserted that any tier meant anything*, and *`biometric_is_refused_…` is the first such
assertion in the crate's history*. **Both were false at `53e2b5a`** — round 25 had already added
two tier-semantic tests, so the round-26 migration **flipped a live assertion** (the control went
from *Biometric passes* to *Confirm passes*) rather than filling a vacuum.

**The operator asked for the claim in those terms; I wrote it without checking it against the
base.** The register records that, and records that "who asked for it" is not a defence — the
point being to keep the register a record of what is true rather than of whose fault it was.
Class 48's predicate then found **three further sites** carrying the same claim.

**So: is the corrected version right this time?** The three-phase account now reads —
pre-round-25 no tier assertion existed (and that is why R25-01's defect was undetectable); round
25 created the first two but encoded the wrong boundary; round 26 inverted one. **The same two
people who produced the error are the ones checking the correction, which is the condition that
produced it.** That is the whole reason this is being asked rather than asserted.

## The round-27 fixes — attack their sufficiency

| finding | fix | attack |
|---|---|---|
| **R27-01** | aggregate `ReadBudget`; default **computed** as `PRE_CONSENT_BUDGET_BYTES / PEAK_MULTIPLE_OF_BUDGET` | the multiplier is read off an allocation table in a doc comment. **Verify the table against the code** — if `canonicalize` retains something the table omits, the ceiling is wrong again and silently |
| **R27-02** | absolute `FRAME_DEADLINE` + `arm_frame_liveness` at accept | the deadline is only reachable if the socket returns. `arm_frame_liveness` is called at **one** accept site (`accept_requester`, which `accept_requester_within` delegates to). Is there any other path that produces a stream `read_frame` is called on? The private channel? |
| **R27-03** | `ceiling_from_var` takes the `Result` | is the env boundary now fully covered, or is there another `.ok()` swallowing a distinction elsewhere? |
| **argv NUL** | validated at both doors | you established `Command` fails closed, so this only moves the refusal earlier. Is refusing at canonicalisation right, or should an unexecutable action be allowed to reach a human who might learn something from seeing it? |
| **clock** | `consent_window_elapsed` extracted; the clock test now PRINTS `BOOTTIME - MONOTONIC` | run 16's transcript reads `= 0s` and states it proves nothing about clock selection. Is a test that reports its own powerlessness worth keeping, or is it noise that should be deleted in favour of the pure edge test? |

## Lane run 16

`EXECUTED 200 / SKIPPED 5 / reported 205`, rc 0, 17/17 producers exited 0. Predicted
`200/5/205` at `09dc36b`, committed alone before the run, matched exactly.

**Membership is proven by IDENTITY for the first time** (D0A-R27-04): `(target, test-name)`
counters, `root 205 / unpriv 205`, zero in either direction, `rc 0`. Note 205 rather than 200 —
membership covers executed **and** skipped; the 200/5 split is the count check. Runs 14 and 15
asserted set equality from matching totals, which was true but unestablished.

Freshness **enforced** (enumeration asserted at 17, both hash sides asserted equal to it,
rebuild failure fatal). Ordering held under convention for the fourth consecutive run — **judge
whether that accumulates into anything, or whether "convention held again" can never become
evidence.**

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per §13.9

**(a) Pre-foreclosed:** **10** (a skip reports `ok`); **43** (child's own stderr); **44**
(restore precondition).

**(b) Applicable and NOT foreclosed:**

- **49** (silence ≠ coverage) — `wire.rs` is its strongest instance to date.
- **50** (the filter is not the mechanism) — applied raw in this range; a stale `172/25/197` in
  PROGRESS was caught by reviewing all 19 hits unfiltered.
- **48** (fix scoped to the named instance) — **four** consecutive catches, the last inside a
  correction.
- **45** (the totality claim) — this range asserts "all twelve fields mutated", "membership
  identical", "the multiplier is read off the allocation table". **Audit all three**; the first
  is this prompt's own table.
- **41** (wrong altitude) — demonstrated twice more here: the timing-classification grep matched
  `elapsed` inside a function *name*, and the decoration grep was wrong on four of twelve.
- **15** (Iron Law #15 clause 2) — every new test in this range was weaken-proven. **Verify the
  weakens discriminate rather than merely fail.**

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Each finding: **ID** (`D0A-R28-nn`), **severity**, **root
cause**, **impact**, **fix sketch**.

**Most valuable returns:** (1) a verdict on `require_exec_sealed` — whether an untested check
that is the stated precondition for a tested one is a defect, and what its RED should be; (2) a
defect in one of the remaining never-named files, `delphi-runtimed.rs` first; (3) whether the
R27-05 correction is right, given that the people who produced the error are the ones checking
it; (4) a fourth field whose mutation I should have run and did not.
