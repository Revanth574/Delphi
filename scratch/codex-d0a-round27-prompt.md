# Codex adversarial review — D0-A round 27 (the merge gate)

This prompt is `scratch/codex-d0a-round27-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff 53e2b5a..aeafc69`** — six commits. Pinned to a SHA, not `..HEAD` (D0A-R18-09).

```
 20 files changed, 1001 insertions(+), 196 deletions(-)
```

The round-26 remediation (five P1, two P2), the residual record, and lane run 15.

---

## Lead: **a field the whole system binds, and nothing decides on**

Round 26's headline finding was not "Biometric is now refused". It was this:

**No test in this crate had ever asserted that any tier meant anything.** The two tier-touching
tests assert that *changing* `required_tier` changes the digest and the preview — which is true
for any two distinct values and would pass with the tiers renamed to colours. `end_to_end.rs`
called it "one Biometric action" in a doc comment. **Every fixture in the crate proposed
`Biometric`, and migrating all twelve files to `Confirm` cost no coverage, because there was
none to lose.**

So the tier system was **uninspectable by construction**, and R25-01's "descriptive only"
defect *could not have been caught by any test that existed* — a defect is findable only
against an assertion, and there was none to violate.
`biometric_is_refused_because_the_shipped_pam_stack_has_no_biometric_factor` is the first
assertion on a tier's meaning in this crate's history.

### The generalization, asked directly: **what else is labelled but never decided on?**

A field that appears in **construction**, **digest binding** and **preview rendering** — but in
no `match`, no comparison, no branch — is decoration. It looks load-bearing at every site a
reader visits, and carries no consequence anywhere.

**I ran that as a check over the twelve fields of `PendingAction` rather than asking you to
imagine it.** Product code only, `#[cfg(test)]` stripped:

| field | decides anything? |
|---|---|
| `pending_id`, `argv`, `cwd`, `env_delta`, `fs_binds`, `net_policy`, `timeout`, `script` | yes — match / compare / branch sites |
| `required_tier` | yes, **as of round 26** — `service.rs:327`. Before that: no |
| `executable_fd`, `executable_digest` | yes — but **my check missed them** (see below) |
| **`preview_version`** | **NO. Nothing anywhere reads it to decide anything.** |

**`preview_version` is a live instance of the class, found by the check and NOT yet judged.**
Its complete product-code life: declared (`action.rs:284`), moved into the digest
(`action.rs:352`), rendered into the preview text (`action.rs:469`), and set to the literal `3`
in `canonicalize.rs:311`. **No version check. No compatibility branch. No rejection of an
unknown version.** A field whose entire purpose is to tell a reader how to interpret what
follows, which no reader consults.

This is adjacent to D0A-R21-03, which made the rendered version come *from* the bound field
instead of a hardcoded string — that fixed the *rendering* and left the *reading* nonexistent.
**Judge whether this is a defect or whether there is a reason no check exists.** I am handing
it over rather than fixing it because I found it with a tool I also have to defend, and because
the question of whether a version field with no consumer is a defect is exactly the kind I got
wrong at R25-01.

### And attack the check itself — it had a 2-in-3 false-positive rate

The check flagged **three** fields; **two were wrong.** `executable_fd` and `executable_digest`
*are* decided on — by `require_exec_sealed` and `require_digest_matches` (`execute.rs:492`,
`:502`) — and my predicate, which looked for operators and `match`/`if`, cannot see a decision
made inside a **function call**. Class 41 in my own tooling, caught by reading the sites rather
than trusting the count.

So: **is `preview_version` a third false positive I failed to catch?** And is the check's shape
salvageable — should it look for "passed to a `require_*` / `verify_*` / `validate_*`", or is
grepping for decisions fundamentally the wrong altitude and the question needs a type-level
answer instead?

---

## Class 49's check, re-run — and it found a flaw in itself

Round 26's prompt handed over: 14 of 26 `runtime/src` files never named across five rounds. You
went to those files. **Three P1 product defects came back.**

Re-running it now produces a contaminated number, and the contamination is instructive:
**round 26's prompt named all fourteen zeros *inside its zeros table*, so listing a file as
unexamined counts as naming it.** That is class 50 one level up — the measurement's own output
became its input. Separating naming-as-**data** from naming-as-**target** (stripping that table):

**Still zero across all six rounds, as a review target:**

| file | lines | why it is worth your attention |
|---|---|---|
| **`wire.rs`** | 109 | **parses untrusted protobuf from the AI** — `read_frame`, `MAX_FRAME`, the length prefix. Six rounds, never named. The single most attacker-adjacent file on the list |
| `delphi-runtimed.rs` | — | the daemon **entrypoint**. R25-08 found a documentation defect in it *only because a different finding pointed nearby* |
| `audit.rs` | — | §7, unwired — a known-open row, so "nothing found" here would be expected |
| `pidfd.rs`, `scaffold_env.rs`, `lib.rs`, `test_child_guard.rs`, the two minimal fixtures | — | lower stakes, listed for completeness |

**Named as a target for the first time in round 26** (and therefore the interesting ones):
`readiness.rs` (2), `pam.rs` (2), `logind.rs` (2), `launcher.rs` (1), `privdrop.rs` (1),
`fdsec.rs` (1), `consent_relay.rs` (1).

**Here is the fact I most want you to interpret: round 26's findings came from
`service.rs`, `canonicalize.rs` and `store.rs` — the already-examined files. Not one came from
the seven newly-named ones.** Two readings, and I cannot distinguish them from here:

- you went there and they are sound — in which case **say so**, and seven files stop being
  open questions; or
- the naming did not actually redirect attention, and they remain as unexamined as before.

**`readiness.rs` is the one I would still start with.** It is the D0 increment's **own
subject**, CLAUDE.md §6 names it as the worked example of the comment-budget failure —
"shipped at 830 lines for a ~200-line mechanism" — and **it is now 1094 lines**, having grown by
a third *since* being declared over-budget. I have no evidence of a defect in it. That is the
point.

---

## The round-26 fixes — attack their sufficiency

Three of round 25's four fixes were refusals with incomplete enumerations; round 26 corrected
them. **The corrections are themselves refusals and bounds.**

| finding | fix | attack |
|---|---|---|
| **R26-01** | `ENFORCED_TIER = Confirm` | is `Confirm` right, or is the honest answer that the daemon enforces *no* named tier and the enum should shrink? The reasoning that walked `Hardware` → `Biometric` → `Confirm` has walked one rung twice; what stops it at `Confirm`? |
| **R26-02** | 30 s deadline on a disposable thread | the abandoned thread holds an fd and a buffer with nothing reaping it. Under repeated hostile proposals, is thread/fd exhaustion a worse denial than the wedge it replaced? Is 30 s derived or chosen? |
| **R26-03** | `CLOCK_BOOTTIME` via `store::boot_secs` | the wall-clock `within_ttl` in `token.rs` is **still there** and still authoritative inside `execute_approved`. Two clocks, one property |
| **R26-04** | `DELPHI_MAX_EXECUTABLE_BYTES`, default 512 MiB | the budget is "1/8 of an 8 GiB workstation floor, peak = 2x ceiling". **Attack the budget, not the observation** — is 1/8 defensible, is 8 GiB the right floor, and is peak really 2x? |
| **R26-05** | the freshness step exits on every check | it hashes what §2 *enumerated*, so an enumeration defect propagates silently into the freshness claim |
| **R26-06** | the expectation's derivation corrected post-hoc | third occurrence of "number right, explanation wrong" — R19-06, R20-07, now this, **inside the file whose whole purpose is that the derivation be checkable** |
| **R26-07** | run 13's "current" label; **class 50** | see below |

### R26-07 and class 50 — the method finding

Class 48's predicate **worked**: it surfaced the line asserting run 13 was current. The output
was then filtered with `grep -viE "…|run 13 \(|…"` to separate live claims from history — and
`RUN 13 (current)` contains `run 13 (`. **The suppression pattern deleted the signal it was
meant to surface.**

Recorded as `DEFECT_CLASSES.md` **class 50** — *a filter applied to a mechanism's output is not
part of the mechanism and can silently invert it* — explicitly distinguished from class 41: the
sweep did not look in the wrong place, it looked in the right place, found the thing, and a
second step discarded it.

**Attack class 50.** Is the distinction from 41 real or a distinction without a difference? Is
"prefer positive selection to negative suppression" sound, or does it just relocate the same
error? And it was applied in this range — the run-14 sweep was reviewed at all 22 raw hits with
no filter — **so check that the application is honest and not ceremonial.**

---

## Lane run 15

`EXECUTED 192 / SKIPPED 5 / reported 197`, rc 0, 0 failures, 17/17 producers exited 0.
Predicted `192/5/197` at `0ad6556`, committed alone before the run, matched exactly. Both lanes
report 197 — the test SET confirmed identical across environments, which is a different
property from the counts agreeing. Freshness **enforced**: enumeration asserted at 17, both hash
sides asserted equal to it, rebuild failure fatal, `diff` empty.

Ordering held under convention for the **third** consecutive run. Judge whether three clean
instances say anything about D0A-R22-01, or whether "convention held again" is a claim that can
never accumulate into evidence.

**Free space was the thinnest margin in the record** — `$CARGO_TARGET_DIR` fell 4467M → 2297M
against a 2048M floor (249M headroom) and was cleared to 4068M after the run. Recorded because
a filling filesystem has already surfaced in this project as a build error in an unrelated
crate.

## OPEN AND UNRESOLVED — carried as findings, not as context

These are **not** background. Each is open, and each has a specific reason it will be mistaken
for closed:

1. **The suspend divergence is UNMEASURED, not verified.** R26-03 moved to `CLOCK_BOOTTIME`
   because `CLOCK_MONOTONIC` pauses across suspend. **This box has never suspended**
   (`BOOTTIME - MONOTONIC = 0.000s`), so no assertion available on this lane distinguishes the
   two clocks; the test that passes checks clock *identity*. **A green run 15 is not evidence
   about suspend.** Judge whether shipping a clock change that the lane cannot test is
   acceptable, and what would make it testable.
2. **The pending store has NO CAP.** The read ceiling bounds one proposal at 2× ; nothing
   bounds accumulation. It is **adjacent to what R26-04 fixed** — which got a derivation, a
   config knob and a test — and that adjacency is exactly how it disappears. Invisible while B1
   services one action and exits; live the moment B2 loops.
3. **`argv` is EMPTINESS-CHECKED ONLY**, while `env_delta` is NUL-checked at both doors
   (R18-03 / R19-05). **Raised in the round-26 prompt; the findings did not answer it.** A
   question a reviewer declined to answer reads as settled unless recorded as unanswered — this
   is that record. Known: the preview renders argv through `escape_debug`, so a NUL would be
   visible, unlike the env-smuggling shape. **Unknown and not asserted**: what
   `std::process::Command` does with an interior NUL at spawn. **Please answer it this round.**

Also open by prior decision: R21-01's semantic-forgery half, R21-04, R21-06 (native-UI
increment); §7's audit unwired; R23-01..R23-10 (a future lane runner); R22-01 (reopened).

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per §13.9

**(a) Pre-foreclosed — do not re-hunt:** **10** (a skip reports `ok` — extractor, exact
baseline, run 15's five skips each quoted); **43** (child's own stderr); **44** (restore
precondition).

**(b) Applicable and NOT foreclosed:**

- **50** (the filter is not the mechanism) — **new this round, first external review of it.**
- **49** (silence ≠ coverage) — its own check contaminated itself here; is the class still sound?
- **48** (fix scoped to the named instance) — three consecutive catches before this round; zero
  new sites found in this one, which is either progress or a predicate going stale.
- **45** (the totality claim) — this range asserts "all five new tests ungated", "both lanes
  report 197 so the set is identical", "peak cost is 2× the ceiling". **Audit all three.**
- **41** (wrong altitude) — **demonstrated again in this prompt**: my decoration check had a
  2-in-3 false-positive rate because it could not see decisions made in function calls.
- **15** (Iron Law #15 clause 2) — every new test in this range was weaken-proven; verify the
  weakens discriminate rather than merely fail, and check the assertions, not the names.

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Each finding: **ID** (`D0A-R27-nn`), **severity**, **root
cause**, **impact**, **fix sketch**.

**Most valuable returns, in order:** (1) a second genuine instance of the decoration class —
a field or parameter bound and displayed but never decided on; (2) a defect in `wire.rs`, the
untrusted-input parser that six rounds have never named; (3) a verdict on whether
`preview_version` is a real defect or my check's third false positive; (4) an answer to the
`argv` NUL question, which round 26 left open.
