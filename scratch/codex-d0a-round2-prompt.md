# Codex adversarial review — D0-A round 2 (six R1 findings fixed)

<!-- Invocation: codex review - < scratch/codex-d0a-round2-prompt.md
     All three range-selection flags reject a PROMPT positional; scope is carried here. -->

## Scope

Round 1 was **REVISE — 2×P1, 3×P2, 1×P3**. All six are fixed, in the order R1-04 → R1-01 →
R1-05 → R1-02 → R1-03 → R1-06 (R1-04 first because it changed the type the next two touch).

**Target: `d8c476f..HEAD`** on `phase-3b/d0-readiness-contract`.

| commit | finding |
|---|---|
| `9355a13` | **R1-04** — the simultaneity law was convention; make it the type |
| `b201a72` | **R1-01** — bind `sd_pidfd_get_session`; no pid crosses between operations |
| `1f189c1` | docs — the delegation boundary + two Class 22 amendments |
| `509bd0e` | **R1-05** — every denial keeps its own cause |
| `ef4f774` | **R1-02 / R1-03 / R1-06** |
| `d02655b` | docs — the silent-no-op class restated at its observed rate |

`git diff --shortstat d8c476f..HEAD` reports: **9 files changed, 570 insertions(+), 209
deletions(-)** (excluding `d02655b`, docs-only). Report a mismatch as a finding.

---

## LEAD — the delegation boundary, and two questions I need answered rather than confirmed

R1-01 replaced the pidfd → pid → lookup two-step with `sd_pidfd_get_session`. The fix rests
entirely on one claim **you supplied**: that systemd does pidfd → PID → lookup → **pidfd
verification**, and that the last step is what our two-step lacked.

**We have not observed that step. It is internal to libsystemd, and it is evidenced by your
reading of the source, not by running it.** A citation is not a measurement — twice this
session a cited-and-plausible mechanism turned out to need checking. So the property is
**foreclosed on our side and DELEGATED on yours**, and I would rather have the delegation
bounded than reassured.

**Q1 — bound your own citation.** Is the pidfd re-verification **unconditional**? Or are there
paths that skip it — version-gated, error-gated, or dependent on how the session was created
(pam_systemd vs. a manually-created session, cgroup-derived vs. pidfd-derived lookups)? **A
citation that is true for the main path and false at the edges leaves the race open precisely
where it matters**, and that is the shape this branch keeps producing.

**Q2 — what would FALSIFY the delegation?** If `sd_pidfd_get_session` does not verify as
claimed, what observable difference appears, and where? If the honest answer is *"nothing
visible off-lane"*, **say that** — it shapes how the lane run is designed rather than being
discovered mid-run. A named falsifier is worth more here than a confirmation.

---

## The pattern this branch keeps producing — the thing most likely still present

**Three of round 1's six findings were a fix's proof inheriting the fix's own class.** Not the
fix being wrong — the *proof* being wrong in the same way:

- **R1-04**: the simultaneity law was policed by a test exercising a permanently-separate
  `Tearing` fixture, so making the PRODUCTION source lazy would have left it green.
- **R1-01**: A2's original test sampled wholly before and wholly after the reap, never across
  the interval. **Then the BARRIER test written specifically to close that gap did the same
  thing** — under the weaken to the old two-step it still PASSED, because it reaped before
  reading the pid, so `fdinfo` reported `-1` and the two-step also returned `None`. Re-aimed to
  read the number while the victim is alive.
- **R1-06**: the fix for a stale string, applied by a replacement that silently matched nothing
  — the identical no-op that produced the stale string in the first place.

**So the highest-value question to ask of this diff is not "is the fix right" but "can each new
test fail?"** Class 22 now carries the staleness-specific form: *name the interval, then point
at the line where the test observes, and ask whether that line is inside it.*

---

## The fixes, and what to press on each

1. **R1-04** — `SessionSource::current()` returns a concrete `SessionSnapshot`; the tearing
   shape is unrepresentable, so `Tearing` and its `#[should_panic]` law were **deleted** rather
   than kept as ceremony. Your settling weaken (make the production source lazy per axis) now
   **fails to compile** (`E0053`). *Is the foreclosure complete, or can an impl still smuggle
   laziness in — e.g. interior mutability behind the source, or a `SessionSource` wrapper that
   re-reads between the gate call and the mint call?*
   **The atomicity claim is WITHDRAWN**: `query` makes three separate libsystemd calls and the
   docs now state a sampling window instead. *Is the stated window accurate — is there any
   logind API that would give a genuinely atomic triple that we should be using instead?*
2. **R1-05** — `SessionResolution` types the outcome; all variants deny, each logs its own
   cause; `NotAPidfd` is `error!` because it is our bug. Errnos **measured** against systemd
   259: `-ENODATA` no session, `-ESRCH` gone, `-EBADF`/`-ENOTTY` our bug. *Are those errnos
   stable API or observed behaviour? Is `-ENODATA` reliably distinguishable from "logind is not
   running at all", which should probably not read as a routine denial?*
3. **R1-02** — the pre-PAM check stays; a **second read now sits adjacent to the mint**. *Is
   adjacent-to-the-mint the right seam, or does `recv_mint_confirm` after PAM reopen the same
   gap on a smaller scale? Is there any remaining path from gate-pass to token that does not
   cross the second check?*
4. **R1-03** — an explicit compile-time seam: under `insecure-test-seams` ONLY, the minimal
   shell writes the SURFACE marker. Production requirement unmoved; both feature configurations
   lint clean. *Does the seam leak into any build that is not the one test that needs it?*

---

## Verification boundary — proven, and NOT proven

**Proven off-lane, executing:** lib 81/81. The barrier test recycles a pid deterministically
inside `unshare -Ur -p` (measured available unprivileged; `ns_last_pid` writable) and proves
the *staleness*: the number read while the victim was alive later addresses a live impostor.
Weakening the recycling fails at `the impostor must occupy the victim's pid` (`left: 44,
right: 3`), so it is not vacuous. Every weaken this round was verified to have applied **and to
have failed at the line it names**.

**TWO LANE OBLIGATIONS, CARRIED EXPLICITLY AS UNPROVEN:**

- **R1-01's answer-discrimination.** Off-lane the fix cannot be shown to change the ANSWER: the
  discriminating case needs the impostor to HAVE a logind session, and on a seatless box every
  lookup returns `None`, so the two-step and the pidfd path agree **by accident**.
- **R1-02's orchestration test.** It must get PAST PAM to reach the second read, so it is
  root-gated and SKIPS here — compile-verified only. **There is no cheaper non-root leg: a
  pre-PAM denial calls the source exactly once, so any off-lane variant would pass whether or
  not the second read exists.** Stated in advance rather than discovered — that judgement is
  what would have saved three rounds on A2.

Both are recorded in `PROGRESS.md`, not left to read as proven.

---

## Defect classes — attention allocation

**Pre-foreclosed, do not re-hunt:** Class 1 (truncation), Class 10 (skip-as-pass), Class 25
(fixtures captured, not invented), Class 22's *applied-and-located* rule (every weaken this
round satisfies it).

**Applicable and NOT foreclosed — spend the budget here:** **Class 22's staleness form** (does
each new test observe ACROSS its interval?), **Class 26** (captured-read-as-present-tense —
R1-02 was this one level above A3, so ask whether a third altitude exists), **Class 27** (two
correct fixes, unsound interaction — R1-01 and R1-05 both rewrote the same resolution path, and
R1-04 changed the type under both), **Class 33** (a diagnostic naming one side of a comparison
— R1-05's log lines are new and unreviewed).

---

## Verdict

**APPROVE / REVISE / FAIL**; per finding: ID (`D0A-R2-NN`), severity, root cause, impact, fix
sketch. Where a finding is a claim rather than a defect, say what measurement settles it.

**Q1 and Q2 above are the ones I most need answered.** An "APPROVE" that leaves the delegation
unbounded is worth less to this branch than a clear statement of where your own citation stops.
