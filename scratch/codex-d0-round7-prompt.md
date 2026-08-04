# Codex adversarial review — D0 round 7

<!-- Invocation: codex review - < scratch/codex-d0-round7-prompt.md
     All three range-selection flags reject a PROMPT positional; scope is carried here. -->

## Scope

Round 6 was **REVISE, 4×P1 + 6×P2**; all ten are fixed, plus one item Codex did not raise.
**Target: commit `bc1cdde`** on `phase-3b/d0-readiness-contract` — `git show bc1cdde`, then the
live files. `PROGRESS.md`, `docs/`, `scratch/` out of scope except as claims cited here.

## Lead — a fix for a review-found regression, going back with NO behavioural evidence

**D0-R6-03 is the one to weigh hardest, and the reason is its provenance, not its size.**

- Item 5 (`44fdfac`) replaced hand-rolled temp paths with `tempfile::TempDir`. It was shipped
  **compile-verified only**, with that stated, because most sites live in root-gated tests.
- Round 6 found a regression in exactly that change: `tempdir()` is **0700 root-owned**, and
  `pam_interposition`'s privilege-dropped child can no longer write the shared response file.
  The bare `/tmp` paths it replaced had permissive modes nobody had recorded as load-bearing.
- **The fix — `chown` + `chmod 0770` — is ALSO root-gated, and is ALSO compile-verified only.**

So a fix for a regression found in review is returning by **the same route the regression
arrived**, with no more evidence than the change that caused it. Please weigh it accordingly:

1. Is `chown` to `setup.ids()` + `0770` sufficient for what the child actually does — creating
   `response` inside the dir, not just writing an existing file? Directory write permission is
   what governs creation; confirm the mode covers it.
2. The child runs after `setgroups([])` + `setgid` + `setuid`. Is the **group** leg real — does
   the dropped child still hold `gid`, given `setgroups([])` clears supplementary groups?
3. Is there an ordering hazard: the `chown` happens in the parent before the fork, but is
   anything created in that dir *before* the chown, inheriting root ownership?
4. `TempDir`'s cleanup runs as root; the child may create files owned by the dropped uid. Does
   removal still succeed, and does a failure surface?

## Also — the automated gate was blind, which changes what "CI is green" is worth

Found while grepping for a third consumer of a parse shape: `.github/workflows/ci.yml:53`
guarded against tests silently disappearing by summing `test result: ok` **passes** against a
floor. **A skipped test scores as a pass**, so a test that starts skipping keeps the floor
satisfied forever — exactly the disappearance the guard exists to catch. It had been running
green on every push.

**Fifth "absent, not passing" of this arc and the first that was supposed to be watching.** The
reviewer should know this when weighing any historical "CI was green" claim. CI now calls
`scripts/test-count.sh`. **Is the replacement itself sound as a gate** — does it fail the job
on REFUSE, and can its output be misparsed by the surrounding `awk`?

## The rest of round 6, with the questions that matter

1. **`check-stale-test-sessions.sh`, re-keyed** (R6-01/02/11). Was matching username prefixes;
   enumeration found **five** in the tree, so it reported clean against three. Now keys on
   `Service=delphi-runtime` and the target VT, fails closed, and has a `--vt` per-test mode
   wired into five test entries. **Does `Service=` actually hold what we think** for a session
   opened by `pam_start("delphi-runtime")` — and does it survive the session going `closing`?
   Is `loginctl show-session -p …` output stable enough that the `sed -n 's/^Service=//p'`
   parse cannot silently yield empty on a real session?
2. **Both `Setup::drop`s** (R6-04) now poll `list-sessions` for the user before `userdel`.
   Is a substring match on the username sound (prefix collisions, e.g. `db1f16` inside
   `db1f1605`)? Can the poll spin or exit early on a transient `loginctl` failure?
3. **`test-count.sh`** (R6-05/06/07/09). Malformed summaries REFUSE; `finished in` taken only
   from summary lines; the floor validated. **R6-06's real severity: matching `finished in`
   anywhere INFLATED elapsed, which RAISES ms-per-test and so WEAKENS the floor** — the
   independent second signal failing open under the noise it existed to survive. Is any other
   guard in this script capable of failing open rather than closed?
4. **`check-free-space.sh`** (R6-08) walks to the nearest existing ancestor. Can that loop fail
   to terminate, or resolve to a filesystem other than the one the path will occupy (a mount
   created later, a symlinked parent)?

## Verification boundary

- **Items 1–4 discharged by a real lane run** (30/30 serial, accounts and sessions delta 0; the
  transaction boundary ran, passed, **and failed under its weaken** naming a survivor;
  readiness reached a gate verdict; `real_webkit_load` EXECUTED 19 / SKIPPED 0 at 400ms/test).
- **R6-03 and R6-04 are behaviour claims with NO behavioural evidence** — both root-gated. A
  lane run is scheduled before D0-A precisely to settle them.
- Dev box: `delphi-runtime` **EXECUTED 102 / SKIPPED 19**; extractor RED-proof **15/15**;
  stale-session and free-space checks green.

## Verdict

**APPROVE / REVISE / FAIL**; per finding: ID (`D0-R7-NN`), severity, root cause, impact, fix
sketch. Where a finding is a claim rather than a defect, say what measurement settles it.

R6-03 is the one where an explicit judgement is most useful: **if it looks right but unproven,
say that** rather than approving it — the next lane run can settle it, and knowing which
specific behaviour to watch is worth more than an approval.
