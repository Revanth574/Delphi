# Codex adversarial review — D0 round 6

<!-- Invocation: codex review - < scratch/codex-d0-round6-prompt.md
     All three range-selection flags reject a PROMPT positional; scope is carried here. -->

## Scope

Round 5 was **REVISE, 1×P1 + 4×P2**; all five were fixed and the branch then went through a
**full lane run**. **Target: `e5cb0cf..HEAD`** on `phase-3b/d0-readiness-contract` — seven
commits. `git log --oneline e5cb0cf..HEAD`, then read the files.

| commit | what |
|---|---|
| `cff5d84` | counts corrected to executed/skipped; `scripts/test-count.sh` |
| `ba62e8a` | the extractor's RED-proof |
| `16a1332` | the extractor's parse was wrong and its fixtures hid it |
| `95149a0` / `44fdfac` | RAII temp dirs (item 5, both halves) |
| `2367ebd` | logind session teardown before `userdel` |
| `59ee0f7` | the physical floor; go/no-go; post-weaken cleanup |
| `a0c99a4` | **`scripts/check-stale-test-sessions.sh`** — the lead below |

Docs (`PROGRESS.md`, `docs/`, `scratch/`) are out of scope except as claims cited here.

## Lead — the new checker, and the reason to distrust it

**`scripts/check-stale-test-sessions.sh` is new, unreviewed, and is now a PRECONDITION for
every lane run** (go/no-go P7, and the post-weaken cleanup in §3a). Its green will be cited as
evidence the environment is clean, so clause (d) makes it tier 1.

**It exists because a previous check named the wrong resource.** After a daemon run, a logind
session `c523` owned by `delphi-r402-119101` survived **on tty1**. Every subsequent test failed
`VirtualTerminalAlreadyTaken` at `pam_open_session`. The cleanup that should have caught it
checked for **processes on tty3** — it had been written while debugging the weaken's tty3
scenario and inherited that scenario's specifics. It reported clean. **Three wrong diagnoses
followed**: a just-landed cleanup fix was blamed first (0/30 immediately after it merged — a
coincidence in time reading as causation), then PAM. The journal gave ground truth.

**So the question is not "does the new checker work" but "does it name the right resource, or
has it merely moved the assumption?"** Specifically:

- It matches sessions whose **user** matches `^(delphi-|db1)`. Is the *user* the right key? A
  session opened by the daemon for a shell — is it always owned by a test account, or can a
  VT-holding session exist under some other user that these tests created indirectly?
- It reads `loginctl list-sessions --no-legend` field **3**. Is that stable across systemd
  versions, and what happens if the format changes — does it fail loudly or report clean?
  (Compare `test-count.sh`, which REFUSES on an unparseable format; this one may not.)
- It checks sessions and accounts. **Is there a third holder of the VT it does not check** —
  an `agetty`, a scope, a `closing` session with no listed user?
- The old check was wrong about *resource* and *VT*. Is there a third axis it was also wrong
  about that the new one inherits — timing, for instance? It runs once, before the run; a
  session appearing mid-suite is not caught.

## Also in scope

1. **`test-count.sh` + its RED-proof + the physical floor.** Tier 1 by clause (d) — its output
   is the project's coverage claim. Its parse was already wrong once (anchored to column 0,
   matched zero of 19 real markers) and its fixtures were **invented rather than captured**,
   which is why the first defect survived review. Now: libtest-format anchor, forced
   `--test-threads=1`, `DELPHI_MIN_MS_PER_TEST` as an independent physical floor, REFUSE on any
   unparseable step. **Is the floor genuinely independent of the SKIP parse, or do they share a
   failure mode?** And can `finished in` summing be fooled (a binary that prints no timing, a
   nested harness)?
2. **The `userdel` teardown** (`2367ebd`). `loginctl terminate-user` → SIGTERM → bounded wait →
   `userdel` → one escalation to `-f`. Can the escalation mask a real problem it should report?
   Is `terminate-user` safe when the account has *no* session? Does any path still discard a
   failure?
3. **Item 5's RAII conversions** (22 sites, `44fdfac`). Guards bound above the existing
   variable so no call site changes. **Is any guard dropped before the directory is last
   used** — particularly where a path is handed to a forked child, a spawned daemon, or a
   thread that outlives the binding? `anchor.rs`, `pam_interposition.rs` and
   `real_webkit_load.rs` needed non-uniform shapes; those are the likeliest to be wrong.
4. **`check-free-space.sh`** — floors per path, names the short one.

## Verification boundary — read before assessing "verified"

- The lane run discharged items 1–4: **30/30** serial with accounts/sessions delta **0**; the
  transaction boundary ran, passed, **and failed under its weaken** naming a survivor;
  readiness reached a gate verdict with no `ShellDiedBeforeReady`/`ShellReadyTimeout`;
  `real_webkit_load` **EXECUTED 19 / SKIPPED 0** at 400ms/test.
- **Item 5's 22 conversions are COMPILE-verified only.** Most live in root-gated tests that
  skip on the dev box. Behaviour is owed to the next lane run.
- Dev box now: `delphi-runtime` **EXECUTED 102 / SKIPPED 19**, `shell-host` **12 / 7** (the 7
  skip correctly — the installed binary predates these edits).

## Verdict

**APPROVE / REVISE / FAIL**; per finding: ID (`D0-R6-NN`), severity, root cause, impact, fix
sketch. Where a finding is a claim rather than a defect, say what measurement settles it.

If the checker names the right resource, say so explicitly — a clean negative on the lead
question is the most useful result available, because the last check of that kind was wrong in
two ways at once and nobody noticed until it cost three diagnoses.
