# Codex adversarial review — D0 round 5

<!-- Invocation: codex review - < scratch/codex-d0-round5-prompt.md
     All three range-selection flags reject a PROMPT positional; scope is carried here. -->

## Scope

Round 4 was **REVISE, 1×P1 + 4×P2**. All five are fixed. **Target: commit `212273a`** on
`phase-3b/d0-readiness-contract` — `git show 212273a`, then the live files. `PROGRESS.md`,
`docs/`, `scratch/` out of scope except as claims cited below.

## Lead — I checked my own seam, and I am the wrong person to have checked it

R4-01 was a **seam between two fixes in one change**: R3-02's guard rested on "an unreaped
zombie holds the pid", and R3-04 reaped it. Each correct alone; jointly the P3a diagnosis never
fired and the guard could root-`SIGKILL` a recycled pid.

**This round changes five things on the same path in one commit.** I ran the seam check and it
came back clean. I am also the author who missed the seam last round, and the invariant that
was removed had been written down explicitly one message earlier — so "I looked and it's fine"
is worth very little here.

**Please make an independent pass on R4-01 ↔ R4-02 ↔ R4-03 specifically:**

- **R4-01** — `ShellGuard` owns the pidfd and signals through it; raw-pid signalling survives
  only in the `fork()` → `pidfd::open` window, justified by "nothing has waited on the child
  yet, so the pid is still reserved".
- **R4-02** — the guard is armed in `fork_shell`'s parent arm *before* any observation, and
  `fork_shell` returns the guard instead of a pid. `reap_within` counts only
  `Exited`/`Signaled` as reaped.
- **R4-03** — `wait_for_child_setup` no longer claims provenance **and no longer waits at
  all**; the guard is the sole owner of the child's lifecycle.

Does any one of these depend on something another removed, changed, or now does at a different
time? R4-02 and R4-03 both altered *when* things happen relative to the fork.

## And attack the seam-check METHOD, which is the weaker artifact

What I actually ran: extract `fork_shell`'s body, assert zero consuming waits; extract the
`fork` → `attach_pidfd` window, assert it contains only the arm.

**That checks for the hazard I already knew about.** The next seam will not be a consuming
wait — it will be some other invariant that some other fix removed, and a grep for `waitpid`
will not see it. So:

1. **What other invariant could a fix in this round have removed that another depends on?**
   Candidates I can name, which is itself the problem: fd lifetime (`shell_end` now drops at a
   different point relative to the guard), signal disposition, the ordering of `pidfd::open`
   against `pam_open_session` in the child, whether `Drop` can run during unwinding from a
   panic inside `await_shell_ready`.
2. **Is there a way to ENUMERATE such invariants rather than check them one hazard at a
   time?** Something closer to: list every precondition each fix's comments *assert*, then ask
   which other fix's diff touches that precondition's source. If there is a mechanical form of
   that, it is worth more to this project than any single finding.

## Also in scope

- **R4-04 was at three sites, not the one named.** `witness_terminal`, `await_shell_ready`'s
  own loop, and the test barrier all used the truncating `Duration → PollTimeout`. All three
  now round up and corroborate `Ok(0)` against the clock. **Is there a fourth?** Any other
  place where a syscall's return is read as a statement about elapsed time.
- **R4-05** — a test-only RAII `ChildGuard` armed on the line after every fork, replacing
  cleanup-before-assert. Proven by the R4-04 weaken, which previously wedged the harness and
  now reports `FAILED`. Are there forks in `runtime/` it does not cover?
- **`reap_within`'s `Ok(_)` arm** now loops on `Stopped`/`Continued`/`PtraceEvent` against the
  same deadline. Can a repeatedly-stopped child spin it, and is the deadline still honoured?

## Known-unproven (do not re-report; tell me if worse than stated)

- `launch_kills_the_shell_when_a_later_step_fails_d0_r4_02` — **the only test of the `launch()`
  transaction boundary — is root-gated and SKIPs here.** That boundary is untested, not
  passing. Its SKIP message says so.
- The WRY host's readiness path is unrun on a display; `leader_is_shell.rs`'s tests SKIP
  without root (serial ≥30 owed on the lane); `cargo check --workspace` is not runnable here.
  Per-crate: `delphi-runtime` 120 (30/30 parallel), `shell-host` 19, Vitest 108.
- The class-26 sweep of other EOF-reading sites is recorded and deliberately not done.

## Verdict

**APPROVE / REVISE / FAIL**; per finding ID (`D0-R5-NN`), severity, root cause, impact, fix
sketch. Where a finding is a claim rather than a defect, say what measurement settles it.

If the three-way interaction is sound, say so explicitly — given that the last seam was found
by you and not by me, a clean independent read on this one is the most useful result available.
