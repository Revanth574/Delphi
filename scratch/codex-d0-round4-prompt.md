# Codex adversarial review — D0 round 4

<!-- Invocation: codex review - < scratch/codex-d0-round4-prompt.md
     All three range-selection flags reject a PROMPT positional; scope is carried here. -->

## Scope

Round 3 was **REVISE, 1×P1 + 3×P2**, and confirmed the class-26 foreclosure holds. All four
are fixed. **Target: commit `646acb6`** on `phase-3b/d0-readiness-contract` — read it
(`git show 646acb6`), then the live files. `PROGRESS.md`, `docs/`, `scratch/` out of scope
except as claims cited below.

## Lead — the thing I would least like to be wrong about

**`launcher::wait_for_child_setup` now has FOUR outcome branches where it had two, on the
trust-boundary spawn path, and the discriminator boundary was derived by me and reviewed by
nobody.**

Round 3's first version reported ambiguity for *any* already-exited child. That broke
B2A-C-R1-01 2/25 and — worse — would have replaced the P3a diagnosis (exec'd, then aborted
during rendering: the most valuable error this system produces) with a vague ambiguity
message. I narrowed it. The narrowing is the unreviewed part:

```
StillAlive            -> Ok
Exited(_, 126)        -> ShellSetupFailed        // CHILD_SETUP_FAILED, the child's own code
Exited(_, other)      -> Ok                      // got past exec; readiness diagnoses it
Signaled(..)          -> ShellSetupAmbiguous     // irreducible: pre- vs post-exec kill
Err(ECHILD) / Err(_)  -> ShellSetupAmbiguous
```

Three questions, directly:

1. **Is 126 the right discriminator?** It is the child's own pre-exec exit code, chosen to be
   distinct from shell exit codes. Can a *shell* exit 126 — `/bin/sh` uses 126 for "command
   found but not executable", and the shell here is `/usr/libexec/delphi-shell`. If it can,
   this branch misreports a post-exec failure as a pre-exec one.
2. **Are the four branches exhaustive and mutually exclusive?** `Stopped`/`Continued` are
   reachable under `WUNTRACED`/`WCONTINUED` (not passed here) — is `Ok(status)` catching
   anything it should not, and is `PtraceEvent` possible for a traced child?
3. **Does any input produce a branch that claims more than the fd can know?** This is
   **class 26 re-applied to the fix for class 26**: `Exited(_, other) -> Ok` asserts "it got
   past the exec", inferred from an exit *code*, not observed. Is that inference sound, or is
   it the same present-tense claim one level up?

## Also attack

**The `ShellGuard` transaction boundary — "every early return routes through `Drop`" is a
claim, not a fact.** Armed after `fork_shell`, disarmed only when `Children` is constructed.
Check it rather than accept it: is there a path between those two points that returns,
panics, or diverges without running `Drop`? Consider `pidfd::open`'s error path, `fork_ai`'s,
a panic inside `await_shell_ready`, and whether `Drop` can run twice or on an already-reaped
pid. Is killing the raw pid genuinely reuse-safe for the *whole* armed window?

**A test whose failure mode is a hang cannot be used as evidence.** Found while weakening
R3-02: a `pause()`ing child outliving a failed assertion holds cargo's capture pipes open, so
the failure presented as a *wedge*, not a failure. Fixed by cleaning up before asserting. Are
there other tests in `runtime/` whose failure path leaks a live child holding the capture
pipes? This is the intermittent-result case of Iron Law 15 clause 2 in its worst form — a
result that is neither pass nor fail.

**`DEATH_GRACE` = 250 ms** now states two limits: an engineering margin measured on one box
and one kernel (not portable), and that the full grace is paid by live `Protocol` paths, not
only successful launches. Is the second still under-stated — how often is a `Protocol` outcome
actually reached in production?

## A claim to attack

`DEFECT_CLASSES.md` 22 now argues that these two are categorically different despite the same
count, against one injected defect:

| instrument | detection |
|---|---|
| child's timing forced (50 ms gap) | 20/20 — sampling with a widened window |
| observation sequence injected into a factored state machine | 20/20 — by construction |

**Is the distinction real, or does the injected test merely move the assumption?** The
injected sequence proves the *state machine* decides correctly; it proves nothing about
whether `witness_terminal` maps real `revents` to the right `Observation`. If the mapping is
where a future defect lands, the factoring has relocated the risk rather than removed it —
say so, and say what covers the mapping.

## Known-unproven (do not re-report; tell me if worse than stated)

- The WRY host's readiness path is **unrun on a display**.
- `leader_is_shell.rs`'s four tests **SKIP without root** here; serial ≥30 owed on the lane.
- `cargo check --workspace` is not runnable here. Per-crate: `delphi-runtime` 118 (30/30
  parallel), `shell-host` 19, Vitest 108.
- The class-26 sweep of other EOF-reading sites (`service.rs`, `consent_relay.rs`,
  `channel.rs`) is **recorded and deliberately not done** — its discriminating question is
  *what is being claimed*, not whether EOF is read.

## Verdict

**APPROVE / REVISE / FAIL**; per finding ID (`D0-R4-NN`), severity, root cause, impact, fix
sketch. Where a finding is a claim rather than a defect, say what measurement settles it.

If the four branches are sound, say so explicitly — a clean negative on the lead question is
the most useful result this round can produce.
