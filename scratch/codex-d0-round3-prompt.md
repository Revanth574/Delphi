# Codex adversarial review — D0 round 3

<!-- Invocation: codex review - < scratch/codex-d0-round3-prompt.md
     All three range-selection flags reject a PROMPT positional; scope is carried here.
     See CLAUDE.md §6. -->

## Scope

Round 2 was **REVISE, 2×P1 + 5×P2**. All seven are fixed at root, and the remediation
surfaced **two further defects of the same class**, both found here rather than by review.

**Target: commit `bd03147`** on `phase-3b/d0-readiness-contract`. Read it
(`git show bd03147`), then the live files. `PROGRESS.md`, `docs/`, `scratch/` are out of scope
except where cited below as a claim.

Round-1 and round-2 findings are in PROGRESS. **Do not re-derive them.**

## Lead: one class, four instances, three rounds — and the last two were introduced by fixes

| # | where | how found |
|---|---|---|
| R1-06 | `poll(pidfd, 0)` negative read as **"alive"** | round 1 |
| R2-01 | pre-`read` `revents` reused post-`read` — **83/100** wrongly accepted (measured) | round 2 |
| R2-01b | `n == 0` branch: absent (and stale) `POLLHUP` as proof of life | **here** |
| R2-01c | the R2-01b **fix** returned `ChannelClosed` on the first `POLLHUP` — a liveness claim made while the death was still in flight | **here, by our own test** |

The class (now `DEFECT_CLASSES.md` 26): a poll result witnesses what was true *at poll time*;
any conclusion drawn after an intervening syscall is a claim about the past stated in the
present tense. The dangerous half is asymmetric — **a negative observation is not a positive
claim.** "pidfd not readable" ≠ "alive"; "`POLLHUP` not set" ≠ "the peer still holds its end".

**The foreclosure, which is the part to attack.** R1-06, R2-01 and R2-01b were fixed with
*rules*. R2-01c is fixed with a *mechanism*: `classify_and_confirm_alive` **no longer takes a
`revents` parameter**, so the stale value is not available to misuse; every liveness
conclusion goes through `witness_terminal`, which re-polls and lets **only death** return
early.

**The question: does the foreclosure actually foreclose?** Is there ANY remaining path in the
readiness/launch code where an observation is captured, a syscall intervenes, and the captured
value is then read as a positive claim? Candidates worth checking rather than assuming:

- `await_shell_ready`'s main loop still captures `chan_revents` / `pidfd_revents` and
  dispatches on them. Is every use of those a *negative-free* dispatch, or does one of them
  smuggle a positive claim?
- `witness_terminal`'s phase 2 latches `hup` and then drops `chan` from the poll set. Is the
  latched boolean itself a stale observation being reused?
- `kill_and_reap_shell` → `reap_within`: `WNOHANG` returning `StillAlive` is a **negative**
  observation. Is it read anywhere as "the process is alive"?
- `launcher.rs`'s `wait_for_child_setup` — untouched by D0's fixes, and it reads an EOF as a
  positive claim ("the `execve` succeeded"). Does the class apply there too?

## Evidence to attack: forcing vs sampling

Against **one** injected defect (return `ChannelClosed` on first `POLLHUP`), same code, same
machine, only the instrument differing:

| instrument | detection |
|---|---|
| naturally-racing test, sampled | **3/12** |
| forced interleaving (child closes the channel, sleeps 50 ms, *then* exits) | **20/20** |

This is now the argument in `DEFECT_CLASSES.md` 22 for preferring forcing over sampling, and
for reporting `n/N` only as a labelled fallback.

**The question: what does forcing NOT prove?** A forced interleaving demonstrates the test
detects *that* interleaving. It is worth knowing what it buys and what it does not:

- Does forcing narrow coverage — trading a weak detector of many orderings for a strong
  detector of one, and if so is the traded-away coverage load-bearing here?
- Can a forced interleaving be *unrepresentative* — an ordering the kernel produces only
  because the test constructed it (e.g. the 50 ms sleep makes `HUP`-then-death separable in a
  way a real abort never is)? If so, is the test still measuring the production hazard?
- Is there a third instrument better than both — one that establishes the ordering *without*
  constructing an artificial gap?

## Also in scope

1. **`DEATH_GRACE` = 250 ms, calibrated not chosen.** 0 ms → 32/100 wrongly accepted; 1 ms →
   **43/100** (worse than 0 — non-monotonic, that region is scheduler-dominated); ≥2 ms →
   0/100. Paid in full only on the success path; deaths return as soon as witnessed. Is the
   reasoning from that table to 250 ms sound, and is the success-path cost acceptable where
   `launch()` sits?
2. **A deliberate diagnosis change:** a shell that closes the channel while **running** now
   reports `Protocol`, not `ShellDiedBeforeReady`. The asserted property (not ready) is
   unchanged. Is that reclassification right, and does anything downstream branch on the
   variant?
3. **`reap_within`** (R2-04) — bounded, gives up after 2 s and leaks a logged zombie rather
   than blocking. Correct tradeoff for a launch path?
4. **`signal_ready_once`** (R2-06) — one-shot released on write failure so a reload retries.
   Can the release race a concurrent renderer message?

## Known-unproven (do not re-report; tell me if worse than stated)

- The WRY host's readiness path is **unrun on a display**; the wry-callback dependency is gone
  but the end-to-end path is still unmeasured.
- `leader_is_shell.rs`'s four tests **SKIP without root** here; the fixture change is
  unexercised on this box. Serial ≥30 owed on the lane.
- `cargo check --workspace` is not runnable here (compositor graphics headers absent).
  Verification is per-crate: `delphi-runtime` (113, 30/30 parallel), `shell-host` (19 — newly
  covered; **they had never been compiled** before this commit), Vitest (108).

## Verdict

**APPROVE / REVISE / FAIL**, then per finding: ID (`D0-R3-NN`), severity, root cause, impact,
fix sketch. Where a finding is a *claim* rather than a defect, say what measurement settles it.

If the answer to "does the foreclosure foreclose" is yes, say so explicitly — a clean negative
on that specific question is the most useful result this round can produce.
