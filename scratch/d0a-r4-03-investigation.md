# `the_daemon_binary_runs_the_real_gate_d0a_r4_03` — the persistent lane failure

An open item with a measurement ledger. Nothing here is a conclusion; each line is what was
run and what it produced. The failure is `shell child failed before execve:
pam_open_session failed`, which makes the daemon exit before emitting the gate witness.

## Ledger

| # | what was run | result |
|---|---|---|
| 1 | lane run 24 — 17 targets, serial, `--nocapture`, featureless | **FAIL** |
| 2 | lane run 25 — same | **FAIL** (2/2) |
| 3 | runs 20, 21, 23 — same shape | PASS (0/3 failures) |
| 4 | bisect, HEAD, the test ALONE, 5 iterations | **PASS 5/5** |
| 5 | bisect, `b51bd8f`, the test alone | **NON-MEASUREMENT** — helper digest pinning; the daemon refused before reaching the gate. Build-path nondeterminism, source verified identical |
| 6 | full `b1_integration` binary, serial, root, no `--nocapture`, 3 iterations | **PASS 3/3** (23 passed, 0 failed) |

## Hypotheses eliminated, with what eliminated them

- **Stale logind/PAM session before the run.** The pre-run stale-session check (added for
  this) reported clean BEFORE run 25's lane and again after.
- **Test ordering inside `b1_integration`.** The two tests added since run 23 change what
  runs immediately before it, but the inserted test SKIPS instantly in the featureless
  build, so it removes no slack. Checked against both retained logs.
- **The commit range, as a sufficient explanation.** Line 4: HEAD passes 5/5 in isolation.
  Whatever the cause, it is not "this commit made the test fail".
- **Something earlier in `b1_integration`.** Line 6: the whole binary, serially, 3/3 clean.

## What is left, and it is now narrow

The lane differs from line 6 in exactly two ways:

1. **`--nocapture`.** The lane invokes `sudo "$b" --nocapture --test-threads=1`; line 6 did
   not. This is not cosmetic — `--nocapture` changes stdio inheritance for every process the
   test spawns, and the failing step is the daemon's `pam_open_session` in a child. A
   plausible mechanism exists; it has NOT been tested.
2. **`anchor` runs first.** It is the only target before `b1_integration` in the lane's
   sorted order. Whether it leaves state that matters is untested.

## The next measurement

Two runs, one variable each:

  (a) `b1_integration` alone WITH `--nocapture` — isolates the stdio variable
  (b) `anchor` then `b1_integration`, both with `--nocapture` — adds the predecessor

If (a) fails, `--nocapture` is the variable and the lane's own invocation is implicated —
which would mean the lane has been measuring the product under a condition the product does
not face in production, and the "failure" is about the harness's stdio, not the gate.

If (a) passes and (b) fails, `anchor` leaves residue.

If both pass, the context is wider still and the next step is the lane's remaining
difference: the freshness step's `touch` + rebuild immediately before the run.

## Why this is being written down rather than concluded

Three plausible explanations have already been eliminated by measurement, and two of them
looked obviously right when proposed. The cost of carrying an open item honestly is lower
than the cost of a confident wrong attribution in a record that later readers trust
(class 51).
