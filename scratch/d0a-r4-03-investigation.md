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
| 7 | same, WITH `--nocapture`, 3 iterations | **PASS 3/3** |
| 8 | `anchor` first, then `b1_integration`, both `--nocapture`, 3 iterations | **PASS 3/3** |
| 9 | same, with the LANE'S FD SHAPE — stdin a regular file, stdout/stderr appended to a file | **PASS 3/3** |

## Hypotheses eliminated, with what eliminated them

- **Stale logind/PAM session before the run.** The pre-run stale-session check (added for
  this) reported clean BEFORE run 25's lane and again after.
- **Test ordering inside `b1_integration`.** The two tests added since run 23 change what
  runs immediately before it, but the inserted test SKIPS instantly in the featureless
  build, so it removes no slack. Checked against both retained logs.
- **The commit range, as a sufficient explanation.** Line 4: HEAD passes 5/5 in isolation.
  Whatever the cause, it is not "this commit made the test fail".
- **Something earlier in `b1_integration`.** Line 6: the whole binary, serially, 3/3 clean.

## What is left, after lines 7 and 8

Fourteen consecutive passes outside the lane against 2/2 failures inside it. `--nocapture`
is eliminated; so is `anchor` as a predecessor.

**The difference I had not accounted for is the FILE DESCRIPTORS.** The lane runs:

```
while read -r b; do
  sudo "$b" --nocapture --test-threads=1 >> "$LOG" 2>&1
done < /tmp/targets.txt
```

so the test binary gets **stdin = a regular file** (`targets.txt`, positioned partway
through) and **stdout/stderr = a regular file opened for append**. Every repro above ran
with **stdin = a terminal** and stdout = a pipe.

That is not cosmetic for this failure. The failing step is `pam_open_session` in a child
the daemon spawns, and that child inherits these descriptors. PAM and logind care about the
terminal; a session opened by a process whose stdin is a regular file is not the same
situation as one whose stdin is a tty.

**This is the first candidate with a mechanism rather than a correlation**, and it was
sitting in the procedure the whole time — visible in the invocation, invisible because
every repro was typed at a prompt.

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

  (a) DONE — line 7, PASS 3/3. `--nocapture` eliminated.
  (b) DONE — line 8, PASS 3/3. `anchor` eliminated.
  (c) NEXT — the lane's FD shape: stdin from a regular file, stdout/stderr appended to a
      file. If this reproduces, split it: stdin alone, then stdout alone.

If (a) fails, `--nocapture` is the variable and the lane's own invocation is implicated —
which would mean the lane has been measuring the product under a condition the product does
not face in production, and the "failure" is about the harness's stdio, not the gate.

If (a) passes and (b) fails, `anchor` leaves residue.

If both pass, the context is wider still and the next step is the lane's remaining
difference: the freshness step's `touch` + rebuild immediately before the run.

## A SCOPE CORRECTION ON EVERY ELIMINATION ABOVE

**The box rebooted between the failures and the investigation.** Runs 24 and 25 ran
2026-09-10 at ~18:19 and ~18:39, the 4th and 5th heavy root runs of one uptime session.
Lines 4 and 6-9 all ran 2026-09-12 on a system **15 minutes old**, with **zero leftover
test users** and none of that session's accumulated state. (`/tmp` being cleaned — which
broke the bisect's worktree registration — was the same reboot.)

**So the eliminations are narrower than they read.** Each shows that *X alone does not
cause the failure on a freshly booted system*. None shows that *X was not a contributor
under the conditions that actually produced it*. Seventeen consecutive passes in a
condition that differs from the failing one is weaker evidence than seventeen passes
sounds, and saying so is the difference between a ledger and a story.

**This also means the failure is currently UNREPRODUCIBLE, not resolved.** The condition
under which it occurred no longer exists on this machine. Nothing here has fixed it, and
the next opportunity to observe it is the next long session with several root runs.

## The proportionate response: instrument, do not chase

Chasing an unreproducible failure by rebuilding the conditions is expensive and
speculative. Capturing the differential evidence when it next occurs is cheap. The lane's
`hygiene.txt` now records **uptime, the count of leftover test accounts, and the live
logind session list** — so a future failure and a future pass can be compared on the axis
this investigation could not test.

If it never recurs, that is also information, and the ledger says what it would take to
believe it gone: root runs in a long session, which is precisely the condition that
produced it twice.

## Why this is being written down rather than concluded

Three plausible explanations have already been eliminated by measurement, and two of them
looked obviously right when proposed. The cost of carrying an open item honestly is lower
than the cost of a confident wrong attribution in a record that later readers trust
(class 51).
