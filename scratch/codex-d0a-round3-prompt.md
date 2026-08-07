# Codex adversarial review — D0-A round 3 (seven R2 findings fixed)

<!-- Invocation: codex review - < scratch/codex-d0a-round3-prompt.md
     All three range-selection flags reject a PROMPT positional; scope is carried here. -->

## Scope — pinned endpoint, stat regenerated at write time

Round 2 was **REVISE — 1×P1, 5×P2, 1×P3**. All seven are fixed.

**Target: `78a110d..d24a172`.** The endpoint is named explicitly (D0A-R2-07): the round-2 prompt
stated a stat measured against `HEAD`, and later commits moved the range underneath it. Both
ends are now commits, so this scope cannot drift.

| commit | findings |
|---|---|
| `5d40c0a` | **R2-01** scaffold env constants + accept deadline; **R2-05** the malformed literal |
| `03baf00` | **R2-03** an observation not a claim; **R2-04** cause retention to the operator |
| `6a696ff` | **R2-06** narrow the guarantee to what the type buys |
| `d24a172` | **R2-02** the delegation falsifier |

`git diff --shortstat 78a110d..d24a172` reports, regenerated as this prompt was written:
**14 files changed, 699 insertions(+), 80 deletions(-)**. Report a mismatch as a finding.

---

## LEAD — R2-02, and the thing that would have made it a fourth instance

You specified the falsifier: pause `sd_pidfd_get_session` after its first pidfd read, reap and
recycle, resume. It is built and it fires:

```
VICTIM 2
CALL BEGIN
BARRIER MATCHED /proc/2/cgroup
BARRIER FIRED victim=2 impostor=2
CALL RETURNED rc=-61 session=(none)
```

`BEGIN < FIRED < RETURNED` is asserted. That ordering leg is what the three earlier proofs
lacked — they observed before and after the interval, never across it.

**The near-miss is worth your attention more than the success.** `strace` shows `openat`, so a
shim interposing `openat` looks obviously correct. **It caught nothing. Neither did `openat64`
nor `__openat64_2`.** The userspace call libsystemd actually makes is **`fopen64`** — strace
renders every variant as the `openat` *syscall*. A shim aimed at the syscall name builds, runs,
reports success and **silently never fires**: precisely the approximation-wearing-a-disguise you
warned about. It was found by `nm -D` on libsystemd and probing each candidate symbol.

**Questions:**

1. Is `fopen64` the *only* path into that lookup? If libsystemd is ever built without LFS
   aliasing, or a different codepath uses `open`/`openat` directly, the barrier stops firing —
   and it would stop firing **silently**, which is the failure shape that matters here. Is the
   `BARRIER MATCHED` assertion sufficient to catch that, or does it need a stronger guard?
2. The shim does the reap+recycle **inside** the interposition, so it runs in the middle of a
   libsystemd call. `fork`, `waitpid`, `kill` and a `/proc` write from there — is any of that
   unsound enough to invalidate what the harness claims to demonstrate?
3. Off-lane the call returns `-ENODATA` across the barrier, exactly as your Q2 predicted. **Is
   there any environment short of a full seated lane where the answer WOULD discriminate** — a
   user session in a container, a `systemd-run --scope`, anything cheaper than the lane?

---

## The rest of round 2

- **R2-01 (P1)** — the R1-02 test passed three environment names that exist nowhere, so the AI
  panicked before connecting and the daemon blocked in `accept` forever. Fixed by foreclosure:
  `runtime/src/scaffold_env.rs` declares each name once, binaries and tests both use it, a
  wrong name is now a compile error. Every literal in the crate was enumerated and routed.
  `accept_requester_within` handles the residual — **RED: fails in 300 ms naming the AI;
  weaken (drop the deadline) HANGS, killed at 25 s.** *Is `DELPHI_AI_BIN` / `DELPHI_TEST_VT`
  correctly left out as a different contract?*
- **R2-05 (P2)** — the literal read `DURING␣×14 authentication`. Cause: a Rust `\`-continuation
  written through a Python heredoc; Rust strips the next line's leading whitespace, Python
  keeps it, and **it compiled**. Now one shared `const` between the message and the assertion.
  *Is a shared const the right coupling, or does it let a wrong message pass a test that only
  compares it to itself?*
- **R2-03 (P2)** — `NoSession` → `LookupNoData`: an observation, not a liveness claim, because
  the verifier is error-gated. `ENOTTY` labelled observed-on-259, not an API promise.
- **R2-04 (P2)** — cause retention now survives the FFI boundary (`AxisQueryFailed{axis,errno}`,
  and `session_is_seated` separates `-ENODATA` from a failed query); the denial text derives
  from the cause, so a gone process is never reported as "the foreground moved". **The test now
  captures log output** — weaken: delete `ProcessGone`'s diagnostic → fails with `Captured: ""`.
  **HONEST GAP, recorded in the test:** the *seat*-axis collapse specifically is **unbitten** —
  making `sd_session_get_seat` fail with something other than `-ENODATA` while the other two
  succeed needs a real session whose seat query errors, not constructible off-lane. One of
  three axes is covered by construction.
- **R2-06 (P2)** — the guarantee narrowed to consumer-side laziness only; producer-side tearing
  explicitly not claimed; both stale doc sites fixed.
- **R2-07 (P3)** — this prompt's scope, above.

---

## Verification boundary

**Proven off-lane:** lib 83/83; `EXECUTED 119 / SKIPPED 20`; barrier suite 5/5 and **10/10
stable**; clippy rc=0 in both feature configurations and on the decoupled shell-host.

**A LEDGER CORRECTION YOU SHOULD HAVE, because it changes what a previous boundary meant.**
R1-02's obligation was recorded as *"compile-verified, needs the lane"*. **That was wrong.**
R2-01 showed the test could not have passed on **any** machine, lane included — the env names
did not exist. The honest entry is **"was unprovable, now testable"**, and those are different
claims. It is corrected in `PROGRESS.md`. Treat any earlier "needs the lane" note on this
branch with that possibility in mind.

**Still lane-only, both recorded:**

- **R1-01's answer-discrimination** — needs the impostor to hold a real session; off-lane every
  lookup returns `ENODATA` and the two paths agree by accident.
- **R1-02's orchestration test** — must pass PAM to reach the second gate read; root-gated, and
  now genuinely runnable.

A lane run is scheduled before merge.

---

## Defect classes — attention allocation

**Pre-foreclosed:** Class 1, Class 10, Class 25, Class 22's *applied-and-located* rule.

**Spend the budget here:** **Class 22's staleness form** — the barrier is the fourth attempt at
crossing this interval and the first that provably does; check the ordering leg actually
discriminates. **Class 26** — `LookupNoData` was renamed *because* it made a present-tense
claim the code could not support; are there others? **Class 27** — R2-01 and R2-05 both touched
the same unrunnable test, and R2-03/R2-04 both rewrote the same enum. **Class 33** — R2-04's
`denial()` strings are new and unreviewed.

---

## Verdict

**APPROVE / REVISE / FAIL**; per finding: ID (`D0A-R3-NN`), severity, root cause, impact, fix
sketch. Where a finding is a claim rather than a defect, say what measurement settles it.

The judgement most useful to me: **is the barrier's `fopen64` dependency a latent silent
failure**, and **is there a cheaper environment than the lane that would discriminate the
answer?** The second would change the schedule, not just the confidence.
