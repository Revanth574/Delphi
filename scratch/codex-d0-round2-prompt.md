# Codex adversarial review — D0 round 2

<!-- Invocation: codex review - < scratch/codex-d0-round2-prompt.md
     All three range-selection flags (--commit/--base/--uncommitted) reject a PROMPT
     positional; the scope is carried in this document. See CLAUDE.md §6. -->

## Scope

Round 1 verdict was **REVISE, 6 findings (3×P1)**. All six are fixed at root. Review the
remediation and what it revealed.

**Target: `a33109a..HEAD` on `phase-3b/d0-readiness-contract`.** Inspect the live tree
(`git log --oneline a33109a~1..HEAD`, then read the files). Four commits:

| commit | what |
|---|---|
| `a33109a` | the six round-1 fixes |
| `b4cff62` | `runtime/tests/common/shell_fixtures.rs` — one construction site for shell fixtures |
| `5d2fb97` | test channel now `SOCK_CLOEXEC`; `POLLHUP` precondition barriers |
| `aede9e3` | `readiness.rs` trimmed 830→597; fixture-divergence sweep (DEFECT_CLASSES 25) |

Round-1 findings and their fixes are in PROGRESS ("D0 Codex round 1"). **Do not re-derive
them; attack what replaced them.** `docs/`, `PROGRESS.md`, `scratch/` are out of scope except
where cited as a claim below.

**Verification standard changed between rounds** (CLAUDE.md §6 "Verification tiers"): full
protocol for code that is the *sole defence*; RED + one weaken for the rest. `readiness.rs`
and `launcher.rs` are tier 1. Judge the tier assignments too if they look wrong.

## Lead with these two — I found them, the review did not

**1. The R1-06 fix inherited the class it was closing.** My first version asked
`poll(pidfd, 0)` and read "not readable" as **"alive"**. Measured: a child closes its fds
*before* its pidfd becomes readable, so a dead shell was reported as a live one with a
protocol fault. Now `child_died_within(pidfd, DEATH_GRACE)` — a pidfd is authoritative for
**death** and says nothing about **life**.

**2. A weaken that detected the same defect 5/20 through one test and 20/20 through another.**
Root cause: the 5/20 test `SIGKILL`ed its child without ordering the child's write first, so
75% of runs exercised a *different* property and passed for the wrong reason while green.

**The question for you: where else did either pattern leak in?** Both are live patterns in
this work, not one-offs — R1-03 was "files I touched" reasoning, and the 5/20 test was a
precondition-free weaken.

- Is there another place a **negative result is read as a positive claim** (`!dead` → alive,
  `!denied` → allowed, `!found` → absent)? Check `classify_and_confirm_alive`'s three branches
  and `wait_for_hup`'s panic path specifically.
- Is there another **test whose setup does not establish its own precondition** before
  asserting? The three `wait_for_hup` barriers in `readiness.rs` are my attempt to fix this
  category; are they complete, and does the barrier itself now hide a real failure?
- `b4cff62`'s enumeration of shell fixtures was built by `grep`, not recall. **Is it
  complete?**

## A claim to attack

`docs/DEFECT_CLASSES.md` class 22 now says: *report a weaken's detection rate as `n/N`; a rate
below `N/N` means the test's setup does not establish its own precondition.*

**Is a detection rate actually sufficient to distinguish a sound weaken from a lucky one — or
does it just move the question?** Specifically: 20/20 bounds nothing about the 21st run, and a
test could detect an *injected* defect deterministically while missing the *real* defect class
the injection stands for. If the rule is weaker than it reads, say how, and say what would
actually settle it. This replaces the class-22 bounding question you were asked in round 1 and
did not answer; if this one is also unanswerable, **say that explicitly** — an explicit refusal
is a usable result and silence is not.

## The four mechanisms most worth breaking

1. **`await_shell_ready`'s decision order** (`readiness.rs`). Marker validated, then terminal
   events overrule. Grounding: a real datagram from a closed peer presents `POLLIN|POLLHUP`
   *together*; an empty datagram and EOF are indistinguishable (`read()==0`, `msg_flags 0x0`,
   `MSG_EOR` **clear** — so `MSG_EOR` does not discriminate). Is any (revents, n, liveness)
   combination misclassified? Is `DEATH_GRACE` reachable on the success path?
2. **`kill_and_reap_shell`** (`launcher.rs`, R1-04). Kills via `pidfd_send_signal`, then
   `waitpid`. Is the `ESRCH` handling right, can the `waitpid` block, and is there a path where
   `launch()` returns `Err` without reaping?
3. **The readiness prologue vs the consent protocol.** The daemon reads one datagram before
   writing anything; the host writes one before `HostSession::recv_approval`. Can any
   interleaving — a shell signalling twice, signalling late, a daemon restart mid-prologue —
   get a readiness marker consumed as an approval, or a mint-confirm consumed as readiness?
4. **The one-shot ack** (`shell-host/src/main.rs` + `shell/src/consent/pam-consent-dialog.tsx`).
   Readiness is now renderer-triggered and native-owned (`READY_SENT`). It authorizes nothing —
   but confirm that, and confirm a reload cannot emit a second marker.

## Known-unproven (do not re-report; tell me if worse than stated)

- The WRY host's readiness path is **unrun on a display**. Removing the wry-callback dependency
  removed one unknown; the end-to-end path is still unmeasured.
- `leader_is_shell.rs`'s four tests **SKIP without root** here, so the fixture change is
  unexercised on this box. Serial ≥30 owed on the lane.
- `cargo check --workspace` is not runnable on this box (compositor's graphics headers absent);
  all verification is `-p delphi-runtime` scoped.

## Verdict

**APPROVE / REVISE / FAIL**, then per finding: ID (`D0-R2-NN`), severity, root cause,
impact, fix sketch. For a finding that is a *claim* rather than a defect, say what measurement
would settle it.

One finding naming a real mechanism beats five restating the known-unproven list.
