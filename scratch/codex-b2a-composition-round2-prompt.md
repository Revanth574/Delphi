# Codex adversarial review — B2a COMPOSITION, round 2 (the round-1 fixes)

You are a COLD ADVERSARIAL REVIEWER continuing a multi-round sweep. Round 1 returned REVISE
with 4 findings. This round is scoped to the REMEDIATION ONLY. Findings only — no praise, no
restatement of what the code does.

(Not to be confused with `scratch/codex-b2a-round2-prompt.md`, which is round 2 of the earlier
B2a SECURITY-CORE increment — a different commit and a different subject.)

## Target

- **Fix commit:** `c2c60f4` — "fix(installer): Codex round 1 — all four findings at root cause".
- **Range:** `a1e90b6..c2c60f4`.
- **Files:** `installer/install.sh`, `installer/p3-preflight.sh`,
  `installer/tests/tree-install.test.sh`, `installer/tests/p3-preflight.test.sh`.
  No production Rust, no `shell/` bundle changes. **Flag scope drift if that differs.**

Read the ACTUAL diff and the ACTUAL current files with the Codex CLI. Verify shell-semantics
and API claims against docs rather than memory. Everything asserted below is a **claim to
check**, including the author's account of their own testing.

## Round-1 scope note, resolved — confirm it

Round 1 flagged 30 commits vs the prompt's 29 and proceeded. The extra commit was **the prompt
commit itself** (`a1e90b6`, 229 lines, `scratch/codex-b2a-composition-prompt.md` only): the
count was written while drafting, and committing the prompt made it 30. No production code sat
outside the scope statement. **Confirm that reading independently** — it is exactly the sort of
claim that should not rest on the author's word.

---

## The four fixes

### B2A-COMP-R1-01 (P1) — subdirectory trust check

**Claim:** every directory in the staged bundle tree now gets the same `fstat_trust` (owner ∈
{root, invoking uid}, no group/other-write, is-a-directory, on the BOUND fd) that staged files
already got. So no unprivileged user can own or write any directory on the path, and therefore
none can create or replace the entry being opened by name.

Attack it:

- The fd is opened, checked, then **closed** (`exec {dfd}<&-`) before children are opened.
  Does closing it reopen the race the check was meant to close? Argue from the actual ordering.
- `find … -print0 | sort -z` orders parents before children lexicographically. Is that
  guaranteed for **every** tree shape, and does the fix depend on it? Consider a directory
  whose name sorts after one of its own children's full paths.
- The documented bash-cannot-`openat` residual is unchanged. Is it still only a **DoS** (wrong
  root binary) rather than attacker code execution, now that directories are in play?
- Does anything still traverse or open a staged path **not** covered by a preceding trust check?

### B2A-COMP-R1-02 (P2) — install fails when the profile does not load

**Claim:** both `apparmor_parser` missing and `apparmor_parser` failing now exit non-zero,
naming the state the system is left in.

Attack it:

- The failure occurs **after** binaries, unit, PAM and the bundle are installed. Is exiting
  non-zero mid-mutation right, or does it leave a state worse than either finishing or rolling
  back? Round 1's **B2A-C-R1-04** requires all checks before any mutation — does this violate
  that principle's spirit, and **could the profile load be moved earlier** (e.g. validate with
  `apparmor_parser -QK` during pre-flight, load after)?
- `set -euo pipefail` is in force. Verify the `if ! command -v` / `if ! apparmor_parser` forms
  actually reach the intended branches rather than aborting earlier.

### B2A-COMP-R2-01 (P2) — marker validated against `DELPHI_AI_BIND_RW`

**Claim:** the pre-flight now checks the marker is inside the sandbox's writable bind, using
the same `/tmp` default `delphi-minimal-ai` uses.

Attack it:

- The test is `case "$AI_ARG/" in "$bind_rw"/*)`. Does it hold for `bind_rw` with a trailing
  slash; `bind_rw=/`; a relative `bind_rw`; a `bind_rw` containing glob metacharacters; or an
  `AI_ARG` that is a prefix-but-not-descendant (`/tmpfoo` vs `/tmp`)?
- Does it match what `delphi-minimal-ai` and `runtime/src/sandbox.rs` **actually** do with the
  bind, or only what the pre-flight assumes? The `/tmp` default is now duplicated in two
  places — is that drift-prone, and should it be derived rather than repeated?

### B2A-COMP-R1-03 (P1) — `sysctl` stubbed so the AppArmor cases are host-independent

**Claim:** stubbing `sysctl` controls the INPUT to the logic under test; both branches
(enforcing / not enforcing) now have cases, so the verdict no longer depends on host config.
**Claim:** this is categorically different from the removed `aa-status` stub, which faked a
CAPABILITY the real tool does not have for an unprivileged caller.

Attack it:

- Is that distinction real, or a rationalisation? If a stub may supply a value, what stops the
  next author stubbing something that hides a genuine incapacity? Is the line drawn in the file
  actually operable by a future reader?
- `/usr/sbin` was added to the namespace tmpfs so `apparmor_parser` ABSENT is representable.
  Does hiding `/usr/sbin` change anything else the installer depends on?
- **HOST-DEPENDENCE AUDIT — verify independently.** The author claims exactly ONE other
  host-state read remains (the exec-label probe, documented as unsimulatable, with the PASS
  case structured around it), and that nothing else in either suite takes its verdict from host
  configuration. **Check both suites yourself and say if that is wrong.**

---

## TWO WEAKENS BY THE AUTHOR WERE INVALID — the part most worth your attention

Round 1's remediation was supposed to be RED-proven. Two weaken runs did not do what they
appeared to, and both are disclosed in the commit body:

1. The first **R1-02** weaken sliced from the apparmor block to `systemctl daemon-reload` and
   **swallowed the entire tree-mutate (two-rename) section** — 8 unrelated failures. Redone
   surgically (only the two `exit 1` statements), with the two-rename section verified present.
2. The first **R2-01** weaken used `s.index('    esac')` from position 0, which matched the
   EARLIER `esac` in the exec-label probe. `j < i`, so the slice re-included the check intact:
   **the weaken removed nothing and the test "passed"**. Redone anchored from `i`, with the
   removal verified by grepping for the refusal string (count 0) before the result was believed.

**What I want from you:** do not take the redone proofs on trust either. For each of the four
fixes, judge whether the regression test that now exists **could actually fail if the fix were
reverted** — reason from the test's assertion and the code path, not from the author's report
of having run it. **If any test cannot fail for the reason it names, that is a P1 finding**, as
in round 1.

Also: the over-broad weaken removed the two-rename section and produced 8 failures. Confirm the
surgical redo covers what the over-broad one only *appeared* to cover — i.e. that nothing about
the apparmor fix was validated only by the broken run.

---

## `docs/DEFECT_CLASSES.md` partition for THIS diff

**(a) pre-foreclosed — do not spend budget here:** class 1 (no hashing changed), class 3 (no
SQLite), class 2 for the *handler* (unchanged this round).

**(b) applicable — concentrate here:** class 2 for the **installer** (the subdirectory race is
exactly this, freshly touched); class 12 (bind-containment gate, name/entry gates); class 14
(does each gate cover all forms of what it guards); class 18 (verify the artifact, not the
operation — the two invalid weakens are instances); class 20 (host-dependence in tests, the
R1-03 subject).

## Out of scope — do not report as findings

The AppArmor profile's `flags=(unconfined)` status (round 1 addressed the framing; a confining
profile is a recorded follow-up increment). The compositor gap and P3b blocked on the PRIMARY
deployment shape. The long-lived-shell lifecycle (P4). The wry IPC unwrap (upstream, reported,
routed around). **Say so if you think any of those is misclassified as out of scope.**

## Verdict format

**APPROVE** / **REVISE** / **FAIL**, then each finding as:

- **ID** (e.g. `B2A-COMP-R2-0N`)
- **Severity**: P1-high → P2-medium → P2-low → P3-informational
- **Root cause** — the mechanism, not the symptom
- **Impact** — what an attacker or a failure actually achieves
- **Fix sketch**

A round returning only policy nits, or APPROVE, means the sweep has converged. **If the
remediation introduced a NEW defect, that outranks everything else — say it first.**
