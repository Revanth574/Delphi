# Codex adversarial review — B2a COMPOSITION, round 6

You are a COLD ADVERSARIAL REVIEWER continuing a multi-round sweep.
R1: REVISE (2×P1, 2×P2). R2: REVISE (3×P2). R3: REVISE (1×P1, 2×P2). R4: REVISE (2×P1, 1×P2).
R5: REVISE (1×P1, 2×P2) — **and one significant negative result, see item 3.**

Findings only. Everything below is a claim to check, **including the author's own audits**,
which have a specific and quantified failure record — see item 1.

## Scope

- **`02e4806..HEAD`** — the round-5 remediation: `installer/install.sh`,
  `installer/p3-preflight.sh`, both installer test suites, `docs/DEFECT_CLASSES.md`, and a
  `scratch/` prompt. Flag scope drift.
- Plus the two standing decisions in item 4, which are not in the diff.

Read the ACTUAL code with the Codex CLI. Verify tool behaviour against the tools' own docs or
`--help`, not memory — item 1 is precisely a case where assuming a tool's behaviour was wrong
three times.

---

# ⚠ ITEM 1 (LEAD) — THE STUB-PERMISSIVENESS AUDIT

**Three rounds running, a test stub has been more permissive than the tool it replaced. All
three were found by you; none by the author.**

| round | stub | how it was laxer than the real tool |
|---|---|---|
| R2→R3 | `aa-status` | returned success + JSON; the real tool answers an unprivileged caller with *"You do not have enough privilege to read the profile set"*. It certified a registry check that **could never work in production**. |
| R4 | `systemctl` | reparsed the unit file — **the exact mirror the fix had just removed** — and answered any `show` call, so a wrong unit or wrong property stayed green. |
| R5 | `systemctl` | accepted `-p Environment` **with or without `--value`** and returned raw `K=V` either way. The real command **prefixes `Environment=`** without `--value`, which makes the caller read every variable as unset. Demonstrated: old stub + that production regression = **22/22 green**; fixed stub + same regression = **1 failed**. |

**The rule this yields, and which the prompt asks you to apply:**

> **A stub must be at least as STRICT as the thing it replaces.** If the real tool refuses,
> errors, or formats differently under some input, the stub must too — otherwise the suite
> certifies a world that does not exist. The test is not "is the stub convenient"; it is
> **"is the stub stricter"**.

**What I want from you: enumerate EVERY stub in the three suites and check each against its
real tool's ACTUAL behaviour.** The complete list (verify it is complete — the author's
enumeration is itself an unverified claim):

- `installer/tests/tree-install.test.sh` → `fakebin/systemctl`, `fakebin/apparmor_parser`
- `installer/tests/p3-preflight.test.sh` → `fakebin/systemctl` (+ its `fakebin/unit-env` data
  file), `fakebin/sysctl` (+ `fakebin/sysctl-value`)

All four real tools are present on this box (`/usr/bin/systemctl`, `/usr/sbin/apparmor_parser`,
`/usr/sbin/sysctl`, `/usr/sbin/aa-status`), so their behaviour can be checked directly rather
than assumed. For each stub ask:

- What does the real tool do on **bad arguments**, **missing privilege**, **a nonexistent
  unit/profile/key**? Does the stub replicate the refusal, or succeed where the real one fails?
- What is the real tool's **exit status** in each case, and does the stub match?
- Does the stub's **output format** match for every argument form the production code could
  send — not just the form it currently sends? (That is exactly R5's finding.)
- `apparmor_parser` in `tree-install` is stubbed `exit 0` for the happy path and a
  `-r`-only-fails variant for one case. Is `-QK` (now a **pre-flight** check) exercised against
  a stub that can actually reject? A stub that accepts every profile makes the parse-validation
  gate untestable.
- `sysctl` returns a fixture value. Does the real `sysctl -n` behave differently for an
  **unknown key** (it errors), and does the pre-flight's `|| echo 0` fallback then mean
  "not enforcing" for a key that merely could not be read?

**Any stub that is laxer than its tool is a P1**, on the same reasoning as a test that cannot
fail for the reason it names.

---

# ⚠ ITEM 2 — THIS ROUND'S METHODOLOGICAL RESULT: THE SAMPLER THAT MEASURED ITS OWN RACE

R6-01's regression test asserts an invariant — *at every instant, at least one of `shell` or
`shell.old` exists* — by sampling the directory while the installer runs.

**The first sampler was wrong, and wrong in a way that manufactured a violation.** It used
**two separate `[ -e ]` stats**. An atomic `rename(2)` landing between them shows the first
path absent (checked before) and the second absent (checked after), reporting a both-absent
state **that never existed**. It attributed its own race to the installer.

It **passed three consecutive runs, then failed on unchanged good code** — intermittent, and
therefore worthless per Iron Law #15 cl. 2: it cannot distinguish a violated property from an
unlucky run. It was caught only because a full-regression run disagreed with the three runs
before it.

**The general form, now in the corpus:** *a measurement composed of several observations is not
a measurement of a single instant.* When the property is "at every instant X", the sample must
be atomic, or the harness will invent violations.

**The fix standard applied, which you should check was actually met** — because a fix for an
intermittent test very easily becomes a test that never fires at all:

1. **determinism proven** — 10/10 consecutive passes on good code;
2. **still bites** — 3/3 failures under weaken (a), removing the restore;
3. weaken (b) (class 22) also caught: keeping the restore but moving the `shell.new` cleanup
   after it produced an actually-observed `both_absent=1`.

Check the sampler as it now stands: is a single `ls -1 | grep -qxE 'shell|shell\.old'` per
iteration genuinely atomic for this purpose? Does `shell.new` ever match and mask a real
violation? Is the busy-loop's CPU contention capable of shifting the installer's timing enough
to hide a window it would otherwise catch?

---

# ITEM 3 — THE HANDLER'S CLEAN PASS IS A FINDING, NOT AN OMISSION

Round 5 changed scope deliberately, because four rounds had converged on `p3-preflight.sh` (a
verification script) while the shipping code had one round. Production files touched per round
were **R1: 20, R2: 4, R3: 2, R4: 2**, and rounds 2–4 found **zero** findings in production code
outside the pre-flight.

Round 5 then examined `runtime/shell-host/src/main.rs` — the custom-protocol handler —
**directly, and found no discrete bug.**

**Read that as positive evidence, not as absence.** Round 1's silence about the handler was
attention settling elsewhere (20 files, four findings, all in `install.sh` and the pre-flight).
Round 5's silence was a dedicated pass. Those are different epistemic states and the difference
is the whole reason the scope was changed.

The author's stated expectation was that the handler would **not** come back clean; that
prediction was wrong, and is recorded as wrong.

**What I want: does a third look change it?** Design B's claim remains:

> The bundle is read ONCE at startup, before any WebKit exists, into a `HashMap`. The handler
> does an **exact key lookup**. No joining, no normalisation, no canonicalisation, no
> filesystem access at request time. `..` is not *rejected* — it is a key that does not exist.

If you agree the claim holds, **say so explicitly** — a second independent confirmation is
worth more than silence, and this increment's honest record needs the positive statement as
much as it needed the findings. If a third look changes it, that outranks everything else.

**Testing note that has already invalidated one test:** the URL layer normalises `../` away
*before* the scheme handler sees the path, so a `../` fetch proves nothing here.

---

# ITEM 4 — TWO STANDING DECISIONS (weigh; do not report as discoveries)

Both were found deliberately, are recorded in `PROGRESS.md`, and are **unfixed on purpose** —
adding unreviewed checks mid-remediation is how a round stops being reviewable.

### 4a. `install.sh` verifies the profile LOADS, never that it ATTACHED

Found by the owed class-22 weaken (b) on R1-02 — the first class recurrence the *author* found
rather than the reviewer. `install.sh` checks `apparmor_parser -r -W` exits 0 and has **zero**
attachment checks; `p3-preflight.sh` has two, because *loaded ≠ attached*. **Measured:** a
profile with a wrong attachment path **parses and loads cleanly**, so the install reports
success while the shell runs unconfined and SIGABRTs on its first themed-icon load.

**Weigh:** is the installer the right layer for an exec-label probe (it would spawn the shell
binary as root to read `/proc/PID/attr/current`)? Or is there a cheaper authoritative check
available to root — `aa-status`, securityfs — that the unprivileged pre-flight could not use
but the installer can?

### 4b. `DELPHI_AI_BIND_RW` existence is unchecked

`bwrap` fails on a missing bind source, so a nonexistent bind is another *all-preconditions-met
over a broken config* shape.

**Weigh:** is **existence** even the right predicate, or **directory-ness**? Will bwrap bind a
regular file? Should this check the source, the destination, or both — and does it belong in
the pre-flight at all, or in the daemon, which could fail fast at launch rather than at first
action?

---

# TEST QUALITY — the standing record

Five rounds: **four tests that could not fail for the reason they named**, **two weakens that
did not weaken**, **one intermittent test**, and **three stubs laxer than their tools**. Every
one found by you.

Structural remedies now in place, which you should verify are actually applied everywhere and
not just where they were introduced:

- `assert_positive` — runs the **pristine** fixture first and fails if the baseline already
  satisfies the expectation, making a generic-string positive assertion *unwritable*. **Check
  every positive assertion in both suites uses it.**
- Each weaken is verified to have **applied** before its result is believed.
- Intermittency: determinism proven by repetition before a timing-sensitive test is trusted.

**Treat any test that cannot fail for the reason it names as P1.** Reason from the assertion
and the code path, not from the author's report of having run it.

# `docs/DEFECT_CLASSES.md` partition

**(a) pre-foreclosed:** class 1 (no hashing), class 3 (no SQLite).
**(b) concentrate here:** **class 19/20** (item 1 — the stub *is* an instrument that differs
from the real one); **class 22** (item 2's sampler, and whether round 5's fixes inherit their
classes); class 2 (item 3's foreclosure claim); class 12/14 (the gates).

# Out of scope

The compositor gap and P3b blocked on the PRIMARY deployment shape. P4. The wry IPC unwrap
(upstream, reported, routed around). The AppArmor profile's `flags=(unconfined)` decision.
**Say so if any is misclassified.**

---

# ON CONVERGENCE

Findings per round: 4 → 3 → 3 → 3 → 3. Flat, not decreasing. **But the composition has
shifted**: round 5's P1 and one P2 were in the test apparatus, and the shipping surface came
back clean under direct examination. That admits two readings — the product is genuinely clean
and the remaining findings are harness debt, or the review is still not looking in the right
place.

**Say which, explicitly, and on what evidence.** If you APPROVE, say what remains unproven
anyway: **P3a-1 proven by observation, P3a-2 proven machine-checkably, P3b/P4/the compositor
gap blocked on the PRIMARY deployment shape** — that split must survive the close intact rather
than be absorbed into it.

# Verdict format

**APPROVE** / **REVISE** / **FAIL**, then each finding as ID / severity (P1-high → P2-medium →
P2-low → P3-informational) / root cause / impact / fix sketch.

**If any stub is laxer than its tool, say that first** — three consecutive rounds make it the
most likely place for a fourth.
