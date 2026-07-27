# Codex adversarial review — B2a COMPOSITION, round 3

You are a COLD ADVERSARIAL REVIEWER continuing a multi-round sweep. Round 1: REVISE (2×P1,
2×P2). Round 2: REVISE (3×P2, no P1 — narrowing). This round reviews the round-2 remediation
**and** carries one retroactive obligation the sweep has incurred. Findings only.

## Target

- **Range:** `c2c60f4..HEAD` (the round-2 fix commit plus one docs commit).
- **Diff stat to expect:** ~7 files, ~395 insertions / ~43 deletions. Files:
  `installer/install.sh`, `installer/p3-preflight.sh`, `installer/tests/p3-preflight.test.sh`,
  `installer/tests/tree-install.test.sh`, `docs/DEFECT_CLASSES.md`, `CLAUDE.md`, and a
  `scratch/` prompt. **Flag scope drift if that differs.**
- Deliberately **no commit count** is stated here: in round 1 the prompt named a count, then
  committing the prompt itself changed it, and you correctly flagged the drift. The range is
  the scope; compute the count yourself if you want it.

Read the ACTUAL diff and current files with the Codex CLI. Verify shell semantics and API
claims against docs, not memory. **Everything below is a claim to check, including the
author's account of their own testing** — that has already been wrong twice in this sweep.

---

# ⚠ LEAD ITEM — CLASS 22, AND A RETROACTIVE DEBT

Round 2 surfaced a pattern that is now named in `docs/DEFECT_CLASSES.md` as **class 22: the
FIX inherits the class it was closing**. The exemplar came from this sweep:

> Round 1's **B2A-COMP-R2-01** added a gate because a sandbox misconfiguration read as
> *all-preconditions-met* — a **false green**. That gate compared paths **lexically**, so
> `/tmp/../var/tmp/marker` against `bind_rw=/tmp` has the right prefix, resolves **outside**
> the bind, and passes. **A false green replaced by a weaker false green.** Round 2's
> R3-02 fixed it by canonicalising with `realpath -m`.

The class prescribes **two weakens, not one**:

- **(a)** revert the fix — the test must fail; and
- **(b)** **re-apply the finding's own question to the fix** — construct an input exhibiting
  the ORIGINAL class against the NEW code, and assert it is caught.

**THE DEBT: B2A-COMP-R1-01, R1-02 and R1-03 were each proven with weaken (a) ONLY.** By the
class's own standard they are proven at the **instance** level, not the **class** level. None
has had (b). That is the single most valuable thing you can do this round:

- **R1-01 (subdirectory trust check).** Original class: a path-resolution race where a check
  and an open disagree (class 2). Re-apply it to the fix: is there an input where the *new*
  per-directory `fstat_trust` passes and the subsequent open still reaches a different inode?
  Consider the fd being closed (`exec {dfd}<&-`) before children are opened; the ordering
  guarantee of `find … -print0 | sort -z`; and whether a directory that passes the check can
  still be *replaced* before its children are enumerated.
- **R1-02 (fail the install when the profile does not load).** Original class: an install
  reporting success for a system it left broken. Re-apply it: is there now a path where the
  install exits **0** while the shell still cannot render? (Consider: profile parses and loads
  but attaches to nothing; `apparmor_parser -r` succeeding while the kernel silently ignores
  the profile; `daemon-reload` failing after everything else succeeded.)
- **R1-03 (sysctl stub for host-independence).** Original class: a test whose verdict comes
  from the environment rather than the property (class 20). Re-apply it: does any *remaining*
  check in either suite still take its verdict from host state? The author claims exactly one
  (the exec-label probe, documented as unsimulatable). **Verify that claim independently —
  check both suites yourself.**

If any of the three fails its (b) weaken, that is a finding at the severity of the original.

---

# The round-2 fixes to attack

## B2A-COMP-R3-01 — preconditions hoisted into pre-flight

**Claim:** `command -v apparmor_parser` and profile-parse validation (`-QK`, skip kernel load)
now run above the first `copy_fd`, where `refuse`'s "no system change made" is TRUE. The `-r`
load cannot be hoisted because loading policy IS a mutation. A new `fail_after_mutation`
states the partial state for anything that dies mid-mutation; **zero `refuse` calls remain
after mutation begins.**

Attack it:
- Verify the "zero `refuse` after mutation" claim mechanically, not by reading the summary.
- Is `-QK` an adequate proxy for "this will load"? What does it NOT catch that `-r` would?
- `set -euo pipefail` is in force. Do the new `if ! command -v` / `if ! apparmor_parser` forms
  reach their branches, or can an earlier abort pre-empt them?
- Is `fail_after_mutation`'s claim of idempotent re-run actually true for every call site?

### ⚠ AND: ONE OF THESE WAS PRE-EXISTING — flagged so you know what the audit found

Round 2's note asked whether anything else in `install.sh` exits after mutation begins. It
does, and it is **older than the code under review**: `copy_fd` has called `refuse` — printing
*"REFUSING (no system change made)"* — **since the original single-file installer**, long
before this increment. It was found by **grepping the pattern** rather than by checking the
instance the finding named (class 17 working as intended). Treat that as context, not as
credit: the question for you is whether the new `fail_after_mutation` actually covers every
post-mutation exit path, including ones neither of us has enumerated.

## B2A-COMP-R3-02 — canonicalise before comparing marker containment

**Claim:** `realpath -m` resolves `..` and symlinks without requiring the target to exist —
which matters because the pre-flight also REQUIRES the marker absent.

Attack it (this is the class-22 exemplar, so attack the fix as hard as the original):
- Does `realpath -m` behave as claimed for a non-existent leaf under an existing parent? Under
  a **non-existent** parent? Verify against docs.
- Symlinked bind: if `bind_rw` is a symlink to another directory, both sides canonicalise —
  does containment still mean what the sandbox means by it?
- Does canonicalising both sides introduce a NEW false-negative — a marker the sandbox WOULD
  accept that this now refuses? A false red before a root run is less dangerous than a false
  green but is still a defect.
- `bind_rw` = `/`; trailing slashes; a `bind_rw` that is a prefix-but-not-ancestor.

## B2A-COMP-R3-03 — mirror the runtime's default rule, not bash's

**Claim:** `unit_env_present` distinguishes absent from declared-but-empty, matching
`env::var().unwrap_or_else()` (defaults only on absence) rather than `${VAR:-default}`
(defaults on both).

Attack it:
- Does `grep -qE "^Environment=$1="` match what **systemd** actually parses? systemd allows
  quoting, multiple assignments on one `Environment=` line, `EnvironmentFile=`, continuation
  lines, and later assignments overriding earlier. Does the pre-flight's parse diverge from
  systemd's for any of those — and if so, is that a new mirroring bug of the same shape?
- The unit is the source the pre-flight reads, but the DAEMON's environment is what the AI
  actually inherits. Is reading the unit file a faithful proxy?

---

# ⚠ SCOPED ITEM — SEVEN MIRRORED VALUES ARE LIVE EXPOSURE, NOT A DOCUMENTED FOOTNOTE

`p3-preflight.sh` **duplicates seven runtime values** rather than reading them (bundle root,
shell bin path, AI bin path, the `/tmp` bind default, which vars are required, the seam
symbol). Round 2 added a header listing all seven with their source of truth, plus one
deliberate divergence stated explicitly (`DELPHI_AI_ARG` is `unwrap_or_default()` at runtime,
so the runtime accepts it absent; the pre-flight refuses, because a run without a marker has
no machine-checkable success signal).

**Do not accept that header as mitigation.** R3-03 *was* one of these seven diverging, and it
surfaced only as a false green. Seven reimplementations of runtime semantics are seven chances
to diverge, and each divergence presents in production as *all-preconditions-met* over a
broken configuration.

This is the same argument that decided the custom-protocol handler's design: **foreclose by
construction rather than check correctly N times.** There, a startup snapshot with exact-key
lookup removed path resolution from the request path entirely — `..` is not rejected, it is a
key that does not exist. The equivalent here is a **`--print-config` mode on the binaries**,
with the pre-flight reading their actual values instead of restating them. That is now a
**scoped item, not an aspiration**.

**What I want from you:** treat the six remaining mirrors as live exposure and say which ones
can diverge *today*, with the input that would do it. Also say whether `--print-config` is the
right foreclosure or whether something cheaper suffices — and whether the deliberate
`DELPHI_AI_ARG` divergence is correctly reasoned or is itself a defect.

---

# TEST QUALITY — THREE NON-BITING TESTS ACROSS TWO ROUNDS

Disclosed so you can calibrate, and because the pattern is the point:

1. **Round 1, R2-01's traversal test** — passed against a deliberately naive
   filesystem-reading handler, because the URL layer normalises `../` away before the scheme
   handler sees it. It could never fail for the reason it named.
2. **Round 1, its replacement** — FAIL/FAIL: the sneaked file was written before the snapshot,
   so it failed against the correct implementation too.
3. **Round 2, R3-01's own test** — asserted the *bundle tree* was absent when the discriminator
   was whether the **binaries** were copied. It passed with the fix reverted. Caught only by
   the step that **verifies the weaken actually applied** before believing its result; the
   weaken reported "moved down" while the test still passed, and that gap was the signal.

Two of round 1's four weakens were also invalid (one swallowed an unrelated section, one
removed nothing and still "passed").

**Treat any test that cannot fail for the reason it names as P1**, as in round 2. Reason from
each test's assertion and the code path — not from the author's report of having run it.

---

# `docs/DEFECT_CLASSES.md` partition

**(a) pre-foreclosed — do not re-hunt:** class 1 (no hashing), class 3 (no SQLite), class 2 for
the *handler* (unchanged since round 1).

**(b) applicable — concentrate here:** **class 22** (the lead item, retroactive debt); class 2
for the **installer** (R1-01's (b) weaken); class 12 and 14 (the containment and default-rule
gates); class 18 (verify the artifact, not the operation); class 20 (host-dependence, R1-03's
(b) weaken).

# Out of scope — do not report as findings

The AppArmor profile's `flags=(unconfined)` status (round 1 addressed the framing; a confining
profile is a recorded follow-up increment). The compositor gap and P3b blocked on the PRIMARY
deployment shape. The long-lived-shell lifecycle (P4). The wry IPC unwrap (upstream, reported,
routed around). **Say so if you think any is misclassified.**

---

# ON CONVERGENCE — YOURS TO DECLARE, NOT THE AUTHOR'S

Round 1 → 2 went 2×P1 to 0×P1, and round 2's findings were narrow. That *looks* like
convergence. **It is not the author's call**: three of the author's own tests did not bite on
first writing across those two rounds, so the author's confidence in their own verification is
demonstrably a poor signal.

State explicitly whether the sweep has converged, and on what evidence. If you APPROVE, say
what remains unproven anyway — the sweep closing is not the same as the increment being
proven, and the standing scope split (P3a proven by observation; P3b, P4 and the compositor
blocked) should survive the close intact.

# Verdict format

**APPROVE** / **REVISE** / **FAIL**, then each finding as ID / severity (P1-high → P2-medium →
P2-low → P3-informational) / root cause / impact / fix sketch.

**If the round-2 remediation introduced a NEW defect, say it first.** And if any round-1 fix
fails its retroactive class-22 weaken, that outranks anything found in round-2 code.
