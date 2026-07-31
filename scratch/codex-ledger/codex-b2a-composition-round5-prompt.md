# Codex adversarial review — B2a COMPOSITION, round 5 (SCOPE CHANGE: the shipping surfaces)

You are a COLD ADVERSARIAL REVIEWER continuing a multi-round sweep.
Round 1: REVISE (2×P1, 2×P2). Round 2: REVISE (3×P2). Round 3: REVISE (1×P1, 2×P2).
Round 4: REVISE (2×P1, 1×P2).

**This round deliberately changes what is under review.** Read the scope observation first —
it is the reason for the change, and it is quantified rather than asserted.

---

# ⚠ SCOPE OBSERVATION — FOUR ROUNDS HAVE CONVERGED ON THE THING THAT CHECKS, NOT THE THING THAT SHIPS

Production (non-doc, non-prompt) files touched per round:

| round | production files |
|---|---|
| **R1** | **20** — the custom-protocol handler, the AppArmor profile, `install.sh`, `build.sh`, the systemd unit, the shell bundle, `p3-preflight.sh`, three test suites |
| R2 | 4 — `install.sh` + `p3-preflight.sh` + their tests |
| R3 | 2 — `p3-preflight.sh` + its test |
| R4 | 2 — `p3-preflight.sh` + its test |

**Rounds 2, 3 and 4 found ZERO findings in production code outside `p3-preflight.sh`.** The
review has been following the newest diff rather than the highest risk. The consequence:

- **`runtime/shell-host/src/main.rs` — the custom-protocol handler — has had ONE round.** It
  was in round 1's scope, but round 1's four findings all landed in `install.sh` and the
  pre-flight, so nothing was ever said about the handler itself. It has not been looked at
  since, while four rounds went into a *verification script*.
- The **tree installer's mutate phase** and the **AppArmor profile as an artifact** are in the
  same position.

**Weight your attention accordingly: the pre-flight has had four rounds; these have had one.**
`p3-preflight.sh` is a script that runs before a root step and refuses; the handler is a
**trusted process taking input from the untrusted renderer on every request**. The risk
ordering and the review ordering have been inverted for three rounds.

## Scope

1. **`02e4806..HEAD`** — the round-4 remediation (~4 files: `p3-preflight.sh`, its test suite,
   and a `scratch/` prompt). Expect ~362 insertions / ~47 deletions. Flag scope drift.
2. **AND an explicit SECOND PASS, at current `HEAD`, on the shipping surfaces below** — not
   limited to what changed recently. These are reviewed as they now stand.

Read the ACTUAL code with the Codex CLI. Verify API and shell-semantics claims against docs,
not memory. Everything below is a claim to check — **including the author's own audits**, which
have a poor record in this sweep (see the last section).

---

# ⚠ ITEM 1 — TWO KNOWN-UNFIXED DECISIONS (weigh them; do not report them as discoveries)

Both were found deliberately, recorded in `PROGRESS.md`, and **left unfixed on purpose**:
adding unreviewed checks while remediating a round is how a round stops being reviewable.

### 1a. `install.sh` verifies the profile LOADS but never that it ATTACHED

Found by finally running the owed class-22 weaken (b) on **B2A-COMP-R1-02**.
`install.sh` checks `apparmor_parser -r -W` **exits 0**. It has **zero** attachment checks.
`p3-preflight.sh` has two — the exec-label probe exists precisely because *loaded ≠ attached*.
**Measured:** a profile whose attachment path is wrong **parses and loads cleanly**, so the
install reports success while the shell runs unconfined and SIGABRTs on its first themed-icon
load. That is the same class R1-02 closed ("an install reporting success for a system it left
unable to render"), one degree weaker — i.e. class 22 again.

Proposed fix: reuse the pre-flight's exec-label probe in the installer after the load.

**Weigh:** is that the right layer? The installer runs as root and would be spawning the shell
binary to read its label — acceptable, or does that belong only in the pre-flight? Is
`/proc/PID/attr/current` after a brief exec the right predicate, or is there a cheaper
authoritative one available to root (`aa-status`, securityfs) that the unprivileged pre-flight
could not use but the installer can?

### 1b. `DELPHI_AI_BIND_RW` is never checked for EXISTENCE

`bwrap` fails on a missing bind source, so a nonexistent bind is another
*all-preconditions-met over a broken config* shape — the family of R2-01 and R3-03.

**Weigh:** is existence even the right predicate? Does bwrap require the source to be a
**directory**, or will it bind a regular file? Should the pre-flight check the source, the
destination, or both? And should this live in the pre-flight at all, or in the daemon which
could fail fast at launch rather than at first action?

---

# ⚠ ITEM 2 — A LIMITATION SEEKING A SECOND OPINION (not an open finding)

**B2A-COMP-R1-01's class-22 weaken (b) could not be constructed.** Two attempts, both
**FAIL/FAIL** — 20/20 and 25/25 runs refused **including the control**, so neither
demonstrated anything. What blocks it: the `-L` symlink check and the by-name
`exec {tfd}<` open sit in the **same loop iteration**, microseconds apart, and a bash-level
racer cannot reliably land in that window. A real attempt needs a C/Rust harness that can
synchronise on the syscall.

It is no longer carried as unpaid debt; it is carried as a **named limitation**.

**The argument standing in its place — explicitly labelled reasoning, not proof:**

> The fix denies the **precondition** rather than winning the race. With every directory on
> the path `fstat_trust`ed (owner ∈ {root, invoking uid}, no group/other-write), an
> unprivileged user cannot create or replace any entry in those directories, so there is
> nothing to race with. The race window exists but is unreachable by an attacker who cannot
> write the directory.

**What I want from you: does that argument hold?** Specifically —
- Is there any way to place or swap an entry in a directory you cannot write (via the parent,
  a rename of the directory itself, a mount, a hardlink, or an already-open fd)?
- The staging root is `installer/staging` inside a repo checkout. Under a `umask 002` checkout
  the repo tree is group-writable — does the trust check cover **every ancestor** up to a
  trusted root, or only from `staging` down?
- If the argument does NOT hold, say so and say what the harness would need to demonstrate it.
  If it DOES hold, say whether the missing empirical proof still matters.

---

# ⚠ ITEM 3 — SECOND PASS ON THE SHIPPING SURFACES (one round each, at current HEAD)

## 3a. The custom-protocol handler — `runtime/shell-host/src/main.rs`

**The newest trusted-side attack surface in the increment, and the least reviewed.** Before
it, the OS loaded a root-owned read-only file. Now a trusted process **takes renderer-supplied
URIs and answers them**.

**Design B's foreclosure claim, to attack rather than accept:**

> The bundle is read ONCE at startup, before any WebKit process exists, into a `HashMap`. The
> handler does an **exact key lookup**. There is no path joining, no normalisation, no
> canonicalisation, and no filesystem access at request time. `..` is not *rejected* — it is a
> key that does not exist.

- Is the lookup actually exact? Find any transformation, decode, or join before it. `/` →
  `/index.html` is the one intentional alias — is it the only one?
- Percent-encoding, unicode normalisation, NUL, very long paths, duplicate slashes, case,
  query strings and fragments: can any make the map answer for a key the author did not intend?
  **Note for testing:** the URL layer normalises `../` away *before* the scheme handler sees
  the path, so a `../` fetch proves nothing here — that fact already invalidated one test.
- `snapshot_bundle` fail-closed set: empty, missing `index.html`, unreadable, non-regular,
  over-deep, unsupported media type. Complete? Does it all run strictly **before** the WebView
  is constructed?
- The MIME allowlist (`html`/`js`/`css`, unknown → refuse at snapshot). Can a wrong
  Content-Type be induced? Does anything downstream trust it?
- The audit line hashes each entry and a length-prefixed tree hash. Injective? Could a crafted
  bundle produce a colliding tree hash?
- Memory: the whole bundle is resident. Bounded anywhere? Failure mode on a large one?
- `shell_url()` / `default_shell_url()` / `SCHEME` / `AUTHORITY`: can the loaded URL be
  influenced by the renderer or an unprivileged local user? `DELPHI_SHELL_URL` and
  `DELPHI_BUNDLE_ROOT` are env overrides and the host is launched by the ROOT daemon with the
  daemon's env — is that a real vector?
- **The IPC path**: `on_ipc` parses `RendererMsg` and routes through `HostSession`. A malformed
  message, or one before the PAM window, must reach the channel nowhere. Still true?

## 3b. The tree installer's MUTATE phase — `installer/install.sh`

Reviewed in rounds 1–2; the mutate phase specifically has had little attention.

- The two-rename replace: `shell` → `shell.old`, `shell.new` → `shell`, `rm -rf shell.old`.
  Non-atomic window is documented and accepted — but are the **crash states** exhaustive? Three
  are handled (`shell.new` present; `shell.old` + `shell`; `shell.old` without `shell`). Is
  there a fourth?
- `rm -rf` on `$OLD`/`$NEW` under a root-owned `/usr/share/delphi`: can anything an
  unprivileged user controls redirect it?
- `fail_after_mutation` claims a re-run is idempotent. True for **every** call site?
- The held-fd set: bounded at 256 entries against the process fd limit. Is the bound checked
  before or after the fds are opened?
- Prior findings **B2A-C-R1-03/R1-04/R2-01/R3-01** must still hold against all added code.

## 3c. The AppArmor profile as an artifact — `installer/apparmor/delphi-shell`

**Do NOT re-litigate `flags=(unconfined)`** — round 1 settled the framing and a confining
profile is a recorded follow-up. Review it as a **shipped artifact**:

- Attachment path correctness (see item 1a — a wrong path loads cleanly and protects nothing).
- Does `include <tunables/global>` / `include if exists <local/delphi-shell>` introduce a
  path an unprivileged user could create or influence?
- Is `userns,` the minimal grant for the glycin/bwrap need, or does it admit more?
- Install mode/ownership, and the `apparmor_parser -r -W` invocation itself.

---

# ITEM 4 — THE SUITE'S OWN FAILURE MODES ARE LEGIBLE, AND THAT MATTERS

**Twice in round 4 the author broke the test suite mid-refactor, and both times the symptom was
"every variable reads as unset"** — which looks exactly like a product defect:

1. A heredoc expanded `${SESSION_USER_FOR_STUB}` and `$tmp` at the wrong time, so the stub held
   literal placeholders and exited 64 on every call.
2. Inside the user namespace `id -un` is `root` (uid 0 is what the outer uid maps to), while
   the stub had been built expecting the outer username — so the unit instance never matched.

Both presented as *"the pre-flight thinks nothing is configured"*. That is the
**harness-defect-presents-as-product-defect** pattern (corpus classes 18/19), and it is worth
knowing when you read a red from this suite: **a wholesale "everything unset" is far more
likely to be the stub than the script.** If you find that shape, suspect the apparatus first —
and say so rather than filing it as a product finding.

---

# TEST QUALITY — the standing record

Across four rounds: **four tests that could not fail for the reason they named**, and **two
weakens that did not weaken**. All four non-biting tests were found by YOU; none by the author.
The author's fixture audits are **zero-for-four** against host-dependence and
non-discrimination.

Round 4 added the structural remedy for the commonest shape: `assert_positive` runs the
**pristine** fixture first and fails if the baseline already satisfies the expectation, making
a generic-string positive assertion *unwritable* rather than merely catchable. **Check that it
is actually used everywhere a positive assertion is made**, not just where round 4 applied it.

**Treat any test that cannot fail for the reason it names as P1.** Reason from the assertion
and the code path, not from the author's report of having run it.

# `docs/DEFECT_CLASSES.md` partition

**(a) pre-foreclosed:** class 1 (no hashing in this diff), class 3 (no SQLite).
**(b) applicable — concentrate here:** class 2 (the handler's foreclosure claim; item 2's
precondition argument); class 12 and 14 (MIME allowlist, fail-closed set, name gates);
class 18 (verify the artifact, not the operation); class 20 (host-dependence); **class 22**
(items 1a and 2, and whether round 4's own fixes inherit their classes).

# Out of scope

The compositor gap and P3b blocked on the PRIMARY deployment shape. The long-lived-shell
lifecycle (P4). The wry IPC unwrap (upstream, reported, routed around). The AppArmor profile's
`flags=(unconfined)` decision. **Say so if you think any is misclassified.**

---

# ON CONVERGENCE

Findings per round: 4 → 3 → 3 → 3. Severity: 2×P1 → 0 → 1×P1 → 2×P1. **That is not
converging**, and round 4's findings were both in the test apparatus rather than the product —
which may mean the product is clean, or may mean the review has been looking at the wrong file
for three rounds. **This round is designed to distinguish those two.**

State explicitly whether the sweep has converged and on what evidence. If you APPROVE, say what
remains unproven anyway: the standing scope split — **P3a-1 proven by observation, P3a-2 proven
machine-checkably, P3b/P4/the compositor gap blocked on the PRIMARY deployment shape** — must
survive the close intact rather than be absorbed into it.

# Verdict format

**APPROVE** / **REVISE** / **FAIL**, then each finding as ID / severity (P1-high → P2-medium →
P2-low → P3-informational) / root cause / impact / fix sketch.

**If the second pass finds anything in the handler, say it first** — it is the surface with the
most authority and the least review.
