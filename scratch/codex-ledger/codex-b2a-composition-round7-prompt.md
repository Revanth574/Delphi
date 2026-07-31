# Codex adversarial review — B2a COMPOSITION, round 7

You are a COLD ADVERSARIAL REVIEWER continuing a multi-round sweep.
R1 REVISE (2×P1, 2×P2) · R2 REVISE (3×P2) · R3 REVISE (1×P1, 2×P2) · R4 REVISE (2×P1, 1×P2) ·
R5 REVISE (1×P1, 2×P2) · R6 REVISE (1×P1, 2×P2).

**This round asks a different question from the previous six. Read the last section first if
you read nothing else — it is the actual deliverable.**

## Scope

- **`efa92f3..HEAD`** — the round-6 remediation: `installer/p3-preflight.sh`,
  `installer/tests/tree-install.test.sh`, `installer/tests/p3-preflight.test.sh`,
  `docs/DEFECT_CLASSES.md`, and a `scratch/` prompt. Flag scope drift.

Read the ACTUAL code with the Codex CLI. Verify claims against tool docs, not memory.

---

# ⚠ ITEM 1 — A LIMIT ON THIS PROJECT'S PRIMARY VERIFICATION TOOL

Round 6's most important output is not a fix. It is this, and it needs adversarial scrutiny
because the project's whole review method rests on it:

> **The weaken/restore protocol has a blind spot for scheduler-dependent properties.**
> Reverting a fix and requiring the test to fail is the project's core evidence that a test
> "bites". **Measured in round 6: a race was REINTRODUCED under an ordinary weaken and the
> test still PASSED** — the bad interleaving simply did not occur that run. The same race had
> already survived a **10/10 deterministic** run.
>
> The protocol degrades silently from *"proven to bite"* to *"did not happen to bite this
> time"*, and **nothing in the output distinguishes those two states.**

The remedy adopted, both parts required, now recorded in `docs/DEFECT_CLASSES.md` class 22:

1. **A happens-before you can point to in the source** — the race removed by construction.
   Here: the initial value is written by the PARENT before the fork (so the file exists
   whenever the parent reads it), and the sampler signals readiness after a *completed* sample
   with the parent blocking on that signal.
2. **A widened-window experiment** — force the bad interleaving rather than waiting for it.
   Under a forced 0.5 s scheduling delay: old shape → `UNKNOWN`, new shape → `0`.

**What I want from you:**

- **Is the blind-spot claim correct as stated, and is it correctly bounded?** It is asserted
  for "ordering between concurrent actors — sampling, signal handling, fork/exec sequencing,
  fd lifetime, lock acquisition". Too broad? Too narrow? Are there properties in THIS codebase
  currently defended only by a weaken that falls inside it — the launcher's fork/exec
  sequencing and setup-sync pipe are the obvious candidates.
- **Is the two-part remedy sufficient**, or does a widened window merely move the goalposts
  (a wider window proves the *widened* system, not the real one)?
- Check the round-6 sampler as it now stands: is `ls -1 | grep -qxE 'shell|shell\.old'` per
  iteration genuinely a single consistent snapshot? Can `shell.new` match and mask a real
  violation? Does the busy-loop's CPU contention shift the installer's timing enough to hide a
  window it would otherwise catch? Is the readiness handshake itself race-free?

---

# ITEM 2 — THE ROUND-6 FIXES

## B2A-COMP-R7-02 — declared-empty bin paths

`${VAR:-default}` defaults on empty AND unset; the runtime's `bin_path()` uses `var_os` and
defaults only on ABSENT, so a declared-empty `DELPHI_SHELL_BIN` made the daemon `execve` an
empty path while the pre-flight checked the default binary. Now a shared `resolve_bin` helper.

Attack: does `resolve_bin`'s `<declared-empty>` sentinel leak into any path where it could be
treated as a filename? Are there other `${VAR:-…}` uses left in the script with the same
divergence? Does the helper match `var_os` semantics for a value that is whitespace-only?

## B2A-COMP-R7-03 — the freshness loop followed the fixed path (class 17)

R6-02 resolved the bin paths for the artifact/seam/exec-label checks but left `[2/7]` hashing
the fixed `/usr/libexec/delphi-minimal-ai`.

Attack: **grep for the shape, do not check the instance.** Are there further sites still using
a fixed path where a resolved one is now available? That is the class-17 question and the
author has already missed it once here.

---

# ITEM 3 — CALIBRATION, DISCLOSED

The author's forecasts about **where findings would be** have been wrong twice in succession,
both pessimistic: predicting the custom-protocol handler would not survive a dedicated pass
(it has now survived **three**), and that a stub audit would find a fourth instance of a
three-for-three pattern (it found **zero** — five stubs enumerated, four real tools available
for direct comparison).

The mechanism, now recorded as corpus class 23: a forecast about one's own code is a model
built from the same understanding that produced the code, so it is wrong **precisely where the
defect is** — common-mode error. The author's *experiments* over the same period (weaken,
widened window, real-binary runs) repeatedly produced correct findings. Standing rule adopted:
**on your own code, construct an experiment rather than forecast a result.**

Relevance to you: **discount any authorial expectation in this prompt**, including the framing
of item 4. The author has been reliably wrong about where to look and reliably right about what
running things shows.

---

# ⚠ ITEM 4 — THE ROUND'S ACTUAL QUESTION

**Do not answer "has the sweep converged." Answer: DOES ANOTHER ROUND CHANGE ANY DECISION?**

The evidence to weigh:

| | |
|---|---|
| Findings per round | 4 → 3 → 3 → 3 → 3 → 3 — **flat, not decreasing** |
| Rounds 5–6 findings in shipping code | **zero** |
| Custom-protocol handler | **three clean passes**, the third stated explicitly |
| Tree installer / AppArmor profile | clean since round 3 |
| Every recent finding | in `installer/p3-preflight.sh` or its test harness |

`p3-preflight.sh` is a **verification script that never ships**. It runs before a root step and
refuses. A defect in it can cause a bad run to be attempted or a good one to be blocked — it
cannot reach a user.

So the sweep is now **finding defects in the instrument rather than in the thing measured**.
Instruments can be improved indefinitely: flat-at-3 could continue for many rounds without ever
touching the merge gate.

**Answer these directly:**

1. **Given the shipping surfaces are clean three times over and the finding stream is harness
   debt on a non-shipping script — is continuing this sweep the right use of the next round,
   or is the merge gate already met?**
2. If you think the **shipping surfaces should be reopened**, say **specifically what would
   reopen them** — a technique not yet applied, a surface not yet examined, a class not yet
   partitioned. *"Look again"* has now returned clean three times, so a fourth undirected look
   needs a reason.
3. If you think the sweep should **close**, say what remains **unproven at close** — closing is
   not the same as proving, and the record must not absorb the difference.

**The standing scope split must survive the close intact rather than be folded into it:**

- **P3a-1 — PROVEN BY OBSERVATION.** The dialog rendered with the injected preview and prompt
  on the seated lane; the operator interacted; 13 bytes returned over `window.ipc` through real
  WebKit.
- **P3a-2 — PROVEN MACHINE-CHECKABLY.** The daemon served one action; the gate DENIED with
  exactly the predicted reason; no marker written.
- **P3b — BLOCKED**, not deferred: gate-POSITIVE via the real shell needs the PRIMARY
  deployment shape, and nothing in the repo can put a display on a bare VT (`compositor/` is
  library-only, winit-backend-only, no udev/DRM/libseat — itself SECONDARY-shaped).
- **P4 (long-lived shell) — NOT STARTED.**
- **Known-unfixed by decision:** installer attachment verification (loaded ≠ attached), and
  `DELPHI_AI_BIND_RW` existence.
- **Named limitation:** B2A-COMP-R1-01's class-22 weaken (b) could not be constructed with
  available tooling (both attempts FAIL/FAIL, control included); the precondition argument
  standing in its place is **reasoning, not proof**.

# Out of scope

The compositor gap, P4, the wry IPC unwrap (upstream, reported, routed around), the AppArmor
profile's `flags=(unconfined)` decision. **Say so if any is misclassified.**

# Verdict format

**APPROVE** / **REVISE** / **FAIL**, plus a direct answer to item 4 — findings alone will not
answer it. Each finding as ID / severity / root cause / impact / fix sketch.

**If your answer to item 4 is "close", say so plainly even if you also file P2/P3 findings** —
a finding in a non-shipping script is not automatically a reason to continue, and the decision
of whether it is belongs in your verdict rather than being implied by the finding count.
