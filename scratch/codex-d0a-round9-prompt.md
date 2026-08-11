# Codex adversarial review — D0-A round 9: a scope pivot

<!-- Invocation: codex review - < scratch/codex-d0a-round9-prompt.md
     All three range-selection flags reject a PROMPT positional; scope is carried here. -->

## This round is NOT a diff review

Round 8's judgement was that the reporting drift indicates **saturation of this review scope,
not whole-surface convergence**, and that round 9 should pivot to `execute`/sandbox and `fdsec`.
That is what this is.

**Target — three files, reviewed as they stand, not as a change:**

| file | lines | tests | last touched | last reviewed under |
|---|---|---|---|---|
| `runtime/src/execute.rs` | 669 | 8 | 2026-06-28 | B1 review round 1 |
| `runtime/src/sandbox.rs` | 205 | 3 | 2026-06-21 | Increment 1d, never since |
| `runtime/src/fdsec.rs` | 137 | 1 | 2026-06-23 | implementation-review round 2 |

Round 8's own fixes are `921a13c..09dadae` if you want them for continuity, but they are not the
subject.

---

## THE QUESTION — sharper than "find defects"

**Which of these paths would FAIL the standard the last eight rounds established?**

They predate all of it. They were reviewed in June, under a threat model this arc then spent
eight rounds sharpening — and only a reviewer holding both the standard and the code can answer
that. The standard is specific, so here it is in full rather than as a gesture:

1. **RED-proven with weakens in both directions**, and the weaken verified to have **applied**
   *and* to have **failed for its stated reason** — not merely to have failed (Class 22).
2. **No ownership inferred from an absence.** A missing variable, an unset flag, an empty read
   is not evidence that something is yours (D0A-R6-02, R8-01).
3. **No negative satisfiable two ways.** `rc != 0`, "no session found", "nothing in the log" —
   each needs the second way excluded explicitly (D0A-R3-01, R6-01).
4. **Fixtures model states that can actually occur.** An impossible fixture and a literal
   assertion stabilise each other and nothing disturbs the pair (Class 36).
5. **Assertions on properties, not literals**, so a correct message that changed wording fails
   for the right reason and a wrong one still fails (D0A-R3-03).
6. **Cleanup survives the panic path** — RAII, not statements after the fallible work
   (D0A-R4-07, R6-06).
7. **Explicit ownership states**, not ordering alone. *Do I still hold what I am about to act
   on?* is a question ordering cannot ask (Codex's own round-8 judgement, adopted).
8. **Bounded waits everywhere**, including inside cleanup; a leak beats a wedge (D0A-R7-03,
   R8-04).
9. **Positive controls** — a falsifier is paired with a run proving the environment can produce
   the positive, or the negative is unearned (Class 35).

`fdsec.rs` contains **zero** occurrences of "weaken" or "RED" and ships **one** test for the fd
allowlist that FD-01 established as a security boundary. `sandbox.rs` has three tests for 205
lines and has not been touched since the increment that created it.

---

## Why the standard is worth applying rather than assuming

These paths are the **execute** side of the boundary: `fdsec` decides which descriptors survive
`execve` into the sandbox, `sandbox` builds the confinement, `execute` runs the approved action
and re-verifies the token against the stored digest. A defect here is not a reporting problem.

Two shapes from this arc that seem most likely to recur there, offered as hypotheses to test
rather than conclusions:

- **fd allowlists are an enumeration** — and Class 17 has now scored **six for six** this round
  alone: every round-8 finding was one site of several, and enumerating found a third unchecked
  `setenv` that the review itself had not cited. An allowlist reviewed once, in June, under a
  weaker standard, is exactly the shape where the reported instance is one of several.
- **`execute` re-verifies a token against a digest** — a comparison, and Class 33 says a
  diagnostic naming one side of a comparison cannot diagnose a divergence in the other.

---

## What this arc has established, for calibration

Eight rounds; the last four found **20 findings, 15 in verification code**. Class 37
(remediation is where a class reappears) has **seven** in-round instances. Round 8 was **six for
six** on Class 17.

**Both predictors have held every time they were tested**, which is why they are stated rather
than rediscovered. If they do not apply to these files, that is itself worth saying — they were
derived from harness and daemon code, and `execute`/`sandbox`/`fdsec` are neither.

**Current state:** R4-03 discharged with both legs at root on current code; lib 86/86;
`EXECUTED 124 / SKIPPED 22`; barrier 5/5 unprivileged, 13/13 root; clippy rc=0 in both feature
configurations; no lane- or root-gated obligations outstanding.

---

## Verdict

**APPROVE / REVISE / FAIL**; per finding: ID (`D0A-R9-NN`), severity, root cause, impact, fix
sketch.

Two things beyond findings would be more useful than a long list:

1. **Which of the nine standards each file most clearly fails**, so remediation is ordered by
   what the standard says rather than by what is easiest.
2. **Whether this scope is the right pivot at all.** You judged the last one saturated; if
   `execute`/`sandbox`/`fdsec` turn out to be in better shape than the harness was, say so early
   rather than finding eight small things — the useful answer might be that the next round
   belongs somewhere else again.
