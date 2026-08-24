# Codex adversarial review — D0-A round 15: the normative text, and four narrow changes

<!-- Invocation: codex review - < scratch/codex-d0a-round15-prompt.md
     Every range-selection flag rejects a PROMPT positional; the scope is carried here. -->

## BEFORE ANYTHING — READ THIS, IT REPLACES A WORSE INSTRUCTION

**Round 15's first issue told you to stop if you could not run the sandbox lanes, and you
did exactly that. The instruction was wrong and it is mine to fix.** Rounds 13 and 14
produced their most valuable findings — R13-01, R14-01, R14-02 — from **reading the tree and
running targeted probes**, not from the test suite. "Stop" discarded the capability that has
actually found things.

**So: stop ONLY if you cannot READ the tree.** Otherwise review, and label each finding with
what it rests on:

- **[static]** — code reading, contract-vs-implementation, no execution needed.
- **[probe]** — a controlled experiment you constructed (your `PT_INTERP` and `env`
  substitutions were this, and they were the best findings of round 14).
- **[suite]** — depends on this repo's tests running, which your environment may prevent.

**A [static] or [probe] finding is fully valid from a restricted sandbox.** Only [suite]
conclusions need the boundary, and for those, say what you could not run rather than
inferring.

**AND YOUR FOUR TEST FAILURES WERE MY DEFECT, NOW FIXED.** They came from tests gated on
`bwrap --version` — **existence, not capability**. In your environment bwrap exists and then
fails at `RTM_NEWADDR`, so those tests RAN and FAILED where they should have SKIPPED. There
is now one shared probe (`bwrap_can_build_a_jail`) that attempts a minimal jail and reports
the real reason; four call sites use it. Re-running here: **17 targets, 0 failures**, and in
a restricted environment they should now skip with a measured blocker rather than fail.

`unshare -rm` is a separate matter: `installer/tests/tree-install.test.sh` genuinely cannot
run without it and REFUSES rather than skipping (D0A-R12-09 — that suite reporting green by
skipping is a defect this arc already paid for). Three shell suites failing in your sandbox is
expected and is not a finding.

**There are no deliberate REDs.** `.githooks/runtime-test-count-baseline` carries no `RED=`
lines. Any failure beyond the environment-dependent ones is real.

## Target

`git diff b4e38e2..1931dc2` — **6 commits, 13 files changed, 678 insertions(+), 99 deletions(-).** PINNED. **If your stat disagrees, report that first.**

**The scope is deliberately narrow — it is exactly what changed since round 14.** After a
FAIL the temptation is to widen the prompt to demonstrate thoroughness; the honest scope is
the remediation.

---

## LEAD WITH THIS: is the normative text still overclaiming, and I cannot answer that myself

**`docs/TRUST_MODEL.md` §3 has been amended twice in two rounds:**

- **round 13 → v7**: the contract was versioned to bind an immutable content snapshot, after
  you established that rehashing cannot close the race;
- **round 14 → limit 2 STRUCK**: v7 declared the dynamic loader and system libraries an
  immutable platform TCB member. D0A-R14-01 falsified it — an approved binary names its own
  `PT_INTERP`, and your probe replaced the loader after sealing and changed executed code.

**Two rounds, two sentences in the normative text that measurement contradicted. That is a
rate, not a coincidence, and the question for this round is whether the CURRENT text
overclaims anywhere else.**

**Why I am asking you rather than checking:** both prior instances were found **by
measurement, not by rereading** — and I wrote the sentences. Rereading text for overclaim is
exactly the verification that failed twice, because the author's model of what the mechanism
does is the same model that produced the sentence. **My verification here is structurally
blind, not merely fallible.** A cold read against the code is the only thing that has worked
on this file so far.

**Concretely, the claims §3 now makes:**

1. v7 binds **the first object** — sealed snapshot, seals verified, digest checked at exec.
2. It does **not** bind the execution chain; three hops are named as an **accepted gap**
   (`PT_INTERP`, `#!/usr/bin/env` → `PATH`, `binfmt_misc`).
3. Named limit 1 refuses **a literal nested `#!`** — narrowed from "closes the chain".
4. A **statically linked native ELF** is the configuration where first-object binding and
   total binding coincide — offered as the way a deployment obtains closure by construction.
5. R14-04 adopted as policy: a non-executable source becomes an **executable** snapshot, and
   `noexec` on the source mount does not stop an approved action.

**Is any of that still wider than the mechanism?** Claim 4 is the one I would attack first —
"no downstream hops" for a static ELF sounds total, and `binfmt_misc` is chosen by the
kernel from the file's magic rather than by the file's contents.

### AND AN EDITORIAL QUESTION A COLD READER ANSWERS BETTER THAN I CAN

Named limit 2 is **struck in place**, with the paragraph left standing as the record that it
was asserted for one day and falsified the next. That is honest, and it has its own failure
mode: **a normative document accumulating struck text makes a reader distinguish live text
from preserved-falsified text**, and §3 has now been amended twice in two rounds. Does the
record belong in `TRUST_MODEL.md`, or in `docs/CONFORMANCE_REGISTER.md` with a pointer from
§3? You are reading the file cold, which is the position that can judge it.

---

## The four changes, each with what it does NOT establish

**1. D0A-R14-03, second half — seals are not identity.** The choke point verified that a
program fd was *sealed* and never that it held what was *approved*. `require_digest_matches`
now hashes the sealed fd at exec against the action's recorded digest (executable,
interpreter, script). **Race-free only because the fd is sealed** — the property v7 bought
and had not spent. **The check immediately refused the two fixtures you named**: `[0x11; 32]`
in `audit.rs`, and `sha256(b"INTERP-V1")` — the marker string rather than the interpreter
bytes. RED: a sealed snapshot swapped for one holding different bytes, token re-minted so
only identity differs, must be refused as `Unapproved`, with the honest action executing
first as a positive control. WEAKEN: check removed → the substituted snapshot **executes**,
`ExitStatus(0)`.

**2. D0A-R14-03, first half — two red integration suites behind a green gate.** The gate ran
`--lib --bins`, so every integration suite was outside it. One was broken by **my own**
nested-shebang rejection; the other hand-built an action with a fake digest. The gate is now
`--tests` — **17 targets, ~3 seconds**, so the narrow scope was never justified by time, only
by not having measured it. **23 of the 139 executed tests skip**, and the baseline now records
that as load-bearing: a rising skip count is as much a signal as a falling executed count.

**3. D0A-R9-06 — the environment left argv.** `--setenv K V` published every approved value in
`/proc/<pid>/cmdline` for bwrap's lifetime, satisfying §6's "scrubbed to `env_delta`" in
public. It now travels on the `Command` (`env_clear` + `envs`).

**Measured before writing, and worth your attention because both halves were assumptions that
would have looked correct either way:** (a) `Command::env_clear()` does **not** break bwrap's
own PATH lookup — the program is resolved against the parent's environment; (b) a payload
under this shape sees **exactly** the delta. **(a) is the one that would have bitten
silently**, since a broken spawn in a rarely-exercised path reads as an unrelated failure.
One minute to measure; a round to discover.

**Both directions are asserted, because either alone passes with the defect present:** the
value must **arrive** (a real bwrap run reads the tool's environment) and must **not appear in
argv**. Weaken → the second fails, printing the command line with `s3cret-value` in it.

**Fixed rather than excepted.** The register committed to recording an explicit dated
exception to Iron Law #2 if R9-06 were open at the next merge. **No exception is recorded and
none is owed.** Is the fix complete — does anything else put approved data on a command line?

**4. Class 44 — a restore whose precondition is absent.** After a weaken, the restoring `cp`
failed because its backup had never been written; **the next two commands measured the
weakened tree and reported clean.** What caught it was the *absence* of a confirmation line.
The remedy recorded is **not** "verify restores" — that rule existed in §6 and in class 18 and
was broken anyway — but that the **backup's success is a precondition of the weaken**. Is that
the right generalisation, or is it the same "add a rule" move one level up?

---

## What remains open, so your budget goes elsewhere

- **D0A-R14-01/02 are accepted gaps, not fixed** — the execution chain is unbound past the
  first object, by decision, with the three hops named in §3.
- **D0A-R10-12** — the pre-drop window's mitigation is named and unimplemented; its duration
  unmeasured.
- **R9-01's socket half** — fixture-measured, not against the real daemon.
- **R9-03 / R9-04 / R9-05 / R9-07 / R9-12** — bind TOCTOU, cgroups, timeout, seccomp, audit
  setup-vs-exit, inter-action isolation. All predate this branch and are scheduled.

## Verdict

**APPROVE / REVISE / FAIL**; per finding: ID (`D0A-R15-NN`), severity, root cause, impact,
fix sketch.

**The two answers worth more than findings:** does the current §3 overclaim anywhere else,
and does the struck-text record belong in the normative document or the register?

**Current state:** clippy `-D warnings` rc=0; **17 cargo targets, 0 failures**;
`EXECUTED 139 / SKIPPED 23 / reported 162`; **ALL 9 SHELL SUITES PASS**; root lane
(2026-08-22, **pre-dating changes 1 and 3** — neither has run at euid 0) `18 passed / 0
failed`.

**One figure in this prompt was wrong until it was re-derived, and the correction is part of
the evidence.** It claimed all 9 shell suites passed; the run said 1 of 9 FAILED. Widening the
gate to `--tests` had left the hook-test's G1 weaken matching nothing, so that suite refused
to report a result about the shipped hook — correct behaviour, counted as a failure, unnoticed
for three commits because **nothing local runs the shell suites** (the pre-commit gate runs
cargo tests; only CI invokes `run-shell-suites.sh`). Fixed in `1931dc2`: the weaken now derives
its target. **A change to the hook broke the hook's own suite and the hook could not notice —
D0A-R14-03's shape, one layer out.** Worth your view on whether that should be closed by
mechanism or left recorded, given a gate running every shell suite per commit is one that gets
`--no-verify`'d.
