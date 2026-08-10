# Codex adversarial review — D0-A round 6

<!-- Invocation: codex review - < scratch/codex-d0a-round6-prompt.md
     All three range-selection flags reject a PROMPT positional; scope is carried here. -->

## Scope — pinned endpoint, stat regenerated at write time

Round 5 was **REVISE — 5×P1, 4×P2**. All nine are fixed, plus two found while fixing them
(R5-10, R5-11).

**Target: `1571d9e..527e8fc`** — 9 commits. `git diff --shortstat`, regenerated as this was
written: **10 files changed, 328 insertions(+), 25 deletions(-)**. Report a mismatch as a
finding.

---

## LEAD — a design question, not a defect: is leg 1 worth keeping?

**`the_daemon_binary_runs_the_real_gate_d0a_r4_03` needed FIVE distinct harness fixes to make
ONE claim.** In order, each failure different and each fix advancing it exactly one step:

1. the entry guard tripping on a session a previous test left;
2. `launch()` refusing a **scaffold-marker** shell where the daemon requires `SurfaceLive`;
3. a **pre-gate false pass** — the presence check accepted `anchor + launcher up`, which the
   daemon prints on the way to failing, so the leg passed for two rounds while never reaching
   the gate;
4. an unbounded `waitpid` on a shell that would never exit;
5. **the surface shell I wrote to fix (2) sitting in `loop { sleep }`**, so the daemon's
   terminal-contract wait never returned.

**All five were in the harness. None was in the assembly under test.** It now passes in 2.36 s.

**The question: is the remaining coupling worth keeping?** Leg 1 drives a real daemon binary, a
real PAM session, a real VT, a purpose-built shell and an AI scaffold, to establish one thing —
*the daemon reached and evaluated the real gate with the seam absent*. **Leg 2 already proves
the harder half independently** (`Resolved { active: false, remote: false, seated: true }` —
the production assembly resolves through the real pidfd) and has passed at root three times
across three different harness states.

Options I can see, and I would rather be told which:

- **keep leg 1 as is** — it exercises the daemon binary end to end, and now that it passes the
  cost is sunk;
- **demote it to a smoke check** — assert the binary starts and the seam is absent, drop the
  gate-evaluation claim, and let leg 2 carry R4-03;
- **something else** — if the five failures indicate the test is proving the wrong thing rather
  than proving it awkwardly.

**A test that needs five repairs to make one claim is evidence about the test's design**, and I
do not trust my own judgement here: I built it, I wrote three of the five defects, and sunk cost
points at "keep".

---

## The base rate held every time it was tested

Round 5's prompt led with *the verification code has been wrong more often than the code it
verifies*. The round returned **9 findings, 7 in verification code**. Leg 1's five failures were
all harness. **Two production findings** — `kill(-1)` reachable as root from an unchecked
`fork()`, and the daemon orphaning shell + AI + session on any error path after `launch()`.

**Class 37 (remediation is where a class reappears) earned two in-round instances**: R5-04's
reproduction appeared inside R5-01's fix within a minute, and R5-08's vacuous assertion sat
inside the R4-03 test that R4-09 and R4-10 had each just repaired. It is recorded as a **search
rule** — *the highest-yield place to look for instance N+1 is the diff that fixed instance N* —
with Class 22's and Class 36's distinct foreclosures deliberately **not** merged.

---

## What was fixed, and the two worth checking hardest

**R5-01** — `preload.c` never checked `fork()`, so a failure published `impostor=-1` and
`driver.c` passed it to `kill(-1, SIGKILL)` **as root**. Guarded at source and sink (`atoi`
returns 0 for garbage, and `kill(0)` takes the process group), plus the same defect at
`reap_and_recycle`'s `victim` — the fourth Class 17 instance this arc.
**R5-03** — the daemon leaked shell + AI + logind session on every error path after `launch()`.
`ChildReaper` is RAII, armed after launch, disarmed where the success path takes over; coverage
verified **by enumerating** the fallible steps in the window rather than by assuming the timeout
was the only one.
**R5-04** — descendants inherit the daemon's pipes, so `wait_with_output()` waited for an EOF no
living process would send. `DaemonGuard` spawns into its own process group and tears the **group**
down. *Proven against a reproduction that R5-01's fix produced by accident, under `timeout`, in
a minute — after four runs of deliberate hang-chasing produced none.*
**R5-05** — leg 1's pre-gate false pass, above. **R5-02** — R4-01 moved the predictable name and
left the parent trusted; as root the parent is now `/run`, verified root-owned and
non-world-writable (`/tmp` is root-OWNED and would pass an ownership-only check).
**R5-06** — the seat *classifier* was tested and the *mapping* was not; swapping its arms stayed
green. **R5-07/08/09** — a VT assumed rather than measured, a gate assertion that passed because
the process was gone, the daemon's own anchor left behind. **R5-10/11** — the cfg seam defeated
by path sharing (`CARGO_BIN_EXE` resolves to a path, not a build), and the surface shell that
could never leave.

*The two I would check hardest: **R5-03**, because it is production and its coverage claim rests
on my enumeration; and **R5-11**, because the surface shell now depends on the daemon's terminal
contract producing an EOF, which couples a test binary to a production ordering guarantee.*

---

## Verification boundary

**R4-03 is fully discharged.** Both legs pass at root; leg 2's `Resolved` confirmed three times.
lib 84/84; `EXECUTED 121 / SKIPPED 22`; b1_integration 14; barrier **13/13 at root** including
R4-02's recycle-equality assertion; clippy rc=0 in both feature configurations.

**No lane-gated or root-gated obligations outstanding.** That claim has been wrong three times
on this branch — **check it rather than accept it.**

**The strongest teardown evidence came from the WORST run, not the passing one**: 0 daemons, 2
sessions, `/run/delphi` empty after a 150-second hang terminated by SIGKILL. `DaemonGuard` and
R5-09 survived the adverse path, which no clean pass could demonstrate.

---

## Defect classes — attention allocation

**Pre-foreclosed:** 1, 10, 25, 22, 34, 35, 36, 37.

**Spend the budget here:** **37** applied to THIS diff — R5-10 and R5-11 are both fixes to
fixes, so they are the highest-yield place for instance N+1. **17** — four instances this arc;
assume the reported instance is one of several. **27** — R5-11 couples the surface shell to the
daemon's terminal-contract EOF; if that ordering ever changes, a test binary wedges.

---

## Verdict

**APPROVE / REVISE / FAIL**; per finding: ID (`D0A-R6-NN`), severity, root cause, impact, fix
sketch.

**The judgement I most need is the LEAD** — whether leg 1 should keep its claim, be demoted to a
smoke check, or be reconsidered entirely. That is a design call where my incentives are wrong,
and it is the one thing in this round I would rather not decide alone.
