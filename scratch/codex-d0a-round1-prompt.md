# Codex adversarial review — D0-A round 1 (findings A3 + A1 + A2)

<!-- Invocation: codex review - < scratch/codex-d0a-round1-prompt.md
     All three range-selection flags reject a PROMPT positional; scope is carried here. -->

## Scope

**Three commits on `phase-3b/d0-readiness-contract`, reviewed as ONE unit:**

| commit | finding |
|---|---|
| `7592f48` | **A3** — the consent gate reads the verdict at the decision, not at startup |
| `903853a` | **A1** — the readiness contract states the property consent needs; **A2** — the pidfd resolves the session |

`git show 7592f48`, `git show 903853a`, then the live files. `git diff --shortstat 7592f48~1
903853a` reports: 11 files changed, 670 insertions(+), 128 deletions(-) — across `runtime/src/{logind,service,readiness,launcher}.rs`,
`runtime/src/bin/*.rs`, `runtime/tests/{b1_integration,leader_is_shell,common/shell_fixtures}.rs`,
`docs/READINESS_CONTRACT.md` and two `docs/DEFECT_CLASSES.md` entries. Report a mismatch as a
finding. `PROGRESS.md` and `scratch/` are out of scope except as claims cited here.

## Where these findings came from, because it changes what to look for

Seven Codex rounds and two lane runs preceded this, and none of them found A1/A2/A3 — **because
every round scoped itself to a diff**. D0-A asked a different question: *is what each CONSUMER
assumes what the contract ESTABLISHES?* All three findings are mismatches at that seam, not
defects inside any one change. So the most valuable review here is of **the seams between the
three fixes**, not of each fix alone.

## LEAD — the seam the sequencing was chosen to expose

**A2 rests on an invariant A3 establishes.** A3 replaced a stored `&dyn SessionVerdict` with a
`SessionSource` queried at each decision; **that is what made A2 a change *inside* the source**
(swap the handle it owns) rather than a rewiring of `launch()`. They were built in that order
and are sent together deliberately: a reviewer seeing them separately cannot check that seam.

1. Is `LogindSource<'a>` borrowing `children.shell_pidfd` sound for the daemon's whole service
   life? `ServiceCtx.session` is `&dyn SessionSource`; the `OwnedFd` lives in `Children`. Does
   any path drop or move `Children` while the source is live?
2. `pid_from_pidfd` reads `/proc/self/fdinfo/<fd>` on **every gate decision** — a `read` +
   parse per consent. Failure modes: `/proc` not mounted, a container hiding `fdinfo`, a
   truncated read. All currently deny. **Is fail-closed right at every one of them**, or does
   some deserve a distinct diagnosis instead?
3. The `Pid:` semantics are **measured, not assumed** (alive → pid, dead-unreaped → pid, reaped
   → `-1`; kernel 7.0.0-28, in the doc comment). Is that stable kernel ABI or an accident of
   this version? A `NSpid:` line also exists — is `Pid:` the right one inside a namespace?

## A3 — the frozen verdict

`LogindVerdict` snapshots three bools; `for_pid` ran ONCE at daemon start; the gate re-read
those frozen bools per request while a comment claimed a live re-check.

- The design rests on **tearing**: `session_passes_gate` reads three axes as three calls, so a
  per-method-querying impl could mix instants. Is the `SessionSource → Box<dyn SessionVerdict>`
  shape actually sufficient to prevent that, **or does it merely relocate it**? An impl can
  still return a lazily-querying object.
- The law is enforced by a permanent `#[should_panic]` test rather than a one-off weaken. **Is
  that test's `Advancing` fixture a fair model** of a source whose state changes, or does its
  alternate-on-every-read behaviour make the law easier to satisfy than reality?
- One consumer is now **three logind round trips per action** where there was one at startup
  (`gate_allows` at startup + per request). Any latency or D-Bus concern at consent time?

## A1 — two markers

`READY_DATAGRAM` = the surface claim; `SCAFFOLD_READY_DATAGRAM` = process-up; `LaunchSpec.ready`
declares the requirement; the weaker marker is refused where the stronger is required.

- **The enforcement is a marker a producer chooses to write.** A shell that signals at entry but
  writes the SURFACE marker is accepted. That is stated as intended (an explicit false claim in
  its own source, rather than an ambiguity) — **is that the right bar, or is there a cheap
  structural check available that we missed?**
- `MAX_MARKER_LEN` sizes the read buffer from the longer marker. Confirm neither marker can be
  truncated into a match of the other, and that the `+1` over-long detection still holds for
  BOTH.
- The daemon requires `SurfaceLive`. Every in-tree fixture declares `ScaffoldEntry`. **Is any
  production path left able to reach `launch()` with `ScaffoldEntry`?**
- The real shell's ready comes from the renderer's `{kind:"ready"}`, posted in the effect that
  registers `window.__delphiConsent` (`shell/src/consent/pam-consent-dialog.tsx:72`). **Does the
  host actually forbid native from signalling on its own** — i.e. is the strong claim structural
  on the production path, or also just a convention?

## Verification boundary — what is proven and what is not

- **Proven off-lane, executing:** A3 4 tests + 2 doctests; A1 4 tests; A2 1 two-legged test.
  Every weaken listed in the commit bodies was verified to have APPLIED **and to have failed at
  the line it names** — a rule added this round (Class 22) after A3's first weaken failed at the
  wrong assertion because a sibling test seeded a process-global `OnceLock`.
- **NOT proven:** of the four rewired `ServiceCtx` sites, ONE executed here
  (`terminal_contract_release_produces_eof_no_wedge`); the other three are root-gated and are
  compile-verified only. The 9 rewired `LaunchSpec` sites are likewise mostly root-gated.
- **NOT proven:** the daemon's own composition — `logind_source(children.shell_pidfd.as_fd())`
  through a real consent — needs the lane.
- Dev box: clippy rc=0 both workspaces (exit captured, never read through a pipe);
  lib 80/80; `EXECUTED 114 / SKIPPED 19`.

## Defect classes — attention allocation

**Pre-foreclosed, do not re-hunt:** Class 1 (truncation — the `+1` buffer and the prefix test),
Class 10 (skip-as-pass — `scripts/test-count.sh` + the CI equality gate), Class 22 (weaken
verified applied *and* located), Class 25 (fixtures captured, not invented).

**Applicable and NOT foreclosed — spend the budget here:** Class 26 (a captured observation read
as present-tense — A3 *is* this class one level up, and A2's `pid_from_pidfd` is a fresh read
whose result is used one syscall later, so the same asymmetry could recur inside it), Class 27
(two correct fixes whose INTERACTION is unsound — the A2/A3 seam above is exactly this shape),
Class 33 (a diagnostic naming one side of a comparison — A1's refusal message names the fault
and the consequence; does it name enough to act on?).

## Verdict

**APPROVE / REVISE / FAIL**; per finding: ID (`D0A-R1-NN`), severity, root cause, impact, fix
sketch. Where a finding is a claim rather than a defect, say what measurement settles it.

The judgement most worth your effort is the **A2/A3 seam** and the **A1 enforcement bar**: both
are places where I chose a level of rigour and could be wrong about the level, not about the
code. Say so plainly if the bar is in the wrong place.
