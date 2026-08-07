# D0-A — the readiness contract, audited as REQUIRES / ESTABLISHES / CONSUMES

Closing audit for increment D0. The question is not "does the code work" — seven Codex rounds
and two lane runs covered that. It is **whether what each consumer assumes is what the contract
actually establishes**, which no round asked, because every round scoped itself to a diff.

Everything below was read from the tree at `e977f41`; line references are live.

---

## REQUIRES — what must hold, that D0 does not itself establish

| # | Requirement | Established by | Enforced? |
|---|---|---|---|
| R1 | The binary at `LaunchSpec.shell_path` writes `READY_DATAGRAM` to `SHELL_CHANNEL_FD` | the shell author | **NO — a doc table only** (`launcher.rs:172`). Structural foreclosure explicitly deferred. A silent fixture times out 10 s from its cause. |
| R2 | The daemon drops its copy of `shell_end` **before** the wait | ordering in `launch()` (`launcher.rs:267`) | comment + ordering. Violating it turns a dead shell into silence and burns the full budget instead of returning at once. |
| R3 | `SHELL_CHANNEL_FD` survives `execve` | `fdsec` allowlist (FD-01) | yes, RED-proven |
| R4 | The pidfd names the shell and nothing else | `clone3(CLONE_PIDFD)`, no fallback (D0-R5-01) | yes, RED-proven (atomic leg + non-atomic twin) |
| R5 | The channel is `SOCK_SEQPACKET` | `approval_socketpair` | yes — `witness_terminal`'s datagram semantics depend on it |
| R6 | `DEATH_GRACE` (250 ms) exceeds death-evidence latency on the target machine | measurement on ONE box, ONE kernel | **NO — documented as a bet** (`readiness.rs:50-58`). A machine that misses it degrades to a **false READY**. |

R1 and R6 are the two that are not enforced by anything. Both are recorded in-source as known.

---

## ESTABLISHES — what `launch() -> Ok` actually means

**"The shell process was alive at the instant it wrote a byte-exact `READY_DATAGRAM`."**

Three limits, all narrower than the phrase "the shell is ready" suggests:

1. **Point-in-time, not durable.** Nothing is guaranteed about the instant `Ok` returns. Between
   the marker and `Ok(Children)` sits `fork_ai` (`launcher.rs:277`) — an `execve` of another
   binary. A shell dying in that window is reported started. This is inherent: a liveness check
   cannot outlive its own observation. The durable handle is `shell_pidfd`, and **nothing polls
   it** after launch.
2. **The meaning is PRODUCER-DEPENDENT, and the doc states the weakest one.** `readiness.rs:12`
   says "it means the process reached the marker". That is true of `delphi-minimal-shell`
   (signals at entry, `bin/delphi-minimal-shell.rs:29`) and of the C sleepers. It is **not** what
   the real shell does: `delphi-shell` signals only when the *renderer* posts `{kind:"ready"}`
   (`shell-host/src/main.rs:357`), which `pam-consent-dialog.tsx:72` sends from inside the same
   effect that registers `window.__delphiConsent`. The real signal therefore carries a strictly
   stronger claim: *a consent request delivered now will reach a live surface.*
3. **Version-exact, not prefix.** `READY_DATAGRAM` is compared whole, so a future tightening is a
   distinguishable marker rather than a silent reinterpretation.

---

## CONSUMES — who depends on it, and on which strength

| Consumer | Assumes | Gets | Match? |
|---|---|---|---|
| `launch()` — forks the AI only after ready | the boundary exists before the AI can call it | exactly that | ✓ |
| `consent_relay` → the shell's dialog | **the surface is registered** (strength 2) | the *documented* contract promises only "process alive" | **✗ — see A1** |
| `delphi-runtimed` — `logind_verdict(children.shell_pid)` (`:128`) | a live pid it can resolve to a session | a raw **pid**, while a race-free `shell_pidfd` sits unused beside it | **✗ — see A2** |
| `serve_one_action` — the consent gate (`service.rs:148`) | "active AND local AND seated", re-evaluated per request | three booleans **frozen at daemon startup** | **✗ — see A3** |

---

## Findings

### A1 — the contract is documented at its weakest producer while a consumer needs its strongest

The relay's precondition (a registered surface) holds today **only because**
`pam-consent-dialog.tsx:72` happens to post `ready` inside the registration effect — an
invariant living in a TSX comment, not in the contract. `readiness.rs:12` explicitly licenses
the weaker reading, so a future shell that signals at process entry would satisfy `launch()`
and silently break the relay: requests hit an unregistered surface and are dropped, presenting
as a hung or denied consent far from its cause. That is D0-R1-01's defect returning through the
contract's own wording.

**RESOLVED.** The contract in `readiness.rs` now states the property the relay depends on —
*a consent request delivered now will reach a live surface* — and says what a producer must do
to satisfy it: signal **after** the point where an inbound request stops being discarded.

The enforcement is a **second marker**, not a doc. `READY_DATAGRAM` is the surface claim;
`SCAFFOLD_READY_DATAGRAM` is "the process is up". `LaunchSpec.ready` declares which the caller
requires, and a scaffold marker where `SurfaceLive` is required is refused by name. **A shell
signalling at process entry is therefore visibly non-conforming**: it either writes the weaker
marker and is refused in production, or writes the surface marker while having no surface —
an explicit false claim in its own source rather than a gap a reader must notice. The prose
table of which fixtures signal (`launcher.rs:172`) is replaced by the field; every fixture in
the tree now declares `ScaffoldEntry`, and the daemon declares `SurfaceLive`.

**Proofs** (`runtime/src/readiness.rs`): the refusal fires and names both the fault and its
consequence; **the same marker is ACCEPTED under a scaffold requirement**, so the refusal is
about the REQUIREMENT and not about the scaffold marker being unparseable — without that leg
the first test passes just as happily for a parsing bug; the surface marker satisfies both
requirements; and neither marker is a prefix of the other, so a truncated read cannot match the
shorter. Weaken (a) — drop the requirement check → the refusal test fails at its named line.
Weaken (b) — respell the scaffold marker as a suffix of the surface one → the prefix test fails.

### A2 — the race-free handle is obtained and then not used

`launch()` returns `shell_pidfd`, the whole point of D0-R5-01's atomic `clone3`. The daemon then
resolves the session with `logind_verdict(children.shell_pid)` and later `waitpid` on the same
raw pid. Today this is safe *by accident of B1's shape*: nothing reaps the shell before those
calls, so the pid cannot be recycled. **P4 (the long-lived service loop) is the increment that
removes that accident** — a loop that reaps and relaunches makes the pid recyclable between
resolution and use.

**RESOLVED — but NOT by what this paragraph first said.** The original fix resolved the pid
through `/proc/self/fdinfo/<fd>` at each `current()` and denied on `Pid: -1`. **Codex D0A-R1-01
found that still race-prone**: reading a number and then looking it up are two operations, and
the pid can be reaped and reused between them. `LogindSource` now binds
`sd_pidfd_get_session`, so **no pid number crosses between operations at all**;
`pid_from_pidfd` survives only as a diagnostic no decision consumes. A3's shape is what made
both versions a change *inside* the source rather than a rewiring of `launch()`.

The `fdinfo` measurement below is kept because it is still true and still the reason the
diagnostic is trustworthy — but it is no longer the resolution path.

**MEASURED, not assumed** (kernel 7.0.0-28): `Pid:` reports the pid while the process is alive,
**still reports it while dead-but-unreaped**, and reports **`-1` once reaped** — which is
precisely when the pid becomes recyclable. `None` here and "this number may now name someone
else" are the same instant.

**Proof**: both legs, because "denies after reaping" passes on an unseated dev box for the wrong
reason — nothing resolves to a session there at all. The discriminating claim is about the pid
RESOLUTION: `Some(child)` while alive, `None` once reaped. Weaken — accept `-1` as if it still
named the process — fails with `left: Some(1)`, i.e. **the reaped shell resolves to init's
session**, which is the impostor case in its most literal form.

### A3 — the gate's dynamic axis is frozen, and a comment asserts otherwise

`LogindVerdict` is a **snapshot** — three `bool`s captured by `query()` (`logind.rs:79-83`).
`for_pid` is called **once**, at `delphi-runtimed.rs:128`. `ServiceCtx.session_verdict` holds
that snapshot and `session_passes_gate` re-reads the same frozen booleans per request.

`delphi-runtimed.rs:132-137` states the opposite in as many words — *"the gate re-checks it per
request"*, *"the `active` axis is dynamic (foreground), not a static config error"*. **The
re-check does not exist.** `active` tracks which VT holds the seat's foreground; frozen, it
answers a question about daemon-start time forever.

**Today's blast radius is one action.** B1 services exactly one action and exits
(`delphi-runtimed.rs:152`), so snapshot and live verdict differ by milliseconds. **P4 is the
increment that makes it a real gate weakness**: a session that stops being foreground keeps
passing the presence check that exists to prove a human is at the seat. PAM still stands behind
it, so this is a weakened gate, not a bypass.

There is a second consequence worth naming because it has already cost diagnosis time: under a
frozen verdict, a `chvt` **after** daemon start cannot flip `active`. The dev SECONDARY shape's
gate-POSITIVE was understood to be reachable by switching to the shell's VT; it is not, and that
is an additional blocker independent of the display one P3b is attributed to.

**RESOLVED.** `ServiceCtx` now holds a `SessionSource`, and `service::gate_allows` — one
function, one site — reads `source.current()` at each decision. `LogindSource` re-queries
logind per call and fail-closes on an unresolvable session; `FixedVerdict` is both a verdict
and a source of itself, so the tests and the insecure seam need no adapter.

**Why a source rather than a live-querying `SessionVerdict`.** `session_passes_gate` reads the
three axes as three calls, so an impl that queried per method could **tear**: `active` from one
instant, `seated` from another, producing a verdict that never described any actual moment.
**This is `DEFECT_CLASSES` 26 one level up** — R2-01/R2-01b/c were a captured `revents` reused
after a syscall; this is a captured verdict reused across the decision it authorizes. Same
asymmetry, different altitude.

**CORRECTION (D0A-R1-04), because A3 shipped with two claims that did not hold.**

1. *"One `current()` per decision yields a triple that was simultaneously true."* **False, and
   withdrawn.** `SessionSnapshot::query` makes THREE separate libsystemd calls
   (`sd_session_is_active`, `sd_session_is_remote`, `sd_session_get_seat`) — logind offers no
   atomic read of the three. The honest guarantee is **three reads in immediate succession**: a
   VT switch landing between them yields a mixed triple, the window is the span of two library
   calls, and the next decision re-reads from scratch. Stated rather than claimed away.
2. *The simultaneity "law" was enforcement.* It was **convention**. `current()` returned
   `Box<dyn SessionVerdict>`, so a lazily-querying impl was still expressible, and the
   `#[should_panic]` test policing it exercised a permanently-separate fixture — making the
   PRODUCTION source lazy would have left the suite green.

Both are closed by `current()` returning a concrete `SessionSnapshot`. The tearing shape is now
**unrepresentable**, so the type is the law and the fixture and its test are deleted.
**Codex's settling weaken — make the production `LogindSource` lazy per axis — no longer
compiles** (`E0053: method 'current' has an incompatible type for trait`). A weaken that fails
to COMPILE forecloses the class rather than detecting an instance of it, which is the stronger
outcome and the one to record.

**Proofs** (`runtime/src/logind.rs` tests):

- *both flip directions*, and which one is the security property: **true → false is the
  dangerous one** — the seat's foreground moved away and a consent minted after that point is
  one no human at the seat authorized, which is exactly what R3-02's `active` axis exists to
  prevent. false → true is a false DENY: annoying, never dangerous, and it is what lets a
  `chvt` to the shell's VT take effect without a daemon restart.
- *the guarantee, at its real width* (**corrected, D0A-R2-06** — this bullet previously
  described a "simultaneity law" enforced by a `#[should_panic]` test, and both are gone). The
  concrete `SessionSnapshot` forecloses **consumer-side** laziness: a caller gets three `bool`s
  already decided and cannot re-read one axis between the gate and the mint. It does **not**
  foreclose **producer-side** tearing — `query_detailed` still makes three separate libsystemd
  calls, since logind offers no atomic read — so a VT switch between them yields a mixed triple.
  The window is two library calls wide and the next decision re-reads. The `#[should_panic]`
  law was deleted because the type replaced it: the settling weaken no longer compiles.

**Measured.** Weaken (a) — freeze the verdict (`OnceLock` memo, the pre-A3 semantics) → the
flip test fails at the true→false leg, naming it: *"a stored verdict is what makes this ALLOW,
minting consent while the seat points elsewhere."* Weaken (b) — weaken the law's assertion to a
tautology → the tearing case stops panicking and the `should_panic` test fails, proving the law
is what catches tearing rather than the harness.

**SUPERSEDED (D0A-R2-06 / R3-05).** Both weakens above describe a `#[should_panic]` law that
**no longer exists**: D0A-R1-04 replaced it with the type, and the settling weaken now fails to
COMPILE rather than to run. The paragraph is kept because it records what was measured at the
time — but as history, not as a live proof. Nothing in the tree today can produce those two
results.

**A decision whose premise was false is now a decision whose premise is true.** When review
asked for an abort on a false startup verdict, the accepted counter-argument was *"the `active`
axis is dynamic and the gate re-checks per request"* — and the gate did not re-check. The
conclusion survives on its other half (aborting would false-positive on the dev SECONDARY shape
and on boot races), but it survives for a reason that now holds. **A decision resting on a false
premise and a decision resting on a true one are different objects even when they reach the same
answer**, and only the second is one a later reader can rely on.

**Consequence for P3b:** a `chvt` after daemon start now flips `active`, so the second blocker
this finding surfaced is removed. P3b remains blocked on the display path alone.

---

## What this audit does NOT cover

The contract's behaviour under a **compositor** (D1–D5). Readiness currently means "the shell
said so over a socket"; once a display exists, "ready" plausibly wants to mean "its buffer
reached scanout". `readiness.rs:12` already flags that tightening as needing D2/D4. Nothing here
forecloses it — the version-exact marker is what keeps that change honest.
