# Conformance register — where the tree does not satisfy `docs/TRUST_MODEL.md`

**`TRUST_MODEL.md` is normative and is NOT edited to match the code.** Marking a ratified clause
"unimplemented" inside the normative text would weaken the invariant until the mismatch
disappears — the move the weaken/restore discipline forbids for a test, applied to a document.
The document keeps asserting the standard; **this register carries the delta.**

Every row: the clause, the finding that found it, the commit at which the gap was measured, and
what closes it. A row leaves only when a test proves it closed.

---

## Opened 2026-08-12 — D0-A round 9 (verdict: **FAIL**, 6×P1 3×P2)

Found by a scope pivot to `execute.rs` / `sandbox.rs` / `fdsec.rs` — paths last reviewed in June,
under a threat model the following eight rounds sharpened. **These defects are on `main`** (B1
merged at `f5b823d`); D0-A did not introduce them, it found them. Measured at `09dadae`.

| § | ratified clause | status | finding | closes when |
|---|---|---|---|---|
| §6 | "the tool runs under a uid that **cannot reach daemon IPC**" | **TWO SEPARATE PROOFS, cited separately (2026-08-16) rather than one test standing for both.** **(1) Credential state** — `an_approved_action_runs_with_the_tool_account_credentials` reads the action's own `/proc/self/status` at root: `Uid:` and `Gid:` all four fields (real/effective/**saved**/fs) equal `delphi-tool`\'s, `Groups:` empty, `CapEff:` zero. It previously observed `id -u` alone and was cited for six things; widened, and renamed to stop claiming the sixth. **(2) The socket refusal** — P\'s production leg, refused at `0660 root:<session-gid>`, **measured against a probe fixture, not the real daemon**. Neither proof covers the **pre-drop window** (D0A-R10-12) | D0A-R9-01 | **remaining:** the socket refusal is measured against the real daemon rather than a fixture |
| §6 | "**seccomp default-deny**" | **ABSENT** — no `--seccomp` anywhere in `sandbox.rs` | D0A-R9-05 | a policy is attached and a denied syscall is proven denied |
| §6 | "**cgroup v2 mem/pids/CPU caps**" | **ABSENT** | D0A-R9-04 | caps applied and a breach proven contained |
| §6 | "**timeout + kill-on-expiry**" | **ABSENT** — `action.timeout` is unenforced | D0A-R9-04 | an over-running action is killed, RED-proven |
| §6 | "mount exactly `fs_binds`" | **PARTIAL** — bind sources are **path-resolved at launch**, so a symlink swap substitutes scope | D0A-R9-03 | binds resolve to what was approved, TOCTOU-proven |
| §7 | audit "carries … result" | **CORRUPTIBLE** — a bwrap SETUP failure exits nonzero and is recorded as the action having run and failed, when it never ran. **Not a bypass**: `execute.rs:175` is the only production spawn (everything else is after `#[cfg(test)]`), and a missing bwrap is a hard error | D0A-R9-07 | setup failure and tool exit are distinguished in the audit entry |
| §6 | "the daemon's socket is a root-owned filesystem socket **outside the jail's mount set**" | **UNENFORCED** — `sandbox.rs:60` binds exactly what was approved with **no path denylist**, so an action may name `/run/delphi/…` and place the socket *inside* the mount set. Distinct from R9-03: that is TOCTOU on *resolution*; this is that nothing forbids naming the target at all | **D0A-R9-10** (found while verifying, not in the review) | **CLOSED 2026-08-15** — `sandbox::refuse_denied_bind` refuses every spelling (lexical fold + canonicalize), wired at the `run_fd_pinned` choke point, with a positive control. Both weakens bite: removing the call site lets execution reach bwrap (`bwrap: Can't find source path /run/delphi/alice` — it would have BOUND it where the path exists); removing traversal folding fails `/tmp/../run/delphi/alice` |

## THE ROOT LANE — WHAT IT PROVED, AND WHAT IT COST TO FIND OUT (runs 3–6, 2026-08-24/25)

**Standing after run 6: 17 targets, 0 failures, 0 skips, 0 leaks, PAM stack intact.** Sixteen
of those seventeen targets had never executed at root before run 3.

| property | standing |
|---|---|
| the approved environment reaches the tool **on the far side of the drop** (D0A-R15-01's gradient branch) | **PROVEN** at root — one artifact carrying `Uid: 997 997 997 997` **and** `DELPHI_SECRET=s3cret-value`, fd 11 carrying the sealed env |
| the drop helper the daemon runs is the one it was built against | **PROVEN** at root — built and installed agree at `aba0f0ea14b751aa…`, and the first time the digest binding refused a *legitimate* change rather than an attack |
| every `b1_integration` / `end_to_end` / `divergence` root path | **PROVEN** — 0 failures, and **0 skips**, so nothing closed by ceasing to run |

### The root EXECUTED figure is still NOT recorded, deliberately

`0 skips` and `169 reported` unprivileged would give `EXECUTED=169` at root by arithmetic.
**That is two measurements and a subtraction, not a measurement**, and it is the move that put
`EXECUTED=141 SKIPPED=0` in the baseline as an expectation nobody had run. The figure gets
recorded when `scripts/test-count.sh` runs at root and prints it. Until then this file records
the shape (17 targets, 0 failures, 0 skips) and not the number.

Superseded and not to be cited: run 3's `159 passed / 8 failed` (17 targets, first whole-suite
measurement) and its lib-only predecessor `112 passed / 1 failed`, which covered one target of
seventeen because the procedure said `head -1`.

### EIGHT FAILURES, FOUR CAUSES, ONE SIGNATURE — the record, because the shape recurs

`8 → 5 → 2 → 0`. Each run shed one cause and exposed the next, and **three of the four
presented identically** as `left: ""` — an empty marker, no error, no denial:

| run | cause | why it was invisible until then |
|---|---|---|
| 3 | fixtures never planned credentials | `#[cfg(test)]` helper cannot exist for an integration test, so the lib fix could not generalise |
| 4 | out dirs not chowned to the planned tuple | the action runs as `delphi-tool` and fails INSIDE the jail, so it never surfaces as a permission error |
| 5 | a second chown instance in a funnel run 4's fix did not reach | the file-granular guard asked whether the FILE chowns, not whether THIS fixture does |
| 5 | a fixture building an action production cannot (plain fd, fake digest) | `unwrap_or_default()` collapsed a correct refusal into an empty string |

**All four were latent, none regressed.** Every one had been present since its code landed and
was waiting for an environment nobody had used — the class-20 shape, four times in one arc.

**The durable fix is not any of the four.** It is that the fixtures now assert the **result
before the marker**, so a fifth cause names itself instead of costing three inferences. And
the enumerating guard, whose record is now decisive: seal check found 9 fixtures, digest check
2, credential guard 7, chown guard 5 — **reading found 0.**

## SUPERSEDED CLAIMS FROM `docs/TRUST_MODEL.md` §3 (relocated here 2026-08-23, D0A-R15-02)

**Why they live here.** A normative document's one job is to let a reader tell what is
required. Struck-through history in §3 made the reader distinguish preserved-falsified text
from active requirement, so the narratives moved and §3 keeps a pointer. The trail survives;
the requirement text does not carry it.

### NAMED LIMIT 2 — the dynamic loader as an immutable platform TCB member

**Claimed** (2026-08-22, v7): the dynamic loader and system libraries are an immutable
platform TCB member, so the chain past the first object needs no binding.

**Falsified** (2026-08-23, D0A-R14-01): an approved binary **names its own `PT_INTERP`**, so
it selects a loader the operator never placed. A controlled probe replaced that loader after
sealing and changed the code that executed.

**Struck, not softened.** A declaration the attacker can invalidate is not a weaker boundary;
it is not a boundary. It stood for one day.

### THE STATIC-ELF CLOSURE CLAIM — "no downstream hops: no `PT_INTERP`, no interpreter, no handler"

**Claimed** (2026-08-23, in the same amendment that struck limit 2): for a statically linked
native ELF, first-object binding and total binding are the same statement.

**Falsified** (2026-08-23, D0A-R15-02): `binfmt_misc` dispatch is a property of the KERNEL,
not the file. A handler can match `\x7fELF` magic and be selected before the native ELF
handler, reintroducing the unbound interpreter hop; an `F`-flagged handler holds its
interpreter open across mount changes. Static linkage removes the two hops that live in the
file and cannot remove the one that lives in the kernel.

**Narrowed, not struck** — the configuration is still the best available, stated with the
precondition it actually needs: no matching handler registered, which a deployment can enforce
and this runtime does not check.

### THE PATTERN, WHICH IS THE POINT OF LISTING THEM TOGETHER

**Three §3 amendments in three consecutive rounds, every one found by MEASUREMENT and none by
rereading.** The author's model of the mechanism is the model that produced the sentence, so
rereading cannot catch it — this is structural blindness, not inattention.

**The narrowing claims survived; the totality claims did not.** "v7 binds the first object"
has held under every probe. "Immutable platform TCB member", "no handler", "everything
downstream is pinned" each failed within a round. §3 is now written under the rule that
follows from that: **it states what is bound, never what is unreachable** — because a claim
about the absence of a path is a claim about the whole kernel, which nothing here can measure.

## STANDING — PROVEN / DECLARED / **FALSIFIED** (three states, 2026-08-23)

The distinction this file exists to keep, and it needed a **third** state the day after it
was written: D0A-R14-01 produced the first **falsification** — a property this document had
listed as *declared* and which measurement then removed. A two-state table would have
absorbed that as a quiet edit to a "declared" row. It gets its own column so the next one
cannot.

**The three states are not degrees of confidence. They are different kinds of claim:**
*proven* is a measurement, *declared* is a trust decision we are making openly, and
*falsified* is a statement that was made and is now known to be untrue.

| property | standing |
|---|---|
| the action runs as `delphi-tool` — all four uids/gids, empty `Groups:`, `CapEff` zero | **PROVEN** (root lane 2026-08-22: `Uid: 997 997 997 997`) |
| bytes written behind a pinned inode do not execute | **PROVEN** at root, through production canonicalization with a real ELF |
| the drop helper is the one this daemon was built against | **PROVEN** at root — the digest binding fires; built/installed/staged hashes matched |
| the credential plan reaches execution (R12-08) | **PROVEN** at root (18 passed / 0 failed) |
| a **literal** nested `#!` interpreter never reaches execution | **PROVEN** at canonicalization — refused before any exec |
| the snapshot is executable regardless of the source's mode (R14-04) | **DECLARED POLICY** — adopted deliberately; a 0644 source yields a runnable object, and `noexec` on the source mount does not stop an approved action |
| **the loader and system libraries are immutable** | ~~DECLARED~~ → **FALSIFIED 2026-08-23 (D0A-R14-01).** An approved binary names its own `PT_INTERP`; a probe replaced the loader after sealing and changed executed code. **Struck from §3**, not qualified — a declaration the attacker can invalidate is not a boundary |
| the execution CHAIN is bound (loader, `env`+`PATH`, `binfmt_misc`) | **ACCEPTED GAP, three hops named in §3** — v7 binds the FIRST OBJECT only. Closure is available **by construction** (a statically linked native ELF has no downstream hops), not by a computation of ours |
| the pre-drop window is **SHORTENED** (D0A-R10-12) | **MITIGATION IMPLEMENTED + duration MEASURED (2026-08-25).** `--cap-drop ALL --cap-add CAP_SETUID --cap-add CAP_SETGID` on the payload; window ~9–11 ms attributable, bind-count-driven, depth-independent. **Shortened, NOT closed** — bwrap's own setup still runs with the full set, and that phase is unmeasured (the census samples after it) |
| the pre-drop payload's BOUNDING set is narrowed | **OPEN — own row, split out of D0A-R10-12 (2026-08-25).** Measured: the R10-12 fix leaves `CapBnd = 000001ffffffffff` at both the payload and the tool. Left inside R10-12 it would let that row close with a named property still standing |
| the socket refusal (R9-01's second half) | **FIXTURE-MEASURED**, not against the real daemon |

**Why the gap is accepted rather than closed** (the decision, so it is not relitigated as an
oversight): computing a dependency closure adds a mechanism to the surface that has produced
findings in **seven consecutive rounds**, and a closure that misses an element fails
**silently at exec** — D0A-R9-02's own shape, reintroduced in service of a claim no
deployment has needed. Refused deliberately.

**The lane run's hygiene, since a root run that mutates what it does not own is worse than
no run:** PAM stack unchanged (`md5sum -c` OK), no stale sessions, 0 leaked daemons, and the
test binary proven current by a forced rebuild with an unchanged sha (`fb8c6c123685…`) rather
than by mtime — the rule that was systematically wrong for hook-built binaries.

**CLOSED — D0A-R9-06 (2026-08-23).** `env_delta` no longer transits argv. `--setenv K V`
published every approved value in `/proc/<pid>/cmdline` — world-readable for as long as bwrap
lived — while satisfying §6's "scrubbed to `env_delta`" in public. The environment now travels
on the `Command` (`env_clear` + `envs`), so bwrap inherits exactly the delta and passes it on;
`--clearenv` went with it, since it would wipe what we are handing over.

**Measured before it was written** (`Command::env_clear()` does not break bwrap's own PATH
lookup, and a payload under this shape sees exactly the delta). **Both halves are asserted,
because one alone passes with the defect:** the value must ARRIVE (a real bwrap run reads the
tool's environment and finds `DELPHI_SECRET=s3cret-value`, with none of the daemon's) and must
NOT be in argv. Weaken — restore the `--setenv` loop — and the second fails, printing the
command line with `s3cret-value` in it.

**Fixed rather than excepted.** This file committed to recording an "explicit dated exception
to Iron Law #2" if R9-06 were still open at the next merge to `main`. An exception is a dated
admission that a known defect ships; taking one for something fixable inside the same review
window is the worse trade, so **no exception is recorded and none is owed**.

**CLOSED — D0A-R9-02 (2026-08-22), and the row is removed per this file's own rule.**
§3's clause now holds because the contract changed to match what a mechanism can actually
deliver: **TRUST_MODEL v7** binds an **immutable content snapshot**, not a filesystem object.
`seal_executable_snapshot` copies the bytes into `memfd_create(MFD_EXEC | MFD_ALLOW_SEALING
| MFD_CLOEXEC)`, applies **and verifies** `F_SEAL_SEAL | F_SEAL_EXEC | F_SEAL_WRITE |
F_SEAL_FUTURE_WRITE | F_SEAL_SHRINK | F_SEAL_GROW`, and `execute` re-checks the seals at the
choke point every execution passes rather than trusting the constructor.

Both reviewer reproductions are green, and both were REBUILT before they were fixed
(D0A-R13-01): the same-inode case now runs through **production canonicalization** with a
real ELF, because the shebang fixture it used tested a shape `canonicalize` never
produces — it would have been an unsafe acceptance criterion. The nested case became a
**rejection** test: a nested shebang is refused at canonicalization (v7 named limit 1)
rather than substituted at exec.

**The helper is covered, which this row required before it could close.** `build.rs` hashes
the helper it just built and embeds `DELPHI_DROP_DIGEST`; the daemon refuses a
`/usr/libexec/delphi-drop` whose bytes are not that digest, then executes a sealed snapshot
of them. Weaken-proven: with the comparison neutered, a one-bit-modified helper is accepted.

**Two residuals, both named rather than implied.** A sealed **dynamic** ELF still resolves
its loader and DSOs by path. This paragraph originally called that "a DECLARED immutable
platform TCB member"; **D0A-R14-01 falsified the declaration the next day** and it is struck
from §3 — see the standing table above. What remains is an **accepted gap** with three named
hops, not a boundary. And the helper path and credential drop execute **only at euid 0**, so
everything above is the unprivileged half; the root lane is owed (class 20 — the gap that
made seven tests silently non-representative for 15 commits).

**CLOSED — D0A-R9-11 (2026-08-15).** The daemon now refuses to serve a **system account**
before the anchor: `uid == 0`, or outside the system's own `UID_MIN..=UID_MAX` from
`/etc/login.defs`. Rejected as a **class**, not an instance — `UID_MIN` alone would have admitted
`nobody` (uid 65534, above `UID_MIN` **and** above `UID_MAX`, which is the bound that excludes
it). Both weakens verified to bite: removing the guard call makes the integration test fail with
`got: Error: establishing the root-owned runtime directory` — the daemon proceeding past user
resolution, which is the breach; narrowing the guard to `uid == 0` makes the class test fail on
`daemon`/`bin`/`nobody`. Paired with a positive control so "root is refused" cannot be confused
with "everything is refused". The row is removed from the table above per this register's rule
that a row leaves only when a test proves it closed.

**OPENED 2026-08-15 — D0A-R9-12: actions have no isolation FROM EACH OTHER.** Recorded as its
own item, deliberately **not** folded into R9-01, because E does not solve it and must not be read
as having done so. Under E every action runs as the **same** `delphi-tool` uid, so two actions —
or one action and a later one — can signal each other, and anything one leaves owner-writable is
reachable by the next. This is **better than today** (they currently share *root*) and **worse
than nothing shared**. It is a different problem with a different fix (a per-action uid, which
`DynamicUser=` cannot supply here for the reason already recorded above). Not a §6 clause
violation — §6 says nothing about inter-action isolation — so it is logged here as a known gap
rather than a conformance delta. **Closes when** two concurrent actions are proven unable to
observe or signal each other.

**NOT a §6 change (checked 2026-08-15, before implementing E).** §6's only namespace clause is
**network** (`--unshare-net` / `--share-net`, line 662); nothing in it mandates a *user*
namespace. `--unshare-all` was an implementation choice in `sandbox.rs`, never ratified text. So
adopting E **closes** the line-665 clause ("the tool runs under a uid that cannot reach daemon
IPC") and **violates none** — it creates no new row here.

**THE E TRADE, RESTATED HONESTLY (2026-08-16, D0A-R10-03).** The previous two versions of this
entry were both wrong, in the same direction, and the second was written while *correcting* the
first. Superseded rather than edited, so the drift is visible.

**What was measured and still holds:** bwrap's own userns maps `sandbox_uid → parent_uid`, so at
root the jail was `INNER 0 / SO_PEERCRED 0` — **identity**-transparent. That measurement is sound.

**What was inferred and never examined:** that identity-transparency meant the namespace "contained
nothing". It did not. **Capabilities are relative to a user namespace.** A process in a child
userns holds a full capability set *in that namespace*, but the kernel checks against the userns
that **owns the resource** — so capabilities never reached initial-namespace objects, whatever the
identity map said. `--unshare-all` was supplying a **capability boundary independent of identity**,
and E removes it. bwrap under real root retains the caller's capabilities through setup, so under E
that code runs with **initial-namespace** capabilities.

**So E is a TRADE ACROSS A TIME BOUNDARY, not a dominance:**

| window | before E | after E |
|---|---|---|
| **pre-drop** (bwrap setup + `delphi-drop` up to `setresuid`) | uid 0, capabilities confined to a child userns | uid 0, **initial-namespace capabilities** — *more powerful* |
| **post-drop** (the tool — the long-lived part) | uid 0 with userns-confined caps | uid **997**, caps dropped with the uid — *less powerful* |

"Strictly better on the escape axis" and "an escape lands on root exactly as before" are **both
false**. E improves the window that lasts and worsens the window that is short. That may still be
the right call — the tool is the untrusted part and the setup is code we ship — but it is a
judgement, and the reasoning that chose it was incomplete.

**A THIRD WINDOW NEITHER R9-01 NOR §6 COVERS.** R9-01's mechanism is *the tool runs as
delphi-tool*; §6's clause is *cannot reach daemon IPC*. The **pre-drop window** is neither, and it
is now the more powerful of the two states. It has no row, no test, and no owner.

**AND R9-01's PROOF IS NARROWER THAN ITS ROW CLAIMS.** The root test observes `id -u` and nothing
else: **not gid, not supplementary groups, not saved ids, not capabilities, and not the daemon-IPC
refusal that is the actual clause.** The gap between "mechanism closed" and "clause closed" is
therefore wider than recorded, and `997` was read from a test that proves one of six things it is
cited for.

**OPENED 2026-08-16 — D0A-R10-12: the PRE-DROP window runs with initial-namespace
capabilities.** Its own row deliberately: it is neither R9-01's mechanism (*the tool runs as
`delphi-tool`*) nor §6's clause (*cannot reach daemon IPC*), and folding it into either would
hide it.

**What is true.** Under E, `bwrap`'s setup and `delphi-drop` up to `setresuid` execute as
initial-namespace root **with capabilities that are no longer confined to a child user
namespace**. Before E the same code held caps only within bwrap's userns, where
`ns_capable(init_user_ns, …)` fails for initial-namespace objects. This is a **real enlargement of
the pre-drop TCB's power**, not a bookkeeping change.

**Why it is accepted.** Both occupants are shipped, root-owned, installer-placed components —
the same trust class as `delphi-runtimed` itself. The decisive asymmetry is *whose code occupies
each window*: **pre-drop holds code we wrote; post-drop holds code the user approved**, and the
consent apparatus exists to constrain the latter. Strengthening an attacker's position inside our
own code to weaken it inside the user's is the right direction — **and it is a trade, not
dominance.**

**The mitigation is NAMED AND UNIMPLEMENTED, which is what keeps this from being a
rationalization:** restrict the helper payload to the minimal `CAP_SETUID`/`CAP_SETGID` set. A
named unimplemented mitigation is an obligation; an unexamined acceptance is a hole.

**The reviewer's alternative — retain a mapped user namespace — is NOT available**, and is
recorded as closed rather than unexplored: that is leg F, abandoned after three harness failures
(path-instead-of-fd, then `EOVERFLOW` from bwrap's newroot setup wanting an id outside a
single-entry map). It was never falsified, only unmeasured.

**Closes when** either the helper runs with the minimal capability set, or the window is measured
and the trade re-decided against that measurement.

### RESOLVED 2026-08-25 — both conditions met, and the row is narrowed rather than closed

`scratch/d0a-r10-12-window-probe.sh`, six legs, zero skips, on the privileged path.

**DURATION.** ~9–11 ms attributable (window minus the payload's own exec chain), ~17–20 ms
wall. Driven by **bind count** (~1.7 ms/bind), **not by ancestor-emission depth** — depth 1
vs 8 does not move it, across three runs. The obligation's specific worry is falsified.

**PLACEMENT, forced by measurement rather than chosen.** Daemon-side is impossible (dropping
the bounding set before bwrap → `Creating new namespace failed: Operation not permitted`;
bwrap needs `CAP_SYS_ADMIN`). The permitted/effective lever does not exist in general: a root
`execve` recomputes `P'(permitted) = F(permitted) & P(bounding)`, and with `F(permitted)`
all-ones for the root case that restores the full set. bwrap's payload-side
`--cap-drop`/`--cap-add` is the only seam that both restricts and holds.

**IT BITES, AND ON SOMEONE ELSE'S DEFAULT.** `c0` survives a further root exec under the
restriction; the control returns `000001ffffffffff` without it. It holds only because bwrap
sets `no_new_privs=1` — unconditional, ungoverned by any flag, and **theirs, not ours**. If
that changed, the profile would still emit the flags, the immediate state would still read
`c0`, and the property would be gone with nothing failing. **Class 42 with a name attached.**
So the guard asserts the state **after a further exec**, never the immediate state, and
carries the control that makes it discriminate.

**THE WINDOW'S SHAPE WAS ALSO WRONG HERE.** The census (corrected — the first version sampled
a bash subshell that, being root, showed an identical cap set and could not discriminate)
reads `CapPrm/CapEff = 0` for bwrap while its payload lives: bwrap drops its own capabilities
after setup. The privileged span is bounded by **setup**, not by the tool's lifetime — a
materially smaller exposure than this row asserted.

**WHAT DID NOT CLOSE.** The tool's bounding set is still full. Split into its own row above.

### THE GUARD'S EVIDENCE IS A PROBE PAIR, NOT A RED — recorded as a limit (2026-08-25)

`the_predrop_payload_cannot_recover_capabilities_across_a_further_exec` is **stable**
(30/30 under default parallel, suite-wide clean) and **not weaken-proven**, and the second
half is a property of the subject rather than a gap in the work.

**The available weaken is the wrong weaken.** Removing the flags makes the "restricted" leg
*become* the control — both are then unflagged bwrap invocations that cannot differ. The
first attempt returned `WRONG ASSERTION — both legs read alike`, which is a correct
observation and an uninformative verdict: it cannot separate *the guard is mis-aimed* from
*the weaken deleted the only thing that made the legs differ*. Reordering the assertions
makes that weaken report the table's success string, but the result would be hollow —
it demonstrates the test notices absent flags, which
`the_credential_drop_restriction_is_emitted_only_when_asked` already demonstrates with two
weakens of its own. **A green obtained that way would overstate what was proven.**

**The regression this guard exists for is bwrap dropping `no_new_privs`, and that variable
is not ours to remove** — no flag governs it (measured against `bwrap --help`, 0.11.1).

**So the discrimination is established by measurement rather than by weaken**, which is
weaker evidence and is named as such:

- **leg 4b** constructs the NNP-absent shape directly — permitted/effective lowered to
  `c0`, bounding full — and the capabilities come back **`000001ffffffffff`** across the
  exec. That is precisely the outcome the test asserts must not occur.
- **6b/6c** show the paired behaviour under bwrap: `c0` persists with the flags, full
  recovery without them.

**The assertion ORDER was also wrong and is fixed independently of all this.** The paired
`assert_ne!` fired first, so under the real regression (both legs read full) the reported
failure was "they read alike" — a message naming no cause. The control is now a
**precondition checked first**, and the property assertion carries the `no_new_privs`
suspect. With both specific assertions present the paired comparison was redundant anyway.

**Closes when** a mechanism exists to exercise NNP-absence in-tree. None is known.

**BOUNDED BY EVIDENCE, NOT ASSUMED SHORT (obligation, 2026-08-16).** "The pre-drop window is
short" is currently an **intuition**. bwrap's setup does mount work, `--dir` creation and now
ancestor emission; the helper performs two `execve`s. If that is milliseconds the trade is
comfortable; if ancestor emission on a deep path makes it materially longer, the calculus shifts.
**Measurable rather than arguable, and not yet measured.**

**AUDIT DISCONTINUITY — `sandbox_profile_digest` values are not comparable across
2026-08-15.** `audit.rs` records a digest of the derived profile args, and two changes landed
that alter those args for **every** action: ancestor emission (`--perms 0755 --dir <ancestor>`
per bind) and the namespace change (`--unshare-all` → the explicit list minus
`--unshare-user`). So every entry after that date differs from every entry before it, for all
actions, with no attack and no defect. Recorded because someone diffing audit history later
would otherwise read a universal change as an anomaly. The `action_digest` is **unaffected** —
the approved action did not change, only the enforced scope's spelling.

**TCB ENLARGED BY ONE MEMBER — `delphi-drop` (2026-08-15).** The credential-drop helper is not
covered by the action digest, not previewed, and not named by any action. That is acceptable on
a **bounded** argument, not on "it is trusted": `bwrap` is already an undigested,
installer-placed, root-owned component the action never names, and the helper joins that
existing class on the same basis rather than establishing a new kind of trust. The enlargement
is real, is small, and is recorded here rather than left implicit. What did **not** change: the
program executed is still the same pinned fd with the same `executable_digest`, and the tool's
`argv` is still exactly `action.argv` — the helper takes `argv0` explicitly so the approved name
still lands in the tool's own `argv[0]`.

**Proof-thinness (not clause violations, recorded so they are not mistaken for coverage):**
D0A-R9-08 — the "exact approved scope" test ignores unsupported grant options, env fidelity,
cwd, and removal of `--clearenv`. D0A-R9-09 — `fdsec`'s sole test proves neither high
descriptors, nor actual exec behaviour, nor the `CLOSE_RANGE_UNSHARE` race-defence leg.

**MEASURED 2026-08-20 — which greens actually bite (`scratch/d0a-mutation-audit.sh`).**
Twelve realistic defects were introduced into the shape-E guards one at a time; five passed
the entire suite. Not read off the tests — measured, and re-measured after the fixes.

| defect introduced | before | now |
|---|---|---|
| ancestor `--perms 0755` → `0700` (bwrap's own default — the value class 40 exists to override) | **NOT CAUGHT** | caught, incl. a real-jail `stat` of the created ancestor |
| `--unshare-net` dropped for `NetPolicy::None` (bwrap then SHARES the host network) | **NOT CAUGHT** | caught by two tests |
| `--clearenv` dropped (the R9-08 gap above, now measured) | **NOT CAUGHT** | caught |
| the approved `argv[0]` never reaches the tool | **NOT CAUGHT** | caught (`exec_tail` extracted so it is provable unprivileged) |
| the drop helper never interposed at all | **NOT CAUGHT** | **STILL NOT CAUGHT** — see below |
| the other seven (denylist legs, ancestor exclusion/ordering/emission, host-creating bind, full seals) | caught | caught |

**The one that remains, stated exactly.** `tool_credentials()` returns `None` unless euid is
0, so on an unprivileged box the interposition is unreachable and no test can observe the
daemon *deciding* to drop. What is now proven without root is the **assembly** (`exec_tail`
— helper, uid, gid, pinned program, approved argv0, in that order). What still needs root is
that **the drop takes**, which is
`an_approved_action_runs_with_the_tool_account_credentials` — and it SKIPs here, so on this
box that property has no live evidence at all. **Closes when** a root lane runs it.

## OPENED-AND-CLOSED 2026-08-20 — the tree-replace invariant had NO LIVE EVIDENCE for 15 commits

Recorded as its own item rather than inside D0A-R10-10's fixture repair, because "the fixture
is fixed" and "the invariant was unproven for a window" are different statements and only the
second is about the clause.

**The clause.** `installer/install.sh` replaces the shell bundle by a two-rename swap whose
invariant is *at every instant there is at least one of `shell` or `shell.old`; it is never
the case that both are absent*. CLAUDE.md §6 names `installer/tests/tree-install.test.sh` as
the **tier-1 SOLE EVIDENCE** for it — tier 1 under clause (d), *cited as the evidence that a
property holds*, despite never shipping.

**What was true.** `cdc3418` added `delphi-drop` to install.sh's staged-artifact loop and not
to that suite's fixture. From `cdc3418` until `10d4d65` — **15 further commits** (`git
rev-list --count cdc3418..9a45679`) — all 16 of the suite's install legs failed in pre-flight
with `cannot open installer/staging/delphi-drop`, before reaching a single assertion about
renames. Measured, not inferred: a worktree at `cdc3418~1` runs **26 passed / 0 failed**; at
`9a45679`, **10 passed / 16 failed**.

**So for that window the invariant was ABSENT, not passing** — the same distinction this file
already records for `runtime/shell-host` and for `cargo check --workspace`, now applied to a
clause the project cites as proven. The install code was not modified in that window, so
there is no reason to believe the invariant was violated; the point is narrower and worse:
**nothing was in a position to notice if it had been.**

**Why nothing noticed.** The suite is run by nothing — not `cargo test` (it is a shell
script), not the pre-commit hook (scoped to staged `runtime/` paths), and not CI, which had
no shell-suite step at all. A tier-1 artifact with no runner is a tier-1 artifact that
reports whatever it last reported.

**Closed** (`10d4d65`): the fixture is repaired and the suite is back to 26/0 — now 29/0 with
the R10-11 legs; `scripts/run-shell-suites.sh` discovers and runs every `*.test.sh`; CI runs
that script. The CI leg is **unverified on a runner** — green on the dev box, never yet
executed by GitHub Actions.

## OPENED-AND-CLOSED 2026-08-20 — two tests were DELETED in a commit that described neither

`f380085` ("widen R9-01's proof to every credential it CAN observe; shrink its name") removed
**135 lines** from `runtime/src/execute.rs`, and two of the things in them were whole tests:

* `the_tool_receives_its_approved_argv0` — a real bwrap run asserting the tool's `$0` is its
  approved name and not `/proc/self/fd/N`;
* `a_second_kept_fd_survives_a_second_exec_and_is_executable` — the **premise measurement**
  the drop helper's entire design rests on.

Neither removal is mentioned in that message. The consequence was measured five commits
later by `scratch/d0a-mutation-audit.sh`: *the approved `argv[0]` never reaches the tool*
survived the entire suite, because the test for it no longer existed. Round 10 had named
that test as a green it did not trust; by the time the round was answered it was gone.

**Both restored 2026-08-20**, verified passing, and kept alongside the unit-level
`the_helper_is_interposed_…` (which observes the assembled arguments — a different, lower
altitude than the running process's `$0`).

**Foreclosed mechanically, because nothing caught this either**: the pre-commit gate counted
FAILURES, which cannot see a test that is absent, and `.github/rust-test-count-baseline` is
deliberately unrecorded, so the disappearance guard built for exactly this was inert.
`.githooks/runtime-test-count-baseline` now records EXECUTED/SKIPPED for
`-p delphi-runtime --lib --bins` and the hook refuses on any change to either number, up or
down, printing the measured pair. Its RED legs are in `.githooks/tests/pre-commit.test.sh`.

## Round 11 (2026-08-21) — the instrument was wrong, and three remedies carried their own defect

**D0A-R11-01 invalidated the previous round's item-4 answer, and that answer is superseded
rather than repaired.** The first mutation harness had no baseline: "caught" meant *any* test
in four hard-coded namespaces failed, minus two known names. In a sandbox with two AMBIENT
bwrap failures that is true for every mutant including the null one — the reviewer's run
reported 12/12 caught, including `tool_credentials() -> None`, which catches nothing. So
"11 of 12" was **unsupported, not wrong**, and is withdrawn.

Rebuilt against a measured baseline (cargo status, result-line count, ran/skipped, the
fully-qualified failure set), with compilation failure scored as CAUGHT, no verdict on
unexplained state, `--lib --bins`, and an isolated git worktree so an interrupt cannot leave
the tree mutated. **It was wrong twice more before it was right** — no `--nocapture` (so a
skip counted as executed), an executed-count that drops on every catch (13 spurious
UNEXPLAINED), and a failure regex that `--nocapture` interleaving defeated (0/16 caught).
Each produced confident output.

**Re-measured, 24 mutants: CAUGHT 21 / NOT CAUGHT 4 / UNEXPLAINED 0.** The four:

| not caught | status |
|---|---|
| the denylist's equality leg | **not a gap** — `starts_with` is reflexive, so the mutation is a semantic no-op |
| `env_delta` never emitted | **FIXED** — the scope check now requires exactly the approved set, both directions |
| the host-creating-bind error VARIANT swapped | **FIXED** — R10-08 *was* a misclassification; `is_err()` was blind to it |
| `tool_credentials() -> None` | **open, root-only** — the interposition is unreachable unprivileged |

**D0A-R11-05 — the parser's METHOD, not its form list.** Three rounds found forms, so the
single-pass strip-and-parse was replaced by shadow's own two phases: store the last RAW
value, then interpret it (quote SCAN — skip any number of leading quotes, terminate at the
first subsequent one — then `strtoul` base 0). Measured: `"50"00"` → **50**, which no
strip-based reading produces. Precedence corrected: `5000` then `garbage` is shadow's
default, not 5000. And ABSENT is no longer the same answer as UNREADABLE — a permission or
UTF-8 error refused to be silently defaulted into a wider range.

**D0A-R11-06 — the validated credentials were not the used credentials.** Three independent
resolutions existed and only one was checked; the startup check also *skipped validation
entirely* on a lookup error (`if let Ok(Some(…))`). Now one resolution, validated, recorded,
and read. **Unprovable unprivileged:** restoring the re-resolution leaves the suite green,
because the path needs euid 0. The planner's decision is covered by injection; "execution
reads the plan" is root-lane evidence.

**D0A-R11-07 — twenty bytes established almost nothing.** Replaced by a full identification
header compared against `/proc/self/exe` (a trusted NATIVE reference, not the daemon —
four mutually-matching foreign binaries passed the old check), plus e_type, e_machine, and
PT_INTERP: a named loader must exist, and `delphi-drop` must name none, since it is exec'd
in a jail that binds nothing. Weaken-proven — under the old check a **dynamic helper
installs (rc=0)**. **Residual, stated in the script:** this is loadability preconditions, not
executability; a well-formed header followed by garbage still passes, and proving otherwise
means executing an unvalidated binary as root.

**D0A-R11-02/03/04 — every remedy from round 10 carried the defect it was built to prevent.**
The hook validated counts, not the identity of the expected failures (a red/green swap
passed) and exited 0 when its baseline was missing; the suite runner refused only at ZERO
discoveries, so deleting one suite while eight survived stayed green; the fixture hard-coded
"5" for a fifth artifact. All fixed — and the hook's first fix had the same bug backwards
(identity without count let a third failure through), caught by the hook's own test suite.

## Round 12 (2026-08-21) — the fix for green-by-skip arrived as green-by-skip

Ten findings. **D0A-R12-09 outranks the six parser findings** and is recorded first because
it is the arc's recurring class landing inside the fix for that class.

**D0A-R12-09 — the tier-1 suite reported GREEN by skipping, in CI, on every run.**
`installer/tests/tree-install.test.sh` exits when it cannot find a built `delphi-drop` to
stage as its static stub, and the R11-07 fixture rewrite made that an `exit 0`. The
shell-suites CI job had **no Rust toolchain**, so on a clean checkout the fixture never
existed: the suite skipped every time and the runner reported it `ok`. It is the file
CLAUDE.md §6 names as the tier-1 **SOLE EVIDENCE** for the tree-replace invariant, so in CI
that invariant had no live evidence at all while the pipeline was green.

**Worse than the 15-commit red it replaced** (recorded above): red-and-unrun is
discoverable; green-by-skip is not. Closed at three levels — the suite REFUSES; the runner
FAILS any suite that exits 0 having printed no result line (the class, for all nine); and CI
builds the fixture, which makes that step load-bearing. Both weakens bite under CI's exact
condition.

**D0A-R12-01/02/03 — absence coerced into a value, three symptoms of one cause.** A field
not in the file read as **0**; an 8-byte field with the top bit set read as **negative**
(and a negative offset passes every `<= size` bound); a `PT_INTERP` of `"\n"` read as
**absent**. For `delphi-drop`, "no PT_INTERP" is the answer that PASSES. Each helper now
returns a failure status rather than a value it invented. Two of three weakens bite; the
negative guard is **not independently isolable** — every negative value reachable is caught
downstream by the short-read check, because `od` produces nothing at a negative offset — and
that is recorded in the script rather than claimed.

**D0A-R12-04/05/06 — a discarded terminator, a wrong bound, a too-strict header.**
The `PT_INTERP` NUL was dropped unseen (weaken: a binary whose terminator is overwritten
INSTALLS, because the old code read the original path and never saw the header lie); the NUL
is now verified **numerically**, since bash cannot hold one — `$(dd …)` warns
`ignored null byte in input` and drops it. `MAX_PHNUM` is **deleted**: 257 program headers
is a valid executable ELF, so a count cap refused good binaries; the table is now one `od` +
one `awk`, bounded by construction. Full `e_ident` equality is replaced by the fields that
decide loadability — EI_OSABI 3 (GNU) is accepted, padding is not compared, and the magic is
checked first so a non-ELF refuses for being a non-ELF.

**D0A-R12-07 — the parser's third round, and the first INTERACTION.** `UID_MIN   "5000"`:
shadow 5000, Delphi 1000. Blanks and quotes were each measured and each correct in
isolation; 28 forms then 38, and not one had **both**. Enumerating a grammar feature at a
time misses the products.

**ROOT LANE RUN, 2026-08-21 — R9-01 IS PROVEN LIVE.** The operator ran the procedure. The
credential proof produced its evidence for the first time on this branch:

```
[R9-01] Uid: 997 997 997 997 / Gid: 972 972 972 972 / Groups: (empty) / CapEff: 0000000000000000
with helper: ["--", "/proc/self/fd/9", "997", "972", "/proc/self/fd/7", "approved-name", "--flag"]
```

So §6's "the tool runs under a uid that cannot reach daemon IPC" now has its **credential
half measured at root**, not reasoned: all four uids and gids are `delphi-tool`'s, the
supplementary set is empty, and `CapEff` is zero. **R12-08 is measured too** — the root path
plans credentials, the helper is interposed with `997 972`, and no
`no validated tool identity was recorded` appeared. The socket-refusal half remains measured
against a probe fixture (R9-01's open remainder), and the PAM stack was verified unchanged
before and after (`439c1d1521d86e4eb011a927aff659db`), 0 leaked daemons, class 16 clean.

**AND THE RUN FOUND SEVEN FAILURES THAT HAD BEEN THERE SINCE SHAPE E — D0A-R12-11.** All one
cause: `cannot create /tmp/delphi-exec-*/out/result: Permission denied`. The tool at uid 997
cannot write an `out/` created by the root test process. **This is the predicted behavioural
change, arriving exactly as recorded twice before E shipped** — dropping the tool off root
removes its access to root-owned paths, a test failing for that reason is CORRECT, and
widening the uid's access to turn it green would be the forbidden weaken. The fix is the
FIXTURE: `Env::new` chowns the out dir to the **planned tuple** (never a fresh lookup —
R11-06's discipline), in the one place that creates it. One test passed at root only because
it chowned by hand; that line is now the fixture's job.

**RE-RUN 2026-08-22 — THE FIXTURE FIX IS MEASURED.** `sudo … execute::tests::` at root:
**15 passed, 2 failed**, and the two are the intentional D0A-R9-02 REDs by name
(`same_inode_overwrite_…`, `nested_interpreter_substitution_…`). Every `Permission denied`
is gone, so the chown-to-the-planned-tuple in `Env::new` is confirmed at the only privilege
level that can execute that code. `an_approved_action_runs_with_the_tool_account_credentials`
printed its `/proc/self/status` block again, and `the_helper_is_interposed_…`,
`the_tool_receives_its_approved_argv0` and `a_second_kept_fd_survives_a_second_exec_…` all
pass at root as well as unprivileged.

**Two corrections to what was written before that run, both mine.** "Expected: 17 passed, 0
failed" was wrong — the R9-02 pair lives in `execute::tests::`, so 15/2 IS the clean result;
the check is the failing NAMES against the recorded `RED=` lines, never the count. And the
binary-freshness rule "mtime must be later than the commit" mis-fires: the pre-commit hook
builds before the commit object exists, so the binary read as 67 seconds stale while
containing the fix (confirmed by a forced rebuild producing the identical hash,
`a6faef1cea8d74be`). Both fixed in `scratch/lane-run-procedure.md`.

**Why nothing caught it, and this is the part worth keeping:** the drop only happens when
`tool_credentials()` returns `Some`, which needs euid 0 — so the unprivileged run of every
execution test takes the **no-helper branch**. It ran, it passed, and it exercised a
different mechanism than production does at root. Not "absent, not passing" in the earlier
sense (a suite nothing ran) but its sharper relative: a suite that runs, reports green, and
is about the other branch. Recorded as an instance under `docs/DEFECT_CLASSES.md` class 20.

**D0A-R12-08 — the root execution tests died before their subject.** R11-06's refusal is
right for production and broke the lane. `build_action` now plans once per process, and
`decide_credentials(euid, planned)` is split out so the ROOT BRANCH is a unit fact.
**MEASURED 2026-08-22** — the root lane ran it; see the RE-RUN paragraph above. (This
sentence previously said "STILL UNMEASURED", contradicting the run recorded 40 lines later —
D0A-R13-05. A register that disagrees with itself about whether something was measured is
worse than one that says nothing.)

**D0A-R12-10 — the poisoning guard compared strings**, so `target/../target`, a symlink, or
a trailing slash walked past it. Canonicalized. Demonstrated at the comparison, because the
audit refuses on a dirty tree and weakening the audit dirties it — the two guards conflict,
so a harness-level weaken cannot run.

**Two process defects of my own, both recorded in commits rather than smoothed over:**
`git checkout --` used as a restore on a file with UNCOMMITTED work discarded the fix along
with the weaken (copy-based restore is the rule while uncommitted); and a claim —
"the alias was ACCEPTED" — was printed beneath a run that had been blocked and did not show
it. The second is this session's own recurring mechanism: a sentence written next to output
that does not support it.

## Claims whose scope was believed wider than their proof

A different kind of row from the table above. Nothing here is a violated clause — each is a
**proof that stands**, carrying a **claim built on it that the proof never covered**, because a
now-violated clause was doing the extending.

| claim as believed | what was actually proven | what extended it | closes when |
|---|---|---|---|
| "a requester cannot forge approvals" (B2a **R-2**) | the **renderer** cannot forge them | §6's "the tool runs under a uid that cannot reach daemon IPC" — **violated**, so the extension to the *executed tool* was never proven | the executed tool is proven unable to reach or satisfy the approval socket |
| "the digest is the binding" (§3) — **claim narrowed 2026-08-13** | **approve-A / execute-B** is refused (the *in-band* substitution), **and the script BODY is genuinely content-pinned** by `FULL_SEALS` | the assumption that pinning an fd pins the bytes — true for the sealed script memfd, **false for `executable_fd` / `interpreter_fd`**, which are inode pins only | the **binary/interpreter** side is content-pinned, with same-inode and nested-shebang substitution as failing-then-passing tests (**both reproduced by the reviewer**) |

### The R-2 keystone — what holds it up today, and why remediation is a TRADE

**The keystone currently holds BECAUSE THE TOOL RUNS AS ROOT**, which is the defect. Traced:
the daemon is root, spawns bwrap as root, and `accept_requester` reads `SO_PEERCRED` uid **0**
against an `expected_uid` that is the **session uid** — mismatch, rejected.

**Apply the obvious R9-01 fix — drop the action to the SESSION uid — and the rejection
disappears.** `SO_PEERCRED` then reports the session uid, `expected_uid` is the session uid, the
peer is accepted; and with **no path denylist** (R9-10) an action may bind the socket into its
own jail. **The remediation removes the mechanism presently doing the protecting.**

So **"any unprivileged uid strictly beats root" is FALSE here**, and "refining which uid is cheap
later" is false with it. **The fix must be a DEDICATED SERVICE UID distinct from the session
uid** — that *is* the decision, not a detail deferred past it.

### The four measurements — RESULTS (2026-08-13, `scratch/d1-peercred-probe.sh`)

`setuid()` inside the userns was the wrong target: what the daemon observes is set by the **uid
map**, not by what the child does after `execve`.

**M1 — at the socket.** A peer inside the jail, connecting over a bound-in socket, is read by
the outside listener as **the uid that launched bwrap** (`SO_PEERCRED pid=5304 uid=1000
gid=1000` from an `OUTER uid=1000` launcher). Observed, not inferred. **Root leg outstanding.**

**M2 — the map.** `/proc/self/uid_map` inside reads `1000 0 1`, which is *not* "inner 1000 →
outer 0": `os.stat` on a file owned by outer-1000 returns **1000** inside, so the net mapping is
**identity for the launching uid**. The `0` is w.r.t. an **intermediate userns** bwrap creates
(mapping the launcher to 0 to obtain mount capability, then mapping back). So inner 0 maps to
the **launcher** — root — **not** to the session uid. **Not breached via the map.**

**M3 — `accept_requester`'s comparison.** `if cred.uid() != expected_uid` — a plain inequality,
**no `&& uid != 0` root exemption**. The rejection is real and does what it appears to.

**M4 — can `expected_uid` be 0? YES, and it is reachable.** See the R9-11 row: unvalidated
`--session %i`. This is the one measurement that found a live breach rather than confirming a
defence.

### The measurement that decides the FIX, not the current state

Leg B ran the profile with **`--uid 65534 --gid 65534`** — the obvious shape of "run under a
dedicated service uid". Inside: `INNER uid=65534`. At the listener: **`SO_PEERCRED uid=1000`**
— *the launcher, unchanged*. **bwrap's `--uid` sets the id INSIDE the namespace and does not
change the credential the kernel reports outside it.** A fix built on `--uid` would show a
non-root `id -u` inside the jail while remaining the launcher's uid to every check performed
outside — cosmetic, and it would read as correct.

**The negative was satisfiable two ways** (standard 3, applied to my own measurement): either
(a) `--uid` never changes the outside credential, or (b) an *unprivileged* launcher owns exactly
one id, so no other result was possible. The unprivileged leg could not discriminate.

**RESOLVED — root leg run 2026-08-13. Both predictions confirmed, and leg B now discriminates:**

```
LEG A (as shipped):   INNER uid=0       →  SO_PEERCRED uid=0
LEG B (--uid 65534):  INNER uid=65534   →  SO_PEERCRED uid=0
```

Root had **two ids available** and `--uid 65534` still produced `uid=0` outside, so explanation
**(a)** holds: **`--uid` is namespace-internal only.** The obvious remediation is cosmetic — it
would pass review while changing nothing an outside check can see.

**Therefore the fix is a real credential change before `execve`** — `setresuid` / `setgid` /
`setgroups`, or a systemd `User=` — **never a bwrap flag.**

**Leg A also closes D0A-R9-11's chain end to end.** The root-launched jail presents as `uid=0` to
the listener; `delphi-runtimed@root` sets `expected_uid = 0` from the unvalidated `%i`; the peer
check compares 0 to 0 and **passes**. No attacker step, no remediation applied — the keystone
falls on a **supported unit instantiation**.

## An unexplained divergence in this file — recorded, not closed

Between the 2026-08-12 and 2026-08-13 commits, this register's working-tree copy contained the
D0A-R9-11 row and an M1–M4 results section **that I did not write**, citing the probe's exact
`pid=5304`. Every claim in it was checked against the probe's own output before it was committed,
and all of them hold.

**That disposition is not the same as knowing where it came from, and this entry exists to keep
those two apart.** The scripted edit that would have overwritten it **asserted NO MATCH and wrote
nothing** — the assert-every-replacement rule is the only reason the divergence is visible at all
rather than silently destroyed. Left **unexplained**; not to be written up later as resolved.

## Scheduling — decided 2026-08-12

**Gate before B2b** (the Brain subsumes `executor.rs`; integrating onto a broken privilege
boundary means re-reviewing all of it later): **D0A-R9-01 + D0A-R9-10 TOGETHER**, and
**D0A-R9-06**.

**R9-01 and R9-10 land together — but NOT because "each is the other's only backstop", which is
what this register said until 2026-08-15 and is wrong. Corrected before the fix, not with it,
because an overstated row reads as established and gets cited.**

Measured: the approval socket is `root:<session-gid>` mode **0660** (`anchor.rs`, "group-
connectable, owner stays root"), and `/run/delphi/<session>` is **0711** root-owned. A bind mount
preserves both. So the two halves are **asymmetric**:

- **Denylist alone** (the tool still root): root **overrides DAC**, so mode bits stop nothing and
  absence-from-the-mount-namespace is the **sole** barrier. One mechanism, one failure.
- **Uid alone** (no denylist): a `delphi-tool` peer is stopped by the socket's **mode** *and* by
  the **`SO_PEERCRED`** mismatch. Two independent mechanisms, neither of them the denylist.
  **The mode half is CONDITIONAL, and the condition is load-bearing (sharpened 2026-08-15):**
  `0660 root:<session-gid>` excludes the tool **only while the tool is outside the session
  group**. Put it inside — which is exactly what the naive R9-01 fix (drop to the *session* uid)
  would do — and `0660` grants it group access. A probe run that chowned the socket to the
  **tool's own** gid measured precisely that misconfiguration and connected; that fixture did not
  model production (`bind_approval_socket(&dir, session_gid)`), so it is **not** evidence the mode
  fails, but it is a live warning about which uid is chosen.

**So the uid is the ENABLING change and the denylist is defence in depth on top of it — while
the tool is root, the mode bits provide nothing at all.** They ship together because the denylist
is a single point of failure without the uid, not because they mutually backstop. The uid must be
a **dedicated service uid**, distinct from the session uid, since `SO_PEERCRED` equality is what
makes "which uid" the whole decision.

**`DynamicUser=` is STRUCTURALLY EXCLUDED, not merely unattractive — recorded so it is not
re-proposed.** It applies to a **systemd unit**; the tool is a child the root daemon *forks*
inside bwrap and is not a unit. Making it one requires `systemd-run` per action, which this
register's own scope cap forbids. Dynamic uid **recycling** is a separate hazard against files a
prior tenant left behind. Provisioning is therefore a **static system account created by the
installer**.

**Predicted, before implementation, so it is not later misread as breakage:** dropping the tool
off root **removes its access to root-owned bound paths**. That is the point of the change. Any
test that fails because of it is **correct**, and the finding is that the test depended on the
tool being root — widening the new uid's access to turn that red green would be the weaken this
project forbids.

**Schedulable:** seccomp (R9-05) and cgroups (R9-04). **Scope cap, deliberate:** seccomp policy
for *arbitrary tools* is open-ended and must not become the next Phase 3B. D1 ships a policy for
the tools actually reachable today, with the open-endedness recorded here rather than absorbed.

**If R9-01 or R9-06 remain open past the next merge to `main`,** that is recorded as an
**explicit dated exception to Iron Law #2 with named closure conditions** — not as a
"documented gap". Otherwise "documented gap" silently becomes what the law means, which is §6's
own failure one level up.
