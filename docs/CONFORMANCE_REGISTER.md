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
| §6 | "the tool runs under a uid that **cannot reach daemon IPC**" | **IMPLEMENTED 2026-08-15 (shape E); PROOF IS ROOT-GATED AND HAS NOT RUN.** The profile drops `--unshare-user` (§6 mandates no user namespace — only `--unshare-net`), and bwrap's payload is `delphi-drop`, a statically linked helper passed **by fd** so it adds no bind, which does `setgroups([]) → setresgid → setresuid` and then execs the pinned program fd. Measured route: `--uid` cosmetic (leg B), drop-before-bwrap breaks setup (leg C), in-userns drop impossible (leg D, `EINVAL`), no-userns drop works end-to-end (E1+E2, `SO_PEERCRED uid=997`). **Not closed:** the `id -u` test skips unprivileged, since below root there is no privilege to drop | D0A-R9-01 | the ROOT run shows the action's own `id -u` == `delphi-tool` |
| §6 | "**seccomp default-deny**" | **ABSENT** — no `--seccomp` anywhere in `sandbox.rs` | D0A-R9-05 | a policy is attached and a denied syscall is proven denied |
| §6 | "**cgroup v2 mem/pids/CPU caps**" | **ABSENT** | D0A-R9-04 | caps applied and a breach proven contained |
| §6 | "**timeout + kill-on-expiry**" | **ABSENT** — `action.timeout` is unenforced | D0A-R9-04 | an over-running action is killed, RED-proven |
| §3 | "**the digest is the binding** for preview = approval = sandbox = audit" | **PARTIAL, AND NARROWER THAN FIRST RECORDED (corrected 2026-08-13, before the tests were written).** The **script body IS content-pinned** — `execute.rs:138` enforces `ScriptPin::FULL_SEALS` on `script_memfd`, so its bytes and length cannot change after the digest. The gap is the **binary and interpreter** side: `executable_fd` and `interpreter_fd` are plain `File::open` fds — **inode-pinned, never sealed, and `executable_digest` is not re-verified at exec**. Same-inode overwrite and nested-shebang swap execute unapproved bytes **there** (both reproduced by the reviewer) | D0A-R9-02 | the binary/interpreter side is content-pinned, with both substitutions as failing-then-passing tests — **AND the drop helper is covered by it.** `execute.rs` opens `/usr/libexec/delphi-drop` by PATH, so it carries this same inode-vs-content gap for itself; opening once per process shrinks the window to process start but does not close it. The helper is the one component whose substitution grants **uid control**, so it is the worst candidate for an exemption: **R9-02 may not be closed without answering it** |
| §6 | "mount exactly `fs_binds`" | **PARTIAL** — bind sources are **path-resolved at launch**, so a symlink swap substitutes scope | D0A-R9-03 | binds resolve to what was approved, TOCTOU-proven |
| §6 | "env is scrubbed to `env_delta`" | **LEAKS** — `env_delta` is passed in **bwrap's argv**, world-readable via `/proc/<pid>/cmdline` | D0A-R9-06 | secrets never transit argv |
| §7 | audit "carries … result" | **CORRUPTIBLE** — a bwrap SETUP failure exits nonzero and is recorded as the action having run and failed, when it never ran. **Not a bypass**: `execute.rs:175` is the only production spawn (everything else is after `#[cfg(test)]`), and a missing bwrap is a hard error | D0A-R9-07 | setup failure and tool exit are distinguished in the audit entry |
| §6 | "the daemon's socket is a root-owned filesystem socket **outside the jail's mount set**" | **UNENFORCED** — `sandbox.rs:60` binds exactly what was approved with **no path denylist**, so an action may name `/run/delphi/…` and place the socket *inside* the mount set. Distinct from R9-03: that is TOCTOU on *resolution*; this is that nothing forbids naming the target at all | **D0A-R9-10** (found while verifying, not in the review) | **CLOSED 2026-08-15** — `sandbox::refuse_denied_bind` refuses every spelling (lexical fold + canonicalize), wired at the `run_fd_pinned` choke point, with a positive control. Both weakens bite: removing the call site lets execution reach bwrap (`bwrap: Can't find source path /run/delphi/alice` — it would have BOUND it where the path exists); removing traversal folding fails `/tmp/../run/delphi/alice` |

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
