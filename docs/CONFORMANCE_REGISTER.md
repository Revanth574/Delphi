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
| §6 | "the tool runs under a uid that **cannot reach daemon IPC**" | **VIOLATED** — the action runs as **root**; `execute.rs:194` has no `uid()`/`gid()`/capability drop | D0A-R9-01 | the action runs under an unprivileged uid, RED-proven |
| §6 | "**seccomp default-deny**" | **ABSENT** — no `--seccomp` anywhere in `sandbox.rs` | D0A-R9-05 | a policy is attached and a denied syscall is proven denied |
| §6 | "**cgroup v2 mem/pids/CPU caps**" | **ABSENT** | D0A-R9-04 | caps applied and a breach proven contained |
| §6 | "**timeout + kill-on-expiry**" | **ABSENT** — `action.timeout` is unenforced | D0A-R9-04 | an over-running action is killed, RED-proven |
| §3 | "**the digest is the binding** for preview = approval = sandbox = audit" | **PARTIAL** — execution pins an **inode**, not content; same-inode overwrite and nested-shebang swap execute unapproved bytes (**both reproduced by the reviewer**) | D0A-R9-02 | execution is content-pinned, with both substitutions as failing-then-passing tests |
| §6 | "mount exactly `fs_binds`" | **PARTIAL** — bind sources are **path-resolved at launch**, so a symlink swap substitutes scope | D0A-R9-03 | binds resolve to what was approved, TOCTOU-proven |
| §6 | "env is scrubbed to `env_delta`" | **LEAKS** — `env_delta` is passed in **bwrap's argv**, world-readable via `/proc/<pid>/cmdline` | D0A-R9-06 | secrets never transit argv |
| §7 | audit "carries … result" | **CORRUPTIBLE** — a bwrap SETUP failure exits nonzero and is recorded as the action having run and failed, when it never ran. **Not a bypass**: `execute.rs:175` is the only production spawn (everything else is after `#[cfg(test)]`), and a missing bwrap is a hard error | D0A-R9-07 | setup failure and tool exit are distinguished in the audit entry |
| §6 | "a uid that **cannot reach daemon IPC**" (the *check* side) | **VACUOUS IN A REACHABLE DEPLOYMENT** — `expected_uid` comes from `User::from_name(&session)` where `session` is the systemd instance name (`ExecStart=… --session %i`), **unvalidated**. `delphi-runtimed@root` sets `expected_uid = 0`; the root-running tool then reads back `SO_PEERCRED uid=0` and **matches**. Keystone breached with no attacker step and no remediation applied | **D0A-R9-11** (measurement 4) | the daemon refuses a root session user, RED-proven |
| §6 | "the daemon's socket is a root-owned filesystem socket **outside the jail's mount set**" | **UNENFORCED** — `sandbox.rs:60` binds exactly what was approved with **no path denylist**, so an action may name `/run/delphi/…` and place the socket *inside* the mount set. Distinct from R9-03: that is TOCTOU on *resolution*; this is that nothing forbids naming the target at all | **D0A-R9-10** (found while verifying, not in the review) | a denylist refuses the daemon's runtime directory, RED-proven — **and it must land WITH the dedicated uid, since each is the other's only backstop** |

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
| "the digest is the binding" (§3) | **approve-A / execute-B** is refused — the *in-band* substitution | the assumption that pinning an fd pins the bytes | **content**-pinned execution, with same-inode and nested-shebang substitution as failing-then-passing tests (**both reproduced by the reviewer**) |

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

**This negative is satisfiable two ways** (standard 3, applied to my own measurement): either
(a) `--uid` never changes the outside credential, or (b) an *unprivileged* launcher owns exactly
one id, so no other result was possible. The unprivileged leg cannot discriminate. **The root
leg does** — root owns every id, so if `--uid 65534` still reports 0 outside, (a) holds.

**Outstanding, and it is the operator's to run:**

```
sudo ./scratch/d1-peercred-probe.sh
```

Predictions, recorded before the run so they score: **leg A → `SO_PEERCRED uid=0`** (keystone
holds today, by root). **Leg B → `SO_PEERCRED uid=0`** (`--uid` is inside-only; the fix needs a
real credential change — `setresuid`/`setgid`/`setgroups` before `execve`, or systemd `User=`).

## Scheduling — decided 2026-08-12

**Gate before B2b** (the Brain subsumes `executor.rs`; integrating onto a broken privilege
boundary means re-reviewing all of it later): **D0A-R9-01 + D0A-R9-10 TOGETHER**, and
**D0A-R9-06**.

**R9-01 and R9-10 are one item, not two.** Dropping to an unprivileged uid without the denylist
*removes* today's protection; the denylist without the uid leaves the §6 clause violated. Each
is the other's only backstop, so shipping either alone is a regression in one direction or a
half-measure in the other. The uid must be a **dedicated service uid**, distinct from the
session uid — chosen up front, because `SO_PEERCRED` equality is what makes "which uid" the
whole decision.

**Schedulable:** seccomp (R9-05) and cgroups (R9-04). **Scope cap, deliberate:** seccomp policy
for *arbitrary tools* is open-ended and must not become the next Phase 3B. D1 ships a policy for
the tools actually reachable today, with the open-endedness recorded here rather than absorbed.

**If R9-01 or R9-06 remain open past the next merge to `main`,** that is recorded as an
**explicit dated exception to Iron Law #2 with named closure conditions** — not as a
"documented gap". Otherwise "documented gap" silently becomes what the law means, which is §6's
own failure one level up.
