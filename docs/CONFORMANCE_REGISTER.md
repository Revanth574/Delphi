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

### The four measurements that precede any D1 design

`setuid()` inside the userns is **downstream and the wrong thing to measure**: what the daemon
observes is fixed by the **uid map**, not by what the child does after `execve`, and `setuid`
only moves within mapped ids.

1. **At the socket.** Connect from inside the jail and have the daemon **log the `SO_PEERCRED`
   triple it actually reads**. Observed, never inferred from the bwrap invocation.
2. **The map.** If bwrap is invoked such that inner 0 maps to the **session uid**, the keystone
   is breached **now**, not conditionally.
3. **`accept_requester`'s exact comparison.** `uid != expected && uid != 0` is the idiomatic
   form; if a **root exemption** is present, the rejection verified above does not exist.
4. **Can `expected_uid` ever be 0?** A root session or service context would make the daemon's
   own check vacuous.

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
