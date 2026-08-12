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
| §7 | audit "carries … result" | **CORRUPTIBLE** — bwrap setup failure and a tool's nonzero exit are indistinguishable | D0A-R9-07 | the two are distinguished in the audit entry |

**Proof-thinness (not clause violations, recorded so they are not mistaken for coverage):**
D0A-R9-08 — the "exact approved scope" test ignores unsupported grant options, env fidelity,
cwd, and removal of `--clearenv`. D0A-R9-09 — `fdsec`'s sole test proves neither high
descriptors, nor actual exec behaviour, nor the `CLOSE_RANGE_UNSHARE` race-defence leg.

### What was checked about the R-2 keystone, and what was not

§6's uid clause was the stated reason an executed tool could not reach daemon IPC. With it
violated, the B2a R-2 proof (*the renderer cannot forge approvals*) does **not** extend to the
executed tool — that was never proven, because §6 asserted it.

**Verified by reading at `09dadae`:** the minting key is memory-only (`delphi-runtimed.rs:106`),
and `--unshare-all` + `--proc` deny the jail any view of the daemon's process, so ptrace and
`/proc/<pid>/mem` are unavailable. `approve.sock` is reachable only if an `fs_bind` names it, and
**`sandbox.rs:60` applies no path denylist**. `accept_requester` (`service.rs`) independently
rejects a peer whose `SO_PEERCRED` uid differs from the session uid.

**NOT verified — and it decides the question:** whether a root process inside bwrap's user
namespace can `setuid()` to the session uid and so satisfy `SO_PEERCRED`. bwrap's default
single-uid map should make that `EINVAL`; *should* is not a measurement. **Until measured, the
keystone holds by PID-namespace isolation and `SO_PEERCRED` — two mechanisms, neither of them
the clause §6 claimed, one of them untested.** This measurement precedes any D1 design.

---

## Scheduling — decided 2026-08-12

**Gate before B2b** (the Brain subsumes `executor.rs`; integrating onto a broken privilege
boundary means re-reviewing all of it later): **D0A-R9-01** (any unprivileged uid strictly beats
root; refining which one is cheap later) and **D0A-R9-06** (contained fix).

**Schedulable:** seccomp (R9-05) and cgroups (R9-04). **Scope cap, deliberate:** seccomp policy
for *arbitrary tools* is open-ended and must not become the next Phase 3B. D1 ships a policy for
the tools actually reachable today, with the open-endedness recorded here rather than absorbed.

**If R9-01 or R9-06 remain open past the next merge to `main`,** that is recorded as an
**explicit dated exception to Iron Law #2 with named closure conditions** — not as a
"documented gap". Otherwise "documented gap" silently becomes what the law means, which is §6's
own failure one level up.
