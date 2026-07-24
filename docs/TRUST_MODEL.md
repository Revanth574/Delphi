# Delphi Runtime Trust Model

- **Status: RATIFIED @ `37f225a` (Codex 6-round adversarial review, APPROVE) —
  STOP-POINT-B passed; this document is the boundary Increment 1 implements.** Rounds 1–2
  fixed structure; v3 specified each mechanism; v4 anchored the
  two trust-chain-bottom links to **root**. **Round-4 confirmed the chain has bottomed out —
  no residual principal below root** (Yama/F1 again, PAM agent-substitution removed, logind
  active-session *not* forgeable, pidfd pid-reuse closed) — and returned REVISE on **two
  spec-precision defects, not trust holes:** (R4-01) v4 *asserted* the runtime directory is
  root-owned but its named mechanism (`@%i` per-user template) implied `User=`, which `man
  systemd.exec` confirms makes the directory **user-owned** (anchor lost); and (R4-02) v4's
  `close_range(3,~0,0)` *closes* the fds it needed to keep — it conflated *closing* with
  *marking close-on-exec*. v5 pins the **privilege-split unit config** (daemon as root,
  fork-then-drop children) with the anchor attributed to **root-owned-directory** semantics,
  and the corrected `close_range(…, CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE)` mechanic. Not
  ratified. **Round-5 confirmed every mechanism sound**, returning one **P3 (R5-01)** — the
  example unit block used inline comments, invalid per `systemd.syntax(7)` (a doc-syntax
  defect, no mechanism change). v6 made the block copy-valid; **round-6 returned APPROVE, no
  findings.** The trust chain — grounded root-to-approver, every mechanism host-verified —
  held across six adversarial rounds. **Increment 1 implements this document; runtime code
  lands only as the ratified boundary specifies.**
- **Provenance:** draft `9a7e3b9` → round-1 FAIL → re-spine `d25b987` → round-2 FAIL → spec
  pass `410b9b3` → round-3 REVISE → root-anchor `c7fee38` → round-4 REVISE → floor-precise
  `a37965a` → round-5 REVISE → syntax `37f225a` → round-6 **APPROVE** → **RATIFIED** (this commit).
- **Verified-on-host primitives this pass rests on** (probed; the target Delphi-OS must
  guarantee them):
  - **systemd 255 is PID 1**, and **`/run` is `root:root 0755`** — a same-uid process
    **cannot** create `/run/delphi` (no write bit on `/run`). This is the **anchor**: a
    root-created socket directory is one a same-uid attacker cannot pre-empt or substitute.
  - **Yama `ptrace_scope`=1** restricts `ptrace`/`PTRACE_MODE_ATTACH_REALCREDS` to
    **descendants** (plus `PR_SET_PTRACER`-declared tracers and `CAP_SYS_PTRACE`). The AI is
    the shell's **sibling, not ancestor** ⇒ fd-theft denied by topology (§4). `PR_SET_DUMPABLE`=0
    + separate uid are belt-and-suspenders, not load-bearing.
  - **`libpam.so.0` present** ⇒ a root-established daemon can run `pam_authenticate` itself
    (the consent party is the daemon, not a substitutable ambient agent — R3-02).
  - **`pidfd_open` present** ⇒ the daemon binds the approver subject to a **race-free pidfd**
    from its own spawn table, not a racy `/proc` `pid+start-time` lookup (R3-03).
  - **`memfd_create` + `F_SEAL_WRITE`/`F_SEAL_EXEC` present** ⇒ script content is sealed
    immutable and the **interpreter fd** is exec'd directly, so the shebang never re-resolves
    by PATH (R3-04).
  - **`man systemd.exec`:** `RuntimeDirectory=` is owned by `User=`/`Group=` (default mode
    0755); with **no `User=`** the directory is **root-owned** — the anchor depends on the
    daemon running as root, not as the user (R4-01).
  - **`man close_range`:** `CLOSE_RANGE_CLOEXEC` (Linux 5.11) **marks** the range
    close-on-exec *rather than closing it*; `CLOSE_RANGE_UNSHARE` unshares the fd table first
    to avoid races with threads sharing it (R4-02). `execveat(…, AT_EMPTY_PATH)` execs an fd.
  - `fexecve`, `CLOEXEC`, and the `AuditEntry` `canonical_hash` + no-`..` pattern
    ([audit.rs:57](fortress/src/audit.rs:57)) — as v3.

---

## §0 · Scope, first goal, sequencing — unchanged

Boundary designed for the hard case (**arbitrary `argv`** for a developer workflow); two
sub-surfaces — (a) the enumerated tier-classified methods ([auth.rs:232](services/src/auth.rs:232)),
(b) arbitrary `argv`. **Increment 1** proves the whole boundary on the known-method
surface; **Increment 2** admits `argv` through it. Autonomous `Brain` (unwired,
[brain.rs:126](die/orchestrator/src/brain.rs:126)) is wired only after both hold.

## §1 · Adversary — unchanged (same-uid is central)

The AI runs *as the user* (its own low-priv uid, §5); same-uid malware presents the same
uid; injected content makes the *honest* AI request destructive actions. uid is necessary
but **not sufficient** to identify the approver — **and (new in v4) nothing the user's own
uid can create is sufficient to be the *launcher* or the *auth party* either.** The trust
chain must bottom out at a principal the user's malware cannot become: **root.**

## §2 · The boundary: human-consent ≠ caller-continuity — unchanged

Two distinct things both hold: **(A) caller-continuity** (SVC-2 same-caller binding,
[auth.rs:535](services/src/auth.rs:535) — reused on the *requester* side) and **(B)
human-consent** (a signal the same-uid requester cannot produce). v4 grounds the mechanisms
for (B) at the OS trust root.

---

## §3 · The canonical `PendingAction` — SPECIFIED (incl. executable + interpreter pinning)

One immutable arbiter-built object; preview, approval-digest, sandbox, and audit all
derive from it.

```
PendingAction {                       // arbiter-built, immutable; id = Uuidv4, single-use
  pending_id, preview_version,
  executable_fd     : OwnedFd,        // OPENED before preview (O_PATH→O_RDONLY); kernel
                                      //   object, not a path — no swap window
  executable_digest : [u8;32],        // hash of the bytes read THROUGH executable_fd
  argv, cwd, env_delta,
  fs_binds          : Vec<(PathBuf,BindMode)>,
  net_policy        : NetPolicy::{None|Full},   // R3 — no allowlist (see §6)
  timeout, required_tier,
  script            : Option<ScriptPin>,        // R3-04 — see below
}
ScriptPin {                           // set iff executable_fd's first bytes are "#!"
  interpreter_fd     : OwnedFd,       // the OPENED interpreter (e.g. /usr/bin/python3)
  interpreter_digest : [u8;32],       // hash read THROUGH interpreter_fd
  script_memfd       : OwnedFd,       // sealed copy of the script bytes (immutable)
  script_digest      : [u8;32],       // hash of the sealed content
}
action_digest = delphi_hardening::canonical_hash(PendingAction)   // injective; no-`..`
```

- **Executable pinning:** the arbiter `open`s the executable **before** preview, hashes the
  bytes read *through that fd*, and execs **that exact fd** by descriptor —
  `fexecve`/`execveat(AT_EMPTY_PATH)`. No path→exec window for a same-uid swap.
- **Script pinning — MECHANICAL (R3-04 fix).** v3 said "scripts pin interpreter+content"
  but `fexecve`-ing the **script** fd lets the kernel read `#!` and **re-resolve the
  interpreter by PATH** — the pinned `interpreter_fd` is never used, leaving the interpreter
  swappable. The mechanical fix:
  1. Read the resolved `executable_fd`'s first bytes; if `#!`, parse the interpreter path+args.
  2. `open` the **interpreter** → `interpreter_fd`; hash through it → `interpreter_digest`
     (pin the interpreter *object*, not its path).
  3. Copy the script bytes into `memfd_create(MFD_CLOEXEC | MFD_ALLOW_SEALING)`, write, then
     `F_ADD_SEALS` with `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL` ⇒ content
     **immutable** (host-verified seals present).
  4. **Execute the interpreter fd** — `execveat(interpreter_fd, "", ["python3",
     "/proc/self/fd/<script_memfd>", …], envp, AT_EMPTY_PATH)`. The shebang is **never
     re-resolved**: we exec the interpreter directly.
  5. **fd discipline + non-CLOEXEC caveat (R4-02 — corrected).** `close_range(3, ~0U,
     CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE)` **marks** every inherited fd ≥ 3 close-on-exec
     (it does **not** close them — `UNSHARE` first detaches the fd table so the marking can't
     race other tasks); then clear `FD_CLOEXEC` on **only** the `script_memfd` (the interpreter
     must read `/proc/self/fd/<script_memfd>`), and keep `interpreter_fd` open for the
     `execveat` (it closes on exec naturally — only the script fd must survive). *Using flags=0
     would instead **close** the script + interpreter fds and break the exec — and an
     implementer fighting that broken call might skip fd cleanup entirely, leaking
     daemon/private fds into the approved interpreter (the §6 reentry hole). The marking flag is
     what keeps daemon IPC fds out of the sandboxed tool.* The sealed content cannot be swapped
     (`F_SEAL_WRITE`), so passing by `/proc/self/fd` is safe — the path resolves to the sealed
     kernel object, not a file an attacker can replace. Executable-TOCTOU is thereby extended
     **to the interpreter**: neither the interpreter binary (exec'd fd) nor the script content
     (sealed memfd) is swappable between hash and exec.
- **The digest is the binding** for preview = approval = sandbox = audit. The no-`..`
  `canonical_hash` discipline means a new `PendingAction`/`ScriptPin` field cannot be
  silently unhashed (DEFECT_CLASSES §1, both-halves).
- **Preview is the arbiter's rendering of this object** — never AI text, never derived from
  observed content (defeats the §1 injection vector: the human sees what *execs*).

---

## §4 · The consent path — ROOT-ANCHORED (R3-01 launcher, R3-02 auth, R3-03 subject)

Round-3 closed **F1** (the AI cannot steal the shell's approval fd) and confirmed the
remaining trust rests on two parties the document had not *established*. v4 grounds both at
root. **R3-01 is the keystone:** once the genuine daemon is root-established, everything
else (the sibling proof, the auth party, the failure modes) hangs off it.

### F1 closure — the sibling topology (CONFIRMED by round-3; stated explicitly)

The daemon parents **both** the shell and the AI, so the AI is the shell's **sibling, not
its ancestor**. `pidfd_getfd` (and ptrace-based fd-theft) requires
`PTRACE_MODE_ATTACH_REALCREDS` → `ptrace_may_access`. Under **Yama `ptrace_scope`=1**, attach
is permitted only to a **descendant** of the caller (or a `PR_SET_PTRACER`-declared tracer,
or `CAP_SYS_PTRACE`). A sibling is **not** a descendant ⇒ the AI is **denied by the topology
itself**, *independent of the dumpable window*. This dissolves the round-2 "execve resets
dumpable" race: the AI was never permitted to attach, dumpable bit or not. `PR_SET_DUMPABLE`=0
on the boundary processes and the AI's separate low-priv uid (§5) are **belt-and-suspenders**.
*(The sibling proof is only valid once a **genuine** daemon is the shared parent — which is
exactly what R3-01 establishes.)*

### R3-01 / R4-01 — the launcher, established by the OS trust root (THE KEYSTONE)

v3 *asserted* "the daemon is the trusted launcher"; v4 anchored it to root but **named the
wrong mechanism** — a `@%i` per-user template implies `User=%i`, and `man systemd.exec`
confirms `RuntimeDirectory=` is then owned by **that user**, making the socket directory
user-writable and the anchor forgeable. v5 pins the **concrete privilege-split unit config**
that keeps the directory root-owned while the children run unprivileged. `installer/` is
greenfield, so this is designed, not retrofitted:

```ini
# /usr/lib/systemd/system/delphi-runtimed@.service — SYSTEM manager unit (NOT a user unit)
[Service]
# NO User=, NO DynamicUser=  → the daemon runs as ROOT → /run/delphi/%i is root:root.
# %i is the target USERNAME passed as an argument (the root daemon resolves it to a uid
#   itself) — it is NOT User=%i.
ExecStart=/usr/libexec/delphi-runtimed --session %i
RuntimeDirectory=delphi/%i
# RuntimeDirectoryMode 0711 → root-owned; the user may traverse (x) to reach the socket but
#   has no write (w) → cannot unlink/replace inodes in the directory.
RuntimeDirectoryMode=0711
```
*(systemd.syntax(7): only whole-line `#`/`;` comments are honored — directive values are bare.)*

- **Root daemon, exec'd by PID 1.** The binary is **root-owned** and started by **systemd
  (PID 1)** — a trusted exec chain from init. The daemon runs as **root** (no `User=`/
  `DynamicUser=`); `%i` is a *username argument*, not `User=%i`. Running as root is precisely
  what makes `RuntimeDirectory=delphi/%i` **root-owned** (`man systemd.exec`: the directory is
  owned by `User=`/`Group=`, default mode 0755).
- **The anchor is the root-owned *directory*, not the socket-file mode (R4-01 sharpening).**
  v4's prose wrongly leaned on a "`0600` socket". The real mechanism: the socket file is mode
  **`0660`** so the user's shell can `connect()` to it — but because the **directory** is
  root-owned `0711`, **a same-uid process cannot `unlink`/recreate the socket inode**
  (`unlink` needs **write on the directory**, which the user lacks). Unsubstitutability comes
  from *directory* ownership, not file mode. Because `/run` is `root:root 0755` (host-verified)
  a same-uid process cannot create `/run/delphi` at all, and within the root-owned per-uid
  directory it can neither win a bind race nor occupy the path — there is **no window** for a
  competing socket. **A systemd *user* unit or `$XDG_RUNTIME_DIR` is explicitly insufficient**
  (user-owned → forgeable).
- **Non-user-readable minting key.** The HMAC key behind the capability token
  ([token.rs:67](die/inference/src/token.rs:67)) is held in the root daemon's memory (or a
  `0600` root-owned file) — **unreadable by the user's uid**, so same-uid malware cannot forge
  a token even with the wire format.
- **Children dropped to the user (the privilege split).** The root daemon `fork()`s the shell
  and the AI and, in **each child**, drops privileges **before** `execve` in the canonical
  order **`setgroups([]) → setgid(target_gid) → setuid(target_uid)`** (`setuid` **last** — once
  it relinquishes root it can no longer set the gid or supplementary groups). The daemon stays
  root (owns the directory, the socket, the key, and the PAM auth); the children run as the
  unprivileged user. This makes the sibling topology's "trusted shared parent" a **grounded**
  claim, not an assumption.
- **The floor — nothing below it.** The chain bottoms out at "root creates the directory and
  execs the binary." There is, by construction, no principal below root for a same-uid attacker
  to become.

### R3-01b — the shell's logind session (shape (b): the child opens its own, then execs into the shell)

R3-01 establishes the root daemon; R3-02's gate then demands the *shell* belong to an
active-local-seated logind session. This subsection specifies how that session comes to
exist — the lane-dependent half, now closed against real logind (systemd 259, Ubuntu 26.04).

- **Shape (a) is foreclosed; shape (b) is forced.** A parent cannot open a session *on behalf
  of* a child: `pam_systemd` always makes the **PAM-calling process itself** the session leader
  (leader == own pid), and logind rejects a second `CreateSession` for an existing leader with
  `SESSION_BUSY`. So the daemon cannot open the session and hand it down. The session must be
  opened by the process that will *be* in it — **shape (b)**.
- **The mechanism.** The root daemon `fork()`s a child. The child, still root, calls
  `pam_start("delphi-runtime", user, &conv)` → `pam_open_session` (becoming the session
  **leader**), then drops privileges in the canonical order `setgroups([]) → setgid → setuid`
  and **`execve`s directly into the shell binary**. Because `execve` preserves the pid, **the
  session leader, the pidfd-pinned process, and the shell are one and the same pid** (the
  leader == shell property — see R3-01c).
- **The daemon is not, and cannot be, the leader — confirmed live.** The production daemon is a
  root system service (R3-01), in `system.slice`, in no login session; `sd_pid_get_session(
  daemon_pid)` returns `-ENODATA`. Recon confirmed this holds regardless of the daemon's own
  cgroup placement: across every variant the daemon's pid did not resolve to the shell's
  session, while the shell's pid did. This is exactly what shape (b) requires and what makes the
  `SESSION_BUSY` foreclosure of shape (a) a non-issue — the daemon never tries to own the session.

### R3-01c — leader == shell, not a forked grandchild (Phase D tiebreaker)

The shape-(b) child could either (i) `execve` **into** the shell after `pam_open_session`
(leader == shell), or (ii) remain as a session-holder and **`fork()` the shell** as a child
(leader ≠ shell). Session *resolution* works for both — `sd_pid_get_session` resolves by
**cgroup membership**, so a grandchild shell resolves to the session and passes the gate just as
the leader does (A-1). The **failure mode** is the tiebreaker.

Recon Phase D killed the session-holder without a clean `pam_close_session`. Under the
leader ≠ shell topology the result was: the session entered state **`closing`** but did **not**
tear down; the orphaned shell **survived** (reparented to the user manager — this system runs the
systemd default `KillUserProcesses=no`) and continued to **cgroup-resolve to the now-`closing`
session**. `# DECISION:` **choose leader == shell.** Then shell-death *is* session-leader-death
*is* session teardown — there is no distinct session-holder that can outlive the shell, and no
orphan window.

**Evidential basis (do not carry silently).** The recon proved leader ≠ shell **end-to-end** (a
grandchild shell resolves *and* passes the full active-local-seated gate), and has now also
proved the exact single-process leader == shell sequence — one pid doing `pam_open_session` as
root → priv-drop → `execve` into the shell. It is **EXERCISED, not assumed**: across three runs
of the A-2 harness, **nine** independent cross-checks confirmed via **logind** — not via the
binary's self-report — that `session.Leader` == the running shell pid == the pid
`sd_pid_get_session` resolves the session from, **all after the `execve`**. The binary reports
only pid-continuity by construction; the authoritative assertion is external
(`loginctl show-session -p Leader` + `sd_pid_get_session`).

**What remains outstanding.** A recon proof is not a shipped regression test. The lane-dependent
build MUST still carry this assertion as its own **RED-first test in the runtime crate** —
verified to FAIL against a leader ≠ shell (forked-grandchild) implementation and pass against
leader == shell — so the property cannot silently regress. Two measurement boundaries also do
not transfer for free: the recon exercised a **stand-in** PAM stack (`/etc/pam.d/delphi-recon`,
`session required pam_systemd.so`), not the installer-shipped `/etc/pam.d/delphi-runtime` (see
the PAM-deviation forward obligation above); and the A-2 **lifecycle/refcount** results were
measured on `class=background` sessions while a production shell is `class=user` (`PAM_TTY` →
`seat0`). `/run/user/<uid>` is refcounted **per-user, not per-session-class**, so those results
are expected to carry — that expectation is **reasoned, not measured**.

This choice also **moots an edge the recon did not test:** whether a `closing` session whose VT
is *foreground* would still report `Active=yes` and thus pass the gate. The recon observed the
orphaned shell as `Active=no` only because the foreground had returned to the desktop's VT; the
foreground-`closing` case was not exercised. Under leader == shell no shell can outlive its
session, so the edge **cannot arise** and needs no separate proof. (Any future variant that
reintroduces a leader ≠ shell path would owe that proof.)

**Pre-`execve` fd containment is mandatory (FD-01).** Because leader == shell means the *same
pid* that ran `pam_start`/`pam_open_session` becomes the shell, every fd PAM opened — including
`pam_systemd`'s D-Bus connection to logind — is live in the process about to `execve`. Any such
fd not close-on-exec would be **inherited by the shell**: the same relay-bypass class B2A-R2-01
closed ([`runtime/src/fdsec.rs`](../runtime/src/fdsec.rs) `mark_cloexec_except`,
`close_range(.., CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE)`), one `execve` away. The launcher
MUST run the `mark_cloexec_except` allowlist sweep **after the last PAM call that needs those
descriptors and before the `execve`, preserving only explicitly intended fds**. The allowlist
MUST be **explicitly enumerated and minimal** — not "whatever happens to be low-numbered." Under
§4's Reading A, the one descriptor that legitimately survives into the shell is the fork-passed
private `SOCK_SEQPACKET` consent channel; everything else (PAM/D-Bus, the spawn pipe, any stray
inherited fd) is swept. This is not optional hardening — under leader == shell it is the identical
fd-containment property the runtime already enforces on the AI-spawn path, now obligatory on the
shell-spawn path. (Surfaced by this recon's own Codex gate — FD-01, P1.)

**What the sweep actually contains — corrected by test, with the PAM claim demoted (FD-01
amendment, 2026-07-22).** The paragraph above named *PAM's D-Bus fd* as the thing riding the
`execve`. A regression test built to prove exactly that (`runtime/tests/leader_is_shell.rs`,
`shell_inherits_only_the_allowlisted_fds_fd_01`) established otherwise, and the correction is
load-bearing:

- **PAM-fd containment is provided by the STACK, not by our sweep — on the current stack.** The
  test's first weaken moved the sweep to *before* `open_own_session`, so `pam_start`,
  `pam_open_session` (pam_systemd's sd-bus connection) and `sd_pid_get_session` all open their fds
  *after* the sweep. The child's post-`execve` fd table was nonetheless **identical** — none
  survived. The only explanation: **libsystemd/libpam open their fds `SOCK_CLOEXEC`/`O_CLOEXEC`
  and/or close them before returning.** So on this stack the sweep's *ordering-after-PAM* is **not
  demonstrably load-bearing** for PAM's own descriptors. **This is a property of THIS stack at THIS
  version, established empirically — NOT a guarantee.** The ordering requirement is **retained as
  defense-in-depth** against that property changing on a libsystemd/libpam upgrade, a different
  libc, or a future PAM module that does not self-CLOEXEC. A future reader must not read "not
  load-bearing" as "removable": remove it and a stack that stops self-containing silently
  reintroduces the relay-bypass.

- **The PRIMARY, load-bearing claim is the DAEMON's own inherited fds.** The approval-socket
  listener, the daemon end of the consent channel, and the spawn pipe are plain sockets/pipes with
  **no self-containment discipline** — nothing sets them `CLOEXEC` unless the sweep does. One of
  *those* riding the `execve` into the shell is the actual B2A-R2-01 relay-bypass instance the
  sweep exists to prevent. The FD-01 test proves this directly: it injects a **non-CLOEXEC socket**
  (the shape of those real fds) into the process that `launch()` forks from, asserts it is open and
  non-CLOEXEC immediately before the fork (so the injection cannot go vacuous the way Rust's
  default-CLOEXEC would make it), and checks it is **gone** from the shell's fd table after the
  `execve`. Its weaken is *removing the sweep entirely*; restored, the injected fd is contained.
  PAM-fd containment is demoted to "the stack provides it"; the sweep's proven job is the daemon's
  own fds.

**The session-only PAM deviation is deliberate, stack-specific, and sound only post-`execve`
(PAM-01/PAM-02/PAM-03).** On the launcher's session path the daemon runs the PAM *session* stack
(`pam_open_session`) of a **deliberately-selected, validated service** — production's
`/etc/pam.d/delphi-runtime`, shipped by `installer/`; it MUST NOT fall through to PAM's generic
`other` stack, since soundness cannot be claimed for a stack that was not deterministically chosen
(PAM-03). Any deviation stated here is a property of *that specific stack*, not of PAM in general.
On this path `pam_setcred` is not called (no `pam_authenticate` precedes it — credential
authentication, including the biometric/TPM tiers, is R3-02's concern, and per R3-02 those tiers
ride the **same daemon-driven PAM stack** as PAM modules, distinct from this launcher's
session-only stack). The **omission of a matching `pam_close_session` is sound ONLY
post-`execve`**: once the session-opening pid has `execve`'d into the shell, leader == shell
guarantees no process outlives the session to close it, and teardown is by **leader exit** (the
shell's death is the session's). **Every pre-`execve` failure path is different and MUST
`pam_close_session` (if the session was opened) + `pam_end` while the handle is still live** —
this is a production-launcher requirement, not optional (PAM-02). **Forward obligation:**
re-validate this deviation against the actual `/etc/pam.d/delphi-runtime` stack when `installer/`
ships it. *(C1 note: the stack now exists at `installer/pam/delphi-runtime` — the
minimal three lines `auth`/`account` `pam_unix.so` + `session required pam_systemd.so`. The
re-validation is against THAT file.)*

*(C2 note — the obligation is NARROWED, NOT closed. `installer/install.sh` now ships this stack
to `/etc/pam.d/delphi-runtime`, and the runtime tests run against the installed real stack. The
**success path is validated** against it: B-1 (leader==shell teardown by leader exit), B-3
(privilege drop), and FD-01 all pass with the session opened on the real stack. But the
**PAM-02 pre-`execve` unwind paths** — `pam_close_session` (if the session was opened) + `pam_end`
while the handle is live, on a failure BEFORE `execve` — are exercised by **no test** against the
real stack; the tests reach only the success path. So the deviation is **partially discharged
against the real stack, NOT closed**: the pre-`execve` failure-unwind behaviour on this specific
stack remains unproven.)*

**PAM-03, second form — an incomplete stack is more dangerous than a missing one.** The
launcher's existence check (`access(F_OK)`) covers "no stack" but **cannot see** "stack present,
`session` group empty." In that case `pam_open_session` returns **SUCCESS while registering no
logind session at all** — the shell then resolves to no session and the seated gate denies every
consent forever, with the symptom arbitrarily far from the cause. This is structurally the same
silent failure `VtName` exists to prevent (a cleanly-succeeding call yielding a seatless/absent
session), one level up. The launcher therefore also asserts the **outcome**: after a successful
`open_session` the pid MUST resolve to a logind session (`logind::session_id_for_pid`).
Deliberately NOT a config grep — following `@include` / `session include` / `substack` would mean
writing a PAM parser in a forked pre-`execve` child, and a grep for a `session` line would repeat
the very covers-one-form-misses-others mistake it is fixing.

**Provenance, worth keeping durable: this finding came from a PROBE, not an inference.**
`scratch/pam-empty-group-probe.sh` asked the question directly — build a throwaway PAM service
with an empty `session` group, call `pam_open_session` against it, and read what comes back —
rather than reasoning from a symptom toward a hypothesis about what PAM *might* do. Contrast the
same session's other misattributions (a stray fixture-owned PAM deleter, a doubled failure
marker, `--nocapture` interleaving, a full `/tmp` tmpfs, `b1_daemon_binary`'s feature gating):
every one of those was eventually SETTLED by reading an actual message or running an actual
check, never by reasoning further from the outside. The generalization: when a system's behavior
under an edge condition is uncertain, write the two-line script that puts the system in that
condition and reads the result, before spending an hour inferring what it probably does.

**`pam_faillock` — the tension is RECORDED, the decision is DEFERRED (do not re-derive this from
scratch).** Adding `auth required pam_faillock.so` (brute-force lockout on the consent prompt) is
a genuine trade-off with arguments on both sides, and someone will propose it later:

- **FOR.** R3-02a makes it sharp: a **locked** session is `Active=yes` and **passes the gate**
  (measured). PAM is therefore *the only control* standing between a locked, unattended Delphi
  screen and a minted consent token. Lockout is the standard defense against repeated guessing at
  exactly that screen.
- **AGAINST.** On this system consent gates **all** privileged action, so lockout is a
  **denial-of-consent** vector: an attacker who can reach the prompt (or merely trigger failed
  attempts) can lock the legitimate user out of approving anything — converting a confidentiality
  control into an availability failure against the user's own machine, which cuts against Iron
  Law #1 (user sovereignty) and #3 (graceful degradation).

`# DECISION:` **not in the minimal stack.** It ships as its own change with its own review, where
the lockout parameters (`deny`, `unlock_time`, whether the *root daemon's* own retries count) can
be reasoned about explicitly. Recording the tension here so the next reader inherits the analysis
rather than rediscovering it — and so a future "obviously we should add faillock" is met with the
availability counter-argument, not just adopted. A leader ≠ shell path would reintroduce both the explicit-close obligation on the
success path and the orphan window Phase D exhibited.

### R3-02 — the auth party is the root daemon (PAM), not a substitutable agent

v3 routed consent through a custom polkit action answered by "an active trusted agent." But
**polkit lets *any* process `RegisterAuthenticationAgent` for a session subject** (it fails
only if one is already registered) — a same-uid process can **race registration**, or **kill
the graphical agent and register its own**, becoming the party that renders the prompt and
collects the secret. That is the fd-theft hole's shape one layer up: the *attacker becomes
the trusted party*.

`# DECISION:` **the root-established daemon performs the authentication itself, over its own
private channel — ambient session agents are removed from the trust chain.** (Spec §11.2:
*highest fidelity / most-direct trusted party wins*.)

- The daemon (root, so it may read `/etc/shadow`) runs **`pam_start("delphi-runtime", user,
  &conv)` → `pam_authenticate`**. The `conv` callback ships each PAM prompt over the
  **private `SOCK_SEQPACKET` channel** to the **pinned shell** (R3-03), which displays it and
  returns the user's secret. The granting party is the **root daemon**; there is **no agent
  to register, hence no registration race**.
- **Active-local-seated gate.** Before authenticating, the daemon confirms the approving
  shell belongs to an **active, local, seated** login session via **systemd-logind**
  (`sd_pid_get_session` on the shell's pidfd-pinned pid → `sd_session_is_active` +
  `sd_session_is_remote` + `sd_session_get_seat`). Absent / inactive / remote / **seatless** →
  **DENY** (no fail-open — the prototype's ghost).
- **Seat provisioning requires only a real VT (recon-confirmed).** For the shape-(b) child's
  session to be seated, it is **sufficient** to hand PAM a real virtual terminal via
  `pam_set_item(PAM_TTY, "ttyN")` — `pam_systemd` derives `XDG_SEAT=seat0` and `XDG_VTNR=N` from
  the tty *name* itself. Explicitly setting `XDG_SEAT`/`XDG_VTNR` is **redundant** and not
  required. A session opened with **no** tty is registered `Class=background`, **seatless** —
  and, notably, still reports `Active=yes`; it is the **seat** axis, not the active axis, that
  denies it. This is the live confirmation that the B2a seat-tightening is load-bearing: the
  pre-B2a `active && !remote` gate would have admitted that seatless session; the seated gate
  correctly denies it.
- **No replay.** Each high-risk approval forces a **fresh `pam_authenticate`**; there is no
  cached/`_keep` authorization to replay. Biometric/TPM tiers ride the **same daemon-driven
  PAM stack** (a PAM module), not a separate agent.
- *(Option B, recorded + rejected: keep polkit but launch-and-pin a Delphi-owned agent from
  the same root launcher, verifying its pidfd/exe/cgroup/unique-bus-name and denying on
  replacement. Rejected: more moving parts — still trusts polkitd plus registration
  ordering — where daemon-owned PAM removes the agent surface entirely.)*

### R3-02a — what makes the active axis satisfiable (the deployment assumption)

R3-02's gate requires the approving shell's session to be **active** — the foreground session on
its seat. §4 required that without recording what makes it *satisfiable*, or what the axis
actually means. Both are settled here, the second by **measurement**.

**What `Active` actually encodes — MEASURED, not reasoned.** On the real seated lane, locking the
session (`loginctl lock-session`) left `Active=yes` and `State=active` **unchanged**; only
`LockedHint` flipped to `yes`. The gate verdict on a pid in that session was **ALLOW while
locked**. So `Active` encodes exactly one thing: **this session holds its seat's foreground**. It
is **necessary but NOT sufficient** for human presence — a locked Delphi screen is an `Active`
session, and the gate **ALLOWs it**.

> **THE GATE AND PAM ARE NOT REDUNDANT — do not "optimize" one away.**
> The gate establishes **WHICH SCREEN**: this session holds the seat's foreground, so a consent
> prompt is being shown where the seat is actually pointing. It says **nothing** about who, or
> whether anyone, is there.
> PAM establishes **WHICH HUMAN**: the fresh `pam_authenticate` the consent flow requires (R3-02,
> "no replay") demands the secret from a person, right now.
> **The locked-screen case is covered by PAM alone.** Measured above: a locked session is
> `Active=yes` and passes the gate. If a future change treats `pam_authenticate` as a removable
> second factor layered on an "already-strict" gate, it removes **the only** control standing
> between a locked, unattended Delphi screen and a minted consent token. The strictness of the
> gate does not substitute for it — the two answer different questions, and both are load-bearing.

**The deployment shapes give opposite answers, so the shape must be pinned:**

- **PRIMARY (the assumption).** The Delphi shell is the seat's own session — display-manager-
  shaped, holding the seat's VT. When the seat is showing Delphi, that session **is** the
  foreground session, so `Active=yes` and the gate can pass.
- **SECONDARY (foreclosed).** The shell runs as an extra session alongside another desktop, on its
  own VT. Recon C.3 measured the consequence: the moment the user returns to their desktop's VT
  the Delphi session reports `Active=no` and the gate **denies**. In that shape a consent prompt is
  essentially never approvable.

`# DECISION:` **Delphi deploys in the PRIMARY shape.** The Living Surface **is** the session on its
seat, not a guest window inside someone else's desktop.

**Product consequence (a security property deciding product scope — not a config gap).** This
forecloses shipping Delphi as an **application running on an existing desktop**. A future reader
finding that limitation should know it is a **security-model conflict**, not an unimplemented
feature or a packaging choice: on someone else's desktop the shell cannot hold the seat's
foreground, so the active axis denies by construction. Changing it means changing the gate, which
means re-deriving R3-02.

**A second case where the shape gives the right answer.** If *another user's* session takes the
seat's foreground, Delphi's session goes `Active=no` and the gate **denies** — correctly: the
person at the screen is not looking at Delphi, and no consent should be mintable on their behalf.
The axis is doing its job in both directions.

**The launcher's tty policy follows.** The shell is provisioned on the seat's VT (display-manager
shape) and `PAM_TTY=ttyN` names that VT — which, per the seat-provisioning simplification in
R3-02, is the **whole** seat obligation.

**Dev-time condition (documented, NOT relaxed).** Development on a workstation runs the SECONDARY
shape — the shell is launched from inside an existing desktop session — so a gate-POSITIVE is
reachable only by switching the seat's foreground to the shell's VT (`chvt`), exactly as the recon
did. This is a known dev-time condition to work *with*. It is **not** grounds for a dev-only
relaxation of the seat/active gate: a build- or env-gated bypass of that axis would be the
stub-shaped false green this arc has refused everywhere else — it would make the tests pass
without the property holding.

### R3-03 — the approver subject is a race-free pidfd from the spawn table

The daemon is the shell's **parent**: at spawn it obtains a **pidfd** (`CLONE_PIDFD` via
`clone3`, or `pidfd_open` immediately post-fork) — a handle **immune to pid-reuse**. The
approval subject is bound to **that pidfd** (the daemon's authoritative spawn-table identity),
**not** a later `/proc` lookup or a `pid+start-time` string (which `pkcheck`/`PolkitUnixProcess`
themselves warn is racy without a pidfd). `SO_PEERCRED` on the private channel corroborates.
If the shell dies, the pidfd reports it (`poll`/`waitid(P_PIDFD)`) ⇒ a recycled pid cannot
impersonate the approver.

### The flow

1. AI requests → arbiter builds `PendingAction` (§3) → returns `confirmation_required
   {pending_id, preview}` (the AI gets an id, not a token).
2. Arbiter delivers the preview to the **pidfd-pinned shell** on the private channel; the
   shell renders the exact action.
3. **Consent event.** Human clicks Approve/Deny. For a high-risk tier the **daemon** runs the
   logind active-session gate, then **`pam_authenticate`**, driving the conversation over the
   private channel to the pinned shell. Failure/absent session → DENY.
4. **Mint (private channel only).** The shell returns `{pending_id, action_digest,
   preview_version}` on the private channel; the arbiter verifies digest + version +
   freshness **and the PAM result** for high-risk, then mints the HMAC capability
   ([token.rs:67](die/inference/src/token.rs:67)) with the **root-held key**, bound to the
   digest + TTL. The mint is reachable **only** here.
5. **Complete (general socket).** The AI presents the token; the arbiter consumes it
   one-shot, **re-verifies the digest** against the live `PendingAction`, and executes the
   §6 sandbox built from that object.

### fd-channel hygiene (unchanged from v3, now under a grounded launcher)

The shell is exec'd with the approval-channel fd present (its `CLOEXEC` cleared); the daemon
holds the other end. The AI is exec'd with **`close_range(3, ~0U, CLOSE_RANGE_CLOEXEC |
CLOSE_RANGE_UNSHARE)`** (R4-02 — marks every inherited fd close-on-exec, so none survive the
AI's `execve`; it un-marks nothing) and is **never** passed the approval fd (no `SCM_RIGHTS`,
ever). `approve` is exposed **only** on the private channel — never on the general IPC socket.

### Failure modes (the APPROVE bar requires them — now anchored)

- **Daemon restart:** systemd restarts the **genuine (root)** daemon; the in-memory
  `PendingAction` registry is empty and the old channel is dead ⇒ **all pending approvals
  fail-closed**. Because the socket lives in the **root-owned** `/run/delphi/%i`, **no
  same-uid impostor can occupy the path during the restart window** (it cannot write the
  directory); the restarted root daemon re-creates the socket and re-spawns shell + AI.
- **Shell crash:** because **leader == shell** (R3-01c), the shell's death *is* the session
  leader's death *is* the session's teardown — there is no lingering `closing`-state session and
  no orphaned session member. The daemon sees the **pidfd death** (and EOF on the channel) ⇒
  **denies all approvals bound to that pidfd**; it re-spawns the shell — which opens a **fresh**
  logind session — with a fresh channel + fresh `PendingAction` ids. A respawned shell cannot
  complete the prior instance's approval.
- **AI-launched-first / ordering:** irrelevant — the daemon controls fd inheritance per-child
  (the AI never gets the fd) **and** the AI is a sibling (cannot ptrace the shell). Before the
  genuine daemon exists there is **no** approval socket and the AI **cannot create one** in
  the root-owned directory, so it cannot stand up a fake channel to self-approve.

---

## §5 · Process identity — DECIDED, with the spec from §4

- **Requester = separate process, dedicated low-priv uid.** In-process **dropped**. This uid
  (a) gives the AI no direct read of user files/the vault, and (b) is belt-and-suspenders for
  the §4 sibling defense (it independently denies ptrace).
- **`SO_PEERCRED`** on the general AF_UNIX socket (`0600`) gives **requester-side** identity
  (caller-continuity, A) and excludes other *users* — **not** the approver proof. The approver
  proof is §4 (root-established daemon + pidfd-pinned shell + daemon-driven PAM).

## §6 · Sandbox — honest scopes + reentry folded into the launch discipline

`bwrap` jail per execution, built from `PendingAction` (§3), default-deny:

- **FS:** no filesystem by default; mount exactly `fs_binds` (incl. the read-only
  `executable_fd`, and the sealed `script_memfd` where present); vault/`$HOME` never
  default-mounted.
- **Network — `none`/`full` only:** `--unshare-net` (none) / `--share-net` (full host net,
  previewed **unmissably** as full). No allowlist scope until real per-exec enforcement
  (nftables/proxy/eBPF) exists — a previewed-but-unenforced allowlist would be decorative.
- **Reentry containment (downstream of §4's grounded launch discipline):** the tool runs
  under a uid that **cannot reach daemon IPC**; the daemon's socket is a **root-owned
  filesystem socket outside the jail's mount set** (no abstract-namespace socket exists);
  inherited fds are cleared (`close_range`); env is scrubbed to `env_delta`. The approved
  command has **no path back into the daemon** to request or self-approve more.
- **Syscalls/resources:** seccomp default-deny; cgroup v2 mem/pids/CPU caps; timeout +
  kill-on-expiry. **Landlock** = optional in-process FS backstop where the target kernel
  guarantees it (FS only, not net).

## §7 · Audit — a TYPED runtime entry from the canonical object

The existing `log_action` records only `module/action/target/tier/result`
([audit.rs:177](fortress/src/audit.rs:177)) — it **cannot** carry the runtime object. **Spec:**
a typed `RuntimeAuditEntry` whose hash derives from the **same `PendingAction` +
`SandboxProfile`** used for preview/approval/sandbox, carrying: requester uid, **approver
(shell pidfd identity + PAM result + logind session id)**, `action_digest`, token
fingerprint, granted scope, **sandbox-profile digest**, and result. Its hash uses
`canonical_hash` with a **no-`..` exhaustive-destructure test mirroring `AuditEntry`'s** (the
dec4026 pattern at [audit.rs:57](fortress/src/audit.rs:57)) — so a field cannot be silently
omitted (DEFECT_CLASSES §1). Hash-chain integrity ≠ audit truth: truth comes from logging the
*same object* that drove preview + sandbox.

## §8 · Reconciliation — unchanged

Fortress is the policy/audit/capability substrate on both transports; caller-continuity
reused for the requester, human-consent a new root-anchored layer; structural confirmation
replaces the shell-UI-by-convention gap ([auth_guard.rs:106](services/src/auth_guard.rs:106));
one gated surface.

---

## Resolved items (rounds 1–5)

1. **AI placement — separate low-priv uid** (in-process dropped). [DECIDED, v2]
2. **F1 — fd-theft of the approval channel — CLOSED by the sibling topology** (AI is the
   shell's sibling, not ancestor; Yama `ptrace_scope`=1 restricts attach to descendants;
   `PR_SET_DUMPABLE`=0 + separate uid are belt). [CLOSED by round-3]
3. **R3-01 / R4-01 — launcher established by the OS trust root, to a concrete unit config**
   (`delphi-runtimed@.service` with **no `User=`** → root-owned `/run/delphi/%i`; the anchor is
   the root-owned **directory** — user can't `unlink` the `0660` socket; children dropped
   `setgroups→setgid→setuid` before exec; minting key `0600` root-only). The floor: nothing
   below "root creates the dir and execs the binary". [SPECIFIED, v5 — keystone]
4. **R3-02 — the auth party is the root daemon via PAM** over the private channel + logind
   active-session gate; ambient polkit agents removed (no registration race). [SPECIFIED, v4]
5. **R3-03 — approver subject = race-free pidfd** from the daemon's spawn table, not a racy
   `/proc` `pid+start-time` lookup. [SPECIFIED, v4]
6. **R3-04 / R4-02 — script pinning is mechanical:** exec the **interpreter fd**, pass the
   script as a **sealed memfd**; fd discipline uses `close_range(…, CLOSE_RANGE_CLOEXEC |
   CLOSE_RANGE_UNSHARE)` to **mark** (not close) then un-mark only the script fd — shebang
   never re-resolves by PATH, and no daemon fd leaks into the tool. [SPECIFIED, v5]
7. **Digest-verified approval mandatory** — bind everything to
   `action_digest = canonical_hash(PendingAction)`; verify at mint AND execute. [SPECIFIED]
8. **Audit truth — typed `RuntimeAuditEntry` from the canonical object + no-`..` test.**
   [SPECIFIED]
9. **Network honesty — `none`/`full` only; reentry closed via §4 launch discipline.** [SPECIFIED]
10. **Landlock = optional FS backstop, not net.** [DECIDED]
11. **R5-01 — the example unit block is copy-valid systemd** (whole-line `#` comments, bare
    directive values per `systemd.syntax(7)`). Documentation-syntax fix, no mechanism change.
    [FIXED, v6]

## What round-6 must confirm (trivial — the unit block parses; everything else is closed)

Round-5 confirmed every mechanism sound — the root-owned-directory anchor (`RuntimeDirectory=`
with no `User=` is root-owned; the `0711` dir blocks same-uid bind/unlink/replace while the
`0660` socket stays connectable), the `setgroups([])→setgid→setuid` drop order, and the full
`close_range(…, CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE)` / `execveat(…, AT_EMPTY_PATH)` fd
discipline — and returned a single **P3 (R5-01)**: the example unit block used inline `#`
comments, which `systemd.syntax(7)` does not honor. Round-6 confirms **only** that the
corrected block (whole-line comments, bare directive values) is **valid systemd syntax**.
Nothing substantive is open — the trust chain was grounded and adversarially attacked across
five rounds and bottoms out at root.

No code until round-6 APPROVE and operator ratification.
