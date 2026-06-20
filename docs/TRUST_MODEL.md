# Delphi Runtime Trust Model

- **Status: DRAFT v3 — STOP POINT B, specification pass after a converging round-2 FAIL.**
  Round-1 FAIL (F1–F6) broke the v1 *structure*; v2 re-spined it. Round-2 confirmed the
  **structure is sound** but returned FAIL on a real defect: the document claimed the
  approver-placement "DECIDED" while leaving the **mechanisms it rests on open** (the
  private-channel launch topology; the polkit replay seam) — an internal contradiction
  (*the approver identity **is** the mechanism; an open mechanism is not a decided
  identity*). v3 is a **specification pass**: each named requirement is pinned to a
  concrete, host-verified mechanism, and the contradiction is resolved. Not ratified;
  goes to **round-3** (does each mechanism close its finding, are the failure modes real),
  then operator ratification. No runtime code until APPROVE + ratify.
- **Provenance:** draft `9a7e3b9` → round-1 FAIL → re-spine `d25b987` → round-2 FAIL →
  this spec pass → round-3 → ratified (separate later commit).
- **Verified-on-host primitives this pass rests on** (probed; the target Delphi-OS kernel
  must guarantee them): `PR_SET_DUMPABLE`=0 + Yama `ptrace_scope`=1 block
  `pidfd_getfd`/ptrace fd-theft (kernel 6.6, `pidfd_getfd` needs
  `PTRACE_MODE_ATTACH_REALCREDS`, denied for a non-dumpable target by a same-uid non-root
  caller); polkit `auth_self` (non-`_keep`) via `pkcheck` (present); `fexecve`/`execveat`
  (present) for fd-based exec; `close_range`/`CLOEXEC` for fd hygiene; the `AuditEntry`
  `canonical_hash` + no-`..` pattern ([audit.rs:57](fortress/src/audit.rs:57)) to mirror.

---

## §0 · Scope, first goal, sequencing — unchanged

Boundary designed for the hard case (**arbitrary `argv`** for a developer workflow); two
sub-surfaces — (a) the enumerated tier-classified methods ([auth.rs:232](services/src/auth.rs:232)),
(b) arbitrary `argv`. **Increment 1** proves the whole boundary on the known-method
surface; **Increment 2** admits `argv` through it. Autonomous `Brain` (unwired) is wired
only after both hold.

## §1 · Adversary — unchanged (same-uid is central)

The AI runs *as the user* (its own low-priv uid, §5); same-uid malware presents the same
uid; injected content makes the *honest* AI request destructive actions. uid is necessary
but **not sufficient** to identify the approver. (v2 §1 stands.)

## §2 · The boundary: human-consent ≠ caller-continuity — unchanged

Two distinct things both hold: **(A) caller-continuity** (SVC-2 same-caller binding,
[auth.rs:534](services/src/auth.rs:534) — reused on the *requester* side) and **(B)
human-consent** (a signal the same-uid requester cannot produce). v3 specifies the
mechanisms for (B); the principle is v2's.

---

## §3 · The canonical `PendingAction` — SPECIFIED (incl. executable pinning, F3 fix)

One immutable arbiter-built object; preview, approval-digest, sandbox, and audit all
derive from it. v3 pins the **executable** so the digest covers the *object that execs*,
not a path (R2-F3):

```
PendingAction {                       // arbiter-built, immutable; id = Uuidv4, single-use
  pending_id, preview_version,
  executable_fd     : OwnedFd,        // OPENED before preview (O_PATH→O_RDONLY); the kernel
                                      //   object, not a path — no swap window
  executable_digest : [u8;32],        // hash of the bytes read THROUGH executable_fd
  argv, cwd, env_delta,
  fs_binds          : Vec<(PathBuf,BindMode)>,
  net_policy        : NetPolicy::{None|Full},   // R3 — no allowlist (see §6)
  timeout, required_tier,
  // for scripts: interpreter_fd + interpreter_digest + script is content-pinned too
}
action_digest = delphi_hardening::canonical_hash(PendingAction)   // injective; no-`..`
```

- **Executable pinning (F3):** the arbiter `open`s the executable **before** preview, hashes
  the bytes read *through that fd*, binds **that exact fd** read-only into the jail, and
  execs it by descriptor — `fexecve`/`execveat(AT_EMPTY_PATH)` (host-verified). There is no
  path→exec window for a same-uid swap. **Scripts** (`#!`) pin *both* the interpreter fd +
  digest **and** the script content (a script is data the interpreter reads; the digest
  covers the opened script object, and it is bound read-only and passed by fd, never re-read
  from a swappable path).
- **The digest is the binding** for preview = approval = sandbox = audit (F3/F4/F6). The
  no-`..` `canonical_hash` discipline means a new `PendingAction` field cannot be silently
  unhashed (DEFECT_CLASSES §1, both-halves).
- **Preview is the arbiter's rendering of this object** — never AI text, never derived from
  observed content (defeats the §1 injection vector: the human sees what *execs*).

---

## §4 · The consent path — SPECIFIED (launch topology F1, polkit F2; the contradiction resolved)

The flow is v2's; v3 **specifies the two mechanisms the approver identity rests on**, so
"the approver is a trusted shell instance" is now a *decided, implementable* claim, not a
named requirement.

### The launch topology (R2-F1 — the new crux, now SPECIFIED to a real mechanism)

`installer/` is empty (greenfield), so this is *designed*, not retrofitted:

- **Parent / root of trust:** the **daemon is the trusted launcher.** It creates the
  approval `socketpair(AF_UNIX, SOCK_SEQPACKET)` and **spawns both the shell and the AI
  itself** (fork+exec), controlling each child's fd table and uid.
- **fd passing — only the shell:** the shell is exec'd with the approval-channel fd present
  in its fd table (that one fd's `CLOEXEC` cleared); the daemon holds the other end. The AI
  is exec'd with **`close_range(3, ~0, 0)`** clearing every inherited fd, and is **never**
  passed the approval fd (no `SCM_RIGHTS` to it, ever). `approve` is exposed **only** on
  this private channel — never on the general IPC socket.
- **fd-theft closure (the verified mechanism):** the boundary-holding processes — daemon and
  shell — call **`prctl(PR_SET_DUMPABLE, 0)`** at startup. With Yama `ptrace_scope`=1, a
  same-uid non-root process (the AI, or same-uid malware) **cannot** `ptrace`-attach or
  `pidfd_getfd` the shell to duplicate its approval fd: `ptrace_may_access` denies
  `PTRACE_MODE_ATTACH_REALCREDS` against a non-dumpable target (host-verified). The fd is
  unreachable via `/proc/<pid>/fd` for the same reason (the dir is root-owned for a
  non-dumpable process). **The AI also runs under a separate, lower-priv uid** (§5), which
  independently denies ptrace.
- **Failure modes (the APPROVE bar requires them):**
  - **Daemon restart:** the daemon owns the `PendingAction` registry (in-memory) and both
    socketpair ends. On restart the registry is empty and the old channel is dead → **all
    pending approvals are invalidated (fail-closed)**; the daemon re-spawns the shell + AI
    and re-creates the channel. No stale approval survives a restart.
  - **Shell crash:** the daemon sees EOF on the private channel → **denies all pending
    approvals bound to that shell instance**; it re-spawns the shell with a fresh channel +
    fresh `PendingAction` ids. A crashed-and-respawned shell cannot complete an approval
    issued to the prior instance.
  - **AI-launched-first / ordering:** irrelevant — the daemon controls fd inheritance
    per-child, so the AI never receives the approval fd regardless of spawn order; and the
    daemon accepts `approve` **only** on the private channel, which the AI has no fd to.

### The consent event + polkit (R2-F2 — replay seam SPECIFIED)

1. AI requests → arbiter builds `PendingAction` (§3) → returns `confirmation_required
   {pending_id, preview}` (the AI gets an id, not a token).
2. Arbiter delivers the preview to the shell **on the private channel**; the shell renders
   the exact action.
3. **Consent event.** Human clicks Approve/Deny. For a **high-risk tier**, the **daemon**
   (not the shell) performs a polkit check via `pkcheck`/libpolkit:
   - a **custom action `org.delphi.runtime.approve`** with `<allow_active>auth_self</allow_active>`,
     `<allow_any>no</allow_any>`, `<allow_inactive>no</allow_inactive>`, and **no `_keep`
     variant** (so each check forces a fresh authentication — **no cached/replayed
     authorization**, closing the consent-replay seam);
   - the **subject is the shell process** (pid + start-time, race-safe), and `pending_id` +
     `action_digest` are passed as **action details** (the authorization is for *this exact
     action*, surfaced in the agent prompt);
   - **polkit / an active trusted agent absent, or not an active local session → DENY**
     (no fail-open — the prototype's ghost). On hardware with biometric/TPM, that rides the
     same polkit/PAM path.
4. **Mint (private channel only).** The shell returns `{pending_id, action_digest,
   preview_version}` on the private channel; the arbiter verifies digest + version +
   freshness **and the polkit result for high-risk**, then mints the HMAC capability
   ([token.rs:67](die/inference/src/token.rs:67)) bound to the digest + TTL. The mint is
   reachable **only** here.
5. **Complete (general socket).** The AI presents the token; the arbiter consumes it
   one-shot, **re-verifies the digest** against the live `PendingAction`, and executes the
   §6 sandbox built from that object.

**Both reopening seams are now closed by verified mechanisms — equally weighted:** the
**fd seam** (private socketpair + `PR_SET_DUMPABLE`=0 + Yama + separate uid + `close_range`)
and the **consent-replay seam** (custom polkit action, non-`_keep`, daemon-performed,
absent→deny). The approver identity is therefore **DECIDED** (no longer contradicted by an
open mechanism).

---

## §5 · Process identity — DECIDED, with the spec from §4

- **Requester = separate process, dedicated low-priv uid.** In-process **dropped** (F2). This
  uid (a) gives the AI no direct read of user files/the vault, and (b) independently denies
  ptrace of the boundary processes.
- **`SO_PEERCRED`** on the general AF_UNIX socket (`0600`) gives **requester-side** identity
  (caller-continuity, A) and excludes other *users* — **not** the approver proof. The
  approver proof is §4 (private channel + polkit).

## §6 · Sandbox — honest scopes + reentry folded into the launch discipline (F5)

`bwrap` jail per execution, built from `PendingAction` (§3), default-deny:

- **FS:** no filesystem by default; mount exactly `fs_binds` (incl. the read-only
  `executable_fd`); vault/`$HOME` never default-mounted.
- **Network — `none`/`full` only (F5, R3-honest):** bwrap is `--unshare-net` (none) /
  `--share-net` (full host net, previewed **unmissably** as full). No allowlist scope is
  offered until real per-exec enforcement (nftables/proxy/eBPF) exists — a previewed-but-
  unenforced allowlist would be a decorative guard.
- **Reentry containment (F5, downstream of §4's launch discipline):** the tool runs under a
  uid that **cannot reach daemon IPC**; **no daemon socket is mounted into the jail and no
  abstract-namespace daemon socket exists** (the daemon uses a filesystem socket outside the
  jail's mount set); inherited fds are cleared (`close_range`); env is scrubbed to
  `env_delta`. The approved command therefore has **no path back into the daemon** to
  request or self-approve more.
- **Syscalls/resources:** seccomp default-deny; cgroup v2 mem/pids/CPU caps; timeout +
  kill-on-expiry. **Landlock** = optional in-process FS backstop where the target kernel
  guarantees it (FS only, not net).

## §7 · Audit — a TYPED runtime entry from the canonical object (F4 fix, SPECIFIED)

The existing `log_action` records only `module/action/target/tier/result`
([audit.rs:177](fortress/src/audit.rs:177)) — it **cannot** carry the runtime object, so the
canonical-object audit was aspirational. **Spec:** a typed `RuntimeAuditEntry` whose hash
derives from the **same `PendingAction` + `SandboxProfile`** used for preview/approval/
sandbox, carrying: requester uid, approver (shell-instance id + polkit result),
`action_digest`, token fingerprint, granted scope, **sandbox-profile digest**, and result.
Its hash uses `canonical_hash` with a **no-`..` exhaustive-destructure test mirroring
`AuditEntry`'s** (the dec4026 pattern at [audit.rs:57](fortress/src/audit.rs:57); 8-field
hasher + destructure) — so a field cannot be silently omitted (DEFECT_CLASSES §1). Hash-
chain integrity ≠ audit truth (F6): truth comes from logging the *same object* that drove
preview + sandbox.

## §8 · Reconciliation — unchanged (v2 §8)

Fortress is the policy/audit/capability substrate on both transports; caller-continuity
reused for the requester, human-consent a new layer; structural confirmation replaces the
shell-UI-by-convention gap ([auth_guard.rs:106](services/src/auth_guard.rs:106)); one gated
surface.

---

## Resolved items (round-1 + round-2)

1. **AI placement — separate low-priv uid** (in-process dropped). [DECIDED, v2]
2. **Approver identity — trusted shell instance via the SPECIFIED launch topology**
   (socketpair + `PR_SET_DUMPABLE`=0 + Yama + separate uid + `close_range`; `approve` only
   on the private channel) **+ the SPECIFIED polkit consent** (custom non-`_keep` action,
   daemon-performed, absent→deny). The v2 DECIDED-vs-open contradiction is resolved: the
   mechanism is now real. [DECIDED + SPECIFIED, v3]
3. **Digest-verified approval mandatory** — bind everything to
   `action_digest = canonical_hash(PendingAction)`; verify at mint AND execute. [SPECIFIED]
4. **Executable TOCTOU — pinned by fd** (`open`→hash-through-fd→`fexecve`; scripts pin
   interpreter+content). [SPECIFIED, F3]
5. **Audit truth — typed `RuntimeAuditEntry` from the canonical object + no-`..` test.**
   [SPECIFIED, F4]
6. **Network honesty — `none`/`full` only; reentry closed via §4 launch discipline.**
   [SPECIFIED, F5]
7. **Landlock = optional FS backstop, not net.** [DECIDED]

## What round-3 must confirm (mechanisms, not concepts)

- **Each mechanism closes its finding** against the live primitives: does
  `PR_SET_DUMPABLE`=0 + Yama actually deny `pidfd_getfd`/ptrace fd-theft on the **target**
  kernel (not just WSL)? Is the custom polkit action non-replayable as specified (no `_keep`,
  daemon-performed, absent→deny — any path to a cached/forged result)? Is `fexecve`-of-fd
  truly swap-free incl. the script case? Does the typed audit entry's no-`..` test foreclose
  field omission?
- **The failure modes are real, not gestured** (daemon restart / shell crash / AI-first) —
  attack each: any window where a stale approval survives, a respawned shell completes a
  prior instance's approval, or the AI obtains the fd across a restart.
- **Residual seams:** a same-uid process that is *itself* made non-dumpable racing the
  launcher; `pidfd` obtained before `PR_SET_DUMPABLE` is set (set it **before** the first
  `exec` and before any fd is live); polkit agent spoofing under the same uid.

No code until round-3 APPROVE and operator ratification.
