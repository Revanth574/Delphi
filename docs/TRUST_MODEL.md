# Delphi Runtime Trust Model

- **Status: DRAFT v4 — STOP POINT B, root-anchor specification pass after a converging
  round-3 REVISE.** Round-1 FAIL (F1–F6) broke the v1 *structure*; v2 re-spined it; round-2
  FAIL caught a DECIDED-vs-open contradiction; v3 specified each mechanism. **Round-3
  CLOSED F1 the strong way** (sibling-topology + Yama `ptrace_scope`=1 — see §4) and
  returned REVISE on the **two trust-chain-bottom links**: the document *named* a "trusted
  launcher" (R3-01) and a "trusted agent" (R3-02) without **establishing** either against
  the OS trust root — and a same-uid process can pre-empt anything established only at user
  level. v4 anchors both to **root** (the floor: same-uid malware cannot become root), and
  fixes the subject-binding (R3-03) and script-pinning (R3-04) mechanics. Not ratified;
  goes to **round-4** (is the launcher grounded to the OS root with nothing below it, is the
  auth party genuine, are the mechanics closed), then operator ratification. **No runtime
  code until APPROVE + ratify.**
- **Provenance:** draft `9a7e3b9` → round-1 FAIL → re-spine `d25b987` → round-2 FAIL → spec
  pass `410b9b3` → round-3 REVISE → this root-anchor pass → round-4 → ratified (separate
  later commit).
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
  - `fexecve`/`execveat(AT_EMPTY_PATH)`, `close_range`/`CLOEXEC`, and the `AuditEntry`
    `canonical_hash` + no-`..` pattern ([audit.rs:57](fortress/src/audit.rs:57)) — as v3.

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
[auth.rs:534](services/src/auth.rs:534) — reused on the *requester* side) and **(B)
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
  5. **Non-CLOEXEC caveat:** the interpreter reads `/proc/self/fd/<script_memfd>`, so the
     memfd must survive the exec — clear `CLOEXEC` on **only** that fd **after**
     `close_range(3, ~0, 0)` has cleared every *other* inherited fd, immediately before the
     exec. The sealed content cannot be swapped (`F_SEAL_WRITE`), so passing by
     `/proc/self/fd` is safe — the path resolves to the sealed kernel object, not a file an
     attacker can replace. Executable-TOCTOU is thereby extended **to the interpreter**:
     neither the interpreter binary (exec'd fd) nor the script content (sealed memfd) is
     swappable between hash and exec.
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

### R3-01 — the launcher, established by the OS trust root (THE KEYSTONE)

v3 *asserted* "the daemon is the trusted launcher" but never established the **genuine**
daemon: a same-uid process could pre-empt a user-level socket/unit or stand up a fake
topology **before** the real daemon exists. `installer/` is greenfield, so this is designed,
not retrofitted. The genuine daemon is established **by root, not by the user**:

- **systemd *system* service (root).** The daemon binary is **root-owned** and exec'd by
  **systemd (PID 1)** — a trusted exec chain from init, not a user-spawned process. A
  per-user instance is templated (`delphi-runtime@%i.service`, started by the system manager
  on session creation), still rooted in the system manager.
- **Root-created runtime directory.** The unit declares the socket directory
  **`/run/delphi/%i`** via `RuntimeDirectory=` (created by systemd as **root**). Because
  `/run` is `root:root 0755` (host-verified), **a same-uid process cannot create
  `/run/delphi` or place/substitute a socket inside the root-owned directory.** The daemon's
  approval socket lives there; a stray/pre-existing entry is an error the (root) daemon
  unlinks. **User-writable `$XDG_RUNTIME_DIR` or a systemd *user* unit is explicitly NOT
  sufficient** — a same-uid process can pre-empt user-level establishment; only root-level
  establishment defeats it.
- **Non-user-readable minting key.** The HMAC key behind the capability token
  ([token.rs:67](die/inference/src/token.rs:67)) is held in the root daemon's memory (or a
  `0600` root-owned file) — **unreadable by the user's uid**, so same-uid malware cannot
  forge a token even with the wire format.
- **The anchor (the floor — nothing below it).** Root is the OS trust root the user's
  malware **cannot become**. Root-established ⇒ the launcher, the socket directory, and the
  minting key are all outside same-uid reach. The daemon then drops to the user's uid to
  spawn the shell + AI as children, making the sibling topology's "trusted shared parent" a
  **grounded** claim rather than an assumption.

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
- **Active-local-session gate.** Before authenticating, the daemon confirms the approving
  shell belongs to an **active, local** login session via **systemd-logind**
  (`sd_pid_get_session` on the shell's pidfd-pinned pid → `sd_session_is_active` +
  seat/remote check). Absent/inactive/remote → **DENY** (no fail-open — the prototype's ghost).
- **No replay.** Each high-risk approval forces a **fresh `pam_authenticate`**; there is no
  cached/`_keep` authorization to replay. Biometric/TPM tiers ride the **same daemon-driven
  PAM stack** (a PAM module), not a separate agent.
- *(Option B, recorded + rejected: keep polkit but launch-and-pin a Delphi-owned agent from
  the same root launcher, verifying its pidfd/exe/cgroup/unique-bus-name and denying on
  replacement. Rejected: more moving parts — still trusts polkitd plus registration
  ordering — where daemon-owned PAM removes the agent surface entirely.)*

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
holds the other end. The AI is exec'd with **`close_range(3, ~0, 0)`** and is **never**
passed the approval fd (no `SCM_RIGHTS`, ever). `approve` is exposed **only** on the private
channel — never on the general IPC socket.

### Failure modes (the APPROVE bar requires them — now anchored)

- **Daemon restart:** systemd restarts the **genuine (root)** daemon; the in-memory
  `PendingAction` registry is empty and the old channel is dead ⇒ **all pending approvals
  fail-closed**. Because the socket lives in the **root-owned** `/run/delphi/%i`, **no
  same-uid impostor can occupy the path during the restart window** (it cannot write the
  directory); the restarted root daemon re-creates the socket and re-spawns shell + AI.
- **Shell crash:** the daemon sees the **pidfd death** (and EOF on the channel) ⇒ **denies
  all approvals bound to that pidfd**; it re-spawns the shell with a fresh channel + fresh
  `PendingAction` ids. A respawned shell cannot complete the prior instance's approval.
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

## Resolved items (rounds 1–3)

1. **AI placement — separate low-priv uid** (in-process dropped). [DECIDED, v2]
2. **F1 — fd-theft of the approval channel — CLOSED by the sibling topology** (AI is the
   shell's sibling, not ancestor; Yama `ptrace_scope`=1 restricts attach to descendants;
   `PR_SET_DUMPABLE`=0 + separate uid are belt). [CLOSED by round-3]
3. **R3-01 — launcher established by the OS trust root** (systemd *system* service,
   root-owned `/run/delphi/%i`, non-user-readable minting key, reject user sockets). The
   floor: same-uid malware cannot be root. [SPECIFIED, v4 — keystone]
4. **R3-02 — the auth party is the root daemon via PAM** over the private channel + logind
   active-session gate; ambient polkit agents removed (no registration race). [SPECIFIED, v4]
5. **R3-03 — approver subject = race-free pidfd** from the daemon's spawn table, not a racy
   `/proc` `pid+start-time` lookup. [SPECIFIED, v4]
6. **R3-04 — script pinning is mechanical:** exec the **interpreter fd**, pass the script as
   a **sealed memfd**, handle the non-CLOEXEC caveat — shebang never re-resolves by PATH.
   [SPECIFIED, v4]
7. **Digest-verified approval mandatory** — bind everything to
   `action_digest = canonical_hash(PendingAction)`; verify at mint AND execute. [SPECIFIED]
8. **Audit truth — typed `RuntimeAuditEntry` from the canonical object + no-`..` test.**
   [SPECIFIED]
9. **Network honesty — `none`/`full` only; reentry closed via §4 launch discipline.** [SPECIFIED]
10. **Landlock = optional FS backstop, not net.** [DECIDED]

## What round-4 must confirm (the bottom link, grounded)

- **Launcher grounded to root, nothing below it (R3-01).** Does systemd-as-PID-1 establishing
  a **root-owned** binary + **root-created** `/run/delphi/%i` actually deny a same-uid process
  any way to **be**, **pre-empt**, or **impersonate** the launcher — including: racing to
  create the socket before the unit (root-owned dir denies it), occupying the path during a
  restart, or templating-unit ordering games? Is the minting key genuinely out of same-uid
  reach? Is there **any** principal below root this still rests on?
- **Auth party genuine (R3-02).** Does daemon-owned `pam_authenticate` + the logind
  active-local-session gate **remove every substitution surface** that the ambient-agent model
  had — confirm no same-uid process can interpose on the PAM conversation, forge a logind
  "active" verdict, or feed the daemon a false PAM result? Is the private channel the *only*
  path the PAM prompt/response travels?
- **Mechanics closed.** pidfd subject binding is race-free (R3-03); interpreter-fd exec +
  sealed memfd is swap-free incl. the non-CLOEXEC caveat (R3-04); the typed audit no-`..` test
  forecloses field omission.
- **Failure modes real, not gestured** (daemon restart / shell crash / AI-first) under the
  root-owned socket directory — attack each for a stale-approval or impostor-socket window.
- **APPROVE bar:** the launcher is grounded to the OS root with nothing below it, the auth
  party is genuine and non-substitutable, and the mechanics are closed. **REVISE** only if a
  residual principal below root remains — name it (there is, by construction, nothing below
  "root creates the directory and execs the binary").

No code until round-4 APPROVE and operator ratification.
