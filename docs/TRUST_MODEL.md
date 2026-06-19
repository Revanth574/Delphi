# Delphi Runtime Trust Model

- **Status: DRAFT v2 — STOP POINT B, re-spined after a Codex round-1 FAIL.** Round-1
  broke the v1 design on paper (findings F1–F6) before any runtime code — the arc working
  as intended (the prototype's equivalent holes were found *after* building, in two
  Critical reviews). v2 re-spines around the root error; it is **not** ratified. It goes
  to a **round-2 adversarial threat-model review** (does the re-spine close F1–F6 and is
  the crux truly resolved), then to operator ratification. No runtime code until APPROVE +
  ratify.
- **What round-1 found (the diagnosis we re-spine around):**
  - **Root (F1+F2 — the FAIL):** v1 reduced "requester ≠ approver" to "different uid."
    `SO_PEERCRED` proves a **uid**, but the runtime runs *as the user*, so the AI, any
    same-uid process/malware, and any in-process refactor all present the **approver's**
    uid; `0600` excludes other *users*, not same-*user* processes. And the cloud-send
    pattern v1 generalized is **same-*caller* binding — a capability/continuity pattern,
    NOT a human-*consent* proof.** v1 conflated *continuity-of-caller* with
    *a-human-approved*.
  - **Canonicalization (F3+F4+F6):** v1 lacked a single immutable source of truth, so
    *preview*, *enforced scope*, *approval*, and *audit* could diverge.
  - **Honesty (F5):** bwrap cannot enforce a network allowlist (R3) — a previewed
    "net only to github.com" would be a decorative guard (the human approves a restriction
    that does not exist).

---

## §0 · Scope, first goal, sequencing

Unchanged from v1 and not at issue in the FAIL. The boundary is designed for the **hard
case — arbitrary `argv` execution** (the developer-workflow first goal: set up a project,
run tests). Two sub-surfaces: **(a)** the enumerated, tier-classified method set
(`METHOD_POLICY`, [auth.rs:232](services/src/auth.rs:232)); **(b)** arbitrary `argv` (no
static policy — the command is data, the highest-risk surface, where the prototype's
bypass landed). **Increment 1** proves the *whole* boundary (now incl. the v2 consent
proof) on the known-method surface; **Increment 2** admits `argv` through the proven
boundary. The autonomous AI tool-invoker (`Brain`, **unwired** — zero consumers) is wired
only after both hold.

---

## §1 · Assets and adversary (the same-uid adversary is now central)

Assets: the user's filesystem, credentials (Fortress vault), network identity, process
execution, and **the integrity of the consent record**.

The FAIL forces the adversary model to be explicit about **same-uid**:

1. **The AI as an untrusted requester running *as the user*.** It presents the user's uid.
   Any defense that authenticates a uid authenticates the AI as readily as the human.
2. **Same-uid malware / a co-resident process.** Identical uid; `0600`/peer-uid does not
   exclude it.
3. **An in-process component** (if the AI shared the daemon's address space) — "one refactor
   from holding the mint" (F2). v2 **removes this category by construction** (§5: the
   requester is a separate process, separate uid).
4. **Prompt-injection / tool-observed content** — the AI is *honest but manipulated* into
   *requesting* a destructive action. A distinct threat from self-minting; defeated only if
   the human approves the **true** action (§3 canonical object + §4 preview fidelity).
5. **A compromised tool** attacking the host (delete/exfiltrate/fork-bomb) — §6 sandbox.

**Consequence:** uid is necessary but **not sufficient** to identify the approver. The
approver must be a **specific, attested shell instance** plus, for high-risk, a **real
human-presence challenge the same-uid AI structurally cannot satisfy** (§4).

---

## §2 · The trust boundary: human-consent ≠ caller-continuity (the root fix)

The corrected principle, stated to foreclose the v1 conflation:

> **Two different things must both hold, and they are NOT the same mechanism:**
> **(A) caller-continuity** — the entity that *completes* an action is the same one the
> approval was issued to (SVC-2's same-caller binding does this; reused on the
> *requester* side); and
> **(B) human-consent** — *a human approved this exact action*, proven by a signal the
> requester (the AI, even same-uid) **cannot produce**.

v1 had only (A) and miscalled it (B). v2 adds (B) as a distinct layer:

- **The approver is a specific trusted *shell instance*, not a uid.** It is reached by a
  **private, daemon-created approval channel** (a `socketpair` whose far end is handed to
  the shell *at launch* and **never** placed in the AI process's fd table — §4/R1). The
  `approve` operation is **not exposed on the general IPC socket at all.** A same-uid
  process that connects to the general socket cannot reach `approve`; it does not have the
  private fd.
- **High-risk actions additionally require OS user-presence** the same-uid AI cannot fake:
  a **polkit** `auth_self`/`auth_admin` challenge (R2 — the user authenticates in the
  *trusted polkit agent*, a process the AI does not control), optionally biometric/TPM via
  PAM/polkit on target hardware. This is the human-consent proof (B) that same-caller
  binding (A) is not.

(A) is reused, not reinvented: the same-caller binding ([auth.rs:534-663](services/src/auth.rs:534))
and `CallerIdentity` ([auth.rs:86](services/src/auth.rs:86)) bind the *requester's*
completion to its issuance — correct and kept. The error was using (A) *as* (B).

---

## §3 · The canonical PendingAction (the spine — closes F3/F4/F6)

The single structural fix for the divergence findings: **one immutable, arbiter-generated
canonical action object** that **preview, approval-digest, sandbox construction, and audit
all derive from.** Nothing AI-supplied flows into any of those four; nothing can diverge.

```
PendingAction {                       // built ONLY by the arbiter, immutable once created
  pending_id        : Uuid,           // unguessable (v4), single-use, never reused
  preview_version   : u32,            // bumped if the arbiter re-renders; approval pins it
  // the EXACT thing that will run — the arbiter's own normalization, never AI text:
  executable        : PathBuf,        // resolved absolute path
  executable_digest : [u8;32],        // hash of the binary that will exec (TOCTOU-closed)
  argv              : Vec<String>,    // the literal argument vector
  cwd               : PathBuf,
  env_delta         : Vec<(String,String)>,   // explicit; the base env is scrubbed (§6)
  fs_binds          : Vec<(PathBuf, BindMode)>,// ro/rw, the EXACT mounts the jail gets
  net_policy        : NetPolicy,      // None | Full  (R3 — no allowlist; §6)
  timeout           : Duration,
  required_tier     : PermissionTier, // from METHOD_POLICY / argv-risk classification
}
```

- **`action_digest = canonical_hash(PendingAction)`** — the injective, length-prefixed,
  field-counted digest from `delphi_hardening::canonical_hash` (the leverage-pass
  primitive; the no-`..` destructure discipline applies so a new field can't be silently
  unhashed). **`PendingAction` is a capability-type in this project's own corpus sense**
  (DEFECT_CLASSES §5): the unforgeable object everything binds to.
- **Preview = the arbiter's rendering of `PendingAction`** — argv array, cwd, executable
  path+digest, env delta, FS bind modes, net policy, timeout. **Never AI-supplied text, and
  never derived from attacker-controlled content** (closes F3 *and* the §1.4 injection
  vector: the human sees what *runs*, not what the AI or an injected page *claims*). The
  prototype literally shows the bug it forecloses: its `approval_scope(&kind)` omitted the
  `check_command` that `request_hash(&kind)` included — **shown scope ≠ enforced scope**
  ([actions.rs `approval_scope`/`request_hash`](shell-bridge/src/actions.rs)). Here preview
  and enforcement are the *same object*.
- **Approval pins the digest** (closes F4 — the approve-A/mint-B race): the approval the
  shell returns carries `{pending_id, action_digest, preview_version}`. The arbiter mints
  **only** if the digest matches the live `PendingAction` and it has not expired; at execute
  time it **re-verifies** the digest before constructing the sandbox. `pending_id`s are
  unguessable and single-use; `PendingAction` records are immutable (a re-render is a new id).
- **Sandbox is constructed from the same object** (§6) — the jail's binds/net/limits are the
  object's fields, so the box is exactly the previewed-and-approved scope.
- **Audit logs the object** (§7) — not AI text.

---

## §4 · Approval and the consent event (re-spined around §2/§3)

The protocol is **request-response, no server push** ([protocol.rs](shell-bridge/src/protocol.rs)).
The flow, with the v2 corrections:

1. **Request (AI, over the general socket).** The AI proposes an action. The arbiter
   **normalizes it into a `PendingAction`** (§3) — resolving the executable, fixing argv,
   computing the digest. It does **not** act. It returns `confirmation_required{pending_id,
   preview}` to the AI. The AI holds a **`pending_id` (an identifier), never a completable
   token.**
2. **Surface to the approver — over the PRIVATE approval channel, not the general socket.**
   The arbiter delivers the `PendingAction` preview to the **shell instance** on the private
   `socketpair` fd (R1). Because there is no push on the general socket, the private channel
   is the daemon→shell path; it is also where `approve` is *received* (and nowhere else).
   The shell renders the arbiter's exact preview.
3. **The consent event.** The human clicks **Approve/Deny** in the shell. For a **high-risk**
   tier, this additionally triggers a **polkit `auth_self`** challenge (R2) — the user
   authenticates in the trusted polkit agent; **the same-uid AI cannot satisfy it.** This is
   human-consent proof (B), not caller-continuity (A).
4. **Mint (approver → arbiter, on the private channel).** The shell returns
   `{pending_id, action_digest, preview_version}` **on the private channel**. The arbiter
   verifies digest + version + freshness, verifies the polkit result for high-risk, then
   mints the HMAC capability bound to the digest + TTL (the R1 token pattern,
   [token.rs:67](die/inference/src/token.rs:67)). **The mint is reachable only via the
   private channel from the attested shell** — never from the general socket the AI uses.
5. **Complete (AI → arbiter, general socket).** The AI presents the token; the arbiter
   `consume`s it one-shot (the prototype's sound half), **re-verifies the digest against the
   live `PendingAction`**, and executes the §6 sandbox built from that object.

**Why the same-uid AI cannot forge consent now:** (i) the token is HMAC-bound (forgery);
(ii) the mint fires only on `approve` over the **private channel**, which the AI's process
**does not have an fd to** (R1) — *not* on a uid it shares; (iii) high-risk additionally
requires a **polkit** challenge the AI cannot answer (R2). The three are independent.

---

## §5 · Transport and process identity (re-spined — the placement crux, DECIDED)

- **The requester (AI) runs as a separate process under a dedicated, lower-privilege uid.**
  **In-process is dropped** (F2: code-discipline, not structure — "one refactor from
  breach"). This is now **decided, not an open item.** The AI's blast radius shrinks as a
  bonus (it cannot read the user's files or the vault directly).
- **`SO_PEERCRED` is used for *requester-side* identity** — distinguishing the AI's uid from
  others, and binding the requester's completion (caller-continuity, A) — **NOT as the
  approver proof.** The approver proof is the private channel + user-presence (§4).
- **The general IPC socket** is AF_UNIX + `SO_PEERCRED` + `0600` (still worthwhile: excludes
  other *users* and gives requester identity). It exposes request/query/complete — **never
  `approve`.**
- **The private approval channel** is a `socketpair` the daemon (or a trusted launcher)
  creates and hands to the shell at launch (R1 — greenfield: no launch topology exists yet,
  so it is designed correctly from the start). The AI process is spawned **without** that fd
  (controlled fd inheritance / no `SCM_RIGHTS` pass to the AI; CLOEXEC on everything not
  explicitly passed). **The launch topology is the new crux and must be specified precisely
  (see open items).**

---

## §6 · Execution sandbox — honest scopes, socket/fd/env discipline (R2/R3 + F5)

A `bwrap` jail per execution, **constructed from the `PendingAction`** (§3), default-deny:

- **Filesystem:** start with **no filesystem**; mount exactly `fs_binds` (the approved ro/rw
  binds). The vault path and `$HOME` are never in the default set.
- **Network — HONEST scopes only (F5 correction):** bwrap is namespace on/off (R3:
  `--unshare-net` / `--share-net`, **no host allowlist**). So the only scopes that can be
  *enforced* are **`none`** (`--unshare-net`) and **`full`** (`--share-net`, previewed
  explicitly as "full host network"). A "net only to host X" scope is **not offered** until
  real per-exec enforcement exists (nftables per-namespace / a forced filtering proxy /
  eBPF) — a previewed-but-unenforced allowlist would be a decorative guard the human
  approves falsely.
- **Daemon-reentry containment (F5):** the executed tool runs as a **non-approver, non-daemon
  uid**; the daemon's IPC sockets are **outside** the jail (no abstract-namespace sockets
  reachable from inside; close all inherited fds; scrub the environment to `env_delta`
  only). Otherwise the approved command could connect back to the daemon and **request more
  actions / self-approve** — re-entering the boundary from inside the box.
- **Syscalls/resources:** seccomp default-deny of dangerous classes; cgroup v2 mem/pids/CPU
  caps; wall-clock timeout + kill-on-expiry (the prototype already had output/kill
  discipline, [actions.rs:40-44](shell-bridge/src/actions.rs:40)).
- **Landlock** is an **optional in-process FS backstop** where the target kernel guarantees
  it (R2: not exposable on WSL) — **FS only, not network**; Increment 1 must hold on
  bwrap+seccomp+cgroups alone.

---

## §7 · Audit — from the canonical object (closes F6)

Every mint, deny, and execution is logged through the built Fortress chain
(`AuditLog::log_action` [audit.rs:177](fortress/src/audit.rs:177), `verify_chain`
[audit.rs:289](fortress/src/audit.rs:289)) **from the `PendingAction` object, not AI text** —
recording: requester uid, approver (shell-instance + polkit result), **`action_digest`**,
token fingerprint, granted scope, **sandbox-profile digest**, and result. **Hash-chain
integrity ≠ audit truth** (F6): integrity proves the log wasn't edited; *truth* comes from
logging the same canonical object that drove preview + sandbox, so the record cannot
describe something other than what ran. The entry hash is `canonical_hash` (injective).

---

## §8 · Reconciliation (corrected)

Not two auth systems — SVC-2 already wired Fortress's engine ("wire-don't-rebuild",
[auth.rs:310](services/src/auth.rs:310); `PermissionChecker` consumed at
[auth.rs:344](services/src/auth.rs:344)). The decision:

1. **Fortress is the policy/audit/capability substrate**, on both transports.
2. **Caller-continuity (SVC-2 same-caller binding) is reused for the requester**; **human-
   consent is a new, distinct layer** (private channel + polkit) — the explicit
   v1→v2 correction.
3. **Structural confirmation replaces the shell-UI-by-convention gap**
   ([auth_guard.rs:106](services/src/auth_guard.rs:106)) for the runtime's destructive
   surface, via §3/§4.
4. **One gated tool surface** (known methods → tier; argv → §3 approval + §6 sandbox); no
   ungated path.

---

## Resolved open items (per the round-1 review)

1. **AI placement — DECIDED: separate process + dedicated low-priv uid.** In-process dropped.
2. **Approver identity — DECIDED: trusted shell instance via a private channel + polkit
   user-presence for high-risk.** The same-uid "shell credential over the general socket"
   idea is **dropped** (it didn't separate approver from requester).
3. **Digest-verified approval is MANDATORY** — preview, approval, sandbox, audit all bind to
   `action_digest = canonical_hash(PendingAction)`; mint and execute both verify it.
4. **Landlock = optional FS backstop, not network** — Increment 1 holds without it.
5. **Scope object is full** — `{executable+digest, argv, cwd, env_delta, fs_binds, net_policy
   (none/full), timeout, tier}`, not just FS+net.

---

## New open items / what round-2 must attack

- **The private-channel launch topology (the new crux, R1 greenfield).** *Who* creates the
  `socketpair` and launches the shell vs. the AI such that only the shell gets the fd? Is it
  the daemon (then who launches the daemon and the shell — systemd user units? a trusted
  launcher?), and can a same-uid process intercept the fd at launch, re-exec, or inherit it?
  This must be specified precisely; it is where the new approver-identity rests.
- **polkit integration fidelity (R2).** Is the polkit action defined so the AI cannot
  pre-authorize, cache, or replay an `auth_self` result? Does `loginctl` seat-presence need
  to be a precondition? What is the fallback on a target without polkit/biometric — deny, or
  a weaker presence signal (and is that honest)?
- **Executable-digest TOCTOU (§3).** Between digest and exec, can the binary be swapped?
  (bwrap `--ro-bind` of the resolved path; re-verify under the mount.)
- **Daemon-reentry (§6).** Prove the jailed tool has *no* path back to any daemon socket
  (abstract namespace, `/proc`, inherited fd, `$XDG_RUNTIME_DIR`).
- **Network honesty (§6/F5).** Confirm `none`/`full` are the only scopes offered until real
  enforcement exists; ensure "full" is previewed unmissably.

---

## What goes to round-2

Codex round-2: **does the re-spine close F1–F6, and is the crux truly resolved?** Confirm:
(F1/F2) the approver is no longer a uid — attack the private channel + polkit instead;
(F3/F4/F6) the canonical `PendingAction` actually makes preview = enforcement = approval =
audit, with no divergence path (re-attack the injection vector §1.4 and the
approve-A/mint-B race); (F5) the network claim is honest and daemon-reentry is closed. And
the convergence bar: **APPROVE requires the new launch-topology crux (private-channel
mechanism) resolved or named** — the boundary's strength now rests there, as it rested on
placement before.

No code until round-2 APPROVE and operator ratification.
