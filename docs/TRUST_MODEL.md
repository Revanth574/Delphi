# Delphi Runtime Trust Model

- **Status: DRAFT — STOP POINT B.** This document is the gate. No runtime code (no
  daemon, no scaffold, no wiring) is written until it is ratified. It goes first to an
  **adversarial threat-model review** (Codex: *find the bypass in the design*), then to
  operator ratification.
- **Scope:** the trust boundary for **executing actions on the user's machine on the
  user's behalf** — the runtime arc. It does **not** re-litigate the existing ZKQP /
  cloud-egress model (that is built and is the *pattern* this reuses).
- **Method:** every reused component is cited at `file:line` against real code. Three
  brief premises were corrected against the code (noted inline + collected at the end).
  Four research tasks (R1–R4) ground the load-bearing decisions; their findings are
  folded into §3–§5.

---

## §0 · Scope, first goal, and sequencing

**The hard case the boundary is designed for.** Delphi's vision is "the AI operates the
user's tools." The runtime therefore has two sub-surfaces:

- **(a) The known, tier-classified method surface** — the ~60 D-Bus methods already
  classified in `METHOD_POLICY` ([auth.rs:232](services/src/auth.rs:232)): read-only →
  `Autonomous`, mutating → `Confirm`, destructive/`forget_*`/reversal → `Biometric`.
  This is a *fixed, enumerated* set with a per-method tier.
- **(b) Arbitrary shell-command execution** — running a caller-supplied `argv` (set up a
  project, run tests, run a build). There is no safe enumerated set here; the command is
  data. This is the **highest-risk surface and the one with no static policy**, and it is
  exactly where the prototype's approval bypass landed (§1, §3).

**This document designs the boundary for (b)** — the hard case — because a boundary that
holds for arbitrary `argv` subsumes the known set. The *first concrete run-anything
goal* is confirmed: **execute shell commands for a developer workflow** (the prototype's
real target — `actions.rs`'s `DEVELOPER_REPO_CHECK`: git checks + an optional
caller-provided project command in a repository). If the real first goal were instead
browser automation or executing code-as-input, §5's sandbox shape would change; it is
not, so §5 is built for subprocess/`argv` containment.

**Sequencing (explicit — this is the recommendation's core, not an aside):**

- **Increment 1 — prove the boundary on the *known-method* surface.** Stand up the daemon
  with the authenticated transport (§4), route requests through the existing SVC-2
  `AuthGuard` tier+identity model (§7), and prove the **structural confirmation** path
  (§3) end-to-end on a *Biometric*-tier known method (e.g. `timeline.undo`). No arbitrary
  `argv` yet. This proves requester≠approver and the consent event on a bounded surface.
- **Increment 2 — arbitrary `argv` through the *proven* boundary.** Only once Increment 1
  is ratified and built: admit the `argv` surface (b), executed inside the
  approval-scoped sandbox (§5). The arbitrary surface rides the boundary proven in
  Increment 1; it is never the first thing wired.

The autonomous AI tool-invoker (`Brain`, currently unwired — zero consumers) is **not**
wired until both increments hold. The boundary exists *before* the thing it constrains.

---

## §1 · Assets and adversary

**Assets protected:** the user's filesystem (read of secrets, write/delete), the user's
credentials (the Fortress vault), the user's network identity (exfiltration), process
execution (arbitrary code / resource exhaustion), and the **integrity of the consent
record** (what the user actually approved).

**Adversaries, in priority order:**

1. **The AI/automation itself, as an *untrusted requester* (the primary adversary).** This
   is the lesson of the prototype and the defining stance of this model. The AI is a
   capable, fast, fallible component that *proposes* actions. It must be treated as
   unable to approve its own actions — not because it is malicious, but because (i) a
   prompt-injection or a model error can make it *try* anything, and (ii) the entire value
   of "operates your tools" collapses if the operator can also self-authorize. **The AI is
   inside the trust boundary for *requesting* and outside it for *approving*.**
2. **A co-resident local process** (same machine, possibly same user) that connects to the
   runtime's IPC surface to drive actions or forge approvals. The current WS transport is
   reachable by *any* local process (§4).
3. **Tool-observed content as an injection vector** — a web page, file, or command output
   that contains text directed at the AI ("approve and run X"). Defended by the same
   requester≠approver structure: observed content can influence what the AI *requests*,
   never what the human *approves*.
4. **A compromised/runaway tool** — the executed command itself attacking the host
   (deleting files, exfiltrating, fork-bombing). Defended by §5 (the sandbox).

**Non-adversary (stated invariant, inherited from SVC-2):** the standard session bus / a
shared-secret-on-an-open-port is **not** a security boundary
([auth.rs:28-36](services/src/auth.rs:28)). The boundary is the authenticated transport
(§4), not the wire.

---

## §2 · The trust boundary: requester ≠ approver

The single structural principle, from which everything else follows:

> **The entity that *requests* an action and the entity that *approves* it must be
> different, and the approval must arrive by a path the requester cannot drive.**

The prototype violated this in the most direct way: approval was a field
(`user_confirmed: bool`) in the *requester's own message*, gated by a *channel secret*
(`bridge_auth_token`) the requester also holds. The requester minted its own approval
([handler.rs `authorize_approval_mint`], read in the recon). The `consume` side was
sound — server-minted random token → server-stored grant **bound to the exact
`ExecuteRequest`**, one-shot, TTL'd ([actions.rs:180-220](shell-bridge/src/actions.rs:180));
the defect was entirely in *minting*. **This model fixes minting and keeps the
consume model.**

Three roles, three distinct identities:

- **Requester** — the AI/automation (or any client) that asks for an action. Untrusted for
  approval.
- **Approver** — the human, acting through the **shell** (the UI surface). The only entity
  that can cause an approval to be minted.
- **Arbiter** — the daemon. Holds the policy (Fortress `PermissionChecker`), the approval
  registry, the audit log, and the sandbox. It mints an approval **only** on a consent
  signal from the approver, and binds it to exactly what the requester asked for.

The reconciliation §7 makes concrete: this is **not** a new auth system — the arbiter is
SVC-2's already-built model, moved onto the runtime's transport.

---

## §3 · Approval minting and the consent event (THE CRUX)

This is the section the whole document's strength rests on, and the one the prototype got
wrong. It answers: **what is the human-consent event, concretely, and how does the daemon
receive a consent signal that did not originate from the AI?**

### R1 — the reusable minting pattern (grounded, confirmed)

Delphi already has an unforgeable consent mechanism for one path (cloud egress). It is two
composed mechanisms, both reused here:

- **Forgery resistance — the HMAC capability.** `ConfirmationToken`
  ([token.rs:67-115](die/inference/src/token.rs:67)) is an opaque HMAC-SHA256 over the
  *exact operation parameters*, keyed by an **ephemeral secret held only by the gateway**.
  Its constructor is `pub(crate)` (no public mint, [token.rs:77](die/inference/src/token.rs:77));
  it is minted only by `issue_token` ([egress.rs:303](die/inference/src/egress.rs:303)) and
  verified only by `verify_token` ([egress.rs:260](die/inference/src/egress.rs:260)), with a
  30s TTL re-derived over the freshly re-sanitized input. **A requester cannot fabricate a
  token that verifies** — the only way to hold a valid one is to have received a
  `ConfirmationRequired` from the gateway.
- **Consent/caller binding — the registry.** `CloudSendConfirmations`
  ([auth.rs:534-663](services/src/auth.rs:534)) binds a pending confirmation to the
  **requester's unspoofable identity** (unique bus name) + TTL; a completion from a
  *different* identity is hard-denied (`is_bound_fresh`,
  [auth.rs:581](services/src/auth.rs:581)).

The working round-trip on `main` (the template): a request returns
`EgressOutcome::ConfirmationRequired` **without acting**
([egress.rs:118](die/inference/src/egress.rs:118)), surfaced as
`{"status":"confirmation_required","sanitized_preview":…,"token":…}`
([services/inference.rs:208-227](services/src/inference.rs:208)); a *second* request
carries the token back; the gateway verifies before acting.

### The gap R1 does *not* close (and the prototype tripped on)

The HMAC token proves *"the gateway issued a confirmation request for this exact thing."*
It does **not**, by itself, prove *"a human approved it"* — that property comes from
**who echoes the token**. In the cloud path the echoer is the shell, and the shell's UI
only echoes after a human clicks. So the consent guarantee ultimately rests on: **the
approval arrives over a connection that belongs to the shell (the human's UI), not to the
AI.** This is the property §4 (transport identity) must provide and §3 must require.

### The consent event, concretely

The protocol is **request-response only — no server push**
([protocol.rs](shell-bridge/src/protocol.rs): `Request{id,method,params}` /
`Response{id,result,error}`). The consent flow is therefore:

1. **Request (AI).** The AI requests an action (a known method, or an `argv` execution
   with a proposed FS/net scope). The daemon does **not** act. It creates a **server-side
   pending approval**: `{pending_id, exact_action, argv, proposed_scope, expiry}`, stored
   in the arbiter. It returns `confirmation_required{pending_id, preview}` to the AI's
   request. **Crucially, the AI receives a `pending_id`, not a token it can complete
   with.**
2. **Surface to the approver.** The daemon makes the pending approval visible to the
   **shell** over the *shell's own connection*. Because the protocol has no push today,
   this is a concrete design choice (§ open items): either (a) extend the protocol with a
   server→client `pending_approval` push frame (recommended — polling is racy for a
   security prompt), or (b) the shell polls `actions.pending_approvals`. The shell renders
   the **exact preview**: the command, the `argv`, the repository, and **the FS/net scope
   that will be granted** (§5 ties the grant to this preview).
3. **The consent event = a human action in the shell UI, off the AI's request path.** The
   user clicks **Approve** (or Deny), or satisfies an OS/biometric prompt for a
   higher-tier action. This event happens *in the shell*, which the AI does not drive.
4. **Mint (approver → arbiter).** The shell sends `actions.approve{pending_id}` **over its
   authenticated connection**. The arbiter mints the approval — an HMAC capability bound
   to `{pending_id, exact_action, granted_scope, TTL}` (the R1 pattern) — **only because
   this message arrived on the approver's authenticated connection** (§4). The mint is
   never reachable from the requester's path.
5. **Complete (AI → arbiter).** The AI presents the token; the arbiter `consume`s it
   (one-shot, request-bound — the prototype's sound half), then executes inside the
   approval-scoped sandbox (§5).

### Why the AI cannot fabricate the consent — and the part that is UNDECIDED

The unforgeability rests on two things. The first is solid; the second is the **single
hardest, partly-undecided decision in this document, and it is an architecture choice, not
a hand-wave:**

- **(i) The token is HMAC-bound and server-minted** (R1). The AI cannot forge it. ✓ Solid.
- **(ii) The mint fires only on `actions.approve` from the *approver's* authenticated
  connection.** This requires the daemon to **distinguish the shell's connection from any
  connection the AI controls.** How that distinction is made depends on where the AI runs —
  and that is a decision this document must make:

  | AI placement | How shell≠AI is enforced | Strength | Cost |
  |---|---|---|---|
  | **Separate process, separate uid** (privilege separation) | `SO_PEERCRED` uid (§4): shell = user uid, AI = a dedicated lower-priv uid. Arbiter accepts `approve` only from the user uid. | **Hard, kernel-enforced** — the AI literally cannot present the approver's uid | Larger: a uid, a sandboxed AI process, IPC between them |
  | **Separate process, same uid** | `SO_PEERCRED` uid cannot distinguish; need a per-connection shell credential established at shell-launch by the daemon (a secret the AI never receives) or pid-pinning the shell | Medium — rests on launch-time secret hygiene, but established *out of band*, not in the AI's request path | Medium |
  | **In-process (AI inside the daemon)** | The AI has *no* WS connection; the only client is the shell. The mint is reachable **only** from the shell-connection message handler, and the AI module never holds the approval-registry handle | Soft — a *code-structure* boundary, not a process boundary; a future refactor could breach it | Smallest |

  **Recommendation:** the autonomous AI tool-invoker runs as a **separate process under a
  dedicated, lower-privilege uid** (row 1) — `SO_PEERCRED` then gives a hard
  requester≠approver boundary for free, and the AI's own blast radius (§5) is reduced as a
  bonus. **Undecided / for ratification:** whether Increment 1 may ship with the in-process
  soft boundary (row 3) as a stopgap — acceptable *only* if (a) the approval-registry
  handle is provably unreachable from any AI/orchestrator module (enforced by crate
  boundaries + a no-`..`-style structural test), and (b) the hard uid boundary lands before
  the autonomous tool-invoker (`Brain`) is wired. This is the explicit decision the
  adversarial review should attack first.

---

## §4 · Transport authentication (R3)

**Today:** the bridge is **TCP `127.0.0.1:9800`** ([server.rs:159](shell-bridge/src/server.rs:159)),
with **no connection authentication and no per-connection identity** — any local process
can connect and call any handler method. The WS caller-binding (Piece-1b) is *started but
unbuilt* ([PROGRESS.md:212](PROGRESS.md:212); [handler.rs:288](shell-bridge/src/handler.rs:288)).

**Decision: AF_UNIX domain socket + `SO_PEERCRED` + `0600` socket permissions.**

- `SO_PEERCRED` (via tokio `UnixStream::peer_cred() → {uid, gid, pid}`) gives the
  **kernel-verified, unforgeable** identity of the connecting peer. This is the **same
  mechanism the existing D-Bus path already trusts** — `caller_resolver` resolves caller
  uid/pid via `get_connection_credentials`
  ([caller_resolver.rs:301-310](services/src/caller_resolver.rs:301)). So this does **not
  invent** an identity model; it brings D-Bus's *own* kernel-verified identity to the WS
  transport. This **dissolves the "WS vs D-Bus" question: one identity model, both
  transports.**
- `0600` ownership on the socket path means only the owner's processes can connect at all
  (defense in depth under the AF_UNIX path; the same single-user assumption the deployed
  D-Bus model makes).
- **Rejected: a token-in-handshake over TCP.** It is strictly weaker — any local process can
  connect to the port, so security rests entirely on token secrecy (where is it stored?
  readable by other local processes?). That is the prototype's channel-secret flaw raised
  one level. AF_UNIX + peer creds replaces *secrecy of a token* with *kernel attestation of
  a process*.

This decision is what makes §3(ii) row 1 buildable: peer-uid is exactly the
shell≠AI discriminator.

---

## §5 · Execution sandbox — default-deny, approval-parameterized (R2)

The argv surface (b) is "run anything," which is only safe if "anything" runs in a box
scoped to **exactly what the human approved**. The sandbox is therefore **default-deny**
and **parameterized by the approval** — it is the runtime enforcement of the §3 grant.

**R2 — primitives actually available** (probed on the dev host, kernel 6.6; the target
Delphi-OS kernel configures its own):

| Primitive | Available | Role |
|---|---|---|
| **bubblewrap (`bwrap`)** | ✅ `/usr/bin/bwrap` | Userspace jail (namespaces + seccomp) driven as a **subprocess wrapper** — fits Delphi's existing subprocess pattern |
| **unprivileged user namespaces** | ✅ (`max_user_namespaces` > 0) | bwrap/namespaces without root |
| **cgroup v2** | ✅ `cgroup2fs` | CPU / memory / pids caps; kill-on-OOM |
| **seccomp-bpf** | standard (kernel ≥3.5) | Syscall allow/deny under bwrap |
| **Landlock** | ⚠️ target-kernel-dependent (not exposable on WSL — no `/sys/kernel/security/lsm`) | In-process path-based FS restriction; **complement on a kernel that guarantees it**, not a dependency in Increment 1 |

**Decision: a `bwrap` subprocess jail per execution, default-deny, scoped by the
approval.**

- **Filesystem:** start with **no filesystem**. The approval grants a specific bind — e.g.
  `--ro-bind <repo>` or `--bind <repo>` for the approved repository path, plus a private
  `--tmpfs /tmp`. Nothing outside the approved path is visible. The Fortress vault path and
  the user's home are *never* in the default mount set.
- **Network:** start with **`--unshare-net` (no network)**. The approval may grant a
  network allowlist; absent that grant, the tool has no network (kills the
  exfiltration adversary §1.4 by default).
- **Syscalls:** seccomp default profile denying the dangerous classes (no new namespaces,
  no `ptrace`, etc.).
- **Resources:** cgroup v2 memory + pids + CPU caps; a wall-clock timeout with
  kill-on-expiry (the prototype already had output/kill discipline,
  [actions.rs:40-44](shell-bridge/src/actions.rs:40)).
- **Landlock** is layered in as an in-process FS backstop **where the target kernel
  guarantees it**; the design does not *depend* on it for Increment 1 (it cannot be
  exercised on the WSL dev kernel).

**The §5↔§3 tie (Sharpening 3):** the sandbox's grant set **is** the approval's scope. The
preview the human approved (§3 step 2) names the FS path and net allowlist; the arbiter
binds that exact scope into the approval token; the sandbox is constructed from the token's
scope, nothing wider. "Run anything" is safe because the *anything* runs in a box that
extends to **precisely** what the human saw and approved — no more. An AI that requests a
broader scope must get a broader approval, and the human sees the broader scope in the
preview before approving.

---

## §6 · Audit and reversibility

Every approval mint, every execution, and every denial is recorded through the **built**
Fortress audit chain — `AuditLog::log_action` ([audit.rs:177](fortress/src/audit.rs:177)),
integrity-verified by `verify_chain` (hash-chained, [audit.rs:289](fortress/src/audit.rs:289)).
The existing `AuthGuard` already records every D-Bus decision at its policy tier
([auth_guard.rs:182](services/src/auth_guard.rs:182)); the runtime extends the *same* sink
to the WS transport and the argv surface.

The record is **leak-safe by existing discipline** (the action string and tier, never
caller payloads — SVC-4). The canonical, injective entry hash is the `delphi-hardening`
`canonical_hash` primitive (the leverage pass's audit-migration site), so an audit entry
cannot be silently edited to change *what was approved*.

Reversibility (the 24-hour-undo affordance) is downstream of this: a faithful audit of
*what ran with what approval* is the precondition for scrubbing an action backward. The
trust model's job is to guarantee the audit is **complete and unforgeable**, which the
above provides; the undo UI is a later runtime deliverable, not part of this boundary.

---

## §7 · The reconciliation decision (what this document ratifies)

The premise of "two parallel security worlds to reconcile" is **corrected by the code**: it
is not two auth systems. SVC-2 already *wired* Fortress's policy engine —
`services::auth::MethodPolicy` builds `PermissionChecker::new(METHOD_POLICY)` and routes
every tier decision through it ([auth.rs:344/369](services/src/auth.rs:344)), explicitly
"wire-don't-rebuild." The split is **by transport**, not by duplicated logic:

- **D-Bus** has the built, layered model (`AuthGuard.enforce`
  [auth_guard.rs:121](services/src/auth_guard.rs:121): tier + unspoofable
  `CallerIdentity` + the cloud-send same-caller binding + audit). It does not run (no
  daemon).
- **WebSocket** — the transport the shell and the runtime use — has **none** of it.

**The decision:**

1. **One identity model, both transports.** Adopt SVC-2's caller-identity + tier model on
   the WebSocket transport via AF_UNIX + `SO_PEERCRED` (§4). Fortress remains the **policy,
   audit, and capability substrate** (`PermissionChecker`, `AuditLog`, the unforgeable
   capability types — `SanitizedPrompt` private mint
   [egress.rs:64-71](die/inference/src/egress.rs:64), the HMAC token). It is **not** a
   parallel world to be merged away; it is the shared foundation both transports stand on.
2. **Close the structural-confirmation gap for the destructive surface.** The documented
   gap — general `Confirm`/`Biometric` methods *proceed* on authorization, relying on the
   shell UI for confirmation rather than a structural token
   ([auth_guard.rs:106-114](services/src/auth_guard.rs:106)) — is closed for the runtime by
   extending the cloud-send unforgeable-token + consent-event model (§3) to **every**
   destructive action and to the argv surface. Confirmation becomes structural at the
   arbiter, not conventional at the shell.
3. **Define the tool surface gated.** The known set is the `METHOD_POLICY` tier table
   (Increment 1). The argv surface (Increment 2) is admitted only through the §3 approval +
   §5 sandbox. There is no fourth, ungated path.
4. **The requester is untrusted for approval.** Encoded structurally per §2/§3, enforced by
   transport identity per §4, with the AI's process/uid placement (§3(ii)) the one open
   architecture decision.

---

## Corrections to the brief, against the code

- **`PermissionChecker` is wired, not orphaned.** The README's "permission engine has no
  production consumer" (from the pre-SVC-2 review FORT-Q5) is **wrong**:
  `services::auth::MethodPolicy` is its production consumer
  ([auth.rs:344](services/src/auth.rs:344)). It is *wired, not running* (no daemon), which
  is a different and weaker claim.
- **The "two parallel security worlds" framing is a transport split, not duplicated auth.**
  SVC-2 chose "wire-don't-rebuild" ([auth.rs:310](services/src/auth.rs:310)); there is one
  policy model, exposed on one transport (D-Bus) and absent on the other (WS). §7 is the
  correction made into a decision.
- **(Confirmed, not corrected)** The cloud-send same-caller binding *is* the reusable
  minting pattern (R1), and the prototype's `consume` half *was* sound — only minting was
  defective.

---

## Open / undecided items (for the adversarial review to attack)

1. **AI process/uid placement (§3(ii)) — the load-bearing one.** Separate-uid privilege
   separation (hard boundary) vs. in-process mint-isolation (soft boundary) for Increment
   1. Recommended: separate-uid before the autonomous tool-invoker ships; in-process
   acceptable for Increment 1 *only* under the two stated conditions.
2. **Pending-approval surfacing under a request-response protocol (§3 step 2).** Add a
   server→client push frame (recommended) vs. shell polling. A polling design has a
   time-of-check window the review should probe.
3. **Same-uid shell≠AI discrimination (§3(ii) row 2)** if privilege separation is deferred:
   the launch-time shell-credential mechanism is unspecified here and must be designed or
   the row-2 option dropped.
4. **Landlock dependency boundary (§5).** Increment 1 must hold on a kernel *without*
   guaranteed Landlock (bwrap + seccomp + cgroups only); confirm the bwrap-only profile is
   sufficient for the argv surface, or mark Landlock as required (which constrains the
   target kernel).
5. **Approval scope expressiveness (§5).** The grant is FS-path + net-allowlist today; is
   that sufficient for "set up a project / run tests," or does it need (e.g.) a
   sub-process/argv allowlist within the repo? Under-expressive scope forces over-broad
   approvals (the thing §5 exists to prevent).

---

## What goes to the adversarial review

Codex is asked to **find the bypass in this design** — the path by which the AI (or a
co-resident process, or injected content) gets an action executed that the human did not
approve, or executed with broader scope than approved. Prime targets, by construction:

- **§3(ii):** can the requester cause an approval to be minted without the approver's
  authenticated connection? (The crux. Attack each AI-placement row.)
- **§4:** can a co-resident process present the approver's identity (peer-cred spoof,
  socket-permission gap, same-uid confusion)?
- **§3 step 2:** the time-of-check / pending-approval race under request-response.
- **§5:** sandbox escape, or a scope the human's preview did not actually convey (preview ≠
  granted scope).
- **§6:** can the audit be made to misrecord *what* was approved?

No code is written until this review converges and the operator ratifies.
