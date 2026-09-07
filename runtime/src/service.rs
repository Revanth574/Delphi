// SPDX-License-Identifier: MIT

//! The daemon service loop (Increment B1) — the assembled consent → execute path.
//!
//! `docs/TRUST_MODEL.md` §4 flow, wired as a daemon routine over the two sockets:
//! the AI's general socket (protobuf, [`wire`](crate::wire)) and the shell's private
//! `SOCK_SEQPACKET` channel. One action, end to end:
//!
//! **Transcribed from the implementation below, not from intent (D0A-R23-13).** The previous
//! version placed the gate before the store and the reply, duplicated a step number, and left
//! the old numbering beside the new — in the commit that claimed to renumber it. Read
//! `serve_one_action` and this list together; if they disagree, this list is wrong.
//!
//! 1. read `Propose` (general socket) → **canonicalize** the one canonical object, then
//!    render its preview.
//! 2. **refuse an unpresentable action** — a preview too large for the private channel is
//!    denied here, BEFORE the store and BEFORE the `Pending` reply, so a size problem
//!    refuses one action instead of aborting the service call (D0A-R21-05).
//! 3. **store** the object under a `pending_id` and reply `Pending` (id only — the AI never
//!    receives the preview, §4 as ratified by D0A-R21-02).
//! 4. **logind gate.** It precedes the PREVIEW DELIVERY, not the store — a gate-denied action
//!    leaves a stored entry and an already-sent `Pending`, and discloses NOTHING to the shell
//!    (D0A-R21-01). What the gate protects here is the renderer, not the store.
//! 5. **deliver the preview** to the pinned shell (private channel), then live **PAM** over
//!    that same channel.
//! 6. read the shell's mint-confirm — a bare `[digest:32]` — verify it equals the stored
//!    digest, **re-read the gate adjacently to the mint** (D0A-R1-02), then **mint** the
//!    digest-bound token and reply `Granted`.
//! 7. read `Present{pending_id, token}` (NO action data) → execute the **STORED**
//!    object for that `pending_id`, re-verifying the token against ITS digest → reply
//!    `Completed`/`Denied`.
//!
//! **THERE IS NO AUDIT STEP, and this list used to claim one (D0A-R24-03).** `audit` appears
//! nowhere in this module and `RuntimeAuditEntry::record` has no production caller — §7 is
//! unwired end to end, which is an OPEN row in `docs/CONFORMANCE_REGISTER.md`. A flow
//! document that lists the gap as a step describes it as closed.
//!
//! THE HALF-(ii) INVARIANT lives at step 7: the executed action is the **stored
//! canonical object**, never anything re-supplied on `Present`. A token minted for A
//! cannot drive execution of B — [`execute_approved`] re-verifies the presented
//! token against `canonical_action_digest(stored object)`.

use std::os::fd::RawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

use nix::sys::socket::sockopt::PeerCredentials;
use nix::sys::socket::getsockopt;

use crate::action::{canonical_action_digest, preview, RequiredTier};
use crate::canonicalize::canonicalize;
use crate::execute::{execute_approved, ConsumptionLedger};
use crate::logind::{session_passes_gate, SessionSource};
use crate::pam::authenticate_over_channel;
use crate::store::{PendingState, PendingStore};
use crate::token::{mint, ApprovalToken, MintingKey};
use crate::wire::{pb, read_frame, read_frame_untrusted, write_frame};
use crate::RuntimeError;

/// Largest private-channel datagram (preview + 32-byte digest prefix).
const MAX_PRIV_MSG: usize = 8192;

/// Does this preview fit the private channel, digest prefix included (D0A-R21-05)?
///
/// Two limits that never had to agree until the preview stopped redacting: a proposal may be
/// up to `wire::MAX_FRAME` (64 KiB), and the private channel accepts `MAX_PRIV_MSG` (8 KiB).
/// A ~9 KiB environment VALUE used to render as `[redacted]` and fit; it now renders in full
/// and does not. Checked BEFORE the action is stored and before the AI is told `Pending`, so
/// an oversized proposal is a clean DENIAL rather than an abort after the requester has
/// already been handed an id for an action that will never be presented.
#[must_use]
pub fn preview_fits_private_channel(preview: &str) -> bool {
    32usize.saturating_add(preview.len()) <= MAX_PRIV_MSG
}

/// A source of unix-seconds time — the seam (like the logind verdict) that keeps the
/// token TTL a REAL control in the assembled loop.
///
/// The service reads it FRESH at mint AND at Present-verify, so the TTL delta is the
/// real wall-time the AI sat on the token (B1-R2-01: a single snapshotted `now` for
/// both made the delta structurally zero — tokens never expired). The daemon uses
/// [`SystemClock`]; tests inject a deterministic clock to exercise expiry without
/// sleeping.
pub trait Clock {
    /// The current time in unix seconds.
    fn now_unix(&self) -> u64;
}

/// The production clock — `SystemTime` wall-clock seconds.
pub struct SystemClock;
impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Everything the service loop needs that isn't the AI connection. Borrowed for one
/// action; the daemon owns the long-lived pieces (key, store, ledger, clock).
pub struct ServiceCtx<'a> {
    /// The daemon's end of the private `SOCK_SEQPACKET` channel to the pinned shell.
    pub channel_fd: RawFd,
    /// Where the shell's logind verdict comes from, queried AT each gate decision rather
    /// than stored (D0-A finding A3 — a stored verdict answers about daemon-start time).
    pub session: &'a dyn SessionSource,
    /// The root-held HMAC minting key.
    pub key: &'a MintingKey,
    /// PAM service name (`delphi-runtime`).
    pub pam_service: &'a str,
    /// The session user PAM authenticates.
    pub session_user: &'a str,
    /// The pending registry (the half-(ii) source of truth).
    pub store: &'a mut PendingStore,
    /// The one-shot consumption ledger (1d).
    pub ledger: &'a mut ConsumptionLedger,
    /// The clock — read FRESH at mint and at Present-verify so the token TTL is a real
    /// control (B1-R2-01), not a frozen-`now` no-op.
    pub clock: &'a dyn Clock,
}

/// Denial when the session stopped qualifying between the PAM prompt and the mint.
///
/// A `const` shared with the test that asserts it (D0A-R2-05): the test required
/// `"DURING authentication"` contiguous while the literal had fourteen spaces baked into it,
/// so the assertion could never match and the production message was malformed. One
/// construction site removes the possibility of the two drifting.
///
/// The padding came from writing a Rust `\`-continuation through a Python heredoc: Rust strips
/// the next line's leading whitespace, Python does not. It compiled, so nothing objected.
pub const REASON_SESSION_LOST_DURING_AUTH: &str =
    "logind: the shell session stopped being active+local+seated DURING authentication - the \
     seat's foreground moved, so this consent is not one a human at the seat gave";

/// Accept the requester, or give up at `deadline`.
///
/// # Why a deadline exists at all (D0A-R2-01)
///
/// A fixture that mis-names an environment variable makes the AI panic *before* it connects,
/// and the plain accept then blocks forever. The run hangs with no output and no cause — the
/// worst failure shape available, because it looks like a slow test rather than a broken one.
/// Foreclosure handles the mis-naming ([`crate::scaffold_env`]); this handles the residual:
/// whatever else stops the AI connecting, the wait ends and says so.
///
/// Production keeps the blocking [`accept_requester`] deliberately — an unbounded wait for the
/// AI is B1's documented shape, and changing it is not this finding's business.
///
/// # Errors
///
/// [`RuntimeError::Protocol`] if nothing connects before `deadline`; otherwise as
/// [`accept_requester`].
///
/// # Examples
///
/// ```no_run
/// # use std::os::unix::net::UnixListener;
/// # use std::time::Duration;
/// # fn demo(l: &UnixListener) -> Result<(), Box<dyn std::error::Error>> {
/// let ai = delphi_runtime::service::accept_requester_within(l, 1000, Duration::from_secs(20))?;
/// # let _ = ai;
/// # Ok(())
/// # }
/// ```
pub fn accept_requester_within(
    listener: &UnixListener,
    expected_uid: u32,
    deadline: Duration,
) -> Result<UnixStream, RuntimeError> {
    use nix::poll::{PollFd, PollFlags};
    use std::os::fd::AsFd;

    let mut fds = [PollFd::new(listener.as_fd(), PollFlags::POLLIN)];
    // The same conversion the readiness wait uses — one site, so D0-R5-02's i32 reasoning
    // is not re-derived here with a different cap.
    let n = nix::poll::poll(&mut fds, crate::readiness::poll_timeout(deadline)).map_err(|source| RuntimeError::Syscall {
        op: "poll (accept requester)",
        source,
    })?;
    if n == 0 {
        return Err(RuntimeError::Protocol(format!(
            "no requester connected to the approval socket within {}s. The AI side never \
             reached connect() - check it started and is reading the same environment names \
             the launcher sets (see scaffold_env). This is a SETUP failure, not a protocol one.",
            deadline.as_secs()
        )));
    }
    accept_requester(listener, expected_uid)
}

/// Evaluate the gate against a verdict read **now**.
///
/// One function, one read: the timing IS the mechanism (D0-A A3), so it lives at exactly one
/// site where a test can reach it.
///
/// # Examples
///
/// ```
/// use delphi_runtime::logind::SessionSnapshot;
/// use delphi_runtime::service::gate_allows;
/// assert!(gate_allows(&SessionSnapshot { active: true, remote: false, seated: true }));
/// assert!(!gate_allows(&SessionSnapshot::DENIED));
/// ```
#[must_use]
pub fn gate_allows(source: &dyn SessionSource) -> bool {
    gate_check(source).is_ok()
}

/// As [`gate_allows`], but handing back **why** it denied (D0A-R3-02).
///
/// The cause was measured in R1-05 and phrased for the operator in R2-04, then collapsed to a
/// `bool` before the service could use it — so a gone process, an invalid pidfd and a genuine
/// seat change all reached the requester as the same sentence. This is the seam that carries
/// the distinction the rest of the way.
///
/// # Errors
///
/// The [`SessionResolution`] that denied, ready for [`SessionResolution::denial`].
///
/// # Examples
///
/// ```
/// use delphi_runtime::logind::SessionSnapshot;
/// use delphi_runtime::service::gate_check;
/// assert!(gate_check(&SessionSnapshot { active: true, remote: false, seated: true }).is_ok());
/// assert!(gate_check(&SessionSnapshot::DENIED).is_err());
/// ```
pub fn gate_check(source: &dyn SessionSource) -> Result<(), crate::logind::SessionResolution> {
    let resolution = source.current();
    if session_passes_gate(resolution.snapshot_or_denied()) {
        Ok(())
    } else {
        Err(resolution)
    }
}

/// The terminal outcome of one serviced action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The stored action executed; carries its exit code (if it ran to completion).
    Completed { pending_id: String, exit_code: Option<i32> },
    /// The action was denied before execution (gate failure, mismatch, bad token).
    Denied { pending_id: String, reason: String },
}

/// Accept one requester connection on the general socket, verifying via SO_PEERCRED
/// that the peer runs as `expected_uid` (the dropped session user — §5).
///
/// # Errors
///
/// [`RuntimeError::Filesystem`] if `accept` fails; [`RuntimeError::Protocol`] if the
/// peer's uid is not `expected_uid` (a different user reaching the socket).
pub fn accept_requester(listener: &UnixListener, expected_uid: u32) -> Result<UnixStream, RuntimeError> {
    let (stream, _addr) = listener.accept().map_err(|source| RuntimeError::Filesystem {
        op: "accept on general socket",
        path: std::path::PathBuf::from("approve.sock"),
        source,
    })?;
    let cred = getsockopt(&stream, PeerCredentials)
        .map_err(|source| RuntimeError::Syscall { op: "getsockopt SO_PEERCRED", source })?;
    // D0A-R27-02: arm the per-read timeout so `read_frame`'s absolute deadline is reachable.
    // Without it a stalled peer blocks the root daemon inside `read`, before consent.
    crate::wire::arm_frame_liveness(&stream)?;
    if cred.uid() != expected_uid {
        return Err(RuntimeError::Protocol(format!(
            "requester uid {} != session uid {expected_uid}",
            cred.uid()
        )));
    }
    Ok(stream)
}

/// The consent tier the daemon's ONE gate sequence can actually ENFORCE (D0A-R25-01,
/// tightened by D0A-R26-01).
///
/// `RequiredTier` has four values; `serve_one_action` runs a single sequence for all of them —
/// logind gate → live PAM over the private channel → shell mint-confirm → second gate read.
/// The question this constant answers is what that sequence is WORTH, and R25-01 answered it
/// one tier too generously.
///
/// **R25-01 set this to `Biometric`**, reasoning that this crate's own doc comment defines
/// that value as "live PAM authentication" and the sequence is exactly that. **R26-01 rejected
/// the reasoning as self-serving**, and it was: the shipped `/etc/pam.d/delphi-runtime` is
/// `pam_unix` alone, `docs/TRUST_MODEL.md` describes the biometric/TPM tiers as riding this
/// stack *because a biometric module would be in it*, and no such module is. So a `Biometric`
/// action was authorised by a PASSWORD while its preview, digest and audit entry claimed a
/// biometric factor — **the identical false claim R25-01 refused `Hardware` for**, one rung
/// down. The argument that refused `Hardware` always refused `Biometric` too; R25-01 stopped
/// where it had already gone far enough to feel finished.
///
/// What the stack provides is a password prompt in front of a human at the seat. That is
/// `Confirm`. Anything above is refused until a factor is shipped AND proven, not until it is
/// merely configured.
///
/// The other direction is fail-safe and deliberately not "corrected": an action requesting
/// `Autonomous` still receives this stronger sequence, because no tier-specific branching
/// exists. Naming the constant is what makes that a decision rather than a coincidence — when
/// branching is added, the floor is here to be consulted, and the requester (the AI, i.e.
/// untrusted input) cannot obtain a weaker gate by classifying its own action.
///
/// **What the fixture migration exposed — CORRECTED at D0A-R27-05.** The note here claimed
/// that nothing had ever asserted what `Biometric` MEANT and that the migration cost no
/// coverage. Both were false: round 25 had already added two tier-semantic assertions
/// (`Hardware` denied as unenforceable; `Biometric` passing the tier check), so the migration
/// **flipped a live assertion** rather than filling a vacuum — the control asserted *Biometric
/// passes* and now asserts *Confirm passes*. What is true, and is why R25-01's defect was
/// undetectable, is that NO tier assertion existed before round 25. See
/// `docs/CONFORMANCE_REGISTER.md` for the three-phase account.
const ENFORCED_TIER: RequiredTier = RequiredTier::Confirm;

/// Service exactly one action over an accepted AI connection (the §4 flow).
///
/// # Errors
///
/// [`RuntimeError::Protocol`] on a wire/sequencing fault; [`RuntimeError::Filesystem`]
/// /[`RuntimeError::Syscall`] on canonicalization or channel I/O failure. A *policy*
/// denial (gate/PAM/token) is `Ok(Outcome::Denied)`, not an error.
pub fn serve_one_action(ai: &mut UnixStream, ctx: &mut ServiceCtx) -> Result<Outcome, RuntimeError> {
    // Steps 1-3 (see the module header): canonicalize, refuse an unpresentable preview,
    // then store the ONE object and reply `Pending`.
    let propose = match read_frame_untrusted::<pb::AiToDaemon>(ai)?.msg {
        Some(pb::ai_to_daemon::Msg::Propose(p)) => p,
        other => return Err(RuntimeError::Protocol(format!("expected Propose, got {other:?}"))),
    };
    let id = ctx.store.next_id();
    let action = canonicalize(&propose, id.clone())?;
    // D0A-R25-01: refuse a tier this daemon cannot enforce, BEFORE storing or previewing.
    // Accepting it would authorize a hardware-claimed action with a password and record the
    // stronger claim in the preview, the digest and the audit entry.
    if action.required_tier > ENFORCED_TIER {
        return deny(
            ai,
            &id,
            &format!(
                "action requires {:?} consent, which this daemon cannot enforce — its gate \
                 sequence implements {ENFORCED_TIER:?} (live PAM over the private channel) and \
                 the installed PAM stack provides no stronger factor. Refused rather than \
                 satisfied with a weaker one (D0A-R25-01)",
                action.required_tier
            ),
        );
    }
    let digest = canonical_action_digest(&action);
    let preview_text = preview(&action);
    // D0A-R21-05: BEFORE storing and before replying. Past this point the requester holds an
    // id and the action is in the store, so a later size failure aborts the whole service
    // call rather than denying one action.
    if !preview_fits_private_channel(&preview_text) {
        return deny(
            ai,
            &id,
            "preview exceeds the private-channel datagram limit — the action cannot be \
             presented to the human, so it is refused rather than executed unseen",
        );
    }
    ctx.store.insert(action);
    write_frame(ai, &pending_msg(&id))?;

    // Step 4. logind gate FIRST — the preview is not sent until the gate passes (D0A-R21-01,
    // disclosure half). This used to send the preview and THEN gate, so a denied action had
    // already disclosed its complete environment to the renderer. That inverted the
    // justification for showing complete values, which is that the renderer holds the
    // password: for a DENIED action it never receives one, and denied actions are the
    // population most likely to carry something an attacker proposed.
    //
    // This is a DISCLOSURE fix and NOT a resolution of D0A-R21-01, whose other half —
    // a compromised renderer displaying a benign preview while collecting the genuine
    // password, since the relay mints from its OWN held digest — is architectural and is
    // recorded as an open finding for the native-UI increment.
    //
    // FIRST of two gate reads: refuse to PROMPT at a surface that is not the seat's
    // foreground.
    if let Err(cause) = gate_check(ctx.session) {
        return deny(ai, &id, &cause.denial(false));
    }

    // Step 5. preview → the pinned shell on the private channel, only now.
    send_approval_request(ctx.channel_fd, &digest, &preview_text)?;

    // 3b. live PAM over the private channel.
    if authenticate_over_channel(ctx.pam_service, ctx.session_user, ctx.channel_fd).is_err() {
        return deny(ai, &id, "PAM authentication failed");
    }

    // Step 6. shell mint-confirm → must match the stored digest → mint.
    let confirm = recv_mint_confirm(ctx.channel_fd)?;
    if confirm != digest {
        return deny(ai, &id, "shell mint-confirm digest != stored digest");
    }
    // SECOND read, ADJACENT TO THE MINT (D0A-R1-02). A3 made the READ fresh and left the
    // DECISION stale: PAM waits on a human, so unboundedly, and `recv_mint_confirm` blocks
    // after it. A session going true → false during authentication still minted — the exact
    // case A3's own docs name as the security property. Class 26 one level above A3.
    if let Err(cause) = gate_check(ctx.session) {
        return deny(ai, &id, &cause.denial(true));
    }
    // Mint at the time of consent (read FRESH — not a frozen snapshot).
    let token = mint(ctx.key, &digest, ctx.clock.now_unix());
    // D0A-R25-04: `grant` sets the state AND the monotonic consent instant together. The
    // token carries the wall-clock issue time because that is what its MAC binds; the instant
    // is what the elapsed check reads, because a wall clock can be set backwards.
    ctx.store.grant(&id);
    write_frame(ai, &granted_msg(&id, &token.to_wire()))?;

    // Step 7. Present{pending_id, token} — NO action data. Execute the STORED object.
    let present = match read_frame_untrusted::<pb::AiToDaemon>(ai)?.msg {
        Some(pb::ai_to_daemon::Msg::Present(p)) => p,
        other => return Err(RuntimeError::Protocol(format!("expected Present, got {other:?}"))),
    };
    // Verify at a FRESH clock read — the real wall-time delta since mint is the TTL the
    // token is checked against (B1-R2-01: an AI that sits on the token past TTL is
    // rejected). The isolated token-expiry RED now bites the ASSEMBLED loop.
    let verify_now = ctx.clock.now_unix();
    let outcome = present_and_execute(
        ctx.store, ctx.ledger, ctx.key, &present.pending_id, &present.token, verify_now,
    );
    let reply = match &outcome {
        Outcome::Completed { pending_id, exit_code } => completed_msg(pending_id, *exit_code),
        Outcome::Denied { pending_id, reason } => denied_msg(pending_id, reason),
    };
    write_frame(ai, &reply)?;
    Ok(outcome)
}

/// THE HALF-(ii) HEART (the §4 step-5 "complete"): execute the **stored canonical
/// object** for `pending_id`, re-verifying the presented `token_wire` against THAT
/// object's digest. `Present` carries no action data, so this is the only action
/// that can run for `pending_id` — there is nowhere to inject a different action B.
///
/// A token minted for action A fails [`execute_approved`]'s digest re-verification
/// against a different stored action B ⇒ `Denied`. The one-shot ledger (1d) makes it
/// execute at most once. Extracted as a function so the approve-A/execute-B RED-proof
/// bites this exact assembled code path.
#[must_use]
pub fn present_and_execute(
    store: &mut PendingStore,
    ledger: &mut ConsumptionLedger,
    key: &MintingKey,
    pending_id: &str,
    token_wire: &str,
    now: u64,
) -> Outcome {
    let denied = |reason: &str| Outcome::Denied { pending_id: pending_id.to_string(), reason: reason.to_string() };

    let Some(candidate) = ApprovalToken::from_wire(token_wire) else {
        return denied("malformed token on Present");
    };
    // Look up the STORED object for THIS pending_id and execute IT — re-verifying the
    // presented token against ITS digest (execute_approved derives the digest from
    // the very object it is about to run).
    let result = {
        let Some(entry) = store.get(pending_id) else {
            return denied("no pending action for this id (unknown, consumed, or restarted)");
        };
        if entry.state != PendingState::Granted {
            return denied("action not in Granted state (replay or never granted)");
        }
        // D0A-R25-04, corrected by D0A-R26-03: the AUTHORITATIVE expiry check, on a clock
        // nobody can adjust AND that keeps running across suspend. `execute_approved`'s
        // `within_ttl` compares Unix timestamps, so rolling the system clock backwards shrinks
        // the apparent age; `CLOCK_MONOTONIC` fixes that but PAUSES while suspended, so a
        // machine closed between consent and Present returns with its window barely moved.
        // `CLOCK_BOOTTIME` is monotonic and suspend-inclusive.
        match (entry.granted_at_boot_secs, crate::store::boot_secs()) {
            (Some(at), Some(now))
                if crate::store::consent_window_elapsed(at, now, crate::token::TOKEN_TTL_SECS) =>
            {
                return denied(
                    "the consent window has elapsed on CLOCK_BOOTTIME — more than the TTL of \
                     real time has passed since consent, including any suspend, whatever the \
                     system clock now reads (D0A-R25-04, D0A-R26-03)",
                );
            }
            (Some(_), Some(_)) => {}
            (None, _) => {
                return denied(
                    "granted action carries no consent instant — refusing rather than falling \
                     back to the adjustable wall clock (D0A-R25-04)",
                );
            }
            (_, None) => {
                return denied(
                    "CLOCK_BOOTTIME could not be read, so the consent window cannot be \
                     bounded — refusing rather than executing unbounded (D0A-R26-03)",
                );
            }
        }
        execute_approved(&entry.action, &candidate, key, now, ledger)
    };
    // B1-04 + B1-R2-03: the store state agrees with the LEDGER on EVERY path. The
    // ledger (execute_approved) consumes once the token VERIFIES — BEFORE the run — so
    // a verified-then-execution-failed action HAS consumed the ledger. Matching 1d's
    // one-shot ("a spawn failure still consumes — one-shot, not one-success"), the
    // store advances to Consumed for EVERY post-verify outcome (Ok, verified-but-
    // failed, and AlreadyConsumed — idempotent). ONLY a token that fails verification
    // (Unapproved) leaves the ledger untouched and the approval Granted (re-presentable
    // with the right token — the 1c "failed-verify doesn't consume" precedent). Store
    // and ledger never disagree.
    //
    // D0A-R15-03 is why that last sentence needs a guard rather than trust: the R14-03
    // digest check runs after the consume and returned `Unapproved`, so a valid token over a
    // mismatched snapshot consumed the ledger and left the store Granted. Any future
    // post-verification refusal MUST NOT reuse `Unapproved` — the variant is the signal that
    // nothing was consumed.
    if !matches!(result, Err(RuntimeError::Unapproved))
        && let Some(e) = store.get_mut(pending_id)
    {
        e.state = PendingState::Consumed;
    }
    match result {
        Ok(output) => Outcome::Completed { pending_id: pending_id.to_string(), exit_code: output.status.code() },
        Err(RuntimeError::Unapproved) => denied("token does not verify against the stored action's digest"),
        // D0A-R15-03: post-verification, so the ledger HAS consumed and the store advanced
        // with it above. Named separately because blaming the token sends the operator to a
        // mechanism that worked.
        Err(RuntimeError::SnapshotMismatch { what }) => denied(&format!(
            "the sealed {what} snapshot does not match the approved digest (approval consumed — one-shot)"
        )),
        Err(RuntimeError::AlreadyConsumed) => denied("approval already consumed (one-shot)"),
        Err(e) => denied(&format!("execution failed (approval consumed — one-shot): {e}")),
    }
}

/// Send `Denied` to the AI and return the terminal outcome.
fn deny(ai: &mut UnixStream, pending_id: &str, reason: &str) -> Result<Outcome, RuntimeError> {
    write_frame(ai, &denied_msg(pending_id, reason))?;
    Ok(Outcome::Denied { pending_id: pending_id.to_string(), reason: reason.to_string() })
}

// ── private-channel datagrams (daemon ↔ shell) ──────────────────────────────
//
// approval request (daemon→shell): [digest:32][preview utf8]
// mint confirm     (shell→daemon): [digest:32]
// (SEQPACKET preserves boundaries — one message per datagram.)

/// Daemon → shell: deliver the approval request (digest + preview).
pub fn send_approval_request(channel_fd: RawFd, digest: &[u8; 32], preview: &str) -> Result<(), RuntimeError> {
    let mut buf = Vec::with_capacity(32 + preview.len());
    buf.extend_from_slice(digest);
    buf.extend_from_slice(preview.as_bytes());
    write_datagram(channel_fd, &buf)
}

/// Shell side: read the approval request → (digest, preview).
pub fn recv_approval_request(channel_fd: RawFd) -> Result<([u8; 32], String), RuntimeError> {
    let buf = read_datagram(channel_fd)?;
    if buf.len() < 32 {
        return Err(RuntimeError::Protocol("approval request shorter than digest".into()));
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&buf[..32]);
    let preview = String::from_utf8_lossy(&buf[32..]).into_owned();
    Ok((digest, preview))
}

/// Shell → daemon: confirm approval by echoing the action digest.
pub fn send_mint_confirm(channel_fd: RawFd, digest: &[u8; 32]) -> Result<(), RuntimeError> {
    write_datagram(channel_fd, digest)
}

/// Daemon side: read the shell's mint-confirm digest.
pub fn recv_mint_confirm(channel_fd: RawFd) -> Result<[u8; 32], RuntimeError> {
    let buf = read_datagram(channel_fd)?;
    if buf.len() != 32 {
        return Err(RuntimeError::Protocol(format!("mint-confirm is {} bytes, want 32", buf.len())));
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&buf);
    Ok(digest)
}

fn write_datagram(fd: RawFd, bytes: &[u8]) -> Result<(), RuntimeError> {
    if bytes.len() > MAX_PRIV_MSG {
        return Err(RuntimeError::Protocol("private-channel datagram too large".into()));
    }
    // SAFETY: write the borrowed fd; SEQPACKET sends `bytes` as one datagram.
    let n = unsafe { nix::libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    if n < 0 {
        return Err(RuntimeError::Syscall { op: "private channel write", source: nix::errno::Errno::last() });
    }
    Ok(())
}

fn read_datagram(fd: RawFd) -> Result<Vec<u8>, RuntimeError> {
    let mut buf = vec![0u8; MAX_PRIV_MSG];
    // SAFETY: read one datagram into the stack-backed buffer; SEQPACKET delivers a
    // whole message or none.
    let n = unsafe { nix::libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(RuntimeError::Syscall { op: "private channel read", source: nix::errno::Errno::last() });
    }
    buf.truncate(n as usize);
    Ok(buf)
}

// ── wire message constructors ───────────────────────────────────────────────

fn pending_msg(id: &str) -> pb::DaemonToAi {
    pb::DaemonToAi { msg: Some(pb::daemon_to_ai::Msg::Pending(pb::Pending { pending_id: id.into() })) }
}
fn granted_msg(id: &str, token: &str) -> pb::DaemonToAi {
    pb::DaemonToAi {
        msg: Some(pb::daemon_to_ai::Msg::Granted(pb::Granted { pending_id: id.into(), token: token.into() })),
    }
}
fn completed_msg(id: &str, exit_code: Option<i32>) -> pb::DaemonToAi {
    pb::DaemonToAi {
        msg: Some(pb::daemon_to_ai::Msg::Completed(pb::Completed {
            pending_id: id.into(),
            exit_code: exit_code.unwrap_or(-1),
        })),
    }
}
fn denied_msg(id: &str, reason: &str) -> pb::DaemonToAi {
    pb::DaemonToAi {
        msg: Some(pb::daemon_to_ai::Msg::Denied(pb::Denied { pending_id: id.into(), reason: reason.into() })),
    }
}

// AI-side helpers (used by the minimal AI bin + the attack tests): encode the two
// AI→daemon messages and read a daemon reply.

/// AI → daemon: a `Propose` envelope.
pub fn propose_msg(propose: pb::Propose) -> pb::AiToDaemon {
    pb::AiToDaemon { msg: Some(pb::ai_to_daemon::Msg::Propose(propose)) }
}
/// AI → daemon: a `Present` envelope (only pending_id + token — no action data).
pub fn present_msg(pending_id: &str, token: &str) -> pb::AiToDaemon {
    pb::AiToDaemon {
        msg: Some(pb::ai_to_daemon::Msg::Present(pb::Present { pending_id: pending_id.into(), token: token.into() })),
    }
}

/// Convenience: send an AI message and read the daemon's reply on `stream`.
pub fn ai_round_trip(stream: &mut UnixStream, msg: &pb::AiToDaemon) -> Result<pb::DaemonToAi, RuntimeError> {
    write_frame(stream, msg)?;
    read_frame(stream)
}

#[cfg(test)]
mod accept_deadline_tests {
    use super::*;

    /// D0A-R2-01: a fixture that never connects must END the wait and NAME the cause. The
    /// defect this replaces was a hang with no output — the worst shape available, because it
    /// reads as a slow test rather than a broken one.
    #[test]
    fn a_requester_that_never_connects_fails_fast_and_names_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("approve.sock");
        let listener = UnixListener::bind(&sock).expect("bind");
        let started = std::time::Instant::now();
        let err = accept_requester_within(&listener, 0, Duration::from_millis(300))
            .expect_err("nothing connected, so the wait must not succeed");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "it must give up at the deadline, not block: took {:?}",
            started.elapsed()
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("never reached connect()") && msg.contains("SETUP failure"),
            "the error must name the AI and say this is setup, not protocol: {msg}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::fd::AsRawFd;

    struct Seatless;
    impl crate::logind::SessionSource for Seatless {
        fn current(&self) -> crate::logind::SessionResolution {
            crate::logind::SessionResolution::LookupNoData
        }
    }

    struct At(u64);
    impl Clock for At {
        fn now_unix(&self) -> u64 {
            self.0
        }
    }

    /// D0A-R26-01 — **`Biometric` is refused**, because `pam_unix` is not a biometric factor.
    ///
    /// R25-01 set the ceiling at `Biometric` on the grounds that this crate defines it as
    /// "live PAM authentication". That reasoning refuses `Hardware` for a false claim while
    /// admitting the same false claim one rung down: the shipped stack is `pam_unix` alone, so
    /// a `Biometric` action was satisfied by a password with the stronger claim recorded in
    /// its preview, digest and audit entry.
    ///
    /// This test is what makes the tighter ceiling a fact rather than a comment.
    ///
    /// **It is NOT the first tier-semantic assertion in this crate (D0A-R27-05), which is what
    /// this comment used to claim.** Round 25 added two: `Hardware` denied as unenforceable,
    /// and `Biometric` PASSING the tier check. This test **inverts the second one** — the
    /// control it sits beside was rewritten from `Biometric` to `Confirm` in the same change.
    /// What is first here is the assertion that `Biometric` is specifically NOT enforceable.
    #[test]
    fn biometric_is_refused_because_the_shipped_pam_stack_has_no_biometric_factor() {
        let (daemon_end, _shell_end) = crate::channel::approval_socketpair().expect("socketpair");
        let (mut ai_daemon, mut ai_peer) = std::os::unix::net::UnixStream::pair().expect("ai pair");

        let propose = pb::Propose {
            argv: vec!["tool".into()],
            cwd: "/".into(),
            env_delta: vec![],
            fs_binds: vec![],
            exe_path: "/bin/sh".into(),
            net_policy: pb::NetPolicy::NetNone as i32,
            timeout_secs: 5,
            required_tier: pb::RequiredTier::TierBiometric as i32,
        };
        crate::wire::write_frame(&mut ai_peer, &propose_msg(propose)).expect("send propose");

        let mut store = PendingStore::new();
        let mut ledger = ConsumptionLedger::new();
        let key = crate::token::MintingKey::from_bytes([7u8; 32]);
        let mut ctx = ServiceCtx {
            channel_fd: daemon_end.as_raw_fd(),
            session: &Seatless,
            key: &key,
            pam_service: "delphi-runtime",
            session_user: "nobody",
            store: &mut store,
            ledger: &mut ledger,
            clock: &At(1_000),
        };

        let outcome = serve_one_action(&mut ai_daemon, &mut ctx).expect("serves without aborting");
        match outcome {
            Outcome::Denied { ref reason, .. } => assert!(
                reason.contains("cannot enforce"),
                "denied, but not for the unenforceable tier — Seatless also denies at the GATE, \
                 so this assertion is what distinguishes the two: {reason}"
            ),
            other => panic!("Biometric must DENY while the stack is pam_unix only, got: {other:?}"),
        }
        assert!(
            ctx.store.get("act-1").is_none(),
            "a Biometric action was stored despite demanding a factor the stack cannot supply"
        );
    }

    /// D0A-R25-04 — an elapsed consent window is denied even when the WALL CLOCK says the
    /// token is fresh.
    ///
    /// The token's TTL is checked against Unix timestamps, so an attacker who can set the
    /// system clock backwards keeps a consented token live indefinitely: `now - issued_at`
    /// never grows. This fixture is that attack in its purest form — the wall clock passed to
    /// `present_and_execute` is EXACTLY the mint time, so `within_ttl` is satisfied, while the
    /// monotonic instant shows the window closed long ago.
    #[test]
    fn an_elapsed_consent_window_is_denied_even_when_the_wall_clock_is_frozen_at_mint_time() {
        const MINT_AT: u64 = 1_000;

        let propose = pb::Propose {
            argv: vec!["tool".into()],
            cwd: "/".into(),
            env_delta: vec![],
            fs_binds: vec![],
            exe_path: "/bin/sh".into(),
            net_policy: pb::NetPolicy::NetNone as i32,
            timeout_secs: 5,
            required_tier: pb::RequiredTier::TierConfirm as i32,
        };
        let action = canonicalize(&propose, "act-1".into()).expect("canonicalize");
        let digest = canonical_action_digest(&action);
        let key = crate::token::MintingKey::from_bytes([7u8; 32]);
        let token = crate::token::mint(&key, &digest, MINT_AT);

        let mut store = PendingStore::new();
        store.insert(action);
        let entry = store.get_mut("act-1").expect("stored");
        entry.state = PendingState::Granted;
        // Real elapsed time is past the TTL.
        entry.granted_at_boot_secs =
            crate::store::boot_secs().map(|n| n.saturating_sub(crate::token::TOKEN_TTL_SECS + 5));
        assert!(
            entry.granted_at_boot_secs.is_some(),
            "precondition: CLOCK_BOOTTIME must be readable for this test to mean anything"
        );

        let mut ledger = ConsumptionLedger::new();
        // The wall clock reads the MINT time — the rollback. `within_ttl` is satisfied here.
        assert!(
            crate::token::verify(&key, &token, &digest, MINT_AT),
            "precondition: the token MUST still verify on the frozen wall clock, or this test \
             proves nothing about the monotonic check"
        );

        match present_and_execute(&mut store, &mut ledger, &key, "act-1", &token.to_wire(), MINT_AT)
        {
            Outcome::Denied { ref reason, .. } => assert!(
                reason.contains("CLOCK_BOOTTIME has elapsed") || reason.contains("elapsed on CLOCK_BOOTTIME"),
                "denied, but not by the boottime window check: {reason}"
            ),
            other => panic!(
                "a token whose consent window elapsed in REAL time was accepted because the \
                 wall clock was rolled back: {other:?}"
            ),
        }
    }

    /// D0A-R25-04 — a `Granted` entry with NO monotonic instant is refused, not waved through.
    ///
    /// `PendingStore::grant` sets both fields together so this cannot arise from the normal
    /// path, but `PendingEntry`'s fields are public (the R19-05 shape), so the state can still
    /// be set without the instant. The choice recorded here is that such an entry is DENIED
    /// rather than falling back to the adjustable wall clock — the fallback would silently
    /// restore exactly the weakness the instant exists to remove.
    #[test]
    fn a_granted_entry_without_a_monotonic_instant_is_refused_rather_than_wall_clocked() {
        const MINT_AT: u64 = 1_000;

        let propose = pb::Propose {
            argv: vec!["tool".into()],
            cwd: "/".into(),
            env_delta: vec![],
            fs_binds: vec![],
            exe_path: "/bin/sh".into(),
            net_policy: pb::NetPolicy::NetNone as i32,
            timeout_secs: 5,
            required_tier: pb::RequiredTier::TierConfirm as i32,
        };
        let action = canonicalize(&propose, "act-1".into()).expect("canonicalize");
        let digest = canonical_action_digest(&action);
        let key = crate::token::MintingKey::from_bytes([7u8; 32]);
        let token = crate::token::mint(&key, &digest, MINT_AT);

        let mut store = PendingStore::new();
        store.insert(action);
        // The split update `grant` exists to prevent.
        let entry = store.get_mut("act-1").expect("stored");
        entry.state = PendingState::Granted;
        assert!(entry.granted_at_boot_secs.is_none(), "precondition: the instant must be unset");

        let mut ledger = ConsumptionLedger::new();
        match present_and_execute(&mut store, &mut ledger, &key, "act-1", &token.to_wire(), MINT_AT)
        {
            Outcome::Denied { ref reason, .. } => assert!(
                reason.contains("no consent instant"),
                "denied, but not for the missing instant: {reason}"
            ),
            other => panic!(
                "an entry marked Granted without a consent instant executed on the wall clock \
                 alone: {other:?}"
            ),
        }
    }

    /// D0A-R25-01 — an action demanding a tier the daemon cannot enforce is DENIED, and
    /// denied BEFORE it is stored or previewed.
    ///
    /// `required_tier` arrived from the AI, was bound into the digest, rendered into the
    /// preview and written to the audit entry — and was never once consulted. All four tiers
    /// took the identical logind → PAM → mint sequence, so a `Hardware` action was authorized
    /// by `pam_unix`'s password while every artifact claimed a hardware factor.
    ///
    /// The seat is deliberately `Seatless` here: the denial must happen BEFORE the gate, so a
    /// gate-passing lane is not needed to prove it, and a test that needed one could not run
    /// unprivileged.
    #[test]
    fn a_tier_the_daemon_cannot_enforce_is_denied_before_the_action_is_stored() {
        let (daemon_end, _shell_end) = crate::channel::approval_socketpair().expect("socketpair");
        let (mut ai_daemon, mut ai_peer) = std::os::unix::net::UnixStream::pair().expect("ai pair");

        let propose = pb::Propose {
            argv: vec!["tool".into()],
            cwd: "/".into(),
            env_delta: vec![],
            fs_binds: vec![],
            exe_path: "/bin/sh".into(),
            net_policy: pb::NetPolicy::NetNone as i32,
            timeout_secs: 5,
            // The tier nothing in the shipped PAM stack can satisfy.
            required_tier: pb::RequiredTier::TierHardware as i32,
        };
        crate::wire::write_frame(&mut ai_peer, &propose_msg(propose)).expect("send propose");

        let mut store = PendingStore::new();
        let mut ledger = ConsumptionLedger::new();
        let key = crate::token::MintingKey::from_bytes([7u8; 32]);
        let mut ctx = ServiceCtx {
            channel_fd: daemon_end.as_raw_fd(),
            session: &Seatless,
            key: &key,
            pam_service: "delphi-runtime",
            session_user: "nobody",
            store: &mut store,
            ledger: &mut ledger,
            clock: &At(1_000),
        };

        let outcome = serve_one_action(&mut ai_daemon, &mut ctx).expect("serves without aborting");
        match outcome {
            Outcome::Denied { ref reason, .. } => assert!(
                reason.contains("cannot enforce"),
                "denied, but not for the unenforceable tier — a Seatless fixture also denies \
                 at the GATE, so this assertion is what distinguishes the two: {reason}"
            ),
            other => panic!("an unenforceable tier must DENY, got: {other:?}"),
        }
        assert!(
            ctx.store.get("act-1").is_none(),
            "the action was stored despite demanding a tier that cannot be satisfied"
        );
    }

    /// D0A-R25-01 — the positive control: the ENFORCED tier is still accepted past this check.
    ///
    /// Without it, a guard that denied every tier would pass the test above. `Seatless` means
    /// this proposal is denied at the GATE, one step later — so the discriminating assertion
    /// is that the reason is the gate's, NOT the tier's.
    #[test]
    fn the_enforced_tier_passes_the_tier_check_and_reaches_the_gate() {
        let (daemon_end, _shell_end) = crate::channel::approval_socketpair().expect("socketpair");
        let (mut ai_daemon, mut ai_peer) = std::os::unix::net::UnixStream::pair().expect("ai pair");

        let propose = pb::Propose {
            argv: vec!["tool".into()],
            cwd: "/".into(),
            env_delta: vec![],
            fs_binds: vec![],
            exe_path: "/bin/sh".into(),
            net_policy: pb::NetPolicy::NetNone as i32,
            timeout_secs: 5,
            required_tier: pb::RequiredTier::TierConfirm as i32,
        };
        crate::wire::write_frame(&mut ai_peer, &propose_msg(propose)).expect("send propose");

        let mut store = PendingStore::new();
        let mut ledger = ConsumptionLedger::new();
        let key = crate::token::MintingKey::from_bytes([7u8; 32]);
        let mut ctx = ServiceCtx {
            channel_fd: daemon_end.as_raw_fd(),
            session: &Seatless,
            key: &key,
            pam_service: "delphi-runtime",
            session_user: "nobody",
            store: &mut store,
            ledger: &mut ledger,
            clock: &At(1_000),
        };

        let outcome = serve_one_action(&mut ai_daemon, &mut ctx).expect("serves without aborting");
        match outcome {
            Outcome::Denied { ref reason, .. } => assert!(
                !reason.contains("cannot enforce"),
                "the ENFORCED tier was refused by the tier check — the guard rejects \
                 everything, so the refusal test above proves nothing: {reason}"
            ),
            other => panic!("Seatless must deny at the gate, got: {other:?}"),
        }
    }

    /// D0A-R21-05 — a legal proposal whose PREVIEW exceeds the private channel is DENIED,
    /// not aborted.
    ///
    /// The two limits never had to agree until the preview stopped redacting: a proposal may
    /// be 64 KiB, the private channel takes 8 KiB. A ~9 KiB environment value used to render
    /// as `[redacted]` and fit. It now renders in full — and without this check the action
    /// was STORED and the requester was told `Pending` before the send failed, so a size
    /// problem became an aborted service call instead of one refused action.
    #[test]
    fn an_oversized_preview_is_denied_before_the_action_is_stored() {
        let (daemon_end, _shell_end) = crate::channel::approval_socketpair().expect("socketpair");
        let (mut ai_daemon, mut ai_peer) = std::os::unix::net::UnixStream::pair().expect("ai pair");

        // Legal as a proposal (well under wire::MAX_FRAME), oversized as a preview.
        let big = "v".repeat(9 * 1024);
        let propose = pb::Propose {
            argv: vec!["tool".into()],
            cwd: "/".into(),
            env_delta: vec![pb::EnvVar { key: "BIG".into(), value: big }],
            fs_binds: vec![],
            exe_path: "/bin/sh".into(),
            net_policy: pb::NetPolicy::NetNone as i32,
            timeout_secs: 5,
            required_tier: pb::RequiredTier::TierConfirm as i32,
        };
        crate::wire::write_frame(&mut ai_peer, &propose_msg(propose)).expect("send propose");

        let mut store = PendingStore::new();
        let mut ledger = ConsumptionLedger::new();
        let key = crate::token::MintingKey::from_bytes([7u8; 32]);
        let mut ctx = ServiceCtx {
            channel_fd: daemon_end.as_raw_fd(),
            session: &Seatless,
            key: &key,
            pam_service: "delphi-runtime",
            session_user: "nobody",
            store: &mut store,
            ledger: &mut ledger,
            clock: &At(1_000),
        };

        // A DENIAL, not an Err — the service call completes.
        let outcome = serve_one_action(&mut ai_daemon, &mut ctx).expect("serves without aborting");
        match outcome {
            Outcome::Denied { ref reason, .. } => assert!(
                reason.contains("private-channel datagram limit"),
                "denied for the wrong reason: {reason}"
            ),
            other => panic!("an oversized preview must DENY, got: {other:?}"),
        }
        // And the action must NOT be in the store — the check precedes the insert. The id was
        // allocated (denials need one), so look it up rather than counting.
        assert!(
            ctx.store.get("act-1").is_none(),
            "the action was stored before the size check; a refused action must leave nothing \
             behind for a later Present to find"
        );
    }

    /// D0A-R21-01 (disclosure half) — A GATE-DENIED ACTION SENDS NO PREVIEW.
    ///
    /// The preview used to go out BEFORE `gate_check`, so an action the system refused had
    /// already handed its complete environment to the renderer. That inverts the reason
    /// complete values are shown at all — that the renderer holds the password — because for
    /// a DENIED action it never receives one, and denied actions are the population most
    /// likely to carry something an attacker proposed.
    ///
    /// The assertion is that the private channel saw ZERO bytes. A preview sent and then
    /// denied still writes, so this notices the ordering being put back.
    #[test]
    fn a_gate_denied_action_sends_no_preview() {
        let (daemon_end, shell_end) = crate::channel::approval_socketpair().expect("socketpair");
        let (mut ai_daemon, mut ai_peer) = std::os::unix::net::UnixStream::pair().expect("ai pair");

        let propose = pb::Propose {
            argv: vec!["tool".into()],
            cwd: "/".into(),
            env_delta: vec![pb::EnvVar { key: "SECRET".into(), value: "s3cret-value".into() }],
            fs_binds: vec![],
            exe_path: "/bin/sh".into(),
            net_policy: pb::NetPolicy::NetNone as i32,
            timeout_secs: 5,
            required_tier: pb::RequiredTier::TierConfirm as i32,
        };
        crate::wire::write_frame(&mut ai_peer, &propose_msg(propose)).expect("send propose");

        let mut store = PendingStore::new();
        let mut ledger = ConsumptionLedger::new();
        let key = crate::token::MintingKey::from_bytes([7u8; 32]);
        let mut ctx = ServiceCtx {
            channel_fd: daemon_end.as_raw_fd(),
            session: &Seatless,
            key: &key,
            pam_service: "delphi-runtime",
            session_user: "nobody",
            store: &mut store,
            ledger: &mut ledger,
            clock: &At(1_000),
        };

        let outcome = serve_one_action(&mut ai_daemon, &mut ctx).expect("serves");
        assert!(matches!(outcome, Outcome::Denied { .. }), "the gate must deny: {outcome:?}");

        // Close the daemon end so a read cannot block, then prove nothing was written.
        drop(daemon_end);
        let mut shell = std::fs::File::from(shell_end);
        // D0A-R22-07: `unwrap_or(0)` made EVERY read error look like a clean EOF, so an
        // interrupted read would have "proved" nothing was sent. Retry EINTR; any other error
        // is a failed measurement, not a zero.
        let mut buf = [0u8; 64];
        let n = loop {
            match shell.read(&mut buf) {
                Ok(n) => break n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => panic!("reading the private channel failed ({e}) — this measures \
                                  nothing about whether a preview was sent"),
            }
        };
        assert_eq!(
            n, 0,
            "a gate-denied action wrote {n} byte(s) to the private channel — the preview \
             reached the renderer for an action the system refused"
        );
    }
}
