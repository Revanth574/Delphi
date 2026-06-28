// SPDX-License-Identifier: MIT

//! The daemon service loop (Increment B1) — the assembled consent → execute path.
//!
//! `docs/TRUST_MODEL.md` §4 flow, wired as a daemon routine over the two sockets:
//! the AI's general socket (protobuf, [`wire`](crate::wire)) and the shell's private
//! `SOCK_SEQPACKET` channel. One action, end to end:
//!
//! 1. read `Propose` (general socket) → **canonicalize + store** the one canonical
//!    object under a `pending_id` → reply `Pending`.
//! 2. deliver the preview to the shell (private channel).
//! 3. **logind gate** (the ADDED composition — proven in `logind_gate`, here in the
//!    sequence) → live **PAM** over the private channel.
//! 4. read the shell's mint-confirm (private channel) → verify it matches the stored
//!    digest → **mint** the digest-bound token → reply `Granted`.
//! 5. read `Present{pending_id, token}` (NO action data) → execute the **STORED**
//!    object for that `pending_id`, re-verifying the token against ITS digest →
//!    audit → reply `Completed`/`Denied`.
//!
//! THE HALF-(ii) INVARIANT lives at step 5: the executed action is the **stored
//! canonical object**, never anything re-supplied on `Present`. A token minted for A
//! cannot drive execution of B — [`execute_approved`] re-verifies the presented
//! token against `canonical_action_digest(stored object)`.

use std::os::fd::RawFd;
use std::os::unix::net::{UnixListener, UnixStream};

use nix::sys::socket::sockopt::PeerCredentials;
use nix::sys::socket::getsockopt;

use crate::action::{canonical_action_digest, preview};
use crate::canonicalize::canonicalize;
use crate::execute::{execute_approved, ConsumptionLedger};
use crate::logind::{session_passes_gate, SessionVerdict};
use crate::pam::authenticate_over_channel;
use crate::store::{PendingState, PendingStore};
use crate::token::{mint, ApprovalToken, MintingKey};
use crate::wire::{pb, read_frame, write_frame};
use crate::RuntimeError;

/// Largest private-channel datagram (preview + 32-byte digest prefix).
const MAX_PRIV_MSG: usize = 8192;

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
    /// The logind active-session verdict for the shell (real `LogindVerdict::for_pid`
    /// in the daemon; a mock in tests — the GATE is composed either way).
    pub session_verdict: &'a dyn SessionVerdict,
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
    if cred.uid() != expected_uid {
        return Err(RuntimeError::Protocol(format!(
            "requester uid {} != session uid {expected_uid}",
            cred.uid()
        )));
    }
    Ok(stream)
}

/// Service exactly one action over an accepted AI connection (the §4 flow).
///
/// # Errors
///
/// [`RuntimeError::Protocol`] on a wire/sequencing fault; [`RuntimeError::Filesystem`]
/// /[`RuntimeError::Syscall`] on canonicalization or channel I/O failure. A *policy*
/// denial (gate/PAM/token) is `Ok(Outcome::Denied)`, not an error.
pub fn serve_one_action(ai: &mut UnixStream, ctx: &mut ServiceCtx) -> Result<Outcome, RuntimeError> {
    // 1. Propose → canonicalize + store the ONE object.
    let propose = match read_frame::<pb::AiToDaemon>(ai)?.msg {
        Some(pb::ai_to_daemon::Msg::Propose(p)) => p,
        other => return Err(RuntimeError::Protocol(format!("expected Propose, got {other:?}"))),
    };
    let id = ctx.store.next_id();
    let action = canonicalize(&propose, id.clone())?;
    let digest = canonical_action_digest(&action);
    let preview_text = preview(&action);
    ctx.store.insert(action);
    write_frame(ai, &pending_msg(&id))?;

    // 2. preview → the pinned shell on the private channel.
    send_approval_request(ctx.channel_fd, &digest, &preview_text)?;

    // 3. logind gate (composed), then live PAM over the private channel.
    if !session_passes_gate(ctx.session_verdict) {
        return deny(ai, &id, "logind: shell session not active+local");
    }
    if authenticate_over_channel(ctx.pam_service, ctx.session_user, ctx.channel_fd).is_err() {
        return deny(ai, &id, "PAM authentication failed");
    }

    // 4. shell mint-confirm → must match the stored digest → mint.
    let confirm = recv_mint_confirm(ctx.channel_fd)?;
    if confirm != digest {
        return deny(ai, &id, "shell mint-confirm digest != stored digest");
    }
    // Mint at the time of consent (read FRESH — not a frozen snapshot).
    let token = mint(ctx.key, &digest, ctx.clock.now_unix());
    if let Some(e) = ctx.store.get_mut(&id) {
        e.state = PendingState::Granted;
    }
    write_frame(ai, &granted_msg(&id, &token.to_wire()))?;

    // 5. Present{pending_id, token} — NO action data. Execute the STORED object.
    let present = match read_frame::<pb::AiToDaemon>(ai)?.msg {
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
    if !matches!(result, Err(RuntimeError::Unapproved))
        && let Some(e) = store.get_mut(pending_id)
    {
        e.state = PendingState::Consumed;
    }
    match result {
        Ok(output) => Outcome::Completed { pending_id: pending_id.to_string(), exit_code: output.status.code() },
        Err(RuntimeError::Unapproved) => denied("token does not verify against the stored action's digest"),
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
