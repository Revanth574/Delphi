// SPDX-License-Identifier: MIT

//! The shell host's consent relay (Increment B2a, R‑2 — the two‑transport separation).
//!
//! In B2a the shell is a raw‑WRY (WebKitGTK) host forked as the launcher's shell
//! child. Its **native Rust layer** holds the private `SOCK_SEQPACKET` channel
//! (`DELPHI_CHANNEL_FD`, kept out of every WebKit subprocess by the proven CLOEXEC
//! discipline). The renderer (React, running in WebKit) can reach that channel **only**
//! through `window.ipc.postMessage(...)` → the native IPC handler → this relay.
//!
//! # Why this is a STATE MACHINE, not a pass‑through (the R‑2 keystone)
//!
//! The de‑risking proof's IPC handler is a **blind relay** — it writes whatever the
//! renderer posts straight to the channel (`proofs/wry-shell-host/src/main.rs`:
//! `chan_ipc.write_all(body)`). That was correct for a proof whose *only* claim was fd
//! containment, but in production it would let a compromised or XSS'd renderer write
//! **arbitrary datagrams** to the channel — including a forged mint‑confirm
//! (`[digest:32]`, [`crate::service::send_mint_confirm`]) — and so **forge a human
//! approval the human never gave**.
//!
//! [`ConsentRelay`] closes that by construction:
//!
//! * it **holds the action digest native‑side and never sends it to the renderer**, so
//!   the renderer has no digest to echo;
//! * it accepts a renderer message **only during the PAM‑prompt window**
//!   ([`Phase::PamPrompt`]) and **only as the password datagram** — everything else (a
//!   forged 32‑byte digest posted outside the window) is dropped;
//! * it emits the **mint‑confirm itself, from its own held digest** — never from a
//!   renderer value — so even a forged digest sent *as* the in‑window password goes out
//!   only as a soon‑rejected password, never as the approval.
//!
//! The keystone RED — `forged_mint_confirm_outside_the_pam_window_is_dropped` — bites
//! the blind shape (which writes it) and passes the state machine (which drops it).
//!
//! # Scope of THIS increment (B2a, Part B — RED‑first checkpoint)
//!
//! This module is the security core of the consent path. The native channel *driving*
//! (reading the approval request + the PAM prompt off the channel), the deny‑on‑EOF
//! dismissal, and the WRY `ipc_handler`/`evaluate_script` wiring land in the GREEN step
//! after the keystone RED is reviewed. The relay is written pure (a [`ChannelSink`]
//! seam, no fd / no WebView) so the security property is unit‑provable in isolation.
//!
//! # Fidelity (Iron Law #13)
//!
//! There is a single interface here — the private channel the launcher fork‑passes — so
//! no fidelity probing applies; the relay either writes an authorized datagram or it
//! does not.

use std::os::fd::RawFd;

use crate::RuntimeError;

/// The sink for the shell→daemon datagrams the host writes to the private channel's
/// shell end. Abstracted behind a trait so the relay's security decision is unit‑
/// testable without a live socketpair or a WebView; the production host backs it with
/// the real channel fd (the same `write_datagram` shape as
/// [`crate::service::send_mint_confirm`]).
pub trait ChannelSink {
    /// Write one datagram (one SEQPACKET message) to the private channel.
    ///
    /// # Errors
    ///
    /// [`RuntimeError`] if the underlying channel write fails.
    fn write_datagram(&mut self, bytes: &[u8]) -> Result<(), RuntimeError>;
}

/// Where the consent flow is, from the host's side. Only [`Phase::PamPrompt`] is the
/// window in which a renderer message becomes the password datagram. No phase lets a
/// renderer value become the mint‑confirm — the relay emits that from its held digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Approval request received (digest held); the daemon's PAM prompt is not yet
    /// open. A renderer message here is **dropped** (the human is still reviewing).
    ApprovalShown,
    /// The daemon's PAM prompt has arrived on the channel — a renderer message is the
    /// password, and answering it (match‑`pam_unix`: one prompt) is immediately
    /// followed by the relay's own mint‑confirm.
    PamPrompt,
    /// Terminal — the mint‑confirm has been emitted (or the flow was denied). A
    /// renderer message here is **dropped**.
    Done,
}

/// The host's native consent relay: the sole mediator between the renderer's IPC and
/// the private channel. See the module docs for the R‑2 keystone it enforces.
pub struct ConsentRelay {
    phase: Phase,
    /// The canonical action digest, received in the approval request and held **native‑
    /// side only**. Never sent to the renderer; the *only* source of the mint‑confirm.
    digest: [u8; 32],
}

impl ConsentRelay {
    /// Construct on receipt of the approval request: hold the digest, await the prompt.
    #[must_use]
    pub fn new(digest: [u8; 32]) -> Self {
        Self { phase: Phase::ApprovalShown, digest }
    }

    /// The current phase (the native driver advances it; tests observe it).
    #[must_use]
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The native layer read the daemon's PAM prompt off the channel → open the
    /// password window. Only valid from [`Phase::ApprovalShown`]; a no‑op otherwise
    /// (the window cannot be re‑opened after it has closed).
    pub fn open_pam_window(&mut self) {
        if self.phase == Phase::ApprovalShown {
            self.phase = Phase::PamPrompt;
        }
    }

    /// Handle a renderer `window.ipc.postMessage(body)`. **THE R‑2 SECURITY DECISION.**
    ///
    /// The payload reaches the channel **only** as the password, **only** in the PAM
    /// window; then the relay writes the mint‑confirm from its **own held digest**
    /// (match‑`pam_unix`: the single prompt answered ⇒ the daemon is at
    /// `recv_mint_confirm`). Outside the window a renderer message — including a forged
    /// 32‑byte digest — reaches the channel **nowhere**.
    ///
    /// # Errors
    ///
    /// [`RuntimeError`] if a channel write fails inside the PAM window.
    pub fn on_renderer_message(
        &mut self,
        body: &[u8],
        sink: &mut dyn ChannelSink,
    ) -> Result<(), RuntimeError> {
        match self.phase {
            Phase::PamPrompt => {
                // The one legitimate renderer→channel write: the password datagram.
                sink.write_datagram(body)?;
                // The mint‑confirm is the relay's HELD digest — never `body`. A forged
                // digest sent as the password goes out here only as a password (PAM
                // rejects it); it can never become the approval.
                sink.write_datagram(&self.digest)?;
                self.phase = Phase::Done;
                Ok(())
            }
            // Outside the PAM window a renderer message is dropped by construction.
            Phase::ApprovalShown | Phase::Done => Ok(()),
        }
    }
}

/// The private channel the host drives: read datagrams from the daemon **and** write
/// them back. Extends [`ChannelSink`] (the write side the keystone decision uses) so one
/// object serves both the driver's reads and the relay's writes.
pub trait Channel: ChannelSink {
    /// Receive one datagram from the daemon. `Ok(None)` means the daemon **closed** its
    /// end (EOF) — the flow is over (deny / dismiss); the caller must never hang on it.
    ///
    /// # Errors
    ///
    /// [`RuntimeError`] if the underlying channel read fails.
    fn recv_datagram(&mut self) -> Result<Option<Vec<u8>>, RuntimeError>;
}

/// Largest private-channel datagram the host reads — matches the daemon's write cap
/// (`service`'s `MAX_PRIV_MSG` = 8192), so a full approval-request preview is never
/// truncated.
const MAX_HOST_MSG: usize = 8192;

/// The real private channel, backed by the fork-passed `SOCK_SEQPACKET` fd
/// (`DELPHI_CHANNEL_FD`). The host adopts the fd (the WRY proof's `FromRawFd` +
/// `close_range` discipline) and drives the consent protocol over it.
pub struct FdChannel {
    fd: RawFd,
}

impl FdChannel {
    /// Wrap the host's end of the private channel (the fork-passed fd).
    #[must_use]
    pub fn new(fd: RawFd) -> Self {
        Self { fd }
    }
}

impl ChannelSink for FdChannel {
    fn write_datagram(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        // SAFETY: write the borrowed channel fd; SEQPACKET sends `bytes` as one datagram.
        let n = unsafe { nix::libc::write(self.fd, bytes.as_ptr().cast(), bytes.len()) };
        if n < 0 {
            return Err(RuntimeError::Syscall {
                op: "host channel write",
                source: nix::errno::Errno::last(),
            });
        }
        Ok(())
    }
}

impl Channel for FdChannel {
    fn recv_datagram(&mut self) -> Result<Option<Vec<u8>>, RuntimeError> {
        let mut buf = vec![0u8; MAX_HOST_MSG];
        // SAFETY: read one datagram into the heap buffer; SEQPACKET delivers a whole
        // message or none. n == 0 ⇒ the peer (daemon) closed the connection (EOF).
        let n = unsafe { nix::libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(RuntimeError::Syscall {
                op: "host channel read",
                source: nix::errno::Errno::last(),
            });
        }
        if n == 0 {
            return Ok(None);
        }
        buf.truncate(n as usize);
        Ok(Some(buf))
    }
}

/// The host's consent session: drives the private-channel protocol (approval request →
/// PAM prompt → password + mint-confirm) while enforcing the [`ConsentRelay`] keystone
/// against the **real** channel. The phase transitions are driven by the real protocol
/// (the daemon's datagrams), preserving exactly what the keystone RED proves.
pub struct HostSession {
    relay: ConsentRelay,
}

impl HostSession {
    /// Read the approval request off the channel, hold its digest, and return the preview
    /// to render. `Ok(None)` if the daemon closed before sending it.
    ///
    /// # Errors
    ///
    /// [`RuntimeError::Protocol`] if the datagram is shorter than the 32-byte digest;
    /// [`RuntimeError`] on a channel read failure.
    pub fn recv_approval(chan: &mut impl Channel) -> Result<Option<(Self, String)>, RuntimeError> {
        let Some(buf) = chan.recv_datagram()? else {
            return Ok(None);
        };
        if buf.len() < 32 {
            return Err(RuntimeError::Protocol("approval request shorter than digest".into()));
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&buf[..32]);
        let preview = String::from_utf8_lossy(&buf[32..]).into_owned();
        Ok(Some((Self { relay: ConsentRelay::new(digest) }, preview)))
    }

    /// Read the daemon's PAM prompt off the channel and open the password window.
    /// `Ok(None)` = the daemon **closed instead of prompting** (the logind gate or PAM
    /// denied) → the host must **dismiss, fail-closed** (the R‑1 deny-on-EOF edge), never
    /// hang. The window stays closed, so any later renderer message is dropped by the
    /// keystone.
    ///
    /// # Errors
    ///
    /// [`RuntimeError`] on a channel read failure.
    pub fn recv_prompt(&mut self, chan: &mut impl Channel) -> Result<Option<String>, RuntimeError> {
        let Some(buf) = chan.recv_datagram()? else {
            return Ok(None); // deny-on-EOF: dismiss, fail-closed (do not hang)
        };
        self.relay.open_pam_window();
        Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
    }

    /// Apply a renderer `postMessage` to the **real** channel via the keystone decision
    /// ([`ConsentRelay::on_renderer_message`]): the password reaches the daemon only in
    /// the PAM window, and the mint-confirm is the held digest — never a renderer value.
    ///
    /// # Errors
    ///
    /// [`RuntimeError`] on a channel write failure inside the PAM window.
    pub fn on_renderer_message(
        &mut self,
        body: &[u8],
        chan: &mut impl Channel,
    ) -> Result<(), RuntimeError> {
        self.relay.on_renderer_message(body, chan)
    }

    /// The current consent phase (native driver advances it; tests observe it).
    #[must_use]
    pub fn phase(&self) -> Phase {
        self.relay.phase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records every datagram written to the channel (the daemon end's view), so a test
    /// can assert exactly what the renderer's message did or did not put on the wire.
    #[derive(Default)]
    struct RecordingSink {
        writes: Vec<Vec<u8>>,
    }
    impl ChannelSink for RecordingSink {
        fn write_datagram(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
            self.writes.push(bytes.to_vec());
            Ok(())
        }
    }

    /// The de‑risking proof's **blind relay**, in shape verbatim
    /// (`proofs/wry-shell-host/src/main.rs`: `chan_ipc.write_all(body)`): it writes
    /// whatever the renderer posted, unconditionally, ignoring phase. This is the
    /// VULNERABLE variant the keystone RED must bite — see
    /// [`keystone_bites_the_blind_relay_and_passes_the_state_machine`].
    struct BlindRelay;
    impl BlindRelay {
        fn on_renderer_message(
            &mut self,
            body: &[u8],
            sink: &mut dyn ChannelSink,
        ) -> Result<(), RuntimeError> {
            sink.write_datagram(body)
        }
    }

    /// A renderer‑supplied 32‑byte value shaped exactly like a mint‑confirm digest.
    const FORGED_DIGEST: [u8; 32] = [0xFF; 32];
    /// The action digest the relay holds native‑side (the real mint‑confirm value).
    const HELD_DIGEST: [u8; 32] = [0xAB; 32];

    /// THE KEYSTONE RED (R‑2, renderer‑cannot‑forge‑approval): a renderer `postMessage`
    /// of a forged 32‑byte digest **outside the PAM‑prompt window** reaches the channel
    /// NOWHERE, so it can never land as a mint‑confirm. Green against the state machine.
    ///
    /// This is the exact path the checkpoint must confirm the RED bites: forged digest,
    /// window CLOSED (`ApprovalShown`).
    #[test]
    fn forged_mint_confirm_outside_the_pam_window_is_dropped() {
        let mut relay = ConsentRelay::new(HELD_DIGEST); // phase = ApprovalShown
        assert_eq!(relay.phase(), Phase::ApprovalShown, "precondition: PAM window is CLOSED");
        let mut sink = RecordingSink::default();

        relay
            .on_renderer_message(&FORGED_DIGEST, &mut sink)
            .expect("relay handles the message");

        assert!(
            sink.writes.is_empty(),
            "SECURITY(R‑2): a forged digest posted OUTSIDE the PAM window reached the \
             channel and could land as a mint‑confirm: {:?}",
            sink.writes
        );
    }

    /// ANTI‑VACUITY GUARD (the R2‑03 lesson, preemptive): the keystone drop is
    /// SELECTIVE, not a no‑op relay that drops everything (which would pass the keystone
    /// for the wrong reason). In the PAM window a renderer message IS written — proving
    /// the relay writes when it should.
    #[test]
    fn password_in_the_pam_window_reaches_the_channel() {
        let mut relay = ConsentRelay::new(HELD_DIGEST);
        relay.open_pam_window(); // native read the daemon's PAM prompt
        assert_eq!(relay.phase(), Phase::PamPrompt);
        let mut sink = RecordingSink::default();

        relay.on_renderer_message(b"correct horse", &mut sink).expect("write");

        assert_eq!(
            sink.writes.first().map(Vec::as_slice),
            Some(&b"correct horse"[..]),
            "the password must reach the channel as the first datagram in the PAM window"
        );
    }

    /// The mint‑confirm is ALWAYS the relay's held digest, NEVER a renderer value — even
    /// a forged digest sent as the in‑window password goes out only as the (rejected)
    /// password; the second datagram, the mint‑confirm, is the held digest. This is the
    /// sharp "renderer cannot forge the approval token" property.
    #[test]
    fn mint_confirm_is_always_the_held_digest_never_a_renderer_value() {
        let mut relay = ConsentRelay::new(HELD_DIGEST);
        relay.open_pam_window();
        let mut sink = RecordingSink::default();

        relay.on_renderer_message(&FORGED_DIGEST, &mut sink).expect("write");

        assert_eq!(
            sink.writes.get(1).map(Vec::as_slice),
            Some(&HELD_DIGEST[..]),
            "the mint‑confirm must be the relay's HELD digest"
        );
        assert_ne!(
            sink.writes.get(1).map(Vec::as_slice),
            Some(&FORGED_DIGEST[..]),
            "SECURITY(R‑2): the mint‑confirm must never be a renderer‑supplied digest"
        );
    }

    /// THE WEAKEN/RESTORE, enforced in one test (proves the keystone RED BITES): the
    /// IDENTICAL security predicate (`writes.is_empty()` for a forged digest with the
    /// window CLOSED) run against both relays. The BLIND relay LEAKS the forged digest
    /// (predicate false ⇒ the RED fails against it — the bite); `ConsentRelay` DROPS it
    /// (predicate true ⇒ green). If the state machine were ever weakened to the blind
    /// shape, the second assertion here fails.
    #[test]
    fn keystone_bites_the_blind_relay_and_passes_the_state_machine() {
        let window_closed_forged = |writes: &[Vec<u8>]| writes.is_empty();

        // WEAKENED (the proof's blind `chan_ipc.write_all(body)`): forged digest leaks.
        let mut sink_blind = RecordingSink::default();
        BlindRelay
            .on_renderer_message(&FORGED_DIGEST, &mut sink_blind)
            .expect("blind writes");
        assert!(
            !window_closed_forged(&sink_blind.writes),
            "the BLIND relay must LEAK the forged digest — this is what the keystone RED \
             bites (it asserts is_empty(), which fails here)"
        );
        assert_eq!(sink_blind.writes, vec![FORGED_DIGEST.to_vec()]);

        // RESTORED (the state machine): the same forged digest, window closed, dropped.
        let mut relay = ConsentRelay::new(HELD_DIGEST);
        let mut sink_sm = RecordingSink::default();
        relay
            .on_renderer_message(&FORGED_DIGEST, &mut sink_sm)
            .expect("state machine handles");
        assert!(
            window_closed_forged(&sink_sm.writes),
            "the state machine must DROP the forged digest outside the PAM window"
        );
    }
}

/// The keystone re-proven against the REAL private channel (a live `SOCK_SEQPACKET`
/// socketpair), plus the R‑1 deny-on-EOF edge — driving the phase transitions from the
/// real protocol, not the `ChannelSink` stub.
#[cfg(test)]
mod host_session_tests {
    use super::*;
    use crate::channel::approval_socketpair;
    use std::os::fd::AsRawFd;

    const HELD: [u8; 32] = [0xAB; 32];
    const FORGED: [u8; 32] = [0xFF; 32];

    fn approval_datagram(digest: &[u8; 32], preview: &str) -> Vec<u8> {
        let mut v = digest.to_vec();
        v.extend_from_slice(preview.as_bytes());
        v
    }

    /// The "daemon" end of the real channel (test scaffolding): raw SEQPACKET I/O.
    fn daemon_send(fd: RawFd, bytes: &[u8]) {
        // SAFETY: one SEQPACKET datagram out the test's daemon end.
        let n = unsafe { nix::libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        assert!(n >= 0, "daemon-side send failed");
    }
    fn daemon_recv(fd: RawFd) -> Vec<u8> {
        let mut buf = vec![0u8; 8192];
        // SAFETY: read one datagram off the test's daemon end.
        let n = unsafe { nix::libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        assert!(n > 0, "daemon-side recv failed/empty");
        buf.truncate(n as usize);
        buf
    }
    fn daemon_recv_nonblocking(fd: RawFd) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 8192];
        // SAFETY: non-blocking read — returns None (EAGAIN) if the daemon end is empty,
        // so the test can assert "nothing reached the daemon" without hanging.
        let n = unsafe {
            nix::libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), nix::libc::MSG_DONTWAIT)
        };
        if n <= 0 {
            return None;
        }
        buf.truncate(n as usize);
        Some(buf)
    }

    /// KEYSTONE against the REAL channel (not the `ChannelSink` stub): a forged digest
    /// posted by the renderer with the PAM window CLOSED reaches the daemon end NOWHERE.
    #[test]
    fn keystone_holds_on_the_real_channel_forged_outside_window_reaches_daemon_nowhere() {
        let (daemon, shell) = approval_socketpair().expect("socketpair");
        let mut host = FdChannel::new(shell.as_raw_fd());
        let dfd = daemon.as_raw_fd();

        daemon_send(dfd, &approval_datagram(&HELD, "rm demo.txt"));
        let (mut session, preview) =
            HostSession::recv_approval(&mut host).unwrap().expect("approval received");
        assert_eq!(preview, "rm demo.txt");
        assert_eq!(session.phase(), Phase::ApprovalShown, "window CLOSED (no PAM prompt yet)");

        // ATTACK: renderer posts a forged digest BEFORE the daemon's PAM prompt.
        session.on_renderer_message(&FORGED, &mut host).unwrap();

        assert!(
            daemon_recv_nonblocking(dfd).is_none(),
            "SECURITY(R‑2, real channel): a forged digest outside the PAM window reached the daemon"
        );
    }

    /// Over the real channel: the in-window password reaches the daemon as the password,
    /// THEN the mint-confirm arrives as the HELD digest — never a renderer value.
    #[test]
    fn password_in_window_reaches_daemon_then_the_held_mint_confirm() {
        let (daemon, shell) = approval_socketpair().unwrap();
        let mut host = FdChannel::new(shell.as_raw_fd());
        let dfd = daemon.as_raw_fd();

        daemon_send(dfd, &approval_datagram(&HELD, "rm demo.txt"));
        let (mut session, _p) = HostSession::recv_approval(&mut host).unwrap().unwrap();

        // Daemon sends the PAM prompt; host reads it → window opens.
        daemon_send(dfd, b"Password: ");
        let prompt = session.recv_prompt(&mut host).unwrap().expect("prompt (not EOF)");
        assert_eq!(prompt, "Password: ");
        assert_eq!(session.phase(), Phase::PamPrompt);

        // Renderer posts the password → daemon receives password THEN the held mint-confirm.
        session.on_renderer_message(b"hunter2", &mut host).unwrap();
        assert_eq!(daemon_recv(dfd), b"hunter2", "the password reaches the daemon");
        assert_eq!(
            daemon_recv(dfd),
            HELD.to_vec(),
            "the mint-confirm is the HELD digest, never a renderer value"
        );
        assert_eq!(session.phase(), Phase::Done);
    }

    /// R‑1 DENY-ON-EOF (fail-closed): the daemon closes after the approval request
    /// (logind/PAM denied) instead of prompting → `recv_prompt` yields `None` (dismiss),
    /// NEVER hangs, the window stays closed, and a late renderer message is dropped.
    #[test]
    fn deny_on_eof_daemon_closes_before_prompting_dismisses_fail_closed() {
        let (daemon, shell) = approval_socketpair().unwrap();
        let mut host = FdChannel::new(shell.as_raw_fd());
        let dfd = daemon.as_raw_fd();

        daemon_send(dfd, &approval_datagram(&HELD, "rm demo.txt"));
        let (mut session, _p) = HostSession::recv_approval(&mut host).unwrap().unwrap();

        // The daemon DENIES (logind/PAM) and closes its end instead of sending a prompt.
        drop(daemon);

        let prompt = session.recv_prompt(&mut host).unwrap();
        assert!(
            prompt.is_none(),
            "deny-on-EOF: the daemon closed → recv_prompt is None (dismiss, no hang)"
        );
        assert_eq!(session.phase(), Phase::ApprovalShown, "the PAM window never opened");

        // A late renderer message after the deny is dropped (fail-closed) — window shut.
        session.on_renderer_message(&FORGED, &mut host).unwrap();
        assert_eq!(session.phase(), Phase::ApprovalShown);
    }
}
