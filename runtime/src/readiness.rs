// SPDX-License-Identifier: MIT

//! The shell readiness contract (Increment D0).
//!
//! # The gap this closes
//!
//! [`crate::launcher::wait_for_child_setup`] answers exactly one question: **did the
//! `execve` happen?** Its sync pipe is `O_CLOEXEC`, so a successful `execve` closes the
//! write end and the parent reads EOF. That is a *pre*-`execve* signal by construction —
//! it has already been delivered by the time the new program's `main` runs, so **nothing
//! the shell does after `execve` can be observed through it**.
//!
//! Measured consequence (PROGRESS.md, P3a): the WRY host reported `GTK INIT: ok`, then
//! **aborted during rendering**. The launcher had already recorded "shell started
//! successfully"; the daemon went on to derive the logind verdict, accept the AI, and
//! service an action *against a shell that was already dead*. The failure was loud in the
//! journal and **invisible to the component whose job is to know whether the shell came
//! up**.
//!
//! This module supplies the missing half: a **post-`execve` liveness + readiness signal**,
//! so `launch()` returning `Ok` means *the shell is running and said so*, not merely that
//! `execve` returned.
//!
//! # Why the signal rides the private channel and not a second pipe
//!
//! A second pipe would have to survive `execve`, which means it must be **exempted from the
//! FD-01 sweep** ([`crate::fdsec::mark_cloexec_except_raw`]). Widening that allowlist is the
//! precise class FD-01 (P1) closed — "the allowlist MUST be explicitly enumerated and
//! minimal" (`docs/TRUST_MODEL.md` §4). So readiness reuses **the one descriptor §4 Reading
//! A already says legitimately survives into the shell**: the fork-passed `SOCK_SEQPACKET`
//! consent channel on [`crate::launcher::SHELL_CHANNEL_FD`]. No new fd, no allowlist change,
//! no new attack surface.
//!
//! The channel is `SOCK_SEQPACKET`, so the ready datagram is **framed** — it cannot be
//! coalesced with, or split across, a later protocol message. Readiness is a *prologue*: the
//! daemon reads exactly one datagram before it writes anything, and the host's
//! [`crate::consent_relay::HostSession::recv_approval`] still reads the approval request as
//! the first datagram *it* receives. The two orderings do not interact.
//!
//! # What "ready" does NOT mean — read this before trusting a green
//!
//! This contract proves the shell **process is alive and reached the point where it emits
//! the marker**. It does **not** prove anything was drawn, and it must never be reported as
//! if it did. Under the SECONDARY dev shape there may be no display at all. Tightening
//! "ready" to mean "a client buffer reached scanout" is D2/D4 work and needs a compositor;
//! see `scratch/display-arc-scoping.md` §4 (Tier 2).
//!
//! A shell that emits the marker and *then* dies is still observable — the daemon holds the
//! pidfd (R3-03) and sees the death. This contract closes the **startup** window only.

use std::os::fd::{AsFd, BorrowedFd};
use std::time::{Duration, Instant};

use nix::poll::{PollFd, PollFlags, PollTimeout};

use crate::RuntimeError;

/// The exact datagram a shell writes to its channel end to claim it is up.
///
/// Versioned (`v1`) so a future tightening of what readiness *means* (D2/D4: a client buffer
/// reached scanout) is a **new marker the daemon can distinguish**, not a silent
/// reinterpretation of this one. A daemon that expects `v2` and receives `v1` must reject —
/// which is why the comparison below is exact-match, not a prefix test.
///
/// Not drawn from any value space the later protocol uses: the channel's subsequent messages
/// are a 32-byte digest + preview, a PAM prompt, a password, and a 32-byte mint-confirm. A
/// fixed ASCII sentinel with a NUL is in none of those spaces, so this is not the in-band
/// sentinel class (`docs/DEFECT_CLASSES.md` class 24) — and the framing makes it moot anyway.
pub const READY_DATAGRAM: &[u8] = b"delphi-shell-ready\0v1";

/// How long the daemon waits for a shell to signal ready before giving up.
///
/// A shell that `execve`s and then hangs forever (no signal, no death) must not wedge the
/// daemon. Ten seconds is generous for a WebKit process on a cold page cache and short
/// enough that a wedged launch surfaces as a bounded failure rather than a hung service.
pub const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Block until the shell signals ready, dies, or the timeout expires.
///
/// Watches **both** the channel and the pidfd, so a shell that dies without signalling is
/// reported immediately rather than after the full timeout. `pidfd` becoming readable is the
/// kernel's race-free death notification for the pinned child (R3-03).
///
/// # Errors
///
/// - [`RuntimeError::ShellDiedBeforeReady`] — the child exited, or closed the channel,
///   before emitting [`READY_DATAGRAM`].
/// - [`RuntimeError::ShellReadyTimeout`] — neither happened within `timeout`.
/// - [`RuntimeError::Protocol`] — the shell wrote something that is not the marker.
/// - [`RuntimeError::Syscall`] — `poll` or `read` failed.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
/// use delphi_runtime::readiness::{await_shell_ready, DEFAULT_READY_TIMEOUT};
/// # fn demo(chan: std::os::fd::BorrowedFd, pidfd: std::os::fd::BorrowedFd) {
/// // Called by `launch()` between the fork and returning `Children`.
/// match await_shell_ready(chan, pidfd, DEFAULT_READY_TIMEOUT) {
///     Ok(()) => { /* the shell is up AND said so */ }
///     Err(e) => eprintln!("shell never came up: {e}"),
/// }
/// # }
/// ```
#[must_use = "a shell that never signalled ready must not be treated as running"]
pub fn await_shell_ready(
    chan: BorrowedFd<'_>,
    pidfd: BorrowedFd<'_>,
    timeout: Duration,
) -> Result<(), RuntimeError> {
    let deadline = Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(RuntimeError::ShellReadyTimeout { secs: timeout.as_secs() });
        }

        // Order is load-bearing for the assertions below: index 0 is the channel, 1 the pidfd.
        let mut fds = [
            PollFd::new(chan, PollFlags::POLLIN),
            PollFd::new(pidfd, PollFlags::POLLIN),
        ];
        let poll_timeout = PollTimeout::try_from(remaining)
            .unwrap_or(PollTimeout::MAX);

        match nix::poll::poll(&mut fds, poll_timeout) {
            // EINTR is not a failure — recompute the remaining budget and re-arm. Without
            // this a stray signal would report a spurious timeout.
            Err(nix::errno::Errno::EINTR) => continue,
            Err(source) => return Err(RuntimeError::Syscall { op: "poll (shell readiness)", source }),
            Ok(0) => return Err(RuntimeError::ShellReadyTimeout { secs: timeout.as_secs() }),
            Ok(_) => {}
        }

        // The channel is checked FIRST and deliberately. A shell can emit the marker and
        // exit so fast that both fds are ready in the same `poll` return; reading the
        // channel first means that race resolves to "it did signal", which is the truth.
        // Checking the pidfd first would report `ShellDiedBeforeReady` for a shell that
        // demonstrably signalled — a false negative manufactured by scheduling.
        if fds[0].revents().is_some_and(|r| r.intersects(PollFlags::POLLIN)) {
            return classify_datagram(chan);
        }
        if fds[1].revents().is_some_and(|r| r.intersects(PollFlags::POLLIN)) {
            return Err(RuntimeError::ShellDiedBeforeReady);
        }
        // POLLHUP/POLLERR on the channel with no POLLIN: the peer is gone with nothing to
        // read. Same verdict as death — the shell will never signal.
        if fds[0].revents().is_some_and(|r| r.intersects(PollFlags::POLLHUP | PollFlags::POLLERR)) {
            return Err(RuntimeError::ShellDiedBeforeReady);
        }
    }
}

/// Read one datagram from the channel and decide whether it is the ready marker.
///
/// Split out so [`await_shell_ready`] stays a readable poll loop (CLAUDE.md §3, 50-line cap).
fn classify_datagram(chan: BorrowedFd<'_>) -> Result<(), RuntimeError> {
    // A datagram larger than the marker is by definition not the marker; a bounded buffer
    // one byte longer lets a too-long message be DETECTED rather than silently truncated
    // into a match. (Truncating into a match is the under-coverage class 1 shape.)
    let mut buf = [0u8; READY_DATAGRAM.len() + 1];
    // SAFETY: `chan` is a valid borrowed fd for the duration of the call; the read is
    // bounded by the buffer's own length. SEQPACKET delivers a whole datagram or none.
    let n = unsafe {
        nix::libc::read(
            std::os::fd::AsRawFd::as_raw_fd(&chan),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n < 0 {
        return Err(RuntimeError::Syscall {
            op: "read (shell readiness marker)",
            source: nix::errno::Errno::last(),
        });
    }
    if n == 0 {
        // EOF: the shell closed its channel end without signalling.
        return Err(RuntimeError::ShellDiedBeforeReady);
    }
    #[allow(clippy::cast_sign_loss)] // n > 0 is established above.
    let got = &buf[..n as usize];
    if got == READY_DATAGRAM {
        return Ok(());
    }
    // Deliberately reports the LENGTH, never the bytes. This datagram arrives before the
    // consent flow, so it should never carry a secret — but "should never" is not a reason
    // to log an untrusted payload into the journal (§10.1: never log user data).
    Err(RuntimeError::Protocol(format!(
        "shell's first datagram was {n} bytes and is not the readiness marker \
         (expected {} bytes of `delphi-shell-ready`); the shell binary is not speaking the \
         D0 readiness contract — check it is the installed /usr/libexec/delphi-shell",
        READY_DATAGRAM.len()
    )))
}

/// Write the readiness marker to `chan` — the shell side of the contract.
///
/// Every binary launched as `LaunchSpec::shell_path` MUST call this once it is up, or the
/// daemon will refuse the launch after [`DEFAULT_READY_TIMEOUT`]. That refusal is the point:
/// a shell that cannot say it is up is indistinguishable from one that died.
///
/// # Errors
///
/// [`RuntimeError::Syscall`] if the write fails (the daemon is gone).
///
/// # Examples
///
/// ```no_run
/// use delphi_runtime::readiness::signal_ready;
/// # fn demo(chan_fd: std::os::fd::RawFd) -> Result<(), Box<dyn std::error::Error>> {
/// signal_ready(chan_fd)?;   // the daemon's `launch()` now returns Ok
/// # Ok(())
/// # }
/// ```
pub fn signal_ready(chan_fd: std::os::fd::RawFd) -> Result<(), RuntimeError> {
    // SAFETY: single bounded write of a const buffer to the caller-supplied channel fd.
    // SEQPACKET sends it as exactly one datagram.
    let n = unsafe {
        nix::libc::write(chan_fd, READY_DATAGRAM.as_ptr().cast(), READY_DATAGRAM.len())
    };
    if n < 0 {
        return Err(RuntimeError::Syscall {
            op: "write (shell readiness marker)",
            source: nix::errno::Errno::last(),
        });
    }
    Ok(())
}

/// Borrow a raw fd as a `BorrowedFd` for the duration of a call.
///
/// The launcher holds the channel as an `OwnedFd`; this keeps the call sites tidy.
#[must_use]
pub fn borrow(fd: &impl AsFd) -> BorrowedFd<'_> {
    fd.as_fd()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, OwnedFd};

    /// A SOCK_SEQPACKET pair standing in for the real private channel.
    fn channel_pair() -> (OwnedFd, OwnedFd) {
        nix::sys::socket::socketpair(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::SeqPacket,
            None,
            nix::sys::socket::SockFlag::empty(),
        )
        .expect("socketpair")
    }

    /// Fork a child that runs `body` and then `_exit(0)`. Returns (pid, pidfd).
    ///
    /// The child does no allocation and no non-async-signal-safe work beyond the raw
    /// syscalls `body` performs, so this is safe from a multithreaded test parent (unlike
    /// the fork+PAM shape in `leader_is_shell.rs`, which is serial-only).
    fn fork_child(body: impl FnOnce()) -> (nix::unistd::Pid, OwnedFd) {
        // SAFETY: the child arm performs only raw syscalls and diverges via `_exit`, never
        // unwinding into a forked copy of the test harness's stack.
        match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => {
                body();
                unsafe { nix::libc::_exit(0) };
            }
            nix::unistd::ForkResult::Parent { child } => {
                let pidfd = crate::pidfd::open(child).expect("pidfd_open");
                (child, pidfd)
            }
        }
    }

    /// THE KEYSTONE. A shell that `execve`s fine and then dies without signalling must NOT
    /// be reported as up. This is the exact P3a failure: the launcher recorded success while
    /// the process was already gone.
    ///
    /// VERIFIED TO BITE: replacing `await_shell_ready`'s body with `Ok(())` — which is a
    /// faithful encoding of the PRE-D0 behaviour, where nothing observed the child after
    /// `execve` — makes this test FAIL. See the weaken record in the D0 commit body.
    #[test]
    fn shell_that_dies_without_signalling_is_not_ready() {
        let (daemon_end, shell_end) = channel_pair();
        let shell_raw = shell_end.as_raw_fd();
        let (_pid, pidfd) = fork_child(|| {
            // Die immediately, exactly like the aborting WRY host: no marker, no write.
            let _ = shell_raw;
        });
        drop(shell_end); // the parent drops its copy so only the (dead) child held one

        let err = await_shell_ready(daemon_end.as_fd(), pidfd.as_fd(), Duration::from_secs(5))
            .expect_err("a dead shell must not be reported ready");
        assert!(
            matches!(err, RuntimeError::ShellDiedBeforeReady),
            "expected ShellDiedBeforeReady, got: {err}"
        );
    }

    /// The positive leg. Without it the keystone above could pass for the wrong reason —
    /// e.g. an implementation that always returns `Err` (the FAIL/FAIL shape Iron Law 15
    /// clause 2 names as equally worthless).
    #[test]
    fn shell_that_signals_is_ready() {
        let (daemon_end, shell_end) = channel_pair();
        let shell_raw = shell_end.as_raw_fd();
        let (_pid, pidfd) = fork_child(move || {
            let _ = signal_ready(shell_raw);
            // Stay alive briefly so the marker is not racing our own exit.
            unsafe { nix::libc::sleep(2) };
        });
        drop(shell_end);

        await_shell_ready(daemon_end.as_fd(), pidfd.as_fd(), Duration::from_secs(5))
            .expect("a shell that signalled must be reported ready");
    }

    /// A shell that comes up but speaks a different protocol is a configuration error, and
    /// must be named as one rather than silently accepted or reported as a death.
    #[test]
    fn wrong_first_datagram_is_a_protocol_error_not_a_ready() {
        let (daemon_end, shell_end) = channel_pair();
        let shell_raw = shell_end.as_raw_fd();
        let (_pid, pidfd) = fork_child(move || {
            let junk = b"hello";
            unsafe { nix::libc::write(shell_raw, junk.as_ptr().cast(), junk.len()) };
            unsafe { nix::libc::sleep(2) };
        });
        drop(shell_end);

        let err = await_shell_ready(daemon_end.as_fd(), pidfd.as_fd(), Duration::from_secs(5))
            .expect_err("a non-marker datagram is not readiness");
        assert!(matches!(err, RuntimeError::Protocol(_)), "expected Protocol, got: {err}");
    }

    /// A marker that is a PREFIX of a longer datagram must not match. This is the
    /// under-coverage shape (class 1): a prefix test would accept
    /// `delphi-shell-ready\0v1<anything>` and so would accept a `v2` shell against a `v1`
    /// daemon.
    #[test]
    fn marker_with_trailing_bytes_does_not_match() {
        let (daemon_end, shell_end) = channel_pair();
        let shell_raw = shell_end.as_raw_fd();
        let (_pid, pidfd) = fork_child(move || {
            let mut longer = READY_DATAGRAM.to_vec();
            longer.extend_from_slice(b"X");
            unsafe { nix::libc::write(shell_raw, longer.as_ptr().cast(), longer.len()) };
            unsafe { nix::libc::sleep(2) };
        });
        drop(shell_end);

        let err = await_shell_ready(daemon_end.as_fd(), pidfd.as_fd(), Duration::from_secs(5))
            .expect_err("a superset of the marker is not the marker");
        assert!(matches!(err, RuntimeError::Protocol(_)), "expected Protocol, got: {err}");
    }

    /// A shell that neither signals nor dies must be given up on, not waited for forever.
    /// The pre-D0 launcher had no timeout because it had no post-`execve` wait at all; a
    /// wait without a bound would trade a silent false-success for a silent hang.
    #[test]
    fn shell_that_neither_signals_nor_dies_times_out() {
        let (daemon_end, shell_end) = channel_pair();
        let (pid, pidfd) = fork_child(|| {
            unsafe { nix::libc::sleep(30) };
        });
        drop(shell_end);

        let started = Instant::now();
        let err = await_shell_ready(daemon_end.as_fd(), pidfd.as_fd(), Duration::from_millis(300))
            .expect_err("a silent live shell must time out");
        assert!(
            matches!(err, RuntimeError::ShellReadyTimeout { .. }),
            "expected ShellReadyTimeout, got: {err}"
        );
        assert!(started.elapsed() < Duration::from_secs(5), "the bound must actually bound");

        // SAFETY: reap the sleeper so it does not outlive the test.
        unsafe { nix::libc::kill(pid.as_raw(), nix::libc::SIGKILL) };
        let _ = nix::sys::wait::waitpid(pid, None);
    }

    /// The marker must stay distinguishable from the protocol messages that follow it on the
    /// same channel. A 32-byte digest is what the *next* datagram is; if the marker were 32
    /// bytes a framing slip would be much harder to diagnose.
    #[test]
    fn marker_is_not_digest_sized() {
        assert_ne!(READY_DATAGRAM.len(), 32, "marker must not collide with the digest size");
        assert!(READY_DATAGRAM.contains(&0), "marker carries a NUL so it is not plain text");
    }
}
