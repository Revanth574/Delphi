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

        let chan_revents = fds[0].revents().unwrap_or(PollFlags::empty());
        let pidfd_revents = fds[1].revents().unwrap_or(PollFlags::empty());

        // The channel is READ first — but reading is not the same as deciding. See
        // `classify_and_confirm_alive`: the marker is VALIDATED first (so a wrong datagram
        // is diagnosed as a protocol error rather than as a death), and only then do
        // terminal events get to overrule it.
        if chan_revents.intersects(PollFlags::POLLIN) {
            return classify_and_confirm_alive(chan, pidfd, chan_revents);
        }
        if pidfd_revents.intersects(PollFlags::POLLIN) {
            return Err(RuntimeError::ShellDiedBeforeReady);
        }
        // POLLHUP/POLLERR on the channel with no POLLIN: the peer is gone with nothing to
        // read. Same verdict as death — the shell will never signal.
        if chan_revents.intersects(PollFlags::POLLHUP | PollFlags::POLLERR) {
            return Err(RuntimeError::ShellDiedBeforeReady);
        }
    }
}

/// How long to wait for a death notification before concluding a process is genuinely alive.
///
/// # This constant exists because the FIRST fix trusted a negative, and that was the same
/// class it was closing
///
/// **MEASURED (parallel-only failure, 2026-07-31).** A child that `_exit`s closes its fds
/// **before** its pidfd becomes readable. In that window the channel already shows `POLLHUP`
/// while `poll(pidfd, 0)` still reports nothing — so an instantaneous check reports
/// "not dead", and the first R1-06 fix turned that into the positive claim **"alive"**,
/// misdiagnosing a genuinely dead shell as a live one with a protocol fault. The window is
/// invisible in an isolated run and opens under parallel scheduling pressure, which is
/// exactly the non-determinism §6 requires ≥30 iterations to see.
///
/// **The general lesson, which outlives this constant:** a pidfd is authoritative for
/// *death* and says **nothing** about life. `!dead` means "not yet observed dead", never
/// "alive". Anywhere the distinction matters, liveness must be established by waiting a
/// bounded time for the death that would contradict it.
const DEATH_GRACE: Duration = Duration::from_millis(250);

/// Has the pinned child died — waiting up to `grace` for a notification?
///
/// `Ok(false)` means "still alive after `grace`", which is a **positive** claim and is why
/// this takes a budget rather than polling instantaneously (see [`DEATH_GRACE`]). Pass
/// `Duration::ZERO` only where a `false` is not treated as evidence of life.
///
/// The pidfd is immune to pid reuse (R3-03), which is why it — and not the socket — is the
/// oracle this module consults whenever the socket's answer is ambiguous.
fn child_died_within(pidfd: BorrowedFd<'_>, grace: Duration) -> Result<bool, RuntimeError> {
    let deadline = Instant::now() + grace;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let mut fds = [PollFd::new(pidfd, PollFlags::POLLIN)];
        let t = PollTimeout::try_from(remaining).unwrap_or(PollTimeout::ZERO);
        match nix::poll::poll(&mut fds, t) {
            Err(nix::errno::Errno::EINTR) => continue,
            Err(source) => {
                return Err(RuntimeError::Syscall { op: "poll (pidfd liveness)", source })
            }
            Ok(0) => return Ok(false), // the grace elapsed with no death
            Ok(_) => {
                if fds[0].revents().is_some_and(|r| r.intersects(PollFlags::POLLIN)) {
                    return Ok(true);
                }
                if remaining.is_zero() {
                    return Ok(false);
                }
            }
        }
    }
}

/// Read one datagram, classify it, and only then let terminal events overrule a valid marker.
///
/// # Why the order is validate-then-overrule (D0-R1-02 / D0-R1-06)
///
/// **MEASURED on this box, 2026-07-31** — these are not reasoned properties:
///
/// | case | `recvmsg` | `msg_flags` | `poll` revents |
/// |---|---|---|---|
/// | empty datagram, peer OPEN | `0` | `0x0` (`MSG_EOR` clear) | `POLLIN` |
/// | empty datagram, peer CLOSED | `0` | `0x0` | `POLLIN\|POLLHUP` |
/// | nothing queued, peer CLOSED (EOF) | `0` | `0x0` | `POLLIN\|POLLHUP` |
/// | **real datagram, peer CLOSED** | `n>0` | — | **`POLLIN\|POLLHUP`** |
///
/// Two consequences, each a finding the first draft got wrong:
///
/// 1. **D0-R1-02 — a queued marker must not outrank a dead peer.** The last row is the
///    killer: a shell that writes the marker and *then dies* presents `POLLIN` **and**
///    `POLLHUP` in the same `poll` return. The first draft checked `POLLIN`, read a valid
///    marker, and returned `Ok` without ever looking at `POLLHUP` — reporting an
///    already-dead shell as ready, which is verbatim the P3a failure D0 exists to prevent.
///    Its stated justification ("resolve the race toward *it did signal*") was backwards:
///    at the moment of return we hold evidence the process is gone, and returning `Ok`
///    would knowingly report a corpse. **Terminal events win — but only AFTER the marker is
///    validated**, so a *wrong* datagram is still diagnosed as a protocol error and not
///    misattributed to death.
/// 2. **D0-R1-06 — `read() == 0` is ambiguous and the socket cannot resolve it.** An empty
///    datagram and EOF are indistinguishable at the socket layer: both return 0, both with
///    `msg_flags == 0x0` and `MSG_EOR` clear (so `MSG_EOR`, the obvious candidate, does
///    **not** discriminate — measured, row 1 vs row 3). The first draft called both EOF and
///    reported `ShellDiedBeforeReady`, sending an operator whose shell is *alive but
///    speaking the wrong protocol* to diagnose a crash. Resolved by asking the
///    **authoritative oracle** — the pidfd — instead of the socket.
fn classify_and_confirm_alive(
    chan: BorrowedFd<'_>,
    pidfd: BorrowedFd<'_>,
    chan_revents: PollFlags,
) -> Result<(), RuntimeError> {
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
        // POLLHUP is the PRIMARY discriminator, and it is decided from the socket alone —
        // no pidfd, no waiting. Without HUP the peer still holds its end, so the shell is
        // alive BY CONSTRUCTION of the socket, and this was an empty datagram. This branch
        // is what keeps the common protocol fault fast and unambiguous.
        if !chan_revents.intersects(PollFlags::POLLHUP) {
            return Err(RuntimeError::Protocol(
                "the shell is RUNNING but sent a ZERO-LENGTH datagram instead of the \
                 readiness marker. SOCK_SEQPACKET permits empty packets, so this is a live \
                 shell speaking the wrong protocol — not a dead one. Check it is the \
                 installed /usr/libexec/delphi-shell."
                    .to_owned(),
            ));
        }
        // HUP: the channel is fully closed. Dead, or alive-having-closed-its-channel — and
        // ONLY here is the distinction temporal, so only here is the grace paid.
        if child_died_within(pidfd, DEATH_GRACE)? {
            return Err(RuntimeError::ShellDiedBeforeReady);
        }
        return Err(RuntimeError::Protocol(
            "the shell is RUNNING but closed its end of the private consent channel without \
             signalling readiness. It can never receive an approval request over a closed \
             channel — this is a shell-side protocol fault, not a crash."
                .to_owned(),
        ));
    }
    #[allow(clippy::cast_sign_loss)] // n > 0 is established above.
    let got = &buf[..n as usize];
    if got == READY_DATAGRAM {
        // D0-R1-02: the marker is VALID. Terminal events now overrule it — a shell that
        // signalled and then died is DEAD, and `launch()` must not hand back `Children`
        // whose pidfd is already a zombie.
        //
        // `POLLHUP` is checked FIRST and short-circuits, so the grace is never paid on the
        // SUCCESS path: a healthy shell holds its channel open, so HUP is clear and the
        // pidfd check below runs with a ZERO budget and returns immediately. The grace is
        // reserved for the ambiguous read()==0 branch above.
        if chan_revents.intersects(PollFlags::POLLHUP)
            || child_died_within(pidfd, Duration::ZERO)?
        {
            return Err(RuntimeError::ShellDiedBeforeReady);
        }
        // RESIDUAL, STATED RATHER THAN PAPERED OVER: a shell that dies in the instant
        // between this check and the return is reported ready. No synchronous check can
        // close that — the process can always die one instruction later. What IS guaranteed
        // is that this function never returns `Ok` while holding evidence of death. The
        // daemon keeps the pidfd (R3-03) and observes any later death there; that is the
        // mechanism for post-launch death, and this contract covers startup only.
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
    use std::os::fd::{AsRawFd, OwnedFd, RawFd};

    /// Serialises the forking tests in this module against **each other**.
    ///
    /// # Measured, not assumed — the mechanism behind a 1-3/30 flake
    ///
    /// `fork()` copies the whole fd table, so a child forked by test B inherits test A's
    /// channel fds and **holds them open for its lifetime**. Any test whose property depends
    /// on the channel being FULLY closed (`POLLHUP`) then observes no `POLLHUP`, because a
    /// sibling's child is still a holder. Measured directly:
    ///
    /// ```text
    /// marker + close(), extra dup OPEN   revents=0x1  POLLIN=1 POLLHUP=0   <- the flake
    /// marker + close(), no extra dup     revents=0x11 POLLIN=1 POLLHUP=1   <- intended
    /// ```
    ///
    /// `shutdown(SHUT_WR)` was tried as a refcount-independent alternative and **measured
    /// not to work** — `POLLHUP` stays clear while a datagram is queued, with or without the
    /// extra reference. So the interference cannot be engineered away inside the child; the
    /// forks must not overlap.
    ///
    /// **PRODUCTION FORECLOSES THIS, which is what makes it a harness artifact rather than a
    /// product defect** (Iron Law 15 clause 5 — shown, not asserted). The consent channel has
    /// exactly two holders: the daemon and the shell. The AI never receives it — `fork_ai`
    /// runs the FD-01 `close_range` sweep — and the daemon forks nothing else in between. A
    /// third process holding the channel fd cannot occur outside this test harness.
    ///
    /// Every test below therefore takes this lock **and reaps its child before releasing
    /// it**, so no child outlives the guard and leaks into the next test's fd table.
    static FORK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take [`FORK_LOCK`], surviving poisoning from an earlier failing test (a poisoned
    /// mutex must not convert one failure into N cascading ones).
    fn fork_guard() -> std::sync::MutexGuard<'static, ()> {
        FORK_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// SIGKILL and reap `pid`, so it cannot outlive the [`FORK_LOCK`] guard.
    fn kill_and_reap(pid: nix::unistd::Pid) {
        // SAFETY: signalling a child this process forked and has not yet reaped.
        unsafe { nix::libc::kill(pid.as_raw(), nix::libc::SIGKILL) };
        let _ = nix::sys::wait::waitpid(pid, None);
    }

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
    /// # The async-signal-safety contract these tests rely on (D0-R1-05)
    ///
    /// This module's tests run under the **DEFAULT PARALLEL** harness, i.e. the fork parent
    /// is multithreaded. That is only sound because every `body` here performs **raw
    /// syscalls and nothing else** — no allocation, no locks, no D-Bus — so the child cannot
    /// deadlock on an allocator lock held by a thread that did not survive the fork (the
    /// hazard `launcher.rs` documents and that makes `leader_is_shell.rs` serial-only).
    ///
    /// **That claim was asserted before it was true.** `marker_with_trailing_bytes_does_not_match`
    /// called `READY_DATAGRAM.to_vec()` *inside* the child — a heap allocation after `fork`,
    /// which is exactly what the claim forbids (D0-R1-05: an honesty declaration checked and
    /// found false). The fix is to allocate **before** the fork and move the finished buffer
    /// into the closure; the child then only reads it. Serial execution was deliberately
    /// **not** the fix — parallel is the configuration that stresses these, so the
    /// allocation moved rather than the test.
    ///
    /// **Standing rule for anything added here: build every buffer before `fork_child`.**
    fn fork_child(body: impl FnOnce()) -> (nix::unistd::Pid, OwnedFd) {
        fork_child_inner(body, None)
    }

    /// Like [`fork_child`], but the parent **blocks until the child's setup is done**.
    ///
    /// # Why this exists — a test of mine that failed 3 runs in 30
    ///
    /// `marker_then_channel_close_while_alive_is_not_ready` needs the child to have written
    /// the marker **and closed its channel end** before the parent polls. Without ordering,
    /// the parent frequently polls in between: `POLLIN` is set (marker queued), `POLLHUP` is
    /// not (the child still holds its end), and `await_shell_ready` correctly returns `Ok` —
    /// so the test failed **3/30 under parallel execution and passed in isolation**.
    ///
    /// That was a **test-design defect, not a product defect**, and the distinction is the
    /// point: a shell that closes the channel *after* the daemon has already judged it ready
    /// is a post-launch event, handled downstream by the pidfd — not something
    /// `await_shell_ready` can or should catch. The test was measuring before its own
    /// precondition held.
    ///
    /// It is recorded here rather than quietly fixed because it is §6's non-determinism rule
    /// paying for itself: a single green run could not have distinguished this from a sound
    /// test, and it would have entered review as evidence.
    /// `body` receives the sync fd and MUST call [`setup_done`] at the exact point its
    /// precondition holds — which is generally *before* any sleep, not after it.
    fn fork_child_synced(body: impl FnOnce(RawFd)) -> (nix::unistd::Pid, OwnedFd) {
        let (r, w) = nix::unistd::pipe().expect("sync pipe");
        let w_raw = w.as_raw_fd();
        let (pid, pidfd) = fork_child_inner(move || body(w_raw), None);
        drop(w); // the parent holds only the read end, so a dead child yields EOF not a hang
        let mut b = [0u8; 1];
        // SAFETY: bounded read on the owned read end; returns 1 (child signalled) or 0 (EOF
        // — the child died without signalling, which the assertion below will surface).
        unsafe { nix::libc::read(r.as_raw_fd(), b.as_mut_ptr().cast(), 1) };
        (pid, pidfd)
    }

    /// Tell the parent the child's setup precondition now holds. Raw write, no allocation.
    fn setup_done(w: RawFd) {
        // SAFETY: single bounded write of a const byte to the caller-supplied pipe fd.
        unsafe { nix::libc::write(w, b"1".as_ptr().cast(), 1) };
    }

    fn fork_child_inner(body: impl FnOnce(), sync_w: Option<RawFd>) -> (nix::unistd::Pid, OwnedFd) {
        // SAFETY: the child arm performs only raw syscalls and diverges via `_exit`, never
        // unwinding into a forked copy of the test harness's stack.
        match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => {
                body();
                // Setup complete — release the parent (raw write, no allocation).
                if let Some(w) = sync_w {
                    unsafe { nix::libc::write(w, b"1".as_ptr().cast(), 1) };
                }
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
        let _guard = fork_guard();
        let (daemon_end, shell_end) = channel_pair();
        let shell_raw = shell_end.as_raw_fd();
        let (pid, pidfd) = fork_child(|| {
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
        kill_and_reap(pid); // before the guard drops — no child may outlive it
    }

    /// The positive leg. Without it the keystone above could pass for the wrong reason —
    /// e.g. an implementation that always returns `Err` (the FAIL/FAIL shape Iron Law 15
    /// clause 2 names as equally worthless).
    #[test]
    fn shell_that_signals_is_ready() {
        let _guard = fork_guard();
        let (daemon_end, shell_end) = channel_pair();
        let shell_raw = shell_end.as_raw_fd();
        let (pid, pidfd) = fork_child(move || {
            let _ = signal_ready(shell_raw);
            // Stay alive briefly so the marker is not racing our own exit.
            unsafe { nix::libc::sleep(2) };
        });
        drop(shell_end);

        await_shell_ready(daemon_end.as_fd(), pidfd.as_fd(), Duration::from_secs(5))
            .expect("a shell that signalled must be reported ready");
        kill_and_reap(pid); // before the guard drops — no child may outlive it
    }

    /// A shell that comes up but speaks a different protocol is a configuration error, and
    /// must be named as one rather than silently accepted or reported as a death.
    #[test]
    fn wrong_first_datagram_is_a_protocol_error_not_a_ready() {
        let _guard = fork_guard();
        let (daemon_end, shell_end) = channel_pair();
        let shell_raw = shell_end.as_raw_fd();
        let (pid, pidfd) = fork_child(move || {
            let junk = b"hello";
            unsafe { nix::libc::write(shell_raw, junk.as_ptr().cast(), junk.len()) };
            unsafe { nix::libc::sleep(2) };
        });
        drop(shell_end);

        let err = await_shell_ready(daemon_end.as_fd(), pidfd.as_fd(), Duration::from_secs(5))
            .expect_err("a non-marker datagram is not readiness");
        assert!(matches!(err, RuntimeError::Protocol(_)), "expected Protocol, got: {err}");
        kill_and_reap(pid); // before the guard drops — no child may outlive it
    }

    /// A marker that is a PREFIX of a longer datagram must not match. This is the
    /// under-coverage shape (class 1): a prefix test would accept
    /// `delphi-shell-ready\0v1<anything>` and so would accept a `v2` shell against a `v1`
    /// daemon.
    #[test]
    fn marker_with_trailing_bytes_does_not_match() {
        let _guard = fork_guard();
        let (daemon_end, shell_end) = channel_pair();
        let shell_raw = shell_end.as_raw_fd();
        // D0-R1-05: allocated in the PARENT, before the fork. The child only reads it.
        let longer: Vec<u8> = READY_DATAGRAM.iter().copied().chain(*b"X").collect();
        let (pid, pidfd) = fork_child(move || {
            unsafe { nix::libc::write(shell_raw, longer.as_ptr().cast(), longer.len()) };
            unsafe { nix::libc::sleep(2) };
        });
        drop(shell_end);

        let err = await_shell_ready(daemon_end.as_fd(), pidfd.as_fd(), Duration::from_secs(5))
            .expect_err("a superset of the marker is not the marker");
        assert!(matches!(err, RuntimeError::Protocol(_)), "expected Protocol, got: {err}");
        kill_and_reap(pid); // before the guard drops — no child may outlive it
    }

    /// A shell that neither signals nor dies must be given up on, not waited for forever.
    /// The pre-D0 launcher had no timeout because it had no post-`execve` wait at all; a
    /// wait without a bound would trade a silent false-success for a silent hang.
    #[test]
    fn shell_that_neither_signals_nor_dies_times_out() {
        let _guard = fork_guard();
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

        kill_and_reap(pid); // before the guard drops — no child may outlive it
    }

    /// **D0-R1-02 REGRESSION.** A shell that writes a VALID marker and then dies is DEAD,
    /// and must not be reported ready. Measured: that shell presents `POLLIN|POLLHUP` in one
    /// `poll` return, so an implementation that reads the marker and returns without
    /// re-checking terminal state reports a corpse as up — verbatim the P3a failure.
    ///
    /// # This test PASSED FOR THE WRONG REASON 15 runs in 20 before it was ordered
    ///
    /// Its first form forked a child that wrote the marker and exited, then had the parent
    /// `kill_and_reap` it. Nothing ordered the child's `write` before the parent's `SIGKILL`,
    /// so the child was frequently killed **before signalling** — and the run then exercised
    /// "died without signalling" (which passes for a completely different reason) instead of
    /// "signalled, then died".
    ///
    /// Measured against an injected R1-02 defect: this test detected it **5/20**, while its
    /// sibling `marker_then_channel_close_while_alive_is_not_ready` detected the *same*
    /// defect **20/20**. A weaken/restore run resting on this test alone would have reported
    /// "the weaken did not bite" three times in four — a **concrete instance of the class-22
    /// blind spot**, produced here rather than argued about. Ordering the child's write ahead
    /// of the parent's kill removes it; the assertions are unchanged.
    #[test]
    fn marker_from_an_already_dead_shell_is_not_ready() {
        let _guard = fork_guard();
        let (daemon_end, shell_end) = channel_pair();
        let shell_raw = shell_end.as_raw_fd();
        let (pid, pidfd) = fork_child_synced(move |sync| {
            let _ = signal_ready(shell_raw);
            setup_done(sync); // the marker IS written before the parent proceeds
            // then fall off the end → `_exit(0)`: the marker is queued behind a dead peer
        });
        drop(shell_end);
        kill_and_reap(pid); // now unambiguously AFTER the write

        let err = await_shell_ready(daemon_end.as_fd(), pidfd.as_fd(), Duration::from_secs(5))
            .expect_err("a shell that signalled and then DIED is dead, not ready");
        assert!(
            matches!(err, RuntimeError::ShellDiedBeforeReady),
            "expected ShellDiedBeforeReady, got: {err}"
        );
    }

    /// **D0-R1-06 REGRESSION.** A LIVE shell that sends a zero-length datagram must be
    /// reported as a PROTOCOL fault, not as a death. Measured: an empty datagram and EOF are
    /// indistinguishable at the socket (`read` → 0, `msg_flags` 0x0, `MSG_EOR` clear for
    /// both), so the verdict must come from the pidfd rather than the socket.
    #[test]
    fn empty_datagram_from_a_live_shell_is_a_protocol_error_not_a_death() {
        let _guard = fork_guard();
        let (daemon_end, shell_end) = channel_pair();
        let shell_raw = shell_end.as_raw_fd();
        let (pid, pidfd) = fork_child(move || {
            // A zero-length SEQPACKET datagram — permitted by the socket type.
            unsafe { nix::libc::write(shell_raw, c"".as_ptr().cast(), 0) };
            unsafe { nix::libc::sleep(5) };
        });
        drop(shell_end);

        let err = await_shell_ready(daemon_end.as_fd(), pidfd.as_fd(), Duration::from_secs(5))
            .expect_err("an empty datagram is not the marker");
        assert!(
            matches!(err, RuntimeError::Protocol(_)),
            "a LIVE shell sending an empty datagram must be a Protocol fault, not \
             ShellDiedBeforeReady — got: {err}"
        );

        kill_and_reap(pid); // before the guard drops — no child may outlive it
    }

    /// **CLASS-22 WEAKEN (b) FOR D0-R1-02 — the second form of the same class.**
    ///
    /// R1-02's fix is `child_is_dead(pidfd)? || chan_revents.intersects(POLLHUP)`. A fix
    /// that checked only ONE of those legs would still pass
    /// `marker_from_an_already_dead_shell_is_not_ready`, where both fire together. This is
    /// the input that separates them: the shell writes a valid marker, **closes its channel
    /// end, and stays ALIVE**. POLLHUP fires; the pidfd does not. A pidfd-only fix reports
    /// ready — and the shell can never receive an approval over a channel it closed.
    #[test]
    fn marker_then_channel_close_while_alive_is_not_ready() {
        let _guard = fork_guard();
        let (daemon_end, shell_end) = channel_pair();
        let shell_raw = shell_end.as_raw_fd();
        // SYNCED: the parent must not poll until the marker is written AND the channel end
        // is closed — otherwise it observes POLLIN without POLLHUP and `Ok` is the correct
        // answer at that instant. Measured 3/30 flaky without this ordering.
        let (pid, pidfd) = fork_child_synced(move |sync| {
            let _ = signal_ready(shell_raw);
            unsafe { nix::libc::close(shell_raw) };
            setup_done(sync);
            unsafe { nix::libc::sleep(5) };
        });
        drop(shell_end);

        let err = await_shell_ready(daemon_end.as_fd(), pidfd.as_fd(), Duration::from_secs(5))
            .expect_err("a shell that closed the consent channel is not ready, alive or not");
        assert!(
            matches!(err, RuntimeError::ShellDiedBeforeReady),
            "expected ShellDiedBeforeReady, got: {err}"
        );

        kill_and_reap(pid); // before the guard drops — no child may outlive it
    }

    /// **CLASS-22 WEAKEN (b) FOR D0-R1-06 — the second ambiguous form.**
    ///
    /// R1-06 is "a `read() == 0` attributed to the wrong cause". The first form is an empty
    /// datagram from a live shell. This is the *other* one: a live shell that closes the
    /// channel **without writing anything at all**. `read` returns 0 exactly as it does at
    /// EOF-by-death, and only the pidfd can tell them apart. A fix that special-cased the
    /// empty-datagram path alone would misreport this as a death.
    #[test]
    fn silent_channel_close_while_alive_is_a_protocol_error_not_a_death() {
        let _guard = fork_guard();
        let (daemon_end, shell_end) = channel_pair();
        let shell_raw = shell_end.as_raw_fd();
        // SYNCED for the same reason as the sibling above — order the close before the poll
        // so the test measures the state it names rather than whatever the scheduler left.
        let (pid, pidfd) = fork_child_synced(move |sync| {
            unsafe { nix::libc::close(shell_raw) };
            setup_done(sync);
            unsafe { nix::libc::sleep(5) };
        });
        drop(shell_end);

        let err = await_shell_ready(daemon_end.as_fd(), pidfd.as_fd(), Duration::from_secs(5))
            .expect_err("a closed channel is not readiness");
        // The process is ALIVE, so "died before ready" would be a false diagnosis.
        assert!(
            matches!(err, RuntimeError::Protocol(_)),
            "a LIVE shell that closed its channel must be a Protocol fault, not \
             ShellDiedBeforeReady — got: {err}"
        );

        kill_and_reap(pid); // before the guard drops — no child may outlive it
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
