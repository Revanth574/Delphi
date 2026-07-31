// SPDX-License-Identifier: MIT

//! The shell readiness contract (Increment D0): a post-`execve` liveness signal.
//!
//! `launcher::wait_for_child_setup`'s sync pipe is `O_CLOEXEC`, so its EOF is delivered *by*
//! the `execve` — it cannot observe anything the shell does afterwards. This module supplies
//! that half, so `launch()` returning `Ok` means the shell is running and said so.
//!
//! Readiness rides the existing consent channel rather than a second inherited fd; rationale
//! in `docs/TRUST_MODEL.md` §4 R3-01e (a new fd would need an FD-01 allowlist exemption).
//!
//! **"Ready" does not mean "drew anything."** It means the process reached the marker.
//! Tightening it to "a client buffer reached scanout" needs a compositor (D2/D4).

use std::os::fd::BorrowedFd;
use std::time::{Duration, Instant};

use nix::poll::{PollFd, PollFlags, PollTimeout};

use crate::RuntimeError;

/// The datagram a shell writes to claim it is up.
///
/// Versioned so a future tightening of what readiness *means* is a marker the daemon can
/// distinguish rather than a silent reinterpretation — hence exact-match, not prefix, below.
pub const READY_DATAGRAM: &[u8] = b"delphi-shell-ready\0v1";

/// Launch budget: a shell that neither signals nor dies must not wedge the daemon.
pub const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Grace for a death notification before concluding a process is genuinely alive.
///
/// A child closes its fds *before* its pidfd becomes readable, so an instantaneous poll can
/// report "not dead" for a corpse. **A pidfd is authoritative for death and says nothing
/// about life**: `!dead` means "not yet observed dead", so any positive liveness claim must
/// wait out the death that would contradict it.
const DEATH_GRACE: Duration = Duration::from_millis(250);

/// Block until the shell signals ready, dies, or `timeout` elapses.
///
/// Watches the channel and the pidfd together, so a death is reported at once rather than
/// after the full budget.
///
/// # Errors
///
/// [`RuntimeError::ShellDiedBeforeReady`], [`RuntimeError::ShellReadyTimeout`],
/// [`RuntimeError::Protocol`] (wrote something that is not the marker), or
/// [`RuntimeError::Syscall`].
///
/// # Examples
///
/// ```no_run
/// use delphi_runtime::readiness::{await_shell_ready, DEFAULT_READY_TIMEOUT};
/// # fn demo(chan: std::os::fd::BorrowedFd, pidfd: std::os::fd::BorrowedFd) {
/// let up = await_shell_ready(chan, pidfd, DEFAULT_READY_TIMEOUT).is_ok();
/// # let _ = up;
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

        let mut fds = [
            PollFd::new(chan, PollFlags::POLLIN),
            PollFd::new(pidfd, PollFlags::POLLIN),
        ];
        match nix::poll::poll(&mut fds, PollTimeout::try_from(remaining).unwrap_or(PollTimeout::MAX))
        {
            Err(nix::errno::Errno::EINTR) => continue, // re-arm on the remaining budget
            Err(source) => {
                return Err(RuntimeError::Syscall { op: "poll (shell readiness)", source })
            }
            Ok(0) => return Err(RuntimeError::ShellReadyTimeout { secs: timeout.as_secs() }),
            Ok(_) => {}
        }

        let chan_revents = fds[0].revents().unwrap_or(PollFlags::empty());
        let pidfd_revents = fds[1].revents().unwrap_or(PollFlags::empty());

        if chan_revents.intersects(PollFlags::POLLIN) {
            return classify_and_confirm_alive(chan, pidfd, chan_revents);
        }
        if pidfd_revents.intersects(PollFlags::POLLIN)
            || chan_revents.intersects(PollFlags::POLLHUP | PollFlags::POLLERR)
        {
            return Err(RuntimeError::ShellDiedBeforeReady);
        }
    }
}

/// Has the pinned child died within `grace`?
///
/// `Ok(false)` is a positive liveness claim, which is why this takes a budget — see
/// [`DEATH_GRACE`]. Pass `ZERO` only where `false` is not treated as evidence of life.
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
            Ok(0) => return Ok(false),
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

/// Read one datagram, validate it, then let terminal events overrule a valid marker.
///
/// Measured on AF_UNIX/SEQPACKET, and both rows foreclose an obvious wrong fix:
/// a real datagram from a **closed** peer presents `POLLIN|POLLHUP` *together* (so returning
/// on `POLLIN` alone reports a corpse as ready — D0-R1-02); and an empty datagram is
/// indistinguishable from EOF at the socket — both `read()==0`, `msg_flags 0x0`, `MSG_EOR`
/// **clear**, so `MSG_EOR` does not discriminate and the pidfd must (D0-R1-06).
fn classify_and_confirm_alive(
    chan: BorrowedFd<'_>,
    pidfd: BorrowedFd<'_>,
    chan_revents: PollFlags,
) -> Result<(), RuntimeError> {
    // One byte longer than the marker, so an over-long datagram is detected, not truncated
    // into a match (DEFECT_CLASSES 1).
    let mut buf = [0u8; READY_DATAGRAM.len() + 1];
    // SAFETY: `chan` is valid for the call; the read is bounded by the buffer's own length.
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
        // No HUP ⇒ the peer still holds its end ⇒ alive by construction of the socket, so no
        // pidfd query and no waiting is needed to call this a protocol fault.
        if !chan_revents.intersects(PollFlags::POLLHUP) {
            return Err(RuntimeError::Protocol(
                "the shell is RUNNING but sent a ZERO-LENGTH datagram instead of the \
                 readiness marker — a live shell speaking the wrong protocol, not a dead \
                 one. Check it is the installed /usr/libexec/delphi-shell."
                    .to_owned(),
            ));
        }
        // HUP: dead, or alive-having-closed-its-channel. Only here is the distinction
        // temporal, so only here is the grace paid.
        if child_died_within(pidfd, DEATH_GRACE)? {
            return Err(RuntimeError::ShellDiedBeforeReady);
        }
        return Err(RuntimeError::Protocol(
            "the shell is RUNNING but closed its end of the private consent channel without \
             signalling readiness — it can never receive an approval request over a closed \
             channel. A shell-side protocol fault, not a crash."
                .to_owned(),
        ));
    }
    #[allow(clippy::cast_sign_loss)] // n > 0 established above
    let got = &buf[..n as usize];
    if got == READY_DATAGRAM {
        // ORDER IS LOAD-BEARING: `POLLHUP` first short-circuits, so the success path (HUP
        // clear) reaches the pidfd query with a ZERO budget and never pays the grace.
        if chan_revents.intersects(PollFlags::POLLHUP)
            || child_died_within(pidfd, Duration::ZERO)?
        {
            return Err(RuntimeError::ShellDiedBeforeReady);
        }
        // Residual: a shell dying between this check and the return is reported ready. No
        // synchronous check can close that; the guarantee is only that `Ok` is never returned
        // while holding evidence of death. Post-launch death is the daemon's pidfd (R3-03).
        return Ok(());
    }
    // Reports the LENGTH, never the bytes — an untrusted payload must not reach the journal.
    Err(RuntimeError::Protocol(format!(
        "shell's first datagram was {n} bytes, not the {}-byte readiness marker; the binary \
         is not speaking the D0 contract — check it is the installed /usr/libexec/delphi-shell",
        READY_DATAGRAM.len()
    )))
}

/// Write the readiness marker — the shell side of the contract.
///
/// Every `LaunchSpec::shell_path` binary must call this once it is up, or `launch()` refuses
/// it after [`DEFAULT_READY_TIMEOUT`]: a shell that cannot say it is up is indistinguishable
/// from one that died.
///
/// # Errors
///
/// [`RuntimeError::Syscall`] if the write fails (the daemon is gone).
///
/// # Examples
///
/// ```no_run
/// # fn demo(chan_fd: std::os::fd::RawFd) -> Result<(), Box<dyn std::error::Error>> {
/// delphi_runtime::readiness::signal_ready(chan_fd)?;
/// # Ok(())
/// # }
/// ```
pub fn signal_ready(chan_fd: std::os::fd::RawFd) -> Result<(), RuntimeError> {
    // SAFETY: single bounded write of a const buffer; SEQPACKET sends it as one datagram.
    let n =
        unsafe { nix::libc::write(chan_fd, READY_DATAGRAM.as_ptr().cast(), READY_DATAGRAM.len()) };
    if n < 0 {
        return Err(RuntimeError::Syscall {
            op: "write (shell readiness marker)",
            source: nix::errno::Errno::last(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};

    /// Serialises this module's forking tests against each other.
    ///
    /// `fork()` copies the fd table, so a sibling test's child holds this test's channel end
    /// and suppresses the `POLLHUP` these tests measure. `shutdown(SHUT_WR)` was measured NOT
    /// to substitute (HUP stays clear while a datagram is queued), so the forks must not
    /// overlap. Production cannot hit this — the channel has exactly two holders, `fork_ai`'s
    /// FD-01 sweep being what keeps the AI from being a third — so it is a harness artifact
    /// (Iron Law 15 clause 5, shown not asserted). Every test reaps its child before
    /// releasing the guard.
    static FORK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take [`FORK_LOCK`], surviving poisoning from an earlier failing test (a poisoned
    /// mutex must not convert one failure into N cascading ones).
    fn fork_guard() -> std::sync::MutexGuard<'static, ()> {
        FORK_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Block until `fd` reports `POLLHUP`, so a test measuring a fully-closed channel does
    /// not run before the channel is closed.
    ///
    /// [`FORK_LOCK`] and `SOCK_CLOEXEC` close two of the three `POLLHUP` suppressors; the
    /// third — a sibling `Command::spawn` holding fds between its `fork` and `exec` — cannot
    /// be locked out from here but always ends. So the test waits for its own precondition
    /// instead of racing it.
    ///
    /// # Panics
    ///
    /// If `POLLHUP` never arrives — a harness failure, and it says so. It must never be
    /// mistaken for the product property, and must never silently skip.
    fn wait_for_hup(fd: BorrowedFd<'_>, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "HARNESS FAILURE (not a product failure): the channel never reported POLLHUP \
                 within {timeout:?}, so this test's precondition — a fully-closed peer — never \
                 held and its assertion would measure something else. Some other process is \
                 holding a copy of the channel fd."
            );
            let mut fds = [PollFd::new(fd, PollFlags::POLLIN)];
            // `poll` does not consume the queued datagram, so the measurement is unaffected.
            let _ = nix::poll::poll(&mut fds, PollTimeout::try_from(remaining).unwrap_or(PollTimeout::ZERO));
            if fds[0].revents().is_some_and(|r| r.intersects(PollFlags::POLLHUP)) {
                return;
            }
        }
    }

    /// SIGKILL and reap `pid`, so it cannot outlive the [`FORK_LOCK`] guard.
    fn kill_and_reap(pid: nix::unistd::Pid) {
        // SAFETY: signalling a child this process forked and has not yet reaped.
        unsafe { nix::libc::kill(pid.as_raw(), nix::libc::SIGKILL) };
        let _ = nix::sys::wait::waitpid(pid, None);
    }

    /// A SOCK_SEQPACKET pair standing in for the real private channel.
    ///
    /// `SOCK_CLOEXEC` mirrors `channel::approval_socketpair`. It is not incidental: with
    /// `empty()`, sibling tests' `Command::spawn` children inherited the fd and suppressed
    /// `POLLHUP`. A test resource constructed with different flags than the production
    /// resource it stands in for is a fidelity gap, not just a flaky one.
    fn channel_pair() -> (OwnedFd, OwnedFd) {
        nix::sys::socket::socketpair(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::SeqPacket,
            None,
            // Mirrors `channel::approval_socketpair` — a test channel that is not the same
            // KIND of channel as production is a fidelity gap, not merely a flaky one.
            nix::sys::socket::SockFlag::SOCK_CLOEXEC,
        )
        .expect("socketpair")
    }

    /// Fork a child that runs `body` and then `_exit(0)`. Returns (pid, pidfd).
    ///
    /// Children here perform raw syscalls only, so the multithreaded-fork hazard that makes
    /// `leader_is_shell.rs` serial-only does not apply and DEFAULT PARALLEL is correct.
    ///
    /// **Build every buffer before `fork_child`** — allocation after `fork` in a
    /// multithreaded harness can deadlock on an allocator lock (D0-R1-05).
    fn fork_child(body: impl FnOnce()) -> (nix::unistd::Pid, OwnedFd) {
        fork_child_inner(body, None)
    }

    /// Like [`fork_child`], but the parent **blocks until the child's setup is done**.
    ///
    /// Orders a child's setup against the parent's measurement. Without it,
    /// `marker_then_channel_close_while_alive_is_not_ready` failed 3/30: the parent polled
    /// between the marker landing and the close, where `Ok` is the correct answer.
    ///
    /// `body` receives the sync fd and MUST call [`setup_done`] at the exact point its
    /// precondition holds — which is generally *before* any sleep, not after it.
    fn fork_child_synced(body: impl FnOnce(RawFd)) -> (nix::unistd::Pid, OwnedFd) {
        // `pipe2(O_CLOEXEC)` mirrors `launcher.rs`'s setup-sync pipe. Harmless either way here
        // (this child never execs), but a hand-rolled fixture that differs from the
        // production constructor is the divergence class (DEFECT_CLASSES 25).
        let (r, w) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("sync pipe");
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

    /// THE KEYSTONE: a shell that exec'd fine and then died is not up — the P3a failure.
    /// Verified to bite; weaken record in the D0 commit body.
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

    /// The positive leg: without it the keystone could pass against an always-`Err` impl
    /// (the FAIL/FAIL shape, Iron Law 15 clause 2).
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

    /// A live shell speaking a different protocol is a config error, not a death.
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

    /// A prefix test would accept a `v2` shell against a `v1` daemon (DEFECT_CLASSES 1).
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

    /// A wedged shell must be given up on: a wait without a bound would trade a silent
    /// false-success for a silent hang.
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
    /// Ordered because the unordered form passed for the WRONG reason 15 runs in 20: nothing
    /// sequenced the child's write before the parent's SIGKILL, so most runs exercised "died
    /// without signalling" instead. Detection of an injected R1-02 defect went 5/20 -> 20/20.
    /// The measurement behind DEFECT_CLASSES 22's n/N rule.
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

        wait_for_hup(daemon_end.as_fd(), Duration::from_secs(5));

        let err = await_shell_ready(daemon_end.as_fd(), pidfd.as_fd(), Duration::from_secs(5))
            .expect_err("a shell that signalled and then DIED is dead, not ready");
        assert!(
            matches!(err, RuntimeError::ShellDiedBeforeReady),
            "expected ShellDiedBeforeReady, got: {err}"
        );
    }

    /// D0-R1-06: an empty datagram and EOF are indistinguishable at the socket, so the
    /// verdict must come from the pidfd. A live shell must not be reported dead.
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

    /// Class-22 weaken (b) for D0-R1-02: separates the two legs of
    /// `POLLHUP || child_died`. Here HUP fires and the pidfd does not, so a pidfd-only fix
    /// still reports ready over a channel the shell closed.
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

        wait_for_hup(daemon_end.as_fd(), Duration::from_secs(5));

        let err = await_shell_ready(daemon_end.as_fd(), pidfd.as_fd(), Duration::from_secs(5))
            .expect_err("a shell that closed the consent channel is not ready, alive or not");
        assert!(
            matches!(err, RuntimeError::ShellDiedBeforeReady),
            "expected ShellDiedBeforeReady, got: {err}"
        );

        kill_and_reap(pid); // before the guard drops — no child may outlive it
    }

    /// Class-22 weaken (b) for D0-R1-06: the other ambiguous `read()==0` — a live shell that
    /// closed the channel writing nothing. A fix special-casing only empty datagrams misses it.
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

        wait_for_hup(daemon_end.as_fd(), Duration::from_secs(5));

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

    /// Keeps the marker distinguishable from the 32-byte digest that follows it on the wire.
    #[test]
    fn marker_is_not_digest_sized() {
        assert_ne!(READY_DATAGRAM.len(), 32, "marker must not collide with the digest size");
        assert!(READY_DATAGRAM.contains(&0), "marker carries a NUL so it is not plain text");
    }
}
