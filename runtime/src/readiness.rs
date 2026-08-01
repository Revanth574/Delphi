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

/// How long to wait for death evidence before concluding a process is genuinely alive.
///
/// A child closes its fds *before* its pidfd becomes readable, so an instantaneous poll can
/// report "not dead" for a corpse. **A pidfd is authoritative for death and says nothing
/// about life**: a negative is only admissible as a liveness claim after waiting out the
/// death that would contradict it.
///
/// CALIBRATED, not guessed (marker-then-immediate-exit, 100 samples each):
///
/// ```text
/// grace=  0ms  wrongly-accepted=32/100      grace= 10ms  wrongly-accepted=0/100
/// grace=  1ms  wrongly-accepted=43/100      grace= 25ms  wrongly-accepted=0/100
/// grace=  2ms  wrongly-accepted= 0/100      grace=250ms  wrongly-accepted=0/100
/// ```
///
/// Non-monotonic below 2ms — that region is scheduler-dominated, which is the reason the
/// constant is not set near the evidence latency. A death returns as soon as it is witnessed
/// (worst observed ~1.8ms); the grace is paid in full only when no death arrives.
///
/// TWO LIMITS, both real:
///
/// * **An engineering margin, not a portable bound.** 0/100 at 2ms was measured on one
///   unloaded box and one kernel. It cannot bound a stressed VM, a different scheduler, or a
///   CPU-starved container. 250ms is ~125x margin on *this* measurement, which is a bet, not
///   a proof; a system that misses it degrades to a false READY.
/// * **It is not only the success path that pays.** Every liveness verdict costs the full
///   grace — including the live-shell `Protocol` outcomes (empty datagram, closed channel),
///   which are error paths. Only `Dead` returns early.
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
            return classify_and_confirm_alive(chan, pidfd);
        }
        if pidfd_revents.intersects(PollFlags::POLLIN)
            || chan_revents.intersects(PollFlags::POLLHUP | PollFlags::POLLERR)
        {
            return Err(RuntimeError::ShellDiedBeforeReady);
        }
    }
}

/// What a FRESH poll witnesses about the channel and the child.
#[derive(Debug, PartialEq, Eq)]
enum Terminal {
    /// No terminal evidence appeared within the grace.
    None,
    /// The pidfd reported the child's death.
    Dead,
    /// The channel is fully closed, but the child is still running.
    ChannelClosed,
}

/// One thing the observer saw. The kernel interaction produces these; the state machine
/// consumes them, and nothing else couples the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Observation {
    /// The channel reported `POLLHUP`/`POLLERR`.
    Hup,
    /// The pidfd reported the child's death.
    Death,
    /// The grace elapsed with nothing further to see.
    Timeout,
}

/// The terminal-state decision, factored OUT of the polling (D0-R3-03).
///
/// # Why this is a separate type and not an inlined `bool`
///
/// The state machine and the kernel interaction were entangled from D0's first commit, and
/// **every timing defect in this file has lived in that entanglement** — R2-01, R2-01b and
/// R2-01c were all decisions about observations, testable only by racing a real child.
/// Separated, the decision is exercised by injecting an exact sequence, and the polling is
/// tested for representativeness on its own.
///
/// `hup` is monotonic: it records that **the channel closed**, which stays true, and never
/// that the process is alive.
#[derive(Debug, Default)]
struct TerminalWitness {
    hup: bool,
}

impl TerminalWitness {
    /// Feed one observation. `Some` ends the witness; `None` means keep watching.
    fn observe(&mut self, o: Observation) -> Option<Terminal> {
        match o {
            // Positive evidence of death is conclusive and outranks a latched HUP.
            Observation::Death => Some(Terminal::Dead),
            // NOT conclusive: a dying child closes its fds before its pidfd signals, so a HUP
            // here may be the leading edge of a death still in flight (D0-R2-01c).
            Observation::Hup => {
                self.hup = true;
                None
            }
            // Only after the grace has elapsed without a death may a liveness claim be made.
            Observation::Timeout => Some(if self.hup {
                Terminal::ChannelClosed
            } else {
                Terminal::None
            }),
        }
    }

    /// Should the channel still be in the poll set?
    ///
    /// Once `HUP` is latched the channel would report it on every iteration and busy-spin out
    /// the remaining grace, so it is dropped from the set.
    fn watching_channel(&self) -> bool {
        !self.hup
    }
}

/// Drive [`TerminalWitness`] from real descriptors for up to `grace`.
///
/// This function owns only the kernel interaction: poll, map `revents` to an
/// [`Observation`], feed. Every decision lives in the state machine.
fn witness_terminal(
    chan: BorrowedFd<'_>,
    pidfd: BorrowedFd<'_>,
    grace: Duration,
) -> Result<Terminal, RuntimeError> {
    let deadline = Instant::now() + grace;
    let mut witness = TerminalWitness::default();

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero()
            && let Some(t) = witness.observe(Observation::Timeout)
        {
            return Ok(t);
        }

        // `chan` carries no requested events: POLLHUP/POLLERR arrive regardless while POLLIN
        // does not, so a queued datagram cannot spin this loop.
        let mut fds = Vec::with_capacity(2);
        if witness.watching_channel() {
            fds.push(PollFd::new(chan, PollFlags::empty()));
        }
        fds.push(PollFd::new(pidfd, PollFlags::POLLIN));
        let pidfd_idx = fds.len() - 1;

        let observation = match nix::poll::poll(&mut fds, poll_timeout(remaining)) {
            Err(nix::errno::Errno::EINTR) => continue,
            Err(source) => {
                return Err(RuntimeError::Syscall { op: "poll (terminal witness)", source })
            }
            Ok(0) => Observation::Timeout,
            Ok(_) => {
                if is_readable(&fds[pidfd_idx]) {
                    Observation::Death
                } else if witness.watching_channel()
                    && fds[0]
                        .revents()
                        .is_some_and(|r| r.intersects(PollFlags::POLLHUP | PollFlags::POLLERR))
                {
                    Observation::Hup
                } else {
                    continue; // spurious wakeup: nothing decidable was seen
                }
            }
        };

        if let Some(t) = witness.observe(observation) {
            return Ok(t);
        }
    }
}

/// `remaining` as a `PollTimeout`, saturating rather than wrapping.
fn poll_timeout(remaining: Duration) -> PollTimeout {
    PollTimeout::try_from(remaining).unwrap_or(PollTimeout::MAX)
}

/// Did this descriptor report `POLLIN`?
fn is_readable(fd: &PollFd<'_>) -> bool {
    fd.revents().is_some_and(|r| r.intersects(PollFlags::POLLIN))
}

/// Read one datagram, validate it, then witness terminal state AFRESH.
///
/// # Captured `revents` are never reused across a syscall (D0-R2-01 / R2-01b)
///
/// A `poll` result describes what was true *at poll time*. The `read` below is an intervening
/// syscall, so any conclusion drawn from the pre-read `revents` is a claim about the past
/// stated in the present tense (DEFECT_CLASSES 26). Measured: reusing them accepted an
/// already-dead shell **83/100**. Both decision points therefore re-poll.
///
/// The socket alone cannot decide either question: a real datagram from a closed peer presents
/// `POLLIN|POLLHUP` together, and an empty datagram is indistinguishable from EOF
/// (`read()==0`, `msg_flags 0x0`, `MSG_EOR` clear — so `MSG_EOR` does not discriminate).
fn classify_and_confirm_alive(
    chan: BorrowedFd<'_>,
    pidfd: BorrowedFd<'_>,
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
        return Err(match witness_terminal(chan, pidfd, DEATH_GRACE)? {
            Terminal::Dead => RuntimeError::ShellDiedBeforeReady,
            Terminal::ChannelClosed => RuntimeError::Protocol(
                "the shell is RUNNING but closed its end of the private consent channel \
                 without signalling readiness — it can never receive an approval request \
                 over a closed channel. A shell-side protocol fault, not a crash."
                    .to_owned(),
            ),
            Terminal::None => RuntimeError::Protocol(
                "the shell is RUNNING but sent a ZERO-LENGTH datagram instead of the \
                 readiness marker — a live shell speaking the wrong protocol, not a dead \
                 one. Check it is the installed /usr/libexec/delphi-shell."
                    .to_owned(),
            ),
        });
    }
    #[allow(clippy::cast_sign_loss)] // n > 0 established above
    let got = &buf[..n as usize];
    if got == READY_DATAGRAM {
        return match witness_terminal(chan, pidfd, DEATH_GRACE)? {
            Terminal::None => Ok(()),
            Terminal::Dead => Err(RuntimeError::ShellDiedBeforeReady),
            // Alive, but unreachable over a closed channel. Reported as a protocol fault
            // rather than a death, for the R1-06 reason: a running process must not be
            // diagnosed as a crash.
            Terminal::ChannelClosed => Err(RuntimeError::Protocol(
                "the shell signalled readiness and then CLOSED the private consent channel \
                 while still running — it can never receive an approval request. A \
                 shell-side protocol fault, not a crash."
                    .to_owned(),
            )),
        };
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

    /// Exit code a forked child uses when it could not write the readiness marker.
    ///
    /// A DISTINCT value, and the distinctness is load-bearing (D0-R3-01): a child that dies
    /// of a signal before reaching `signal_ready` yields neither 0 nor this, so a test must
    /// assert the EXACT value rather than treating "not 98" as success.
    const CHILD_MARKER_WRITE_FAILED: i32 = 98;

    /// Reap `pid` and return its exit code, or `-signal` if it died of one.
    ///
    /// The parent, not the child, must witness what the child did. A child's `expect` is
    /// invisible here: it kills only the child, and the parent's `await_shell_ready` reads
    /// that death as the very `Err` the test expects (D0-R3-01).
    fn reap_status(pid: nix::unistd::Pid) -> i32 {
        match nix::sys::wait::waitpid(pid, None) {
            Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => code,
            Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => -(sig as i32),
            other => panic!("unexpected wait status for {pid}: {other:?}"),
        }
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
        // SAFETY: bounded read on the owned read end.
        let n = unsafe { nix::libc::read(r.as_raw_fd(), b.as_mut_ptr().cast(), 1) };
        // D0-R2-02: an ignored result made this barrier a no-op — EOF (the child died before
        // signalling) read as "ordered", so the test proceeded to measure an unordered run
        // and could pass having established nothing.
        assert_eq!(n, 1, "HARNESS FAILURE: the child died before signalling setup_done, so \
                          this test's ordering precondition never held");
        (pid, pidfd)
    }

    /// Tell the parent the child's setup precondition now holds. Raw write, no allocation.
    fn setup_done(w: RawFd) {
        // SAFETY: single bounded write of a const byte to the caller-supplied pipe fd.
        let n = unsafe { nix::libc::write(w, b"1".as_ptr().cast(), 1) };
        // Runs in the forked child: `assert!` would unwind into a copy of the harness's
        // stack, so a failure diverges via `_exit` and surfaces as the parent's read EOF.
        if n != 1 {
            unsafe { nix::libc::_exit(97) };
        }
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

    /// **D0-R3-01 — the exit code actually discriminates.**
    ///
    /// Makes the *absence* of 98 load-bearing in the test above: unless a failed write really
    /// produces exactly 98, asserting 0 there proves nothing. The child closes the channel
    /// before writing, so `signal_ready` fails with `EBADF`.
    #[test]
    fn child_that_cannot_write_the_marker_exits_with_the_distinct_code() {
        let _guard = fork_guard();
        let (_daemon_end, shell_end) = channel_pair();
        let raw = shell_end.as_raw_fd();
        let (pid, _pidfd) = fork_child(move || {
            unsafe { nix::libc::close(raw) };
            if signal_ready(raw).is_err() {
                unsafe { nix::libc::_exit(CHILD_MARKER_WRITE_FAILED) };
            }
        });
        drop(shell_end);
        assert_eq!(
            reap_status(pid),
            CHILD_MARKER_WRITE_FAILED,
            "a failed marker write must be distinguishable from BOTH a clean exit and a \
             signal death"
        );
    }

    /// **D0-R3-03 — the state machine, exercised by INJECTION.** No kernel, no scheduler:
    /// the sequence is the input, so the HUP-without-death window is entered by construction
    /// rather than by the observer happening to be scheduled inside it.
    #[test]
    fn terminal_witness_decides_injected_sequences() {
        use Observation::{Death, Hup, Timeout};
        let run = |seq: &[Observation]| {
            let mut w = TerminalWitness::default();
            seq.iter().find_map(|o| w.observe(*o))
        };

        // Death is conclusive wherever it appears — INCLUDING after a latched HUP, which is
        // the R2-01c defect stated as a sequence.
        assert_eq!(run(&[Death]), Some(Terminal::Dead));
        assert_eq!(run(&[Hup, Death]), Some(Terminal::Dead));
        assert_eq!(run(&[Hup, Hup, Death]), Some(Terminal::Dead), "latch stays monotonic");

        // A liveness claim is only reachable through Timeout — i.e. after the grace.
        assert_eq!(run(&[Hup, Timeout]), Some(Terminal::ChannelClosed));
        assert_eq!(run(&[Timeout]), Some(Terminal::None));

        // HUP alone decides nothing.
        assert_eq!(run(&[Hup]), None, "HUP must not end the witness by itself");
    }

    /// The channel leaves the poll set once HUP latches, or it would report HUP every
    /// iteration and busy-spin out the grace.
    #[test]
    fn latched_hup_removes_the_channel_from_the_poll_set() {
        let mut w = TerminalWitness::default();
        assert!(w.watching_channel());
        assert_eq!(w.observe(Observation::Hup), None);
        assert!(!w.watching_channel());
    }

    /// **D0-R2-01c REGRESSION — the interleaving is FORCED, not sampled.**
    ///
    /// The child closes the channel, sleeps, and only then exits, so `POLLHUP` is
    /// **guaranteed** to be visible strictly before the death. That is the ordering a dying
    /// child produces naturally (fds close before the pidfd signals), made deterministic.
    ///
    /// An implementation that returns on the first `POLLHUP` calls this an alive-shell
    /// protocol fault; the death arriving inside the grace makes it a death. Detects the
    /// defect 20/20, where the naturally-racing keystone managed only 3/12.
    #[test]
    fn channel_closed_then_death_within_grace_is_reported_as_death() {
        let _guard = fork_guard();
        let (daemon_end, shell_end) = channel_pair();
        let raw = shell_end.as_raw_fd();
        let (pid, pidfd) = fork_child(move || {
            unsafe { nix::libc::close(raw) };
            unsafe { nix::libc::usleep(50_000) }; // HUP now; death in 50ms, inside the grace
        });
        drop(shell_end);

        let err = await_shell_ready(daemon_end.as_fd(), pidfd.as_fd(), Duration::from_secs(5))
            .expect_err("a child that closed the channel and then died is dead");
        assert!(
            matches!(err, RuntimeError::ShellDiedBeforeReady),
            "a death arriving within the grace must outrank the earlier HUP, got: {err}"
        );
        kill_and_reap(pid);
    }

    /// **D0-R2-01 REGRESSION — forces the interleaving rather than sampling it.**
    ///
    /// The child writes the marker and exits IMMEDIATELY, with no barrier, so the death is
    /// in flight while the parent is deciding. Measured against the pre-fix code (which
    /// reused the pre-`read` `revents`): **83/100 wrongly accepted**. The fix must be
    /// deterministic, so this asserts 0 over N — a rate, but of a FORCED interleaving, not
    /// of sampled schedules (DEFECT_CLASSES 22).
    #[test]
    fn marker_then_immediate_exit_is_never_accepted() {
        const N: usize = 50;
        let mut accepted = 0;
        for _ in 0..N {
            let _g = fork_guard();
            let (daemon_end, shell_end) = channel_pair();
            let raw = shell_end.as_raw_fd();
            let (pid, pidfd) = fork_child(move || {
                // NOT `expect`: a panic here unwinds into a forked copy of the harness stack
                // (the post-fork contract), and worse, the parent would read the resulting
                // death as the Err it is expecting — a green proof with no marker written.
                if signal_ready(raw).is_err() {
                    unsafe { nix::libc::_exit(CHILD_MARKER_WRITE_FAILED) };
                }
                // exit immediately: no sleep, no barrier — the death races the decision
            });
            drop(shell_end);
            if await_shell_ready(daemon_end.as_fd(), pidfd.as_fd(), Duration::from_secs(2)).is_ok()
            {
                accepted += 1;
            }
            // EXACTLY 0: the child reached the end of its body, so the marker WAS written.
            // `!= 98` would accept a SIGSEGV before `signal_ready` ever ran.
            assert_eq!(
                reap_status(pid),
                0,
                "the child did not exit cleanly, so this iteration proved nothing about a \
                 marker that may never have been written"
            );
        }
        assert_eq!(accepted, 0, "a shell that signalled and died was accepted {accepted}/{N}");
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
            signal_ready(shell_raw).expect("signal_ready");
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
            signal_ready(shell_raw).expect("signal_ready");
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
            signal_ready(shell_raw).expect("signal_ready");
            unsafe { nix::libc::close(shell_raw) };
            setup_done(sync);
            unsafe { nix::libc::sleep(5) };
        });
        drop(shell_end);

        wait_for_hup(daemon_end.as_fd(), Duration::from_secs(5));

        let err = await_shell_ready(daemon_end.as_fd(), pidfd.as_fd(), Duration::from_secs(5))
            .expect_err("a shell that closed the consent channel is not ready, alive or not");
        // The PROPERTY (not ready) is unchanged; only the DIAGNOSIS is corrected. This shell
        // is demonstrably running, so reporting `ShellDiedBeforeReady` was the same
        // misdiagnosis R1-06 fixed one branch over — a live process named as a crash.
        assert!(
            matches!(err, RuntimeError::Protocol(_)),
            "a shell that is ALIVE must not be diagnosed as dead, got: {err}"
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
