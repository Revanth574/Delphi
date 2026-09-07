// SPDX-License-Identifier: MIT

//! Bounded child shutdown — the daemon's exit policy, extracted so it can be tested.
//!
//! # Why this module exists (D0A-R28-02, unexercised through D0A-R29)
//!
//! The daemon's exit path did an unconditional blocking `waitpid` on **both** children, one of
//! them the **untrusted AI**. An AI that takes its terminal response and simply does not exit
//! held the ROOT daemon forever — so "B1 services one action and exits" was a property that
//! depended on the AI's cooperation, the one thing this boundary refuses to depend on anywhere
//! else.
//!
//! The fix (grace → `SIGKILL` → bounded reap) lived inline in `main` for two rounds and was
//! **never executed at root and never covered by any test**:
//!
//! * its only root exercise, `b1_daemon_binary_runs_the_assembled_flow`, SKIPS on the
//!   development lane for want of `--features insecure-test-seams`;
//! * and even unskipped, `delphi-minimal-ai` **cooperates** — it returns after its terminal
//!   response — so the `SIGKILL` branch is never taken;
//! * D0A-R29-05 then *modified* that same untested path. **A change to untested code does not
//!   become tested by being changed.**
//!
//! # The extraction's one condition
//!
//! `main` must call **this** implementation, not a copy of it. A duplicate is the failure mode
//! that makes an extraction *look* done while the shipping path stays untested — the tests
//! would exercise a faithful reproduction of logic nobody runs.
//!
//! That is enforced, not asserted: [`tests::the_daemon_delegates_shutdown_and_does_not_reap_by_hand`]
//! reads `bin/delphi-runtimed.rs` and requires that it calls [`shutdown_all`] and contains **no
//! reaping or signalling primitives of its own**. See that test for what it does and does not
//! prove.

use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

/// Poll interval while waiting for a corpse. Matches `launcher`'s.
const POLL: Duration = Duration::from_millis(10);

/// What became of one child.
///
/// Distinguishing these is the point: the previous inline version discarded the `kill` result
/// and the post-kill reap result, so a child left in uninterruptible sleep was indistinguishable
/// from a clean exit (D0A-R29-05).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildOutcome {
    /// Exited on its own within the grace period. **The status is preserved** — a shutdown
    /// policy that discards it cannot tell a clean exit from a crash.
    Exited { code: i32 },
    /// Died of a signal within the grace period.
    Signaled { signal: i32 },
    /// Nothing outstanding to reap (`ECHILD`) — already reaped, or never ours.
    AlreadyGone,
    /// Outlived the grace period, was `SIGKILL`ed, and was then reaped.
    Terminated,
    /// Outlived the grace period and was **not reaped even after `SIGKILL`** — typically
    /// uninterruptible sleep. `kill_error` is `Some` if the signal itself failed.
    Unreaped { kill_error: Option<String> },
}

impl ChildOutcome {
    /// Did cleanup succeed for this child?
    ///
    /// `Terminated` counts as success: the child is gone and reaped, which is the property
    /// cleanup owes. Only [`Unreaped`](Self::Unreaped) is a failure.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        !matches!(self, Self::Unreaped { .. })
    }
}

/// What a bounded wait actually learned. **Distinct outcomes, because collapsing them is what
/// D0A-R30-02 was** — see [`shutdown_child`].
#[derive(Debug)]
enum Waited {
    /// The child reached a terminal state and THIS call consumed it.
    Terminal(WaitStatus),
    /// `ECHILD` — there was nothing outstanding. Someone else reaped it, or it was never ours.
    /// **Not an exit status, and must never be fabricated into one.**
    Absent,
    /// Still alive when the deadline passed.
    Timeout,
    /// The wait itself failed.
    Failed,
}

/// Reap `pid` within `timeout`, **preserving the terminal status**.
///
/// # D0A-R30-02: this is the ONLY status-consuming wait, and that is the fix
///
/// There used to be two. A separate `already_gone()` helper called `waitpid(WNOHANG)` purely to
/// classify — but `waitpid` **CONSUMES** a terminal status, so for a child that had already
/// exited it reaped the corpse, **discarded the status**, and returned "not gone". The real
/// wait then received `ECHILD`, which was fabricated into `Exited(pid, 0)`.
///
/// Measured, deterministically, by establishing the terminal state with `waitid(WNOWAIT)` first:
/// an `exit 7` child returned `Exited { code: 0 }` and a **SIGTERM death** also returned
/// `Exited { code: 0 }`. The one property the extraction was built to preserve — a cooperating
/// child's exit status — was destroyed by the classifier standing in front of it.
///
/// `a_cooperating_child_is_reaped_within_grace_with_its_status_preserved` passed anyway,
/// because the child is usually still running when the classifier looks. **It passed on
/// scheduling, not on correctness** (Iron Law #15 clause 2: green from a test that never bit).
///
/// `EINTR` is retried against the same deadline. Non-terminal statuses (`Stopped`, `Continued`)
/// are not reaps — counting a stopped child as gone let one escape with its PAM session
/// (D0-R4-02).
fn wait_within(pid: i32, timeout: Duration) -> Waited {
    if pid <= 0 {
        // D0A-R7-07: `waitpid` reads 0 as "any child in my process group" and -1 as ANY child.
        return Waited::Failed;
    }
    let deadline = Instant::now() + timeout;
    loop {
        match nix::sys::wait::waitpid(Pid::from_raw(pid), Some(WaitPidFlag::WNOHANG)) {
            Ok(s @ (WaitStatus::Exited(..) | WaitStatus::Signaled(..))) => {
                return Waited::Terminal(s)
            }
            Err(nix::errno::Errno::ECHILD) => return Waited::Absent,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => return Waited::Failed,
            Ok(_) => {
                if Instant::now() >= deadline {
                    return Waited::Timeout;
                }
                std::thread::sleep(POLL);
            }
        }
    }
}

/// Shut one child down: wait `grace`, then `SIGKILL`, then wait `post_kill`.
///
/// Every wait is BOUNDED. Restoring an unbounded wait to obtain certainty is the defect
/// D0A-R28-02 closed — a wedged root daemon is worse than a logged unreaped child.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
/// use delphi_runtime::shutdown::{shutdown_child, ChildOutcome};
/// let outcome = shutdown_child(4242, Duration::from_secs(5), Duration::from_secs(2));
/// assert!(outcome.is_clean() || matches!(outcome, ChildOutcome::Unreaped { .. }));
/// ```
#[must_use]
pub fn shutdown_child(pid: i32, grace: Duration, post_kill: Duration) -> ChildOutcome {
    // D0A-R7-07, AND THIS GUARD WAS MISSING FROM THE FIRST DRAFT. `kill(0, ..)` signals THE
    // ENTIRE PROCESS GROUP and `kill(-1, ..)` every signallable process. The wait side guarded
    // `pid <= 0` and fell straight through to the `kill` —
    // `non_positive_pids_are_refused_rather_than_signalling_a_group` demonstrated it by
    // SIGKILLing the test runner (exit 137). A guard on the WAIT side is not a guard on the
    // SIGNAL side; they are separate reachable arguments.
    if pid <= 0 {
        return ChildOutcome::Unreaped {
            kill_error: Some(format!(
                "refusing to shut down pid {pid}: 0 means the process group and -1 means every \
                 signallable process (D0A-R7-07)"
            )),
        };
    }
    // ONE status-consuming wait (D0A-R30-02). No classifier in front of it.
    match wait_within(pid, grace) {
        Waited::Terminal(WaitStatus::Exited(_, code)) => return ChildOutcome::Exited { code },
        Waited::Terminal(WaitStatus::Signaled(_, sig, _)) => {
            return ChildOutcome::Signaled { signal: sig as i32 }
        }
        Waited::Terminal(_) => return ChildOutcome::AlreadyGone,
        Waited::Absent => return ChildOutcome::AlreadyGone,
        Waited::Failed => {
            return ChildOutcome::Unreaped {
                kill_error: Some(format!("wait on pid {pid} failed")),
            }
        }
        Waited::Timeout => {}
    }
    // Outlived the grace period.
    let kill_error = match kill(Pid::from_raw(pid), Signal::SIGKILL) {
        Ok(()) => None,
        // ESRCH means it died between the wait and the signal — not a failure.
        Err(nix::errno::Errno::ESRCH) => None,
        Err(e) => Some(e.to_string()),
    };
    match wait_within(pid, post_kill) {
        // Gone one way or another. `Absent` here means someone else reaped it; either way the
        // child is not outstanding, which is what cleanup owes.
        Waited::Terminal(_) | Waited::Absent => ChildOutcome::Terminated,
        Waited::Timeout | Waited::Failed => ChildOutcome::Unreaped { kill_error },
    }
}

/// Shut every child down **independently**, returning each one's outcome.
///
/// Independently matters: one child stuck in uninterruptible sleep must not prevent the other
/// from being reaped, and the caller must be able to name WHICH failed.
#[must_use]
pub fn shutdown_all(
    children: &[(&'static str, i32)],
    grace: Duration,
    post_kill: Duration,
) -> Vec<(&'static str, ChildOutcome)> {
    children
        .iter()
        .map(|&(what, pid)| (what, shutdown_child(pid, grace, post_kill)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    /// Spawn a child that sleeps `secs` and never cooperates.
    fn sleeper(secs: u32) -> i32 {
        Command::new("sleep")
            .arg(secs.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleeper")
            .id() as i32
    }

    /// Spawn a child that exits promptly with `code`.
    fn quick_exit(code: u8) -> i32 {
        Command::new("sh")
            .arg("-c")
            .arg(format!("exit {code}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn")
            .id() as i32
    }

    /// Block until `pid` is terminal WITHOUT consuming its status (`waitid(WNOWAIT)`).
    ///
    /// This is what makes the two tests below deterministic rather than racy: the child is
    /// KNOWN dead and KNOWN still reapable when `shutdown_child` is called, which is exactly
    /// the state D0A-R30-02 mishandled and exactly the state a spawn-then-call test reaches
    /// only by luck.
    fn await_terminal_without_reaping(pid: i32) {
        // SAFETY: `waitid` writes a `siginfo_t` this frame owns and fully initialises; WNOWAIT
        // leaves the child reapable so the code under test still sees a terminal status.
        unsafe {
            let mut si: nix::libc::siginfo_t = std::mem::zeroed();
            nix::libc::waitid(
                nix::libc::P_PID,
                pid as nix::libc::id_t,
                &mut si,
                nix::libc::WEXITED | nix::libc::WNOWAIT,
            );
        }
    }

    /// D0A-R30-02 — an ALREADY-DEAD child's exit code survives, deterministically.
    ///
    /// The previous version of this property spawned a child and called `shutdown_child`
    /// immediately, so the child was usually still RUNNING and the defect was skipped. Here the
    /// child is established terminal-but-unreaped first, which is the state that broke:
    /// `already_gone()`'s classifying `waitpid` consumed the status, discarded it, and the real
    /// wait then turned `ECHILD` into `Exited { code: 0 }`.
    ///
    /// Measured against the pre-fix module: `exit 7` → `Exited { code: 0 }`.
    #[test]
    fn an_already_dead_childs_exit_code_survives_shutdown() {
        let pid = quick_exit(7);
        await_terminal_without_reaping(pid);
        assert_eq!(
            shutdown_child(pid, Duration::from_secs(2), Duration::from_secs(2)),
            ChildOutcome::Exited { code: 7 },
            "the exit status was destroyed by a classifier in front of the real wait — the one \
             property this module exists to preserve (D0A-R30-02)"
        );
    }

    /// D0A-R30-02 — a child that DIED OF A SIGNAL is not reported as a clean exit.
    ///
    /// The sharper half: the pre-fix module returned `Exited { code: 0 }` for a SIGTERM death,
    /// so a killed child and a successful one were the same event. A shutdown policy that
    /// cannot tell those apart cannot report anything useful about cleanup.
    #[test]
    fn a_child_that_died_of_a_signal_is_not_reported_as_a_clean_exit() {
        let pid = Command::new("sh")
            .arg("-c")
            .arg("kill -TERM $$")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn")
            .id() as i32;
        await_terminal_without_reaping(pid);
        match shutdown_child(pid, Duration::from_secs(2), Duration::from_secs(2)) {
            ChildOutcome::Signaled { signal } => assert_eq!(
                signal,
                nix::libc::SIGTERM,
                "reported the wrong signal"
            ),
            other => panic!(
                "a SIGTERM death reported as {other:?} — pre-fix this was Exited{{code:0}}, \
                 making a killed child indistinguishable from a successful one (D0A-R30-02)"
            ),
        }
    }

    /// CASE 1 — a cooperating child is reaped within grace AND ITS EXIT STATUS SURVIVES.
    ///
    /// The inline version returned only "gone", so a clean exit and a crash were the same
    /// event to the shutdown policy.
    #[test]
    fn a_cooperating_child_is_reaped_within_grace_with_its_status_preserved() {
        let pid = quick_exit(7);
        let out = shutdown_child(pid, Duration::from_secs(5), Duration::from_secs(2));
        assert_eq!(out, ChildOutcome::Exited { code: 7 }, "exit status must survive shutdown");
        assert!(out.is_clean());
    }

    /// CASE 2 — a child that outlives grace is TERMINATED and reaped.
    ///
    /// This is the branch D0A-R28-02 exists for and that nothing had ever executed: the
    /// untrusted AI that takes its terminal response and stays alive.
    #[test]
    fn a_child_that_outlives_the_grace_period_is_killed_and_reaped() {
        let pid = sleeper(120);
        let started = Instant::now();
        let out = shutdown_child(pid, Duration::from_millis(150), Duration::from_secs(3));
        assert_eq!(out, ChildOutcome::Terminated, "an uncooperative child must be terminated");
        assert!(out.is_clean(), "terminated-and-reaped IS clean cleanup");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "shutdown must be BOUNDED — an unbounded wait here is the wedge R28-02 closed"
        );
    }

    /// CASE 6 — an already-reaped child is `AlreadyGone`, not an error and not a wait.
    #[test]
    fn an_already_reaped_child_is_reported_gone_without_waiting() {
        let pid = quick_exit(0);
        // Reap it out from under the policy.
        let _ = nix::sys::wait::waitpid(Pid::from_raw(pid), None);
        let started = Instant::now();
        assert_eq!(
            shutdown_child(pid, Duration::from_secs(5), Duration::from_secs(2)),
            ChildOutcome::AlreadyGone
        );
        assert!(started.elapsed() < Duration::from_secs(1), "must not wait on a reaped child");
    }

    /// CASE 4 — a pid that is not ours: signalling cannot succeed and shutdown still returns.
    ///
    /// # This test used pid 1, and that was safe unprivileged and reckless at root
    ///
    /// `already_gone(1)` returns `ECHILD` before the `kill` is reached, so the signal is
    /// unreachable and the test passed. But the CONSEQUENCE of being wrong is not
    /// lane-independent: unprivileged, a stray `kill(1, SIGKILL)` fails `EPERM` and nothing
    /// happens; **as root it is permitted, and pid 1 is init.** Lane run 19 is the first time
    /// this suite runs where that mistake ends the machine rather than the test.
    ///
    /// So the fixture is now a pid that CANNOT be live: `pid_max`, which the kernel documents
    /// as one greater than the maximum allocatable pid. `waitpid` still gives `ECHILD` — the
    /// property under test is unchanged — while a stray signal would be `ESRCH` at any
    /// privilege level. **Changed BEFORE the root run, not after it**, because the reasoning
    /// that says the kill is unreachable is the same reasoning that would have to be wrong for
    /// it to matter, and a test should not stake a machine on its own correctness.
    #[test]
    fn a_pid_that_is_not_our_child_terminates_the_policy_promptly() {
        let pid_max: i32 = std::fs::read_to_string("/proc/sys/kernel/pid_max")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(4_194_304);
        // PRECONDITION: it must not exist. `kill(pid, 0)` probes without signalling.
        assert!(
            nix::sys::signal::kill(Pid::from_raw(pid_max), None).is_err(),
            "fixture pid {pid_max} is LIVE — pick another; this test must never name a real \
             process, least of all at root"
        );
        let started = Instant::now();
        let out = shutdown_child(pid_max, Duration::from_millis(100), Duration::from_millis(100));
        assert_eq!(out, ChildOutcome::AlreadyGone);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// Guard on the pid argument itself (D0A-R7-07): 0 means "my process group" and -1 means
    /// ANY child. Neither may be shut down by accident.
    #[test]
    fn non_positive_pids_are_refused_rather_than_signalling_a_group() {
        for pid in [0, -1] {
            let out = shutdown_child(pid, Duration::from_millis(50), Duration::from_millis(50));
            match out {
                ChildOutcome::Unreaped { kill_error: Some(ref m) } => assert!(
                    m.contains("D0A-R7-07"),
                    "refused, but not by the non-positive-pid guard: {m}"
                ),
                other => panic!(
                    "pid {pid} produced {other:?} — it must be REFUSED before any kill. On the \
                     first draft this reached `kill(0, SIGKILL)` and killed the test runner's \
                     entire process group (exit 137)."
                ),
            }
        }
    }

    /// CASE 7 — children are shut down INDEPENDENTLY and each outcome is named.
    ///
    /// One uncooperative child must not prevent the other from being reaped, and the caller
    /// must be able to say WHICH failed — the inline version could only say "something".
    #[test]
    fn children_are_shut_down_independently_and_each_outcome_is_attributed() {
        let cooperative = quick_exit(0);
        let stubborn = sleeper(120);
        let outcomes = shutdown_all(
            &[("cooperative", cooperative), ("stubborn", stubborn)],
            Duration::from_millis(150),
            Duration::from_secs(3),
        );
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].0, "cooperative");
        assert_eq!(outcomes[0].1, ChildOutcome::Exited { code: 0 });
        assert_eq!(outcomes[1].0, "stubborn");
        assert_eq!(outcomes[1].1, ChildOutcome::Terminated);
        assert!(outcomes.iter().all(|(_, o)| o.is_clean()));
    }

    /// `is_clean` is the predicate `main` branches on, so its boundary is asserted directly.
    #[test]
    fn only_an_unreaped_child_counts_as_failed_cleanup() {
        assert!(ChildOutcome::Exited { code: 0 }.is_clean());
        assert!(ChildOutcome::Exited { code: 9 }.is_clean(), "a nonzero exit is still reaped");
        assert!(ChildOutcome::Signaled { signal: 9 }.is_clean());
        assert!(ChildOutcome::AlreadyGone.is_clean());
        assert!(ChildOutcome::Terminated.is_clean(), "killed-and-reaped is clean");
        assert!(!ChildOutcome::Unreaped { kill_error: None }.is_clean());
        assert!(!ChildOutcome::Unreaped { kill_error: Some("EPERM".into()) }.is_clean());
    }

    /// **THE EXTRACTION'S CONDITION: `main` calls THIS, not a copy of it.**
    ///
    /// A duplicate is the failure mode that makes an extraction *look* done — the tests above
    /// would exercise a faithful reproduction of logic the daemon does not run, which is
    /// exactly the position D0A-R28-02 was already in.
    ///
    /// **What this proves:** `delphi-runtimed.rs` invokes [`shutdown_all`] and contains no
    /// reaping or signalling primitive of its own, so it cannot be carrying a second copy of
    /// the policy.
    ///
    /// **What it does NOT prove:** that the call is on the path taken after a terminal outcome
    /// — that is assembly coverage, and it is owed (the reviewer named it separately). A
    /// source-level check is a weak instrument in general (`DEFECT_CLASSES` 41); it is used
    /// here because the property is exactly "these tokens do not appear", which is the one
    /// shape a source check answers precisely.
    #[test]
    fn the_daemon_delegates_shutdown_and_does_not_reap_by_hand() {
        let src = include_str!("bin/delphi-runtimed.rs");
        assert!(
            src.contains("shutdown_all("),
            "the daemon must CALL the extracted policy; if this fails the extraction is \
             decorative and the shipping path is still untested"
        );
        for primitive in ["waitpid(", "reap_within(", "Signal::SIGKILL"] {
            assert!(
                !src.contains(primitive),
                "delphi-runtimed.rs still calls `{primitive}` directly — it is carrying its own \
                 copy of the shutdown policy, so the tests in this module exercise logic the \
                 daemon does not run (D0A-R28-02)"
            );
        }
    }
}
