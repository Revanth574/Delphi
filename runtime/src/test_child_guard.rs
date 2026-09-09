// SPDX-License-Identifier: MIT

//! RAII cleanup for forked children in unit tests (D0-R4-05).
//!
//! # If this module is ever compiled into a non-test build
//!
//! It is behind the `test-fixtures` feature so integration-test crates can reach it —
//! `#[cfg(test)]` items are invisible across crate boundaries, which is why the first version
//! did not cover `runtime/tests/*` at all (D0-R5-05).
//!
//! **If the feature were accidentally enabled in a production build, this module does
//! nothing**: it defines a type that nothing in `src/bin` or the library path constructs, so
//! no `Drop` is ever registered and no signal is ever sent. It is inert, not dormant. That is
//! deliberately weaker than the `insecure-test-seams` precedent — that feature opens a
//! gate-bypass and therefore carries an installer pre-flight check that production binaries do
//! not ship it. A cleanup helper with no constructor on any production path needs no such
//! check, and adding one would imply a hazard that does not exist.
//!
//! # Why this is a type and not a rule
//!
//! A `pause()`ing child that outlives a failed assertion holds cargo's captured stdout/stderr
//! open, so the harness never sees EOF and **wedges instead of reporting the failure**. A test
//! whose failure mode is a hang cannot be used as evidence — it is neither a pass nor a fail,
//! the worst case of Iron Law 15 clause 2.
//!
//! The first response was to clean up before asserting at the one site that hit it. Three more
//! sites carried the same shape, and a fourth was introduced while fixing something else — the
//! signature of a rule (`DEFECT_CLASSES` 17). Arming this guard immediately after a `fork`
//! makes cleanup structural: it runs on the panic path because `Drop` runs while unwinding.

use nix::unistd::Pid;

/// Kills and reaps a forked test child on drop, however the test exits.
///
/// Arm it on the line after `fork()` returns in the parent. Do not defer it past an assertion:
/// deferring is precisely what fails, because the assertion is what diverges.
pub struct ChildGuard {
    pid: Pid,
    armed: bool,
}

/// The machine-readable marker every PRECONDITION failure carries (D0A-R31-06).
///
/// A precondition failure means **the environment was wrong**, not that a mutation was caught
/// or a regression found. The mutation campaign classified these by matching PROSE — a list
/// that missed "could not run <script>", so a failure to even LAUNCH the stale-session checker
/// was scored as a detection. An indefinitely-extended prose list is class 48 by construction:
/// each new phrasing is a new instance to discover.
///
/// One token, emitted by every site, matched by the classifier. New precondition messages are
/// covered the moment they carry it.
pub const PRECONDITION_TOKEN: &str = "DELPHI_PRECONDITION_FAILED";

impl ChildGuard {
    /// Guard `pid` until this value drops.
    pub fn arm(pid: Pid) -> Self {
        Self { pid, armed: true }
    }

    /// Reap now and disarm, for a test that needs the child's exit status.
    ///
    /// Returns the exit code, or `-signal` if it died of one.
    /// D0A-R29-06: **disarm only after a TERMINAL status.** This used to disarm first, so an
    /// EINTR from `waitpid` panicked with the guard already disabled and `Drop` did nothing —
    /// leaking the child. In tests whose children inherit the capture pipes, that turns a
    /// failure into a HUNG HARNESS, which is the exact scenario this guard exists to prevent.
    /// A signal-injection probe reproduced it: `panicked=true, child after drop=StillAlive`.
    ///
    /// `EINTR` is retried rather than treated as terminal — it says nothing about the child.
    /// Non-terminal statuses (`Stopped`, `Continued`, `PtraceEvent`) are also retried, for the
    /// D0-R4-02 reason: counting a stopped child as reaped let one escape with its PAM session.
    pub fn reap_status(mut self) -> i32 {
        loop {
            match nix::sys::wait::waitpid(self.pid, None) {
                Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => {
                    self.armed = false;
                    return code;
                }
                Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => {
                    self.armed = false;
                    return -(sig as i32);
                }
                Err(nix::errno::Errno::EINTR) => continue,
                // A live child changing state is not a reap. Keep waiting, keep the guard
                // ARMED so a panic below still cleans up.
                Ok(nix::sys::wait::WaitStatus::Stopped(..))
                | Ok(nix::sys::wait::WaitStatus::Continued(_)) => continue,
                other => panic!(
                    "unexpected wait status for {}: {other:?} (guard remains ARMED, so Drop \
                     will still clean up — D0A-R29-06)",
                    self.pid
                ),
            }
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // SAFETY: signalling a child this process forked and has not reaped, so its pid is
        // still reserved by its own table entry.
        unsafe { nix::libc::kill(self.pid.as_raw(), nix::libc::SIGKILL) };
        let _ = nix::sys::wait::waitpid(self.pid, None);
    }
}

/// Assert no previous run's session still holds `vt` — a PER-TEST ENTRY assertion (D0-R6-11).
///
/// # Why per-test and not once before the run
///
/// A go/no-go check cannot see mid-run leakage by construction, and running it more often at
/// that level does not help: mid-run session *creation* is normal (every `launch()` opens
/// one); mid-run *leakage* is the hazard. When one test's teardown fails, every later test
/// dies at `pam_open_session` with `VirtualTerminalAlreadyTaken` — a message naming neither
/// the cause nor the culprit. That is the 9-consecutive-failures shape.
///
/// Called at test entry, this attributes the failure to the PREVIOUS test, at the point of
/// entry, by name. It shells out to `scripts/check-stale-test-sessions.sh --vt` rather than
/// reimplementing the query: the last checker's defect was two callers with divergent
/// assumptions, so there is exactly one construction site.
///
/// # Panics
///
/// If a stale session holds `vt`, or if the checker cannot determine the answer — it fails
/// closed, and so does this.
pub fn assert_no_stale_session_on(vt: &str) {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../scripts/check-stale-test-sessions.sh");
    let out = match std::process::Command::new(script).args(["--vt", vt]).output() {
        Ok(o) => o,
        Err(e) => panic!(
            "{PRECONDITION_TOKEN}: could not run {script}: {e} — the environment is UNKNOWN, \
             not clean"
        ),
    };
    assert!(
        out.status.success(),
        "{PRECONDITION_TOKEN}: before this test ran — a session is live on {vt}. \
         DO NOT assume a PREVIOUS test left it (D0A-R4-07): a daemon spawned by THIS run \
         can create one and outlive the test that spawned it. Check `ps -ef | grep \
         delphi-runtimed` for a live ROOT daemon before blaming an earlier test — four \
         orphaned root daemons once presented exactly this way, one per attempt.\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A temp dir whose cleanup FAILURE is reported (D0-R7-07).
///
/// # Why a reporting Drop rather than an explicit `TempDir::close()`
///
/// `close()` returns a `Result` and is the stronger check — but it only runs on the path
/// where it is called, i.e. the success path, and putting it before a test's assertions is
/// exactly the cleanup-before-assert ordering that once left a `pause()`ing child holding
/// cargo's capture pipes and WEDGED the harness. Twenty-plus call sites each needing it as
/// the last statement is a rule that will be forgotten, and forgotten silently.
///
/// So the removal is attempted on **every** path, including panics, and a failure is
/// **reported** rather than discarded — which is what `DEFECT_CLASSES` 31 requires ("a
/// teardown that can fail must report its failure"). `TempDir`'s own `Drop` discards the
/// error; that discard is the whole defect.
pub struct ReportingTempDir(Option<tempfile::TempDir>);

impl ReportingTempDir {
    /// Wrap a `TempDir` so its removal failure becomes visible.
    #[must_use]
    pub fn new(inner: tempfile::TempDir) -> Self {
        Self(Some(inner))
    }

    /// The path, for handing to the code under test.
    ///
    /// # Panics
    ///
    /// If called after the value was consumed — a programming error.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        self.0.as_ref().expect("ReportingTempDir used after close").path()
    }
}

/// Decide whether a failed `TempDir::close` is a LEAK, separated from the `Drop` so it is
/// provable without arranging a real teardown failure (D0A whole-suite root run).
///
/// **`NotFound` is not a leak — it is the desired end state reached by another route.** The
/// root run reported `/run/delphi-b1-…` and `/run/delphi-e2e-…` as LEAKED with
/// `No such file or directory`: the directories were already gone. A teardown guard that
/// warns on its own success path is worse than one that says nothing, because it trains the
/// reader to skip the warning that matters — the same dynamic as a flaky test.
#[must_use]
pub fn leak_report(err: &std::io::Error, path: &std::path::Path) -> Option<String> {
    if err.kind() == std::io::ErrorKind::NotFound {
        return None;
    }
    Some(format!(
        "WARN: could not remove the temp dir {} — it has LEAKED: {err}. \
         Left unreported this is DEFECT_CLASSES 31 (a teardown whose failure is \
         unobservable); reported, it is a fact you can act on.",
        path.display()
    ))
}

impl Drop for ReportingTempDir {
    fn drop(&mut self) {
        if let Some(inner) = self.0.take() {
            let p = inner.path().to_path_buf();
            if let Err(e) = inner.close()
                && let Some(msg) = leak_report(&e, &p)
            {
                eprintln!("{msg}");
            }
        }
    }
}

#[cfg(test)]
mod leak_report_tests {
    use super::leak_report;
    use std::io::{Error, ErrorKind};
    use std::path::Path;

    /// Both directions, because either alone is satisfiable by a constant.
    #[test]
    fn an_already_removed_dir_is_not_a_leak_and_a_busy_one_is() {
        let p = Path::new("/run/delphi-b1-Yo7srF");
        assert!(
            leak_report(&Error::new(ErrorKind::NotFound, "No such file or directory"), p).is_none(),
            "NotFound means the directory is GONE, which is what teardown is for. The root run \
             reported exactly this as a LEAK for two directories that had already been removed."
        );
        let busy = leak_report(&Error::from_raw_os_error(nix::libc::EBUSY), p)
            .expect("a genuine removal failure MUST still be reported");
        assert!(busy.contains("LEAKED") && busy.contains("delphi-b1-Yo7srF"), "{busy}");
    }
}

#[cfg(test)]
mod eintr_tests {
    use super::ChildGuard;
    use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};
    use nix::unistd::Pid;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    static DELIVERED: AtomicUsize = AtomicUsize::new(0);

    /// Stops the sender and restores the handler on EVERY path, including unwinding.
    ///
    /// The order is load-bearing: the sender must be stopped and JOINED before the handler is
    /// restored, or a signal already in flight can arrive under the previous disposition —
    /// which for SIGUSR1 is `SIG_DFL`, i.e. it terminates the test process.
    struct SenderGuard {
        stop: Arc<AtomicBool>,
        hammer: Option<std::thread::JoinHandle<()>>,
        previous: SigAction,
    }

    impl Drop for SenderGuard {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(h) = self.hammer.take() {
                let _ = h.join();
            }
            // SAFETY: restoring the disposition captured before this test installed its own,
            // and only after the sender is provably stopped.
            unsafe { sigaction(Signal::SIGUSR1, &self.previous) }.expect("restore SIGUSR1");
        }
    }

    /// Async-signal-safe: one relaxed atomic add and nothing else.
    extern "C" fn on_usr1(_: nix::libc::c_int) {
        DELIVERED.fetch_add(1, Ordering::Relaxed);
    }

    /// D0A-R29-06 shipped the EINTR retry WITHOUT a test, and the extraction of `shutdown.rs`
    /// did not move this function, so it stayed uncovered for three rounds. The reviewer
    /// reproduced the pre-fix failure with an external probe; by this project's own rule an
    /// unretained probe is not coverage, so the condition is constructed here.
    ///
    /// **How the interruption is made to happen rather than hoped for:** the handler is
    /// installed with `SaFlags::empty()` — SA_RESTART deliberately ABSENT, because with it the
    /// kernel restarts `waitpid` transparently and `EINTR` never reaches the code under test.
    /// Signals are then delivered with `pthread_kill` to *this* thread, the one blocked in
    /// `waitpid`, rather than to the process, where any thread could take them.
    ///
    /// **What proves the condition was reached, rather than merely that the test passed:** the
    /// weaken. Deleting `Err(EINTR) => continue` makes this test panic in the catch-all arm. If
    /// no interruption occurred, deleting the retry would change nothing and the weaken would
    /// pass — so the RED is the evidence, not the green.
    #[test]
    fn reap_status_retries_a_waitpid_interrupted_by_a_signal() {
        let act = SigAction::new(SigHandler::Handler(on_usr1), SaFlags::empty(), SigSet::empty());
        // SAFETY: installing a handler that only performs one relaxed atomic increment. The
        // previous disposition is restored before the test returns.
        let previous = unsafe { sigaction(Signal::SIGUSR1, &act) }.expect("install SIGUSR1");

        let child = std::process::Command::new("sh")
            .arg("-c")
            .arg("sleep 1; exit 7")
            .spawn()
            .expect("spawn the child to be reaped");
        #[allow(clippy::cast_possible_wrap)]
        let pid = Pid::from_raw(child.id() as i32);
        // The guard owns the reap from here; `Child` must not also wait for it.
        std::mem::forget(child);
        let guard = ChildGuard::arm(pid);

        let before = DELIVERED.load(Ordering::Relaxed);
        // `libc` directly rather than `nix::sys::pthread`, which would need a nix feature
        // added to the crate's dependencies for a test-only call. `pthread_t` is an integer
        // handle and is Send.
        // SAFETY: `pthread_self` takes no arguments and cannot fail.
        let target = unsafe { nix::libc::pthread_self() };
        let stop = Arc::new(AtomicBool::new(false));
        let stop_tx = Arc::clone(&stop);
        let hammer = std::thread::spawn(move || {
            while !stop_tx.load(Ordering::Relaxed) {
                // SAFETY: signalling a thread of this process that is live for the whole
                // loop — `hammer` is joined before the test returns.
                unsafe { nix::libc::pthread_kill(target, nix::libc::SIGUSR1) };
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        });

        // UNWIND-SAFE (D0A-R33-02). `reap_status` is the call under test and it PANICS when
        // the retry is deleted — which is the weaken this test exists to fail under. Stopping
        // the sender only on the normal path meant the RED path left a thread signalling
        // SIGUSR1 into a process whose handler had just been restored to its previous
        // disposition, and left it running past this test's lifetime. The cleanup a test needs
        // most is the cleanup on the path where it fails.
        let code = {
            let sender = SenderGuard { stop: Arc::clone(&stop), hammer: Some(hammer), previous };
            let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                guard.reap_status()
            }));
            drop(sender); // stops, joins, THEN restores — in that order, on both paths
            match code {
                Ok(c) => c,
                Err(payload) => std::panic::resume_unwind(payload),
            }
        };

        assert_eq!(
            code, 7,
            "the child's real exit status must survive the interruptions; EINTR says nothing \
             about the child and must not be reported as its outcome (D0A-R29-06)"
        );
        assert!(
            DELIVERED.load(Ordering::Relaxed) > before,
            "no SIGUSR1 was delivered at all, so this run exercised nothing — the test would \
             pass with the retry deleted, which is the PASS/PASS case Iron Law 15 clause 2 \
             calls worthless"
        );
    }
}
