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

impl ChildGuard {
    /// Guard `pid` until this value drops.
    pub fn arm(pid: Pid) -> Self {
        Self { pid, armed: true }
    }

    /// Reap now and disarm, for a test that needs the child's exit status.
    ///
    /// Returns the exit code, or `-signal` if it died of one.
    pub fn reap_status(mut self) -> i32 {
        self.armed = false;
        match nix::sys::wait::waitpid(self.pid, None) {
            Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => code,
            Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => -(sig as i32),
            other => panic!("unexpected wait status for {}: {other:?}", self.pid),
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
        Err(e) => panic!("could not run {script}: {e} — the environment is UNKNOWN, not clean"),
    };
    assert!(
        out.status.success(),
        "PRECONDITION FAILED before this test ran — a previous test leaked a session on {vt}. \
         This test has not started; the fault is upstream.\n{}{}",
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

impl Drop for ReportingTempDir {
    fn drop(&mut self) {
        if let Some(inner) = self.0.take() {
            let p = inner.path().to_path_buf();
            if let Err(e) = inner.close() {
                eprintln!(
                    "WARN: could not remove the temp dir {} — it has LEAKED: {e}. \
                     Left unreported this is DEFECT_CLASSES 31 (a teardown whose failure is \
                     unobservable); reported, it is a fact you can act on.",
                    p.display()
                );
            }
        }
    }
}
