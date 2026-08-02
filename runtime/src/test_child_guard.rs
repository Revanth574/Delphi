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
