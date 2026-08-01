// SPDX-License-Identifier: MIT

//! RAII cleanup for forked children in unit tests (D0-R4-05).
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
pub(crate) struct ChildGuard {
    pid: Pid,
    armed: bool,
}

impl ChildGuard {
    /// Guard `pid` until this value drops.
    pub(crate) fn arm(pid: Pid) -> Self {
        Self { pid, armed: true }
    }

    /// Reap now and disarm, for a test that needs the child's exit status.
    ///
    /// Returns the exit code, or `-signal` if it died of one.
    pub(crate) fn reap_status(mut self) -> i32 {
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
