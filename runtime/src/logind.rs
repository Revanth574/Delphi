// SPDX-License-Identifier: MIT

//! The logind active-local-session gate (Increment 1c, R3-02).
//!
//! Before minting a consent token, the daemon confirms the approving shell
//! belongs to an **active, local** login session (`docs/TRUST_MODEL.md` §4, R3-02
//! — "the daemon confirms the approving shell belongs to an active, local login
//! session via systemd-logind"). The verdict must come from **logind**, which a
//! same-uid process cannot forge — not from a same-uid-assertable signal.
//!
//! # Fidelity (Iron Law #13)
//!
//! The gate **queries logind directly** via the stable sd-login ABI
//! (`sd_session_is_active`, `sd_session_is_remote`), the highest-fidelity binding
//! — "ask logind", not "parse `loginctl`'s text". We declare the three symbols
//! ourselves and link the system `libsystemd.so.0` by soname (see `build.rs`):
//! the obvious crate, `libsystemd-sys`, is `LGPL-2.1-or-later` (outside
//! `deny.toml`) and needs `libsystemd-dev`, so an own MIT binding keeps both the
//! fidelity and the license clean. A `loginctl`-subprocess parser would be
//! strictly lower fidelity and is deliberately NOT used.
//!
//! # What this proves, and what is deferred
//!
//! The **decision** (`active && !remote`) is unit-testable without a live session
//! ([`session_passes_gate`]). The **logind query** ([`LogindVerdict`]) is proven
//! live where a real session exists (gated). Provisioning a logind session *for a
//! daemon-spawned shell* (via `pam_open_session`/`pam_systemd`) is a **deploy
//! requirement**, documented not faked — WSL2's sessions are ephemeral/seatless.
//! logind-gate-resistance = `(gate trusts logind, RED-proven vs same-uid-signal)
//! + (logind authoritative, deploy-real)`, provisioning deferred.

use std::ffi::{c_char, c_int, CStr, CString};

// SAFETY: the three stable sd-login ABI symbols, resolved from the system
// `libsystemd.so.0` (linked by soname in build.rs). Signatures match
// `sd-login.h`.
unsafe extern "C" {
    fn sd_session_is_active(session: *const c_char) -> c_int;
    fn sd_session_is_remote(session: *const c_char) -> c_int;
    fn sd_pid_get_session(pid: nix::libc::pid_t, session: *mut *mut c_char) -> c_int;
}

/// A session's active/remote verdict — the seam between the **decision** (unit-
/// testable) and its **source** (logind, gated-live; or, in the RED-proof, a
/// same-uid-assertable signal).
pub trait SessionVerdict {
    /// Whether the session is currently active (the foreground session on its seat).
    fn is_active(&self) -> bool;
    /// Whether the session is remote (e.g. SSH) rather than local.
    fn is_remote(&self) -> bool;
}

/// THE DECISION: a session passes the gate iff it is **active AND local**
/// (not remote). Unit-testable without any live session.
#[must_use]
pub fn session_passes_gate(verdict: &impl SessionVerdict) -> bool {
    verdict.is_active() && !verdict.is_remote()
}

/// The **authoritative** verdict: queried directly from logind. A same-uid process
/// cannot make logind report a session as active-and-local when it is not.
pub struct LogindVerdict {
    active: bool,
    remote: bool,
}

impl LogindVerdict {
    /// Query logind for the named session id. Returns `None` if logind does not
    /// know the session (or on error).
    #[must_use]
    pub fn query(session: &str) -> Option<Self> {
        let c = CString::new(session).ok()?;
        // SAFETY: `c` is a valid NUL-terminated string; the calls only read it and
        // return an int (>0 yes, 0 no, <0 error).
        let (a, r) = unsafe {
            (
                sd_session_is_active(c.as_ptr()),
                sd_session_is_remote(c.as_ptr()),
            )
        };
        if a < 0 || r < 0 {
            return None;
        }
        Some(Self { active: a > 0, remote: r > 0 })
    }

    /// Resolve the session owning `pid` (the daemon's pidfd-pinned shell), then
    /// query it. `None` if the pid has no logind session.
    #[must_use]
    pub fn for_pid(pid: i32) -> Option<Self> {
        let mut sess: *mut c_char = std::ptr::null_mut();
        // SAFETY: `sess` receives a malloc'd C string on success (rc >= 0); we copy
        // it out and free it.
        let rc = unsafe { sd_pid_get_session(pid, &mut sess) };
        if rc < 0 || sess.is_null() {
            return None;
        }
        // SAFETY: `sess` is a valid C string allocated by libsystemd.
        let owned = unsafe { CStr::from_ptr(sess) }.to_str().ok().map(str::to_owned);
        // SAFETY: free the libsystemd-allocated string exactly once.
        unsafe { nix::libc::free(sess.cast()) };
        Self::query(&owned?)
    }
}

impl SessionVerdict for LogindVerdict {
    fn is_active(&self) -> bool {
        self.active
    }
    fn is_remote(&self) -> bool {
        self.remote
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mock {
        active: bool,
        remote: bool,
    }
    impl SessionVerdict for Mock {
        fn is_active(&self) -> bool {
            self.active
        }
        fn is_remote(&self) -> bool {
            self.remote
        }
    }

    /// THE DECISION LOGIC (unit, no live session): passes iff active AND local.
    #[test]
    fn gate_passes_only_active_and_local() {
        assert!(session_passes_gate(&Mock { active: true, remote: false }), "active local → pass");
        assert!(!session_passes_gate(&Mock { active: false, remote: false }), "inactive → deny");
        assert!(!session_passes_gate(&Mock { active: true, remote: true }), "remote → deny");
        assert!(!session_passes_gate(&Mock { active: false, remote: true }), "inactive remote → deny");
    }
}
