// SPDX-License-Identifier: MIT

//! The logind active-local-**seated** session gate (Increment 1c R3-02; tightened in B2a).
//!
//! Before minting a consent token, the daemon confirms the approving shell belongs to
//! an **active, local, seated** login session (`docs/TRUST_MODEL.md` §4, R3-02 — "the
//! daemon confirms the approving shell belongs to an active, local login session via
//! systemd-logind"). The verdict must come from **logind**, which a same-uid process
//! cannot forge — not from a same-uid-assertable signal.
//!
//! # B2a strengthening — the seat axis (R3-02 tightening)
//!
//! The pre-B2a gate was `active && !remote`. B2a **tightens** it to
//! `active && !remote && seated`: the ratified intent is *consent from a human at the
//! physical seat*, but an active, non-remote yet **seatless** session (a bare `pts`, a
//! seatless container login) passed the old gate while being no such thing. Requiring a
//! real seat (`sd_session_get_seat` succeeds) closes the gap between the ratified intent
//! and the code. This is strictly **more restrictive** — it can only deny sessions the
//! old gate allowed, never admit a new one — so it cannot weaken the boundary. Stated as
//! a surfaced §4 strengthening, reasoning recorded, not a silent change.
//!
//! # Fidelity (Iron Law #13)
//!
//! The gate **queries logind directly** via the stable sd-login ABI
//! (`sd_session_is_active`, `sd_session_is_remote`, `sd_session_get_seat`), the highest-
//! fidelity binding — "ask logind", not "parse `loginctl`'s text". We declare the
//! symbols ourselves and link the system `libsystemd.so.0` by soname (see `build.rs`):
//! the obvious crate, `libsystemd-sys`, is `LGPL-2.1-or-later` (outside `deny.toml`) and
//! needs `libsystemd-dev`, so an own MIT binding keeps both the fidelity and the license
//! clean. A `loginctl`-subprocess parser would be strictly lower fidelity and is
//! deliberately NOT used.
//!
//! # What this proves, and what is deferred
//!
//! The **decision** (`active && !remote && seated`) is unit-testable without a live
//! session ([`session_passes_gate`]) — including the B2a gate-negative (a seatless
//! active-local session is denied). The **logind query** ([`LogindVerdict`]) is proven
//! live where a real session exists (gated): the seatless-negative bites on WSL2's real
//! seatless session; the seated-**positive** needs a real seated lane. Provisioning a
//! logind session *for a daemon-spawned shell* (via `pam_open_session`/`pam_systemd`) is
//! the B2a lane-dependent half, proven on the real seated lane — not faked here.

use std::ffi::{c_char, c_int, CStr, CString};

// SAFETY: the four stable sd-login ABI symbols, resolved from the system
// `libsystemd.so.0` (linked by soname in build.rs). Signatures match `sd-login.h`.
unsafe extern "C" {
    fn sd_session_is_active(session: *const c_char) -> c_int;
    fn sd_session_is_remote(session: *const c_char) -> c_int;
    fn sd_session_get_seat(session: *const c_char, seat: *mut *mut c_char) -> c_int;
    fn sd_pid_get_session(pid: nix::libc::pid_t, session: *mut *mut c_char) -> c_int;
}

/// A session's active/remote/seated verdict — the seam between the **decision** (unit-
/// testable) and its **source** (logind, gated-live; or, in the RED-proof, a same-uid-
/// assertable signal).
pub trait SessionVerdict {
    /// Whether the session is currently active (the foreground session on its seat).
    fn is_active(&self) -> bool;
    /// Whether the session is remote (e.g. SSH) rather than local.
    fn is_remote(&self) -> bool;
    /// Whether the session is attached to a physical **seat** (a local console). A
    /// seatless session (bare `pts`, seatless container) is not a physical-console
    /// session, so it cannot represent a human present at the seat (B2a R3-02 tightening).
    fn is_seated(&self) -> bool;
}

/// THE DECISION: a session passes the gate iff it is **active AND local AND seated**.
/// Unit-testable without any live session. The seat requirement is the B2a
/// strengthening (see the module docs) — strictly more restrictive than the pre-B2a
/// `active && !remote`.
#[must_use]
pub fn session_passes_gate(verdict: &(impl SessionVerdict + ?Sized)) -> bool {
    verdict.is_active() && !verdict.is_remote() && verdict.is_seated()
}

/// The **authoritative** verdict: queried directly from logind. A same-uid process
/// cannot make logind report a session as active-local-seated when it is not.
pub struct LogindVerdict {
    active: bool,
    remote: bool,
    seated: bool,
}

impl LogindVerdict {
    /// Query logind for the named session id. Returns `None` if logind does not know the
    /// session (or on error querying active/remote).
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
        Some(Self { active: a > 0, remote: r > 0, seated: session_is_seated(&c) })
    }

    /// Resolve the session owning `pid` (the daemon's pidfd-pinned shell), then query
    /// it. `None` if the pid has no logind session.
    #[must_use]
    pub fn for_pid(pid: i32) -> Option<Self> {
        let mut sess: *mut c_char = std::ptr::null_mut();
        // SAFETY: `sess` receives a malloc'd C string on success (rc >= 0); we copy it
        // out and free it.
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

/// Whether `session` is attached to a seat. `sd_session_get_seat` returns a non-negative
/// value and a malloc'd seat name when seated, and **`-ENODATA`** for a seatless session
/// (per sd-login) — so a negative return, or a null out-pointer, means "no seat".
fn session_is_seated(session: &CStr) -> bool {
    let mut seat: *mut c_char = std::ptr::null_mut();
    // SAFETY: `session` is a valid NUL-terminated string; `seat` receives a malloc'd C
    // string on success (rc >= 0), untouched on failure (rc < 0, e.g. -ENODATA seatless).
    let rc = unsafe { sd_session_get_seat(session.as_ptr(), &mut seat) };
    if rc < 0 || seat.is_null() {
        return false;
    }
    // SAFETY: free the libsystemd-allocated seat string exactly once.
    unsafe { nix::libc::free(seat.cast()) };
    true
}

impl SessionVerdict for LogindVerdict {
    fn is_active(&self) -> bool {
        self.active
    }
    fn is_remote(&self) -> bool {
        self.remote
    }
    fn is_seated(&self) -> bool {
        self.seated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mock {
        active: bool,
        remote: bool,
        seated: bool,
    }
    impl SessionVerdict for Mock {
        fn is_active(&self) -> bool {
            self.active
        }
        fn is_remote(&self) -> bool {
            self.remote
        }
        fn is_seated(&self) -> bool {
            self.seated
        }
    }

    /// THE DECISION LOGIC (unit, no live session): passes iff active AND local AND seated.
    #[test]
    fn gate_passes_only_active_local_and_seated() {
        assert!(
            session_passes_gate(&Mock { active: true, remote: false, seated: true }),
            "active local seated → pass"
        );
        // THE B2a GATE-NEGATIVE (the bite): active + local but SEATLESS — this passed the
        // pre-B2a `active && !remote` gate; it must now be DENIED by the seated gate.
        assert!(
            !session_passes_gate(&Mock { active: true, remote: false, seated: false }),
            "active local but SEATLESS → deny (B2a R3-02 tightening)"
        );
        assert!(
            !session_passes_gate(&Mock { active: false, remote: false, seated: true }),
            "inactive → deny"
        );
        assert!(
            !session_passes_gate(&Mock { active: true, remote: true, seated: true }),
            "remote → deny"
        );
    }
}
