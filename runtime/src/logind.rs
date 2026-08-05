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

use std::os::fd::{AsRawFd, BorrowedFd};
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
        Self::query(&session_id_for_pid(pid)?)
    }
}

/// The logind session id `pid` belongs to, or `None` if it belongs to none.
///
/// # Resolution is by CGROUP MEMBERSHIP, not leadership (§4 R3-01c, A-1)
///
/// `sd_pid_get_session` answers "which session's cgroup contains this pid" — so it
/// resolves for a session **leader** and for any descendant alike. That property is what
/// makes this function usable as the *non-circular first half* of the leader==shell
/// assertion: resolve the session by membership (which succeeds under BOTH the
/// leader==shell and the leader≠shell topology), then compare that session's `Leader` to
/// the shell's pid to discriminate them. Resolving *by* leadership would make the
/// assertion vacuous — it would find only the session it was about to prove.
///
/// # Why this is public API and not a test helper
///
/// Two production callers: the launcher's post-`pam_open_session` outcome check
/// ([`crate::launcher`] — "did a session actually get registered?"), and the B-1
/// leader==shell regression test. The `-ENODATA` case is the one that matters: a
/// `pam_open_session` that "succeeded" against an **empty session group** registers no
/// session at all, and this is the call that sees it.
///
/// # Examples
///
/// ```
/// use delphi_runtime::logind::session_id_for_pid;
/// // Pid 1 (the init system) is never in a login session.
/// assert!(session_id_for_pid(1).is_none());
/// ```
#[must_use]
pub fn session_id_for_pid(pid: i32) -> Option<String> {
    let mut sess: *mut c_char = std::ptr::null_mut();
    // SAFETY: `sess` receives a malloc'd C string on success (rc >= 0); we copy it
    // out and free it. A negative rc (e.g. -ENODATA, "no session") leaves it untouched.
    let rc = unsafe { sd_pid_get_session(pid, &mut sess) };
    if rc < 0 || sess.is_null() {
        return None;
    }
    // SAFETY: `sess` is a valid C string allocated by libsystemd.
    let owned = unsafe { CStr::from_ptr(sess) }.to_str().ok().map(str::to_owned);
    // SAFETY: free the libsystemd-allocated string exactly once.
    unsafe { nix::libc::free(sess.cast()) };
    owned
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

/// A source of the shell session's verdict, queried **at** the decision it authorizes.
///
/// # Why a source and not a stored verdict (D0-A finding A3)
///
/// `active` means "is this session the foreground one on its seat **now**". A verdict captured
/// at daemon start answers about daemon-start time forever, so the axis the gate exists to
/// enforce stops tracking anything. `docs/READINESS_CONTRACT.md` A3.
///
/// # Why the source returns a verdict rather than the trait querying per method
///
/// [`session_passes_gate`] reads `is_active`, `is_remote`, `is_seated` as three calls. An impl
/// that queried logind per method could TEAR — `active` from one instant, `seated` from
/// another — producing a verdict that never described any actual moment. One `current()` per
/// decision yields a triple that was simultaneously true, which is what "active-local-seated
/// now" means. `DEFECT_CLASSES` 26 one level up: there, a captured `revents` reused after a
/// syscall; here, a captured verdict reused across the decision it authorizes.
///
/// Implementations MUST return a verdict describing ONE instant. `verdict_triple_is_simultaneous`
/// in this module's tests is that law, and it is proven discriminating against a tearing impl.
pub trait SessionSource {
    /// The session's verdict as of now. Fail-closed: unresolvable ⇒ a denying verdict.
    fn current(&self) -> Box<dyn SessionVerdict>;
}

/// A verdict fixed at construction — the fail-closed default, and the test seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedVerdict {
    /// Foreground on its seat.
    pub active: bool,
    /// Remote (SSH) rather than local.
    pub remote: bool,
    /// Attached to a physical seat.
    pub seated: bool,
}

impl FixedVerdict {
    /// The fail-closed verdict: fails every axis the gate reads.
    pub const DENIED: Self = Self { active: false, remote: false, seated: false };
}

impl SessionVerdict for FixedVerdict {
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

impl SessionSource for FixedVerdict {
    fn current(&self) -> Box<dyn SessionVerdict> {
        Box::new(*self)
    }
}

/// The pid a pidfd currently refers to, or `None` once it refers to nothing.
///
/// # Why not just keep the pid (D0-A finding A2)
///
/// A pid is reusable the moment the process is reaped, so a stored one can come to name a
/// DIFFERENT process — and `sd_pid_get_session` would then answer about the impostor. The
/// pidfd is the race-free handle `clone3(CLONE_PIDFD)` exists to provide; reading the pid back
/// out of it at each use is what makes the answer about the shell rather than about a number.
///
/// MEASURED (kernel 7.0.0-28, `/proc/self/fdinfo/<pidfd>`): `Pid:` reports the pid while the
/// process is **alive**, still reports it while **dead but unreaped**, and reports **`-1`**
/// once **reaped** — which is exactly when the pid becomes recyclable. So `None` here and
/// "the pid may now name someone else" are the same instant.
///
/// # Examples
///
/// ```
/// use delphi_runtime::logind::pid_from_pidfd;
/// # use std::os::fd::AsFd;
/// # fn demo(pidfd: std::os::fd::BorrowedFd) {
/// let _ = pid_from_pidfd(pidfd); // Some(pid) while it names a process, None once reaped
/// # }
/// ```
#[must_use]
pub fn pid_from_pidfd(pidfd: BorrowedFd<'_>) -> Option<i32> {
    let path = format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd());
    let text = std::fs::read_to_string(path).ok()?;
    let pid: i32 = text
        .lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .map(str::trim)
        .and_then(|v| v.parse().ok())?;
    // -1 = reaped. 0 = a pid outside our namespace. Neither is a process we may ask about.
    (pid > 0).then_some(pid)
}

/// The production source: resolves the shell through its **pidfd** and re-queries logind on
/// every call.
pub struct LogindSource<'a> {
    pidfd: BorrowedFd<'a>,
}

impl<'a> LogindSource<'a> {
    /// Read the session of whatever `pidfd` names, at each [`SessionSource::current`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use delphi_runtime::logind::{LogindSource, SessionSource};
    /// # fn demo(pidfd: std::os::fd::BorrowedFd) {
    /// let src = LogindSource::for_pidfd(pidfd);
    /// let _ = src.current();
    /// # }
    /// ```
    #[must_use]
    pub fn for_pidfd(pidfd: BorrowedFd<'a>) -> Self {
        Self { pidfd }
    }
}

impl SessionSource for LogindSource<'_> {
    fn current(&self) -> Box<dyn SessionVerdict> {
        match pid_from_pidfd(self.pidfd).and_then(LogindVerdict::for_pid) {
            Some(v) => Box::new(v),
            // Reaped, or no resolvable session ⇒ deny. Unknown is never "fine" at a gate.
            None => Box::new(FixedVerdict::DENIED),
        }
    }
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

    /// A source whose state advances on every READ of the underlying cell.
    ///
    /// Snapshot impls read the cell ONCE per `current()`, so their triple is one instant.
    /// A per-method-querying impl reads it three times and mixes instants.
    struct Advancing {
        reads: std::cell::Cell<usize>,
    }
    impl Advancing {
        const A: FixedVerdict = FixedVerdict { active: true, remote: false, seated: true };
        const B: FixedVerdict = FixedVerdict { active: false, remote: true, seated: false };
        fn read(&self) -> FixedVerdict {
            let n = self.reads.get();
            self.reads.set(n + 1);
            if n.is_multiple_of(2) { Self::A } else { Self::B }
        }
    }
    /// CORRECT shape: one read per decision.
    impl SessionSource for Advancing {
        fn current(&self) -> Box<dyn SessionVerdict> {
            Box::new(self.read())
        }
    }

    /// The forbidden shape, kept so the law below is PROVEN discriminating rather than
    /// merely asserted: each axis is read at a different instant.
    struct Tearing {
        inner: Advancing,
    }
    struct TornVerdict {
        active: bool,
        remote: bool,
        seated: bool,
    }
    impl SessionSource for Tearing {
        fn current(&self) -> Box<dyn SessionVerdict> {
            Box::new(TornVerdict {
                active: self.inner.read().active,
                remote: self.inner.read().remote,
                seated: self.inner.read().seated,
            })
        }
    }
    impl SessionVerdict for TornVerdict {
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

    /// THE LAW every `SessionSource` owes: the triple describes ONE instant.
    ///
    /// Against a source whose state advances per read, a conforming `current()` returns
    /// exactly `A` or exactly `B` — never a mixture. A verdict assembled from three instants
    /// never described any actual moment, which is not a thing the gate can act on.
    fn assert_triple_is_simultaneous(src: &dyn SessionSource) {
        for _ in 0..8 {
            let v = src.current();
            let got = FixedVerdict {
                active: v.is_active(),
                remote: v.is_remote(),
                seated: v.is_seated(),
            };
            assert!(
                got == Advancing::A || got == Advancing::B,
                "TORN verdict {got:?} — assembled from more than one instant, so it describes \
                 no actual moment (D0-A A3; DEFECT_CLASSES 26 one level up)"
            );
        }
    }

    #[test]
    fn a_snapshotting_source_yields_a_simultaneous_triple() {
        assert_triple_is_simultaneous(&Advancing { reads: std::cell::Cell::new(0) });
    }

    /// The law's discrimination, PROVEN — not a weaken run once and reported, but a case that
    /// fails forever if `current()` is ever refactored into per-method queries.
    #[test]
    #[should_panic(expected = "TORN verdict")]
    fn the_law_rejects_a_source_that_reads_each_axis_at_a_different_instant() {
        assert_triple_is_simultaneous(&Tearing { inner: Advancing { reads: std::cell::Cell::new(0) } });
    }

    /// A source read at the decision follows a flip. Both directions, because only one of
    /// them is the security property.
    #[test]
    fn the_gate_follows_the_session_state_in_both_directions() {
        // true -> false is THE SECURITY PROPERTY: the seat's foreground moved away, and a
        // consent minted after that point is one no human at the seat authorized. A stored
        // verdict answers `true` forever and mints it.
        let s = Advancing { reads: std::cell::Cell::new(0) };
        assert!(crate::service::gate_allows(&s), "first decision: active+local+seated → ALLOW");
        assert!(
            !crate::service::gate_allows(&s),
            "after the flip the gate must DENY — a stored verdict is what makes this ALLOW, \
             minting consent while the seat points elsewhere (R3-02's whole subject)"
        );
        // false -> true: a false DENY. Annoying, never dangerous — and it is what makes a
        // `chvt` to the shell's VT take effect without restarting the daemon.
        let s = Advancing { reads: std::cell::Cell::new(1) };
        assert!(!crate::service::gate_allows(&s), "first decision: not active → DENY");
        assert!(crate::service::gate_allows(&s), "after the flip back the gate must ALLOW");
    }

    /// A2: the pidfd names the shell while it lives and NOTHING once it is reaped — which is
    /// exactly when the pid becomes recyclable. Both legs, because "denies after reaping"
    /// passes on this box for the wrong reason (no session resolves here at all): the
    /// DISCRIMINATING claim is about the pid RESOLUTION, not about the verdict.
    #[test]
    fn a_pidfd_resolves_to_its_process_while_alive_and_to_nothing_once_reaped() {
        use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd};
        // SAFETY: fork in a test; the child only calls async-signal-safe pause/_exit.
        let child = unsafe { nix::libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            // SAFETY: child arm — pause until killed.
            unsafe {
                nix::libc::pause();
                nix::libc::_exit(0);
            }
        }
        // SAFETY: pidfd_open on our own child; the fd is owned from here.
        let raw = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, child, 0) };
        assert!(raw >= 0, "pidfd_open failed");
        #[allow(clippy::cast_possible_truncation)]
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let fd = unsafe { BorrowedFd::borrow_raw(pidfd.as_raw_fd()) };

        assert_eq!(
            pid_from_pidfd(fd),
            Some(child),
            "while the process lives, the pidfd must resolve to it"
        );

        // SAFETY: killing and reaping our own child.
        unsafe {
            nix::libc::kill(child, nix::libc::SIGKILL);
            let mut st = 0;
            nix::libc::waitpid(child, &raw mut st, 0);
        }

        assert_eq!(
            pid_from_pidfd(fd),
            None,
            "once REAPED the pid is recyclable, so the pidfd must resolve to nothing — a \
             stored pid would keep naming a number that can now be someone else"
        );
        // And the gate fail-closes on it.
        assert!(!crate::service::gate_allows(&LogindSource::for_pidfd(fd)));
    }
}
