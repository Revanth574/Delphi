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
//! active-local session is denied). The **logind query** ([`SessionSnapshot::query`]) is proven
//! live where a real session exists (gated): the seatless-negative bites on WSL2's real
//! seatless session; the seated-**positive** is proven ROOT-GATED, not lane-gated —
//! D0A-R3-01 settled it on this dev box with a real session (control `rc=0 session=2`,
//! barrier `rc=-3`). SUPERSEDED CLAIM, kept visible: this paragraph said "needs a real
//! seated lane" for three rounds while the requirement was `sudo`. Provisioning a
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
    /// systemd >= 253. Resolves a **pidfd** to its session, re-verifying the pidfd after the
    /// lookup — the step a hand-rolled pidfd→pid→lookup cannot perform (D0A-R1-01).
    fn sd_pidfd_get_session(pidfd: c_int, session: *mut *mut c_char) -> c_int;
    fn sd_pid_get_session(pid: nix::libc::pid_t, session: *mut *mut c_char) -> c_int;
}

/// The three axes the gate reads, sampled together.
///
/// # A CONCRETE TRIPLE, NOT A TRAIT — and why that is the mechanism (D0A-R1-04)
///
/// A3 returned `Box<dyn SessionVerdict>` and asked implementations, in prose, to describe one
/// instant. That was a **convention**: an impl could still read each axis lazily at call time,
/// mixing instants, and the `#[should_panic]` law policing it exercised a permanently separate
/// fixture — so making the *production* source lazy would have left the suite green. A struct
/// of three `bool`s makes the tearing shape **unrepresentable**, so the type is the law and no
/// test is needed to enforce it.
///
/// # WHAT THIS DOES *NOT* CLAIM — the atomicity correction (D0A-R1-04)
///
/// A3's write-up said one query yields "a triple that was simultaneously true". **That was
/// false and is withdrawn.** [`SessionSnapshot::query`] makes THREE separate libsystemd calls
/// (`sd_session_is_active`, `sd_session_is_remote`, `sd_session_get_seat`); logind offers no
/// atomic read of the three. The honest guarantee is **three reads in immediate succession**:
/// a VT switch landing between them yields a mixed triple, the window is the span of two
/// library calls, and the next decision re-reads from scratch. Documented rather than claimed
/// away — a false atomicity claim is worse than a stated sampling window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionSnapshot {
    /// Foreground on its seat.
    pub active: bool,
    /// Remote (SSH) rather than local.
    pub remote: bool,
    /// Attached to a physical seat.
    pub seated: bool,
}

impl SessionSnapshot {
    /// The fail-closed triple: fails every axis the gate reads.
    pub const DENIED: Self = Self { active: false, remote: false, seated: false };
}

/// THE DECISION: a session passes the gate iff it is **active AND local AND seated**.
/// Unit-testable without any live session. The seat requirement is the B2a strengthening
/// (see the module docs) — strictly more restrictive than the pre-B2a `active && !remote`.
#[must_use]
pub fn session_passes_gate(s: SessionSnapshot) -> bool {
    s.active && !s.remote && s.seated
}

/// The **authoritative** triple: queried directly from logind. A same-uid process cannot make
/// logind report a session as active-local-seated when it is not.
impl SessionSnapshot {
    /// Query logind for the named session id. Returns `None` if logind does not know the
    /// session (or on error querying active/remote).
    #[must_use]
    pub fn query(session: &str) -> Option<Self> {
        Self::query_detailed(session).ok()
    }

    /// As [`Self::query`], but reporting WHICH axis failed (D0A-R2-04).
    ///
    /// # Errors
    ///
    /// [`SessionResolution::AxisQueryFailed`] naming the libsystemd call and its errno.
    pub fn query_detailed(session: &str) -> Result<Self, SessionResolution> {
        let c = CString::new(session).map_err(|_| SessionResolution::AxisQueryFailed {
            axis: "session id contains NUL",
            errno: nix::libc::EINVAL,
        })?;
        // SAFETY: `c` is a valid NUL-terminated string; the calls only read it and
        // return an int (>0 yes, 0 no, <0 error).
        let (a, r) = unsafe {
            (
                sd_session_is_active(c.as_ptr()),
                sd_session_is_remote(c.as_ptr()),
            )
        };
        if a < 0 {
            return Err(SessionResolution::AxisQueryFailed {
                axis: "sd_session_is_active",
                errno: -a,
            });
        }
        if r < 0 {
            return Err(SessionResolution::AxisQueryFailed {
                axis: "sd_session_is_remote",
                errno: -r,
            });
        }
        // A seat query FAILING is not the same fact as "no seat", so it is not folded into a
        // bool here (D0A-R2-04).
        let seated = session_is_seated(&c).map_err(|errno| SessionResolution::AxisQueryFailed {
            axis: "sd_session_get_seat",
            errno,
        })?;
        Ok(Self { active: a > 0, remote: r > 0, seated })
    }

    /// Resolve the session owning `pid` (the daemon's pidfd-pinned shell), then query
    /// it. `None` if the pid has no logind session.
    #[must_use]
    pub fn for_pid(pid: i32) -> Option<Self> {
        Self::query(&session_id_for_pid(pid)?)
    }

    /// Resolve the session of a **pidfd**, then query it — the race-free path.
    ///
    /// # Why not pidfd → pid → [`Self::for_pid`] (D0A-R1-01)
    ///
    /// That is two operations with an interval between them: the process can exit, be reaped,
    /// and its pid REUSED after the number is read and before it is looked up, so the answer
    /// describes an impostor. A2 shipped exactly that shape, and its test never exercised the
    /// interval — it sampled wholly before and wholly after the reap, never across.
    /// `sd_pidfd_get_session` closes the interval inside libsystemd by re-verifying the pidfd
    /// after the lookup. Bound rather than hand-rolled — and measured rather than taken on
    /// trust: `pidfd_refuses_a_recycled_pid_barrier` recycles the pid and checks the refusal.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use delphi_runtime::logind::SessionSnapshot;
    /// # fn demo(pidfd: std::os::fd::BorrowedFd) {
    /// let _ = SessionSnapshot::for_pidfd(pidfd);
    /// # }
    /// ```
    #[must_use]
    pub fn for_pidfd(pidfd: BorrowedFd<'_>) -> SessionResolution {
        let mut session: *mut c_char = std::ptr::null_mut();
        // SAFETY: a valid fd passed by value; libsystemd allocates `session` on success.
        let rc = unsafe { sd_pidfd_get_session(pidfd.as_raw_fd(), &raw mut session) };
        if rc < 0 {
            return SessionResolution::from_errno(-rc);
        }
        if session.is_null() {
            return SessionResolution::QueryFailed(0);
        }
        // SAFETY: non-null, NUL-terminated, allocated by libsystemd; freed exactly once below.
        let id = unsafe { CStr::from_ptr(session) }.to_string_lossy().into_owned();
        // SAFETY: free the libsystemd-allocated string exactly once.
        unsafe { nix::libc::free(session.cast()) };
        match Self::query_detailed(&id) {
            Ok(snap) => SessionResolution::Resolved(snap),
            Err(cause) => cause,
        }
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
/// What `sd_session_get_seat`'s return code means (D0A-R4-05).
///
/// Split out because the distinction it encodes — `-ENODATA` is a real "no seat", any other
/// negative is a FAILED QUERY and must never be reported as seatless — was previously
/// untestable: making the call fail with something other than `-ENODATA` needs a live session
/// whose seat query errors, which is not constructible. As a pure function of the rc it is
/// directly testable, which is what D0A-R2-04's unbitten weaken was missing.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SeatRc {
    /// rc >= 0 — the session has a seat.
    HasSeat,
    /// `-ENODATA` — genuinely no seat.
    NoSeat,
    /// Any other negative — the QUERY failed; the seat state is UNKNOWN, not absent.
    QueryFailed(i32),
}

/// The rc → outcome mapping `session_is_seated` uses (D0A-R5-06).
///
/// D0A-R4-05 extracted the CLASSIFIER and tested it, and left the MAPPING from `SeatRc` to
/// `Result` inline and untested — so swapping the `NoSeat` and `QueryFailed` arms kept the
/// suite green. The classifier test and the production mapping agreed only by inspection,
/// which is Class 36's mutual stabilisation appearing inside the fix that closed R4-05.
///
/// # Errors
///
/// The errno, when the query failed rather than answering "no seat".
pub(crate) fn seat_outcome(rc: c_int) -> Result<bool, i32> {
    match classify_seat_rc(rc) {
        SeatRc::HasSeat => Ok(true),
        SeatRc::NoSeat => Ok(false),
        SeatRc::QueryFailed(e) => Err(e),
    }
}

pub(crate) fn classify_seat_rc(rc: c_int) -> SeatRc {
    if rc >= 0 {
        SeatRc::HasSeat
    } else if rc == -nix::libc::ENODATA {
        SeatRc::NoSeat
    } else {
        SeatRc::QueryFailed(-rc)
    }
}

fn session_is_seated(session: &CStr) -> Result<bool, i32> {
    let mut seat: *mut c_char = std::ptr::null_mut();
    // SAFETY: `session` is a valid NUL-terminated string; `seat` receives a malloc'd C
    // string on success (rc >= 0), untouched on failure (rc < 0, e.g. -ENODATA seatless).
    let rc = unsafe { sd_session_get_seat(session.as_ptr(), &mut seat) };
    if !seat_outcome(rc)? {
        return Ok(false);
    }
    if seat.is_null() {
        return Ok(false);
    }
    // SAFETY: free the libsystemd-allocated seat string exactly once.
    unsafe { nix::libc::free(seat.cast()) };
    Ok(true)
}

/// A source of the shell session's verdict, queried **at** the decision it authorizes.
///
/// # Why a source and not a stored verdict (D0-A finding A3)
///
/// `active` means "is this session the foreground one on its seat **now**". A verdict captured
/// at daemon start answers about daemon-start time forever, so the axis the gate exists to
/// enforce stops tracking anything. `docs/READINESS_CONTRACT.md` A3.
///
/// # What returning a concrete triple buys — and what it does NOT (D0A-R2-06)
///
/// It forecloses **consumer-side** laziness: a caller receives three `bool`s already decided,
/// so it cannot re-read one axis at a time between the gate and the mint. That is the property
/// A3 needed and the one the type now guarantees — the settling weaken (make the production
/// source lazy per axis) does not compile.
///
/// **It does not foreclose producer-side tearing, and it is not claimed to.**
/// [`SessionSnapshot::query_detailed`] still makes three separate libsystemd calls, because
/// logind exposes no atomic read of the three; a VT switch landing between them yields a mixed
/// triple. The window is the span of two library calls and the next decision re-reads from
/// scratch. **Narrower than the original claim, and stated instead of assumed away.**
///
/// `DEFECT_CLASSES` 26 is the reason the read is taken at the decision at all: there, a
/// captured `revents` reused after a syscall; here, a captured verdict reused across the
/// decision it authorizes.
pub trait SessionSource {
    /// The session as of now, **with the cause when it did not resolve** (D0A-R3-02).
    ///
    /// Returning a bare triple discarded the distinctions R1-05 measured before they could
    /// reach the operator. `Resolved` still carries a CONCRETE `SessionSnapshot`, so the
    /// consumer-side foreclosure of D0A-R1-04 is unchanged — an implementation still cannot
    /// hand back something that re-reads an axis later.
    fn current(&self) -> SessionResolution;
}

impl SessionSource for SessionSnapshot {
    fn current(&self) -> SessionResolution {
        SessionResolution::Resolved(*self)
    }
}

/// Why a session could not be resolved — every variant DENIES, none is silent (D0A-R1-05).
///
/// Fail-closed was already right; losing the diagnosis was not. A single `Option` collapsed a
/// missing `/proc`, a wrong fd, a reaped shell and a sessionless process into one `None`, so
/// the operator saw the same denial for a configuration error and for normal operation.
///
/// **MEASURED, not assumed** (libsystemd, systemd 259): `sd_pidfd_get_session` returns
/// `-ENODATA` for a live process in no session, `-ESRCH` once it is reaped, `-EBADF` for a
/// closed fd and `-ENOTTY` for an fd that is not a pidfd. Binding it in D0A-R1-01 therefore
/// made MORE causes distinguishable than the `/proc` parse it replaced, not fewer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionResolution {
    /// logind answered; this is the triple.
    Resolved(SessionSnapshot),
    /// `-ENODATA` from the lookup. **An observation, not a liveness claim (D0A-R2-03).**
    ///
    /// The previous name, `NoSession`, asserted the process was alive and merely unattached.
    /// It cannot: the verifier is **error-gated** — on this path libsystemd returns before
    /// proving liveness, so a victim that vanished between the first read and the lookup, with
    /// an impostor at its pid, also lands here. All that is known is *the lookup returned no
    /// data*. Normal on a seatless box; NOT evidence about the process.
    LookupNoData,
    /// `-ESRCH` — the process is gone. The pidfd outlived what it named.
    ProcessGone,
    /// `-EBADF` / `-ENOTTY` — the fd is closed or is not a pidfd. **Our bug, not the user's.**
    ///
    /// `ENOTTY` for a non-pidfd is **observed on systemd 259, not an API promise** — measured,
    /// and named here as observation so a later kernel or libsystemd reporting `EINVAL` shows
    /// up as `QueryFailed` rather than being silently misfiled.
    NotAPidfd(i32),
    /// Any other `-errno` from the session lookup.
    QueryFailed(i32),
    /// The session id resolved, but an **axis query** failed (D0A-R2-04).
    ///
    /// `sd_session_is_active` / `is_remote` / `get_seat` each return a negative errno of their
    /// own. Collapsing those into "not seated" made a query failure look like a real seatless
    /// session — a *different fact*, and the one that reads as routine.
    AxisQueryFailed {
        /// Which axis failed, by its libsystemd call.
        axis: &'static str,
        /// The errno it returned.
        errno: i32,
    },
}

impl SessionResolution {
    /// Why this denied, phrased for the operator — **derived from the cause** (D0A-R2-04).
    ///
    /// A fixed string claiming "the seat's foreground moved" is false when the shell is gone or
    /// the pidfd is invalid. `during_auth` selects the phase wording, but only where the
    /// session genuinely resolved and then failed the gate; every other cause names itself.
    #[must_use]
    pub fn denial(&self, during_auth: bool) -> String {
        match self {
            // D0A-R4-04: derived from WHICH axes failed. These arms ignored the snapshot and
            // claimed the seat's foreground had moved for EVERY resolved denial — unsupported
            // when the session is remote or seatless, which systemd defines as distinct facts.
            Self::Resolved(s) => {
                let foreground_only = !s.active && !s.remote && s.seated;
                if during_auth && foreground_only {
                    crate::service::REASON_SESSION_LOST_DURING_AUTH.to_owned()
                } else {
                    let mut failed = Vec::new();
                    if !s.active {
                        failed.push("not the seat's foreground");
                    }
                    if s.remote {
                        failed.push("REMOTE rather than on a local seat");
                    }
                    if !s.seated {
                        failed.push("attached to NO seat");
                    }
                    let when = if during_auth { " — it changed during authentication" } else { "" };
                    format!("logind: the shell's session is {}{when}", failed.join(", "))
                }
            }
            Self::LookupNoData => {
                "logind: no session data for the shell (it is in no session, or it vanished \
                 before the lookup could say)"
                    .to_owned()
            }
            Self::ProcessGone => {
                "logind: the pinned shell process is GONE - there is no session to consent \
                 from, whatever stage this reached"
                    .to_owned()
            }
            Self::NotAPidfd(e) => format!(
                "logind: the pinned handle is not a usable pidfd (errno {e}) - a DAEMON BUG, \
                 not a seat or configuration problem"
            ),
            Self::QueryFailed(e) => format!("logind: session lookup failed (errno {e})"),
            Self::AxisQueryFailed { axis, errno } => format!(
                "logind: session resolved but `{axis}` failed (errno {errno}) - the verdict is \
                 UNKNOWN, which is not the same as seatless"
            ),
        }
    }
}

impl SessionResolution {
    fn from_errno(e: i32) -> Self {
        match e {
            nix::libc::ENODATA => Self::LookupNoData,
            nix::libc::ESRCH => Self::ProcessGone,
            nix::libc::EBADF | nix::libc::ENOTTY => Self::NotAPidfd(e),
            other => Self::QueryFailed(other),
        }
    }

    /// The triple to gate on. Every non-`Resolved` cause denies — and says which it was.
    #[must_use]
    pub fn snapshot_or_denied(&self) -> SessionSnapshot {
        match self {
            Self::Resolved(s) => *s,
            Self::LookupNoData => {
                tracing::warn!("consent DENIED: no session data for the shell");
                SessionSnapshot::DENIED
            }
            Self::AxisQueryFailed { axis, errno } => {
                tracing::warn!(axis, errno, "consent DENIED: a session axis query failed - the \
                               verdict is UNKNOWN, not seatless");
                SessionSnapshot::DENIED
            }
            Self::ProcessGone => {
                tracing::warn!("consent DENIED: the pinned shell process is gone");
                SessionSnapshot::DENIED
            }
            Self::NotAPidfd(e) => {
                tracing::error!(errno = e, "consent DENIED: the pidfd is invalid — a DAEMON \
                                BUG (closed fd or not a pidfd), not a user misconfiguration");
                SessionSnapshot::DENIED
            }
            Self::QueryFailed(e) => {
                tracing::warn!(errno = e, "consent DENIED: logind query failed");
                SessionSnapshot::DENIED
            }
        }
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
    fn current(&self) -> SessionResolution {
        // D0A-R1-01: resolved from the PIDFD, so no pid number crosses between two operations.
        // D0A-R1-05/R3-02: every failure denies, and the cause travels with it.
        SessionSnapshot::for_pidfd(self.pidfd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE DECISION LOGIC (unit, no live session): passes iff active AND local AND seated.
    #[test]
    fn gate_passes_only_active_local_and_seated() {
        assert!(
            session_passes_gate(SessionSnapshot { active: true, remote: false, seated: true }),
            "active local seated → pass"
        );
        // THE B2a GATE-NEGATIVE (the bite): active + local but SEATLESS — this passed the
        // pre-B2a `active && !remote` gate; it must now be DENIED by the seated gate.
        assert!(
            !session_passes_gate(SessionSnapshot { active: true, remote: false, seated: false }),
            "active local but SEATLESS → deny (B2a R3-02 tightening)"
        );
        assert!(
            !session_passes_gate(SessionSnapshot { active: false, remote: false, seated: true }),
            "inactive → deny"
        );
        assert!(
            !session_passes_gate(SessionSnapshot { active: true, remote: true, seated: true }),
            "remote → deny"
        );
    }

    /// A source whose state advances on every READ of the underlying cell.
    struct Advancing {
        reads: std::cell::Cell<usize>,
    }
    impl Advancing {
        const A: SessionSnapshot = SessionSnapshot { active: true, remote: false, seated: true };
        const B: SessionSnapshot = SessionSnapshot { active: false, remote: true, seated: false };
        fn read(&self) -> SessionSnapshot {
            let n = self.reads.get();
            self.reads.set(n + 1);
            if n.is_multiple_of(2) { Self::A } else { Self::B }
        }
    }
    impl SessionSource for Advancing {
        fn current(&self) -> SessionResolution {
            SessionResolution::Resolved(self.read())
        }
    }

    // D0A-R1-04: the `Tearing` fixture and the `#[should_panic]` law that policed it are GONE.
    // `current()` returns a concrete `SessionSnapshot`, so an implementation CANNOT read one
    // axis at a time — the settling weaken (make the production source lazy per axis) no longer
    // COMPILES. Foreclosed rather than detected, which is why no test replaces them.

    /// The fixture yields one state or the other, never a blend — a sanity check on the test
    /// double itself, since the TYPE now guarantees this for every real source.
    #[test]
    fn the_advancing_fixture_yields_one_state_at_a_time() {
        let src = Advancing { reads: std::cell::Cell::new(0) };
        for _ in 0..8 {
            let got = src.current().snapshot_or_denied();
            assert!(got == Advancing::A || got == Advancing::B, "blended triple {got:?}");
        }
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

    /// D0A-R1-05 — each cause keeps its own identity instead of collapsing into one denial.
    ///
    /// Fail-closed was already right; losing the diagnosis was not. The errnos below are
    /// MEASURED against libsystemd (systemd 259), not assumed — binding
    /// `sd_pidfd_get_session` in R1-01 made MORE causes distinguishable, not fewer.
    #[test]
    fn each_resolution_failure_keeps_its_own_cause() {
        use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};

        // A live process in no session (this box has none) → NoSession, NOT ProcessGone.
        #[allow(clippy::cast_possible_wrap)]
        let self_pid = std::process::id() as i32;
        // SAFETY: pidfd_open on ourselves.
        let raw = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, self_pid, 0) };
        assert!(raw >= 0);
        #[allow(clippy::cast_possible_truncation)]
        let me = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let live = SessionSnapshot::for_pidfd(me.as_fd());
        assert!(
            matches!(live, SessionResolution::LookupNoData | SessionResolution::Resolved(_)),
            "a LIVE process must report LookupNoData (or resolve, on a seated box) — never \
             ProcessGone, which is the cause that means the pidfd outlived what it named. \
             Got {live:?}"
        );

        // Not a pidfd → OUR bug, and it says so distinctly.
        let pipe = std::io::stdout();
        assert!(
            matches!(SessionSnapshot::for_pidfd(pipe.as_fd()), SessionResolution::NotAPidfd(_)),
            "an fd that is not a pidfd is a DAEMON bug and must not look like a user's \
             misconfiguration"
        );
        // A CLOSED fd number — not `-1`, which `BorrowedFd::borrow_raw` rejects outright
        // (reserved for niche optimization; it panics `fd != -1`). Measured, not assumed.
        // SAFETY: a stale fd number; the call only inspects it and returns -EBADF.
        let bad = unsafe { BorrowedFd::borrow_raw(9999) };
        assert!(
            matches!(SessionSnapshot::for_pidfd(bad), SessionResolution::NotAPidfd(_)),
            "a closed fd is EBADF — also our bug, and reported as such"
        );

        // EVERY cause denies — the diagnosis is added, the fail-closed posture is unchanged.
        // AND each must actually EMIT its diagnosis: asserting enum identities alone would
        // stay green with every log line deleted, which is Class 22's question turned on this
        // test rather than on the code (D0A-R2-04).
        for (r, must_say) in [
            (SessionResolution::LookupNoData, "no session data"),
            (SessionResolution::ProcessGone, "shell process is gone"),
            (SessionResolution::NotAPidfd(nix::libc::EBADF), "pidfd is invalid"),
            (SessionResolution::QueryFailed(nix::libc::EIO), "logind query failed"),
            (
                SessionResolution::AxisQueryFailed {
                    axis: "sd_session_is_active",
                    errno: nix::libc::EIO,
                },
                "axis query failed",
            ),
        ] {
            let logged = capture_logs(|| {
                assert_eq!(r.snapshot_or_denied(), SessionSnapshot::DENIED, "{r:?} must DENY");
            });
            assert!(!session_passes_gate(r.snapshot_or_denied()));
            assert!(
                logged.to_lowercase().contains(must_say),
                "{r:?} denied silently — it must SAY {must_say:?}, or the operator sees the \
                 same denial for a daemon bug and for normal operation. Captured: {logged:?}"
            );
            // And the operator-facing reason must name THIS cause, not a generic one.
            let reason = r.denial(true);
            assert!(
                !matches!(r, SessionResolution::Resolved(_))
                    && reason != crate::service::REASON_SESSION_LOST_DURING_AUTH,
                "{r:?} must not be reported as 'the foreground moved during authentication' — \
                 that claim is false for a gone process or a bad pidfd (D0A-R2-04)"
            );
        }
    }

    /// D0A-R2-04, the CONSTRUCTION half: an axis query that fails must PRODUCE
    /// `AxisQueryFailed`, not collapse into a triple that reads as a real seatless session.
    ///
    /// Measured: every `sd_session_*` axis returns `-EINVAL` for an unusable session id
    /// (systemd 259), so this path is reachable without a live session.
    ///
    /// **WHAT THIS LEG DOES NOT COVER, stated rather than left implied:** it exercises the
    /// FIRST axis. Making `sd_session_get_seat` fail with something other than `-ENODATA`
    /// while the other two succeed needs a real session whose seat query errors, which is not
    /// constructible off-lane — so the seat-axis collapse specifically is unbitten here.
    #[test]
    fn an_axis_query_failure_is_produced_not_collapsed() {
        let bogus = format!("delphi-no-such-session-{}", std::process::id());
        match SessionSnapshot::query_detailed(&bogus) {
            Err(SessionResolution::AxisQueryFailed { axis, errno }) => {
                assert_eq!(axis, "sd_session_is_active");
                assert_ne!(errno, 0, "the errno must be retained, not zeroed");
            }
            other => panic!(
                "a failing axis query must name itself; collapsing it makes a FAILED QUERY \
                 look like a real seatless session, which is a different fact and the one \
                 that reads as routine. Got {other:?}"
            ),
        }
        // And it denies, like every other cause.
        let r = SessionSnapshot::query_detailed(&bogus).unwrap_err();
        assert_eq!(r.snapshot_or_denied(), SessionSnapshot::DENIED);
    }

    /// D0A-R4-05: the seat rc classification, directly testable now that it is a pure
    /// function. `-ENODATA` is the only negative that means "no seat"; every other negative is
    /// a failed QUERY whose result must not be reported as seatless — a different fact, and
    /// the one that reads as routine.
    #[test]
    fn a_failed_seat_query_is_not_the_same_as_no_seat() {
        // D0A-R5-06: the MAPPING, not just the classifier. Swapping the NoSeat and
        // QueryFailed arms left the suite green because nothing tested this step.
        assert_eq!(seat_outcome(0), Ok(true), "rc>=0 means the session HAS a seat");
        assert_eq!(seat_outcome(-nix::libc::ENODATA), Ok(false), "ENODATA is a real 'no seat'");
        assert_eq!(
            seat_outcome(-nix::libc::EIO),
            Err(nix::libc::EIO),
            "any other errno is a FAILED QUERY — it must not map to 'no seat', which is what \
             a swapped arm would do and what nothing was checking"
        );
        assert_eq!(classify_seat_rc(0), SeatRc::HasSeat);
        assert_eq!(classify_seat_rc(1), SeatRc::HasSeat);
        assert_eq!(classify_seat_rc(-nix::libc::ENODATA), SeatRc::NoSeat);
        for e in [nix::libc::EIO, nix::libc::EPERM, nix::libc::EINVAL, nix::libc::ENOENT] {
            assert_eq!(
                classify_seat_rc(-e),
                SeatRc::QueryFailed(e),
                "errno {e} is a FAILED QUERY — reporting it as seatless would turn an unknown \
                 into a routine-looking denial"
            );
        }
    }

    /// D0A-R6-01: the WITNESS FORMAT that leg 1 parses, pinned here.
    ///
    /// The daemon prints `DELPHI_GATE_WITNESS {resolution:?}` and `b1_integration` matches on
    /// `Resolved(`, `active: false`, `remote: false`, `seated: true`. That is a coupling across
    /// two crates with nothing holding it — a `Debug` change would break the parse silently and
    /// leg 1 would report "never reached the gate" for a formatting reason.
    ///
    /// It also MEASURES the R6-01 weaken instead of predicting it: substituting
    /// `SessionSnapshot::DENIED` for the real source yields the string below, which fails leg
    /// 1's `seated: true` check — the WRONG-CAUSE branch, not the absence branch.
    #[test]
    fn the_gate_witness_format_discriminates_denied_from_a_real_resolution() {
        let expected = format!("{:?}", SessionResolution::Resolved(SessionSnapshot {
            active: false,
            remote: false,
            seated: true,
        }));
        let denied = format!("{:?}", SessionResolution::Resolved(SessionSnapshot::DENIED));

        // What leg 1 requires.
        let passes = |w: &str| {
            w.contains("Resolved(")
                && w.contains("active: false")
                && w.contains("remote: false")
                && w.contains("seated: true")
        };
        assert!(passes(&expected), "the real non-foreground resolution must satisfy leg 1: {expected}");
        assert!(
            !passes(&denied),
            "a DENIED substitution must FAIL leg 1 — this is the R6-01 weaken, measured rather \
             than predicted. Got: {denied}"
        );
        assert!(
            denied.contains("seated: false"),
            "and it must fail on the AXIS, so the message names the wrong cause: {denied}"
        );
        // Absence is a different failure: an empty witness satisfies neither branch.
        assert!(!passes(""), "an absent witness must not satisfy the wrong-cause check");
    }

    /// Run `f` with a subscriber capturing everything it logs.
    fn capture_logs(f: impl FnOnce()) -> String {
        use std::sync::{Arc, Mutex};
        #[derive(Clone)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("log buffer").extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl tracing_subscriber::fmt::MakeWriter<'_> for Buf {
            type Writer = Self;
            fn make_writer(&self) -> Self {
                self.clone()
            }
        }
        let buf = Buf(Arc::new(Mutex::new(Vec::new())));
        let sub = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(sub, f);
        let out = buf.0.lock().expect("log buffer").clone();
        String::from_utf8_lossy(&out).into_owned()
    }

    /// D0A-R1-01 — THE BARRIER. A pid is RECYCLED, and the pidfd must still refuse.
    ///
    /// A2's original proof sampled wholly before and wholly after the reap, so it never
    /// exercised the interval that makes a pid unsafe: read the number, the process is reaped,
    /// the number is REUSED by someone else, and the lookup answers about the impostor. Here
    /// the impostor is made real — same pid, live, different process — and the assertion is
    /// that resolution through the pidfd is unmoved by it.
    ///
    /// Runs itself under `unshare -Ur -p --fork --mount-proc`, where pids restart low and
    /// `/proc/sys/kernel/ns_last_pid` is writable without root, so recycling is deterministic
    /// rather than a 4-million-fork spin.
    #[test]
    fn pidfd_refuses_a_recycled_pid_barrier() {
        use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd};
        if std::env::var_os("DELPHI_BARRIER_CHILD").is_none() {
            let exe = std::env::current_exe().expect("current_exe");
            let out = std::process::Command::new("unshare")
                .args(["-Ur", "-p", "--fork", "--mount-proc"])
                .arg(&exe)
                .args(["--exact", "--nocapture", "--test-threads=1",
                       "logind::tests::pidfd_refuses_a_recycled_pid_barrier"])
                .env("DELPHI_BARRIER_CHILD", "1")
                .output();
            match out {
                Ok(o) if o.status.success() => {}
                Ok(o) => {
                    // A skip proves nothing, so say exactly what could not be set up.
                    let err = String::from_utf8_lossy(&o.stderr);
                    assert!(
                        err.contains("unshare") || err.contains("Operation not permitted"),
                        "the barrier ran and FAILED (not a setup problem):\n{}\n{err}",
                        String::from_utf8_lossy(&o.stdout)
                    );
                    eprintln!("SKIP pidfd_refuses_a_recycled_pid_barrier: user namespaces \
                               unavailable here, so a pid cannot be recycled deterministically");
                }
                Err(e) => eprintln!("SKIP pidfd_refuses_a_recycled_pid_barrier: no `unshare`: {e}"),
            }
            return;
        }

        // ── inside the pid namespace ──────────────────────────────────────────────────
        // SAFETY: fork in a single-purpose child; the forked side only pauses or _exits.
        let spawn = || unsafe {
            let p = nix::libc::fork();
            assert!(p >= 0, "fork failed");
            if p == 0 {
                nix::libc::pause();
                nix::libc::_exit(0);
            }
            p
        };
        let victim = spawn();
        // SAFETY: pidfd_open on our own child.
        let raw = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, victim, 0) };
        assert!(raw >= 0, "pidfd_open failed");
        #[allow(clippy::cast_possible_truncation)]
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let fd = unsafe { BorrowedFd::borrow_raw(pidfd.as_raw_fd()) };

        // STEP 1 of the two-step, taken while the victim is ALIVE — this is the number a
        // pidfd->pid->lookup would carry into its second operation.
        let number_read_while_alive =
            pid_from_pidfd(fd).expect("the victim is alive, so its pid resolves");
        assert_eq!(number_read_while_alive, victim);

        // SAFETY: kill and reap our own child — after this the pid is recyclable.
        unsafe {
            nix::libc::kill(victim, nix::libc::SIGKILL);
            let mut st = 0;
            nix::libc::waitpid(victim, &raw mut st, 0);
        }

        // Force the NEXT pid to be the victim's, making a live impostor at that number.
        std::fs::write("/proc/sys/kernel/ns_last_pid", (victim - 1).to_string())
            .expect("ns_last_pid is writable inside the userns");
        let impostor = spawn();
        assert_eq!(
            impostor, victim,
            "setup: the impostor must occupy the victim's pid, or there is no barrier to test"
        );
        // SAFETY: signal 0 probes liveness without delivering anything.
        assert_eq!(
            unsafe { nix::libc::kill(impostor, 0) },
            0,
            "setup: the impostor must be ALIVE at the recycled pid"
        );

        // THE VULNERABILITY, made concrete: the number taken in step 1 now names a DIFFERENT,
        // LIVE process. A second operation keyed on it answers about the impostor. This is the
        // interval A2's proof never crossed — it reaped before reading, so it saw only `-1`.
        assert_eq!(
            number_read_while_alive, impostor,
            "the number carried from step 1 now addresses the impostor — that is the race"
        );

        // THE FIX: resolution through the pidfd carries no number at all, and refuses.
        assert_eq!(
            SessionSnapshot::for_pidfd(fd),
            SessionResolution::ProcessGone,
            "a reaped process must resolve to PROCESS GONE — not merely 'no session', which is \
             what a live process in no session reports (D0A-R1-05 makes the two distinct)"
        );
        // And after the reap the diagnostic reports nothing rather than the recycled number.
        assert_eq!(pid_from_pidfd(fd), None, "post-reap the pidfd yields no number");

        // ── WHAT THIS TEST CANNOT SHOW HERE, STATED RATHER THAN IMPLIED ──────────────────
        // The DISCRIMINATING leg — the impostor's session resolving where the victim's would
        // not — needs the impostor to HAVE a logind session. Inside this namespace (and on any
        // seatless dev box) every lookup returns None, so `for_pid(stale)` and `for_pidfd`
        // agree by accident. The staleness above is proven; that the FIX changes the ANSWER is
        // not. SUPERSEDED (D0A-R4-06): this said "owed to the seated lane". It was owed to
        // ROOT, and `runtime/tests/pidfd-barrier.test.sh`'s root section discharged it —
        // 12 assertions, then 60 runs with zero misses. See PROGRESS.md.

        // SAFETY: clean up the impostor.
        unsafe {
            nix::libc::kill(impostor, nix::libc::SIGKILL);
            let mut st = 0;
            nix::libc::waitpid(impostor, &raw mut st, 0);
        }
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
