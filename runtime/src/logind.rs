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
    /// systemd >= 253. Resolves a **pidfd** to its session, re-verifying the pidfd after the
    /// lookup — the step a hand-rolled pidfd→pid→lookup cannot perform (D0A-R1-01).
    fn sd_pidfd_get_session(pidfd: c_int, session: *mut *mut c_char) -> c_int;
    fn sd_pid_get_session(pid: nix::libc::pid_t, session: *mut *mut c_char) -> c_int;
}

/// A session's active/remote/seated verdict — the seam between the **decision** (unit-
/// testable) and its **source** (logind, gated-live; or, in the RED-proof, a same-uid-
/// assertable signal).
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
    pub fn for_pidfd(pidfd: BorrowedFd<'_>) -> Option<Self> {
        let mut session: *mut c_char = std::ptr::null_mut();
        // SAFETY: a valid fd passed by value; libsystemd allocates `session` on success.
        let rc = unsafe { sd_pidfd_get_session(pidfd.as_raw_fd(), &raw mut session) };
        if rc < 0 || session.is_null() {
            return None;
        }
        // SAFETY: non-null, NUL-terminated, allocated by libsystemd; freed exactly once below.
        let id = unsafe { CStr::from_ptr(session) }.to_string_lossy().into_owned();
        // SAFETY: free the libsystemd-allocated string exactly once.
        unsafe { nix::libc::free(session.cast()) };
        Self::query(&id)
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
    /// The session's triple as of now. Fail-closed: unresolvable ⇒ [`SessionSnapshot::DENIED`].
    fn current(&self) -> SessionSnapshot;
}

impl SessionSource for SessionSnapshot {
    fn current(&self) -> SessionSnapshot {
        *self
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
    fn current(&self) -> SessionSnapshot {
        // D0A-R1-01: resolved from the PIDFD, so no pid number crosses between two operations.
        // Reaped, or no resolvable session ⇒ deny. Unknown is never "fine" at a gate.
        SessionSnapshot::for_pidfd(self.pidfd).unwrap_or(SessionSnapshot::DENIED)
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
        fn current(&self) -> SessionSnapshot {
            self.read()
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
            let got = src.current();
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
        assert!(
            SessionSnapshot::for_pidfd(fd).is_none(),
            "a reaped process must not resolve, even though its pid is live again"
        );
        // And after the reap the diagnostic reports nothing rather than the recycled number.
        assert_eq!(pid_from_pidfd(fd), None, "post-reap the pidfd yields no number");

        // ── WHAT THIS TEST CANNOT SHOW HERE, STATED RATHER THAN IMPLIED ──────────────────
        // The DISCRIMINATING leg — the impostor's session resolving where the victim's would
        // not — needs the impostor to HAVE a logind session. Inside this namespace (and on any
        // seatless dev box) every lookup returns None, so `for_pid(stale)` and `for_pidfd`
        // agree by accident. The staleness above is proven; that the FIX changes the ANSWER is
        // not, and is owed to the seated lane. See PROGRESS.md.

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
