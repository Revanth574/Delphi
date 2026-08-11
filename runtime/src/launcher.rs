// SPDX-License-Identifier: MIT

//! The daemon launcher loop (Increment B1) — fork the shell + AI as same-uid
//! siblings of a trusted root parent (`docs/TRUST_MODEL.md` §4, R3-01).
//!
//! ASSEMBLY of 1a/1b primitives into the daemon's real fork sequence. The
//! **asymmetric fd-discipline is spec-pinned** (§4 line 272), applied with EXACTLY
//! 1b's proven `close_range` primitive so the `sibling_fd_theft` RED-proof bites the
//! real launcher, not just 1b's isolated test:
//!
//! * **shell** — fork-pass the private `SOCK_SEQPACKET` channel (Reading A: the
//!   channel arrives **at fork**, reusing 1b's proven mechanism); place it at a fixed
//!   fd, keep ONLY it (`mark_cloexec_except_raw([chan])`), drop to the session user,
//!   exec; pin it by `pidfd` (R3-03).
//! * **AI** — `mark_cloexec_except_raw([])` (keep NOTHING — the AI is **never**
//!   passed the channel), drop, exec. It reaches the daemon only by `connect()`ing
//!   the group-connectable `approve.sock` (the general socket).
//!
//! The pre_exec closures are allocation-free (the 1D-03 discipline): the raw fd core
//! returns an `Errno`, mapped via `io::Error::from_raw_os_error` (no `Box`).

use std::ffi::CString;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};

use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::unistd::{Gid, Pid, Uid};
use pam_client2::conv_null::Conversation as NullConv;
use pam_client2::{Context, Flag, SessionToken};

use crate::channel::approval_socketpair;
use crate::privdrop::{drop_privileges, RealPrivDropOps};
use crate::readiness;
use crate::RuntimeError;

/// Where the forked shell finds its private-channel fd (the launcher dups the
/// channel onto this number; the shell reads `DELPHI_CHANNEL_FD` to confirm).
pub const SHELL_CHANNEL_FD: RawFd = 3;

/// The forked shell child's WRITE end of the setup-sync pipe (P1 / B2A-C-R1-01). The child
/// publishes it as the FIRST thing it does after `fork`; every [`child_diag`] then writes one
/// failure byte here before `_exit`, so a pre-`execve` failure reaches the parent's
/// [`wait_for_child_setup`]. On a SUCCESSFUL `execve` the fd is CLOEXEC-closed, so the parent
/// reads EOF instead. `-1` in the parent, which never touches this — it reads the pipe's READ
/// end directly. A `static` (not a threaded parameter) so that EVERY `child_bail`/`child_fail`
/// call site signals without plumbing the fd through all of them; sound because the child is
/// single-threaded post-`fork` and `fork` gives it a private copy of the static.
static CHILD_SYNC_FD: AtomicI32 = AtomicI32::new(-1);

/// A validated Linux virtual-terminal name (`ttyN`) — the **sole** input deciding whether
/// the shell's session is SEATED (§4 R3-02: `PAM_TTY=ttyN` is the *whole* seat obligation,
/// because `pam_systemd` derives `XDG_SEAT=seat0` and `XDG_VTNR=N` from the tty **name**).
///
/// # Why a newtype and not `&str` (the capability-type idiom)
///
/// A malformed tty name does **not** fail loudly. `pam_open_session` **SUCCEEDS** and logind
/// registers a `Class=background`, **seatless** session — recon Variant A measured exactly
/// this: the session opens cleanly, even reports `Active=yes`, and the seated gate then
/// **denies every consent, forever**. The symptom ("the session opens fine but consent never
/// works") appears far from its cause (a typo in a string field). Possession of a `VtName`
/// is proof the name is well-formed, so that failure moves to a loud **"launch refused:
/// invalid VT"** *before* `pam_open_session` instead of a silent misconfiguration after it.
/// Same idiom as the project's other validated newtypes (`SanitizedPrompt`,
/// `ConfirmationTokenWire`): the only constructor establishes the invariant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtName(String);

impl VtName {
    /// THE ONLY CONSTRUCTOR. Accepts exactly `tty<N>` with `N` in **1..=63** (Linux
    /// `MAX_NR_CONSOLES`; `0` means "no VT"), decimal, no leading zeros — the canonical form
    /// `pam_systemd` parses. Deliberately strict: `/dev/tty1`, `TTY1`, and `pts/3` are
    /// **rejected**, `pts/3` most importantly — a pty is precisely the input that yields the
    /// seatless session this type exists to prevent.
    ///
    /// # Errors
    ///
    /// [`RuntimeError::Config`] if `name` is not a well-formed `ttyN` in range.
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_runtime::launcher::VtName;
    /// assert!(VtName::new("tty7").is_ok());
    /// assert!(VtName::new("pts/3").is_err());   // seatless trap
    /// assert!(VtName::new("tty0").is_err());    // 0 == "no VT"
    /// ```
    ///
    /// # Structural proofs that the invariant is unforgeable (class 5)
    ///
    /// These are `compile_fail` doctests, not source greps: they prove the bypass shapes
    /// **cannot be written** from outside this module, enforced by the compiler with no
    /// count constant and nothing a future edit can silently disarm (see
    /// `docs/DEFECT_CLASSES.md` class 15). Each is RED-proven — introducing the
    /// corresponding erosion makes the snippet compile, and the doctest then FAILS.
    ///
    /// The field is private, so the raw value cannot be forged past `new`:
    ///
    /// ```compile_fail
    /// use delphi_runtime::launcher::VtName;
    /// // A pty would open the SEATLESS session `new` exists to reject.
    /// let forged = VtName("pts/3".to_string());
    /// ```
    ///
    /// No `Deref` escape hatch hands out the inner `String`:
    ///
    /// ```compile_fail
    /// use delphi_runtime::launcher::VtName;
    /// let vt = VtName::new("tty1").unwrap();
    /// let inner: &String = &*vt;
    /// ```
    ///
    /// No `into_inner` / `as_mut` accessor reaches or mutates it:
    ///
    /// ```compile_fail
    /// use delphi_runtime::launcher::VtName;
    /// let vt = VtName::new("tty1").unwrap();
    /// let owned: String = vt.into_inner();
    /// ```
    pub fn new(name: &str) -> Result<Self, RuntimeError> {
        let bad = || RuntimeError::Config {
            what: "PAM_TTY must be a virtual terminal `ttyN`, N in 1..=63 (a pty or malformed \
                   name opens a SEATLESS session that the active-local-seated gate denies)",
        };
        let digits = name.strip_prefix("tty").ok_or_else(bad)?;
        if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(bad());
        }
        let n: u16 = digits.parse().map_err(|_| bad())?;
        if !(1..=63).contains(&n) {
            return Err(bad());
        }
        Ok(Self(name.to_owned()))
    }

    /// The `ttyN` string to hand PAM as `PAM_TTY`.
    #[must_use]
    pub fn as_pam_tty(&self) -> &str {
        &self.0
    }

    /// Whether the corresponding `/dev/ttyN` is present as a character device on **this**
    /// machine. Deliberately **not** part of the constructor's invariant: the type guarantees
    /// the *form* `pam_systemd` can parse, while presence is a property of the machine. The
    /// launcher checks this before forking so a missing VT fails as "launch refused" rather
    /// than as a silently seatless session.
    #[must_use]
    pub fn exists_on_system(&self) -> bool {
        use std::os::unix::fs::FileTypeExt;
        std::fs::metadata(format!("/dev/{}", self.0))
            .map(|m| m.file_type().is_char_device())
            .unwrap_or(false)
    }
}

/// What to launch and as whom.
pub struct LaunchSpec<'a> {
    /// The shell binary to exec (B1: the minimal shell).
    ///
    /// # OBLIGATION — this binary must signal the readiness [`LaunchSpec::ready`] requires
    ///
    /// It writes [`crate::readiness::READY_DATAGRAM`] (a request delivered now reaches a live
    /// surface) or [`crate::readiness::SCAFFOLD_READY_DATAGRAM`] (the process is up) to
    /// [`SHELL_CHANNEL_FD`], or [`launch`] refuses it after
    /// [`crate::readiness::DEFAULT_READY_TIMEOUT`] and kills it.
    ///
    /// **The prose table that used to live here is now the `ready` field.** It listed which
    /// fixtures signal and which do not, which is documentation — weaker than a type, and D0-A
    /// A1 is the reason: an entry-signalling shell satisfied `launch()` identically to a
    /// surface-registering one, so it broke consent silently. Declaring the requirement makes
    /// the weaker producer REFUSED rather than merely undocumented.
    pub shell_path: &'a Path,
    /// The AI binary to exec (B1: the minimal AI).
    pub ai_path: &'a Path,
    /// The session user the children are dropped to.
    pub uid: Uid,
    /// The session group the children are dropped to.
    pub gid: Gid,
    /// The general socket the AI connects to (`approve.sock`).
    pub socket_path: &'a Path,
    /// The seat's VT the shell is provisioned on (§4 **R3-02a**: PRIMARY deployment — the
    /// Living Surface **is** the session on its seat). Handed to PAM as `PAM_TTY`, which is
    /// the whole seat obligation. A validated [`VtName`] rather than a string so a typo is
    /// refused at launch instead of producing a cleanly-opened but SEATLESS session that the
    /// gate then denies forever.
    ///
    /// VT **allocation policy** (how a free VT is chosen) is deliberately NOT here: R3-02a
    /// pins the *shape* (the seat's VT, PRIMARY), and choosing one is a separate concern that
    /// would widen the diff B-3's re-run REDs must bite against. C1 takes what the caller
    /// supplies.
    pub tty: &'a VtName,
    /// What the caller requires of the shell's readiness signal. Production (the daemon)
    /// requires [`crate::readiness::ReadySemantics::SurfaceLive`]; fixtures that signal at
    /// process entry declare `ScaffoldEntry` and are refused anywhere `SurfaceLive` is asked
    /// for (D0-A A1).
    pub ready: crate::readiness::ReadySemantics,
    /// Extra env passed only to the shell child (B1 test scaffolding: the scripted
    /// password — in production the human types it, never env).
    pub shell_env: &'a [(&'a str, &'a str)],
    /// Extra env passed only to the AI child (B1 test scaffolding: the fixed action —
    /// in production Brain decides it, never env).
    pub ai_env: &'a [(&'a str, &'a str)],
}

/// The launched children + the daemon's handles to them.
pub struct Children {
    /// The daemon's end of the private channel to the shell.
    pub daemon_channel: OwnedFd,
    /// The shell's pid.
    pub shell_pid: i32,
    /// The race-free pidfd pin of the shell (R3-03).
    pub shell_pidfd: OwnedFd,
    /// The AI's pid.
    pub ai_pid: i32,
}

/// Fork + exec the shell (channel fork-passed) and the AI (no channel), each
/// dropped to the session user, and pin the shell by pidfd.
///
/// # The two-phase launch contract (Increment D0)
///
/// `Ok` means **the shell is running and said so**, not merely that `execve` returned.
/// Two distinct signals are required, and they answer different questions:
///
/// 1. [`wait_for_child_setup`] — *did the child reach `execve`?* A `O_CLOEXEC` sync pipe,
///    so it is delivered **by the `execve` itself** and can say nothing about what happens
///    afterwards.
/// 2. [`readiness::await_shell_ready`] — *is the shell alive on the other side?* The shell
///    writes [`readiness::READY_DATAGRAM`] on the private channel once it is up.
///
/// Before D0 only (1) existed, so a shell that exec'd and then aborted was reported
/// **started** — measured live in P3a, where the daemon went on to service an action
/// against a dead shell. Do not remove (2) as redundant: (1) cannot observe a post-`execve`
/// death by construction, and (2) is the only thing that can.
///
/// The AI is forked **after** the shell is ready, so a failed shell launch never leaves an
/// orphaned AI running against a boundary that will not exist.
///
/// # Errors
///
/// [`RuntimeError::Syscall`] if the socketpair or pidfd fails;
/// [`RuntimeError::Filesystem`] if a child cannot be spawned;
/// [`RuntimeError::ShellSetupFailed`] if the child died before `execve`;
/// [`RuntimeError::ShellDiedBeforeReady`] / [`RuntimeError::ShellReadyTimeout`] if it
/// exec'd but never came up.
pub fn launch(spec: &LaunchSpec) -> Result<Children, RuntimeError> {
    // The private channel (1b): daemon keeps `.0`, the shell gets `.1` at fork.
    let (daemon_end, shell_end) = approval_socketpair()?;

    // The shell arrives ALREADY GUARDED: `fork_shell` arms in its own parent arm, before it
    // observes anything (D0-R4-02). From here to `Ok(Children)` the shell is a transaction —
    // every early return, `?` included, runs `Drop`.
    let shell_tx = fork_shell(spec, &shell_end)?;

    // Drop the daemon's copy of the shell's end BEFORE the readiness wait: while it holds
    // one, the channel never reaches EOF, so a dead shell would present as silence and burn
    // the full timeout instead of returning at once.
    drop(shell_end);

    // Phase 2 — the shell must SAY it is up (see the two-phase contract above). Under
    // leader == shell (R3-01c) killing it is also what releases its logind session and VT.
    readiness::await_shell_ready(
        daemon_end.as_fd(),
        shell_tx.pidfd(),
        readiness::DEFAULT_READY_TIMEOUT,
        spec.ready,
    )?;

    let ai_pid = fork_ai(spec)?;

    let (shell_pid, shell_pidfd) = shell_tx.into_parts();
    Ok(Children { daemon_channel: daemon_end, shell_pid, shell_pidfd, ai_pid })
}

/// A child created together with its pidfd — the parent arm never sees a bare pid.
enum SpawnResult {
    Parent { child: Pid, pidfd: OwnedFd },
    Child,
}

/// `clone3(CLONE_PIDFD)` — create the child and its pidfd **atomically** (D0-R5-01).
///
/// # Why not `fork()` + `pidfd_open`, and why there is no fallback to it
///
/// The pair leaves a window in which only a pid exists, and R4-01 justified that window with
/// "nothing has waited on the child yet, so its pid is reserved". **That is not sufficient on
/// Linux.** Measured: with `SIGCHLD` set to `SIG_IGN` the kernel auto-reaps, and
/// `pidfd_open` returns `ESRCH` while `waitpid` returns `ECHILD` — for a child nothing ever
/// waited on. `SA_NOCLDWAIT` and an async reaping handler do the same. The daemon does not
/// control every module that might set those.
///
/// The consequence was the defect R4-01 set out to remove: `pidfd_open` fails, the `?`
/// unwinds through an armed guard, and the guard signals a **raw pid that may already have
/// been recycled** — as root.
///
/// `clone3` closes it by construction: there is no interval to reason about, so no
/// precondition to be wrong about. **A fallback to `fork()` + `pidfd_open` is deliberately
/// NOT provided** — it would reinstate the exact defect this removes, and would do so on
/// precisely the systems whose kernel or seccomp policy is unusual. Refusing is fail-closed;
/// falling back is fail-open on the platforms least likely to be tested.
fn spawn_with_pidfd() -> Result<SpawnResult, RuntimeError> {
    let mut pidfd_raw: nix::libc::c_int = -1;
    let mut args: nix::libc::clone_args = unsafe { std::mem::zeroed() };
    args.flags = nix::libc::CLONE_PIDFD as u64;
    args.pidfd = std::ptr::addr_of_mut!(pidfd_raw) as u64;
    // Without this the child is not a SIGCHLD child and `waitpid` cannot reap it.
    args.exit_signal = nix::libc::SIGCHLD as u64;

    // SAFETY: `clone3` with a zeroed-then-populated `clone_args` of the size passed. No
    // CLONE_VM/CLONE_THREAD, so this has `fork` semantics: 0 in the child, pid in the parent.
    let rc = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_clone3,
            std::ptr::addr_of!(args),
            std::mem::size_of::<nix::libc::clone_args>(),
        )
    };
    if rc < 0 {
        let errno = nix::errno::Errno::last();
        if errno == nix::errno::Errno::ENOSYS {
            return Err(RuntimeError::Config {
                what: "clone3(CLONE_PIDFD) is unavailable (ENOSYS). Delphi requires Linux \
                       5.3+ with clone3 permitted by the seccomp policy — container runtimes \
                       with an older default profile block it. There is deliberately NO \
                       fallback: fork()+pidfd_open leaves a window in which a recycled pid \
                       could be SIGKILLed as root, so the launch refuses instead.",
            });
        }
        return Err(RuntimeError::Syscall { op: "clone3 (shell, shape (b))", source: errno });
    }
    if rc == 0 {
        return Ok(SpawnResult::Child);
    }
    // SAFETY: the kernel wrote a fresh owned descriptor into `pidfd_raw` on the parent path.
    let pidfd = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(pidfd_raw) };
    #[allow(clippy::cast_possible_truncation)] // a pid fits in i32 by definition
    Ok(SpawnResult::Parent { child: Pid::from_raw(rc as i32), pidfd })
}

/// Kills and reaps a launched shell unless the launch ran to completion (D0-R3-02/R4-01).
///
/// # The invariant became a kernel guarantee (D0-R4-01)
///
/// The first version signalled a raw pid and rested on "an unreaped zombie holds the pid".
/// That invariant was true when written and **removed by another fix in the same change** —
/// R3-04's `waitpid` reaped the child, after which the guard could root-`SIGKILL` a recycled
/// pid. So the guard now takes ownership of the **pidfd** and signals through it: targeting
/// the right process stops being something this code maintains and becomes something the
/// kernel enforces. Same move as removing the `revents` parameter (`DEFECT_CLASSES` 26) —
/// the only shape that has held.
///
/// The raw-pid window is now the few instructions between `fork()` and `pidfd::open`, where
/// nothing has yet waited on the child, so the pid provably cannot have been recycled.
struct ShellGuard {
    pid: i32,
    /// `None` only in the fork→`pidfd_open` window.
    pidfd: Option<OwnedFd>,
    armed: bool,
}

impl ShellGuard {
    /// Arm on a freshly forked child, before anything observes it.
    fn arm(pid: i32, pidfd: OwnedFd) -> Self {
        Self { pid, pidfd: Some(pidfd), armed: true }
    }

    /// The pidfd, for the readiness wait.
    ///
    /// # Panics
    ///
    /// If called before [`Self::attach_pidfd`] — a programming error, not a runtime one.
    fn pidfd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_ref().expect("pidfd attached before use").as_fd()
    }

    /// The launch completed: disarm and hand the shell to [`Children`].
    fn into_parts(mut self) -> (i32, OwnedFd) {
        self.armed = false;
        let fd = self.pidfd.take().expect("pidfd attached before use");
        (self.pid, fd)
    }
}

impl Drop for ShellGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // SAFETY: `pidfd_send_signal(pidfd, sig, NULL, 0)` on an owned, valid fd — immune to
        // pid reuse by construction. There is no raw-pid arm: since D0-R5-01 the handle
        // arrives WITH the child, so a guard without one cannot exist. The previous fallback
        // justified itself with "nothing has waited, so the pid is reserved", which is false
        // under SIGCHLD=SIG_IGN (measured) — leaving it as dead code would have preserved a
        // disproven claim for the next reader to trust.
        if let Some(fd) = self.pidfd.as_ref() {
            unsafe {
                nix::libc::syscall(
                    nix::libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    nix::libc::SIGKILL,
                    std::ptr::null::<nix::libc::siginfo_t>(),
                    0,
                );
            }
        }
        if !reap_within(self.pid, REAP_TIMEOUT) {
            tracing::warn!(
                shell_pid = self.pid,
                "shell did not exit within {REAP_TIMEOUT:?} of SIGKILL — leaving it UNREAPED \
                 rather than blocking the daemon. A task in uninterruptible sleep is the \
                 usual cause."
            );
        }
    }
}

/// Reap `pid`, giving up after `timeout`. Returns whether it was reaped.
///
/// `pub(crate)` since D0A-R6-03: `ChildReaper` in the daemon binary wrote its own UNBOUNDED
/// `waitpid`, which is the wedge this function already existed to prevent. One implementation,
/// so the reasoning below cannot be re-derived differently at a second site.
///
/// A blocking `waitpid` here can wedge the daemon's launch path: `SIGKILL` does not dislodge
/// a task in uninterruptible sleep, the kill may have failed outright, and `EINTR` would
/// restart an unbounded wait indefinitely. Bounded polling makes the worst case a logged,
/// leaked UNREAPED CHILD instead of a hung service.
///
/// # Examples
///
/// ```
/// // A pid that is not our child has NOTHING OUTSTANDING to reap: `waitpid` gives `ECHILD`,
/// // which this reports as reaped. The property worth pinning is the BOUND — it returns
/// // promptly rather than blocking, which is the whole reason the daemon shares it.
/// let started = std::time::Instant::now();
/// assert!(delphi_runtime::reap_within(1, std::time::Duration::from_millis(50)));
/// assert!(started.elapsed() < std::time::Duration::from_secs(2));
/// ```
#[must_use]
pub fn reap_within(pid: i32, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match nix::sys::wait::waitpid(Pid::from_raw(pid), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(REAP_POLL_INTERVAL);
            }
            // ONLY these two mean the child is gone. `Stopped`/`Continued`/`PtraceEvent` are
            // status changes of a LIVE child, and counting them as reaped (D0-R4-02) let a
            // stopped shell escape with its PAM session and VT.
            Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) => return true,
            Ok(_) => {
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(REAP_POLL_INTERVAL);
            }
            Err(nix::errno::Errno::EINTR) => {}         // retry against the same deadline
            Err(nix::errno::Errno::ECHILD) => return true, // already reaped
            Err(e) => {
                tracing::warn!(pid, error = %e, "could not reap the unready shell");
                return false;
            }
        }
    }
}

/// How long [`ShellGuard`] waits for a SIGKILLed shell before giving up.
const REAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// Poll interval while waiting for the corpse.
const REAP_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

/// Fork the shell via a **manual `fork()`** (shape (b), `docs/TRUST_MODEL.md` §4 R3-01b):
/// the child opens its OWN logind session and then `execve`s **in place**, so the session
/// leader IS the shell (R3-01c, leader == shell).
///
/// # Why not `Command`/`pre_exec` (the B1 shape)
///
/// The child must call `pam_open_session` **as root, before the privilege drop** — and PAM
/// is emphatically **not** async-signal-safe (it allocates, and `pam_systemd` talks D-Bus to
/// logind). `pre_exec` runs between `fork` and `execve`, where only async-signal-safe calls
/// are permitted, so PAM cannot live there.
///
/// # STANDING CONSTRAINT — this is safe ONLY because the daemon is single-threaded
///
/// Calling PAM in a post-`fork` child is safe here because `delphi-runtimed` is a plain
/// single-threaded `fn main()` (no tokio, no `thread::spawn` anywhere in this crate). In a
/// **multithreaded** parent this child could deadlock on an allocator lock held by a thread
/// that did not survive the fork. **If `delphi-runtimed` ever becomes multithreaded, this
/// shape is unsafe** and the child must move to the exec-a-helper shape: exec a small
/// single-threaded root helper that does PAM → priv-drop → `execve` the shell, which
/// preserves leader == shell because `execve` preserves the pid throughout.
fn fork_shell(spec: &LaunchSpec, shell_end: &OwnedFd) -> Result<ShellGuard, RuntimeError> {
    let chan_raw = shell_end.as_raw_fd();

    // ── SETUP-SYNC PIPE (P1 / B2A-C-R1-01) ──────────────────────────────────────────────
    // The manual fork's parent arm cannot see a child-side setup failure the way the old
    // `Command::spawn`/`pre_exec` path could (a failed `pre_exec` made `spawn()` return `Err`).
    // Restore that propagation: the child writes ONE byte to `sync_w` on any pre-`execve`
    // failure (via `child_diag`); a SUCCESSFUL `execve` CLOEXEC-closes `sync_w`, so the parent
    // reads EOF. `pipe2(O_CLOEXEC)` is REQUIRED — plain `pipe()` is NOT close-on-exec (verified
    // against nix 0.30 source: it calls raw `libc::pipe`), and a non-CLOEXEC write end would
    // ride the `execve` into the shell so the parent's read would block forever.
    let (sync_r, sync_w) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).map_err(|source| {
        RuntimeError::Syscall { op: "pipe2 (shell setup-sync)", source }
    })?;

    // SAFETY: manual fork. The parent path records the pid and reads the sync pipe; the child
    // path publishes the sync fd and runs the never-returning sequence — every child exit is an
    // `_exit(2)` (never `panic!`/`return`, which would unwind into a forked copy of the
    // daemon's stack and run its destructors twice).
    match spawn_with_pidfd()? {
        SpawnResult::Parent { child, pidfd } => {
            drop(sync_w); // the parent holds ONLY the read end
            // The pidfd arrived WITH the child (D0-R5-01), so the guard is armed on a handle
            // from its first instant — there is no window in which only a pid exists.
            let guard = ShellGuard::arm(child.as_raw(), pidfd);
            wait_for_child_setup(sync_r, child)?;
            Ok(guard)
        }
        SpawnResult::Child => {
            drop(sync_r); // the child holds ONLY the write end
            // Publish the write end so every `child_diag` can signal a failure. In the daemon
            // (and the tests' launch caller) fd 3 is already held, so `pipe2` returns fds > 3
            // and `sync_w` never collides with the `dup2(chan, SHELL_CHANNEL_FD)` below; the
            // debug_assert is the tripwire if that ever stops holding.
            let raw = sync_w.as_raw_fd();
            debug_assert!(raw > SHELL_CHANNEL_FD, "setup-sync fd {raw} collides with the channel fd");
            // `forget` the OwnedFd so its Drop does not close the raw fd we now rely on; the
            // kernel reclaims it on `execve` (CLOEXEC) or `_exit`.
            std::mem::forget(sync_w);
            CHILD_SYNC_FD.store(raw, Ordering::SeqCst);
            // Diverges: either it becomes the shell, or it `_exit`s non-zero.
            shell_child_become(spec, chan_raw)
        }
    }
}

/// Parent side of the setup-sync pipe (P1 / B2A-C-R1-01): block until the child either
/// `execve`s (the write end CLOEXEC-closes → EOF → the shell started) or writes a failure byte
/// then `_exit`s (→ the child died in its pre-`execve` setup). On failure, **reap the child**
/// (so it is not a zombie) and return [`RuntimeError::ShellSetupFailed`] rather than the false
/// `Ok` with a dead shell that this whole mechanism exists to prevent.
fn wait_for_child_setup(sync_r: OwnedFd, _child: Pid) -> Result<(), RuntimeError> {
    let mut byte = [0u8; 1];
    // SAFETY: single-byte read on the owned read end; the fd is valid for the call.
    let n = unsafe { nix::libc::read(sync_r.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
    if n == 0 {
        // EOF means ONLY that no process holds the write end. It does NOT prove the `execve`
        // succeeded — a pre-exec child killed before it could write its failure byte produces
        // the identical signal. An exit STATUS cannot settle it either: it supplies outcome,
        // not provenance, and an exec'd binary may exit with any 8-bit code (D0-R4-03).
        //
        // So this stops claiming provenance. The authority is the READINESS CONTRACT, whose
        // datagram can only be written by the exec'd program — D0 already built the post-exec
        // provenance signal, and a second marker could only disagree with it.
        return Ok(());
    }
    // A failure byte: the child reported a pre-`execve` failure. No wait here — the caller's
    // `ShellGuard` owns the kill and the reap, and a wait at this site would race it.
    Err(RuntimeError::ShellSetupFailed)
}

/// THE SHELL CHILD (shape (b)) — runs in the forked child, never returns.
///
/// Sequence, all in ONE pid so that leader == shell:
/// `dup2` channel → stdio policy → PAM session (root) → FD-01 sweep → priv-drop → `execve`.
fn shell_child_become(spec: &LaunchSpec, chan_raw: RawFd) -> ! {
    // Any failure before the execve exits non-zero; the parent observes the pidfd death.
    // `child_fail` performs the PAM unwind where a session is live (see below).
    if unsafe { nix::libc::dup2(chan_raw, SHELL_CHANNEL_FD) } < 0 {
        child_bail("dup2 channel");
    }

    // ── STDIO POLICY (explicitly decided, not inherited from the sweep's range start) ──
    // `mark_cloexec_except_raw` sweeps `close_range(3, ..)`, so 0/1/2 survive by the range
    // start — an implicit guarantee a future edit could silently remove. If 0/1/2 were ever
    // closed at exec, the shell's next `open()` would return fd 0 and anything writing to
    // "stdout" would corrupt that file. So the disposition is stated and enforced here:
    //   stdin  -> /dev/null   (the shell must never consume the daemon's input stream)
    //   stdout -> inherited   (the daemon is a systemd service => the journal; a GUI shell
    //   stderr -> inherited    has no terminal, and these are its only diagnostics)
    // # DECISION: stdout/stderr are inherited rather than /dev/null'd so WebKit/wry
    // diagnostics remain recoverable; the cost is that shell output is attributed to the
    // daemon's unit in the journal, which C2 addresses with a `SyslogIdentifier`.
    if !stdio_is_open_or_nulled() {
        child_bail("stdio policy (0/1/2 not open)");
    }

    // ── PAM: the child opens its OWN session, as root, before the drop ──
    // PAM_TTY=ttyN is the WHOLE seat obligation (§4 R3-02): pam_systemd derives
    // XDG_SEAT=seat0 and XDG_VTNR from the tty NAME, so no explicit XDG_* is set.
    let session = match open_own_session(spec) {
        Ok(s) => s,
        // The Err payload IS the diagnostic (a literal) — it names which PAM step failed,
        // including the PAM-03 refusal to run against an unselected stack.
        Err(why) => child_bail(why),
    };

    // ── FD-01 (P1) — mandatory pre-execve fd containment, EXPLICITLY ENUMERATED ──
    // THIS SWEEP MUST STAY AFTER `open_own_session` ABOVE. That call opens fds twice over:
    // PAM/`pam_systemd`'s D-Bus connection to logind, AND the descriptors
    // `sd_pid_get_session` opens for its cgroup lookup in the session-outcome guard. Both
    // are live in the pid that is about to BECOME the shell, and this sweep is the only
    // thing that contains them. Reordering — sweeping first, then opening the session —
    // would compile, pass every unit test, and silently ship the relay-bypass.
    // Under leader == shell the PAM/D-Bus fds are open in the very pid that becomes the
    // shell, so a leak here is the relay-bypass class B2A-R2-01 closed, one execve away.
    // The allowlist is minimal and stated: stdio (per the policy above) + the private
    // consent channel — the ONE descriptor §4 Reading A says survives into the shell.
    if crate::fdsec::mark_cloexec_except_raw(&[
        nix::libc::STDIN_FILENO,
        nix::libc::STDOUT_FILENO,
        nix::libc::STDERR_FILENO,
        SHELL_CHANNEL_FD,
    ])
    .is_err()
    {
        child_fail(session, "fd-discipline sweep");
    }

    // ── Privilege drop: setgroups([]) -> setgid -> setuid (setuid LAST) ──
    if drop_privileges(&RealPrivDropOps, spec.uid, spec.gid).is_err() {
        child_fail(session, "priv-drop");
    }

    // ══ THE UNWIND WINDOW CLOSES HERE ══════════════════════════════════════════════
    // Up to this point every failure path unwinds properly: pam_close_session (if the
    // session opened) + pam_end while the handle is still live (PAM-02, §4 R3-01c).
    // `leak()` deliberately surrenders that handle so `Session::Drop` cannot close the
    // session we are about to BECOME. Past this line there is no handle to close, so an
    // execve failure can only `_exit` and let logind reap the session by LEADER DEATH.
    // That is CORRECT and is exactly R3-01c's teardown model — not a missing unwind.
    // Do not "fix" it by reintroducing a close here: under leader == shell there is no
    // process left to hold the handle, and a close before execve would tear down the
    // session the shell is about to run in.
    let _token = session.leak();

    // ══ R3-01c SEAM — THE SINGLE BRANCH POINT ══════════════════════════════════════
    // PRODUCTION: exec in place, so the session leader IS the shell (R3-01c).
    // B-1 WEAKEN (RED-proof only, NEVER committed enabled): replace this ONE call with
    // `fork_grandchild_then_exec(spec)` to produce the leader != shell topology. The B-1
    // assertion MUST fail under that swap and pass on restore — a RED that fails because
    // the topology is wrong, not because the implementation is missing.
    exec_shell_in_place(spec)
}

// ═══════════════════════════════════════════════════════════════════════════════════
// THE SHELL CHILD'S HELPERS — every one of these runs POST-`fork`, PRE-`execve`.
//
// Standing discipline for this whole block (the forked-child contract):
//   * NEVER `panic!` / unwind — that would run the daemon's destructors in a forked
//     copy of its stack (double-close of the anchor's fds, double-unlink of the
//     socket). Every failure exit is a diverging `libc::_exit`.
//   * NEVER `std::process::exit` — it runs `atexit` handlers and flushes the FORKED
//     COPY of the parent's stdio buffers, duplicating whatever the daemon had
//     pending into the journal. `_exit` skips both.
//   * Diagnostics via `write(2)` to fd 2, not `eprintln!` — the same buffer-sharing
//     reason, plus `eprintln!` can panic on a closed fd.
// ═══════════════════════════════════════════════════════════════════════════════════

/// The PAM service whose **session** stack the shell child opens (§4 R3-01c PAM-03: the
/// stack MUST be deterministically chosen — never a fall-through to PAM's generic `other`,
/// since soundness cannot be claimed for a stack that was not deliberately selected).
/// Shipped by `installer/` as `/etc/pam.d/delphi-runtime`.
const PAM_SERVICE: &str = "delphi-runtime";

/// Exit status for any pre-`execve` child failure. Distinct from a shell exit code so the
/// parent can tell "the shell never started" from "the shell ran and exited".
const CHILD_SETUP_FAILED: i32 = 126;

/// The session-only PAM handle the shell child owns between `pam_open_session` and either
/// [`OwnSession::leak`] (success — `execve`) or [`child_fail`] (failure — full unwind).
///
/// # Why a raw `Context` pointer and not a held `Session`
///
/// `Session<'a, C>` borrows its `Context<C>`, so a struct holding both would be
/// self-referential. `pam_client2` provides the exact escape hatch: `Session::leak()` →
/// [`SessionToken`] and `Context::unleak_session(token)` → `Session` again. So this stores
/// the **detached** token plus an owning raw pointer to the heap `Context`, and rehydrates a
/// real `Session` only on the unwind path. No self-reference, and the unwind still runs the
/// genuine `pam_close_session`.
/// # Raw-pointer lifecycle
///
/// `ctx` is an owning raw pointer with a hand-maintained contract. The full answer to *who
/// frees it, whether `pam_end` double-frees, and why the success path abandons it* is
/// documented at the allocation site in [`open_own_session`] — read that before touching
/// either this type or [`child_fail`]. Note the deliberate absence of a `Drop` impl: an
/// implicit free would be a second reclaim on whichever path already frees.
struct OwnSession {
    /// Owning pointer to the heap `Context` — reclaimed (running `pam_end` + the struct
    /// free) ONLY by [`child_fail`]. Deliberately abandoned on the success path, where
    /// `execve` replaces the address space (see [`OwnSession::leak`]).
    ctx: *mut Context<NullConv>,
    /// The detached session, re-attachable via `Context::unleak_session`.
    token: SessionToken,
}

impl OwnSession {
    /// Surrender the handle for the `execve` (§4 R3-01c PAM-02's post-`execve` clause).
    ///
    /// Deliberately does **not** reclaim `ctx`, so no `pam_close_session` and no `pam_end`
    /// run: under leader == shell this pid is *about to become* the session's own leader, and
    /// closing here would tear down the very session the shell is going to run in. Teardown
    /// is by **leader death** — the shell's exit is the session's. The `Context` allocation
    /// is intentionally leaked; `execve` replaces the address space microseconds later.
    fn leak(self) -> SessionToken {
        let Self { ctx: _, token } = self;
        token
    }
}

/// Enforce the child's stdio policy, returning `false` if it could not be established.
///
/// * **stdin → `/dev/null`, unconditionally.** The shell must never consume bytes from the
///   daemon's own input stream.
/// * **stdout/stderr → inherited** (the daemon is a systemd service, so these are its journal
///   stream; a GUI shell has no terminal and these are its only diagnostics) — **unless** the
///   descriptor is not open, in which case it too gets `/dev/null`.
///
/// # Why this is not left to the sweep's range start
///
/// [`crate::fdsec::mark_cloexec_except_raw`] sweeps from fd 3 up, so 0/1/2 survive *by the
/// range start* — an implicit guarantee a future edit to that constant would silently remove.
/// Worse, if 0/1/2 were ever closed at `execve`, the shell's next `open()` would be handed
/// **fd 0**, and any subsequent write to "stdout" would corrupt that file. Guaranteeing all
/// three are open here makes that corruption impossible **by construction**, independent of
/// the sweep's range.
fn stdio_is_open_or_nulled() -> bool {
    // SAFETY: plain syscalls on fixed fd numbers in a single-threaded forked child. No
    // allocation, no locks — async-signal-safe.
    unsafe {
        let devnull = nix::libc::open(c"/dev/null".as_ptr(), nix::libc::O_RDWR);
        if devnull < 0 {
            return false;
        }
        // stdin is ALWAYS replaced, open or not.
        let mut ok = nix::libc::dup2(devnull, nix::libc::STDIN_FILENO) >= 0;
        // stdout/stderr are inherited when open; nulled only if they are not.
        for fd in [nix::libc::STDOUT_FILENO, nix::libc::STDERR_FILENO] {
            if nix::libc::fcntl(fd, nix::libc::F_GETFD) < 0 {
                ok &= nix::libc::dup2(devnull, fd) >= 0;
            }
        }
        if devnull > nix::libc::STDERR_FILENO {
            nix::libc::close(devnull);
        }
        ok
    }
}

/// Open the child's **own** logind session as root (shape (b), §4 R3-01b).
///
/// `PAM_TTY=ttyN` is the **whole** seat obligation (§4 R3-02): `pam_systemd` derives
/// `XDG_SEAT=seat0` and `XDG_VTNR=N` from the tty **name** itself, so `XDG_SEAT`/`XDG_VTNR`
/// are deliberately **not** set — recon measured them to be redundant.
///
/// The conversation handler is the **null** handler: this stack is session-only (no
/// `pam_authenticate` precedes it — R3-02's credential authentication is a separate,
/// channel-routed stack in [`crate::pam`]), so nothing should prompt. If a module does
/// prompt, the null handler fails the call, which is the correct fail-closed answer for an
/// unattended session open.
///
/// The `Err` is a `&'static str` — the exact diagnostic [`child_bail`] will `write(2)`. A
/// typed error would allocate and would have no one to inspect it: the caller diverges to
/// `_exit` on every failure. A literal keeps the failure both allocation-free and specific
/// (CLAUDE.md §8 — an error must name what to *do*, not just that something broke).
fn open_own_session(spec: &LaunchSpec) -> Result<OwnSession, &'static str> {
    // ── PAM-03 GUARD: refuse a stack that was not deliberately selected ──────────────
    // §4 R3-01c Amendment B: soundness of the session-only deviation is a property of the
    // SPECIFIC validated `delphi-runtime` stack, not of PAM in general. `pam_start` does NOT
    // fail on a missing service file — libpam silently falls through to `/etc/pam.d/other`,
    // whose content is a deployment accident (on a hardened host `pam_deny`, on a permissive
    // one `pam_permit`, which would open a session under a stack nobody reviewed). Neither
    // outcome may be claimed sound, so the launcher REFUSES rather than inheriting it. This
    // mirrors the recon binary's round-2 PAM-03 fix, moved onto the production path.
    //
    // This is a `access(F_OK)` check, so it is inherently TOCTOU-racy against the file being
    // removed between here and `pam_start`. That is acceptable and not the threat: the file
    // is root-owned in a root-owned directory, so an attacker who can delete it already has
    // root. The guard exists to catch the DEPLOYMENT error (C2 has not shipped the stack
    // yet), not to defend a boundary.
    if unsafe { nix::libc::access(c"/etc/pam.d/delphi-runtime".as_ptr(), nix::libc::F_OK) } != 0 {
        return Err("PAM service stack /etc/pam.d/delphi-runtime is missing — refusing to \
                    fall through to PAM's generic `other` stack (TRUST_MODEL.md §4 R3-01c \
                    PAM-03). Install the stack shipped by installer/ and retry.");
    }

    // uid → username for `pam_start`. `getpwuid_r` allocates; that is within this child's
    // documented standing constraint (the daemon is single-threaded, and PAM itself
    // allocates far more), and it happens before any privilege change.
    let user = match nix::unistd::User::from_uid(spec.uid) {
        Ok(Some(u)) => u.name,
        _ => return Err("no passwd entry for the session uid (pam_start needs a username)"),
    };

    // ── RAW-POINTER LIFECYCLE (the one unsafe surface on this path) ──────────────────
    // The heap `Context` is handed to `Box::into_raw` so it can outlive this function's
    // stack frame without a self-referential struct (see `OwnSession`). Three questions a
    // future reader will have, answered here so nobody has to re-derive them:
    //
    // (a) WHO FREES IT? Exactly one of two places, never both:
    //       * `child_fail` — reclaims via `Box::from_raw` and drops it. THE ONLY free.
    //       * `OwnSession::leak` — deliberately abandons it (see (c)).
    //     Nothing else may reclaim this pointer. `OwnSession` intentionally has no `Drop`:
    //     an implicit free would be a second reclaim on whichever path also frees.
    //
    // (b) IS THERE A DOUBLE-FREE WITH `pam_end`? NO — verified against the crate source
    //     (pam-client2-0.5.5 src/context.rs:120-124, 735-742). `Context` owns only
    //     `handle: PamHandle` (a NonNull into LIBPAM's allocation) plus a `Cell` and a
    //     `PhantomData`. `Context::Drop` calls `pam_end(handle)` — freeing libpam's
    //     allocation — and frees the crate's own conversation box. The Rust `Context`
    //     STRUCT's allocation is a separate thing, owned solely by our `Box`. So one
    //     `Box::from_raw(..)` + drop = one `Context::Drop` = one `pam_end`, then the struct's
    //     own free. Two distinct allocations, each freed once. No double-free.
    //
    // (c) THE SUCCESS PATH ABANDONS THE POINTER — AND THAT IS CORRECT, DO NOT "FIX" IT.
    //     After `OwnSession::leak` the pointer is never reclaimed: no `pam_end`, no struct
    //     free. This is not a bug and not an oversight. `execve` replaces the entire address
    //     space microseconds later, so "leaking" here frees nothing that outlives the call —
    //     while running `Context::Drop` instead would `pam_end` the transaction of the very
    //     session this pid is about to BECOME the leader of. Adding a free here to silence a
    //     leak-checker would break leader == shell (R3-01c). It is deliberate; leave it.
    let ctx = Box::into_raw(Box::new(
        Context::new(PAM_SERVICE, Some(&user), NullConv::new())
            .map_err(|_| "pam_start failed for service `delphi-runtime`")?,
    ));

    // SAFETY: `ctx` is freshly out of `Box::into_raw`, non-null, and unaliased — each
    // reborrow below is bounded to its own statement, and no reference derived from it is
    // live across the `fail` reclaim. Per (a), `fail` is the sole free on these paths.
    let fail = |ctx: *mut Context<NullConv>, why: &'static str| {
        drop(unsafe { Box::from_raw(ctx) }); // pam_end + struct free, handle still live
        Err(why)
    };

    if unsafe { &mut *ctx }.set_tty(Some(spec.tty.as_pam_tty())).is_err() {
        return fail(ctx, "pam_set_item(PAM_TTY) failed");
    }

    // Becoming the session LEADER happens here — `pam_systemd` makes the calling pid the
    // leader, and `execve` later preserves that pid. That is leader == shell (R3-01c).
    let token = match unsafe { &mut *ctx }.open_session(Flag::NONE) {
        Ok(session) => session.leak(),
        Err(_) => return fail(ctx, "pam_open_session failed"),
    };

    // ── PAM-03, SECOND FORM: assert the OUTCOME, not the config ─────────────────────
    // The existence guard above catches "no stack". It CANNOT catch the worse case: a
    // stack that exists but whose `session` group is EMPTY (no `pam_systemd.so`). There,
    // `pam_open_session` returns success while registering NO logind session — and the
    // failure surfaces far away, as a shell that resolves to no session and is denied by
    // the seated gate forever. That is `VtName`'s seatless-string failure one level up: a
    // cleanly-succeeding call that yields no session.
    //
    // # Why an outcome check and not a config parse
    //
    // Grepping the file for a `session` line would be the Class-14 mistake this very
    // guard is fixing — it covers one FORM and misses the others (`@include`,
    // `session include`, `substack`, a module that loads but no-ops). Following includes
    // means writing a PAM config parser in a forked pre-`execve` child. So the guard
    // reads what the call DID, not the markers the config carries: after a successful
    // `open_session` this pid MUST resolve to a logind session. That is exactly the
    // property the rest of the design depends on, checked directly and form-independently.
    //
    // Note this asserts session EXISTENCE only, deliberately — not active/seated. The
    // active-local-seated GATE is the daemon's job, applied later to the pinned shell pid
    // (R3-02); duplicating it here would fail launches for a transient VT foreground state
    // that the gate is designed to evaluate at consent time.
    // ORDERING IS LOAD-BEARING FOR FD-01 — DO NOT MOVE THIS CHECK LATER.
    // `sd_pid_get_session` reads cgroup state and OPENS FILE DESCRIPTORS to do it. This
    // whole function runs BEFORE the caller's `mark_cloexec_except_raw` sweep, so those
    // fds are contained by it (verified: `shell_child_become` calls `open_own_session`,
    // then the sweep, then priv-drop, then execve). Relocating this check — or the
    // `open_own_session` call — to AFTER the sweep would leak libsystemd's descriptors
    // into the shell across the `execve`: the exact relay-bypass class B2A-R2-01 closed
    // and that §4 FD-01 made mandatory on this path. The sweep is the ONLY containment;
    // anything that opens an fd must run upstream of it.
    //
    // THIS CHECK IS LOAD-BEARING — MEASURED, NOT ASSUMED.
    // `pam_open_session` against a stack whose `session` group is EMPTY returns
    // **rc=0 (PAM_SUCCESS)**. Measured 2026-07-22 as root on the seated dev VM
    // (Ubuntu 26.04, systemd 259) via `scratch/pam-empty-group-probe.sh`, which builds a
    // throwaway service with `auth`+`account` only and calls `pam_open_session` on it.
    // Confound ruled out: the probe prints the stack in force (no `session` line), and a
    // success return carries no error text to misread.
    //
    // THE GENERAL LESSON, worth more than this one call site: `pam_open_session`'s SUCCESS
    // RETURN CARRIES ALMOST NO INFORMATION BY ITSELF. At the return value an empty session
    // group is INDISTINGUISHABLE from a fully working one — both are 0. So "the call
    // succeeded" cannot be used to infer "a session exists"; the property must be VERIFIED
    // against logind, which is what the line below does. This is the same discipline as the
    // consent gate trusting logind over any self-reported signal: ask the authority, do not
    // infer from a return code.
    //
    // Without this check a session-less stack yields a cleanly-succeeding, entirely
    // SESSIONLESS launch — and the failure surfaces arbitrarily far away, as a shell the
    // seated gate denies forever.
    if crate::logind::session_id_for_pid(nix::unistd::getpid().as_raw()).is_none() {
        // PAM-02 unwind. A session IS open here (open_session succeeded), so it must be
        // closed while the handle is live — `child_fail` is the audited path that does
        // exactly that (`unleak_session(token).close()` then `pam_end` via the Box drop).
        // It is reused rather than reimplemented: an inline `drop(token)` would NOT close
        // the session, it would silently discard the handle. `child_fail` diverges, which
        // is sound here because `open_own_session` is private and runs only in the forked
        // child (see `shell_child_become`), where every failure ends in `_exit` anyway.
        child_fail(OwnSession { ctx, token }, PAM03_EMPTY_SESSION_GROUP);
    }

    Ok(OwnSession { ctx, token })
}

/// The diagnostic for the empty-`session`-group case (see the outcome check above). A
/// module-level const so the B-1 lane's tests can pin the exact message.
pub(crate) const PAM03_EMPTY_SESSION_GROUP: &str =
    "pam_open_session succeeded but registered NO logind session — /etc/pam.d/delphi-runtime \
     exists yet its `session` group is empty or lacks pam_systemd.so (TRUST_MODEL.md §4 \
     R3-01c PAM-03). The shell would resolve to no session and the seated gate would deny \
     every consent. Add `session required pam_systemd.so` to the stack.";

/// Write a diagnostic for a pre-`execve` child failure straight to fd 2.
///
/// `write(2)` rather than `eprintln!`: the child shares the parent's buffered stdio, so
/// formatted printing would risk duplicating the daemon's pending output, and `eprintln!`
/// panics on a write error. `what` is always a string **literal**, so this allocates nothing.
fn child_diag(what: &str) {
    // SAFETY: three `write(2)` calls on fd 2 with borrowed, correctly-sized buffers. Return
    // values are deliberately ignored — a failed diagnostic must not change the exit path.
    unsafe {
        let prefix = b"delphi-runtimed: shell child failed before execve: ";
        nix::libc::write(2, prefix.as_ptr().cast(), prefix.len());
        nix::libc::write(2, what.as_ptr().cast(), what.len());
        nix::libc::write(2, b"\n".as_ptr().cast(), 1);
    }
    // P1 / B2A-C-R1-01: signal the PARENT that this child died pre-`execve`. One byte on the
    // setup-sync write end; the parent's blocking read returns it instead of the EOF a
    // successful `execve` would deliver. Guarded on `>= 0` so it is a no-op in the parent (or
    // before the child publishes the fd). The fd is still open — CLOEXEC only closes it on
    // `execve`, which by definition has not happened on any failure path.
    let sfd = CHILD_SYNC_FD.load(Ordering::SeqCst);
    if sfd >= 0 {
        // SAFETY: one-byte write on the sync write end; return value ignored (a failed signal
        // must not change the exit path).
        unsafe {
            nix::libc::write(sfd, b"x".as_ptr().cast(), 1);
        }
    }
}

/// Diverge from a child failure with **no** live PAM session to unwind.
///
/// Used for every step before `pam_open_session` succeeds, and for a failed `execve` (past
/// which the session is deliberately leaked — see [`OwnSession::leak`]).
fn child_bail(what: &str) -> ! {
    child_diag(what);
    // SAFETY: `_exit` terminates immediately without running atexit handlers or flushing the
    // forked copy of the parent's stdio buffers. Diverges.
    unsafe { nix::libc::_exit(CHILD_SETUP_FAILED) }
}

/// Diverge from a child failure **while a PAM session is live** — the PAM-02 unwind.
///
/// §4 R3-01c PAM-02: *every* pre-`execve` failure path MUST `pam_close_session` (the session
/// was opened) **and** `pam_end` while the handle is still live. The "no close is possible"
/// rationale that justifies omitting the close on the success path holds **only
/// post-`execve`**, where leader == shell means no process survives to close it. Here the
/// process very much does survive — for the microseconds it takes to unwind — so it must.
fn child_fail(session: OwnSession, what: &str) -> ! {
    let OwnSession { ctx, token } = session;
    // SAFETY: `ctx` is the sole owning pointer from `open_own_session`'s `Box::into_raw`, not
    // yet reclaimed (only `OwnSession::leak` skips the reclaim, and it consumes the value).
    // Reclaiming it here runs `Context::Drop` => `pam_end` after the explicit close below.
    let mut ctx = unsafe { Box::from_raw(ctx) };
    // Re-attach the leaked session so the REAL `pam_close_session` runs, then let the Box
    // drop run `pam_end`. Errors are ignored: we are already on a failure path and must
    // still exit — but the close is genuinely attempted, not skipped.
    let _ = ctx.unleak_session(token).close(Flag::NONE);
    drop(ctx);
    child_bail(what)
}

/// Build the shell's `argv` and `envp`, inheriting the daemon's environment and layering on
/// `DELPHI_CHANNEL_FD` plus [`LaunchSpec::shell_env`] (last write wins, matching the
/// `Command::env` semantics this path replaced).
///
/// `Err(())` if any path or variable contains an interior NUL and so cannot cross `execve`.
fn shell_argv_envp(spec: &LaunchSpec) -> Result<(CString, Vec<CString>), ()> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let path = CString::new(spec.shell_path.as_os_str().as_bytes()).map_err(|_| ())?;

    let overrides: Vec<(&str, String)> = std::iter::once((
        crate::scaffold_env::CHANNEL_FD,
        SHELL_CHANNEL_FD.to_string(),
    ))
    .chain(spec.shell_env.iter().map(|(k, v)| (*k, (*v).to_owned())))
    .collect();

    let mut envp: Vec<CString> = Vec::new();
    for (k, v) in std::env::vars_os() {
        // Inherited entries an override supersedes are dropped here so the override is the
        // only definition of that key in `envp`.
        if overrides.iter().any(|(ok, _)| k.as_bytes() == ok.as_bytes()) {
            continue;
        }
        let mut entry = k.into_vec();
        entry.push(b'=');
        entry.extend_from_slice(v.as_bytes());
        envp.push(CString::new(entry).map_err(|_| ())?);
    }
    for (k, v) in &overrides {
        envp.push(CString::new(format!("{k}={v}")).map_err(|_| ())?);
    }

    Ok((path, envp))
}

/// **PRODUCTION** — `execve` the shell **in this very pid**, so the session leader IS the
/// shell (§4 R3-01c, leader == shell).
///
/// Diverges: `execve` only returns on failure, and the caller has already leaked the PAM
/// handle, so the only remaining move is `_exit` and let logind reap the session by leader
/// death — which is exactly R3-01c's teardown model, not a missing unwind.
fn exec_shell_in_place(spec: &LaunchSpec) -> ! {
    let Ok((path, envp)) = shell_argv_envp(spec) else {
        child_bail("build shell argv/envp");
    };
    let argv = [path.clone()];
    match nix::unistd::execve(&path, &argv, &envp) {
        Ok(never) => match never {},
        Err(_) => child_bail("execve shell"),
    }
}

/// **B-1 WEAKEN TWIN — NEVER CALLED IN PRODUCTION.** Stay as a session-holder and `fork()`
/// the shell as a **grandchild**, producing the leader != shell topology R3-01c rejected.
///
/// # Why this exists, and why it is a source edit rather than a `cfg`
///
/// B-1's `leader == shell` regression test must be **verified to bite**: a test that passes
/// against a wrong implementation is worse than no test (§6, the Codex round-3 precedent).
/// Proving it bites means running it against a real leader != shell launcher — this one. The
/// swap is a **deliberate one-line source edit** at the marked seam in
/// [`shell_child_become`], *not* a `cfg`/feature flag: a compiled-in weakened path could ship
/// by accident, whereas an edit is visible in the diff and cannot survive review.
///
/// Under this topology, recon Phase D measured the failure R3-01c exists to prevent: killing
/// the session-holder leaves the session `closing` but not torn down, and the orphaned shell
/// **survives**, still cgroup-resolving to it. Do not wire this up.
pub fn fork_grandchild_then_exec(spec: &LaunchSpec) -> ! {
    // SAFETY: same forked-child contract as `fork_shell`. The grandchild diverges into
    // `execve`; this process stays behind as the session holder — the very topology the
    // weaken is demonstrating.
    match unsafe { nix::unistd::fork() } {
        Err(_) => child_bail("fork grandchild (weaken twin)"),
        Ok(nix::unistd::ForkResult::Child) => exec_shell_in_place(spec),
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            // B2A-C-R1-01: the holder MUST close its copy of the setup-sync write end. The
            // grandchild's `execve` CLOEXEC-closes ITS copy, but the parent's
            // `wait_for_child_setup` reads EOF only when ALL copies are closed — without this
            // it would HANG under the B-1 weaken (leader != shell). Closing here lets the
            // grandchild's `execve` deliver EOF so the parent returns `Ok(holder_pid)` and B-1
            // can measure the leader != shell topology. This coupling exists ONLY because the
            // weaken twin mirrors the production child; production never forks here.
            let sfd = CHILD_SYNC_FD.swap(-1, Ordering::SeqCst);
            if sfd >= 0 {
                // SAFETY: closing the holder's own copy of the sync write end.
                unsafe { nix::libc::close(sfd) };
            }
            // Hold the session open for as long as the shell runs, then exit with its status
            // — without this the holder would exit immediately and orphan the shell at once.
            let mut status: nix::libc::c_int = 0;
            // SAFETY: `waitpid` on our own child with a valid out-pointer.
            unsafe { nix::libc::waitpid(child.as_raw(), &mut status, 0) };
            // SAFETY: diverging `_exit`, per the forked-child contract.
            unsafe { nix::libc::_exit(CHILD_SETUP_FAILED) }
        }
    }
}

/// Fork the AI: keep NOTHING (never the channel), drop, exec; it connects to the
/// general socket by path.
fn fork_ai(spec: &LaunchSpec) -> Result<i32, RuntimeError> {
    let (uid, gid) = (spec.uid, spec.gid);

    let mut cmd = Command::new(spec.ai_path);
    cmd.env(crate::scaffold_env::APPROVE_SOCK, spec.socket_path);
    for (k, v) in spec.ai_env {
        cmd.env(k, v);
    }
    // SAFETY: as fork_shell, but the keep-list is EMPTY — no daemon fd survives the
    // AI's execve (R4-02). Allocation-free.
    unsafe {
        cmd.pre_exec(move || {
            crate::fdsec::mark_cloexec_except_raw(&[])
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            drop_privileges(&RealPrivDropOps, uid, gid).map_err(priv_to_io)?;
            Ok(())
        });
    }
    spawn_pid(cmd, spec.ai_path)
}

fn spawn_pid(mut cmd: Command, path: &Path) -> Result<i32, RuntimeError> {
    let child = cmd.spawn().map_err(|source| RuntimeError::Filesystem {
        op: "spawn child",
        path: PathBuf::from(path),
        source,
    })?;
    Ok(child.id() as i32)
}

/// Map a privilege-drop error to an allocation-free `io::Error` for the pre_exec
/// closure (the 1D-03 discipline — `from_raw_os_error` wraps an int, no `Box`).
fn priv_to_io(e: RuntimeError) -> io::Error {
    match e {
        RuntimeError::Syscall { source, .. } => io::Error::from_raw_os_error(source as i32),
        _ => io::Error::from_raw_os_error(nix::libc::EPERM),
    }
}

#[cfg(test)]
mod tests {
    /// **D0-R3-02 — cleanup is structural, not per-error-path.**
    ///
    /// The NON-ATOMIC pair, kept as a weaken twin and never called in production.
    ///
    /// Mirrors the pre-R5-01 `fork()` + `pidfd_open`, including the interval between them.
    /// The interval is the point: production had one too, it was simply short.
    #[cfg(test)]
    fn spawn_pair_nonatomic_twin() -> Result<(), nix::errno::Errno> {
        // SAFETY: the child diverges via `_exit`; the parent only opens a pidfd.
        match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => unsafe { nix::libc::_exit(0) },
            nix::unistd::ForkResult::Parent { child } => {
                unsafe { nix::libc::usleep(20_000) }; // let the child exit first
                let rc = unsafe {
                    nix::libc::syscall(nix::libc::SYS_pidfd_open, child.as_raw(), 0)
                };
                if rc < 0 {
                    return Err(nix::errno::Errno::last());
                }
                unsafe { nix::libc::close(rc as nix::libc::c_int) };
                let _ = nix::sys::wait::waitpid(child, None);
                Ok(())
            }
        }
    }

    /// **D0-R5-01 — the pid-reservation precondition does not hold, so it is gone.**
    ///
    /// MEASURED: with `SIGCHLD` = `SIG_IGN` the kernel auto-reaps, so a child nothing ever
    /// waited on yields `pidfd_open` → `ESRCH` and `waitpid` → `ECHILD`.
    ///
    /// **BOTH LEGS ARE REQUIRED.** The first draft asserted only that `spawn_with_pidfd`
    /// succeeds, and PASSED against the weakened `fork()`+`pidfd_open` implementation — the
    /// parent simply won the race, because the draft had no interval where production has a
    /// short one. Asserting the twin FAILS under the same disposition is what makes the pair
    /// discriminating rather than decorative.
    ///
    /// Run in a SUBPROCESS: `SIG_IGN` is process-wide and would break every other test's
    /// `waitpid`.
    #[test]
    fn spawn_with_pidfd_survives_sigchld_ignored_where_the_pair_does_not() {
        let (r, w) = nix::unistd::pipe().expect("pipe");
        // SAFETY: the child performs raw syscalls only and diverges via `_exit`.
        match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => {
                unsafe { nix::libc::signal(nix::libc::SIGCHLD, nix::libc::SIG_IGN) };
                // bit 0: the atomic spawn produced a handle. bit 1: the twin FAILED, i.e.
                // the hazard is real on this kernel and the test is not vacuous.
                let mut bits = 0u8;
                match spawn_with_pidfd() {
                    Ok(SpawnResult::Child) => unsafe { nix::libc::_exit(0) },
                    Ok(SpawnResult::Parent { .. }) => bits |= 1,
                    Err(_) => {}
                }
                if spawn_pair_nonatomic_twin().is_err() {
                    bits |= 2;
                }
                unsafe { nix::libc::write(w.as_raw_fd(), std::ptr::addr_of!(bits).cast(), 1) };
                unsafe { nix::libc::_exit(0) };
            }
            nix::unistd::ForkResult::Parent { child } => {
                drop(w);
                let mut got = [0u8; 1];
                // SAFETY: bounded read on the owned read end.
                let n = unsafe { nix::libc::read(r.as_raw_fd(), got.as_mut_ptr().cast(), 1) };
                let _ = nix::sys::wait::waitpid(child, None);
                assert_eq!(n, 1, "the probe child did not report");
                assert_eq!(
                    got[0] & 2,
                    2,
                    "the non-atomic twin SUCCEEDED under SIGCHLD=SIG_IGN — the hazard did not \
                     reproduce, so this run cannot certify the atomic spawn either"
                );
                assert_eq!(
                    got[0] & 1,
                    1,
                    "spawn_with_pidfd failed under SIGCHLD=SIG_IGN, where the pair also fails \
                     — atomicity is exactly what should make it survive"
                );
            }
        }
    }

    /// Root-free: exercises the guard itself rather than `launch()` (which needs PAM), so the
    /// mechanism is proven on every box. The composition — `launch()` with a bad `ai_path` —
    /// is asserted in `leader_is_shell.rs` and runs only on the root lane.
    #[test]
    fn an_armed_shell_guard_kills_its_child_on_drop() {
        // Built with the REAL primitive, so these tests exercise the atomic pair rather than
        // a `fork` the production path no longer uses.
        let (pid, pidfd) = match spawn_with_pidfd().expect("clone3") {
            SpawnResult::Child => {
                unsafe { nix::libc::pause() };
                unsafe { nix::libc::_exit(0) };
            }
            SpawnResult::Parent { child, pidfd } => (child.as_raw(), pidfd),
        };
        let g = ShellGuard::arm(pid, pidfd);

        drop(g);

        // Reaped by the guard, so the pid is gone: a second wait must report ECHILD rather
        // than a live child. Checking `kill(pid, 0)` instead would be unsound — the pid may
        // already have been recycled by the time we look.
        let again = nix::sys::wait::waitpid(Pid::from_raw(pid), Some(WaitPidFlag::WNOHANG));

        // Clean up BEFORE asserting. A `pause()`ing child that outlives a failed assertion
        // holds cargo's captured stdout/stderr open, so the harness never sees EOF and WEDGES
        // instead of reporting the failure — measured while weakening this very test. A test
        // whose failure mode is a hang cannot be used as evidence (Iron Law 15 clause 2's
        // intermittent case, in its worst form).
        if !matches!(again, Err(nix::errno::Errno::ECHILD)) {
            unsafe { nix::libc::kill(pid, nix::libc::SIGKILL) };
            let _ = nix::sys::wait::waitpid(Pid::from_raw(pid), None);
        }
        assert!(
            matches!(again, Err(nix::errno::Errno::ECHILD)),
            "guard must have killed AND reaped the shell, got: {again:?}"
        );
    }

    /// A disarmed guard leaves the child alone — otherwise a SUCCESSFUL launch would kill the
    /// shell it just started, and `an_armed_shell_guard_kills_its_child_on_drop` could pass
    /// against a guard that kills unconditionally.
    #[test]
    fn a_disarmed_shell_guard_leaves_its_child_running() {
        // Built with the REAL primitive, so these tests exercise the atomic pair rather than
        // a `fork` the production path no longer uses.
        let (pid, pidfd) = match spawn_with_pidfd().expect("clone3") {
            SpawnResult::Child => {
                unsafe { nix::libc::pause() };
                unsafe { nix::libc::_exit(0) };
            }
            SpawnResult::Parent { child, pidfd } => (child.as_raw(), pidfd),
        };
        let g = ShellGuard::arm(pid, pidfd);

        drop(g.into_parts()); // completing the launch disarms

        let status = nix::sys::wait::waitpid(Pid::from_raw(pid), Some(WaitPidFlag::WNOHANG));
        assert!(
            matches!(status, Ok(WaitStatus::StillAlive)),
            "a disarmed guard must not touch the child, got: {status:?}"
        );

        unsafe { nix::libc::kill(pid, nix::libc::SIGKILL) };
        let _ = nix::sys::wait::waitpid(Pid::from_raw(pid), None);
    }


    /// **D0-R2-04.** `reap_within` must return on a child that outlives the budget rather
    /// than blocking. The forced shape: a child that ignores nothing but is simply still
    /// alive — an unbounded `waitpid` here never returns, which is the wedge this bounds.
    #[test]
    fn reap_within_gives_up_on_a_child_that_outlives_the_budget() {
        // SAFETY: the child only sleeps and `_exit`s — raw syscalls, no allocation.
        let pid = match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => {
                unsafe { nix::libc::sleep(30) };
                unsafe { nix::libc::_exit(0) };
            }
            nix::unistd::ForkResult::Parent { child } => child,
        };

        let t0 = std::time::Instant::now();
        let reaped = super::reap_within(pid.as_raw(), std::time::Duration::from_millis(200));
        let elapsed = t0.elapsed();

        assert!(!reaped, "a live child must not report as reaped");
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "reap_within blocked for {elapsed:?} — the bound is not bounding"
        );

        // SAFETY: clean up our own child.
        unsafe { nix::libc::kill(pid.as_raw(), nix::libc::SIGKILL) };
        let _ = nix::sys::wait::waitpid(pid, None);
    }

    /// The ordinary path: an already-dead child is reaped promptly.
    #[test]
    fn reap_within_reaps_a_dead_child() {
        // SAFETY: the child exits immediately.
        let pid = match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => unsafe { nix::libc::_exit(0) },
            nix::unistd::ForkResult::Parent { child } => child,
        };
        assert!(super::reap_within(pid.as_raw(), std::time::Duration::from_secs(2)));
    }
    use super::*;

    /// **B2A-C-R1-01 regression — the setup-sync mechanism DISCRIMINATES failure from success.**
    ///
    /// Codex round 1: the manual fork's parent arm returned `Ok` immediately, so a child that
    /// died in its pre-`execve` setup left `launch()` returning a false `Ok` with a dead shell.
    /// The fix is the setup-sync pipe read by [`wait_for_child_setup`]. This proves the read
    /// distinguishes the two cases — it FAILS against any inversion of the EOF-vs-byte logic.
    ///
    /// Non-root and fork-safe: the child does ONLY async-signal-safe work (`write` / `_exit` /
    /// `execv`), no allocation, no lock, so forking from the multithreaded test runner is sound.
    #[test]
    fn setup_sync_reports_child_failure_and_success_b2a_c_r1_01() {
        use nix::fcntl::OFlag;
        use nix::unistd::{fork, pipe2, ForkResult};

        // FAILURE: the child writes one byte then `_exit` — the parent MUST see `Err`.
        {
            let (r, w) = pipe2(OFlag::O_CLOEXEC).expect("pipe2");
            let wfd = w.as_raw_fd(); // captured before fork; child touches only raw libc
            // SAFETY: fork; child path is async-signal-safe only and diverges via `_exit`.
            match unsafe { fork() }.expect("fork") {
                ForkResult::Child => unsafe {
                    nix::libc::write(wfd, b"x".as_ptr().cast(), 1);
                    nix::libc::_exit(0);
                },
                ForkResult::Parent { child } => {
                    drop(w);
                    // D0-R5-05: guard on the line after the fork. R4-03 removed the callee's
                    // wait, so without this the child is never reaped and leaks a zombie —
                    // and the earlier "a guard after every test fork" claim was simply false.
                    let _child = crate::test_child_guard::ChildGuard::arm(child);
                    let res = wait_for_child_setup(r, child);
                    assert!(res.is_err(), "a child that writes a failure byte must yield Err");
                }
            }
        }
        // SUCCESS: the child `execve`s `/bin/true`; the CLOEXEC write end closes → the parent
        // reads EOF → `Ok`.
        {
            let (r, w) = pipe2(OFlag::O_CLOEXEC).expect("pipe2");
            // SAFETY: fork; child `execv`s (async-signal-safe) or `_exit`s.
            match unsafe { fork() }.expect("fork") {
                ForkResult::Child => unsafe {
                    let path = c"/bin/true";
                    let argv = [path.as_ptr(), std::ptr::null()];
                    nix::libc::execv(path.as_ptr(), argv.as_ptr());
                    nix::libc::_exit(127); // only reached if execv failed
                },
                ForkResult::Parent { child } => {
                    drop(w);
                    let res = wait_for_child_setup(r, child);
                    assert!(res.is_ok(), "a child that execve's must yield Ok (EOF via CLOEXEC)");
                    // `wait_for_child_setup`'s success path does not reap (production pins the
                    // long-lived shell by pidfd); reap `/bin/true` here so the test leaks no
                    // zombie.
                    let _ = nix::sys::wait::waitpid(child, None);
                }
            }
        }
    }

    /// This module's own source, for the class-5 accessor audit below.
    const SELF_SRC: &str = include_str!("launcher.rs");

    /// The PRODUCTION half of this file — everything before the `#[cfg(test)]` module.
    ///
    /// The audit MUST NOT read its own source: the assertions below mention `Self(` and
    /// `self.0` as string literals, so grepping the whole file counts the test's own text and
    /// the audit reports a violation that does not exist in shipped code (observed on first
    /// run: 4 constructors instead of 1). Scoping to the production half is what makes the
    /// count mean what it claims to mean.
    fn production_src() -> &'static str {
        let (prod, _tests) = SELF_SRC
            .split_once("#[cfg(test)]")
            .expect("launcher.rs has exactly one #[cfg(test)] module marker");
        prod
    }

    // ── VtName: the capability-type RED-proofs (DEFECT_CLASSES.md class 5) ───────────
    //
    // The invariant is NOT secrecy — it is well-formedness: possession of a `VtName` must
    // prove the string is a `ttyN` that `pam_systemd` will parse into a SEAT. The failure
    // this forecloses is silent: a malformed name does not make `pam_open_session` fail, it
    // makes it succeed into a `Class=background`, SEATLESS session that reports `Active=yes`
    // and that the active-local-seated gate then denies forever (§4 R3-02, recon Variant A).

    /// A pty is the single most dangerous input: it *looks* like a terminal, `pam_open_session`
    /// accepts it, and the result is the seatless session described above. RED-proven: an
    /// implementation that accepted any non-empty tty string passes every other test here.
    #[test]
    fn vtname_rejects_pty_the_seatless_trap() {
        for pty in ["pts/3", "/dev/pts/3", "pts/0"] {
            assert!(VtName::new(pty).is_err(), "`{pty}` is a pty — it opens a SEATLESS session");
        }
    }

    /// `tty0` is not a VT: in Linux `0` means "no VT / the current one". Accepting it would
    /// hand PAM a name that resolves to no seat.
    #[test]
    fn vtname_rejects_tty0_and_out_of_range() {
        assert!(VtName::new("tty0").is_err(), "tty0 means `no VT`");
        assert!(VtName::new("tty64").is_err(), "64 exceeds MAX_NR_CONSOLES (63)");
        assert!(VtName::new("tty01").is_err(), "leading zero is not the canonical form");
        // The boundary the two rejections bracket must itself still be accepted, or the
        // range check could pass by rejecting everything.
        assert!(VtName::new("tty1").is_ok());
        assert!(VtName::new("tty63").is_ok());
    }

    /// Other malformed shapes, including the ones that look plausible in a config file.
    #[test]
    fn vtname_rejects_malformed_shapes() {
        for bad in ["/dev/tty1", "TTY1", "tty", "tty-1", "tty 1", "tty1 ", "", "console"] {
            assert!(VtName::new(bad).is_err(), "`{bad}` is not a canonical ttyN");
        }
    }

    /// CLASS-5 RESIDUAL AUDIT — ONLY what `compile_fail` cannot reach.
    ///
    /// # Remedy ordering (docs/DEFECT_CLASSES.md class 15)
    ///
    /// Source-inspecting assertions are the LAST resort, because they audit a region that
    /// contains their own text and carry a count constant a future edit can silently bump.
    /// So every bypass shape that can be expressed as "this must not compile from outside
    /// the module" is proven by a `compile_fail` doctest on `VtName::new` instead — the
    /// compiler enforces it, there is no constant, and there is nothing to disarm. Those
    /// cover the **pub-field**, **`Deref`**, and **`into_inner`** erosions (each RED-proven
    /// to fail when the erosion is introduced).
    ///
    /// What remains here is the one property `compile_fail` provably CANNOT express:
    /// `compile_fail` is **enumerative** — it catches the shapes you can NAME, from outside.
    /// This audit is **exhaustive over the module** — it catches ANY second construction site
    /// or raw-field reader added INSIDE it, whose name is unknowable in advance and where the
    /// private field is legitimately accessible. That gap is real, so the grep survives for
    /// it and for nothing else.
    #[test]
    fn vtname_internal_construction_and_reads_stay_at_the_sanctioned_sites() {
        let src = production_src();

        // Exactly ONE construction site: `new`'s `Ok(Self(..))`. A second `Self(` anywhere in
        // the module is a second constructor that never ran the validation. Not expressible
        // as a compile_fail: a new internal constructor's NAME is unknown in advance.
        let ctors = src.matches("Self(").count();
        assert_eq!(
            ctors, 1,
            "VtName must have exactly one construction site (new's Ok(Self(..))), found \
             {ctors} — a second one bypasses validation. Do NOT raise this number to make \
             the test pass; that is the class-15 disarmament. Re-derive it: \
             `awk '/^#\\[cfg\\(test\\)\\]/{{exit}} {{print}}' runtime/src/launcher.rs \
             | grep -c 'Self('`"
        );

        // Exactly TWO readers of the raw field: `as_pam_tty` (hands PAM the string) and
        // `exists_on_system` (builds /dev/<name>). Both read-only, neither leaks a handle.
        let readers = src.matches("self.0").count();
        assert_eq!(
            readers, 2,
            "expected exactly 2 readers of VtName's raw field (as_pam_tty, exists_on_system), \
             found {readers} — a new reader needs its own audit. Same warning as above: \
             re-derive the count, do not bump the constant."
        );
    }
}
