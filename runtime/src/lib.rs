// SPDX-License-Identifier: MIT

//! Delphi runtime daemon — the root-anchored launcher (Increment 1a).
//!
//! This crate implements the *keystone* of the ratified runtime trust model
//! (`docs/TRUST_MODEL.md`, §4 "R3-01 / R4-01 — the launcher, established by the
//! OS trust root"): a **root-established** approval-socket directory that a
//! same-uid attacker cannot pre-empt, substitute, or unlink, while the
//! legitimate same-uid client can still `connect()`.
//!
//! # Scope (Increments 1a–1b, built bottom-up)
//!
//! Each layer is proven in isolation before the next. So far:
//!
//! * [`anchor`] (1a) — create the root-owned runtime directory (mode `0711`) and
//!   bind the approval socket inside it (mode `0660`, group-owned by the session
//!   user so it stays connectable) — the running-code form of "unsubstitutable
//!   YET connectable".
//! * [`privdrop`] (1a) — the canonical child privilege-drop
//!   (`setgroups([]) → setgid → setuid`, in that load-bearing order) behind a
//!   mockable seam so the *order* is unit-testable without root.
//! * [`channel`] (1b) — the private `SOCK_SEQPACKET` approval channel
//!   (daemon end + shell end).
//! * [`fdsec`] (1b) — the `close_range(CLOEXEC|UNSHARE)` fd-discipline that keeps
//!   the approval fd out of every child except the shell.
//! * [`pidfd`] (1b) — pinning the spawned shell by pidfd (R3-03). The sibling
//!   topology means a same-uid *sibling* AI cannot `pidfd_getfd` the shell's
//!   approval fd under Yama `ptrace_scope=1` — the F1 defense the 1b attack test
//!   proves.
//!
//! It does NOT yet contain PAM consent, token mint, the canonical action,
//! sandbox, or execute — those are Increments 1c–1d, added on top and reviewed
//! together at the end of 1d.
//!
//! # Fidelity
//!
//! The "external source" here is the OS kernel itself. There is a single,
//! highest-fidelity interface — **direct syscalls** (via `nix` / `std::os::unix`)
//! — so no fidelity probing applies: the kernel's `unlink`/`connect` permission
//! checks against directory ownership *are* the security boundary, not an
//! approximation of one. Every operation reports a typed [`RuntimeError`] on
//! failure rather than a fidelity level.

use std::path::PathBuf;

pub mod action;
pub mod anchor;
pub mod audit;
pub mod canonicalize;
pub mod channel;
pub mod consent_relay;
pub mod execute;
pub mod fdsec;
pub mod launcher;

/// Bounded child reaping, shared with the daemon binary (D0A-R6-03).
pub use launcher::reap_within;
pub mod logind;
pub mod pam;
pub mod pidfd;
pub mod privdrop;
pub mod readiness;
pub mod sandbox;
pub mod scaffold_env;
pub mod service;
pub mod store;
#[cfg(any(test, feature = "test-fixtures"))]
pub mod test_child_guard;
pub mod token;
pub mod wire;

pub use anchor::{bind_approval_socket, ensure_runtime_dir, AnchorPaths};
pub use channel::approval_socketpair;
pub use fdsec::mark_cloexec_except;
pub use privdrop::{drop_privileges, PrivDropOps, RealPrivDropOps};

/// Errors from establishing or operating the root anchor.
///
/// Every variant is actionable (CLAUDE.md §8): it names the failing operation
/// and, where relevant, the path or the launch precondition that was violated.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// A filesystem operation (mkdir / chown / set-permissions / bind) failed.
    #[error("failed to {op} `{}`: {source}", path.display())]
    Filesystem {
        /// The operation that failed (e.g. "create runtime dir", "bind socket").
        op: &'static str,
        /// The path involved.
        path: PathBuf,
        /// The underlying OS error.
        source: std::io::Error,
    },

    /// A privilege-management or path syscall failed.
    #[error("`{op}` syscall failed: {source}")]
    Syscall {
        /// The syscall that failed (e.g. "setgroups", "setuid").
        op: &'static str,
        /// The underlying errno.
        source: nix::Error,
    },

    /// The daemon was not launched as root.
    ///
    /// The anchor depends on the daemon running as root so the runtime directory
    /// is root-owned (`docs/TRUST_MODEL.md` §4, R3-01). Launch it via the
    /// `delphi-runtimed@.service` system unit, not as a user.
    #[error(
        "must run as root to establish the root-owned anchor (effective uid is {euid}); \
         launch via the delphi-runtimed@.service system unit — see TRUST_MODEL.md §4 R3-01"
    )]
    NotRoot {
        /// The effective uid the daemon was started with.
        euid: u32,
    },

    /// A PAM consent step failed (Increment 1c).
    ///
    /// Carries the failing PAM operation and the library's detail string. A wrong
    /// password surfaces here as `pam_authenticate` failed.
    #[error("PAM {op} failed: {detail}")]
    Pam {
        /// The PAM operation that failed (e.g. "pam_authenticate").
        op: &'static str,
        /// The PAM library's error detail.
        detail: String,
    },

    /// Execution was attempted without a valid approval token for the action
    /// (Increment 1d — the consent gate). The token did not verify against the
    /// action's canonical digest, so the action is unapproved and is not run.
    #[error("execution denied: no valid approval token for this action (the 1c consent gate)")]
    Unapproved,

    /// The action's approval was already consumed (Increment 1d — one-shot,
    /// `docs/TRUST_MODEL.md` §4: "the arbiter consumes it one-shot"). One human
    /// approval authorizes ONE execution, not repeated execution within the token
    /// TTL (closes approve-once/execute-many).
    #[error("execution denied: this action's approval was already consumed (one-shot — TRUST_MODEL.md §4)")]
    AlreadyConsumed,

    /// A pinned script's content memfd is not FULLY sealed against mutation
    /// (Increment 1d — R4-02, `docs/TRUST_MODEL.md` §3). The ratified immutability is
    /// the full seal set `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL`:
    /// write-sealing alone does NOT stop `ftruncate` shrink/grow, so a write-only
    /// seal still permits content/length mutation between the digest and the exec.
    /// A script missing any of the four seals is refused before any exec path.
    #[error("execution denied: the script content is not fully sealed (need F_SEAL_WRITE|SHRINK|GROW|SEAL) — its content or length could be mutated after approval (TRUST_MODEL.md §3, R4-02)")]
    UnsealedScript,

    /// An approved action named the daemon's own runtime directory as an `fs_bind`
    /// (D0A-R9-10, `docs/TRUST_MODEL.md` §6: the approval socket is "outside the
    /// jail's mount set"). Nothing previously forbade *naming* it, so an action could
    /// place the socket and the anchor inside its own jail.
    ///
    /// Distinct from D0A-R9-03, which is the TOCTOU on bind *resolution*: this refuses
    /// the name; that one is about the name changing meaning after the check.
    #[error("execution denied: `{}` is inside the daemon's runtime directory `{}` — an action may not mount the approval socket or anchor into its own jail (TRUST_MODEL.md §6, D0A-R9-10)", path.display(), base.display())]
    DeniedBind { path: std::path::PathBuf, base: std::path::PathBuf },

    /// The dedicated tool account is missing while running privileged (D0A-R9-01).
    /// Fail closed: without it there is no unprivileged identity to drop to, and
    /// running the action as root is the defect itself.
    #[error("execution denied: the tool account `{account}` does not exist, so the action cannot be dropped off root. Create it: `useradd --system --no-create-home --shell /usr/sbin/nologin {account}` (TRUST_MODEL.md §6, D0A-R9-01)")]
    MissingToolAccount {
        /// The account name that was looked up.
        account: String,
    },

    /// The credential-drop helper is not installed (D0A-R9-01). bwrap cannot drop
    /// the payload itself (`--uid` needs a user namespace and is namespace-internal
    /// anyway), so without this binary the action would run as root.
    #[error("execution denied: the drop helper `{path}` is missing, so the action cannot be dropped off root. Re-run `installer/install.sh` (TRUST_MODEL.md §6, D0A-R9-01)")]
    MissingDropHelper {
        /// The install path that was opened.
        path: String,
    },

    /// A wire-protocol fault on the AI↔daemon general socket (B1) — a malformed
    /// frame, an oversized message, a decode failure, or an unexpected message for
    /// the current state. Never carries user data.
    #[error("protocol error on the general socket: {0}")]
    Protocol(String),

    /// The AI referenced a `pending_id` the daemon has no registered action for
    /// (B1) — unknown, already consumed, or lost across a daemon restart
    /// (fail-closed, `docs/TRUST_MODEL.md` §4 failure modes).
    #[error("no pending action registered for id `{0}` (unknown, consumed, or restarted)")]
    UnknownPending(String),

    /// A launch precondition supplied by the operator is malformed (C1 — e.g. a
    /// `PAM_TTY` that is not a well-formed `ttyN`).
    ///
    /// Distinct from [`RuntimeError::Syscall`]: nothing was attempted. The input was
    /// refused *before* the syscall, so the failure surfaces as a loud "launch refused"
    /// at its cause rather than as a silently degraded session at some later gate
    /// (`docs/TRUST_MODEL.md` §4 R3-02 — a malformed tty opens a cleanly-registered but
    /// SEATLESS session that the active-local-seated gate then denies forever).
    #[error("launch refused — invalid configuration: {what}")]
    Config {
        /// What was wrong, and what the valid form is.
        what: &'static str,
    },

    /// The forked shell child died during its pre-`execve` setup (`dup2` / stdio / PAM /
    /// FD-01 sweep / privilege-drop / `execve`) instead of becoming the shell. The manual
    /// fork has no `Command::spawn` to surface this, so the launcher reads a setup-sync pipe
    /// and returns this rather than a false `Ok` with a dead shell (§4 R3-01b; B2A-C-R1-01).
    /// The specific failing step is written to the daemon's journal by the child's
    /// `write(2)` diagnostic (`delphi-runtimed: shell child failed before execve: …`).
    #[error(
        "shell child failed its pre-execve setup (see the daemon journal for the step: \
         `shell child failed before execve: …`)"
    )]
    ShellSetupFailed,

    /// The shell `execve`d successfully and then died — or closed its channel — before
    /// signalling readiness (Increment D0, `readiness::READY_DATAGRAM`).
    ///
    /// This is the case the pre-D0 launcher **could not represent at all**: its setup-sync
    /// pipe is `O_CLOEXEC`, so a successful `execve` already delivered EOF and the parent
    /// had recorded "shell started". Measured live in P3a — the WRY host reported
    /// `GTK INIT: ok`, aborted during rendering, and the daemon serviced an action against
    /// a corpse.
    #[error(
        "the shell is NOT running: it died before signalling readiness. Whether it got as \
         far as `execve` is NOT known here — a pre-exec failure (a signal during PAM or the \
         privilege drop) and an exec'd shell that aborted are indistinguishable at this \
         point, so check the daemon journal for BOTH `shell child failed before execve` and \
         the shell's own diagnostics. \
         Check the daemon journal for the shell's own diagnostics (it inherits the daemon's \
         stderr): a WebKit/GTK abort, a missing AppArmor profile, or an absent display are \
         the observed causes. Verify with `installer/p3-preflight.sh`."
    )]
    ShellDiedBeforeReady,


    /// The shell neither signalled readiness nor died within the launch budget
    /// (Increment D0, `readiness::DEFAULT_READY_TIMEOUT`).
    ///
    /// Distinct from [`Self::ShellDiedBeforeReady`] on purpose: a wedged shell and a dead
    /// shell have different causes and different fixes, and collapsing them would make the
    /// journal say the wrong thing about which one happened.
    #[error(
        "the shell neither signalled readiness nor exited within {secs}s — it is \
         wedged, not dead. A shell that cannot say it is up is indistinguishable from one \
         that never came up, so the launch is refused rather than proceeding against it."
    )]
    ShellReadyTimeout {
        /// The budget that elapsed, in seconds.
        secs: u64,
    },
}
