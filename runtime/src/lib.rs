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
pub mod channel;
pub mod execute;
pub mod fdsec;
pub mod logind;
pub mod pam;
pub mod pidfd;
pub mod privdrop;
pub mod sandbox;
pub mod token;

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
}
