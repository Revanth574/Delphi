// SPDX-License-Identifier: MIT

//! Pinning a spawned child by pidfd (Increment 1b, R3-03).
//!
//! The daemon opens a pidfd to the shell it spawned — a race-free handle immune
//! to pid-reuse — to bind the approver subject (`docs/TRUST_MODEL.md` §4, R3-03:
//! "the approver subject is a race-free pidfd from the spawn table"). 1b provides
//! the pin; binding consent to it is 1c.
//!
//! Note: `pidfd_open` only obtains a *handle*; it is not the attack surface. The
//! fd-theft an attacker would attempt is `pidfd_getfd` (duplicating a descriptor
//! out of the target), which is gated by `PTRACE_MODE_ATTACH_REALCREDS` and so is
//! denied to a same-uid *sibling* under Yama `ptrace_scope=1` — that denial is the
//! property the 1b attack test proves.

use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use nix::errno::Errno;
use nix::unistd::Pid;

use crate::RuntimeError;

/// Open a pidfd referring to `pid` — the daemon's race-free pin of a child it
/// spawned.
///
/// # Errors
///
/// [`RuntimeError::Syscall`] if `pidfd_open` fails (e.g. the pid does not exist).
///
/// # Examples
///
/// ```
/// use nix::unistd::Pid;
///
/// // Pin ourselves (always valid) — in production the daemon pins the shell.
/// let pidfd = delphi_runtime::pidfd::open(Pid::this()).unwrap();
/// use std::os::fd::AsRawFd;
/// assert!(pidfd.as_raw_fd() >= 0);
/// ```
pub fn open(pid: Pid) -> Result<OwnedFd, RuntimeError> {
    // SAFETY: SYS_pidfd_open returns a fresh owned fd or -1; on success we wrap the
    // returned descriptor in OwnedFd exactly once.
    let rc = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid.as_raw(), 0) };
    if rc < 0 {
        return Err(RuntimeError::Syscall { op: "pidfd_open", source: Errno::last() });
    }
    // SAFETY: rc is a valid file descriptor freshly returned by pidfd_open.
    Ok(unsafe { OwnedFd::from_raw_fd(rc as RawFd) })
}
