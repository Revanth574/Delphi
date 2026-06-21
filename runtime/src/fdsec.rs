// SPDX-License-Identifier: MIT

//! fd-discipline at child spawn (Increment 1b).
//!
//! Before a child `execve`s, mark every inherited descriptor `>= 3`
//! close-on-exec — so none leak into the child — except an explicit allowlist.
//! The shell keeps the approval fd; the AI keeps nothing
//! (`docs/TRUST_MODEL.md` §4, R4-02).
//!
//! The corrected mechanic (round-4): `close_range(.., CLOSE_RANGE_CLOEXEC |
//! CLOSE_RANGE_UNSHARE)` **marks** the range close-on-exec rather than closing it
//! (a plain `close_range(.., 0)` would close the fds the child still needs), and
//! `UNSHARE` detaches the fd table first so the marking cannot race a sibling
//! thread. The kept fds then have `CLOEXEC` cleared so they survive the exec.

use std::os::fd::{BorrowedFd, RawFd};

use nix::errno::Errno;
use nix::fcntl::{fcntl, FcntlArg, FdFlag};

use crate::RuntimeError;

/// Mark every fd `>= 3` close-on-exec except those in `keep`.
///
/// Marks (does not close): the marked fds close at the child's `execve`; the
/// `keep` fds have `CLOEXEC` cleared so they survive it. Call this in the child
/// after the privilege drop and immediately before `execve`.
///
/// # Errors
///
/// [`RuntimeError::Syscall`] if `close_range` or the per-fd `fcntl` fails.
pub fn mark_cloexec_except(keep: &[RawFd]) -> Result<(), RuntimeError> {
    // SAFETY: `close_range` with CLOSE_RANGE_CLOEXEC only sets the close-on-exec
    // flag across the descriptor range; it closes nothing and touches no memory.
    let rc = unsafe {
        nix::libc::close_range(
            3,
            nix::libc::c_uint::MAX,
            (nix::libc::CLOSE_RANGE_CLOEXEC | nix::libc::CLOSE_RANGE_UNSHARE) as nix::libc::c_int,
        )
    };
    if rc != 0 {
        return Err(RuntimeError::Syscall { op: "close_range", source: Errno::last() });
    }
    for &fd in keep {
        clear_cloexec(fd)?;
    }
    Ok(())
}

/// Clear the `CLOEXEC` flag on a single fd so it survives `execve`.
fn clear_cloexec(fd: RawFd) -> Result<(), RuntimeError> {
    // SAFETY: borrow the raw fd for the duration of the two fcntl calls; the
    // borrow does not outlive the descriptor (the caller owns it across the call).
    let bf = unsafe { BorrowedFd::borrow_raw(fd) };
    let bits = fcntl(bf, FcntlArg::F_GETFD)
        .map_err(|source| RuntimeError::Syscall { op: "fcntl F_GETFD", source })?;
    let mut flags = FdFlag::from_bits_truncate(bits);
    flags.remove(FdFlag::FD_CLOEXEC);
    fcntl(bf, FcntlArg::F_SETFD(flags))
        .map_err(|source| RuntimeError::Syscall { op: "fcntl F_SETFD", source })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn is_cloexec(fd: RawFd) -> bool {
        // SAFETY: fd is owned by the test for the duration of the call.
        let bf = unsafe { BorrowedFd::borrow_raw(fd) };
        let bits = fcntl(bf, FcntlArg::F_GETFD).expect("F_GETFD");
        FdFlag::from_bits_truncate(bits).contains(FdFlag::FD_CLOEXEC)
    }

    /// Marking sets CLOEXEC on an inherited fd but clears it on a kept fd (runs in
    /// normal CI — no root, no exec; we observe the FD_CLOEXEC flag directly).
    #[test]
    fn marks_all_but_keeps_the_allowlisted_fd() {
        // Two pipe read-ends (non-CLOEXEC) to stand in for inherited fds.
        let kept = nix::unistd::pipe().expect("pipe").0;
        let marked = nix::unistd::pipe().expect("pipe").0;
        let kept_fd = kept.as_raw_fd();
        let marked_fd = marked.as_raw_fd();

        mark_cloexec_except(&[kept_fd]).expect("mark");

        assert!(!is_cloexec(kept_fd), "the kept fd must survive exec (CLOEXEC cleared)");
        assert!(is_cloexec(marked_fd), "a non-kept fd must be marked CLOEXEC");
    }
}
