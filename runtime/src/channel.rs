// SPDX-License-Identifier: MIT

//! The private approval channel (Increment 1b).
//!
//! A `SOCK_SEQPACKET` `AF_UNIX` socketpair: the daemon keeps one end, the shell
//! gets the other (`docs/TRUST_MODEL.md` §4 — "fd-channel hygiene": the approval
//! fd is passed ONLY to the shell, never the AI). SEQPACKET preserves message
//! boundaries (one approval = one datagram) and is connection-oriented, so the
//! daemon detects shell death as EOF (the failure-mode discipline in §4).
//!
//! 1b establishes the channel and the fd-discipline that keeps it from the AI; it
//! does not yet carry approval messages (that is 1c's consent path).

use std::os::fd::OwnedFd;

use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};

use crate::RuntimeError;

/// Create the private approval channel as a `SOCK_SEQPACKET` pair.
///
/// Returns `(daemon_end, shell_end)`: the daemon retains `.0`; `.1` is handed to
/// the shell (and to no one else). Both ends are `CLOEXEC` by default, so they do
/// not leak across an unrelated `execve`; the shell end's `CLOEXEC` is cleared
/// only when it is deliberately passed to the shell.
///
/// # Examples
///
/// ```
/// use std::os::fd::AsRawFd;
///
/// let (daemon_end, shell_end) = delphi_runtime::channel::approval_socketpair().unwrap();
/// assert_ne!(daemon_end.as_raw_fd(), shell_end.as_raw_fd());
/// ```
pub fn approval_socketpair() -> Result<(OwnedFd, OwnedFd), RuntimeError> {
    socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(|source| RuntimeError::Syscall { op: "socketpair", source })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    /// The pair is a connected channel: a byte written to one end is read on the
    /// other (runs in normal CI — no root needed).
    #[test]
    fn pair_is_a_connected_channel() {
        let (a, b) = approval_socketpair().expect("socketpair");
        let mut a = UnixStream::from(a);
        let mut b = UnixStream::from(b);
        a.write_all(&[0x42]).expect("write");
        let mut buf = [0u8; 1];
        b.read_exact(&mut buf).expect("read");
        assert_eq!(buf[0], 0x42);
    }
}
