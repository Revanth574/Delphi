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

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use nix::unistd::{Gid, Pid, Uid};

use crate::channel::approval_socketpair;
use crate::pidfd;
use crate::privdrop::{drop_privileges, RealPrivDropOps};
use crate::RuntimeError;

/// Where the forked shell finds its private-channel fd (the launcher dups the
/// channel onto this number; the shell reads `DELPHI_CHANNEL_FD` to confirm).
pub const SHELL_CHANNEL_FD: RawFd = 3;

/// What to launch and as whom.
pub struct LaunchSpec<'a> {
    /// The shell binary to exec (B1: the minimal shell).
    pub shell_path: &'a Path,
    /// The AI binary to exec (B1: the minimal AI).
    pub ai_path: &'a Path,
    /// The session user the children are dropped to.
    pub uid: Uid,
    /// The session group the children are dropped to.
    pub gid: Gid,
    /// The general socket the AI connects to (`approve.sock`).
    pub socket_path: &'a Path,
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
/// # Errors
///
/// [`RuntimeError::Syscall`] if the socketpair or pidfd fails;
/// [`RuntimeError::Filesystem`] if a child cannot be spawned.
pub fn launch(spec: &LaunchSpec) -> Result<Children, RuntimeError> {
    // The private channel (1b): daemon keeps `.0`, the shell gets `.1` at fork.
    let (daemon_end, shell_end) = approval_socketpair()?;

    let shell_pid = fork_shell(spec, &shell_end)?;
    let shell_pidfd = pidfd::open(Pid::from_raw(shell_pid))?;
    // The daemon closes its copy of the shell's end; only the shell holds it now.
    drop(shell_end);

    let ai_pid = fork_ai(spec)?;

    Ok(Children { daemon_channel: daemon_end, shell_pid, shell_pidfd, ai_pid })
}

/// Fork the shell: place the channel at [`SHELL_CHANNEL_FD`], keep ONLY it, drop, exec.
fn fork_shell(spec: &LaunchSpec, shell_end: &OwnedFd) -> Result<i32, RuntimeError> {
    let chan_raw = shell_end.as_raw_fd();
    let (uid, gid) = (spec.uid, spec.gid);

    let mut cmd = Command::new(spec.shell_path);
    cmd.env("DELPHI_CHANNEL_FD", SHELL_CHANNEL_FD.to_string());
    for (k, v) in spec.shell_env {
        cmd.env(k, v);
    }
    // SAFETY: pre_exec runs in the forked child before execve. Only async-signal-safe
    // ops: dup2, the alloc-free fd-discipline core, and the privilege-drop syscalls;
    // errors map to io::Error::from_raw_os_error (no allocation).
    unsafe {
        cmd.pre_exec(move || {
            if nix::libc::dup2(chan_raw, SHELL_CHANNEL_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            // Keep ONLY the channel fd; mark every other inherited fd close-on-exec.
            crate::fdsec::mark_cloexec_except_raw(&[SHELL_CHANNEL_FD])
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            drop_privileges(&RealPrivDropOps, uid, gid).map_err(priv_to_io)?;
            Ok(())
        });
    }
    spawn_pid(cmd, spec.shell_path)
}

/// Fork the AI: keep NOTHING (never the channel), drop, exec; it connects to the
/// general socket by path.
fn fork_ai(spec: &LaunchSpec) -> Result<i32, RuntimeError> {
    let (uid, gid) = (spec.uid, spec.gid);

    let mut cmd = Command::new(spec.ai_path);
    cmd.env("DELPHI_APPROVE_SOCK", spec.socket_path);
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
