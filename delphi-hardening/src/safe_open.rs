// SPDX-License-Identifier: MIT

//! Race-free safe-open of a file beneath a held trusted-root directory handle.
//!
//! # Defect class foreclosed: path-resolution races (symlink / TOCTOU / intermediate)
//!
//! Opening a file "under a trusted root" by validating a path string and then
//! opening it is racy: a symlink can be swapped in between the check and the
//! open (TOCTOU), and an intermediate component can be a symlink that escapes
//! the root. This primitive closes that class on Linux by handing the kernel a
//! **held directory file descriptor** as the resolution anchor and using
//! `openat2(2)` with `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`, so the kernel
//! refuses to traverse ANY symlink/reparse point or escape the anchored
//! directory — atomically, with no userspace re-resolution window. (Lifted from
//! the 3A.5 knowledge-ingestion hardening, finding FIX 15 / the F8/F10/F15
//! path-race family.)
//!
//! The caller is responsible for the **trust anchor**: `trusted_root_handle`
//! must be a directory opened with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` at
//! registration time and held thereafter, so the kernel inode it references
//! stays valid even if the path string is later renamed or swapped. (Encapsulating
//! that flags-invariant in an unforgeable `TrustedRoot` newtype is a tracked
//! follow-up — see `docs/DEFECT_CLASSES.md`, capability-type pattern.)
//!
//! # Fidelity / platform
//!
//! - **Linux**: `openat2(2)` with `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`
//!   (`SYS_openat2` = 437, stable since kernel 5.6).
//! - **non-Linux**: returns [`std::io::ErrorKind::Unsupported`] carrying the
//!   caller-supplied `unsupported_msg` verbatim. The message is left to the
//!   caller so this generic primitive stays domain-free; the message IS the
//!   behavior on that platform.

use std::fs::File;
use std::io;
use std::path::Path;

/// Open `target` for reading, anchored to a held directory handle for the
/// trusted root. Refuses to traverse ANY symlink/reparse point between the held
/// root and the target (Linux, via `openat2`).
///
/// `target` should already be canonicalized; this re-validates that it lies
/// under the held root's *current* canonical path (read via `/proc/self/fd`,
/// robust against a directory rename after the fd was opened).
///
/// On non-Linux, returns [`io::ErrorKind::Unsupported`] with `unsupported_msg`
/// (caller-supplied so the message can be domain-appropriate).
///
/// # Errors
///
/// - `Unsupported` on non-Linux (with `unsupported_msg`).
/// - `PermissionDenied` if `target` is not under the held root's canonical path.
/// - the kernel's `openat2` error (e.g. `ELOOP` on a symlink component, `EXDEV`
///   on an escape) surfaced via [`io::Error::last_os_error`].
pub fn open_beneath(
    trusted_root_handle: &File,
    target: &Path,
    unsupported_msg: &str,
) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    {
        let _ = unsupported_msg;
        linux_openat2_under_held_root(trusted_root_handle, target)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // openat2 is Linux-specific; Windows has no documented kernel-level
        // equivalent (NtCreateFile + OBJ_DONT_REPARSE is undocumented and
        // version-unstable) and macOS support via repeated openat walks is
        // deferred. The caller supplies a domain-appropriate message.
        let _ = (trusted_root_handle, target);
        Err(io::Error::new(io::ErrorKind::Unsupported, unsupported_msg.to_string()))
    }
}

/// Linux-specific implementation: `openat2(2)` with
/// `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`, anchored to a held directory fd.
///
/// The held fd IS the trust anchor — we never re-open the root by path. The
/// kernel walks `target` (made relative to the root's current canonical path via
/// `/proc/self/fd` readlink) relative to the held `dirfd`, returning `-ELOOP` on
/// any symlink component or `-EXDEV` on an escape.
///
/// Memory safety (per CLAUDE.md §3):
/// - the `OpenHow` struct is owned on the stack and only read by the kernel;
/// - `relative_cstr` owns its bytes for the syscall's lifetime;
/// - the returned raw fd is immediately wrapped in `OwnedFd` (closes on drop),
///   then `File` (transfers ownership) — no double-close or leak path.
#[cfg(target_os = "linux")]
fn linux_openat2_under_held_root(trusted_root_handle: &File, target: &Path) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    // The held fd IS the trust anchor; openat2's dirfd resolves `target`
    // relative to the already-open directory's inode, immune to path swaps.
    let root_fd = trusted_root_handle.as_raw_fd();

    // Current canonical path of the held inode (robust against renames after
    // the fd was opened).
    let proc_path = format!("/proc/self/fd/{root_fd}");
    let canonical_root = std::fs::read_link(&proc_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("could not resolve held root fd via /proc/self/fd: {e}"),
        )
    })?;

    // Defense in depth: refuse a target that doesn't lexically fit under the
    // held root's current canonical path.
    let relative = target.strip_prefix(&canonical_root).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "target path is not under the held trusted root",
        )
    })?;

    let relative_cstr = CString::new(relative.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "relative path contains an embedded NUL byte",
        )
    })?;

    // The `open_how` struct passed to openat2(2). Mirrors <linux/openat2.h>.
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    // From <linux/openat2.h> kernel uapi headers. Stable since 5.6.
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;

    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH,
    };

    // SAFETY: we pass the kernel a raw root_fd we own (alive via the borrow for
    // the syscall), a NUL-terminated C string we own, and a pointer to a
    // stack-allocated OpenHow with its size. The kernel reads the path bytes and
    // writes nothing through these pointers. The return is the new fd on success
    // or -1 with errno set.
    let raw_fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd,
            relative_cstr.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };

    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: raw_fd is a positive value the kernel verified is a valid
    // newly-opened fd. We transfer ownership into OwnedFd (closes on drop), then
    // into File. No other code holds raw_fd.
    let owned: OwnedFd = unsafe { OwnedFd::from_raw_fd(raw_fd as i32) };
    Ok(File::from(owned))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::Read;

    const MSG: &str = "unsupported on this platform";

    fn open_root(dir: &Path) -> File {
        // Mirror the registration flags the trust-anchor invariant requires.
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dir)
            .expect("open trusted root dir")
    }

    #[test]
    fn opens_a_real_file_under_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::write(root.join("doc.txt"), b"hello").unwrap();
        let handle = open_root(&root);
        let mut f = open_beneath(&handle, &root.join("doc.txt"), MSG).expect("should open");
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello");
    }

    #[test]
    fn refuses_a_leaf_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let outside = dir.path().join("outside_secret");
        std::fs::write(&outside, b"secret").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let handle = open_root(&root);
        // RESOLVE_NO_SYMLINKS makes the kernel refuse the symlink leaf.
        assert!(open_beneath(&handle, &root.join("link"), MSG).is_err());
    }

    #[test]
    fn refuses_a_target_outside_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let outside = dir.path().canonicalize().unwrap().join("elsewhere");
        std::fs::write(&outside, b"x").unwrap();
        let handle = open_root(&root);
        let err = open_beneath(&handle, &outside, MSG).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
