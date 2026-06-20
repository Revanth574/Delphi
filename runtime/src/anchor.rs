// SPDX-License-Identifier: MIT

//! The root anchor: a root-owned approval-socket directory.
//!
//! This is the keystone the whole runtime boundary hangs from
//! (`docs/TRUST_MODEL.md` §4, "R3-01 / R4-01"). The security property proved in
//! Increment 1a is **"unsubstitutable YET connectable"**, and it decomposes into
//! two independent kernel facts:
//!
//! * **Unsubstitutable** — the per-session directory `/run/delphi/<session>` is
//!   **root-owned, mode `0711`**. A same-uid attacker cannot `unlink`/replace the
//!   socket inode inside it, because `unlink(2)` requires **write on the
//!   directory**, which the user lacks. (And because `/run` itself is
//!   `root:root 0755`, the user cannot pre-create the path at all.)
//! * **Connectable** — the socket `approve.sock` is **`root:<session-gid>`, mode
//!   `0660`**, so the legitimate same-uid client (in the session group) can
//!   `connect()` while "other" users cannot.
//!
//! The split is deliberate: unsubstitutability comes from *directory* ownership,
//! connectability from *socket* group/mode. A lockdown tight enough to also block
//! the legitimate client would defeat the system, so 1a's test proves both halves.

use std::fs::{self, DirBuilder, Permissions};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use nix::unistd::{chown, geteuid, Gid, Uid};

use crate::RuntimeError;

/// The canonical filesystem name of the per-session directory's base.
///
/// Mirrors `RuntimeDirectory=delphi/%i` in `delphi-runtimed@.service`: systemd
/// creates `/run/delphi/<session>` as root in production; [`ensure_runtime_dir`]
/// replicates it so the anchor is testable without systemd-as-PID-1.
pub const DEFAULT_RUNTIME_BASE: &str = "/run/delphi";

/// The fixed name of the approval socket inside the per-session directory.
pub const APPROVAL_SOCKET_NAME: &str = "approve.sock";

/// The established anchor paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorPaths {
    /// The per-session directory `<base>/<session>` — root-owned, mode `0711`.
    pub dir: PathBuf,
    /// The approval socket `<dir>/approve.sock` — `root:<gid>`, mode `0660`.
    pub socket: PathBuf,
}

/// Create the root-owned per-session runtime directory and return its path.
///
/// `base/<session>` is created mode `0711` and `base` (if absent) mode `0755`,
/// both owned by the current process — which **must be root**, so the directory
/// is root-owned and therefore unsubstitutable by the session user. Idempotent:
/// re-establishes the exact modes if the directories already exist.
///
/// # Errors
///
/// [`RuntimeError::NotRoot`] if the effective uid is not 0;
/// [`RuntimeError::Filesystem`] if a directory cannot be created or re-moded.
///
/// # Examples
///
/// ```no_run
/// use delphi_runtime::{ensure_runtime_dir, anchor::DEFAULT_RUNTIME_BASE};
/// use std::path::Path;
///
/// // Run as root (systemd launches the daemon as root):
/// let dir = ensure_runtime_dir(Path::new(DEFAULT_RUNTIME_BASE), "alice").unwrap();
/// assert!(dir.ends_with("alice"));
/// ```
pub fn ensure_runtime_dir(base: &Path, session: &str) -> Result<PathBuf, RuntimeError> {
    let euid = geteuid().as_raw();
    if euid != 0 {
        return Err(RuntimeError::NotRoot { euid });
    }

    create_dir_with_mode(base, 0o755)?;
    let dir = base.join(session);
    create_dir_with_mode(&dir, 0o711)?;
    Ok(dir)
}

/// Create `path` with exactly `mode` (re-applying the mode if it already exists),
/// owned by the current (root) process.
fn create_dir_with_mode(path: &Path, mode: u32) -> Result<(), RuntimeError> {
    match DirBuilder::new().mode(mode).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(source) => {
            return Err(RuntimeError::Filesystem {
                op: "create runtime dir",
                path: path.to_path_buf(),
                source,
            });
        }
    }
    // `DirBuilder::mode` is masked by umask and is a no-op when the dir already
    // exists; set the exact mode explicitly so the anchor mode is deterministic.
    fs::set_permissions(path, Permissions::from_mode(mode)).map_err(|source| {
        RuntimeError::Filesystem { op: "set dir mode", path: path.to_path_buf(), source }
    })
}

/// Bind the approval socket inside `dir`, group-owned by `session_gid`, mode
/// `0660` — connectable by the session user, unsubstitutable via the root-owned
/// directory.
///
/// The returned [`UnixListener`] must be kept alive by the caller (the daemon);
/// dropping it removes the bound socket. Any stale socket at the path is removed
/// first (root may, since the directory is root-owned).
///
/// # Errors
///
/// [`RuntimeError::Filesystem`] if the socket cannot be bound or its mode set;
/// [`RuntimeError::Syscall`] if the `chown` to the session group fails.
///
/// # Examples
///
/// ```no_run
/// use delphi_runtime::{ensure_runtime_dir, bind_approval_socket};
/// use delphi_runtime::anchor::DEFAULT_RUNTIME_BASE;
/// use std::path::Path;
///
/// let dir = ensure_runtime_dir(Path::new(DEFAULT_RUNTIME_BASE), "alice").unwrap();
/// let (paths, _listener) = bind_approval_socket(&dir, 1000).unwrap();
/// assert!(paths.socket.ends_with("approve.sock"));
/// ```
pub fn bind_approval_socket(
    dir: &Path,
    session_gid: u32,
) -> Result<(AnchorPaths, UnixListener), RuntimeError> {
    let socket = dir.join(APPROVAL_SOCKET_NAME);

    match fs::remove_file(&socket) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(RuntimeError::Filesystem {
                op: "remove stale socket",
                path: socket.clone(),
                source,
            });
        }
    }

    let listener = UnixListener::bind(&socket).map_err(|source| RuntimeError::Filesystem {
        op: "bind approval socket",
        path: socket.clone(),
        source,
    })?;

    // root:<session-gid>, 0660 — group-connectable, owner stays root.
    chown(&socket, Some(Uid::from_raw(0)), Some(Gid::from_raw(session_gid))).map_err(
        |source| RuntimeError::Syscall { op: "chown approval socket", source },
    )?;
    fs::set_permissions(&socket, Permissions::from_mode(0o660)).map_err(|source| {
        RuntimeError::Filesystem { op: "set socket mode", path: socket.clone(), source }
    })?;

    Ok((AnchorPaths { dir: dir.to_path_buf(), socket }, listener))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Non-root callers get a clear, actionable `NotRoot` rather than a confusing
    /// filesystem error (runs in normal CI, where the test process is not root).
    #[test]
    fn ensure_runtime_dir_rejects_non_root() {
        if geteuid().as_raw() == 0 {
            // Running as root (e.g. the privileged lane) — this guard can't fire.
            return;
        }
        let err = ensure_runtime_dir(Path::new("/run/delphi"), "ignored")
            .expect_err("a non-root caller must be rejected");
        match err {
            RuntimeError::NotRoot { euid } => assert_eq!(euid, geteuid().as_raw()),
            other => panic!("expected NotRoot, got {other:?}"),
        }
    }
}
