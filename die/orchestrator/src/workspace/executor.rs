// SPDX-License-Identifier: MIT

//! Safe filesystem + command execution engine for workspace creation.
//!
//! This module turns a validated [`WorkspaceSpec`] into real files,
//! directories, and (allowlisted) setup-command runs on disk. It is the
//! ONLY component that mutates the filesystem, and it does so under a
//! defense-in-depth security model:
//!
//! - **Re-validation.** [`WorkspaceExecutor::execute`] re-runs
//!   [`validate_spec`] before touching the filesystem (Iron Law #11). It
//!   never assumes the validator already ran.
//! - **Kernel-anchored creation.** Every directory and file is created
//!   beneath a held directory handle via `openat2(RESOLVE_NO_SYMLINKS |
//!   RESOLVE_BENEATH)` to resolve the *parent*, then a single-component
//!   `mkdirat` / `openat(O_CREAT|O_EXCL|O_NOFOLLOW)` for the *leaf*. A
//!   concurrent attacker cannot swap a path component for a symlink: the
//!   parent resolution fails with `ELOOP`, and the leaf creation uses
//!   `O_NOFOLLOW | O_EXCL`. This is the create-side analogue of
//!   `knowledge.rs::safe_open_under_root_handle`.
//! - **No shell.** Commands run via `std::process::Command` with explicit
//!   argv and a minimal environment (`PATH` only). No interpolation.
//! - **Bounded.** Each command has a 60 s timeout; on timeout the child
//!   is killed.
//! - **Reversible.** [`WorkspaceExecutor::undo`] removes the workspace
//!   root with a symlink-safe, idempotent, containment-checked removal.
//!
//! # Platform support
//!
//! Creation requires Linux's `openat2(2)` (kernel ≥ 5.6). On non-Linux
//! targets every mutating method returns [`ExecutorError::Unsupported`]
//! rather than fall back to a racy path-string walk — the same FIX-16
//! posture as the knowledge store. Read-only helpers (`undo` containment
//! checks) work everywhere.

use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use crate::workspace::spec::{EntryKind, WorkspaceSpec};
use crate::workspace::validator::{ValidatorError, validate_spec};

/// Default per-command wall-clock timeout.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

/// Outcome of running one setup command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutcome {
    /// The program that was run.
    pub program: String,
    /// The argv tail.
    pub args: Vec<String>,
    /// Process exit code, or `None` if the process was killed (timeout)
    /// or terminated by a signal.
    pub exit_code: Option<i32>,
    /// Whether the command was killed for exceeding [`COMMAND_TIMEOUT`].
    pub timed_out: bool,
    /// Captured stdout (UTF-8 lossy is applied by consumers; stored raw).
    pub stdout: Vec<u8>,
    /// Captured stderr.
    pub stderr: Vec<u8>,
}

impl CommandOutcome {
    /// Whether the command succeeded (exit code 0, not timed out).
    #[must_use]
    pub fn succeeded(&self) -> bool {
        !self.timed_out && self.exit_code == Some(0)
    }
}

/// Terminal status of an [`ExecutionOutcome`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ExecutionStatus {
    /// All entries created and all commands exited 0.
    Completed,
    /// A filesystem entry could not be created. Files created before the
    /// failure remain on disk and the workspace is recorded for undo.
    TreeCreationFailed {
        /// The relative path that failed.
        path: String,
        /// Human-readable error.
        error: String,
    },
    /// A setup command failed (non-zero exit) or timed out. Entries and
    /// prior successful commands remain; recorded for undo.
    CommandFailed {
        /// The program that failed.
        program: String,
        /// Its exit code, if any.
        exit_code: Option<i32>,
        /// Whether it was a timeout.
        timed_out: bool,
    },
}

impl ExecutionStatus {
    /// Whether the workspace was created fully and successfully.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self, ExecutionStatus::Completed)
    }
}

/// Result of a successful *call* to [`WorkspaceExecutor::execute`].
///
/// Note that `Ok(ExecutionOutcome)` does NOT imply the workspace was
/// created without error — it means execution proceeded past the
/// pre-mutation gate (re-validation, root-exists check). Post-mutation
/// failures are reported in [`ExecutionOutcome::status`] so the caller
/// can still record the partially-created workspace for undo. Only
/// pre-mutation failures return `Err(ExecutorError)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutcome {
    /// Stable identifier for this workspace (name + creation epoch).
    pub workspace_id: String,
    /// The absolute workspace root that was created.
    pub root_dir: PathBuf,
    /// Number of directory-tree entries successfully created.
    pub created_entry_count: u32,
    /// Per-command outcomes, in declaration order, up to the first
    /// failure.
    pub command_outcomes: Vec<CommandOutcome>,
    /// Terminal status.
    pub status: ExecutionStatus,
}

/// Errors that prevent execution from beginning (pre-mutation only).
#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    /// The platform lacks `openat2`; creation is refused rather than
    /// performed through a racy fallback.
    #[error("workspace creation is supported on Linux only (requires openat2); {0}")]
    Unsupported(String),

    /// The spec failed re-validation in the executor.
    #[error("spec re-validation failed: {0}")]
    Validation(#[from] ValidatorError),

    /// `root_dir` already exists and is non-empty.
    #[error("workspace root already exists and is not empty: {0}")]
    RootExists(String),

    /// `root_dir` is not under the executor's allowed root (defense in
    /// depth; the validator should already guarantee this).
    #[error("root_dir {root} is not under allowed root {allowed}")]
    RootOutsideAllowed {
        /// The offending root.
        root: String,
        /// The configured allowed root.
        allowed: String,
    },

    /// A path component of the workspace root resolved to a symlink.
    #[error("a symlink was encountered while resolving the workspace root: {0}")]
    SymlinkEncountered(String),

    /// Could not open the allowed-root directory handle.
    #[error("could not open allowed root {path}: {source}")]
    AllowedRootOpen {
        /// The allowed root path.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },
}

/// Executes validated workspace specs under a fixed allowed root.
///
/// The allowed root (e.g. `~/projects`) is the containment boundary: no
/// spec may create or remove anything outside it.
///
/// # Examples
///
/// ```no_run
/// use die_orchestrator::workspace::executor::WorkspaceExecutor;
/// use die_orchestrator::workspace::templates::build_research_template;
/// use std::path::Path;
///
/// let exec = WorkspaceExecutor::new(Path::new("/home/u/projects"));
/// let spec = build_research_template("thesis", Path::new("/home/u/projects/thesis"));
/// let outcome = exec.execute(&spec).unwrap();
/// assert!(outcome.status.is_complete());
/// ```
pub struct WorkspaceExecutor {
    allowed_root: PathBuf,
}

impl WorkspaceExecutor {
    /// Create an executor bound to `allowed_root`.
    #[must_use]
    pub fn new(allowed_root: &Path) -> Self {
        Self {
            allowed_root: allowed_root.to_path_buf(),
        }
    }

    /// The allowed root this executor is bound to.
    #[must_use]
    pub fn allowed_root(&self) -> &Path {
        &self.allowed_root
    }

    /// Validate and execute a workspace spec.
    ///
    /// Returns `Err` only for pre-mutation failures (re-validation,
    /// root-exists, allowed-root open). Once filesystem mutation begins,
    /// any later failure is captured in [`ExecutionOutcome::status`] and
    /// returned as `Ok` so the caller can record the partial workspace
    /// for undo.
    ///
    /// # Errors
    ///
    /// See [`ExecutorError`] for the pre-mutation failure modes.
    pub fn execute(&self, spec: &WorkspaceSpec) -> Result<ExecutionOutcome, ExecutorError> {
        // Defense in depth (Iron Law #11): re-validate before any I/O.
        validate_spec(spec, &self.allowed_root)?;
        self.execute_impl(spec)
    }

    /// Undo a workspace creation by removing its root directory.
    ///
    /// The removal is:
    /// - **containment-checked**: refuses to remove anything not strictly
    ///   under the allowed root;
    /// - **symlink-safe**: if `root_dir` itself is a symlink it removes
    ///   the link, never the target; nested symlinks are removed as links
    ///   (never traversed) by the symlink-aware walk;
    /// - **idempotent**: removing an already-absent root is `Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError`] if `root_dir` is outside the allowed
    /// root or the removal hits an I/O error other than "not found".
    pub fn undo(&self, root_dir: &Path) -> Result<(), ExecutorError> {
        // Containment: component-wise, normalized, strictly under root.
        if !is_strictly_under(root_dir, &self.allowed_root) {
            return Err(ExecutorError::RootOutsideAllowed {
                root: root_dir.display().to_string(),
                allowed: self.allowed_root.display().to_string(),
            });
        }

        match std::fs::symlink_metadata(root_dir) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    // root_dir is itself a symlink: remove the LINK, never
                    // its target.
                    std::fs::remove_file(root_dir).map_err(|e| ExecutorError::AllowedRootOpen {
                        path: root_dir.display().to_string(),
                        source: e,
                    })?;
                    return Ok(());
                }
                // Real directory: symlink-aware recursive removal. Each
                // entry is lstat'd; symlinks are unlinked as links, never
                // followed, so a malicious symlink inside the tree cannot
                // redirect the removal outside the workspace.
                remove_tree_no_follow(root_dir).map_err(|e| ExecutorError::AllowedRootOpen {
                    path: root_dir.display().to_string(),
                    source: e,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()), // idempotent
            Err(e) => Err(ExecutorError::AllowedRootOpen {
                path: root_dir.display().to_string(),
                source: e,
            }),
        }
    }

    #[cfg(target_os = "linux")]
    fn execute_impl(&self, spec: &WorkspaceSpec) -> Result<ExecutionOutcome, ExecutorError> {
        use std::os::fd::AsRawFd;

        let workspace_id = make_workspace_id(&spec.name);

        // strip_prefix is guaranteed to succeed by the validator, but we
        // re-check defensively.
        let root_rel = spec
            .root_dir
            .strip_prefix(&self.allowed_root)
            .map_err(|_| ExecutorError::RootOutsideAllowed {
                root: spec.root_dir.display().to_string(),
                allowed: self.allowed_root.display().to_string(),
            })?;

        // Held directory handle for the allowed root — the trust anchor
        // for the whole operation (O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC).
        let allowed_handle =
            open_dir_handle(&self.allowed_root).map_err(|e| ExecutorError::AllowedRootOpen {
                path: self.allowed_root.display().to_string(),
                source: e,
            })?;
        let allowed_fd = allowed_handle.as_raw_fd();

        // Root-existence gate.
        match open_dir_beneath(allowed_fd, root_rel) {
            Ok(_existing) => {
                // Exists as a real directory beneath the root. It must be
                // empty (we never destroy user data on create).
                if dir_is_nonempty(&spec.root_dir) {
                    return Err(ExecutorError::RootExists(
                        spec.root_dir.display().to_string(),
                    ));
                }
            }
            Err(e) => match e.raw_os_error() {
                Some(libc::ENOENT) => {
                    // Create the workspace root itself.
                    mkdir_beneath(allowed_fd, root_rel).map_err(|me| {
                        // ENOENT here means an ancestor of root_dir under
                        // the allowed root does not exist.
                        ExecutorError::AllowedRootOpen {
                            path: spec.root_dir.display().to_string(),
                            source: me,
                        }
                    })?;
                }
                Some(libc::ELOOP) => {
                    return Err(ExecutorError::SymlinkEncountered(
                        spec.root_dir.display().to_string(),
                    ));
                }
                _ => {
                    return Err(ExecutorError::AllowedRootOpen {
                        path: spec.root_dir.display().to_string(),
                        source: e,
                    });
                }
            },
        }

        // Create entries parent-first so each parent exists (as a real
        // dir we made) before its children.
        let mut entries: Vec<&crate::workspace::spec::DirectoryEntry> =
            spec.directory_tree.iter().collect();
        entries.sort_by_key(|e| Path::new(&e.relative_path).components().count());

        let mut created: u32 = 0;
        for entry in entries {
            let full_rel = root_rel.join(&entry.relative_path);
            let result = match entry.kind {
                EntryKind::Directory => mkdir_beneath(allowed_fd, &full_rel),
                EntryKind::File => {
                    let content = entry.content.as_deref().unwrap_or("");
                    create_file_beneath(allowed_fd, &full_rel, content.as_bytes())
                }
            };
            match result {
                Ok(()) => created = created.saturating_add(1),
                Err(e) => {
                    return Ok(ExecutionOutcome {
                        workspace_id,
                        root_dir: spec.root_dir.clone(),
                        created_entry_count: created,
                        command_outcomes: Vec::new(),
                        status: ExecutionStatus::TreeCreationFailed {
                            path: entry.relative_path.clone(),
                            error: e.to_string(),
                        },
                    });
                }
            }
        }

        // Run setup commands in declaration order; bail (capture + stop)
        // on the first failure.
        let mut command_outcomes = Vec::new();
        let mut status = ExecutionStatus::Completed;
        for cmd in &spec.setup_commands {
            let working_dir = if cmd.working_dir_relative.is_empty() {
                spec.root_dir.clone()
            } else {
                spec.root_dir.join(&cmd.working_dir_relative)
            };
            let outcome = run_command(&working_dir, &cmd.program, &cmd.args, COMMAND_TIMEOUT);
            let failed = !outcome.succeeded();
            let (program, exit_code, timed_out) = (
                outcome.program.clone(),
                outcome.exit_code,
                outcome.timed_out,
            );
            command_outcomes.push(outcome);
            if failed {
                status = ExecutionStatus::CommandFailed {
                    program,
                    exit_code,
                    timed_out,
                };
                break;
            }
        }

        Ok(ExecutionOutcome {
            workspace_id,
            root_dir: spec.root_dir.clone(),
            created_entry_count: created,
            command_outcomes,
            status,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn execute_impl(&self, _spec: &WorkspaceSpec) -> Result<ExecutionOutcome, ExecutorError> {
        Err(ExecutorError::Unsupported(
            "openat2 is Linux-only; workspace creation is disabled on this platform".to_string(),
        ))
    }
}

/// Generate a stable workspace id from the display name and the current
/// epoch. Non-alphanumeric characters in the name are replaced with `-`.
fn make_workspace_id(name: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let slug: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("ws-{slug}-{epoch}")
}

/// Whether `path` is absolute, normalized (no `.`/`..`), and STRICTLY
/// under `root` (component-wise, never string-prefix). Used by `undo`'s
/// containment check independent of the validator.
fn is_strictly_under(path: &Path, root: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    for comp in path.components() {
        if matches!(comp, Component::ParentDir | Component::CurDir) {
            return false;
        }
    }
    path.starts_with(root) && path != root
}

/// `read_dir`-based emptiness check. The caller has already verified via
/// `openat2(RESOLVE_NO_SYMLINKS)` that the path is a real directory under
/// the allowed root; file creation still uses `O_EXCL`, so the small
/// path re-resolution here cannot cause an unsafe write.
fn dir_is_nonempty(path: &Path) -> bool {
    match std::fs::read_dir(path) {
        Ok(mut rd) => rd.next().is_some(),
        Err(_) => false,
    }
}

/// Split a relative path into `(parent, leaf)`. The parent may be the
/// empty path (meaning "the anchor directory itself").
fn split_parent_leaf(rel: &Path) -> Option<(&Path, &std::ffi::OsStr)> {
    let leaf = rel.file_name()?;
    let parent = rel.parent().unwrap_or_else(|| Path::new(""));
    Some((parent, leaf))
}

/// Symlink-aware recursive directory removal. Never follows symlinks:
/// each entry is `symlink_metadata`-checked; symlinks (and files) are
/// unlinked as links, real subdirectories are recursed then `rmdir`-ed.
fn remove_tree_no_follow(dir: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)?;
        let ft = meta.file_type();
        if ft.is_dir() {
            // A real directory (symlinks report is_symlink, not is_dir,
            // under symlink_metadata). The recursive call removes the
            // child's contents AND the child directory itself (its
            // trailing `remove_dir`), so we must NOT remove it again here.
            remove_tree_no_follow(&path)?;
        } else {
            // Regular file or symlink: unlink the entry itself. For a
            // symlink this removes the link, never its target.
            std::fs::remove_file(&path)?;
        }
    }
    std::fs::remove_dir(dir)?;
    Ok(())
}

/// Open a directory as a held handle: `O_DIRECTORY | O_NOFOLLOW |
/// O_CLOEXEC`, read-only. The `O_NOFOLLOW` makes the opened inode the
/// trust anchor even if the path is later swapped for a symlink.
#[cfg(unix)]
fn open_dir_handle(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(not(unix))]
fn open_dir_handle(path: &Path) -> std::io::Result<std::fs::File> {
    let _ = path;
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "directory handles require unix",
    ))
}

// ── Linux openat2 / mkdirat / openat create helpers ─────────────────

/// Open a directory `rel` beneath the held `dirfd` using
/// `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)`. An empty `rel`
/// returns a `dup` of `dirfd` (the anchor directory itself).
#[cfg(target_os = "linux")]
fn open_dir_beneath(dirfd: i32, rel: &Path) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{FromRawFd, OwnedFd};

    if rel.as_os_str().is_empty() {
        // SAFETY: `dirfd` is a valid open directory fd owned by the
        // caller for the duration of this call. `dup` returns a fresh
        // owned fd or -1/errno.
        let dup = unsafe { libc::dup(dirfd) };
        if dup < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `dup` is a fresh, valid, owned fd.
        return Ok(unsafe { OwnedFd::from_raw_fd(dup) });
    }

    let flags = (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    let raw = linux_openat2(dirfd, rel, flags)?;
    // SAFETY: openat2 returned a valid new fd (checked >= 0 inside).
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Create directory `rel` beneath `dirfd`. Resolves the parent via
/// `openat2` (symlink-safe), then `mkdirat` the single-component leaf.
#[cfg(target_os = "linux")]
fn mkdir_beneath(dirfd: i32, rel: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    let (parent, leaf) = split_parent_leaf(rel).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let parent_fd = open_dir_beneath(dirfd, parent)?;
    let leaf_c = CString::new(leaf.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path leaf"))?;

    // SAFETY: parent_fd is a valid directory fd; leaf_c is a valid
    // NUL-terminated C string owned for the call. mkdirat creates a
    // single-component directory relative to parent_fd; it does NOT
    // follow a final-component symlink (returns EEXIST instead).
    let r = unsafe { libc::mkdirat(parent_fd.as_raw_fd(), leaf_c.as_ptr(), 0o755) };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Create and write file `rel` beneath `dirfd`. Resolves the parent via
/// `openat2`, then `openat(O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW)` the leaf
/// so an existing entry or a leaf symlink is refused. Content is written
/// and `fsync`-ed.
#[cfg(target_os = "linux")]
fn create_file_beneath(dirfd: i32, rel: &Path, content: &[u8]) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    let (parent, leaf) = split_parent_leaf(rel).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let parent_fd = open_dir_beneath(dirfd, parent)?;
    let leaf_c = CString::new(leaf.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path leaf"))?;

    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: parent_fd is a valid directory fd; leaf_c is owned for the
    // call. openat with O_CREAT takes a mode via the variadic argument.
    // O_EXCL|O_NOFOLLOW guarantee we create a fresh regular file and
    // never follow/overwrite an existing entry or symlink.
    let raw = unsafe {
        libc::openat(
            parent_fd.as_raw_fd(),
            leaf_c.as_ptr(),
            flags,
            0o644 as libc::c_uint,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: raw is a fresh valid fd; transfer ownership into File.
    let mut file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(raw) });
    file.write_all(content)?;
    file.sync_all()?;
    Ok(())
}

/// Raw `openat2(2)` returning the new fd. `flags` is the open-flags
/// bitfield; resolve flags are fixed to `RESOLVE_NO_SYMLINKS |
/// RESOLVE_BENEATH`. Mirrors `knowledge.rs::linux_openat2_under_held_root`.
#[cfg(target_os = "linux")]
fn linux_openat2(dirfd: i32, rel: &Path, flags: u64) -> std::io::Result<i32> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;

    let rel_c = CString::new(rel.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path"))?;
    let how = OpenHow {
        flags,
        mode: 0,
        resolve: RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH,
    };

    // SAFETY: dirfd is a valid directory fd owned by the caller; rel_c is
    // a NUL-terminated C string owned for the call; &how points to a live
    // stack struct of the given size. The kernel only reads through these
    // pointers and returns a new fd or -1/errno.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            rel_c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(raw as i32)
}

fn spawn_command(builder: &mut std::process::Command) -> std::io::Result<std::process::Child> {
    spawn_command_impl(builder)
}

#[cfg(unix)]
fn spawn_command_impl(builder: &mut std::process::Command) -> std::io::Result<std::process::Child> {
    use std::os::unix::process::CommandExt;
    builder.process_group(0).spawn()
}

#[cfg(not(unix))]
fn spawn_command_impl(builder: &mut std::process::Command) -> std::io::Result<std::process::Child> {
    builder.spawn()
}

#[cfg(unix)]
fn terminate_child_tree(child: &mut std::process::Child) {
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;

    let pgid = Pid::from_raw(child.id() as i32);
    let _ = killpg(pgid, Signal::SIGTERM);
    std::thread::sleep(Duration::from_millis(500));
    if matches!(child.try_wait(), Ok(None)) {
        let _ = killpg(pgid, Signal::SIGKILL);
    }
    let _ = child.wait();
}

#[cfg(not(unix))]
fn terminate_child_tree(child: &mut std::process::Child) {
    // Windows/macOS are not target deployment platforms for the secure
    // executor yet; retain direct-child cleanup there.
    let _ = child.kill();
    let _ = child.wait();
}

/// Run one command with a wall-clock timeout, capturing stdout/stderr.
///
/// The command runs via explicit argv (never a shell) with a minimal
/// environment (`PATH` only). stdout/stderr are drained on dedicated
/// threads to avoid a full-pipe deadlock; the main path polls
/// `try_wait` and kills the child if `timeout` elapses.
///
/// This function does NOT consult the allowlist — that is the
/// validator's responsibility, enforced before any spec reaches the
/// executor. Keeping the primitive allowlist-free lets the timeout /
/// exit-code paths be unit-tested with arbitrary programs.
fn run_command(
    working_dir: &Path,
    program: &str,
    args: &[String],
    timeout: Duration,
) -> CommandOutcome {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let mut builder = Command::new(program);
    builder
        .args(args)
        .current_dir(working_dir)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(path) = std::env::var_os("PATH") {
        builder.env("PATH", path);
    }

    let mut child = match spawn_command(&mut builder) {
        Ok(c) => c,
        Err(e) => {
            return CommandOutcome {
                program: program.to_string(),
                args: args.to_vec(),
                exit_code: None,
                timed_out: false,
                stdout: Vec::new(),
                stderr: format!("failed to spawn: {e}").into_bytes(),
            };
        }
    };

    // Drain pipes on threads so a chatty child can't deadlock on a full
    // pipe buffer while we poll for completion.
    let mut out_pipe = child.stdout.take();
    let mut err_pipe = child.stderr.take();
    let out_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = out_pipe.as_mut() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });
    let err_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = err_pipe.as_mut() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });

    let deadline = Instant::now() + timeout;
    let (exit_code, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status.code(), false),
            Ok(None) => {
                if Instant::now() >= deadline {
                    terminate_child_tree(&mut child);
                    break (None, true);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                terminate_child_tree(&mut child);
                break (None, false);
            }
        }
    };

    let stdout = out_handle.join().unwrap_or_default();
    let stderr = err_handle.join().unwrap_or_default();

    CommandOutcome {
        program: program.to_string(),
        args: args.to_vec(),
        exit_code,
        timed_out,
        stdout,
        stderr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::spec::{DirectoryEntry, TemplateId, WorkspaceMetadata, WorkspaceSpec};
    use crate::workspace::templates;
    use tempfile::TempDir;

    /// Build (allowed_root, executor) backed by a fresh temp dir.
    fn fixture() -> (TempDir, WorkspaceExecutor) {
        let allowed = TempDir::new().unwrap();
        let exec = WorkspaceExecutor::new(allowed.path());
        (allowed, exec)
    }

    fn ws_root(allowed: &TempDir, name: &str) -> PathBuf {
        allowed.path().join(name)
    }

    fn finalize(mut spec: WorkspaceSpec) -> WorkspaceSpec {
        spec.metadata = spec.compute_metadata();
        spec
    }

    // ── helpers visible on all platforms ──────────────────────────────

    #[test]
    fn make_workspace_id_slugifies() {
        let id = make_workspace_id("My Project!");
        assert!(id.starts_with("ws-My-Project-"));
    }

    #[test]
    fn is_strictly_under_accepts_child() {
        assert!(is_strictly_under(Path::new("/a/b/c"), Path::new("/a/b")));
    }

    #[test]
    fn is_strictly_under_rejects_equal() {
        assert!(!is_strictly_under(Path::new("/a/b"), Path::new("/a/b")));
    }

    #[test]
    fn is_strictly_under_rejects_sibling_prefix() {
        assert!(!is_strictly_under(Path::new("/a/bcd"), Path::new("/a/b")));
    }

    #[test]
    fn is_strictly_under_rejects_parentdir() {
        assert!(!is_strictly_under(
            Path::new("/a/b/../../etc"),
            Path::new("/a/b")
        ));
    }

    #[test]
    fn split_parent_leaf_single_component() {
        let (p, l) = split_parent_leaf(Path::new("ws")).unwrap();
        assert_eq!(p, Path::new(""));
        assert_eq!(l, std::ffi::OsStr::new("ws"));
    }

    #[test]
    fn split_parent_leaf_nested() {
        let (p, l) = split_parent_leaf(Path::new("ws/notes/lit.md")).unwrap();
        assert_eq!(p, Path::new("ws/notes"));
        assert_eq!(l, std::ffi::OsStr::new("lit.md"));
    }

    #[test]
    fn command_outcome_succeeded_predicate() {
        let ok = CommandOutcome {
            program: "p".into(),
            args: vec![],
            exit_code: Some(0),
            timed_out: false,
            stdout: vec![],
            stderr: vec![],
        };
        assert!(ok.succeeded());
        let nonzero = CommandOutcome {
            exit_code: Some(1),
            ..ok.clone()
        };
        assert!(!nonzero.succeeded());
        let timed = CommandOutcome {
            exit_code: None,
            timed_out: true,
            ..ok.clone()
        };
        assert!(!timed.succeeded());
    }

    #[test]
    fn execution_status_is_complete_predicate() {
        assert!(ExecutionStatus::Completed.is_complete());
        assert!(
            !ExecutionStatus::CommandFailed {
                program: "git".into(),
                exit_code: Some(1),
                timed_out: false,
            }
            .is_complete()
        );
        assert!(
            !ExecutionStatus::TreeCreationFailed {
                path: "x".into(),
                error: "e".into(),
            }
            .is_complete()
        );
    }

    // ── Linux-only: real filesystem execution ─────────────────────────

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use std::path::Path;

        /// A spec with no setup commands (pure filesystem creation), so
        /// tests don't depend on `git` being installed.
        fn fs_only_spec(allowed: &TempDir, name: &str) -> WorkspaceSpec {
            let root = ws_root(allowed, name);
            finalize(WorkspaceSpec {
                name: name.to_string(),
                root_dir: root,
                template_id: TemplateId::Research,
                directory_tree: vec![
                    DirectoryEntry {
                        relative_path: "papers".to_string(),
                        kind: EntryKind::Directory,
                        content: None,
                    },
                    DirectoryEntry {
                        relative_path: "notes".to_string(),
                        kind: EntryKind::Directory,
                        content: None,
                    },
                    DirectoryEntry {
                        relative_path: "notes/lit.md".to_string(),
                        kind: EntryKind::File,
                        content: Some("# lit\n".to_string()),
                    },
                    DirectoryEntry {
                        relative_path: "README.md".to_string(),
                        kind: EntryKind::File,
                        content: Some("# readme\n".to_string()),
                    },
                ],
                setup_commands: vec![],
                calendar_blocks: vec![],
                metadata: WorkspaceMetadata::default(),
            })
        }

        #[test]
        fn execute_creates_directories_and_files() {
            let (allowed, exec) = fixture();
            let spec = fs_only_spec(&allowed, "ws");
            let outcome = exec.execute(&spec).unwrap();
            assert!(outcome.status.is_complete());
            assert_eq!(outcome.created_entry_count, 4);
            assert!(spec.root_dir.join("papers").is_dir());
            assert!(spec.root_dir.join("notes").is_dir());
            assert!(spec.root_dir.join("notes/lit.md").is_file());
            assert!(spec.root_dir.join("README.md").is_file());
        }

        #[test]
        fn execute_writes_correct_file_contents() {
            let (allowed, exec) = fixture();
            let spec = fs_only_spec(&allowed, "ws");
            exec.execute(&spec).unwrap();
            let body = std::fs::read_to_string(spec.root_dir.join("notes/lit.md")).unwrap();
            assert_eq!(body, "# lit\n");
        }

        #[test]
        fn execute_sets_conservative_file_mode() {
            use std::os::unix::fs::PermissionsExt;
            let (allowed, exec) = fixture();
            let spec = fs_only_spec(&allowed, "ws");
            exec.execute(&spec).unwrap();
            let meta = std::fs::metadata(spec.root_dir.join("README.md")).unwrap();
            // 0o644 subject to umask; the file must not be world-writable.
            assert_eq!(meta.permissions().mode() & 0o022, 0);
        }

        #[test]
        fn execute_each_baseline_template_creates_tree() {
            let names = ["research", "code", "document", "design"];
            let builders: [fn(&str, &Path) -> WorkspaceSpec; 4] = [
                |n, r| templates::build_research_template(n, r),
                |n, r| {
                    templates::build_code_project_template(
                        n,
                        r,
                        &templates::TemplateParams::default(),
                    )
                },
                |n, r| templates::build_document_template(n, r),
                |n, r| templates::build_design_template(n, r),
            ];
            for (name, builder) in names.iter().zip(builders.iter()) {
                let allowed = TempDir::new().unwrap();
                let exec = WorkspaceExecutor::new(allowed.path());
                let root = allowed.path().join(name);
                let spec = builder(name, &root);
                // Drop setup_commands so the test does not depend on git.
                let mut spec = spec;
                spec.setup_commands.clear();
                spec.metadata = spec.compute_metadata();
                let outcome = exec.execute(&spec).unwrap();
                assert!(
                    outcome.status.is_complete(),
                    "template {name} should execute cleanly"
                );
                assert!(root.join("README.md").is_file());
            }
        }

        #[test]
        fn execute_rejects_invalid_spec_at_revalidation() {
            let (allowed, exec) = fixture();
            let mut spec = fs_only_spec(&allowed, "ws");
            // Corrupt a path to a traversal AFTER metadata is computed —
            // simulates a spec that bypassed the validator.
            spec.directory_tree[0].relative_path = "../escape".to_string();
            let err = exec.execute(&spec).unwrap_err();
            assert!(matches!(err, ExecutorError::Validation(_)));
        }

        #[test]
        fn execute_rejects_root_outside_allowed() {
            let allowed = TempDir::new().unwrap();
            let other = TempDir::new().unwrap();
            let exec = WorkspaceExecutor::new(allowed.path());
            let mut spec = fs_only_spec(&allowed, "ws");
            spec.root_dir = other.path().join("ws");
            spec.metadata = spec.compute_metadata();
            let err = exec.execute(&spec).unwrap_err();
            // Validation catches it first (root not under allowed).
            assert!(matches!(err, ExecutorError::Validation(_)));
        }

        #[test]
        fn execute_bails_when_root_nonempty() {
            let (allowed, exec) = fixture();
            let spec = fs_only_spec(&allowed, "ws");
            std::fs::create_dir(&spec.root_dir).unwrap();
            std::fs::write(spec.root_dir.join("preexisting.txt"), b"hi").unwrap();
            let err = exec.execute(&spec).unwrap_err();
            assert!(matches!(err, ExecutorError::RootExists(_)));
        }

        #[test]
        fn execute_accepts_preexisting_empty_root() {
            let (allowed, exec) = fixture();
            let spec = fs_only_spec(&allowed, "ws");
            std::fs::create_dir(&spec.root_dir).unwrap();
            let outcome = exec.execute(&spec).unwrap();
            assert!(outcome.status.is_complete());
            assert!(spec.root_dir.join("README.md").is_file());
        }

        #[test]
        fn execute_refuses_root_that_is_symlink() {
            let (allowed, exec) = fixture();
            let target = TempDir::new().unwrap();
            let link = allowed.path().join("ws");
            std::os::unix::fs::symlink(target.path(), &link).unwrap();
            let spec = fs_only_spec(&allowed, "ws");
            let err = exec.execute(&spec).unwrap_err();
            // openat2(RESOLVE_NO_SYMLINKS) on the root yields ELOOP, OR
            // the read_dir emptiness check sees the (non-empty) target.
            assert!(
                matches!(
                    err,
                    ExecutorError::SymlinkEncountered(_) | ExecutorError::RootExists(_)
                ),
                "got {err:?}"
            );
        }

        #[test]
        fn execute_refuses_symlinked_intermediate_dir() {
            // Pre-create the workspace root, then replace an intermediate
            // dir with a symlink. The parent resolution via
            // openat2(RESOLVE_NO_SYMLINKS) must refuse to descend it.
            let (allowed, exec) = fixture();
            let root = ws_root(&allowed, "ws");
            std::fs::create_dir(&root).unwrap();
            let escape = TempDir::new().unwrap();
            // `notes` is a symlink pointing outside the workspace.
            std::os::unix::fs::symlink(escape.path(), root.join("notes")).unwrap();
            // root is now non-empty, so the create path bails early; this
            // documents that we never write through the symlink.
            let spec = fs_only_spec(&allowed, "ws");
            let err = exec.execute(&spec).unwrap_err();
            assert!(matches!(err, ExecutorError::RootExists(_)));
            // The escape target must remain untouched.
            assert!(escape.path().exists());
        }

        #[test]
        fn execute_creates_nested_depth() {
            let (allowed, exec) = fixture();
            let root = ws_root(&allowed, "ws");
            let spec = finalize(WorkspaceSpec {
                name: "ws".to_string(),
                root_dir: root.clone(),
                template_id: TemplateId::Research,
                directory_tree: vec![
                    DirectoryEntry {
                        relative_path: "a".to_string(),
                        kind: EntryKind::Directory,
                        content: None,
                    },
                    DirectoryEntry {
                        relative_path: "a/b".to_string(),
                        kind: EntryKind::Directory,
                        content: None,
                    },
                    DirectoryEntry {
                        relative_path: "a/b/c".to_string(),
                        kind: EntryKind::Directory,
                        content: None,
                    },
                    DirectoryEntry {
                        relative_path: "a/b/c/deep.txt".to_string(),
                        kind: EntryKind::File,
                        content: Some("deep".to_string()),
                    },
                ],
                setup_commands: vec![],
                calendar_blocks: vec![],
                metadata: WorkspaceMetadata::default(),
            });
            let outcome = exec.execute(&spec).unwrap();
            assert!(outcome.status.is_complete());
            assert_eq!(
                std::fs::read_to_string(root.join("a/b/c/deep.txt")).unwrap(),
                "deep"
            );
        }

        #[test]
        fn execute_unsorted_tree_creates_parents_first() {
            // Children listed before parents; the executor sorts by depth.
            let (allowed, exec) = fixture();
            let root = ws_root(&allowed, "ws");
            let spec = finalize(WorkspaceSpec {
                name: "ws".to_string(),
                root_dir: root.clone(),
                template_id: TemplateId::Research,
                directory_tree: vec![
                    DirectoryEntry {
                        relative_path: "a/b/file.txt".to_string(),
                        kind: EntryKind::File,
                        content: Some("x".to_string()),
                    },
                    DirectoryEntry {
                        relative_path: "a/b".to_string(),
                        kind: EntryKind::Directory,
                        content: None,
                    },
                    DirectoryEntry {
                        relative_path: "a".to_string(),
                        kind: EntryKind::Directory,
                        content: None,
                    },
                ],
                setup_commands: vec![],
                calendar_blocks: vec![],
                metadata: WorkspaceMetadata::default(),
            });
            let outcome = exec.execute(&spec).unwrap();
            assert!(outcome.status.is_complete(), "got {:?}", outcome.status);
            assert!(root.join("a/b/file.txt").is_file());
        }

        // ── undo ──────────────────────────────────────────────────────

        #[test]
        fn undo_removes_workspace() {
            let (allowed, exec) = fixture();
            let spec = fs_only_spec(&allowed, "ws");
            exec.execute(&spec).unwrap();
            assert!(spec.root_dir.exists());
            exec.undo(&spec.root_dir).unwrap();
            assert!(!spec.root_dir.exists());
        }

        #[test]
        fn undo_is_idempotent() {
            let (allowed, exec) = fixture();
            let spec = fs_only_spec(&allowed, "ws");
            exec.execute(&spec).unwrap();
            exec.undo(&spec.root_dir).unwrap();
            // Second undo on an absent root is a no-op success.
            exec.undo(&spec.root_dir).unwrap();
        }

        #[test]
        fn undo_on_never_created_is_ok() {
            let (allowed, exec) = fixture();
            let root = ws_root(&allowed, "never");
            exec.undo(&root).unwrap();
        }

        #[test]
        fn undo_refuses_path_outside_allowed() {
            let (allowed, exec) = fixture();
            let _ = &allowed;
            let outside = TempDir::new().unwrap();
            let victim = outside.path().join("victim");
            std::fs::create_dir(&victim).unwrap();
            let err = exec.undo(&victim).unwrap_err();
            assert!(matches!(err, ExecutorError::RootOutsideAllowed { .. }));
            assert!(
                victim.exists(),
                "undo must not touch paths outside allowed root"
            );
        }

        #[test]
        fn undo_does_not_follow_symlink_to_external_target() {
            // Workspace contains a symlink pointing to an external file.
            // Undo must remove the LINK, leaving the target intact.
            let (allowed, exec) = fixture();
            let spec = fs_only_spec(&allowed, "ws");
            exec.execute(&spec).unwrap();

            let external = TempDir::new().unwrap();
            let sentinel = external.path().join("precious.txt");
            std::fs::write(&sentinel, b"do not delete").unwrap();
            std::os::unix::fs::symlink(&sentinel, spec.root_dir.join("link-to-precious")).unwrap();

            exec.undo(&spec.root_dir).unwrap();
            assert!(!spec.root_dir.exists());
            assert!(
                sentinel.exists(),
                "undo must not follow symlink to delete external target"
            );
            assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "do not delete");
        }

        #[test]
        fn undo_root_itself_symlink_removes_link_only() {
            let (allowed, exec) = fixture();
            let external = TempDir::new().unwrap();
            std::fs::write(external.path().join("keep.txt"), b"keep").unwrap();
            let link = ws_root(&allowed, "ws");
            std::os::unix::fs::symlink(external.path(), &link).unwrap();
            exec.undo(&link).unwrap();
            assert!(!link.exists());
            assert!(external.path().join("keep.txt").exists());
        }

        // ── concurrency ────────────────────────────────────────────────

        #[test]
        fn concurrent_distinct_workspaces_both_succeed() {
            let allowed = TempDir::new().unwrap();
            let allowed_path = allowed.path().to_path_buf();
            let handles: Vec<_> = (0..4)
                .map(|i| {
                    let ap = allowed_path.clone();
                    std::thread::spawn(move || {
                        let exec = WorkspaceExecutor::new(&ap);
                        let name = format!("ws{i}");
                        let root = ap.join(&name);
                        let spec = finalize(WorkspaceSpec {
                            name: name.clone(),
                            root_dir: root,
                            template_id: TemplateId::Research,
                            directory_tree: vec![DirectoryEntry {
                                relative_path: "README.md".to_string(),
                                kind: EntryKind::File,
                                content: Some("x".to_string()),
                            }],
                            setup_commands: vec![],
                            calendar_blocks: vec![],
                            metadata: WorkspaceMetadata::default(),
                        });
                        exec.execute(&spec).map(|o| o.status.is_complete())
                    })
                })
                .collect();
            for h in handles {
                assert!(h.join().unwrap().unwrap());
            }
        }

        #[test]
        fn concurrent_same_root_one_wins() {
            let allowed = TempDir::new().unwrap();
            let allowed_path = allowed.path().to_path_buf();
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let ap = allowed_path.clone();
                    let b = std::sync::Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        let exec = WorkspaceExecutor::new(&ap);
                        let root = ap.join("shared");
                        let spec = finalize(WorkspaceSpec {
                            name: "shared".to_string(),
                            root_dir: root,
                            template_id: TemplateId::Research,
                            directory_tree: (0..20)
                                .map(|j| DirectoryEntry {
                                    relative_path: format!("f{j}.txt"),
                                    kind: EntryKind::File,
                                    content: Some("x".to_string()),
                                })
                                .collect(),
                            setup_commands: vec![],
                            calendar_blocks: vec![],
                            metadata: WorkspaceMetadata::default(),
                        });
                        b.wait();
                        exec.execute(&spec)
                    })
                })
                .collect();
            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            // Exactly one attempt may report a fully-complete success.
            // If both complete, overlapping create calls raced past the
            // root/leaf O_EXCL boundary.
            let complete_count = results
                .iter()
                .filter(|r| matches!(r, Ok(o) if o.status.is_complete()))
                .count();
            assert_eq!(complete_count, 1, "only one creation should complete");
        }

        #[test]
        fn execute_denied_when_allowed_root_unwritable() {
            use std::os::unix::fs::PermissionsExt;
            let allowed = TempDir::new().unwrap();
            let exec = WorkspaceExecutor::new(allowed.path());
            // Make the allowed root read+execute only (no write) so
            // mkdirat of the workspace root fails with EACCES.
            let mut perms = std::fs::metadata(allowed.path()).unwrap().permissions();
            perms.set_mode(0o555);
            std::fs::set_permissions(allowed.path(), perms).unwrap();

            let spec = fs_only_spec(&allowed, "ws");
            let result = exec.execute(&spec);

            // Restore perms so TempDir cleanup can run.
            let mut restore = std::fs::metadata(allowed.path()).unwrap().permissions();
            restore.set_mode(0o755);
            std::fs::set_permissions(allowed.path(), restore).unwrap();

            assert!(
                result.is_err(),
                "creation under an unwritable root must fail"
            );
        }

        // ── command execution primitive ────────────────────────────────

        #[test]
        fn run_command_captures_success() {
            let dir = TempDir::new().unwrap();
            let outcome = run_command(dir.path(), "true", &[], Duration::from_secs(5));
            assert!(outcome.succeeded());
            assert_eq!(outcome.exit_code, Some(0));
            assert!(!outcome.timed_out);
        }

        #[test]
        fn run_command_captures_nonzero_exit() {
            let dir = TempDir::new().unwrap();
            let outcome = run_command(dir.path(), "false", &[], Duration::from_secs(5));
            assert!(!outcome.succeeded());
            assert_eq!(outcome.exit_code, Some(1));
        }

        #[test]
        fn run_command_captures_stdout() {
            let dir = TempDir::new().unwrap();
            let outcome = run_command(
                dir.path(),
                "echo",
                &["hello".to_string()],
                Duration::from_secs(5),
            );
            assert!(outcome.succeeded());
            assert_eq!(String::from_utf8_lossy(&outcome.stdout).trim(), "hello");
        }

        #[test]
        fn run_command_times_out_long_process() {
            let dir = TempDir::new().unwrap();
            let start = std::time::Instant::now();
            let outcome = run_command(
                dir.path(),
                "sleep",
                &["30".to_string()],
                Duration::from_millis(300),
            );
            assert!(outcome.timed_out, "sleep 30 must time out at 300ms");
            assert!(outcome.exit_code.is_none());
            // Should return promptly after the timeout, not after 30s.
            assert!(start.elapsed() < Duration::from_secs(5));
        }

        #[test]
        fn timeout_kills_descendant_processes() {
            use nix::errno::Errno;
            use nix::sys::signal;
            use nix::unistd::Pid;

            let dir = TempDir::new().unwrap();
            let pid_file = dir.path().join("descendant.pid");
            let script = format!("sleep 30 & echo $! > {}; sleep 30", pid_file.display());
            let outcome = run_command(
                dir.path(),
                "/bin/sh",
                &["-c".to_string(), script],
                Duration::from_millis(300),
            );
            assert!(outcome.timed_out, "shell command should time out");

            let mut pid_text = String::new();
            for _ in 0..20 {
                if let Ok(text) = std::fs::read_to_string(&pid_file) {
                    pid_text = text;
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let descendant_pid: i32 = pid_text.trim().parse().expect("descendant pid");
            std::thread::sleep(Duration::from_millis(500));
            let still_exists = signal::kill(Pid::from_raw(descendant_pid), None);
            assert!(
                matches!(still_exists, Err(Errno::ESRCH)),
                "descendant {descendant_pid} should be gone, got {still_exists:?}"
            );
        }

        #[test]
        fn run_command_missing_program_is_captured() {
            let dir = TempDir::new().unwrap();
            let outcome = run_command(
                dir.path(),
                "definitely-not-a-real-program-xyz",
                &[],
                Duration::from_secs(5),
            );
            assert!(!outcome.succeeded());
            assert!(!outcome.stderr.is_empty());
        }

        #[test]
        fn run_command_minimal_env_has_no_inherited_vars() {
            // Set a sentinel var in the parent; the child (env_clear) must
            // not see it. We probe via `env` and grep its output.
            let dir = TempDir::new().unwrap();
            // SAFETY: single-threaded test setup; set then read.
            unsafe { std::env::set_var("DELPHI_SENTINEL_XYZ", "leak") };
            let outcome = run_command(dir.path(), "env", &[], Duration::from_secs(5));
            unsafe { std::env::remove_var("DELPHI_SENTINEL_XYZ") };
            let out = String::from_utf8_lossy(&outcome.stdout);
            assert!(
                !out.contains("DELPHI_SENTINEL_XYZ"),
                "child env must not inherit parent vars beyond PATH"
            );
        }

        #[test]
        fn execute_runs_git_init_when_available() {
            // Integration: a spec whose single command is the allowlisted
            // `git init --quiet`. Skips gracefully if git is absent.
            let git_present = run_command(
                std::env::temp_dir().as_path(),
                "git",
                &["--version".to_string()],
                Duration::from_secs(5),
            )
            .succeeded();
            if !git_present {
                return;
            }
            let (allowed, exec) = fixture();
            let spec = templates::build_research_template("ws", &ws_root(&allowed, "ws"));
            let outcome = exec.execute(&spec).unwrap();
            assert!(outcome.status.is_complete(), "got {:?}", outcome.status);
            assert_eq!(outcome.command_outcomes.len(), 1);
            assert!(outcome.command_outcomes[0].succeeded());
            assert!(spec.root_dir.join(".git").is_dir());
        }

        #[test]
        fn execute_records_command_failure_in_status() {
            let (allowed, exec) = fixture();
            let spec = finalize(WorkspaceSpec {
                name: "ws".to_string(),
                root_dir: ws_root(&allowed, "ws"),
                template_id: TemplateId::Research,
                directory_tree: vec![DirectoryEntry {
                    relative_path: "Cargo.toml".to_string(),
                    kind: EntryKind::File,
                    content: Some(
                        "[package]\nname = \"already-here\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
                            .to_string(),
                    ),
                }],
                setup_commands: vec![crate::workspace::spec::SetupCommand {
                    program: "cargo".to_string(),
                    args: vec!["init".to_string()],
                    working_dir_relative: String::new(),
                    description: "cargo init must fail on an existing Cargo.toml".to_string(),
                }],
                calendar_blocks: vec![],
                metadata: WorkspaceMetadata::default(),
            });
            let outcome = exec.execute(&spec).unwrap();
            assert!(
                matches!(
                    outcome.status,
                    ExecutionStatus::CommandFailed {
                        program: ref p,
                        ..
                    } if p == "cargo"
                ),
                "expected cargo CommandFailed, got {:?}",
                outcome.status
            );
            assert_eq!(outcome.command_outcomes.len(), 1);
            assert!(!outcome.command_outcomes[0].succeeded());
        }

        #[test]
        fn execute_distinct_names_get_distinct_ids() {
            let (allowed, exec) = fixture();
            let a = fs_only_spec(&allowed, "alpha");
            let b = fs_only_spec(&allowed, "beta");
            let oa = exec.execute(&a).unwrap();
            let ob = exec.execute(&b).unwrap();
            assert_ne!(oa.workspace_id, ob.workspace_id);
            assert!(oa.workspace_id.contains("alpha"));
            assert!(ob.workspace_id.contains("beta"));
        }

        #[test]
        fn execute_empty_tree_creates_only_root() {
            let (allowed, exec) = fixture();
            let root = ws_root(&allowed, "bare");
            let spec = finalize(WorkspaceSpec {
                name: "bare".to_string(),
                root_dir: root.clone(),
                template_id: TemplateId::Research,
                directory_tree: vec![],
                setup_commands: vec![],
                calendar_blocks: vec![],
                metadata: WorkspaceMetadata::default(),
            });
            let outcome = exec.execute(&spec).unwrap();
            assert!(outcome.status.is_complete());
            assert_eq!(outcome.created_entry_count, 0);
            assert!(root.is_dir());
        }

        #[test]
        fn undo_removes_deeply_nested_tree() {
            let (allowed, exec) = fixture();
            let root = ws_root(&allowed, "deep");
            let spec = finalize(WorkspaceSpec {
                name: "deep".to_string(),
                root_dir: root.clone(),
                template_id: TemplateId::Research,
                directory_tree: vec![
                    DirectoryEntry {
                        relative_path: "a".to_string(),
                        kind: EntryKind::Directory,
                        content: None,
                    },
                    DirectoryEntry {
                        relative_path: "a/b".to_string(),
                        kind: EntryKind::Directory,
                        content: None,
                    },
                    DirectoryEntry {
                        relative_path: "a/b/c".to_string(),
                        kind: EntryKind::Directory,
                        content: None,
                    },
                    DirectoryEntry {
                        relative_path: "a/b/c/x.txt".to_string(),
                        kind: EntryKind::File,
                        content: Some("x".to_string()),
                    },
                    DirectoryEntry {
                        relative_path: "a/b/y.txt".to_string(),
                        kind: EntryKind::File,
                        content: Some("y".to_string()),
                    },
                ],
                setup_commands: vec![],
                calendar_blocks: vec![],
                metadata: WorkspaceMetadata::default(),
            });
            exec.execute(&spec).unwrap();
            assert!(root.join("a/b/c/x.txt").is_file());
            exec.undo(&root).unwrap();
            assert!(!root.exists());
        }

        #[test]
        fn execute_then_undo_round_trip_clean() {
            let (allowed, exec) = fixture();
            let spec = fs_only_spec(&allowed, "roundtrip");
            exec.execute(&spec).unwrap();
            assert!(spec.root_dir.join("notes/lit.md").is_file());
            exec.undo(&spec.root_dir).unwrap();
            assert!(!spec.root_dir.exists());
            // allowed root still exists and is now empty of the workspace.
            assert!(allowed.path().is_dir());
            assert!(!allowed.path().join("roundtrip").exists());
        }
    }
}
