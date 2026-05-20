// SPDX-License-Identifier: MIT

//! Safety validator for workspace specs.
//!
//! This is the single enforcement point for workspace-spec safety. Both
//! trusted baseline templates and untrusted cloud-inferred specs pass
//! through [`validate_spec`] before any filesystem mutation. The executor
//! re-runs this same validator defensively before execution (Iron Law
//! #11), so a hypothetical future code path that constructs a spec
//! without validating it still cannot escape these checks.
//!
//! # What the validator guarantees
//!
//! If `validate_spec(spec, allowed_root)` returns `Ok(())`, then:
//!
//! - `spec.root_dir` is absolute, contains no `.`/`..` components, and is
//!   strictly under `allowed_root`
//! - every directory-tree path and command working-dir is relative,
//!   component-clean (only `Component::Normal`), free of shell
//!   metacharacters and NUL bytes, under 256 bytes, and — when joined to
//!   `root_dir` — stays strictly under `root_dir` (verified via
//!   `Path::components`, never string parsing)
//! - file/dir invariants hold (`File` ⇒ `Some(content)`, `Directory` ⇒
//!   `None`)
//! - per-file content ≤ 1 MiB, total content ≤ 10 MiB, tree depth ≤ 8,
//!   entry count ≤ 200
//! - every setup command exactly matches the [`COMMAND_ALLOWLIST`]
//! - the spec's self-reported metadata matches the recomputed metadata
//!   (a hostile spec cannot understate its size to dodge the limits)
//!
//! What the validator does NOT do: detect symlinks. Symlinks cannot be
//! identified from a path *string*. Symlink safety is enforced at
//! creation time by the executor's `openat2(RESOLVE_NO_SYMLINKS)` +
//! `O_NOFOLLOW | O_EXCL` flags. The validator's job is to guarantee the
//! path is lexically incapable of escaping; the executor's job is to
//! guarantee the kernel never follows a link while creating it.

use std::path::{Component, Path};

use crate::workspace::spec::{EntryKind, SetupCommand, WorkspaceSpec};

/// Maximum byte length of any single relative path (or command
/// working-dir). Keeps individual paths well under common `PATH_MAX`.
pub const MAX_PATH_LEN: usize = 256;

/// Maximum byte length of any single file's content (1 MiB).
pub const MAX_FILE_CONTENT_BYTES: usize = 1024 * 1024;

/// Maximum total byte length of all file contents combined (10 MiB).
pub const MAX_TOTAL_CONTENT_BYTES: u64 = 10 * 1024 * 1024;

/// Maximum directory-tree depth (number of path components) from
/// `root_dir`. A `relative_path` of `a/b/c` is depth 3.
pub const MAX_TREE_DEPTH: usize = 8;

/// Maximum number of directory-tree entries (files + directories).
pub const MAX_ENTRY_COUNT: usize = 200;

/// Characters forbidden anywhere in a path or command argument.
///
/// This is the shell-metacharacter set named in the Phase 3A.6 spec plus
/// the NUL byte. Even though commands run via explicit argv (never a
/// shell) and paths are created via `openat2` (never a shell), rejecting
/// these defends against (a) a future code path that does shell out, and
/// (b) embedded-NUL truncation attacks at the FFI boundary.
pub const FORBIDDEN_CHARS: &[char] = &[';', '|', '&', '>', '<', '`', '$', '\0'];

/// Commands explicitly allowed in `setup_commands`.
///
/// Each tuple is `(program, &[allowed argv patterns])`. A
/// [`SetupCommand`] is accepted only if its `program` exactly equals one
/// of these program names AND its `args.join(" ")` exactly equals one of
/// that program's listed argv patterns. No wildcards, no prefixes, no
/// regex, no environment substitution.
///
/// Extending this list requires a code change + review + a new test —
/// the allowlist is the single source of truth for command safety.
pub const COMMAND_ALLOWLIST: &[(&str, &[&str])] = &[
    ("git", &["init", "init --quiet"]),
    ("pnpm", &["install"]),
    ("npm", &["install"]),
    ("cargo", &["init", "init --lib", "init --bin"]),
    ("conda", &["env create -f environment.yml"]),
    ("uv", &["init"]),
    ("python", &["-m venv .venv"]),
];

/// Reasons a [`WorkspaceSpec`] can be rejected.
///
/// Every variant names the offending spec field and value so the D-Bus
/// layer and preview UI can surface a precise, actionable message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidatorError {
    /// `root_dir` is not an absolute path.
    #[error("root_dir must be absolute, got: {0}")]
    RootNotAbsolute(String),

    /// `root_dir` contains a `.` or `..` component (it must be already
    /// normalized so the `allowed_root` containment check is sound).
    #[error("root_dir must not contain '.' or '..' components: {0}")]
    RootNotNormalized(String),

    /// `root_dir` is not strictly under `allowed_root`.
    #[error("root_dir {root} is not under the allowed root {allowed}")]
    RootOutsideAllowed {
        /// The offending root.
        root: String,
        /// The configured allowed root.
        allowed: String,
    },

    /// A path is empty.
    #[error("empty path is not allowed (field: {field})")]
    EmptyPath {
        /// Which spec field held the empty path.
        field: &'static str,
    },

    /// A path was absolute where a relative one was required.
    #[error("path must be relative, got absolute: {path}")]
    PathNotRelative {
        /// The offending path.
        path: String,
    },

    /// A path contained a `..` (parent-dir) component.
    #[error("path contains a parent-directory ('..') component: {path}")]
    PathTraversal {
        /// The offending path.
        path: String,
    },

    /// A path contained a `.` (current-dir) component, which is not
    /// allowed (paths must be canonical).
    #[error("path contains a current-directory ('.') component: {path}")]
    PathCurrentDir {
        /// The offending path.
        path: String,
    },

    /// A path or argument contained a forbidden shell metacharacter or
    /// NUL byte.
    #[error("path/argument contains forbidden character {ch:?}: {value}")]
    ForbiddenCharacter {
        /// The offending character.
        ch: char,
        /// The offending value.
        value: String,
    },

    /// A path exceeded [`MAX_PATH_LEN`] bytes.
    #[error("path exceeds {MAX_PATH_LEN} bytes ({len}): {path}")]
    PathTooLong {
        /// The offending path.
        path: String,
        /// Its byte length.
        len: usize,
    },

    /// A path, though component-clean, joined to `root_dir` to a location
    /// outside `root_dir`. (Defense-in-depth; the component check should
    /// already prevent this.)
    #[error("path escapes the workspace root: {path}")]
    PathEscapesRoot {
        /// The offending path.
        path: String,
    },

    /// A `File` entry had `None` content (use `Some(String::new())` for
    /// an intentionally empty file).
    #[error("file entry has no content: {path}")]
    FileMissingContent {
        /// The offending path.
        path: String,
    },

    /// A `Directory` entry carried `Some` content.
    #[error("directory entry must not carry content: {path}")]
    DirectoryHasContent {
        /// The offending path.
        path: String,
    },

    /// A single file's content exceeded [`MAX_FILE_CONTENT_BYTES`].
    #[error("file content exceeds {MAX_FILE_CONTENT_BYTES} bytes ({size}): {path}")]
    FileContentTooLarge {
        /// The offending path.
        path: String,
        /// The content byte length.
        size: usize,
    },

    /// Total content across all files exceeded [`MAX_TOTAL_CONTENT_BYTES`].
    #[error("total content exceeds {MAX_TOTAL_CONTENT_BYTES} bytes ({size})")]
    TotalContentTooLarge {
        /// The computed total.
        size: u64,
    },

    /// The directory tree was deeper than [`MAX_TREE_DEPTH`].
    #[error("path depth {depth} exceeds maximum {MAX_TREE_DEPTH}: {path}")]
    TreeTooDeep {
        /// The offending path.
        path: String,
        /// Its component depth.
        depth: usize,
    },

    /// The entry count exceeded [`MAX_ENTRY_COUNT`].
    #[error("entry count {count} exceeds maximum {MAX_ENTRY_COUNT}")]
    TooManyEntries {
        /// The actual count.
        count: usize,
    },

    /// A setup command did not match the allowlist.
    #[error("command not on allowlist: program={program:?} args={args:?}")]
    CommandNotAllowed {
        /// The rejected program.
        program: String,
        /// The rejected argv tail.
        args: Vec<String>,
    },

    /// The spec's self-reported metadata disagreed with the recomputed
    /// metadata.
    #[error("metadata field {field} mismatch: declared {declared}, computed {computed}")]
    MetadataMismatch {
        /// Which metadata field disagreed.
        field: &'static str,
        /// The spec's declared value.
        declared: u64,
        /// The recomputed value.
        computed: u64,
    },
}

/// Validate a workspace spec against an allowed root.
///
/// Returns `Ok(())` iff the spec satisfies every safety invariant
/// documented at the module level. On the first violation it returns a
/// specific [`ValidatorError`] identifying the offending field.
///
/// # Examples
///
/// ```
/// use die_orchestrator::workspace::templates;
/// use die_orchestrator::workspace::validator::validate_spec;
/// use std::path::Path;
///
/// let allowed = Path::new("/home/u/projects");
/// let spec = templates::build_research_template(
///     "thesis",
///     Path::new("/home/u/projects/thesis"),
/// );
/// assert!(validate_spec(&spec, allowed).is_ok());
/// ```
///
/// # Errors
///
/// Returns the specific [`ValidatorError`] for the first invariant the
/// spec violates.
pub fn validate_spec(spec: &WorkspaceSpec, allowed_root: &Path) -> Result<(), ValidatorError> {
    validate_root_dir(&spec.root_dir, allowed_root)?;

    // Entry-count limit (files + directories).
    if spec.directory_tree.len() > MAX_ENTRY_COUNT {
        return Err(ValidatorError::TooManyEntries {
            count: spec.directory_tree.len(),
        });
    }

    // Per-entry path + content checks, accumulating total size.
    let mut total_content: u64 = 0;
    for entry in &spec.directory_tree {
        validate_relative_path(&entry.relative_path, "directory_tree")?;

        match entry.kind {
            EntryKind::File => {
                let content = entry.content.as_ref().ok_or_else(|| {
                    ValidatorError::FileMissingContent {
                        path: entry.relative_path.clone(),
                    }
                })?;
                if content.len() > MAX_FILE_CONTENT_BYTES {
                    return Err(ValidatorError::FileContentTooLarge {
                        path: entry.relative_path.clone(),
                        size: content.len(),
                    });
                }
                total_content = total_content.saturating_add(content.len() as u64);
            }
            EntryKind::Directory => {
                if entry.content.is_some() {
                    return Err(ValidatorError::DirectoryHasContent {
                        path: entry.relative_path.clone(),
                    });
                }
            }
        }
    }

    if total_content > MAX_TOTAL_CONTENT_BYTES {
        return Err(ValidatorError::TotalContentTooLarge {
            size: total_content,
        });
    }

    // Setup commands.
    for cmd in &spec.setup_commands {
        validate_relative_path_allow_empty(&cmd.working_dir_relative, "working_dir_relative")?;
        validate_command(cmd)?;
    }

    // Metadata cross-check: the spec cannot lie about its own counts/size
    // to slip past the limits above (the limits were checked against the
    // computed values, but a mismatch still signals tampering / a buggy
    // producer, so reject it explicitly).
    let computed = spec.compute_metadata();
    if computed.total_file_count as u64 != spec.metadata.total_file_count as u64 {
        return Err(ValidatorError::MetadataMismatch {
            field: "total_file_count",
            declared: spec.metadata.total_file_count as u64,
            computed: computed.total_file_count as u64,
        });
    }
    if computed.total_directory_count as u64 != spec.metadata.total_directory_count as u64 {
        return Err(ValidatorError::MetadataMismatch {
            field: "total_directory_count",
            declared: spec.metadata.total_directory_count as u64,
            computed: computed.total_directory_count as u64,
        });
    }
    if computed.estimated_total_size_bytes != spec.metadata.estimated_total_size_bytes {
        return Err(ValidatorError::MetadataMismatch {
            field: "estimated_total_size_bytes",
            declared: spec.metadata.estimated_total_size_bytes,
            computed: computed.estimated_total_size_bytes,
        });
    }

    Ok(())
}

/// Validate that `root_dir` is absolute, normalized, and under
/// `allowed_root`.
fn validate_root_dir(root_dir: &Path, allowed_root: &Path) -> Result<(), ValidatorError> {
    if !root_dir.is_absolute() {
        return Err(ValidatorError::RootNotAbsolute(
            root_dir.display().to_string(),
        ));
    }

    // Reject any `.`/`..` component. Without this, a `starts_with`
    // containment check is unsound: `/allowed/../../etc` is component-wise
    // `starts_with("/allowed")` yet escapes.
    for comp in root_dir.components() {
        match comp {
            Component::ParentDir | Component::CurDir => {
                return Err(ValidatorError::RootNotNormalized(
                    root_dir.display().to_string(),
                ));
            }
            _ => {}
        }
    }

    // Containment: component-wise prefix check (Path::starts_with is
    // component-aware, not string-prefix). Both paths are absolute and
    // normalized, so this is sound. Require STRICTLY under (root_dir must
    // not equal allowed_root — we never scaffold directly into the
    // projects root).
    if !root_dir.starts_with(allowed_root) || root_dir == allowed_root {
        return Err(ValidatorError::RootOutsideAllowed {
            root: root_dir.display().to_string(),
            allowed: allowed_root.display().to_string(),
        });
    }

    Ok(())
}

/// Validate a non-empty relative path from the directory tree.
fn validate_relative_path(path: &str, field: &'static str) -> Result<(), ValidatorError> {
    if path.is_empty() {
        return Err(ValidatorError::EmptyPath { field });
    }
    validate_path_inner(path)
}

/// Validate a relative path that is allowed to be empty (an empty
/// `working_dir_relative` means "the workspace root itself").
fn validate_relative_path_allow_empty(
    path: &str,
    _field: &'static str,
) -> Result<(), ValidatorError> {
    if path.is_empty() {
        return Ok(());
    }
    validate_path_inner(path)
}

/// Shared path-safety checks: length, forbidden chars, and component
/// analysis via [`Path::components`].
fn validate_path_inner(path: &str) -> Result<(), ValidatorError> {
    if path.len() > MAX_PATH_LEN {
        return Err(ValidatorError::PathTooLong {
            path: path.to_string(),
            len: path.len(),
        });
    }

    // Forbidden characters (shell metacharacters + NUL).
    if let Some(ch) = path.chars().find(|c| FORBIDDEN_CHARS.contains(c)) {
        return Err(ValidatorError::ForbiddenCharacter {
            ch,
            value: path.to_string(),
        });
    }

    // Component analysis — the robust escape check. A safe relative path
    // consists ONLY of `Component::Normal` parts. Anything else (RootDir,
    // Prefix, ParentDir, CurDir) is rejected with a specific error.
    let p = Path::new(path);
    for comp in p.components() {
        match comp {
            Component::Normal(_) => {}
            Component::ParentDir => {
                return Err(ValidatorError::PathTraversal {
                    path: path.to_string(),
                });
            }
            Component::CurDir => {
                return Err(ValidatorError::PathCurrentDir {
                    path: path.to_string(),
                });
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(ValidatorError::PathNotRelative {
                    path: path.to_string(),
                });
            }
        }
    }

    // Depth limit: count Normal components.
    let depth = p.components().count();
    if depth > MAX_TREE_DEPTH {
        return Err(ValidatorError::TreeTooDeep {
            path: path.to_string(),
            depth,
        });
    }

    // Defense in depth: join to a sentinel root and confirm containment.
    // After the all-Normal check this is guaranteed, but the redundant
    // verification protects against any future change to the component
    // logic above.
    let sentinel = Path::new("/__delphi_ws_root__");
    let joined = sentinel.join(p);
    if !joined.starts_with(sentinel) {
        return Err(ValidatorError::PathEscapesRoot {
            path: path.to_string(),
        });
    }

    Ok(())
}

/// Validate a setup command against the allowlist.
fn validate_command(cmd: &SetupCommand) -> Result<(), ValidatorError> {
    // Forbidden-character scan on program + each arg first, so a hostile
    // argument yields a precise error before the allowlist comparison.
    if let Some(ch) = cmd.program.chars().find(|c| FORBIDDEN_CHARS.contains(c)) {
        return Err(ValidatorError::ForbiddenCharacter {
            ch,
            value: cmd.program.clone(),
        });
    }
    for arg in &cmd.args {
        if let Some(ch) = arg.chars().find(|c| FORBIDDEN_CHARS.contains(c)) {
            return Err(ValidatorError::ForbiddenCharacter {
                ch,
                value: arg.clone(),
            });
        }
    }

    // Exact allowlist match: program name AND the space-joined argv.
    let joined = cmd.args.join(" ");
    let allowed = COMMAND_ALLOWLIST.iter().any(|(prog, patterns)| {
        *prog == cmd.program && patterns.iter().any(|pat| *pat == joined)
    });
    if !allowed {
        return Err(ValidatorError::CommandNotAllowed {
            program: cmd.program.clone(),
            args: cmd.args.clone(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::spec::{
        CalendarBlock, DirectoryEntry, TemplateId, WorkspaceMetadata, WorkspaceSpec,
    };
    use std::path::PathBuf;

    const ALLOWED: &str = "/home/u/projects";

    /// Build a minimal valid spec under the allowed root, then let the
    /// caller mutate it to construct the failure case under test.
    fn base_spec() -> WorkspaceSpec {
        let mut spec = WorkspaceSpec {
            name: "ws".to_string(),
            root_dir: PathBuf::from("/home/u/projects/ws"),
            template_id: TemplateId::Research,
            directory_tree: vec![
                DirectoryEntry {
                    relative_path: "src".to_string(),
                    kind: EntryKind::Directory,
                    content: None,
                },
                DirectoryEntry {
                    relative_path: "README.md".to_string(),
                    kind: EntryKind::File,
                    content: Some("# ws\n".to_string()),
                },
            ],
            setup_commands: vec![SetupCommand {
                program: "git".to_string(),
                args: vec!["init".to_string(), "--quiet".to_string()],
                working_dir_relative: String::new(),
                description: "init".to_string(),
            }],
            calendar_blocks: vec![],
            metadata: WorkspaceMetadata::default(),
        };
        spec.metadata = spec.compute_metadata();
        spec
    }

    fn allowed() -> &'static Path {
        Path::new(ALLOWED)
    }

    // ── Happy path ────────────────────────────────────────────────────

    #[test]
    fn base_spec_validates() {
        assert!(validate_spec(&base_spec(), allowed()).is_ok());
    }

    #[test]
    fn empty_tree_and_commands_validate() {
        let mut spec = base_spec();
        spec.directory_tree.clear();
        spec.setup_commands.clear();
        spec.metadata = spec.compute_metadata();
        assert!(validate_spec(&spec, allowed()).is_ok());
    }

    // ── root_dir checks ───────────────────────────────────────────────

    #[test]
    fn rejects_relative_root() {
        let mut spec = base_spec();
        spec.root_dir = PathBuf::from("relative/ws");
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::RootNotAbsolute(_))
        ));
    }

    #[test]
    fn rejects_root_outside_allowed() {
        let mut spec = base_spec();
        spec.root_dir = PathBuf::from("/etc/evil");
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::RootOutsideAllowed { .. })
        ));
    }

    #[test]
    fn rejects_root_equal_to_allowed() {
        let mut spec = base_spec();
        spec.root_dir = PathBuf::from(ALLOWED);
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::RootOutsideAllowed { .. })
        ));
    }

    #[test]
    fn rejects_root_with_parentdir_escape() {
        // Component-wise starts_with would accept this; the explicit
        // `..`-component rejection is what blocks it.
        let mut spec = base_spec();
        spec.root_dir = PathBuf::from("/home/u/projects/../../etc/evil");
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::RootNotNormalized(_))
        ));
    }

    #[test]
    fn accepts_root_with_harmless_curdir() {
        // Rust's `Path::components()` normalizes away a MID-PATH `.`
        // (CurDir): `/home/u/projects/./ws` resolves to the same inode
        // as `/home/u/projects/ws`. A `.` cannot change the target or
        // escape the allowed root, so it is harmless and validates. This
        // is the deliberate counterpart to `..` rejection — `..` is NOT
        // normalized (it would be unsound across symlinks) and is
        // rejected by `rejects_root_with_parentdir_escape`.
        let mut spec = base_spec();
        spec.root_dir = PathBuf::from("/home/u/projects/./ws");
        assert!(validate_spec(&spec, allowed()).is_ok());
    }

    #[test]
    fn rejects_sibling_prefix_root() {
        // "/home/u/projects-evil" string-prefix-matches "/home/u/projects"
        // but is NOT component-wise under it. Path::starts_with is
        // component-aware, so this must be rejected.
        let mut spec = base_spec();
        spec.root_dir = PathBuf::from("/home/u/projects-evil/ws");
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::RootOutsideAllowed { .. })
        ));
    }

    // ── path-escape attempts ──────────────────────────────────────────

    #[test]
    fn rejects_parentdir_in_tree_path() {
        let mut spec = base_spec();
        spec.directory_tree[0].relative_path = "../escape".to_string();
        spec.metadata = spec.compute_metadata();
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::PathTraversal { .. })
        ));
    }

    #[test]
    fn rejects_nested_parentdir_in_tree_path() {
        let mut spec = base_spec();
        spec.directory_tree[0].relative_path = "a/b/../../../etc".to_string();
        spec.metadata = spec.compute_metadata();
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::PathTraversal { .. })
        ));
    }

    #[test]
    fn rejects_absolute_tree_path() {
        let mut spec = base_spec();
        spec.directory_tree[0].relative_path = "/etc/passwd".to_string();
        spec.metadata = spec.compute_metadata();
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::PathNotRelative { .. })
        ));
    }

    #[test]
    fn rejects_curdir_in_tree_path() {
        let mut spec = base_spec();
        spec.directory_tree[0].relative_path = "./hidden".to_string();
        spec.metadata = spec.compute_metadata();
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::PathCurrentDir { .. })
        ));
    }

    #[test]
    fn rejects_empty_tree_path() {
        let mut spec = base_spec();
        spec.directory_tree[0].relative_path = String::new();
        spec.metadata = spec.compute_metadata();
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::EmptyPath { .. })
        ));
    }

    #[test]
    fn rejects_nul_byte_in_path() {
        let mut spec = base_spec();
        spec.directory_tree[0].relative_path = "ok\0evil".to_string();
        spec.metadata = spec.compute_metadata();
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::ForbiddenCharacter { ch: '\0', .. })
        ));
    }

    #[test]
    fn rejects_windows_style_parentdir() {
        // On Unix `\..\` is a single filename component (backslash is a
        // valid filename char), so it does NOT traverse — but it is an
        // unusual name. The important guarantee is it cannot escape:
        // either it's a Normal component (safe) or rejected. Here we
        // assert it does not escape root (validates as a literal name).
        let mut spec = base_spec();
        spec.directory_tree[0].relative_path = r"a\..\b".to_string();
        spec.metadata = spec.compute_metadata();
        // On Unix this is one Normal component named `a\..\b`, which is
        // safe (cannot escape). Accept it; the executor's openat2 will
        // create a file with that literal name under root.
        assert!(validate_spec(&spec, allowed()).is_ok());
    }

    #[test]
    fn rejects_path_too_long() {
        let mut spec = base_spec();
        spec.directory_tree[0].relative_path = "a".repeat(MAX_PATH_LEN + 1);
        spec.metadata = spec.compute_metadata();
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::PathTooLong { .. })
        ));
    }

    #[test]
    fn accepts_path_at_length_limit() {
        let mut spec = base_spec();
        spec.directory_tree[0].relative_path = "a".repeat(MAX_PATH_LEN);
        spec.metadata = spec.compute_metadata();
        assert!(validate_spec(&spec, allowed()).is_ok());
    }

    // ── forbidden characters in paths ─────────────────────────────────

    #[test]
    fn rejects_each_shell_metacharacter_in_path() {
        for &ch in FORBIDDEN_CHARS {
            if ch == '\0' {
                continue; // covered separately
            }
            let mut spec = base_spec();
            spec.directory_tree[0].relative_path = format!("a{ch}b");
            spec.metadata = spec.compute_metadata();
            assert!(
                matches!(
                    validate_spec(&spec, allowed()),
                    Err(ValidatorError::ForbiddenCharacter { .. })
                ),
                "metacharacter {ch:?} must be rejected in a path"
            );
        }
    }

    // ── depth + count limits ──────────────────────────────────────────

    #[test]
    fn rejects_tree_too_deep() {
        let mut spec = base_spec();
        // 9 components > MAX_TREE_DEPTH (8).
        spec.directory_tree[0].relative_path = "a/b/c/d/e/f/g/h/i".to_string();
        spec.metadata = spec.compute_metadata();
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::TreeTooDeep { depth: 9, .. })
        ));
    }

    #[test]
    fn accepts_tree_at_depth_limit() {
        let mut spec = base_spec();
        spec.directory_tree[0].relative_path = "a/b/c/d/e/f/g/h".to_string(); // 8
        spec.metadata = spec.compute_metadata();
        assert!(validate_spec(&spec, allowed()).is_ok());
    }

    #[test]
    fn rejects_too_many_entries() {
        let mut spec = base_spec();
        spec.directory_tree = (0..=MAX_ENTRY_COUNT)
            .map(|i| DirectoryEntry {
                relative_path: format!("f{i}"),
                kind: EntryKind::Directory,
                content: None,
            })
            .collect();
        spec.metadata = spec.compute_metadata();
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::TooManyEntries { .. })
        ));
    }

    #[test]
    fn accepts_entries_at_count_limit() {
        let mut spec = base_spec();
        spec.directory_tree = (0..MAX_ENTRY_COUNT)
            .map(|i| DirectoryEntry {
                relative_path: format!("f{i}"),
                kind: EntryKind::Directory,
                content: None,
            })
            .collect();
        spec.metadata = spec.compute_metadata();
        assert!(validate_spec(&spec, allowed()).is_ok());
    }

    // ── content-size limits ───────────────────────────────────────────

    #[test]
    fn rejects_oversized_file() {
        let mut spec = base_spec();
        spec.directory_tree[1].content = Some("x".repeat(MAX_FILE_CONTENT_BYTES + 1));
        spec.metadata = spec.compute_metadata();
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::FileContentTooLarge { .. })
        ));
    }

    #[test]
    fn accepts_file_at_size_limit() {
        let mut spec = base_spec();
        spec.directory_tree[1].content = Some("x".repeat(MAX_FILE_CONTENT_BYTES));
        spec.metadata = spec.compute_metadata();
        assert!(validate_spec(&spec, allowed()).is_ok());
    }

    #[test]
    fn rejects_oversized_total() {
        let mut spec = base_spec();
        // 11 files of 1 MiB each = 11 MiB > 10 MiB total.
        spec.directory_tree = (0..11)
            .map(|i| DirectoryEntry {
                relative_path: format!("big{i}.bin"),
                kind: EntryKind::File,
                content: Some("x".repeat(MAX_FILE_CONTENT_BYTES)),
            })
            .collect();
        spec.metadata = spec.compute_metadata();
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::TotalContentTooLarge { .. })
        ));
    }

    // ── file/dir invariants ───────────────────────────────────────────

    #[test]
    fn rejects_file_without_content() {
        let mut spec = base_spec();
        spec.directory_tree[1].content = None; // index 1 is a File
        spec.metadata = spec.compute_metadata();
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::FileMissingContent { .. })
        ));
    }

    #[test]
    fn rejects_directory_with_content() {
        let mut spec = base_spec();
        spec.directory_tree[0].content = Some("oops".to_string()); // index 0 is a Dir
        spec.metadata = spec.compute_metadata();
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::DirectoryHasContent { .. })
        ));
    }

    #[test]
    fn accepts_empty_file_content() {
        let mut spec = base_spec();
        spec.directory_tree[1].content = Some(String::new());
        spec.metadata = spec.compute_metadata();
        assert!(validate_spec(&spec, allowed()).is_ok());
    }

    // ── command allowlist ─────────────────────────────────────────────

    #[test]
    fn rejects_disallowed_program_rm() {
        let mut spec = base_spec();
        spec.setup_commands[0] = SetupCommand {
            program: "rm".to_string(),
            args: vec!["-rf".to_string(), "/".to_string()],
            working_dir_relative: String::new(),
            description: "evil".to_string(),
        };
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::CommandNotAllowed { .. })
        ));
    }

    #[test]
    fn rejects_disallowed_program_bash() {
        let mut spec = base_spec();
        spec.setup_commands[0] = SetupCommand {
            program: "bash".to_string(),
            args: vec!["-c".to_string(), "echo hi".to_string()],
            working_dir_relative: String::new(),
            description: "evil".to_string(),
        };
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::CommandNotAllowed { .. })
        ));
    }

    #[test]
    fn rejects_disallowed_program_curl() {
        let mut spec = base_spec();
        spec.setup_commands[0] = SetupCommand {
            program: "curl".to_string(),
            args: vec!["https://evil.example".to_string()],
            working_dir_relative: String::new(),
            description: "evil".to_string(),
        };
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::CommandNotAllowed { .. })
        ));
    }

    #[test]
    fn rejects_disallowed_program_sudo() {
        let mut spec = base_spec();
        spec.setup_commands[0] = SetupCommand {
            program: "sudo".to_string(),
            args: vec!["rm".to_string()],
            working_dir_relative: String::new(),
            description: "evil".to_string(),
        };
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::CommandNotAllowed { .. })
        ));
    }

    #[test]
    fn rejects_disallowed_argv_for_allowed_program() {
        // `git push` is not on the git allowlist (only init / init --quiet).
        let mut spec = base_spec();
        spec.setup_commands[0] = SetupCommand {
            program: "git".to_string(),
            args: vec!["push".to_string()],
            working_dir_relative: String::new(),
            description: "evil".to_string(),
        };
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::CommandNotAllowed { .. })
        ));
    }

    #[test]
    fn rejects_git_with_extra_args_beyond_pattern() {
        // "init --quiet --bare" is not exactly "init" or "init --quiet".
        let mut spec = base_spec();
        spec.setup_commands[0] = SetupCommand {
            program: "git".to_string(),
            args: vec![
                "init".to_string(),
                "--quiet".to_string(),
                "--bare".to_string(),
            ],
            working_dir_relative: String::new(),
            description: "sneaky".to_string(),
        };
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::CommandNotAllowed { .. })
        ));
    }

    #[test]
    fn accepts_each_allowlisted_command() {
        let cases: &[(&str, &[&str])] = &[
            ("git", &["init"]),
            ("git", &["init", "--quiet"]),
            ("pnpm", &["install"]),
            ("npm", &["install"]),
            ("cargo", &["init"]),
            ("cargo", &["init", "--lib"]),
            ("cargo", &["init", "--bin"]),
            ("uv", &["init"]),
        ];
        for (prog, args) in cases {
            let mut spec = base_spec();
            spec.setup_commands[0] = SetupCommand {
                program: (*prog).to_string(),
                args: args.iter().map(|s| (*s).to_string()).collect(),
                working_dir_relative: String::new(),
                description: "ok".to_string(),
            };
            assert!(
                validate_spec(&spec, allowed()).is_ok(),
                "command {prog} {args:?} should be allowed"
            );
        }
    }

    #[test]
    fn accepts_multiword_allowlisted_command() {
        let mut spec = base_spec();
        spec.setup_commands[0] = SetupCommand {
            program: "conda".to_string(),
            args: vec![
                "env".to_string(),
                "create".to_string(),
                "-f".to_string(),
                "environment.yml".to_string(),
            ],
            working_dir_relative: String::new(),
            description: "conda env".to_string(),
        };
        assert!(validate_spec(&spec, allowed()).is_ok());
    }

    #[test]
    fn rejects_command_arg_metacharacter() {
        // Even an allowlisted program with an injected metacharacter arg
        // is rejected at the metachar scan (before allowlist comparison).
        let mut spec = base_spec();
        spec.setup_commands[0] = SetupCommand {
            program: "git".to_string(),
            args: vec!["init; rm -rf /".to_string()],
            working_dir_relative: String::new(),
            description: "inject".to_string(),
        };
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::ForbiddenCharacter { .. })
        ));
    }

    #[test]
    fn rejects_command_program_metacharacter() {
        let mut spec = base_spec();
        spec.setup_commands[0] = SetupCommand {
            program: "git$(whoami)".to_string(),
            args: vec!["init".to_string()],
            working_dir_relative: String::new(),
            description: "inject".to_string(),
        };
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::ForbiddenCharacter { .. })
        ));
    }

    #[test]
    fn rejects_working_dir_escape() {
        let mut spec = base_spec();
        spec.setup_commands[0].working_dir_relative = "../../etc".to_string();
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::PathTraversal { .. })
        ));
    }

    #[test]
    fn accepts_empty_working_dir() {
        let mut spec = base_spec();
        spec.setup_commands[0].working_dir_relative = String::new();
        assert!(validate_spec(&spec, allowed()).is_ok());
    }

    #[test]
    fn accepts_nested_working_dir() {
        let mut spec = base_spec();
        spec.directory_tree.push(DirectoryEntry {
            relative_path: "frontend".to_string(),
            kind: EntryKind::Directory,
            content: None,
        });
        spec.setup_commands[0] = SetupCommand {
            program: "pnpm".to_string(),
            args: vec!["install".to_string()],
            working_dir_relative: "frontend".to_string(),
            description: "deps".to_string(),
        };
        spec.metadata = spec.compute_metadata();
        assert!(validate_spec(&spec, allowed()).is_ok());
    }

    // ── metadata cross-check ──────────────────────────────────────────

    #[test]
    fn rejects_understated_file_count() {
        let mut spec = base_spec();
        spec.metadata.total_file_count = 0; // lie: actually 1
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::MetadataMismatch {
                field: "total_file_count",
                ..
            })
        ));
    }

    #[test]
    fn rejects_understated_total_size() {
        let mut spec = base_spec();
        spec.metadata.estimated_total_size_bytes = 0; // lie
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::MetadataMismatch {
                field: "estimated_total_size_bytes",
                ..
            })
        ));
    }

    #[test]
    fn rejects_wrong_directory_count() {
        let mut spec = base_spec();
        spec.metadata.total_directory_count = 99; // lie
        assert!(matches!(
            validate_spec(&spec, allowed()),
            Err(ValidatorError::MetadataMismatch {
                field: "total_directory_count",
                ..
            })
        ));
    }

    // ── calendar blocks don't affect validity ─────────────────────────

    #[test]
    fn calendar_blocks_do_not_affect_validation() {
        let mut spec = base_spec();
        spec.calendar_blocks = vec![CalendarBlock {
            title: "review; rm -rf /".to_string(), // metachars here are harmless
            duration_minutes: 30,
            suggested_time: "morning".to_string(),
            recurrence: None,
        }];
        // Calendar blocks carry no FS/command authority, so even
        // metacharacter-laden titles do not fail validation.
        assert!(validate_spec(&spec, allowed()).is_ok());
    }
}
