// SPDX-License-Identifier: MIT

//! Workspace specification types — the data model for generative
//! workspace creation (capability #18).
//!
//! A [`WorkspaceSpec`] is the declarative description of an entire
//! working environment: its directory tree, file contents, allowlisted
//! setup commands, and optional calendar blocks. Specs come from two
//! sources:
//!
//! 1. **Baseline templates** (`templates.rs`) — four hardcoded, compile-
//!    time-audited specs (research / code-project / document / design).
//!    These are the trusted fast path.
//! 2. **Cloud-inferred custom specs** — produced by Tier 3 inference for
//!    arbitrary user intents. These are UNTRUSTED and MUST pass through
//!    [`crate::workspace::validator::validate_spec`] before any
//!    filesystem mutation.
//!
//! Every field carries validation invariants documented inline. The
//! validator (`validator.rs`) is the single enforcement point; the
//! executor (`executor.rs`) re-validates defensively before execution
//! per Iron Law #11 ("never skip, never assume, always verify").
//!
//! # Serialization
//!
//! All types derive `Serialize`/`Deserialize` so specs can cross the
//! D-Bus boundary as JSON (`org.delphi.Workspace.Create(spec_json)`).
//! The wire format is the serde-default JSON representation.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// A complete, declarative description of a workspace to be created.
///
/// A spec is inert data until handed to the executor. It describes
/// *what* to create but performs no I/O itself. The executor
/// ([`crate::workspace::executor`]) is the only component that touches
/// the filesystem, and it re-validates the spec before doing so.
///
/// # Validation invariants (enforced by `validate_spec`)
///
/// - `root_dir` is absolute and strictly under the caller's allowed root
/// - every `directory_tree` path is relative, escape-free, and under
///   `root_dir`
/// - every `setup_commands` entry matches the command allowlist
/// - total file count, tree depth, per-file size, and total size are
///   within the documented limits
///
/// # Examples
///
/// ```
/// use die_orchestrator::workspace::spec::{
///     WorkspaceSpec, TemplateId, WorkspaceMetadata,
/// };
/// use std::path::PathBuf;
///
/// let spec = WorkspaceSpec {
///     name: "my-research".to_string(),
///     root_dir: PathBuf::from("/home/u/projects/my-research"),
///     template_id: TemplateId::Research,
///     directory_tree: vec![],
///     setup_commands: vec![],
///     calendar_blocks: vec![],
///     metadata: WorkspaceMetadata::default(),
/// };
/// assert_eq!(spec.name, "my-research");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceSpec {
    /// Human-readable workspace display name (shown in the preview UI
    /// and recorded in the action timeline). Not used as a filesystem
    /// path; `root_dir` is the authoritative location.
    pub name: String,

    /// Absolute path of the workspace root. MUST resolve to a path
    /// strictly under the caller-supplied allowed root (e.g.
    /// `~/projects/`). The validator rejects any `root_dir` outside
    /// the allowed root, and the executor refuses to create it if it
    /// already exists and is non-empty.
    pub root_dir: PathBuf,

    /// Which template produced this spec. Baseline variants are trusted;
    /// [`TemplateId::Custom`] indicates a cloud-inferred spec that
    /// received no extra trust — it passes the same validator.
    pub template_id: TemplateId,

    /// Directories and files to create, relative to `root_dir`. Order is
    /// not assumed; the executor sorts so parents precede children.
    pub directory_tree: Vec<DirectoryEntry>,

    /// Allowlisted setup commands to run after the tree is created, in
    /// declaration order. Each must match the command allowlist exactly.
    pub setup_commands: Vec<SetupCommand>,

    /// Optional calendar blocks to suggest to the user. Empty when the
    /// template/spec proposes no scheduling. Calendar blocks are
    /// suggestions surfaced in the preview; they are not executed by
    /// the filesystem engine.
    pub calendar_blocks: Vec<CalendarBlock>,

    /// Derived metadata (counts, sizes, timestamp) used for the preview
    /// and the limit checks. Recomputed and cross-checked by the
    /// validator — a spec cannot lie about its own size to bypass limits.
    pub metadata: WorkspaceMetadata,
}

/// Identifies which template a [`WorkspaceSpec`] came from.
///
/// The four baseline variants are produced by the hardcoded constructors
/// in [`crate::workspace::templates`] and are audited at compile time.
/// [`TemplateId::Custom`] carries the natural-language description that
/// drove a cloud inference; it receives no additional trust.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TemplateId {
    /// Research project: papers / notes / code / data / figures.
    Research,
    /// Code project: src / tests / docs with language scaffolding.
    CodeProject,
    /// Document project: drafts / references / figures.
    Document,
    /// Design project: assets / exports / mockups / references.
    Design,
    /// Cloud-inferred custom spec. The string is the originating user
    /// intent, retained for the preview and audit trail. Custom specs
    /// are validated identically to baseline specs — the description is
    /// metadata only and grants no trust.
    Custom {
        /// The natural-language description that produced this spec.
        description: String,
    },
}

/// A single directory or file to create within the workspace.
///
/// # Validation invariants
///
/// - `relative_path` is relative (never starts with `/`), contains no
///   `..` segments, no shell metacharacters, no NUL bytes, is valid
///   UTF-8, is under 256 bytes, and resolves strictly under `root_dir`
///   when joined (verified via `Path::components`, not string matching)
/// - `content` is `Some` iff `kind == EntryKind::File`; directories
///   carry `None`
/// - a file's `content` length is at most 1 MiB
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// Path relative to the workspace `root_dir`. Validated for escape
    /// safety before any filesystem operation.
    pub relative_path: String,

    /// Whether this entry is a directory or a regular file.
    pub kind: EntryKind,

    /// File contents for `EntryKind::File`; `None` for directories. The
    /// validator rejects a `File` with `None` content (use `Some("")`
    /// for an intentionally empty file) and a `Directory` with `Some`.
    pub content: Option<String>,
}

/// Discriminates a [`DirectoryEntry`] between a directory and a file.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EntryKind {
    /// A directory to create (`mkdirat`, mode 0o755 on Unix).
    Directory,
    /// A regular file to create and write (`O_CREAT|O_EXCL|O_NOFOLLOW`,
    /// mode 0o644 on Unix).
    File,
}

/// An allowlisted setup command to run after the directory tree exists.
///
/// Commands are executed via `std::process::Command` with an explicit
/// argv vector — NEVER through a shell. There is no string
/// interpolation, no `bash -c`, no `sh "$@"`. The `program` plus the
/// space-joined `args` must exactly match an entry in the validator's
/// `COMMAND_ALLOWLIST`.
///
/// # Validation invariants
///
/// - `(program, args.join(" "))` matches the allowlist exactly
/// - `working_dir_relative` is validated identically to a
///   [`DirectoryEntry`] path (relative, escape-free, under `root_dir`)
/// - no argument contains shell metacharacters or NUL bytes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetupCommand {
    /// The program to invoke, e.g. `"git"`. Must exactly match an
    /// allowlisted program name — no path components, no `./` prefix.
    pub program: String,

    /// Arguments passed as an explicit argv tail, e.g.
    /// `["init", "--quiet"]`. The space-join of these must match one of
    /// the allowlisted argv patterns for `program`.
    pub args: Vec<String>,

    /// Working directory for the command, relative to `root_dir`. The
    /// empty string means `root_dir` itself. Validated for escape safety.
    pub working_dir_relative: String,

    /// Human-readable description of what the command does, shown in the
    /// dry-run preview. Display-only; not used for execution decisions.
    pub description: String,
}

/// A calendar block suggested alongside the workspace.
///
/// Calendar blocks are *suggestions* surfaced in the preview UI. The
/// workspace executor does not create calendar entries itself; a future
/// calendar integration consumes these. They carry no filesystem or
/// command-execution authority and therefore are not part of the
/// validator's security checks (beyond UTF-8 / size sanity).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CalendarBlock {
    /// Block title, e.g. `"Daily research review"`.
    pub title: String,

    /// Suggested duration in minutes.
    pub duration_minutes: u32,

    /// Suggested time — an ISO 8601 timestamp or a relative description
    /// like `"weekday mornings"`. Free-form; interpreted by the
    /// calendar integration, not this module.
    pub suggested_time: String,

    /// Optional recurrence description, e.g. `"weekdays"`. `None` for a
    /// single occurrence.
    pub recurrence: Option<String>,
}

/// Derived metadata about a workspace spec.
///
/// These values are used for the preview and to cross-check the
/// validator's limit enforcement. The validator recomputes the counts
/// and total size from `directory_tree` and rejects the spec if the
/// declared metadata disagrees with the computed values — a spec cannot
/// understate its size to slip past the limits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WorkspaceMetadata {
    /// Unix epoch seconds when the spec was created. `0` is acceptable
    /// for synthetic/test specs; the executor stamps the real creation
    /// time into the action-timeline record independently.
    pub created_at: i64,

    /// Sum of all file content lengths in bytes. Cross-checked by the
    /// validator against the actual `directory_tree` contents.
    pub estimated_total_size_bytes: u64,

    /// Count of `EntryKind::File` entries. Cross-checked by the validator.
    pub total_file_count: u32,

    /// Count of `EntryKind::Directory` entries. Cross-checked by the
    /// validator.
    pub total_directory_count: u32,
}

impl WorkspaceSpec {
    /// Recompute [`WorkspaceMetadata`] from the current `directory_tree`.
    ///
    /// Template constructors call this so their declared metadata always
    /// matches their contents. The validator calls it to cross-check an
    /// incoming (possibly hostile) spec's self-reported metadata.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::workspace::spec::{
    ///     WorkspaceSpec, TemplateId, WorkspaceMetadata, DirectoryEntry, EntryKind,
    /// };
    /// use std::path::PathBuf;
    ///
    /// let mut spec = WorkspaceSpec {
    ///     name: "x".into(),
    ///     root_dir: PathBuf::from("/home/u/projects/x"),
    ///     template_id: TemplateId::Research,
    ///     directory_tree: vec![
    ///         DirectoryEntry { relative_path: "src".into(), kind: EntryKind::Directory, content: None },
    ///         DirectoryEntry { relative_path: "README.md".into(), kind: EntryKind::File, content: Some("hi".into()) },
    ///     ],
    ///     setup_commands: vec![],
    ///     calendar_blocks: vec![],
    ///     metadata: WorkspaceMetadata::default(),
    /// };
    /// let m = spec.compute_metadata();
    /// assert_eq!(m.total_file_count, 1);
    /// assert_eq!(m.total_directory_count, 1);
    /// assert_eq!(m.estimated_total_size_bytes, 2);
    /// ```
    #[must_use]
    pub fn compute_metadata(&self) -> WorkspaceMetadata {
        let mut total_size: u64 = 0;
        let mut files: u32 = 0;
        let mut dirs: u32 = 0;
        for entry in &self.directory_tree {
            match entry.kind {
                EntryKind::File => {
                    files = files.saturating_add(1);
                    if let Some(content) = &entry.content {
                        total_size = total_size.saturating_add(content.len() as u64);
                    }
                }
                EntryKind::Directory => {
                    dirs = dirs.saturating_add(1);
                }
            }
        }
        WorkspaceMetadata {
            created_at: self.metadata.created_at,
            estimated_total_size_bytes: total_size,
            total_file_count: files,
            total_directory_count: dirs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_spec() -> WorkspaceSpec {
        WorkspaceSpec {
            name: "sample".to_string(),
            root_dir: PathBuf::from("/home/u/projects/sample"),
            template_id: TemplateId::Research,
            directory_tree: vec![
                DirectoryEntry {
                    relative_path: "papers".to_string(),
                    kind: EntryKind::Directory,
                    content: None,
                },
                DirectoryEntry {
                    relative_path: "README.md".to_string(),
                    kind: EntryKind::File,
                    content: Some("# Sample\n".to_string()),
                },
            ],
            setup_commands: vec![SetupCommand {
                program: "git".to_string(),
                args: vec!["init".to_string(), "--quiet".to_string()],
                working_dir_relative: String::new(),
                description: "Initialize git repository".to_string(),
            }],
            calendar_blocks: vec![CalendarBlock {
                title: "Daily research review".to_string(),
                duration_minutes: 30,
                suggested_time: "weekday mornings".to_string(),
                recurrence: Some("weekdays".to_string()),
            }],
            metadata: WorkspaceMetadata {
                created_at: 1_700_000_000,
                estimated_total_size_bytes: 9,
                total_file_count: 1,
                total_directory_count: 1,
            },
        }
    }

    #[test]
    fn workspace_spec_json_roundtrips() {
        let spec = sample_spec();
        let json = serde_json::to_string(&spec).unwrap();
        let back: WorkspaceSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
    }

    #[test]
    fn template_id_baseline_variants_roundtrip() {
        for id in [
            TemplateId::Research,
            TemplateId::CodeProject,
            TemplateId::Document,
            TemplateId::Design,
        ] {
            let json = serde_json::to_string(&id).unwrap();
            let back: TemplateId = serde_json::from_str(&json).unwrap();
            assert_eq!(id, back);
        }
    }

    #[test]
    fn template_id_custom_preserves_description() {
        let id = TemplateId::Custom {
            description: "a kanban board for my thesis".to_string(),
        };
        let json = serde_json::to_string(&id).unwrap();
        let back: TemplateId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
        match back {
            TemplateId::Custom { description } => {
                assert!(description.contains("kanban"));
            }
            _ => panic!("expected Custom variant"),
        }
    }

    #[test]
    fn entry_kind_roundtrips() {
        for k in [EntryKind::Directory, EntryKind::File] {
            let json = serde_json::to_string(&k).unwrap();
            let back: EntryKind = serde_json::from_str(&json).unwrap();
            assert_eq!(k, back);
        }
    }

    #[test]
    fn directory_entry_file_roundtrips() {
        let e = DirectoryEntry {
            relative_path: "notes/lit.md".to_string(),
            kind: EntryKind::File,
            content: Some("body".to_string()),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: DirectoryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn directory_entry_dir_has_none_content() {
        let e = DirectoryEntry {
            relative_path: "data".to_string(),
            kind: EntryKind::Directory,
            content: None,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: DirectoryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.content, None);
    }

    #[test]
    fn setup_command_roundtrips() {
        let c = SetupCommand {
            program: "pnpm".to_string(),
            args: vec!["install".to_string()],
            working_dir_relative: "frontend".to_string(),
            description: "Install JS deps".to_string(),
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: SetupCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn calendar_block_roundtrips_with_and_without_recurrence() {
        let recurring = CalendarBlock {
            title: "Standup".to_string(),
            duration_minutes: 15,
            suggested_time: "09:00".to_string(),
            recurrence: Some("weekdays".to_string()),
        };
        let single = CalendarBlock {
            title: "Kickoff".to_string(),
            duration_minutes: 60,
            suggested_time: "2026-06-01T10:00:00Z".to_string(),
            recurrence: None,
        };
        for block in [recurring, single] {
            let json = serde_json::to_string(&block).unwrap();
            let back: CalendarBlock = serde_json::from_str(&json).unwrap();
            assert_eq!(block, back);
        }
    }

    #[test]
    fn workspace_metadata_default_is_zeroed() {
        let m = WorkspaceMetadata::default();
        assert_eq!(m.created_at, 0);
        assert_eq!(m.estimated_total_size_bytes, 0);
        assert_eq!(m.total_file_count, 0);
        assert_eq!(m.total_directory_count, 0);
    }

    #[test]
    fn compute_metadata_counts_files_dirs_and_size() {
        let spec = sample_spec();
        let m = spec.compute_metadata();
        assert_eq!(m.total_file_count, 1);
        assert_eq!(m.total_directory_count, 1);
        assert_eq!(m.estimated_total_size_bytes, "# Sample\n".len() as u64);
        // created_at is preserved from the existing metadata.
        assert_eq!(m.created_at, 1_700_000_000);
    }

    #[test]
    fn compute_metadata_empty_tree_is_zero() {
        let mut spec = sample_spec();
        spec.directory_tree.clear();
        let m = spec.compute_metadata();
        assert_eq!(m.total_file_count, 0);
        assert_eq!(m.total_directory_count, 0);
        assert_eq!(m.estimated_total_size_bytes, 0);
    }

    #[test]
    fn full_spec_pretty_json_roundtrips() {
        // Pretty-printed JSON (as the D-Bus preview may emit) must
        // round-trip identically to compact JSON.
        let spec = sample_spec();
        let pretty = serde_json::to_string_pretty(&spec).unwrap();
        let back: WorkspaceSpec = serde_json::from_str(&pretty).unwrap();
        assert_eq!(spec, back);
    }
}
