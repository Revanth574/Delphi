// SPDX-License-Identifier: MIT

//! [`WorkspaceManager`] — the public domain API for workspace creation.
//!
//! The manager ties the pieces together:
//!
//! ```text
//! templates ─┐
//!            ├─→ WorkspaceSpec ─→ validate_spec ─→ WorkspaceExecutor ─→ Timeline.record_action
//! cloud spec ┘                                      (filesystem)         (24h undoable)
//! ```
//!
//! It is deliberately D-Bus-free: the zbus interface (`org.delphi.Workspace`)
//! lives in `services/src/workspace.rs` and wraps a `WorkspaceManager`,
//! per CLAUDE.md §3 ("service wrapper lives in the services crate, actual
//! logic lives in the domain crate"). This keeps the manager fully
//! unit-testable without a bus.
//!
//! # Reversibility (Iron Law #5)
//!
//! Every successful creation is recorded in the action [`Timeline`]. The
//! recorded entry's `undo_command` field stores the workspace root path;
//! [`WorkspaceManager::undo`] reads it back (which also enforces the
//! 24-hour window and marks the entry undone) and asks the executor to
//! remove the workspace. The executor's removal is idempotent and
//! symlink-safe.

use std::path::{Path, PathBuf};

use crate::OrchestratorError;
use crate::timeline::Timeline;
use crate::workspace::executor::{ExecutionStatus, ExecutorError, WorkspaceExecutor};
use crate::workspace::spec::{TemplateId, WorkspaceSpec};
use crate::workspace::templates::{self, TemplateParams};
use crate::workspace::validator::{ValidatorError, validate_spec};

/// Metadata describing a baseline template for the `ListTemplates` API.
///
/// Derives `Serialize`/`Deserialize` so the D-Bus layer can return the
/// template catalog as a JSON array (matching the project convention of
/// JSON-string returns for complex D-Bus payloads, e.g. `health.rs`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateInfo {
    /// Stable template id string (`"research"`, `"code-project"`,
    /// `"document"`, `"design"`).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// One-line description for the UI.
    pub description: String,
    /// Parameter keys this template accepts (e.g. `["language"]`).
    pub parameters: Vec<String>,
}

/// The result of a dry-run [`WorkspaceManager::preview`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewResult {
    /// Human-readable, multi-line summary of what would be created.
    pub preview: String,
    /// Validation problems, if any. Empty means the spec is valid and
    /// safe to create. The validator reports the first violation it
    /// finds, so this holds 0 or 1 entries; fixing the reported problem
    /// and re-previewing reveals the next.
    pub validation_errors: Vec<String>,
}

/// The result of a [`WorkspaceManager::create`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateResult {
    /// The created workspace's stable id.
    pub workspace_id: String,
    /// The action-timeline entry id (used to [`undo`](WorkspaceManager::undo)).
    pub action_timeline_id: String,
    /// Terminal execution status (so the UI can surface a partial /
    /// command failure even though the call returned `Ok`).
    pub status: ExecutionStatus,
}

/// Errors from the manager's public API.
#[derive(Debug, thiserror::Error)]
pub enum WorkspaceManagerError {
    /// The spec failed validation before any execution.
    #[error("workspace spec rejected: {0}")]
    Validation(#[from] ValidatorError),

    /// Execution could not begin (pre-mutation failure).
    #[error("workspace execution failed: {0}")]
    Execution(#[from] ExecutorError),

    /// The requested template id is not a baseline template.
    #[error("unknown or non-baseline template: {0}")]
    UnknownTemplate(String),

    /// The action timeline could not be read or written.
    #[error("action timeline error: {0}")]
    Timeline(String),

    /// The action timeline was recorded but could not be finalized.
    #[error("action timeline update error: {0}")]
    TimelineUpdate(String),
}

/// Coordinates template expansion, validation, safe execution, and
/// action-timeline recording for workspace creation.
pub struct WorkspaceManager {
    allowed_root: PathBuf,
    executor: WorkspaceExecutor,
    timeline: Timeline,
}

impl WorkspaceManager {
    /// Construct a manager bound to `allowed_root`, backed by the given
    /// action `timeline`.
    #[must_use]
    pub fn new(allowed_root: &Path, timeline: Timeline) -> Self {
        Self {
            allowed_root: allowed_root.to_path_buf(),
            executor: WorkspaceExecutor::new(allowed_root),
            timeline,
        }
    }

    /// Construct a manager with an in-memory action timeline (tests).
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceManagerError::Timeline`] if the in-memory
    /// timeline cannot be created.
    pub fn in_memory(allowed_root: &Path) -> Result<Self, WorkspaceManagerError> {
        let timeline =
            Timeline::in_memory().map_err(|e| WorkspaceManagerError::Timeline(e.to_string()))?;
        Ok(Self::new(allowed_root, timeline))
    }

    /// The allowed root this manager creates workspaces under.
    #[must_use]
    pub fn allowed_root(&self) -> &Path {
        &self.allowed_root
    }

    /// The action timeline used by this manager.
    #[must_use]
    pub fn timeline(&self) -> &Timeline {
        &self.timeline
    }

    /// List the four baseline templates and their accepted parameters.
    #[must_use]
    pub fn list_templates(&self) -> Vec<TemplateInfo> {
        vec![
            TemplateInfo {
                id: "research".to_string(),
                name: "Research".to_string(),
                description: "Papers, notes, code, data, and figures for a research project."
                    .to_string(),
                parameters: vec![],
            },
            TemplateInfo {
                id: "code-project".to_string(),
                name: "Code project".to_string(),
                description: "src/tests/docs with language scaffolding (Rust or TypeScript)."
                    .to_string(),
                parameters: vec!["language".to_string()],
            },
            TemplateInfo {
                id: "document".to_string(),
                name: "Document".to_string(),
                description: "Drafts, references, and figures for a writing project.".to_string(),
                parameters: vec![],
            },
            TemplateInfo {
                id: "design".to_string(),
                name: "Design".to_string(),
                description: "Assets, exports, mockups, and references for a design project."
                    .to_string(),
                parameters: vec![],
            },
        ]
    }

    /// Map a template-id string (as sent over D-Bus) to a [`TemplateId`].
    fn parse_template_id(id: &str) -> Option<TemplateId> {
        match id {
            "research" => Some(TemplateId::Research),
            "code-project" | "code_project" | "codeproject" => Some(TemplateId::CodeProject),
            "document" => Some(TemplateId::Document),
            "design" => Some(TemplateId::Design),
            _ => None,
        }
    }

    /// Produce a dry-run preview + validation report for a spec. Performs
    /// no filesystem mutation.
    #[must_use]
    pub fn preview(&self, spec: &WorkspaceSpec) -> PreviewResult {
        let validation_errors = match validate_spec(spec, &self.allowed_root) {
            Ok(()) => Vec::new(),
            Err(e) => vec![e.to_string()],
        };
        PreviewResult {
            preview: render_preview(spec),
            validation_errors,
        }
    }

    /// Build a spec from a baseline template and preview it.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceManagerError::UnknownTemplate`] for a
    /// non-baseline id.
    pub fn preview_from_template(
        &self,
        template_id: &str,
        name: &str,
        root_dir: &Path,
        params: &TemplateParams,
    ) -> Result<PreviewResult, WorkspaceManagerError> {
        let spec = self.spec_from_template(template_id, name, root_dir, params)?;
        Ok(self.preview(&spec))
    }

    /// Validate, execute, and record a workspace spec.
    ///
    /// # Errors
    ///
    /// - [`WorkspaceManagerError::Validation`] if the spec is unsafe.
    /// - [`WorkspaceManagerError::Execution`] if execution cannot begin.
    /// - [`WorkspaceManagerError::Timeline`] if recording fails.
    ///
    /// Note: a non-fatal command failure during execution is reported in
    /// [`CreateResult::status`], not as an `Err` — the workspace files
    /// exist and are recorded for undo.
    pub fn create(&self, spec: &WorkspaceSpec) -> Result<CreateResult, WorkspaceManagerError> {
        // Validate up front for a clean, specific error (the executor
        // also re-validates as defense in depth).
        validate_spec(spec, &self.allowed_root)?;

        let description = format!(
            "Created workspace '{}' (pending) at {}",
            spec.name,
            spec.root_dir.display()
        );
        let undo_payload = spec.root_dir.to_string_lossy();
        let action_id = self
            .timeline
            .record_pending("workspace.create", &undo_payload, &description)
            .map_err(|e: OrchestratorError| WorkspaceManagerError::Timeline(e.to_string()))?;

        let outcome = match self.executor.execute(spec) {
            Ok(outcome) => outcome,
            Err(err) => {
                let partial_state = format!("execution failed before completion: {err}");
                let _ = self
                    .timeline
                    .mark_pending_partial(&action_id, &partial_state);
                return Err(WorkspaceManagerError::Execution(err));
            }
        };

        let status_payload = serde_json::to_string(&outcome.status)
            .unwrap_or_else(|_| format!("{:?}", outcome.status));
        let finalize_result = if outcome.status.is_complete() {
            self.timeline
                .complete_pending(&action_id, Some(&status_payload))
        } else {
            self.timeline
                .mark_pending_partial(&action_id, &status_payload)
        };
        finalize_result
            .map_err(|e: OrchestratorError| WorkspaceManagerError::TimelineUpdate(e.to_string()))?;

        Ok(CreateResult {
            workspace_id: outcome.workspace_id,
            action_timeline_id: action_id,
            status: outcome.status,
        })
    }

    /// Build a spec from a baseline template, then [`create`](Self::create) it.
    ///
    /// # Errors
    ///
    /// As [`create`](Self::create), plus
    /// [`WorkspaceManagerError::UnknownTemplate`].
    pub fn create_from_template(
        &self,
        template_id: &str,
        name: &str,
        root_dir: &Path,
        params: &TemplateParams,
    ) -> Result<CreateResult, WorkspaceManagerError> {
        let spec = self.spec_from_template(template_id, name, root_dir, params)?;
        self.create(&spec)
    }

    /// Undo a recorded workspace creation by its action-timeline id.
    ///
    /// Reads the recorded root path (which also enforces the 24-hour
    /// window and marks the entry undone via the timeline), then removes
    /// the workspace via the executor (idempotent, symlink-safe).
    ///
    /// # Errors
    ///
    /// - [`WorkspaceManagerError::Timeline`] if the entry is missing,
    ///   already undone, or outside the 24-hour window.
    /// - [`WorkspaceManagerError::Execution`] if removal fails.
    pub fn undo(&self, action_timeline_id: &str) -> Result<(), WorkspaceManagerError> {
        let root_path = self
            .timeline
            .begin_undo(action_timeline_id)
            .map_err(|e| WorkspaceManagerError::Timeline(e.to_string()))?;
        let root_dir = PathBuf::from(root_path);
        if let Err(err) = self.executor.undo(&root_dir) {
            self.timeline
                .abort_undo(action_timeline_id)
                .map_err(|e| WorkspaceManagerError::TimelineUpdate(e.to_string()))?;
            return Err(WorkspaceManagerError::Execution(err));
        }
        self.timeline
            .complete_undo(action_timeline_id)
            .map_err(|e| WorkspaceManagerError::TimelineUpdate(e.to_string()))?;
        Ok(())
    }

    fn spec_from_template(
        &self,
        template_id: &str,
        name: &str,
        root_dir: &Path,
        params: &TemplateParams,
    ) -> Result<WorkspaceSpec, WorkspaceManagerError> {
        let id = Self::parse_template_id(template_id)
            .ok_or_else(|| WorkspaceManagerError::UnknownTemplate(template_id.to_string()))?;
        templates::build_baseline(&id, name, root_dir, params)
            .ok_or_else(|| WorkspaceManagerError::UnknownTemplate(template_id.to_string()))
    }
}

/// Render a human-readable dry-run preview of a spec.
fn render_preview(spec: &WorkspaceSpec) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "Workspace: {}", spec.name);
    let _ = writeln!(s, "Location:  {}", spec.root_dir.display());
    let _ = writeln!(
        s,
        "Contents:  {} directories, {} files ({} bytes)",
        spec.metadata.total_directory_count,
        spec.metadata.total_file_count,
        spec.metadata.estimated_total_size_bytes
    );

    if !spec.directory_tree.is_empty() {
        let _ = writeln!(s, "\nTree:");
        let mut paths: Vec<&str> = spec
            .directory_tree
            .iter()
            .map(|e| e.relative_path.as_str())
            .collect();
        paths.sort_unstable();
        for p in paths {
            let _ = writeln!(s, "  {p}");
        }
    }

    if !spec.setup_commands.is_empty() {
        let _ = writeln!(s, "\nSetup commands:");
        for c in &spec.setup_commands {
            let _ = writeln!(
                s,
                "  {} {} — {}",
                c.program,
                c.args.join(" "),
                c.description
            );
        }
    }

    if !spec.calendar_blocks.is_empty() {
        let _ = writeln!(s, "\nSuggested calendar blocks:");
        for b in &spec.calendar_blocks {
            let recur = b.recurrence.as_deref().unwrap_or("once");
            let _ = writeln!(
                s,
                "  {} ({} min, {}, {})",
                b.title, b.duration_minutes, b.suggested_time, recur
            );
        }
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline::ActionStatus;
    use tempfile::TempDir;

    fn manager(allowed: &TempDir) -> WorkspaceManager {
        WorkspaceManager::in_memory(allowed.path()).unwrap()
    }

    #[test]
    fn lists_four_templates() {
        let allowed = TempDir::new().unwrap();
        let mgr = manager(&allowed);
        let templates = mgr.list_templates();
        assert_eq!(templates.len(), 4);
        let ids: Vec<&str> = templates.iter().map(|t| t.id.as_str()).collect();
        assert!(ids.contains(&"research"));
        assert!(ids.contains(&"code-project"));
        assert!(ids.contains(&"document"));
        assert!(ids.contains(&"design"));
    }

    #[test]
    fn code_project_template_advertises_language_param() {
        let allowed = TempDir::new().unwrap();
        let mgr = manager(&allowed);
        let cp = mgr
            .list_templates()
            .into_iter()
            .find(|t| t.id == "code-project")
            .unwrap();
        assert_eq!(cp.parameters, vec!["language".to_string()]);
    }

    #[test]
    fn parse_template_id_accepts_aliases() {
        assert_eq!(
            WorkspaceManager::parse_template_id("code_project"),
            Some(TemplateId::CodeProject)
        );
        assert_eq!(
            WorkspaceManager::parse_template_id("code-project"),
            Some(TemplateId::CodeProject)
        );
        assert_eq!(WorkspaceManager::parse_template_id("nope"), None);
    }

    #[test]
    fn preview_of_valid_template_has_no_errors() {
        let allowed = TempDir::new().unwrap();
        let mgr = manager(&allowed);
        let root = allowed.path().join("thesis");
        let result = mgr
            .preview_from_template("research", "thesis", &root, &TemplateParams::default())
            .unwrap();
        assert!(result.validation_errors.is_empty());
        assert!(result.preview.contains("Workspace: thesis"));
        assert!(result.preview.contains("Setup commands"));
    }

    #[test]
    fn preview_of_invalid_spec_reports_error() {
        let allowed = TempDir::new().unwrap();
        let mgr = manager(&allowed);
        // root outside allowed → preview should surface a validation error.
        let mut spec = templates::build_research_template("x", &allowed.path().join("x"));
        spec.root_dir = PathBuf::from("/etc/evil");
        spec.metadata = spec.compute_metadata();
        let result = mgr.preview(&spec);
        assert_eq!(result.validation_errors.len(), 1);
    }

    #[test]
    fn preview_unknown_template_errors() {
        let allowed = TempDir::new().unwrap();
        let mgr = manager(&allowed);
        let err = mgr
            .preview_from_template(
                "kanban",
                "x",
                &allowed.path().join("x"),
                &TemplateParams::default(),
            )
            .unwrap_err();
        assert!(matches!(err, WorkspaceManagerError::UnknownTemplate(_)));
    }

    #[test]
    fn create_records_timeline_entry_when_execution_fails() {
        let allowed = TempDir::new().unwrap();
        let mgr = manager(&allowed);
        let root = allowed.path().join("missing-parent").join("ws");
        let mut spec = templates::build_document_template("ws", &root);
        spec.setup_commands.clear();
        spec.metadata = spec.compute_metadata();

        let result = mgr.create(&spec);
        assert!(matches!(result, Err(WorkspaceManagerError::Execution(_))));
        let recent = mgr.timeline().list_recent(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].status, ActionStatus::PartiallyCompleted);
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;

        #[test]
        fn create_from_template_makes_files_and_records_action() {
            let allowed = TempDir::new().unwrap();
            let mgr = manager(&allowed);
            let root = allowed.path().join("thesis");
            // Use document template (no git dependency on the command? it
            // still runs git init). Drop to a custom spec without commands
            // for hermetic testing of the manager wiring.
            let mut spec = templates::build_document_template("thesis", &root);
            spec.setup_commands.clear();
            spec.metadata = spec.compute_metadata();
            let result = mgr.create(&spec).unwrap();
            assert!(result.status.is_complete());
            assert!(!result.action_timeline_id.is_empty());
            assert!(root.join("README.md").is_file());
        }

        #[test]
        fn create_then_undo_removes_workspace() {
            let allowed = TempDir::new().unwrap();
            let mgr = manager(&allowed);
            let root = allowed.path().join("ws");
            let mut spec = templates::build_research_template("ws", &root);
            spec.setup_commands.clear();
            spec.metadata = spec.compute_metadata();
            let result = mgr.create(&spec).unwrap();
            assert!(root.exists());
            mgr.undo(&result.action_timeline_id).unwrap();
            assert!(!root.exists());
        }

        #[test]
        fn undo_unknown_action_errors() {
            let allowed = TempDir::new().unwrap();
            let mgr = manager(&allowed);
            let err = mgr.undo("tl-nonexistent").unwrap_err();
            assert!(matches!(err, WorkspaceManagerError::Timeline(_)));
        }

        #[test]
        fn create_rejects_unsafe_spec() {
            let allowed = TempDir::new().unwrap();
            let mgr = manager(&allowed);
            let mut spec = templates::build_research_template("ws", &allowed.path().join("ws"));
            spec.directory_tree[0].relative_path = "../escape".to_string();
            spec.metadata = spec.compute_metadata();
            let err = mgr.create(&spec).unwrap_err();
            assert!(matches!(err, WorkspaceManagerError::Validation(_)));
        }

        #[test]
        fn double_undo_second_call_errors_on_timeline() {
            let allowed = TempDir::new().unwrap();
            let mgr = manager(&allowed);
            let root = allowed.path().join("ws");
            let mut spec = templates::build_research_template("ws", &root);
            spec.setup_commands.clear();
            spec.metadata = spec.compute_metadata();
            let result = mgr.create(&spec).unwrap();
            mgr.undo(&result.action_timeline_id).unwrap();
            // Second undo: timeline reports already-undone.
            let err = mgr.undo(&result.action_timeline_id).unwrap_err();
            assert!(matches!(err, WorkspaceManagerError::Timeline(_)));
        }

        #[test]
        fn undo_remains_reversible_when_cleanup_fails() {
            let allowed = TempDir::new().unwrap();
            let mgr = manager(&allowed);
            let outside = TempDir::new().unwrap();
            let outside_root = outside.path().join("victim");
            std::fs::create_dir(&outside_root).unwrap();
            let action_id = mgr
                .timeline()
                .record_action("bad workspace payload", &outside_root.to_string_lossy())
                .unwrap();

            let first = mgr.undo(&action_id);
            assert!(matches!(first, Err(WorkspaceManagerError::Execution(_))));
            assert_eq!(
                mgr.timeline().get_action_status(&action_id).unwrap(),
                ActionStatus::Complete
            );
        }
    }
}
