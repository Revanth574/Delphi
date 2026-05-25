// SPDX-License-Identifier: MIT

//! D-Bus Workspace interface — capability #18 (generative workspace creation).
//!
//! Exposes the orchestrator's [`WorkspaceManager`] over D-Bus so the
//! shell can preview, create, and undo workspaces. Per CLAUDE.md §3
//! ("service wrapper lives in the services crate, actual logic lives in
//! the domain crate"), this file is a thin transport layer: it
//! deserializes JSON specs, locks the manager, and serializes results.
//! All safety (validation, openat2-anchored creation, command allowlist,
//! symlink-safe undo) lives in the orchestrator's `workspace` module.
//!
//! Interface: `org.delphi.Workspace`
//!
//! # Payload encoding
//!
//! Complex inputs/outputs cross the bus as JSON strings, matching the
//! project convention established by `health.rs` / `knowledge.rs`:
//!
//! - `Preview(spec_json, dry_run)` → `(preview_text, validation_errors)`
//! - `Create(spec_json)` → `(workspace_id, action_timeline_id)`
//! - `CreateFromTemplate(template_id, name, root_dir, params)` →
//!   `(workspace_id, action_timeline_id)`
//! - `ListTemplates()` → JSON array of template metadata
//! - `Undo(action_timeline_id)` → `()`
//!
//! Uses `std::sync::Mutex` (not `tokio::sync`) because the underlying
//! [`WorkspaceManager`] holds a `Timeline` whose `rusqlite::Connection`
//! is `!Send` across await points — see CLAUDE.md §3 rule 6. No method
//! holds the lock across an `.await`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use tracing::{info, warn};

use die_orchestrator::workspace::{
    ExecutionStatus, TemplateParams, WorkspaceManager, WorkspaceManagerError, WorkspaceSpec,
};

/// D-Bus object path for the Workspace interface.
pub const PATH: &str = "/org/delphi/Workspace";

/// Workspace D-Bus service.
///
/// Wraps a [`WorkspaceManager`] in `Arc<Mutex<...>>` so async D-Bus
/// methods can lock briefly, call into the synchronous domain logic, and
/// drop the guard before returning.
///
/// # Examples
///
/// ```
/// use delphi_services::workspace::WorkspaceService;
/// use die_orchestrator::workspace::WorkspaceManager;
/// use std::path::Path;
/// use std::sync::{Arc, Mutex};
///
/// let manager = WorkspaceManager::in_memory(Path::new("/home/u/projects")).unwrap();
/// let svc = WorkspaceService::new(Arc::new(Mutex::new(manager)));
/// ```
pub struct WorkspaceService {
    manager: Arc<Mutex<WorkspaceManager>>,
}

impl WorkspaceService {
    /// Wrap a [`WorkspaceManager`] for D-Bus exposure.
    #[must_use]
    pub fn new(manager: Arc<Mutex<WorkspaceManager>>) -> Self {
        Self { manager }
    }

    fn lock(&self) -> zbus::fdo::Result<std::sync::MutexGuard<'_, WorkspaceManager>> {
        self.manager
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("workspace manager lock poisoned: {e}")))
    }
}

fn parse_spec(spec_json: &str) -> zbus::fdo::Result<WorkspaceSpec> {
    serde_json::from_str::<WorkspaceSpec>(spec_json).map_err(|e| {
        warn!("workspace spec JSON parse failed: {e}");
        zbus::fdo::Error::InvalidArgs("Invalid spec format".to_string())
    })
}

fn status_json(status: &ExecutionStatus) -> zbus::fdo::Result<String> {
    serde_json::to_string(status).map_err(|e| {
        warn!("workspace status serialization failed: {e}");
        zbus::fdo::Error::Failed("Workspace status serialization failed".to_string())
    })
}

fn map_workspace_error(context: &str, error: WorkspaceManagerError) -> zbus::fdo::Error {
    warn!(context, error = ?error, "workspace operation failed");
    match error {
        WorkspaceManagerError::Validation(_) => {
            zbus::fdo::Error::InvalidArgs("Spec failed validation".to_string())
        }
        WorkspaceManagerError::UnknownTemplate(_) => {
            zbus::fdo::Error::InvalidArgs("Unknown workspace template".to_string())
        }
        WorkspaceManagerError::Execution(_) => {
            zbus::fdo::Error::Failed("Workspace operation failed".to_string())
        }
        WorkspaceManagerError::Timeline(_) | WorkspaceManagerError::TimelineUpdate(_) => {
            zbus::fdo::Error::Failed("Action recording failed".to_string())
        }
    }
}

#[zbus::interface(name = "org.delphi.Workspace")]
impl WorkspaceService {
    /// Dry-run preview a spec. Never mutates the filesystem regardless of
    /// `dry_run` (the flag exists for caller intent / forward-compat).
    /// Returns `(preview_text, validation_errors)`; an empty error list
    /// means the spec is safe to create.
    async fn preview(
        &self,
        spec_json: String,
        dry_run: bool,
    ) -> zbus::fdo::Result<(String, Vec<String>)> {
        info!(dry_run, "D-Bus workspace preview");
        crate::limits::ensure_within(&spec_json, crate::limits::MAX_STRING_BYTES, "spec_json")?;
        let spec = parse_spec(&spec_json)?;
        let mgr = self.lock()?;
        let result = mgr.preview(&spec);
        let errors = if result.validation_errors.is_empty() {
            Vec::new()
        } else {
            warn!(
                errors = ?result.validation_errors,
                "workspace preview validation failed"
            );
            vec!["Spec failed validation".to_string()]
        };
        Ok((result.preview, errors))
    }

    /// Validate, execute, and record a spec. Returns
    /// `(workspace_id, action_timeline_id, status_json)`.
    async fn create(&self, spec_json: String) -> zbus::fdo::Result<(String, String, String)> {
        info!("D-Bus workspace create");
        crate::limits::ensure_within(&spec_json, crate::limits::MAX_STRING_BYTES, "spec_json")?;
        let spec = parse_spec(&spec_json)?;
        let mgr = self.lock()?;
        let result = mgr
            .create(&spec)
            .map_err(|e| map_workspace_error("create", e))?;
        let status = status_json(&result.status)?;
        Ok((result.workspace_id, result.action_timeline_id, status))
    }

    /// Build a spec from a baseline template, then create it. The fast
    /// path for the four baseline templates.
    async fn create_from_template(
        &self,
        template_id: String,
        name: String,
        root_dir: String,
        params: HashMap<String, String>,
    ) -> zbus::fdo::Result<(String, String, String)> {
        info!(template_id = %template_id, name = %name, "D-Bus workspace create_from_template");
        crate::limits::ensure_within(&template_id, crate::limits::MAX_STRING_BYTES, "template_id")?;
        crate::limits::ensure_within(&name, crate::limits::MAX_STRING_BYTES, "name")?;
        crate::limits::ensure_within(&root_dir, crate::limits::MAX_STRING_BYTES, "root_dir")?;
        let tparams = TemplateParams::from_map(&params);
        let mgr = self.lock()?;
        let result = mgr
            .create_from_template(&template_id, &name, Path::new(&root_dir), &tparams)
            .map_err(|e| map_workspace_error("create_from_template", e))?;
        let status = status_json(&result.status)?;
        Ok((result.workspace_id, result.action_timeline_id, status))
    }

    /// Return the four baseline templates as a JSON array of
    /// `{id, name, description, parameters}`.
    async fn list_templates(&self) -> zbus::fdo::Result<String> {
        info!("D-Bus workspace list_templates");
        let mgr = self.lock()?;
        let templates = mgr.list_templates();
        serde_json::to_string(&templates).map_err(|e| {
            warn!("workspace list_templates serialization failed: {e}");
            zbus::fdo::Error::Failed("Template serialization failed".to_string())
        })
    }

    /// Undo a recorded workspace creation by its action-timeline id.
    /// Errors if outside the 24-hour window, already undone, or unknown.
    async fn undo(&self, action_timeline_id: String) -> zbus::fdo::Result<()> {
        info!(action_timeline_id = %action_timeline_id, "D-Bus workspace undo");
        let mgr = self.lock()?;
        mgr.undo(&action_timeline_id)
            .map_err(|e| map_workspace_error("undo", e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use die_orchestrator::workspace::{DirectoryEntry, EntryKind, TemplateId, WorkspaceMetadata};
    use tempfile::TempDir;

    fn service(allowed: &TempDir) -> WorkspaceService {
        let manager = WorkspaceManager::in_memory(allowed.path()).unwrap();
        WorkspaceService::new(Arc::new(Mutex::new(manager)))
    }

    #[tokio::test]
    async fn list_templates_returns_four() {
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        let json = svc.list_templates().await.unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 4);
    }

    #[tokio::test]
    async fn preview_invalid_json_is_invalid_args() {
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        let err = svc.preview("not json".to_string(), true).await.unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
    }

    #[tokio::test]
    async fn preview_valid_template_spec_has_no_errors() {
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        let root = allowed.path().join("thesis");
        let spec = die_orchestrator::workspace::templates::build_research_template("thesis", &root);
        let spec_json = serde_json::to_string(&spec).unwrap();
        let (preview, errors) = svc.preview(spec_json, true).await.unwrap();
        assert!(errors.is_empty());
        assert!(preview.contains("thesis"));
    }

    #[tokio::test]
    async fn preview_unsafe_spec_reports_validation_error() {
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        // SVC-10: isolate the out-of-bounds root as the *cause* of rejection.
        // The in-bounds template previews with zero validation errors; mutating
        // ONLY the root to a path outside `allowed_root` must flip it to one
        // error. Without this control, `errors.len() == 1` passed for ANY
        // validation failure — the "passes for the wrong reason" gap.
        let mut spec = die_orchestrator::workspace::templates::build_research_template(
            "x",
            &allowed.path().join("x"),
        );
        let safe_json = serde_json::to_string(&spec).unwrap();
        let (_p, safe_errors) = svc.preview(safe_json, true).await.unwrap();
        assert!(
            safe_errors.is_empty(),
            "in-bounds template must validate cleanly: {safe_errors:?}"
        );

        spec.root_dir = std::path::PathBuf::from("/etc/evil");
        spec.metadata = spec.compute_metadata();
        let unsafe_json = serde_json::to_string(&spec).unwrap();
        let (_p2, errors) = svc.preview(unsafe_json, true).await.unwrap();
        assert_eq!(errors.len(), 1, "out-of-bounds root must be rejected");
        // SVC-10: the collapsed error must not leak the server-side allowed
        // root or validator internals (matches the no-leak discipline of
        // create_with_outside_root_does_not_leak_allowed_root_in_error).
        let allowed_str = allowed.path().to_string_lossy().to_string();
        let joined = errors.join(" ");
        assert!(!joined.contains(&allowed_str), "leaked allowed-root path: {joined}");
        assert!(!joined.contains("allowed_root"), "leaked validator internals: {joined}");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn create_from_template_then_undo() {
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        let root = allowed.path().join("ws");
        let mut params = HashMap::new();
        params.insert("language".to_string(), "rust".to_string());
        // The research template runs `git init`; use document which also
        // runs git — to stay hermetic we instead drive a no-command path
        // via create() with a command-free spec below. Here we exercise
        // the template path and tolerate git presence.
        let git_ok = std::process::Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !git_ok {
            return;
        }
        let (workspace_id, action_id, status_json) = svc
            .create_from_template(
                "code-project".to_string(),
                "ws".to_string(),
                root.to_string_lossy().to_string(),
                params,
            )
            .await
            .unwrap();
        let status: ExecutionStatus = serde_json::from_str(&status_json).unwrap();
        assert!(workspace_id.contains("ws"));
        assert!(status.is_complete());
        assert!(root.join("Cargo.toml").is_file());
        svc.undo(action_id).await.unwrap();
        assert!(!root.exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn create_command_free_spec_and_undo() {
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        let root = allowed.path().join("doc");
        let mut spec =
            die_orchestrator::workspace::templates::build_document_template("doc", &root);
        spec.setup_commands.clear();
        spec.metadata = spec.compute_metadata();
        let spec_json = serde_json::to_string(&spec).unwrap();
        let (_wid, action_id, status_json) = svc.create(spec_json).await.unwrap();
        let status: ExecutionStatus = serde_json::from_str(&status_json).unwrap();
        assert!(status.is_complete());
        assert!(root.join("README.md").is_file());
        svc.undo(action_id).await.unwrap();
        assert!(!root.exists());
    }

    #[tokio::test]
    async fn create_unsafe_spec_fails() {
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        let mut spec = die_orchestrator::workspace::templates::build_research_template(
            "x",
            &allowed.path().join("x"),
        );
        spec.directory_tree[0].relative_path = "../escape".to_string();
        spec.metadata = spec.compute_metadata();
        let spec_json = serde_json::to_string(&spec).unwrap();

        // SVC-10: prove the rejection is the path-traversal *validation*, not
        // an incidental JSON-parse failure (which would ALSO surface as
        // InvalidArgs). A successful preview confirms the spec is well-formed
        // and parses, yet the validator still flags exactly one error for the
        // `../escape` component.
        let (_p, errors) = svc.preview(spec_json.clone(), true).await.unwrap();
        assert_eq!(errors.len(), 1, "../ traversal must be flagged by the validator");

        // create() then rejects the same well-formed spec at validation,
        // before any filesystem mutation.
        let err = svc.create(spec_json).await.unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
        // SVC-10: the rejection must not leak the server-side allowed root or
        // validator internals across the bus.
        let msg = err.to_string();
        let allowed_str = allowed.path().to_string_lossy().to_string();
        assert!(!msg.contains(&allowed_str), "leaked allowed-root path: {msg}");
        assert!(!msg.contains("allowed_root"), "leaked validator internals: {msg}");
    }

    #[tokio::test]
    async fn create_with_outside_root_does_not_leak_allowed_root_in_error() {
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        let mut spec = die_orchestrator::workspace::templates::build_research_template(
            "x",
            &allowed.path().join("x"),
        );
        spec.root_dir = std::path::PathBuf::from("/etc/evil");
        spec.metadata = spec.compute_metadata();
        let err = svc
            .create(serde_json::to_string(&spec).unwrap())
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(!msg.contains(&allowed.path().to_string_lossy().to_string()));
        assert!(!msg.contains("allowed_root"));
        assert!(!msg.contains("/etc/evil"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn create_with_duplicate_files_returns_tree_creation_failed_status() {
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        let mut spec = WorkspaceSpec {
            name: "dup".to_string(),
            root_dir: allowed.path().join("dup"),
            template_id: TemplateId::Research,
            directory_tree: vec![
                DirectoryEntry {
                    relative_path: "README.md".to_string(),
                    kind: EntryKind::File,
                    content: Some("first".to_string()),
                },
                DirectoryEntry {
                    relative_path: "README.md".to_string(),
                    kind: EntryKind::File,
                    content: Some("second".to_string()),
                },
            ],
            setup_commands: vec![],
            calendar_blocks: vec![],
            metadata: WorkspaceMetadata::default(),
        };
        spec.metadata = spec.compute_metadata();

        let (_workspace_id, _action_id, status_json) = svc
            .create(serde_json::to_string(&spec).unwrap())
            .await
            .unwrap();
        let status: ExecutionStatus = serde_json::from_str(&status_json).unwrap();
        assert!(matches!(status, ExecutionStatus::TreeCreationFailed { .. }));
    }

    #[tokio::test]
    async fn create_from_unknown_template_fails() {
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        let err = svc
            .create_from_template(
                "kanban".to_string(),
                "x".to_string(),
                allowed.path().join("x").to_string_lossy().to_string(),
                HashMap::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
    }

    #[tokio::test]
    async fn undo_unknown_action_fails() {
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        let err = svc.undo("tl-nope".to_string()).await.unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::Failed(_)));
    }

    /// SVC-6: a `spec_json` larger than the general cap must be rejected with
    /// a size error BEFORE deserialization. RED pre-fix (an oversize blob
    /// reaches `parse_spec` and fails as "Invalid spec format", not a size
    /// error), GREEN once the cap is enforced at the method boundary.
    #[tokio::test]
    async fn create_rejects_oversize_spec_json() {
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        let oversize = "x".repeat(crate::limits::MAX_STRING_BYTES + 1);
        let err = svc.create(oversize).await.unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
        assert!(
            err.to_string().contains("limit"),
            "expected a size-limit error, got: {err}"
        );
    }
}
