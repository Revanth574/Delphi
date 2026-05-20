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

use tracing::info;

use die_orchestrator::workspace::{TemplateParams, WorkspaceManager, WorkspaceSpec};

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
    serde_json::from_str::<WorkspaceSpec>(spec_json)
        .map_err(|e| zbus::fdo::Error::InvalidArgs(format!("invalid workspace spec JSON: {e}")))
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
        let spec = parse_spec(&spec_json)?;
        let mgr = self.lock()?;
        let result = mgr.preview(&spec);
        Ok((result.preview, result.validation_errors))
    }

    /// Validate, execute, and record a spec. Returns
    /// `(workspace_id, action_timeline_id)`.
    async fn create(&self, spec_json: String) -> zbus::fdo::Result<(String, String)> {
        info!("D-Bus workspace create");
        let spec = parse_spec(&spec_json)?;
        let mgr = self.lock()?;
        let result = mgr
            .create(&spec)
            .map_err(|e| zbus::fdo::Error::Failed(format!("workspace create failed: {e}")))?;
        Ok((result.workspace_id, result.action_timeline_id))
    }

    /// Build a spec from a baseline template, then create it. The fast
    /// path for the four baseline templates.
    async fn create_from_template(
        &self,
        template_id: String,
        name: String,
        root_dir: String,
        params: HashMap<String, String>,
    ) -> zbus::fdo::Result<(String, String)> {
        info!(template_id = %template_id, name = %name, "D-Bus workspace create_from_template");
        let tparams = TemplateParams::from_map(&params);
        let mgr = self.lock()?;
        let result = mgr
            .create_from_template(&template_id, &name, Path::new(&root_dir), &tparams)
            .map_err(|e| {
                zbus::fdo::Error::Failed(format!("workspace create_from_template failed: {e}"))
            })?;
        Ok((result.workspace_id, result.action_timeline_id))
    }

    /// Return the four baseline templates as a JSON array of
    /// `{id, name, description, parameters}`.
    async fn list_templates(&self) -> zbus::fdo::Result<String> {
        info!("D-Bus workspace list_templates");
        let mgr = self.lock()?;
        let templates = mgr.list_templates();
        serde_json::to_string(&templates)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize templates: {e}")))
    }

    /// Undo a recorded workspace creation by its action-timeline id.
    /// Errors if outside the 24-hour window, already undone, or unknown.
    async fn undo(&self, action_timeline_id: String) -> zbus::fdo::Result<()> {
        info!(action_timeline_id = %action_timeline_id, "D-Bus workspace undo");
        let mgr = self.lock()?;
        mgr.undo(&action_timeline_id)
            .map_err(|e| zbus::fdo::Error::Failed(format!("workspace undo failed: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let mut spec = die_orchestrator::workspace::templates::build_research_template(
            "x",
            &allowed.path().join("x"),
        );
        spec.root_dir = std::path::PathBuf::from("/etc/evil");
        spec.metadata = spec.compute_metadata();
        let spec_json = serde_json::to_string(&spec).unwrap();
        let (_preview, errors) = svc.preview(spec_json, true).await.unwrap();
        assert_eq!(errors.len(), 1);
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
        let (workspace_id, action_id) = svc
            .create_from_template(
                "code-project".to_string(),
                "ws".to_string(),
                root.to_string_lossy().to_string(),
                params,
            )
            .await
            .unwrap();
        assert!(workspace_id.contains("ws"));
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
        let (_wid, action_id) = svc.create(spec_json).await.unwrap();
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
        let err = svc.create(spec_json).await.unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::Failed(_)));
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
        assert!(matches!(err, zbus::fdo::Error::Failed(_)));
    }

    #[tokio::test]
    async fn undo_unknown_action_fails() {
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        let err = svc.undo("tl-nope".to_string()).await.unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::Failed(_)));
    }
}
