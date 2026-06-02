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
//! SVC-2: every method enforces authorization via the shared [`AuthGuard`] on
//! its first line. `preview`/`list_templates` are Autonomous; `create`/
//! `create_from_template` are Confirm; `undo` is the destructive Biometric tier
//! (proceed-and-audit — see `AuthGuard::enforce`).
//!
//! # Payload encoding
//!
//! Complex inputs/outputs cross the bus as JSON strings, matching the
//! project convention established by `health.rs` / `knowledge.rs`.
//!
//! Uses `std::sync::Mutex` (not `tokio::sync`) because the underlying
//! [`WorkspaceManager`] holds a `Timeline` whose `rusqlite::Connection`
//! is `!Send` across await points — see CLAUDE.md §3 rule 6. No method
//! holds the lock across an `.await`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use tracing::{info, warn};
use zbus::message::Header;

use die_orchestrator::workspace::{
    ExecutionStatus, TemplateParams, WorkspaceManager, WorkspaceManagerError, WorkspaceSpec,
};

use crate::auth_guard::AuthGuard;

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
/// use delphi_services::auth_guard::AuthGuard;
/// use die_orchestrator::workspace::WorkspaceManager;
/// use std::path::Path;
/// use std::sync::{Arc, Mutex};
///
/// let manager = WorkspaceManager::in_memory(Path::new("/home/u/projects")).unwrap();
/// let svc = WorkspaceService::new(Arc::new(Mutex::new(manager)), Arc::new(AuthGuard::dev_in_memory()));
/// ```
pub struct WorkspaceService {
    manager: Arc<Mutex<WorkspaceManager>>,
    guard: Arc<AuthGuard>,
}

impl WorkspaceService {
    /// Wrap a [`WorkspaceManager`] for D-Bus exposure, guarded by the shared
    /// [`AuthGuard`].
    #[must_use]
    pub fn new(manager: Arc<Mutex<WorkspaceManager>>, guard: Arc<AuthGuard>) -> Self {
        Self { manager, guard }
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
    /// `dry_run`. Returns `(preview_text, validation_errors)`.
    async fn preview(
        &self,
        #[zbus(header)] header: Header<'_>,
        spec_json: String,
        dry_run: bool,
    ) -> zbus::fdo::Result<(String, Vec<String>)> {
        self.guard.enforce("workspace.preview", &header)?;
        // SVC-6-R2-3: cap BEFORE info!()/parse/store, never after.
        crate::limits::ensure_within(&spec_json, crate::limits::MAX_STRING_BYTES, "spec_json")?;
        info!(dry_run, "D-Bus workspace preview");
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
    async fn create(
        &self,
        #[zbus(header)] header: Header<'_>,
        spec_json: String,
    ) -> zbus::fdo::Result<(String, String, String)> {
        self.guard.enforce("workspace.create", &header)?;
        crate::limits::ensure_within(&spec_json, crate::limits::MAX_STRING_BYTES, "spec_json")?;
        info!("D-Bus workspace create");
        let spec = parse_spec(&spec_json)?;
        let mgr = self.lock()?;
        let result = mgr
            .create(&spec)
            .map_err(|e| map_workspace_error("create", e))?;
        let status = status_json(&result.status)?;
        Ok((result.workspace_id, result.action_timeline_id, status))
    }

    /// Build a spec from a baseline template, then create it.
    async fn create_from_template(
        &self,
        #[zbus(header)] header: Header<'_>,
        template_id: String,
        name: String,
        root_dir: String,
        params: HashMap<String, String>,
    ) -> zbus::fdo::Result<(String, String, String)> {
        self.guard.enforce("workspace.create_from_template", &header)?;
        // SVC-6-R2-3: every cap (including the params map) BEFORE info!()/parse/store.
        crate::limits::ensure_within(&template_id, crate::limits::MAX_STRING_BYTES, "template_id")?;
        crate::limits::ensure_within(&name, crate::limits::MAX_STRING_BYTES, "name")?;
        crate::limits::ensure_within(&root_dir, crate::limits::MAX_STRING_BYTES, "root_dir")?;
        crate::limits::ensure_map_within(
            &params,
            crate::limits::MAX_MAP_ENTRIES,
            crate::limits::MAX_STRING_BYTES,
            "params",
        )?;
        info!(template_id = %template_id, name = %name, "D-Bus workspace create_from_template");
        let tparams = TemplateParams::from_map(&params);
        let mgr = self.lock()?;
        let result = mgr
            .create_from_template(&template_id, &name, Path::new(&root_dir), &tparams)
            .map_err(|e| map_workspace_error("create_from_template", e))?;
        let status = status_json(&result.status)?;
        Ok((result.workspace_id, result.action_timeline_id, status))
    }

    /// Return the baseline templates as a JSON array.
    async fn list_templates(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<String> {
        self.guard.enforce("workspace.list_templates", &header)?;
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
    async fn undo(
        &self,
        #[zbus(header)] header: Header<'_>,
        action_timeline_id: String,
    ) -> zbus::fdo::Result<()> {
        // SVC-2: undo is the destructive Biometric tier — proceed-and-audit.
        self.guard.enforce("workspace.undo", &header)?;
        crate::limits::ensure_within(
            &action_timeline_id,
            crate::limits::MAX_STRING_BYTES,
            "action_timeline_id",
        )?;
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

    use crate::auth::AuthPolicy;
    use crate::auth_guard::completeness::{
        assert_all_methods_classified, assert_behavioral_covers_all, header_msg as msg,
    };

    fn service(allowed: &TempDir) -> WorkspaceService {
        service_with(allowed, AuthPolicy::dev())
    }

    fn service_with(allowed: &TempDir, policy: AuthPolicy) -> WorkspaceService {
        let manager = WorkspaceManager::in_memory(allowed.path()).unwrap();
        let guard = Arc::new(AuthGuard::new(
            policy,
            Arc::new(Mutex::new(fortress::audit::AuditLog::in_memory())),
        ));
        WorkspaceService::new(Arc::new(Mutex::new(manager)), guard)
    }

    #[tokio::test]
    async fn list_templates_returns_four() {
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        let m = msg(":1.5");
        let json = svc.list_templates(m.header()).await.unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 4);
    }

    #[tokio::test]
    async fn preview_invalid_json_is_invalid_args() {
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        let m = msg(":1.5");
        let err = svc.preview(m.header(), "not json".to_string(), true).await.unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
    }

    #[tokio::test]
    async fn preview_valid_template_spec_has_no_errors() {
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        let root = allowed.path().join("thesis");
        let spec = die_orchestrator::workspace::templates::build_research_template("thesis", &root);
        let spec_json = serde_json::to_string(&spec).unwrap();
        let m = msg(":1.5");
        let (preview, errors) = svc.preview(m.header(), spec_json, true).await.unwrap();
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
        let safe_json = serde_json::to_string(&spec).unwrap();
        let m = msg(":1.5");
        let (_p, safe_errors) = svc.preview(m.header(), safe_json, true).await.unwrap();
        assert!(
            safe_errors.is_empty(),
            "in-bounds template must validate cleanly: {safe_errors:?}"
        );

        spec.root_dir = std::path::PathBuf::from("/etc/evil");
        spec.metadata = spec.compute_metadata();
        let unsafe_json = serde_json::to_string(&spec).unwrap();
        let m = msg(":1.5");
        let (_p2, errors) = svc.preview(m.header(), unsafe_json, true).await.unwrap();
        assert_eq!(errors.len(), 1, "out-of-bounds root must be rejected");
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
        let git_ok = std::process::Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !git_ok {
            return;
        }
        let m = msg(":1.5");
        let (workspace_id, action_id, status_json) = svc
            .create_from_template(
                m.header(),
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
        let m = msg(":1.5");
        svc.undo(m.header(), action_id).await.unwrap();
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
        let m = msg(":1.5");
        let (_wid, action_id, status_json) = svc.create(m.header(), spec_json).await.unwrap();
        let status: ExecutionStatus = serde_json::from_str(&status_json).unwrap();
        assert!(status.is_complete());
        assert!(root.join("README.md").is_file());
        let m = msg(":1.5");
        svc.undo(m.header(), action_id).await.unwrap();
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

        let m = msg(":1.5");
        let (_p, errors) = svc.preview(m.header(), spec_json.clone(), true).await.unwrap();
        assert_eq!(errors.len(), 1, "../ traversal must be flagged by the validator");

        let m = msg(":1.5");
        let err = svc.create(m.header(), spec_json).await.unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
        let msg_str = err.to_string();
        let allowed_str = allowed.path().to_string_lossy().to_string();
        assert!(!msg_str.contains(&allowed_str), "leaked allowed-root path: {msg_str}");
        assert!(!msg_str.contains("allowed_root"), "leaked validator internals: {msg_str}");
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
        let m = msg(":1.5");
        let err = svc
            .create(m.header(), serde_json::to_string(&spec).unwrap())
            .await
            .unwrap_err();
        let msg_str = err.to_string();
        assert!(!msg_str.contains(&allowed.path().to_string_lossy().to_string()));
        assert!(!msg_str.contains("allowed_root"));
        assert!(!msg_str.contains("/etc/evil"));
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

        let m = msg(":1.5");
        let (_workspace_id, _action_id, status_json) = svc
            .create(m.header(), serde_json::to_string(&spec).unwrap())
            .await
            .unwrap();
        let status: ExecutionStatus = serde_json::from_str(&status_json).unwrap();
        assert!(matches!(status, ExecutionStatus::TreeCreationFailed { .. }));
    }

    #[tokio::test]
    async fn create_from_unknown_template_fails() {
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        let m = msg(":1.5");
        let err = svc
            .create_from_template(
                m.header(),
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
        let m = msg(":1.5");
        let err = svc.undo(m.header(), "tl-nope".to_string()).await.unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::Failed(_)));
    }

    /// SVC-6: a `spec_json` larger than the general cap must be rejected with
    /// a size error BEFORE deserialization (after the SVC-2 guard).
    #[tokio::test]
    async fn create_rejects_oversize_spec_json() {
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        let oversize = "x".repeat(crate::limits::MAX_STRING_BYTES + 1);
        let m = msg(":1.5");
        let err = svc.create(m.header(), oversize).await.unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
        assert!(
            err.to_string().contains("limit"),
            "expected a size-limit error, got: {err}"
        );
    }

    /// SVC-6-R2-3: every D-Bus `String` parameter (and the `params` map) is
    /// capped at the boundary *before* logging, parsing, or storage.
    #[tokio::test]
    async fn every_string_param_rejects_oversize() {
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        let oversize = "x".repeat(crate::limits::MAX_STRING_BYTES + 1);

        let m = msg(":1.5");
        assert!(matches!(
            svc.preview(m.header(), oversize.clone(), false).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.create_from_template(m.header(), oversize.clone(), "n".to_string(), "/tmp".to_string(), HashMap::new())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.create_from_template(m.header(), "research".to_string(), oversize.clone(), "/tmp".to_string(), HashMap::new())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.create_from_template(m.header(), "research".to_string(), "n".to_string(), oversize.clone(), HashMap::new())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let too_many: HashMap<String, String> = (0..=crate::limits::MAX_MAP_ENTRIES)
            .map(|i| (format!("k{i}"), "v".to_string()))
            .collect();
        let m = msg(":1.5");
        assert!(matches!(
            svc.create_from_template(m.header(), "research".to_string(), "n".to_string(), "/tmp".to_string(), too_many)
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let mut big_value = HashMap::new();
        big_value.insert("k".to_string(), oversize.clone());
        let m = msg(":1.5");
        assert!(matches!(
            svc.create_from_template(m.header(), "research".to_string(), "n".to_string(), "/tmp".to_string(), big_value)
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let mut big_key = HashMap::new();
        big_key.insert(oversize.clone(), "v".to_string());
        let m = msg(":1.5");
        assert!(matches!(
            svc.create_from_template(m.header(), "research".to_string(), "n".to_string(), "/tmp".to_string(), big_key)
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.undo(m.header(), oversize.clone()).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
    }

    // ── SVC-2 completeness (Decision 3) ──

    #[test]
    fn svc2_every_method_is_classified() {
        use zbus::object_server::Interface;
        let allowed = TempDir::new().unwrap();
        let svc = service(&allowed);
        let mut xml = String::new();
        svc.introspect_to_writer(&mut xml, 0);
        assert_all_methods_classified("workspace", &xml);
    }

    #[tokio::test]
    async fn svc2_every_method_denies_unrecognized_caller_when_deployed() {
        let allowed = TempDir::new().unwrap();
        let svc = service_with(&allowed, AuthPolicy::deployed());
        let mut exercised: Vec<&str> = Vec::new();

        exercised.push("Preview");
        let m = msg(":1.999");
        assert!(matches!(
            svc.preview(m.header(), "{}".to_string(), true).await.unwrap_err(),
            zbus::fdo::Error::AccessDenied(_)
        ));
        exercised.push("Create");
        let m = msg(":1.999");
        assert!(matches!(
            svc.create(m.header(), "{}".to_string()).await.unwrap_err(),
            zbus::fdo::Error::AccessDenied(_)
        ));
        exercised.push("CreateFromTemplate");
        let m = msg(":1.999");
        assert!(matches!(
            svc.create_from_template(m.header(), "research".to_string(), "n".to_string(), "/tmp".to_string(), HashMap::new())
                .await
                .unwrap_err(),
            zbus::fdo::Error::AccessDenied(_)
        ));
        exercised.push("ListTemplates");
        let m = msg(":1.999");
        assert!(matches!(
            svc.list_templates(m.header()).await.unwrap_err(),
            zbus::fdo::Error::AccessDenied(_)
        ));
        exercised.push("Undo");
        let m = msg(":1.999");
        assert!(matches!(
            svc.undo(m.header(), "tl".to_string()).await.unwrap_err(),
            zbus::fdo::Error::AccessDenied(_)
        ));

        use zbus::object_server::Interface;
        let mut xml = String::new();
        svc.introspect_to_writer(&mut xml, 0);
        assert_behavioral_covers_all("workspace", &xml, &exercised);
    }
}
