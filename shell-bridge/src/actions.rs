// SPDX-License-Identifier: MIT

//! Runtime action API for the shell bridge.
//!
//! This module owns the first "living loop" workflow exposed by the local
//! daemon: inspect a repository, run approved checks, write an action receipt,
//! and observe the episode as metadata for the learning facade.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use die_learning::{EventCategory, LearningError, LearningEvent};
use die_orchestrator::OrchestratorError;
use die_orchestrator::learning::LearningFacade;
use die_orchestrator::timeline::Timeline;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::time::sleep;

/// The first proven workflow supported by the runtime API.
pub const DEVELOPER_REPO_CHECK: &str = "developer_repo_check";

/// Runtime workflow for an approved timeline undo operation.
pub const TIMELINE_UNDO: &str = "timeline_undo";

const WORKFLOW_ACTION_TYPE: &str = "developer.workflow.repo_check";
const DEFAULT_TIMEOUT_SECS: u64 = 60;
const MAX_TIMEOUT_SECS: u64 = 300;
const DEFAULT_APPROVAL_TTL_SECS: u64 = 120;
const MAX_ARG_BYTES: usize = 2048;
const MAX_ARGS: usize = 64;
const MAX_OUTPUT_CHARS: usize = 2048;
const MAX_CAPTURE_BYTES: usize = 64 * 1024;
const OUTPUT_DRAIN_TIMEOUT_SECS: u64 = 2;
const PROCESS_KILL_GRACE_MS: u64 = 300;

#[derive(Debug, thiserror::Error)]
pub enum ActionApiError {
    #[error("missing required param: {0}")]
    MissingParam(&'static str),
    #[error("unsupported workflow: {0}")]
    UnsupportedWorkflow(String),
    #[error("execution requires a server-issued approval token")]
    ApprovalRequired,
    #[error("invalid approval token: {0}")]
    ApprovalInvalid(String),
    #[error("approval minting requires the bridge auth token")]
    BridgeAuthRequired,
    #[error("invalid bridge auth token")]
    BridgeAuthInvalid,
    #[error("approval minting requires explicit user confirmation")]
    UserConfirmationRequired,
    #[error("invalid repo_path")]
    InvalidRepoPath,
    #[error("invalid command: {0}")]
    InvalidCommand(String),
    #[error("timeline state unavailable")]
    TimelineUnavailable,
    #[error("learning state unavailable")]
    LearningUnavailable,
    #[error("timeline error: {0}")]
    Timeline(#[from] OrchestratorError),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
struct PlanParams {
    #[serde(default = "default_workflow")]
    workflow: String,
    #[serde(default)]
    repo_path: Option<String>,
    #[serde(default)]
    check_command: Option<Vec<String>>,
    #[serde(default)]
    timeout_secs: Option<u64>,
    #[serde(default)]
    action_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExecuteParams {
    #[serde(default = "default_workflow")]
    workflow: String,
    repo_path: String,
    #[serde(default)]
    check_command: Option<Vec<String>>,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct UndoParams {
    action_id: String,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

fn default_workflow() -> String {
    DEVELOPER_REPO_CHECK.to_string()
}

#[derive(Debug, Clone, Serialize)]
pub struct ApprovalCapability {
    pub token: String,
    pub expires_at_epoch_secs: i64,
    pub request_hash: String,
    pub scope: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecuteRequest {
    workflow: String,
    repo_path: PathBuf,
    workspace_root: PathBuf,
    git_root: PathBuf,
    display_repo_path: String,
    check_command: Option<Vec<String>>,
    timeout_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UndoRequest {
    action_id: String,
    timeout_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovalKind {
    Execute(ExecuteRequest),
    Undo(UndoRequest),
}

#[derive(Clone, Debug)]
struct ApprovalGrant {
    kind: ApprovalKind,
    expires_at_epoch_secs: i64,
}

#[derive(Debug, Default)]
pub struct ApprovalRegistry {
    grants: HashMap<String, ApprovalGrant>,
}

impl ApprovalRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn issue(&mut self, kind: ApprovalKind) -> ApprovalCapability {
        self.retain_live();
        let token = random_token();
        let expires_at_epoch_secs = current_epoch_secs() + DEFAULT_APPROVAL_TTL_SECS as i64;
        let request_hash = request_hash(&kind);
        let scope = approval_scope(&kind);
        self.grants.insert(
            token.clone(),
            ApprovalGrant {
                kind,
                expires_at_epoch_secs,
            },
        );
        ApprovalCapability {
            token,
            expires_at_epoch_secs,
            request_hash,
            scope,
        }
    }

    pub fn consume_execute(
        &mut self,
        token: &str,
        request: &ExecuteRequest,
    ) -> Result<(), ActionApiError> {
        match self.consume(token)? {
            ApprovalKind::Execute(approved) if approved == *request => Ok(()),
            ApprovalKind::Execute(_) => Err(ActionApiError::ApprovalInvalid(
                "token is bound to a different execution request".to_string(),
            )),
            ApprovalKind::Undo(_) => Err(ActionApiError::ApprovalInvalid(
                "token is not an execution approval".to_string(),
            )),
        }
    }

    pub fn consume_undo(
        &mut self,
        token: &str,
        request: &UndoRequest,
    ) -> Result<(), ActionApiError> {
        match self.consume(token)? {
            ApprovalKind::Undo(approved) if approved == *request => Ok(()),
            ApprovalKind::Undo(_) => Err(ActionApiError::ApprovalInvalid(
                "token is bound to a different undo request".to_string(),
            )),
            ApprovalKind::Execute(_) => Err(ActionApiError::ApprovalInvalid(
                "token is not an undo approval".to_string(),
            )),
        }
    }

    fn consume(&mut self, token: &str) -> Result<ApprovalKind, ActionApiError> {
        if token.trim().is_empty() {
            return Err(ActionApiError::ApprovalRequired);
        }
        self.retain_live();
        let grant = self.grants.remove(token).ok_or_else(|| {
            ActionApiError::ApprovalInvalid("missing, expired, or already used".to_string())
        })?;
        if grant.expires_at_epoch_secs <= current_epoch_secs() {
            return Err(ActionApiError::ApprovalInvalid("expired".to_string()));
        }
        Ok(grant.kind)
    }

    fn retain_live(&mut self) {
        let now = current_epoch_secs();
        self.grants
            .retain(|_, grant| grant.expires_at_epoch_secs > now);
    }
}

#[derive(Debug, Serialize)]
pub struct ActionPlan {
    pub workflow: String,
    pub summary: String,
    pub risk_tier: String,
    pub requires_approval: bool,
    pub reversible: bool,
    pub undo_available: bool,
    pub steps: Vec<PlanStep>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalCapability>,
}

#[derive(Debug, Serialize)]
pub struct PlanStep {
    pub id: String,
    pub tool: String,
    pub description: String,
    pub requires_approval: bool,
}

#[derive(Debug, Serialize)]
pub struct ProjectContext {
    pub repo_path: String,
    pub project_name: String,
    pub markers: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CommandRun {
    pub tool: String,
    pub argv: Vec<String>,
    pub status: String,
    pub exit_code: Option<i32>,
    pub output_summary: String,
}

#[derive(Debug, Serialize)]
pub struct VerificationResult {
    pub status: String,
    pub summary: String,
}

#[derive(Debug, Serialize)]
pub struct Reversibility {
    pub reversible: bool,
    pub undo_available: bool,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct AutomationCandidate {
    pub id: String,
    pub stage: String,
    pub next_stage_on_accept: String,
    pub autonomous: bool,
    pub promotion_requirement: String,
}

#[derive(Debug, Serialize)]
pub struct LearningReceipt {
    pub observed: bool,
    pub episode_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate: Option<AutomationCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ActionReceipt {
    pub workflow: String,
    pub status: String,
    pub timeline_id: String,
    pub context: ProjectContext,
    pub commands: Vec<CommandRun>,
    pub summary: String,
    pub proposed_next_step: String,
    pub reversibility: Reversibility,
    pub verification: VerificationResult,
    pub learning: LearningReceipt,
}

#[derive(Debug, Serialize)]
pub struct UndoReceipt {
    pub status: String,
    pub action_id: String,
    pub command: CommandRun,
    pub executed: bool,
}

#[derive(Debug, Serialize)]
struct TimelineReceiptSummary {
    workflow: String,
    status: String,
    timeline_id: String,
    project_name: String,
    command_count: usize,
    failed_tools: Vec<String>,
    verification_status: String,
    verification_summary: String,
    learning_observed: bool,
}

/// Static capability list for the runtime API.
#[must_use]
pub fn capabilities_payload() -> serde_json::Value {
    serde_json::json!({
        "tools": [
            {
                "id": "file.context",
                "kind": "observation",
                "description": "Inspect local project metadata without reading file contents"
            },
            {
                "id": "git.status",
                "kind": "observation",
                "description": "Run git status --short in the approved repository"
            },
            {
                "id": "git.log",
                "kind": "observation",
                "description": "Run git log --oneline -5 in the approved repository"
            },
            {
                "id": "command.run",
                "kind": "high_risk_project_controlled_execution",
                "requires_approval": true,
                "constraints": [
                    "server-issued one-shot approval token from actions.approve",
                    "actions.approve requires app-local bridge auth and explicit user confirmation",
                    "approval bound to workflow, repo path, argv, timeout, and expiry",
                    "subprocess environment is cleared except a minimal allowlist",
                    "timeouts terminate the process tree and bound output draining",
                    "argv array only",
                    "developer command allowlist only; package manager and Cargo commands execute project-controlled code"
                ]
            },
            {
                "id": "timeline.record",
                "kind": "audit",
                "description": "Record pending and terminal action states with redacted summaries"
            },
            {
                "id": "learning.observe_episode",
                "kind": "metadata_only",
                "description": "Observe workflow metadata unless Focus mode is active"
            }
        ],
        "workflows": [
            {
                "id": DEVELOPER_REPO_CHECK,
                "stage": "proven_slice",
                "requires_approval": true
            },
            {
                "id": TIMELINE_UNDO,
                "stage": "guarded_runtime_api",
                "requires_approval": true
            }
        ]
    })
}

/// Build an execution plan for the supported workflow.
pub fn plan(params: &serde_json::Value) -> Result<ActionPlan, ActionApiError> {
    let params: PlanParams = serde_json::from_value(params.clone())?;
    match params.workflow.as_str() {
        DEVELOPER_REPO_CHECK => plan_developer_repo_check(params),
        TIMELINE_UNDO => plan_timeline_undo(params),
        other => Err(ActionApiError::UnsupportedWorkflow(other.to_string())),
    }
}

fn plan_developer_repo_check(params: PlanParams) -> Result<ActionPlan, ActionApiError> {
    if let Some(command) = &params.check_command {
        validate_command(command)?;
    }

    let target = match params.repo_path.as_deref() {
        Some(path) => {
            normalize_execute_parts(
                &params.workflow,
                path,
                params.check_command.clone(),
                params.timeout_secs,
            )?
            .display_repo_path
        }
        None => "the selected repository".to_string(),
    };

    Ok(ActionPlan {
        workflow: params.workflow,
        summary: format!(
            "Inspect {target}, run git checks, optionally run a high-risk approved project command, and return an action receipt."
        ),
        risk_tier: "high_risk".to_string(),
        requires_approval: true,
        reversible: false,
        undo_available: false,
        steps: vec![
            PlanStep {
                id: "record_pending".to_string(),
                tool: "timeline.record".to_string(),
                description: "Record the workflow as pending before command execution".to_string(),
                requires_approval: false,
            },
            PlanStep {
                id: "inspect_context".to_string(),
                tool: "file.context".to_string(),
                description: "Inspect repository metadata and project markers".to_string(),
                requires_approval: false,
            },
            PlanStep {
                id: "git_status".to_string(),
                tool: "git.status".to_string(),
                description: "Run git status --short".to_string(),
                requires_approval: true,
            },
            PlanStep {
                id: "git_log".to_string(),
                tool: "git.log".to_string(),
                description: "Run git log --oneline -5".to_string(),
                requires_approval: true,
            },
            PlanStep {
                id: "run_check".to_string(),
                tool: "command.run".to_string(),
                description: "Run the caller-provided project command, if any, as high-risk approved execution".to_string(),
                requires_approval: true,
            },
            PlanStep {
                id: "observe_episode".to_string(),
                tool: "learning.observe_episode".to_string(),
                description: "Record a metadata-only workflow episode unless Focus is active"
                    .to_string(),
                requires_approval: false,
            },
        ],
        approval: None,
    })
}

fn plan_timeline_undo(params: PlanParams) -> Result<ActionPlan, ActionApiError> {
    let action_id = params
        .action_id
        .as_deref()
        .ok_or(ActionApiError::MissingParam("action_id"))?;
    if action_id.trim().is_empty() {
        return Err(ActionApiError::MissingParam("action_id"));
    }
    Ok(ActionPlan {
        workflow: TIMELINE_UNDO.to_string(),
        summary: format!(
            "Undo timeline action {action_id} only if a structured argv undo payload is present."
        ),
        risk_tier: "confirm".to_string(),
        requires_approval: true,
        reversible: false,
        undo_available: false,
        steps: vec![
            PlanStep {
                id: "reserve_undo".to_string(),
                tool: "timeline.begin_undo".to_string(),
                description: "Reserve the undo window without marking the action undone"
                    .to_string(),
                requires_approval: true,
            },
            PlanStep {
                id: "run_structured_undo".to_string(),
                tool: "command.run".to_string(),
                description: "Run only a structured argv undo payload through the approved runner"
                    .to_string(),
                requires_approval: true,
            },
            PlanStep {
                id: "finalize_undo".to_string(),
                tool: "timeline.complete_undo".to_string(),
                description: "Mark the action undone only after the undo command succeeds"
                    .to_string(),
                requires_approval: false,
            },
        ],
        approval: None,
    })
}

pub fn approval_kind_for_plan(
    params: &serde_json::Value,
) -> Result<Option<ApprovalKind>, ActionApiError> {
    let params: PlanParams = serde_json::from_value(params.clone())?;
    match params.workflow.as_str() {
        DEVELOPER_REPO_CHECK => match params.repo_path {
            Some(repo_path) => Ok(Some(ApprovalKind::Execute(normalize_execute_parts(
                &params.workflow,
                &repo_path,
                params.check_command,
                params.timeout_secs,
            )?))),
            None => Ok(None),
        },
        TIMELINE_UNDO => {
            let action_id = params
                .action_id
                .ok_or(ActionApiError::MissingParam("action_id"))?;
            Ok(Some(ApprovalKind::Undo(UndoRequest {
                action_id,
                timeout_secs: clamp_timeout(params.timeout_secs),
            })))
        }
        other => Err(ActionApiError::UnsupportedWorkflow(other.to_string())),
    }
}

pub fn normalize_execute_request(
    params: &serde_json::Value,
) -> Result<ExecuteRequest, ActionApiError> {
    let params: ExecuteParams = serde_json::from_value(params.clone())?;
    normalize_execute_parts(
        &params.workflow,
        &params.repo_path,
        params.check_command,
        params.timeout_secs,
    )
}

fn normalize_execute_parts(
    workflow: &str,
    repo_path: &str,
    check_command: Option<Vec<String>>,
    timeout_secs: Option<u64>,
) -> Result<ExecuteRequest, ActionApiError> {
    ensure_workflow(workflow)?;
    if let Some(command) = &check_command {
        validate_command(command)?;
    }
    let scope = canonical_repo_scope(repo_path)?;
    Ok(ExecuteRequest {
        workflow: workflow.to_string(),
        display_repo_path: display_path(&scope.repo_path, &scope.workspace_root),
        repo_path: scope.repo_path,
        workspace_root: scope.workspace_root,
        git_root: scope.git_root,
        check_command,
        timeout_secs: clamp_timeout(timeout_secs),
    })
}

pub fn normalize_undo_request(params: &serde_json::Value) -> Result<UndoRequest, ActionApiError> {
    let params: UndoParams = serde_json::from_value(params.clone())?;
    if params.action_id.trim().is_empty() {
        return Err(ActionApiError::MissingParam("action_id"));
    }
    Ok(UndoRequest {
        action_id: params.action_id,
        timeout_secs: clamp_timeout(params.timeout_secs),
    })
}

pub fn required_approval_token(params: &serde_json::Value) -> Result<String, ActionApiError> {
    params
        .get("approval_token")
        .and_then(|v| v.as_str())
        .filter(|token| !token.trim().is_empty())
        .map(ToOwned::to_owned)
        .ok_or(ActionApiError::ApprovalRequired)
}

/// Execute the developer repository workflow and return an action receipt.
pub async fn execute(
    request: ExecuteRequest,
    timeline: &Arc<Mutex<Timeline>>,
    learning: &Arc<Mutex<LearningFacade>>,
) -> Result<ActionReceipt, ActionApiError> {
    let redactor = Redactor::for_request(&request);
    let context = inspect_project_context(&request, &redactor);
    let timeline_id = {
        let tl = timeline
            .lock()
            .map_err(|_| ActionApiError::TimelineUnavailable)?;
        tl.record_pending_irreversible(
            WORKFLOW_ACTION_TYPE,
            &format!("Developer repo check: {}", context.project_name),
        )?
    };

    let mut commands = Vec::new();
    commands.push(
        run_command(
            &request.repo_path,
            &[
                "git".to_string(),
                "status".to_string(),
                "--short".to_string(),
            ],
            request.timeout_secs,
            "git.status",
            &redactor,
        )
        .await,
    );
    commands.push(
        run_command(
            &request.repo_path,
            &[
                "git".to_string(),
                "log".to_string(),
                "--oneline".to_string(),
                "-5".to_string(),
            ],
            request.timeout_secs,
            "git.log",
            &redactor,
        )
        .await,
    );
    let check_was_requested = request.check_command.is_some();
    if let Some(command) = &request.check_command {
        commands.push(
            run_command(
                &request.repo_path,
                command,
                request.timeout_secs,
                "command.run",
                &redactor,
            )
            .await,
        );
    }

    let verification = verify_commands(&commands, check_was_requested);
    let status = if verification.status == "passed" {
        "complete"
    } else {
        "failed"
    }
    .to_string();
    let summary = summarize_workflow(&commands, &verification);
    let proposed_next_step = propose_next_step(&verification, check_was_requested);
    let learning_receipt =
        observe_learning_episode(learning, &timeline_id, &status, &verification)?;

    let receipt = ActionReceipt {
        workflow: request.workflow,
        status,
        timeline_id: timeline_id.clone(),
        context,
        commands,
        summary,
        proposed_next_step,
        reversibility: Reversibility {
            reversible: false,
            undo_available: false,
            reason: "Observation/check workflow; no state mutation to undo".to_string(),
        },
        verification,
        learning: learning_receipt,
    };

    let outputs = timeline_summary_json(&receipt)?;
    let tl = timeline
        .lock()
        .map_err(|_| ActionApiError::TimelineUnavailable)?;
    if receipt.status == "complete" {
        tl.complete_pending(&timeline_id, Some(&outputs))?;
    } else {
        tl.fail_pending(&timeline_id, Some(&outputs))?;
    }

    Ok(receipt)
}

/// Execute an approved structured undo.
///
/// The current timeline stores legacy undo payloads as strings. This runtime
/// path only executes payloads that are JSON argv arrays. Unstructured payloads
/// are rejected after aborting the undo reservation, so the timeline never
/// claims an action was undone when no reversing operation ran.
pub async fn undo(
    request: UndoRequest,
    timeline: &Arc<Mutex<Timeline>>,
) -> Result<UndoReceipt, ActionApiError> {
    let undo_payload = {
        let tl = timeline
            .lock()
            .map_err(|_| ActionApiError::TimelineUnavailable)?;
        tl.begin_undo(&request.action_id)?
    };

    let argv = match parse_structured_undo_payload(&undo_payload) {
        Ok(argv) => argv,
        Err(e) => {
            abort_undo_best_effort(timeline, &request.action_id);
            return Err(e);
        }
    };

    let cwd = std::env::current_dir().map_err(|_| ActionApiError::InvalidRepoPath)?;
    let redactor = Redactor::for_paths(&cwd, &cwd);
    let command = run_command(
        &cwd,
        &argv,
        request.timeout_secs,
        "timeline.undo",
        &redactor,
    )
    .await;

    if command.status == "complete" {
        let tl = timeline
            .lock()
            .map_err(|_| ActionApiError::TimelineUnavailable)?;
        tl.complete_undo(&request.action_id)?;
        Ok(UndoReceipt {
            status: "complete".to_string(),
            action_id: request.action_id,
            command,
            executed: true,
        })
    } else {
        abort_undo_best_effort(timeline, &request.action_id);
        Ok(UndoReceipt {
            status: "failed".to_string(),
            action_id: request.action_id,
            command,
            executed: false,
        })
    }
}

#[must_use]
pub fn timeline_outputs_summary(outputs: Option<&str>) -> Option<serde_json::Value> {
    let outputs = outputs?;
    match serde_json::from_str::<serde_json::Value>(outputs) {
        Ok(value) => Some(serde_json::json!({
            "workflow": value.get("workflow").cloned().unwrap_or(serde_json::Value::Null),
            "status": value.get("status").cloned().unwrap_or(serde_json::Value::Null),
            "command_count": value.get("command_count").cloned().unwrap_or(serde_json::Value::Null),
            "failed_tools": value.get("failed_tools").cloned().unwrap_or_else(|| serde_json::json!([])),
            "verification_status": value.get("verification_status").cloned().unwrap_or(serde_json::Value::Null),
            "learning_observed": value.get("learning_observed").cloned().unwrap_or(serde_json::Value::Null),
        })),
        Err(_) => Some(serde_json::json!({
            "status": "redacted",
            "summary": truncate_chars(redact_for_bridge(outputs), MAX_OUTPUT_CHARS)
        })),
    }
}

#[must_use]
pub fn redact_for_bridge(text: &str) -> String {
    Redactor::for_bridge().redact(text)
}

#[must_use]
pub fn undo_payload_preview(payload: &str) -> serde_json::Value {
    match serde_json::from_str::<Vec<String>>(payload) {
        Ok(argv) => serde_json::json!({
            "kind": "structured_argv",
            "program": argv.first().map(|program| redact_for_bridge(program)),
            "arg_count": argv.len().saturating_sub(1),
        }),
        Err(_) => serde_json::json!({
            "kind": "legacy_payload",
            "summary": "redacted; legacy undo payload is not returned over the bridge"
        }),
    }
}

fn ensure_workflow(workflow: &str) -> Result<(), ActionApiError> {
    if workflow == DEVELOPER_REPO_CHECK {
        Ok(())
    } else {
        Err(ActionApiError::UnsupportedWorkflow(workflow.to_string()))
    }
}

fn clamp_timeout(timeout_secs: Option<u64>) -> u64 {
    timeout_secs
        .unwrap_or(DEFAULT_TIMEOUT_SECS)
        .clamp(1, MAX_TIMEOUT_SECS)
}

#[derive(Debug)]
struct RepoScope {
    repo_path: PathBuf,
    workspace_root: PathBuf,
    git_root: PathBuf,
}

fn canonical_repo_scope(path: &str) -> Result<RepoScope, ActionApiError> {
    if path.trim().is_empty() {
        return Err(ActionApiError::MissingParam("repo_path"));
    }
    let path = PathBuf::from(path);
    let canonical = std::fs::canonicalize(&path).map_err(|_| ActionApiError::InvalidRepoPath)?;
    if !canonical.is_dir() {
        return Err(ActionApiError::InvalidRepoPath);
    }
    let git_root = find_git_root(&canonical).ok_or(ActionApiError::InvalidRepoPath)?;
    let workspace_root = workspace_root_for(&canonical).ok_or(ActionApiError::InvalidRepoPath)?;
    if !git_root.starts_with(&workspace_root) && !canonical.starts_with(&workspace_root) {
        return Err(ActionApiError::InvalidRepoPath);
    }
    Ok(RepoScope {
        repo_path: canonical,
        workspace_root,
        git_root,
    })
}

fn find_git_root(path: &Path) -> Option<PathBuf> {
    let mut cursor = Some(path);
    while let Some(candidate) = cursor {
        if candidate.join(".git").exists() {
            return Some(candidate.to_path_buf());
        }
        cursor = candidate.parent();
    }
    None
}

fn workspace_root_for(path: &Path) -> Option<PathBuf> {
    configured_workspace_roots()
        .into_iter()
        .filter(|root| path.starts_with(root))
        .max_by_key(|root| root.components().count())
}

fn configured_workspace_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(raw) = std::env::var_os("DELPHI_WORKSPACE_ROOTS") {
        roots.extend(std::env::split_paths(&raw).filter_map(canonical_dir));
    }
    if let Ok(current_dir) = std::env::current_dir() {
        if let Some(canonical) = canonical_dir(current_dir.clone()) {
            roots.push(canonical);
        }
        if let Some(git_root) = find_git_root(&current_dir).and_then(canonical_dir) {
            roots.push(git_root);
        }
    }
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if let Some(canonical) = canonical_dir(manifest_dir.to_path_buf()) {
        roots.push(canonical);
    }
    if let Some(git_root) = find_git_root(manifest_dir).and_then(canonical_dir) {
        roots.push(git_root);
    }
    roots.sort();
    roots.dedup();
    roots
}

fn canonical_dir(path: PathBuf) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(path).ok()?;
    canonical.is_dir().then_some(canonical)
}

fn inspect_project_context(request: &ExecuteRequest, redactor: &Redactor) -> ProjectContext {
    let mut markers = Vec::new();
    for (file, marker) in [
        ("Cargo.toml", "rust-workspace"),
        ("package.json", "node-project"),
        ("pnpm-lock.yaml", "pnpm-lock"),
        (".git", "git-worktree"),
    ] {
        if request.repo_path.join(file).exists() {
            markers.push(marker.to_string());
        }
    }

    ProjectContext {
        repo_path: request.display_repo_path.clone(),
        project_name: request
            .repo_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("repository")
            .to_string(),
        markers: markers
            .into_iter()
            .map(|marker| redactor.redact(&marker))
            .collect(),
    }
}

fn validate_command(command: &[String]) -> Result<(), ActionApiError> {
    if command.is_empty() {
        return Err(ActionApiError::InvalidCommand(
            "argv array is empty".to_string(),
        ));
    }
    if command.len() > MAX_ARGS {
        return Err(ActionApiError::InvalidCommand(
            "too many arguments".to_string(),
        ));
    }
    for arg in command {
        if arg.is_empty() {
            return Err(ActionApiError::InvalidCommand("empty argument".to_string()));
        }
        if arg.contains('\0') {
            return Err(ActionApiError::InvalidCommand(
                "NUL byte in argument".to_string(),
            ));
        }
        if arg.len() > MAX_ARG_BYTES {
            return Err(ActionApiError::InvalidCommand(
                "argument too large".to_string(),
            ));
        }
    }
    if command[0].contains('/') || command[0].contains('\\') {
        return Err(ActionApiError::InvalidCommand(
            "program must be selected from the high-risk developer execution allowlist"
                .to_string(),
        ));
    }

    let program = Path::new(&command[0])
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(command[0].as_str())
        .to_ascii_lowercase();

    if !allowed_developer_check(&program, &command[1..]) {
        return Err(ActionApiError::InvalidCommand(format!(
            "{program} is not in the high-risk developer execution allowlist"
        )));
    }
    Ok(())
}

fn allowed_developer_check(program: &str, args: &[String]) -> bool {
    let Some(first) = args.first().map(|arg| arg.as_str()) else {
        return false;
    };
    match program {
        "cargo" | "cargo.exe" => matches!(
            first,
            "build" | "check" | "clippy" | "test" | "nextest"
        ),
        "pnpm" | "pnpm.cmd" | "pnpm.exe" => allowed_package_manager_args(first, &args[1..]),
        "npm" | "npm.cmd" | "npm.exe" => allowed_npm_args(first, &args[1..]),
        "yarn" | "yarn.cmd" | "yarn.exe" => allowed_package_manager_args(first, &args[1..]),
        "bun" | "bun.exe" => matches!(first, "test"),
        _ => false,
    }
}

fn allowed_package_manager_args(first: &str, rest: &[String]) -> bool {
    match first {
        "test" | "build" | "lint" | "typecheck" | "check" => true,
        "run" => rest
            .first()
            .is_some_and(|script| allowed_script_name(script)),
        _ => false,
    }
}

fn allowed_npm_args(first: &str, rest: &[String]) -> bool {
    match first {
        "test" => true,
        "run" => rest
            .first()
            .is_some_and(|script| allowed_script_name(script)),
        _ => false,
    }
}

fn allowed_script_name(script: &str) -> bool {
    !script.starts_with('.')
        && script.len() <= 64
        && script
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':' | '.'))
}

async fn run_command(
    repo_path: &Path,
    argv: &[String],
    timeout_secs: u64,
    tool: &str,
    redactor: &Redactor,
) -> CommandRun {
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .current_dir(repo_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_command_for_tree_control(&mut command);
    configure_minimal_environment(&mut command);

    let spawn = command.spawn();
    let mut child = match spawn {
        Ok(child) => child,
        Err(e) => {
            return CommandRun {
                tool: tool.to_string(),
                argv: redact_argv(argv, redactor),
                status: "failed".to_string(),
                exit_code: None,
                output_summary: redactor.redact(&format!("failed to start command: {e}")),
            };
        }
    };
    let child_pid = child.id();

    let stdout_task = child
        .stdout
        .take()
        .map(|stdout| tokio::spawn(read_output(stdout)));
    let stderr_task = child
        .stderr
        .take()
        .map(|stderr| tokio::spawn(read_output(stderr)));

    let wait_result = tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait()).await;
    let mut timed_out = false;
    let exit_status = match wait_result {
        Ok(Ok(status)) => Some(status),
        Ok(Err(e)) => {
            let stdout = collect_output_bounded(stdout_task).await;
            let stderr = collect_output_bounded(stderr_task).await;
            return CommandRun {
                tool: tool.to_string(),
                argv: redact_argv(argv, redactor),
                status: "failed".to_string(),
                exit_code: None,
                output_summary: redactor.redact(&format!(
                    "failed while waiting for command: {e}; {}",
                    summarize_output(&stdout.bytes, &stderr.bytes, redactor)
                )),
            };
        }
        Err(_) => {
            timed_out = true;
            terminate_process_tree(child_pid).await;
            let _ = child.kill().await;
            let _ = tokio::time::timeout(Duration::from_secs(OUTPUT_DRAIN_TIMEOUT_SECS), child.wait())
                .await;
            None
        }
    };

    let stdout = collect_output_bounded(stdout_task).await;
    let stderr = collect_output_bounded(stderr_task).await;

    if timed_out {
        let captured = summarize_output(&stdout.bytes, &stderr.bytes, redactor);
        let drain_note = if stdout.timed_out || stderr.timed_out {
            "; output drain timed out after process-tree termination"
        } else {
            ""
        };
        return CommandRun {
            tool: tool.to_string(),
            argv: redact_argv(argv, redactor),
            status: "failed".to_string(),
            exit_code: None,
            output_summary: format!(
                "timed out after {timeout_secs}s{drain_note}; captured: {captured}"
            ),
        };
    }

    let status = exit_status.expect("non-timeout path must have an exit status");
    let command_status = if status.success() {
        "complete"
    } else {
        "failed"
    };
    let mut output_summary = summarize_output(&stdout.bytes, &stderr.bytes, redactor);
    if stdout.timed_out || stderr.timed_out {
        output_summary.push_str("\n[output drain timed out]");
    }
    CommandRun {
        tool: tool.to_string(),
        argv: redact_argv(argv, redactor),
        status: command_status.to_string(),
        exit_code: status.code(),
        output_summary,
    }
}

#[cfg(unix)]
fn configure_command_for_tree_control(command: &mut Command) {
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_command_for_tree_control(_command: &mut Command) {}

fn configure_minimal_environment(command: &mut Command) {
    command.env_clear();
    for key in minimal_environment_keys() {
        if let Ok(value) = std::env::var(key) {
            command.env(key, value);
        }
    }
    command.env("CI", "true");
    command.env("DELPHI_APPROVED_TOOL_EXECUTION", "1");
}

#[cfg(unix)]
fn minimal_environment_keys() -> &'static [&'static str] {
    &["PATH", "LANG", "LC_ALL"]
}

#[cfg(windows)]
fn minimal_environment_keys() -> &'static [&'static str] {
    &["PATH", "PATHEXT", "SystemRoot", "WINDIR", "TEMP", "TMP"]
}

#[cfg(not(any(unix, windows)))]
fn minimal_environment_keys() -> &'static [&'static str] {
    &["PATH"]
}

async fn terminate_process_tree(child_pid: Option<u32>) {
    let Some(pid) = child_pid else {
        return;
    };
    terminate_process_tree_for_pid(pid).await;
}

#[cfg(unix)]
async fn terminate_process_tree_for_pid(pid: u32) {
    let process_group = format!("-{pid}");
    let _ = Command::new("kill")
        .args(["-TERM", &process_group])
        .status()
        .await;
    sleep(Duration::from_millis(PROCESS_KILL_GRACE_MS)).await;
    let _ = Command::new("kill")
        .args(["-KILL", &process_group])
        .status()
        .await;
}

#[cfg(windows)]
async fn terminate_process_tree_for_pid(pid: u32) {
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .status()
        .await;
}

#[cfg(not(any(unix, windows)))]
async fn terminate_process_tree_for_pid(_pid: u32) {}

async fn read_output<R>(mut reader: R) -> Vec<u8>
where
    R: AsyncRead + Unpin,
{
    let mut captured = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let remaining = MAX_CAPTURE_BYTES.saturating_sub(captured.len());
                if remaining > 0 {
                    captured.extend_from_slice(&buf[..n.min(remaining)]);
                }
            }
            Err(_) => break,
        }
    }
    captured
}

#[derive(Debug, Default)]
struct CapturedOutput {
    bytes: Vec<u8>,
    timed_out: bool,
}

async fn collect_output_bounded(
    handle: Option<tokio::task::JoinHandle<Vec<u8>>>,
) -> CapturedOutput {
    let Some(mut handle) = handle else {
        return CapturedOutput::default();
    };
    tokio::select! {
        result = &mut handle => CapturedOutput {
            bytes: result.unwrap_or_default(),
            timed_out: false,
        },
        _ = sleep(Duration::from_secs(OUTPUT_DRAIN_TIMEOUT_SECS)) => {
            handle.abort();
            CapturedOutput {
                bytes: Vec::new(),
                timed_out: true,
            }
        }
    }
}

fn redact_argv(argv: &[String], redactor: &Redactor) -> Vec<String> {
    argv.iter().map(|arg| redactor.redact(arg)).collect()
}

fn summarize_output(stdout: &[u8], stderr: &[u8], redactor: &Redactor) -> String {
    let mut summary = String::new();
    let out = String::from_utf8_lossy(stdout).replace('\r', "");
    let err = String::from_utf8_lossy(stderr).replace('\r', "");
    if !out.trim().is_empty() {
        summary.push_str(out.trim());
    }
    if !err.trim().is_empty() {
        if !summary.is_empty() {
            summary.push('\n');
        }
        summary.push_str(err.trim());
    }
    if summary.is_empty() {
        summary.push_str("(no output)");
    }
    let scrubbed = scrub_sensitive_output(&summary);
    truncate_chars(redactor.redact(&scrubbed), MAX_OUTPUT_CHARS)
}

fn scrub_sensitive_output(text: &str) -> String {
    text.lines()
        .map(|line| {
            if line_looks_sensitive(line) {
                "[redacted sensitive output line]"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn line_looks_sensitive(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "authorization:",
        "bearer ",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "secret",
        "password",
        "passwd",
        "private key",
        "sk-",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn truncate_chars(mut text: String, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text;
    }
    let byte_index = text
        .char_indices()
        .nth(max_chars)
        .map(|(idx, _)| idx)
        .unwrap_or(text.len());
    text.truncate(byte_index);
    text.push_str("\n[truncated]");
    text
}

fn verify_commands(commands: &[CommandRun], check_was_requested: bool) -> VerificationResult {
    let failed: Vec<&CommandRun> = commands
        .iter()
        .filter(|cmd| cmd.status != "complete")
        .collect();
    if failed.is_empty() {
        let summary = if check_was_requested {
            "repository inspection and approved check command passed"
        } else {
            "repository inspection passed; no check command was requested"
        };
        return VerificationResult {
            status: "passed".to_string(),
            summary: summary.to_string(),
        };
    }

    VerificationResult {
        status: "failed".to_string(),
        summary: format!(
            "{} command(s) failed: {}",
            failed.len(),
            failed
                .iter()
                .map(|cmd| cmd.tool.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn summarize_workflow(commands: &[CommandRun], verification: &VerificationResult) -> String {
    let complete = commands
        .iter()
        .filter(|cmd| cmd.status == "complete")
        .count();
    format!(
        "{} of {} command(s) completed; verification {}",
        complete,
        commands.len(),
        verification.status
    )
}

fn propose_next_step(verification: &VerificationResult, check_was_requested: bool) -> String {
    if verification.status == "failed" {
        "inspect the first failed command summary, fix that failure, then rerun the workflow"
            .to_string()
    } else if check_was_requested {
        "continue with the next scoped change or run the broader verification gate".to_string()
    } else {
        "run the project's normal test command through actions.execute with approval".to_string()
    }
}

fn observe_learning_episode(
    learning: &Arc<Mutex<LearningFacade>>,
    timeline_id: &str,
    status: &str,
    verification: &VerificationResult,
) -> Result<LearningReceipt, ActionApiError> {
    let metadata = serde_json::json!({
        "workflow": DEVELOPER_REPO_CHECK,
        "timeline_id": timeline_id,
        "status": status,
        "verification": verification.status,
    })
    .to_string();
    let event = LearningEvent::with_metadata(
        EventCategory::AiQuery,
        "developer_repo_check repo",
        None,
        &metadata,
    );

    let observed = {
        let mut facade = learning
            .lock()
            .map_err(|_| ActionApiError::LearningUnavailable)?;
        facade.observe(event)
    };

    match observed {
        Ok(_) => Ok(LearningReceipt {
            observed: true,
            episode_kind: DEVELOPER_REPO_CHECK.to_string(),
            candidate: Some(AutomationCandidate {
                id: format!("workflow:{DEVELOPER_REPO_CHECK}"),
                stage: "assisted".to_string(),
                next_stage_on_accept: "practicing".to_string(),
                autonomous: false,
                promotion_requirement: "acceptance plus repeated verified supervised successes"
                    .to_string(),
            }),
            blocked_reason: None,
        }),
        Err(LearningError::ObserverPaused) => Ok(LearningReceipt {
            observed: false,
            episode_kind: DEVELOPER_REPO_CHECK.to_string(),
            candidate: None,
            blocked_reason: Some("focus_mode".to_string()),
        }),
        Err(_) => Ok(LearningReceipt {
            observed: false,
            episode_kind: DEVELOPER_REPO_CHECK.to_string(),
            candidate: None,
            blocked_reason: Some("learning_rejected".to_string()),
        }),
    }
}

fn timeline_summary_json(receipt: &ActionReceipt) -> Result<String, ActionApiError> {
    let failed_tools = receipt
        .commands
        .iter()
        .filter(|cmd| cmd.status != "complete")
        .map(|cmd| cmd.tool.clone())
        .collect();
    let summary = TimelineReceiptSummary {
        workflow: receipt.workflow.clone(),
        status: receipt.status.clone(),
        timeline_id: receipt.timeline_id.clone(),
        project_name: receipt.context.project_name.clone(),
        command_count: receipt.commands.len(),
        failed_tools,
        verification_status: receipt.verification.status.clone(),
        verification_summary: receipt.verification.summary.clone(),
        learning_observed: receipt.learning.observed,
    };
    Ok(serde_json::to_string(&summary)?)
}

fn parse_structured_undo_payload(payload: &str) -> Result<Vec<String>, ActionApiError> {
    let argv: Vec<String> = serde_json::from_str(payload).map_err(|_| {
        ActionApiError::InvalidCommand(
            "undo payload must be a structured JSON argv array".to_string(),
        )
    })?;
    validate_command(&argv)?;
    Ok(argv)
}

fn abort_undo_best_effort(timeline: &Arc<Mutex<Timeline>>, action_id: &str) {
    if let Ok(tl) = timeline.lock() {
        let _ = tl.abort_undo(action_id);
    }
}

#[derive(Debug, Default)]
struct Redactor {
    replacements: Vec<(String, String)>,
    username: Option<String>,
}

impl Redactor {
    fn for_bridge() -> Self {
        let mut redactor = Self::default();
        for root in configured_workspace_roots() {
            redactor.add_path(&root, "$WORKSPACE");
        }
        redactor.add_home();
        redactor.add_username();
        redactor
    }

    fn for_request(request: &ExecuteRequest) -> Self {
        let mut redactor = Self::default();
        redactor.add_path(&request.workspace_root, "$WORKSPACE");
        redactor.add_path(&request.git_root, "$GIT_ROOT");
        redactor.add_path(&request.repo_path, "$REPO");
        redactor.add_home();
        redactor.add_username();
        redactor
    }

    fn for_paths(repo_path: &Path, workspace_root: &Path) -> Self {
        let mut redactor = Self::default();
        redactor.add_path(workspace_root, "$WORKSPACE");
        redactor.add_path(repo_path, "$REPO");
        redactor.add_home();
        redactor.add_username();
        redactor
    }

    fn add_home(&mut self) {
        if let Some(home) = std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from)
            .and_then(canonical_dir)
        {
            self.add_path(&home, "~");
        }
    }

    fn add_username(&mut self) {
        self.username = std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
            .ok()
            .filter(|name| name.len() > 2);
    }

    fn add_path(&mut self, path: &Path, replacement: &str) {
        let raw = path.display().to_string();
        if !raw.is_empty() {
            self.replacements
                .push((raw.clone(), replacement.to_string()));
            let slash = raw.replace('\\', "/");
            if slash != raw {
                self.replacements.push((slash, replacement.to_string()));
            }
        }
        self.replacements
            .sort_by(|left, right| right.0.len().cmp(&left.0.len()));
    }

    fn redact(&self, text: &str) -> String {
        let mut redacted = text.to_string();
        for (needle, replacement) in &self.replacements {
            redacted = redacted.replace(needle, replacement);
        }
        if let Some(username) = &self.username {
            redacted = redacted.replace(username, "$USER");
        }
        redacted
    }
}

fn display_path(path: &Path, workspace_root: &Path) -> String {
    match path.strip_prefix(workspace_root) {
        Ok(relative) if relative.as_os_str().is_empty() => "$WORKSPACE".to_string(),
        Ok(relative) => format!("$WORKSPACE/{}", path_slash(relative)),
        Err(_) => path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("repository")
            .to_string(),
    }
}

fn path_slash(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn request_hash(kind: &ApprovalKind) -> String {
    let value = match kind {
        ApprovalKind::Execute(request) => serde_json::json!({
            "kind": "execute",
            "workflow": request.workflow,
            "repo_path": path_slash(&request.repo_path),
            "check_command": request.check_command,
            "timeout_secs": request.timeout_secs,
        }),
        ApprovalKind::Undo(request) => serde_json::json!({
            "kind": "undo",
            "action_id": request.action_id,
            "timeout_secs": request.timeout_secs,
        }),
    };
    let encoded = serde_json::to_vec(&value).unwrap_or_default();
    let digest = Sha256::digest(encoded);
    hex_encode(&digest)
}

fn approval_scope(kind: &ApprovalKind) -> String {
    match kind {
        ApprovalKind::Execute(request) => format!(
            "{} {} timeout={}s",
            request.workflow, request.display_repo_path, request.timeout_secs
        ),
        ApprovalKind::Undo(request) => {
            format!(
                "{} {} timeout={}s",
                TIMELINE_UNDO, request.action_id, request.timeout_secs
            )
        }
    }
}

fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    hex_encode(&bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn current_epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_requires_approval() {
        let plan = plan(&serde_json::json!({
            "workflow": DEVELOPER_REPO_CHECK,
            "check_command": ["cargo", "test", "--workspace"]
        }))
        .unwrap();
        assert!(plan.requires_approval);
        assert_eq!(plan.risk_tier, "high_risk");
        assert!(plan.approval.is_none());
    }

    #[test]
    fn command_validation_rejects_shell_and_mediators() {
        let shell = validate_command(&["sh".to_string(), "-c".to_string(), "echo no".to_string()])
            .unwrap_err();
        assert!(shell.to_string().contains("developer execution allowlist"));

        let mediator = validate_command(&[
            "python".to_string(),
            "-c".to_string(),
            "print(1)".to_string(),
        ])
        .unwrap_err();
        assert!(mediator
            .to_string()
            .contains("developer execution allowlist"));
    }

    #[test]
    fn approval_token_is_one_shot_and_request_bound() {
        let request = normalize_execute_parts(
            DEVELOPER_REPO_CHECK,
            env!("CARGO_MANIFEST_DIR"),
            Some(vec!["cargo".to_string(), "test".to_string()]),
            Some(30),
        )
        .unwrap();
        let mut registry = ApprovalRegistry::new();
        let capability = registry.issue(ApprovalKind::Execute(request.clone()));
        registry
            .consume_execute(&capability.token, &request)
            .expect("first consume should pass");
        let second = registry.consume_execute(&capability.token, &request);
        assert!(matches!(second, Err(ActionApiError::ApprovalInvalid(_))));
    }
}
