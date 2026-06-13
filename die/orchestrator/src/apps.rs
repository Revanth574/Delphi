// SPDX-License-Identifier: MIT

//! Cross-app orchestration via SSI manifests.
//!
//! The app controller executes multi-step workflows that span multiple
//! applications. It uses SSI manifests to discover what each app can do,
//! resolves dependencies between steps, and executes them — logging every
//! action to the timeline for the 24-hour undo window.
//!
//! # Boundaries (CLAUDE.md Section 4)
//!
//! - SSI execution of app capabilities MUST go through the action timeline
//! - SSI auto-generation MUST NOT execute discovered capabilities without
//!   user consent
//! - Maximum 4 parallel steps (performance budget: <3s per step)
//! - Low-confidence capabilities (<0.7) require explicit user confirmation

use std::collections::HashMap;

use delphi_hardening::canonical_hash::CanonicalHasher;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::OrchestratorError;

/// Maximum number of steps that can execute in parallel.
const MAX_PARALLEL: usize = 4;

/// Minimum confidence for automatic execution (below this, ask user).
const MIN_AUTO_CONFIDENCE: f64 = 0.7;

/// Maximum retry attempts per step.
const MAX_RETRIES: u32 = 3;

/// A workflow step targeting a specific app capability.
///
/// # Examples
///
/// ```
/// use die_orchestrator::apps::WorkflowStep;
///
/// let step = WorkflowStep::new(
///     "open-file",
///     "org.gnome.TextEditor",
///     "file.open",
/// );
/// assert_eq!(step.step_id, "open-file");
/// assert!(step.depends_on.is_empty());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    /// Unique step identifier within the workflow.
    pub step_id: String,
    /// Target application (SSI app_id).
    pub app_id: String,
    /// Capability to invoke on the target app.
    pub capability: String,
    /// Parameters to pass to the capability.
    pub params: HashMap<String, String>,
    /// IDs of steps this step depends on (must complete first).
    pub depends_on: Vec<String>,
    /// Context keys this step produces (available to later steps).
    pub produces: Vec<String>,
    /// SSI-manifest capability confidence in `[0.0, 1.0]`. Below
    /// [`MIN_AUTO_CONFIDENCE`] the step is refused inside
    /// [`AppController::execute_step`] pending explicit user confirmation
    /// (ORCH-R1-05 — the gate is structural at dispatch, not advisory).
    /// Defaults to `1.0` (fully trusted) when absent on the wire.
    #[serde(default = "default_step_confidence")]
    pub confidence: f64,
}

/// Serde default for [`WorkflowStep::confidence`] — fully trusted when a step
/// arrives without the field (forward/backward wire compatibility).
fn default_step_confidence() -> f64 {
    1.0
}

impl WorkflowStep {
    /// Create a new workflow step.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::WorkflowStep;
    ///
    /// let step = WorkflowStep::new("step-1", "org.app", "action.do");
    /// assert!(step.params.is_empty());
    /// ```
    #[must_use]
    pub fn new(step_id: &str, app_id: &str, capability: &str) -> Self {
        Self {
            step_id: step_id.to_string(),
            app_id: app_id.to_string(),
            capability: capability.to_string(),
            params: HashMap::new(),
            depends_on: Vec::new(),
            produces: Vec::new(),
            confidence: 1.0,
        }
    }

    /// Add a parameter to this step.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::WorkflowStep;
    ///
    /// let step = WorkflowStep::new("s1", "org.app", "file.open")
    ///     .with_param("path", "/home/user/doc.pdf");
    /// assert_eq!(step.params["path"], "/home/user/doc.pdf");
    /// ```
    #[must_use]
    pub fn with_param(mut self, key: &str, value: &str) -> Self {
        self.params.insert(key.to_string(), value.to_string());
        self
    }

    /// Declare a dependency on another step.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::WorkflowStep;
    ///
    /// let step = WorkflowStep::new("s2", "org.app", "transform")
    ///     .depends_on("s1");
    /// assert_eq!(step.depends_on, vec!["s1"]);
    /// ```
    #[must_use]
    pub fn depends_on(mut self, step_id: &str) -> Self {
        self.depends_on.push(step_id.to_string());
        self
    }

    /// Declare a context key this step produces.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::WorkflowStep;
    ///
    /// let step = WorkflowStep::new("s1", "org.app", "export")
    ///     .produces_key("output_path");
    /// assert_eq!(step.produces, vec!["output_path"]);
    /// ```
    #[must_use]
    pub fn produces_key(mut self, key: &str) -> Self {
        self.produces.push(key.to_string());
        self
    }

    /// Set the SSI-manifest capability confidence for this step.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::WorkflowStep;
    ///
    /// let step = WorkflowStep::new("s1", "org.app", "risky").with_confidence(0.4).unwrap();
    /// assert!((step.confidence - 0.4).abs() < f64::EPSILON);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError::Validation`] if `confidence` is NaN or
    /// outside `[0.0, 1.0]` (ORCH-R1-05 round-2 depth). A caller passing such a
    /// value has a bug; rejecting surfaces it rather than silently clamping and
    /// hiding it. The `execute_step` gate is independently fail-closed, so this
    /// is defense in depth, not the security boundary — the pub `confidence`
    /// field can still be written directly.
    pub fn with_confidence(self, confidence: f64) -> Result<Self, OrchestratorError> {
        if !(0.0..=1.0).contains(&confidence) {
            // NaN and ±inf both fail the range check (NaN compares false).
            return Err(OrchestratorError::Validation {
                domain: "workflow",
                field: "confidence",
                reason: "must be a finite value in [0.0, 1.0]",
            });
        }
        Ok(Self { confidence, ..self })
    }
}

/// A multi-app workflow definition.
///
/// # Examples
///
/// ```
/// use die_orchestrator::apps::{Workflow, WorkflowStep};
///
/// let wf = Workflow::new("export-report")
///     .with_step(WorkflowStep::new("s1", "org.editor", "file.open"))
///     .with_step(
///         WorkflowStep::new("s2", "org.export", "pdf.create")
///             .depends_on("s1"),
///     );
/// assert_eq!(wf.steps.len(), 2);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    /// Workflow name (human-readable).
    pub name: String,
    /// Ordered list of steps.
    pub steps: Vec<WorkflowStep>,
    /// Unforgeable proof that the user consented to THIS workflow
    /// (ORCH-R1-05). `None` until a [`ConsentToken`] minted by
    /// [`ConsentToken::issue`] for this exact workflow is attached via
    /// [`Workflow::with_consent`]. `#[serde(skip)]` makes consent an
    /// **in-process** capability: it never crosses the wire, so a deserialized
    /// workflow is always unconsented and a token cannot be forged by sending
    /// one (the confirmation *signal* crosses the bus; the capability is minted
    /// locally — mirrors SVC-1 SanitizedPrompt / SVC-8 ValidatedIngestionPath).
    #[serde(skip)]
    pub consent: Option<ConsentToken>,
}

impl Workflow {
    /// Create a new empty workflow.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::Workflow;
    ///
    /// let wf = Workflow::new("my-workflow");
    /// assert!(wf.steps.is_empty());
    /// assert!(wf.consent.is_none());
    /// ```
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            steps: Vec::new(),
            consent: None,
        }
    }

    /// Add a step to the workflow.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::{Workflow, WorkflowStep};
    ///
    /// let wf = Workflow::new("test")
    ///     .with_step(WorkflowStep::new("s1", "org.app", "do"));
    /// assert_eq!(wf.steps.len(), 1);
    /// ```
    #[must_use]
    pub fn with_step(mut self, step: WorkflowStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Attach an unforgeable [`ConsentToken`] proving the user consented to
    /// this workflow (ORCH-R1-05). The token MUST have been minted by
    /// [`ConsentToken::issue`] for this exact workflow after a verified
    /// confirmation; a token bound to a different (or later-mutated) workflow
    /// is rejected at execution by the fingerprint check, so granting consent
    /// then mutating the steps cannot smuggle unconsented actions past the gate.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::{ConsentToken, Workflow, WorkflowStep};
    ///
    /// let wf = Workflow::new("test").with_step(WorkflowStep::new("s1", "org.app", "do"));
    /// let token = ConsentToken::issue(&wf);
    /// let wf = wf.with_consent(token);
    /// assert!(wf.consent.is_some());
    /// ```
    #[must_use]
    pub fn with_consent(mut self, token: ConsentToken) -> Self {
        self.consent = Some(token);
        self
    }

    /// Stable fingerprint of the workflow's identity (name + ordered steps and
    /// their actions), used to bind a [`ConsentToken`] to this exact workflow
    /// (ORCH-R1-05). Canonical and collision-resistant: every field is
    /// LENGTH-PREFIXED and every collection count-prefixed (ORCH-R2-02), so no
    /// two distinct workflows hash alike; map params are in sorted-key order.
    /// Excludes the `consent` field itself (so attaching a token does not change
    /// the hash it is bound to). INCLUDES per-step `confidence`: it is read by
    /// the `execute_step` confidence gate, so it is execution-affecting and must
    /// be bound — otherwise raising a step's confidence after consent would
    /// bypass the gate without invalidating the token (ORCH-R1-05 round-2). The
    /// name, step Vec order, and dependency/produces order are over-included
    /// (a reorder forces a conservative re-consent) — safe, since the binding
    /// must never be LESS sensitive than execution behavior, only more.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        // ORCH-R2-02: canonical LENGTH-PREFIXED, injective encoding via the shared
        // `canonical_hash` primitive (leverage pass P2). Two top-level fields —
        // `name` and the `steps` sequence; `consent` is deliberately excluded (it
        // is the binding TARGET: the token binds to this fingerprint, so it cannot
        // bind to itself). Every variable field is length-prefixed and every
        // collection count-prefixed, so no two distinct workflows share a byte
        // stream (the git `blob <len>\0` lesson — the delimiter join this replaced
        // let ("a\0b","c") collide with ("a","b\0c") and {"a":"b=c"} with
        // {"a=b":"c"}). Per-step `confidence` is execution-affecting (the
        // execute_step gate reads it) so it MUST be bound (ORCH-R1-05 round-2);
        // name + step/dep/produce order are over-included (a reorder forces
        // conservative re-consent) — the binding must never be LESS sensitive than
        // execution behavior, only more.
        let mut h = CanonicalHasher::new(2);
        h.field(self.name.as_bytes()).seq(self.steps.len(), |steps| {
            for step in &self.steps {
                steps
                    .field(step.step_id.as_bytes())
                    .field(step.app_id.as_bytes())
                    .field(step.capability.as_bytes())
                    // Fixed 8 bytes (f64 bit pattern); execution-affecting, bound.
                    .fixed(&step.confidence.to_bits().to_le_bytes());
                let mut keys: Vec<&String> = step.params.keys().collect();
                keys.sort();
                steps.seq(keys.len(), |kv| {
                    for k in keys {
                        kv.field(k.as_bytes()).field(step.params[k].as_bytes());
                    }
                });
                steps.seq(step.depends_on.len(), |dep| {
                    for d in &step.depends_on {
                        dep.field(d.as_bytes());
                    }
                });
                steps.seq(step.produces.len(), |prod| {
                    for p in &step.produces {
                        prod.field(p.as_bytes());
                    }
                });
            }
        });
        // Infallible by construction: exactly two top-level fields are appended,
        // matching the declared count. `expect` is the fail-closed posture.
        h.finish()
            .expect("workflow fingerprint hashes exactly 2 declared fields (name + steps)")
    }
}

/// Unforgeable proof that the user consented to a specific [`Workflow`]
/// (ORCH-R1-05). The only constructor is [`ConsentToken::issue`]; the single
/// private field has no public initializer, and the type intentionally has no
/// `Default`, `Serialize`, or `Deserialize`, so a token cannot be fabricated by
/// a struct literal, defaulted into existence, or forged by deserializing
/// attacker-supplied bytes. It is an **in-process** capability: the verified
/// confirmation (Confirm/Biometric tier) happens at the shell/services
/// boundary, and `issue` is the single local mint point invoked from that path.
/// Possessing a token proves consent was minted through the sanctioned path,
/// and the embedded fingerprint proves it was for THIS workflow — the same
/// shape as SVC-1 `ConfirmationToken` (bound to the sanitized prompt) and
/// SVC-8 `ValidatedIngestionPath`.
///
/// # Forward requirement (discharged by this type)
///
/// When cross-app dispatch is wired to real execution, `issue` MUST be called
/// only after the user confirms the workflow in the UI. The capability is
/// structurally in place now, so the wiring inherits an armed gate rather than
/// a deferred to-do.
///
/// # Forgery is a compile error
///
/// ```compile_fail
/// use die_orchestrator::apps::ConsentToken;
/// // The single field is private and there is no public constructor besides
/// // `issue` (and no Default/Deserialize), so a struct literal cannot compile:
/// let _forged = ConsentToken { workflow_fingerprint: [0u8; 32] };
/// ```
#[derive(Debug, Clone)]
pub struct ConsentToken {
    /// Fingerprint of the workflow this token authorizes. Private — set only
    /// by [`ConsentToken::issue`].
    workflow_fingerprint: [u8; 32],
}

impl ConsentToken {
    /// Mint a consent token bound to `workflow`. THE verified-path mint
    /// (ORCH-R1-05): in production this is called only after the user confirms
    /// the workflow at the shell/services confirmation boundary.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::{ConsentToken, Workflow, WorkflowStep};
    ///
    /// let wf = Workflow::new("t").with_step(WorkflowStep::new("s1", "org.app", "do"));
    /// let token = ConsentToken::issue(&wf);
    /// assert!(token.authorizes(&wf));
    /// ```
    #[must_use]
    pub fn issue(workflow: &Workflow) -> Self {
        Self {
            workflow_fingerprint: workflow.fingerprint(),
        }
    }

    /// Whether this token authorizes `workflow` — true only if `workflow`'s
    /// current fingerprint matches the one captured at [`issue`](Self::issue)
    /// time. A workflow mutated after consent was granted no longer matches.
    #[must_use]
    pub fn authorizes(&self, workflow: &Workflow) -> bool {
        self.workflow_fingerprint == workflow.fingerprint()
    }
}

/// Result of executing a single workflow step.
///
/// # Examples
///
/// ```
/// use die_orchestrator::apps::StepResult;
///
/// let result = StepResult::success("s1", "File opened");
/// assert!(result.succeeded);
/// assert_eq!(result.step_id, "s1");
/// ```
#[derive(Debug, Clone)]
pub struct StepResult {
    /// Which step this result is for.
    pub step_id: String,
    /// Whether execution succeeded.
    pub succeeded: bool,
    /// Human-readable output/description.
    pub output: String,
    /// Context values produced by this step.
    pub context: HashMap<String, String>,
    /// Timeline action ID (for undo).
    pub timeline_id: Option<String>,
    /// How many attempts were needed.
    pub attempts: u32,
}

impl StepResult {
    /// Create a successful step result.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::StepResult;
    ///
    /// let r = StepResult::success("step-1", "Done");
    /// assert!(r.succeeded);
    /// assert_eq!(r.attempts, 1);
    /// ```
    #[must_use]
    pub fn success(step_id: &str, output: &str) -> Self {
        Self {
            step_id: step_id.to_string(),
            succeeded: true,
            output: output.to_string(),
            context: HashMap::new(),
            timeline_id: None,
            attempts: 1,
        }
    }

    /// Create a failed step result.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::StepResult;
    ///
    /// let r = StepResult::failure("step-1", "App not found", 3);
    /// assert!(!r.succeeded);
    /// assert_eq!(r.attempts, 3);
    /// ```
    #[must_use]
    pub fn failure(step_id: &str, reason: &str, attempts: u32) -> Self {
        Self {
            step_id: step_id.to_string(),
            succeeded: false,
            output: reason.to_string(),
            context: HashMap::new(),
            timeline_id: None,
            attempts,
        }
    }

    /// Add a context value to the result.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::StepResult;
    ///
    /// let r = StepResult::success("s1", "exported")
    ///     .with_context("path", "/tmp/out.pdf");
    /// assert_eq!(r.context["path"], "/tmp/out.pdf");
    /// ```
    #[must_use]
    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.context.insert(key.to_string(), value.to_string());
        self
    }
}

/// Result of executing a complete workflow.
///
/// # Examples
///
/// ```
/// use die_orchestrator::apps::{WorkflowResult, StepResult};
///
/// let result = WorkflowResult {
///     workflow_name: "export".to_string(),
///     step_results: vec![StepResult::success("s1", "ok")],
///     completed: true,
///     summary: "All steps succeeded".to_string(),
/// };
/// assert!(result.all_succeeded());
/// ```
#[derive(Debug, Clone)]
pub struct WorkflowResult {
    /// Name of the workflow that was executed.
    pub workflow_name: String,
    /// Results for each step.
    pub step_results: Vec<StepResult>,
    /// Whether all steps completed (even if some failed).
    pub completed: bool,
    /// Human-readable summary.
    pub summary: String,
}

impl WorkflowResult {
    /// Whether all steps succeeded.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::{WorkflowResult, StepResult};
    ///
    /// let result = WorkflowResult {
    ///     workflow_name: "test".to_string(),
    ///     step_results: vec![
    ///         StepResult::success("s1", "ok"),
    ///         StepResult::failure("s2", "failed", 3),
    ///     ],
    ///     completed: true,
    ///     summary: String::new(),
    /// };
    /// assert!(!result.all_succeeded());
    /// ```
    #[must_use]
    pub fn all_succeeded(&self) -> bool {
        self.step_results.iter().all(|r| r.succeeded)
    }

    /// Number of steps that succeeded.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::{WorkflowResult, StepResult};
    ///
    /// let result = WorkflowResult {
    ///     workflow_name: "test".to_string(),
    ///     step_results: vec![
    ///         StepResult::success("s1", "ok"),
    ///         StepResult::success("s2", "ok"),
    ///         StepResult::failure("s3", "err", 1),
    ///     ],
    ///     completed: true,
    ///     summary: String::new(),
    /// };
    /// assert_eq!(result.succeeded_count(), 2);
    /// ```
    #[must_use]
    pub fn succeeded_count(&self) -> usize {
        self.step_results.iter().filter(|r| r.succeeded).count()
    }

    /// Number of steps that failed.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::{WorkflowResult, StepResult};
    ///
    /// let result = WorkflowResult {
    ///     workflow_name: "test".to_string(),
    ///     step_results: vec![StepResult::failure("s1", "err", 2)],
    ///     completed: true,
    ///     summary: String::new(),
    /// };
    /// assert_eq!(result.failed_count(), 1);
    /// ```
    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.step_results.iter().filter(|r| !r.succeeded).count()
    }
}

/// The app controller that executes cross-app workflows.
///
/// # Examples
///
/// ```
/// use die_orchestrator::apps::AppController;
///
/// let controller = AppController::new();
/// assert_eq!(controller.max_parallel(), 4);
/// ```
pub struct AppController {
    /// Maximum parallel execution slots.
    max_parallel: usize,
    /// Maximum retries per step.
    max_retries: u32,
    /// Minimum confidence for auto-execution.
    min_confidence: f64,
}

impl AppController {
    /// Create a new app controller with default settings.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::AppController;
    ///
    /// let ctrl = AppController::new();
    /// assert_eq!(ctrl.max_parallel(), 4);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_parallel: MAX_PARALLEL,
            max_retries: MAX_RETRIES,
            min_confidence: MIN_AUTO_CONFIDENCE,
        }
    }

    /// Maximum parallel execution slots.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::AppController;
    /// assert_eq!(AppController::new().max_parallel(), 4);
    /// ```
    #[must_use]
    pub fn max_parallel(&self) -> usize {
        self.max_parallel
    }

    /// Maximum retries per step.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::AppController;
    /// assert_eq!(AppController::new().max_retries(), 3);
    /// ```
    #[must_use]
    pub fn max_retries(&self) -> u32 {
        self.max_retries
    }

    /// Minimum confidence for automatic execution.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::AppController;
    /// assert!((AppController::new().min_confidence() - 0.7).abs() < 0.001);
    /// ```
    #[must_use]
    pub fn min_confidence(&self) -> f64 {
        self.min_confidence
    }

    /// Validate a workflow before execution.
    ///
    /// Checks:
    /// 1. Workflow has user consent
    /// 2. No duplicate step IDs
    /// 3. All dependencies reference existing steps
    /// 4. No circular dependencies
    /// 5. Parallelism does not exceed max_parallel
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if validation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::{AppController, ConsentToken, Workflow, WorkflowStep};
    ///
    /// let ctrl = AppController::new();
    /// let wf = Workflow::new("test")
    ///     .with_step(WorkflowStep::new("s1", "org.app", "do"));
    /// let token = ConsentToken::issue(&wf);
    /// let wf = wf.with_consent(token);
    /// assert!(ctrl.validate(&wf).is_ok());
    /// ```
    pub fn validate(&self, workflow: &Workflow) -> Result<(), OrchestratorError> {
        // ORCH-R1-05: must carry a consent capability (presence check). The
        // workflow-BINDING (token bound to THIS workflow's fingerprint) is
        // enforced at the execution door in `execute` — the door that performs
        // the action — so a validate->mutate->execute substitution cannot slip
        // a different workflow past consent granted for the original.
        if workflow.consent.is_none() {
            return Err(OrchestratorError::Conflict {
                domain: "workflow",
                reason: "workflow requires user consent before execution",
            });
        }

        if workflow.steps.is_empty() {
            return Err(OrchestratorError::Planning(
                "workflow has no steps".to_string(),
            ));
        }

        // Check for duplicate step IDs.
        let mut seen_ids: HashMap<&str, bool> = HashMap::new();
        for step in &workflow.steps {
            if seen_ids.contains_key(step.step_id.as_str()) {
                return Err(OrchestratorError::Planning(format!(
                    "duplicate step ID: {}",
                    step.step_id,
                )));
            }
            seen_ids.insert(&step.step_id, true);
        }

        // Check all dependencies reference existing steps.
        for step in &workflow.steps {
            for dep in &step.depends_on {
                if !seen_ids.contains_key(dep.as_str()) {
                    return Err(OrchestratorError::Planning(format!(
                        "step '{}' depends on non-existent step '{dep}'",
                        step.step_id,
                    )));
                }
            }
        }

        // Check for circular dependencies via topological sort.
        if has_cycle(&workflow.steps) {
            return Err(OrchestratorError::Planning(
                "workflow has circular dependencies".to_string(),
            ));
        }

        // Check that parallelism at any level does not exceed max.
        let levels = compute_execution_levels(&workflow.steps);
        for level in &levels {
            if level.len() > self.max_parallel {
                return Err(OrchestratorError::Planning(format!(
                    "execution level has {} parallel steps (max {})",
                    level.len(),
                    self.max_parallel,
                )));
            }
        }

        info!(
            workflow = %workflow.name,
            steps = workflow.steps.len(),
            levels = levels.len(),
            "workflow validated"
        );

        Ok(())
    }

    /// Resolve the execution order for a workflow.
    ///
    /// Groups steps into execution levels where all steps in a level
    /// can run in parallel (their dependencies are in prior levels).
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if the workflow is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::{AppController, ConsentToken, Workflow, WorkflowStep};
    ///
    /// let ctrl = AppController::new();
    /// let wf = Workflow::new("test")
    ///     .with_step(WorkflowStep::new("s1", "org.a", "open"))
    ///     .with_step(WorkflowStep::new("s2", "org.b", "open"))
    ///     .with_step(
    ///         WorkflowStep::new("s3", "org.c", "merge")
    ///             .depends_on("s1")
    ///             .depends_on("s2"),
    ///     );
    /// let token = ConsentToken::issue(&wf);
    /// let wf = wf.with_consent(token);
    ///
    /// let levels = ctrl.resolve_order(&wf).unwrap();
    /// // Level 0: s1, s2 (parallel); Level 1: s3
    /// assert_eq!(levels.len(), 2);
    /// assert_eq!(levels[0].len(), 2);
    /// assert_eq!(levels[1].len(), 1);
    /// ```
    pub fn resolve_order(
        &self,
        workflow: &Workflow,
    ) -> Result<Vec<Vec<String>>, OrchestratorError> {
        self.validate(workflow)?;
        Ok(compute_execution_levels(&workflow.steps))
    }

    /// Check if a capability confidence requires user confirmation.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::AppController;
    ///
    /// let ctrl = AppController::new();
    /// assert!(!ctrl.needs_confirmation(0.9));
    /// assert!(ctrl.needs_confirmation(0.5));
    /// assert!(!ctrl.needs_confirmation(0.7));
    /// ```
    #[must_use]
    pub fn needs_confirmation(&self, confidence: f64) -> bool {
        // ORCH-R1-05 round-2 / ORCH-R2-01: FAIL-CLOSED over the whole invalid
        // CLASS. Auto-execution requires a finite confidence in [min, 1.0];
        // confirmation is required for ANYTHING else — NaN, ±inf, and
        // out-of-range (e.g. 2.0). The old `confidence < min` let NaN AND
        // +inf/>1.0 through (those comparisons are false), a fail-OPEN; gating
        // the whole class (not just the NaN that surfaced) is the airtight
        // boundary.
        !(confidence.is_finite() && (self.min_confidence..=1.0).contains(&confidence))
    }

    /// Execute a validated workflow step (simulated — real execution
    /// requires D-Bus connection to the target app).
    ///
    /// In production, this would:
    /// 1. Look up the app's SSI manifest
    /// 2. Find the capability
    /// 3. Check confidence (ask user if low)
    /// 4. Execute via D-Bus / AT-SPI
    /// 5. Log to action timeline
    /// 6. Return result with context
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if execution fails after
    /// all retry attempts.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::{AppController, WorkflowStep};
    /// use std::collections::HashMap;
    ///
    /// let ctrl = AppController::new();
    /// let step = WorkflowStep::new("s1", "org.app", "file.open")
    ///     .with_param("path", "/tmp/test.txt");
    /// let result = ctrl.execute_step(&step, &HashMap::new());
    /// assert!(result.is_ok());
    /// ```
    pub fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, String>,
    ) -> Result<StepResult, OrchestratorError> {
        info!(
            step_id = %step.step_id,
            app = %step.app_id,
            capability = %step.capability,
            "executing workflow step"
        );

        // ORCH-R1-05: the confidence gate is STRUCTURAL at dispatch — a
        // low-confidence capability is refused HERE, not merely flagged by the
        // advisory needs_confirmation() a caller might skip (the SVC-5
        // unarmed-gate lesson). Confirmation/escalation is the caller's job
        // before retrying; execute_step never silently runs a low-confidence step.
        if self.needs_confirmation(step.confidence) {
            tracing::debug!(
                step_id = %step.step_id,
                confidence = step.confidence,
                threshold = self.min_confidence,
                "step below auto-confidence threshold; refused pending confirmation"
            );
            return Err(OrchestratorError::Conflict {
                domain: "workflow",
                reason: "step confidence below auto-execution threshold; requires confirmation",
            });
        }

        // Resolve parameter references from context.
        let resolved_params = resolve_params(&step.params, context);

        debug!(
            step_id = %step.step_id,
            params = ?resolved_params,
            "resolved parameters"
        );

        // Simulated execution — in production this calls D-Bus.
        let output = format!(
            "Executed {}.{} on {}",
            step.app_id, step.capability, step.step_id,
        );

        let mut result = StepResult::success(&step.step_id, &output);

        // Populate produced context keys.
        for key in &step.produces {
            result.context.insert(
                key.clone(),
                format!("{{result_of_{}}}", step.step_id),
            );
        }

        Ok(result)
    }

    /// Execute a complete workflow.
    ///
    /// Processes execution levels sequentially — within each level,
    /// steps are logically parallel (executed in order here since
    /// actual D-Bus calls are not available yet).
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if the workflow is invalid.
    /// Individual step failures do NOT abort the entire workflow — they
    /// are recorded in the result.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::apps::{AppController, ConsentToken, Workflow, WorkflowStep};
    ///
    /// let ctrl = AppController::new();
    /// let wf = Workflow::new("simple")
    ///     .with_step(WorkflowStep::new("s1", "org.app", "do"));
    /// let token = ConsentToken::issue(&wf);
    /// let wf = wf.with_consent(token);
    ///
    /// let result = ctrl.execute(&wf).unwrap();
    /// assert!(result.all_succeeded());
    /// ```
    pub fn execute(&self, workflow: &Workflow) -> Result<WorkflowResult, OrchestratorError> {
        let levels = self.resolve_order(workflow)?;
        // ORCH-R1-05: re-verify the consent binding AT THE EXECUTION DOOR —
        // against the workflow actually being executed, not only in validate().
        // This closes the validate->mutate->execute substitution: a token minted
        // for an earlier workflow shape does not authorize a mutated one. The
        // door that performs the action is where the check must fire (same
        // principle as SVC-1-R1-1-01's live-path closure).
        match &workflow.consent {
            Some(token) if token.authorizes(workflow) => {}
            _ => {
                return Err(OrchestratorError::Conflict {
                    domain: "workflow",
                    reason: "consent does not authorize this workflow",
                });
            }
        }
        let mut all_results: Vec<StepResult> = Vec::new();
        let mut context: HashMap<String, String> = HashMap::new();

        info!(
            workflow = %workflow.name,
            levels = levels.len(),
            "starting workflow execution"
        );

        // Build a lookup from step_id to step.
        let step_map: HashMap<&str, &WorkflowStep> = workflow
            .steps
            .iter()
            .map(|s| (s.step_id.as_str(), s))
            .collect();

        for (level_idx, level) in levels.iter().enumerate() {
            info!(
                level = level_idx,
                steps = level.len(),
                "executing level"
            );

            for step_id in level {
                let step = step_map.get(step_id.as_str()).ok_or_else(|| {
                    OrchestratorError::Planning(format!(
                        "internal error: step '{step_id}' not found in map"
                    ))
                })?;

                // Check if all dependencies succeeded.
                let deps_ok = step.depends_on.iter().all(|dep_id| {
                    all_results
                        .iter()
                        .any(|r| r.step_id == *dep_id && r.succeeded)
                });

                if !deps_ok {
                    warn!(
                        step_id,
                        "skipping step — dependency failed"
                    );
                    all_results.push(StepResult::failure(
                        step_id,
                        "skipped: dependency failed",
                        0,
                    ));
                    continue;
                }

                match self.execute_step(step, &context) {
                    Ok(result) => {
                        // Merge produced context.
                        for (k, v) in &result.context {
                            context.insert(k.clone(), v.clone());
                        }
                        all_results.push(result);
                    }
                    Err(e) => {
                        warn!(
                            step_id,
                            error = %e,
                            "step execution failed"
                        );
                        all_results.push(StepResult::failure(
                            step_id,
                            &e.to_string(),
                            self.max_retries,
                        ));
                    }
                }
            }
        }

        let succeeded = all_results.iter().filter(|r| r.succeeded).count();
        let total = all_results.len();
        let summary = format!(
            "{succeeded}/{total} steps succeeded in workflow '{}'",
            workflow.name,
        );

        info!(summary = %summary, "workflow complete");

        Ok(WorkflowResult {
            workflow_name: workflow.name.clone(),
            step_results: all_results,
            completed: true,
            summary,
        })
    }
}

impl Default for AppController {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve parameter values, substituting `${key}` references from context.
///
/// # Examples
///
/// ```
/// use die_orchestrator::apps::resolve_params;
/// use std::collections::HashMap;
///
/// let mut params = HashMap::new();
/// params.insert("input".to_string(), "${prev_output}".to_string());
/// params.insert("format".to_string(), "pdf".to_string());
///
/// let mut ctx = HashMap::new();
/// ctx.insert("prev_output".to_string(), "/tmp/data.csv".to_string());
///
/// let resolved = resolve_params(&params, &ctx);
/// assert_eq!(resolved["input"], "/tmp/data.csv");
/// assert_eq!(resolved["format"], "pdf");
/// ```
#[must_use]
pub fn resolve_params(
    params: &HashMap<String, String>,
    context: &HashMap<String, String>,
) -> HashMap<String, String> {
    params
        .iter()
        .map(|(k, v)| {
            let resolved = if let Some(key) = v.strip_prefix("${").and_then(|s| s.strip_suffix('}'))
            {
                context.get(key).cloned().unwrap_or_else(|| v.clone())
            } else {
                v.clone()
            };
            (k.clone(), resolved)
        })
        .collect()
}

/// Detect circular dependencies in a set of workflow steps.
///
/// Uses Kahn's algorithm for topological sort — if we can't process
/// all nodes, there's a cycle.
///
/// # Examples
///
/// ```
/// use die_orchestrator::apps::{has_cycle, WorkflowStep};
///
/// let steps = vec![
///     WorkflowStep::new("a", "org.x", "do"),
///     WorkflowStep::new("b", "org.y", "do").depends_on("a"),
/// ];
/// assert!(!has_cycle(&steps));
/// ```
#[must_use]
pub fn has_cycle(steps: &[WorkflowStep]) -> bool {
    let mut in_degree: HashMap<&str, usize> = HashMap::new();
    let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();

    // Initialize.
    for step in steps {
        in_degree.entry(&step.step_id).or_insert(0);
        adjacency.entry(&step.step_id).or_default();
    }

    // Build the graph.
    for step in steps {
        for dep in &step.depends_on {
            adjacency.entry(dep.as_str()).or_default().push(&step.step_id);
            *in_degree.entry(&step.step_id).or_insert(0) += 1;
        }
    }

    // Kahn's algorithm.
    let mut queue: Vec<&str> = in_degree
        .iter()
        .filter(|(_, deg)| **deg == 0)
        .map(|(&id, _)| id)
        .collect();

    let mut processed = 0;

    while let Some(node) = queue.pop() {
        processed += 1;
        if let Some(neighbors) = adjacency.get(node) {
            for &neighbor in neighbors {
                if let Some(deg) = in_degree.get_mut(neighbor) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push(neighbor);
                    }
                }
            }
        }
    }

    processed != steps.len()
}

/// Compute execution levels (topological layers) for parallel execution.
///
/// Each level contains steps whose dependencies are all in prior levels.
///
/// # Examples
///
/// ```
/// use die_orchestrator::apps::{compute_execution_levels, WorkflowStep};
///
/// let steps = vec![
///     WorkflowStep::new("a", "org.x", "do"),
///     WorkflowStep::new("b", "org.y", "do"),
///     WorkflowStep::new("c", "org.z", "merge")
///         .depends_on("a")
///         .depends_on("b"),
/// ];
///
/// let levels = compute_execution_levels(&steps);
/// assert_eq!(levels.len(), 2);
/// // a and b in level 0, c in level 1
/// assert!(levels[0].contains(&"a".to_string()));
/// assert!(levels[0].contains(&"b".to_string()));
/// assert_eq!(levels[1], vec!["c".to_string()]);
/// ```
#[must_use]
pub fn compute_execution_levels(steps: &[WorkflowStep]) -> Vec<Vec<String>> {
    if steps.is_empty() {
        return Vec::new();
    }

    let mut in_degree: HashMap<&str, usize> = HashMap::new();
    let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();

    for step in steps {
        in_degree.entry(&step.step_id).or_insert(0);
        adjacency.entry(&step.step_id).or_default();
    }

    for step in steps {
        for dep in &step.depends_on {
            adjacency.entry(dep.as_str()).or_default().push(&step.step_id);
            *in_degree.entry(&step.step_id).or_insert(0) += 1;
        }
    }

    let mut levels: Vec<Vec<String>> = Vec::new();
    let mut current_level: Vec<&str> = in_degree
        .iter()
        .filter(|(_, deg)| **deg == 0)
        .map(|(&id, _)| id)
        .collect();

    current_level.sort(); // Deterministic ordering.

    while !current_level.is_empty() {
        levels.push(current_level.iter().map(|s| s.to_string()).collect());

        let mut next_level: Vec<&str> = Vec::new();
        for &node in &current_level {
            if let Some(neighbors) = adjacency.get(node) {
                for &neighbor in neighbors {
                    if let Some(deg) = in_degree.get_mut(neighbor) {
                        *deg -= 1;
                        if *deg == 0 {
                            next_level.push(neighbor);
                        }
                    }
                }
            }
        }
        next_level.sort(); // Deterministic ordering.
        current_level = next_level;
    }

    levels
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper: mint a consent token bound to `wf` and attach it
    /// (ORCH-R1-05). Simulates the in-process post-confirmation mint —
    /// production calls `ConsentToken::issue` AFTER the verified UI confirmation.
    fn consented(wf: Workflow) -> Workflow {
        let token = ConsentToken::issue(&wf);
        wf.with_consent(token)
    }

    // ── ORCH-R1-05: consent capability + structural confidence gate ──
    #[test]
    fn execute_step_refuses_low_confidence_orch_r1_05() {
        let ctrl = AppController::new();
        let step = WorkflowStep::new("s1", "org.app", "risky")
            .with_confidence(0.4)
            .unwrap();
        let err = ctrl.execute_step(&step, &HashMap::new()).unwrap_err();
        assert!(
            matches!(err, OrchestratorError::Conflict { domain: "workflow", .. }),
            "low-confidence step must be refused inside execute_step, got {err:?}"
        );
    }

    #[test]
    fn execute_step_allows_high_confidence_orch_r1_05() {
        let ctrl = AppController::new();
        let step = WorkflowStep::new("s1", "org.app", "safe")
            .with_confidence(0.95)
            .unwrap();
        assert!(ctrl.execute_step(&step, &HashMap::new()).is_ok());
    }

    #[test]
    fn execute_step_gates_nan_confidence_orch_r1_05() {
        // ORCH-R1-05 round-2 (gate fail-closed): a NaN confidence must be GATED,
        // not executed. RED pre-fix: `NaN < 0.7` is false, so the `<` gate let it
        // through — a fail-OPEN. confidence is set via the direct pub field
        // because with_confidence now rejects NaN.
        let ctrl = AppController::new();
        let mut step = WorkflowStep::new("s1", "org.app", "do");
        step.confidence = f64::NAN;
        let err = ctrl.execute_step(&step, &HashMap::new()).unwrap_err();
        assert!(
            matches!(err, OrchestratorError::Conflict { domain: "workflow", .. }),
            "a NaN-confidence step must be gated (fail-closed), got {err:?}"
        );
    }

    #[test]
    fn gate_rejects_non_finite_and_out_of_range_confidence_orch_r2_01() {
        // ORCH-R2-01: the gate must reject the whole INVALID CLASS (non-finite
        // OR outside [min, 1.0]), not just the NaN value that surfaced. RED
        // pre-fix: +inf and 2.0 passed (inf<0.7 and 2.0<0.7 are false, neither is
        // NaN). confidence is set via the direct field — the with_confidence /
        // serde bypass path the gate must catch as the airtight boundary.
        let ctrl = AppController::new();
        for bad in [f64::INFINITY, f64::NEG_INFINITY, 2.0_f64, -0.1_f64, f64::NAN] {
            let mut step = WorkflowStep::new("s", "app", "do");
            step.confidence = bad;
            let err = ctrl.execute_step(&step, &HashMap::new()).unwrap_err();
            assert!(
                matches!(err, OrchestratorError::Conflict { domain: "workflow", .. }),
                "invalid confidence {bad} must be gated, got {err:?}"
            );
        }
        // A valid high confidence still auto-executes.
        let mut ok = WorkflowStep::new("s", "app", "do");
        ok.confidence = 0.95;
        assert!(ctrl.execute_step(&ok, &HashMap::new()).is_ok());
    }

    #[test]
    fn with_confidence_rejects_nan_and_out_of_range_orch_r1_05() {
        // Defense in depth: with_confidence REJECTS (does not silently clamp)
        // NaN / non-finite / out-of-[0,1], surfacing a caller's bug at
        // construction rather than hiding it as a plausible value.
        let base = || WorkflowStep::new("s1", "org.app", "do");
        assert!(base().with_confidence(f64::NAN).is_err());
        assert!(base().with_confidence(f64::INFINITY).is_err());
        assert!(base().with_confidence(2.0).is_err());
        assert!(base().with_confidence(-0.1).is_err());
        assert!(base().with_confidence(0.0).is_ok());
        assert!(base().with_confidence(1.0).is_ok());
        assert!(base().with_confidence(0.5).is_ok());
    }

    #[test]
    fn consent_token_does_not_authorize_mutated_workflow_orch_r1_05() {
        let wf = Workflow::new("t").with_step(WorkflowStep::new("s1", "org.app", "do"));
        let token = ConsentToken::issue(&wf);
        let mutated = wf
            .with_consent(token)
            .with_step(WorkflowStep::new("s2", "org.evil", "exfiltrate"));
        assert!(
            !mutated.consent.as_ref().unwrap().authorizes(&mutated),
            "a token issued for the pre-mutation workflow must not authorize the mutated one"
        );
    }

    #[test]
    fn fingerprint_no_collision_on_delimiter_shifted_fields_orch_r2_02() {
        // ORCH-R2-02: delimiter joining made ("a\0b","c") and ("a","b\0c") hash
        // identically (both -> a\0b\0c). Length-prefixing distinguishes them, so
        // a token for one cannot authorize the behaviorally-different other.
        // RED pre-fix: the fingerprints collide and the token authorizes.
        let wf1 = Workflow::new("w").with_step(WorkflowStep::new("a\0b", "c", "cap"));
        let wf2 = Workflow::new("w").with_step(WorkflowStep::new("a", "b\0c", "cap"));
        assert_ne!(
            wf1.fingerprint(),
            wf2.fingerprint(),
            "delimiter-shifted step_id/app_id must not collide"
        );
        let token = ConsentToken::issue(&wf1);
        assert!(
            !token.authorizes(&wf2),
            "consent for wf1 must not authorize the colliding wf2"
        );
    }

    #[test]
    fn fingerprint_no_collision_on_param_delimiter_orch_r2_02() {
        // ORCH-R2-02: {"a":"b=c"} and {"a=b":"c"} both joined to a=b=c\0 under
        // delimiter hashing. Length-prefixing distinguishes them.
        let wf1 = Workflow::new("w")
            .with_step(WorkflowStep::new("s", "app", "cap").with_param("a", "b=c"));
        let wf2 = Workflow::new("w")
            .with_step(WorkflowStep::new("s", "app", "cap").with_param("a=b", "c"));
        assert_ne!(
            wf1.fingerprint(),
            wf2.fingerprint(),
            "param key/value delimiter collision must not occur"
        );
        let token = ConsentToken::issue(&wf1);
        assert!(
            !token.authorizes(&wf2),
            "consent for one param map must not authorize the colliding other"
        );
    }

    /// canonical_hash extraction (leverage pass P2, site 2 — the `seq()`
    /// exerciser): byte-identical proof + struct-grew tripwires at BOTH levels.
    ///
    /// The no-`..` destructures of `Workflow` AND `WorkflowStep` fail to COMPILE
    /// when either struct grows, forcing the "must this new field be in the
    /// fingerprint?" decision at field-add time. `consent` is deliberately NOT
    /// fingerprinted — it is the binding TARGET (the token binds to the
    /// fingerprint, so it cannot bind to itself); the destructure binds it
    /// explicitly so a future field cannot hide behind a `..`.
    ///
    /// `GOLDEN` is `wf.fingerprint()` captured from the pre-extraction
    /// implementation; the `CanonicalHasher`/`seq`-based fingerprint must
    /// reproduce it exactly — the byte-identical proof for the nested shape.
    #[test]
    fn fingerprint_is_exhaustive_and_byte_identical_canonical_hash() {
        let mut s1 = WorkflowStep::new("s1", "org.app", "file.open")
            .with_param("path", "/doc")
            .with_param("mode", "ro");
        s1.produces.push("handle".to_string());
        let s2 = WorkflowStep::new("s2", "org.export", "pdf.make").depends_on("s1");
        let wf = Workflow::new("wf-golden").with_step(s1).with_step(s2);

        // Top-level struct-grew tripwire — NO `..`.
        let Workflow {
            name,
            steps,
            consent,
        } = &wf;
        let _ = (name, steps, consent); // consent: deliberately NOT fingerprinted (binding target)

        // Per-step struct-grew tripwire — NO `..`.
        for step in &wf.steps {
            let WorkflowStep {
                step_id,
                app_id,
                capability,
                params,
                depends_on,
                produces,
                confidence,
            } = step;
            let _ = (step_id, app_id, capability, params, depends_on, produces, confidence);
        }

        // Pinned from the pre-extraction `fp_field`-based fingerprint.
        const GOLDEN: [u8; 32] = [
            25, 224, 140, 3, 20, 12, 23, 107, 59, 16, 35, 105, 240, 247, 138, 218, 130, 143, 110,
            52, 248, 89, 133, 175, 108, 234, 28, 36, 166, 56, 253, 131,
        ];
        assert_eq!(
            wf.fingerprint(),
            GOLDEN,
            "workflow fingerprint must be byte-identical across the canonical_hash extraction"
        );
    }

    #[test]
    fn execute_rejects_consent_for_mutated_workflow_at_the_door_orch_r1_05() {
        // Binding enforced AT THE EXECUTION DOOR, not only validate: issue for
        // X, mutate to Y, execute(Y) -> rejected.
        let ctrl = AppController::new();
        let wf = Workflow::new("t").with_step(WorkflowStep::new("s1", "org.app", "do"));
        let token = ConsentToken::issue(&wf);
        let mutated = wf
            .with_consent(token)
            .with_step(WorkflowStep::new("s2", "org.evil", "exfiltrate"));
        let err = ctrl.execute(&mutated).unwrap_err();
        assert!(
            matches!(err, OrchestratorError::Conflict { domain: "workflow", .. }),
            "execute must reject consent bound to a different (pre-mutation) workflow, got {err:?}"
        );
    }

    #[test]
    fn execute_rejects_confidence_raised_after_consent_orch_r1_05() {
        // ORCH-R1-05 round-2 (fingerprint behavioral coverage): per-step
        // confidence is execution-affecting (the execute_step gate reads it), so
        // RAISING it after consent must invalidate the binding. RED pre-fix:
        // confidence was excluded from the fingerprint, so the mutated workflow
        // hashed identically, the execution door passed, and the now-high-
        // confidence step executed.
        let ctrl = AppController::new();
        let wf = Workflow::new("t").with_step(
            WorkflowStep::new("s1", "org.app", "do")
                .with_confidence(0.5)
                .unwrap(),
        );
        let token = ConsentToken::issue(&wf);
        let mut consented_wf = wf.with_consent(token);
        // Raise the step's confidence AFTER consent was minted.
        consented_wf.steps[0].confidence = 0.95;
        let err = ctrl.execute(&consented_wf).unwrap_err();
        assert!(
            matches!(err, OrchestratorError::Conflict { domain: "workflow", .. }),
            "raising a step's confidence post-consent must invalidate the token, got {err:?}"
        );
    }

    #[test]
    fn workflow_step_creation() {
        let step = WorkflowStep::new("s1", "org.app", "file.open");
        assert_eq!(step.step_id, "s1");
        assert_eq!(step.app_id, "org.app");
        assert_eq!(step.capability, "file.open");
        assert!(step.params.is_empty());
        assert!(step.depends_on.is_empty());
        assert!(step.produces.is_empty());
    }

    #[test]
    fn workflow_step_with_params() {
        let step = WorkflowStep::new("s1", "org.app", "file.open")
            .with_param("path", "/home/user/doc.txt")
            .with_param("mode", "read");
        assert_eq!(step.params.len(), 2);
        assert_eq!(step.params["path"], "/home/user/doc.txt");
    }

    #[test]
    fn workflow_step_dependencies() {
        let step = WorkflowStep::new("s3", "org.c", "merge")
            .depends_on("s1")
            .depends_on("s2");
        assert_eq!(step.depends_on.len(), 2);
    }

    #[test]
    fn workflow_step_produces() {
        let step = WorkflowStep::new("s1", "org.app", "export")
            .produces_key("output_path")
            .produces_key("file_size");
        assert_eq!(step.produces.len(), 2);
    }

    #[test]
    fn workflow_creation_and_consent() {
        let wf = Workflow::new("test-workflow");
        assert!(wf.consent.is_none());
        assert!(wf.steps.is_empty());

        let wf = consented(wf);
        assert!(wf.consent.is_some());
    }

    #[test]
    fn step_result_success() {
        let r = StepResult::success("s1", "done");
        assert!(r.succeeded);
        assert_eq!(r.attempts, 1);
        assert!(r.timeline_id.is_none());
    }

    #[test]
    fn step_result_failure() {
        let r = StepResult::failure("s1", "timeout", 3);
        assert!(!r.succeeded);
        assert_eq!(r.attempts, 3);
    }

    #[test]
    fn step_result_context() {
        let r = StepResult::success("s1", "ok")
            .with_context("path", "/tmp/out.pdf");
        assert_eq!(r.context["path"], "/tmp/out.pdf");
    }

    #[test]
    fn workflow_result_all_succeeded() {
        let result = WorkflowResult {
            workflow_name: "test".to_string(),
            step_results: vec![
                StepResult::success("s1", "ok"),
                StepResult::success("s2", "ok"),
            ],
            completed: true,
            summary: String::new(),
        };
        assert!(result.all_succeeded());
        assert_eq!(result.succeeded_count(), 2);
        assert_eq!(result.failed_count(), 0);
    }

    #[test]
    fn workflow_result_partial_failure() {
        let result = WorkflowResult {
            workflow_name: "test".to_string(),
            step_results: vec![
                StepResult::success("s1", "ok"),
                StepResult::failure("s2", "failed", 3),
            ],
            completed: true,
            summary: String::new(),
        };
        assert!(!result.all_succeeded());
        assert_eq!(result.succeeded_count(), 1);
        assert_eq!(result.failed_count(), 1);
    }

    #[test]
    fn controller_defaults() {
        let ctrl = AppController::new();
        assert_eq!(ctrl.max_parallel(), 4);
        assert_eq!(ctrl.max_retries(), 3);
        assert!((ctrl.min_confidence() - 0.7).abs() < 0.001);
    }

    #[test]
    fn controller_default_trait() {
        let ctrl = AppController::default();
        assert_eq!(ctrl.max_parallel(), 4);
    }

    #[test]
    fn confidence_confirmation() {
        let ctrl = AppController::new();
        assert!(!ctrl.needs_confirmation(0.9));
        assert!(!ctrl.needs_confirmation(0.7));
        assert!(ctrl.needs_confirmation(0.69));
        assert!(ctrl.needs_confirmation(0.3));
    }

    #[test]
    fn validate_requires_consent() {
        let ctrl = AppController::new();
        let wf = Workflow::new("test")
            .with_step(WorkflowStep::new("s1", "org.app", "do"));
        assert!(ctrl.validate(&wf).is_err());
    }

    #[test]
    fn validate_rejects_empty_workflow() {
        let ctrl = AppController::new();
        let wf = consented(Workflow::new("empty"));
        assert!(ctrl.validate(&wf).is_err());
    }

    #[test]
    fn validate_rejects_duplicate_ids() {
        let ctrl = AppController::new();
        let wf = consented(
            Workflow::new("test")
                .with_step(WorkflowStep::new("s1", "org.a", "do"))
                .with_step(WorkflowStep::new("s1", "org.b", "do")),
        );
        let err = ctrl.validate(&wf).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn validate_rejects_missing_dependency() {
        let ctrl = AppController::new();
        let wf = consented(
            Workflow::new("test")
                .with_step(WorkflowStep::new("s1", "org.a", "do").depends_on("nonexistent")),
        );
        let err = ctrl.validate(&wf).unwrap_err();
        assert!(err.to_string().contains("non-existent"));
    }

    #[test]
    fn validate_accepts_valid_workflow() {
        let ctrl = AppController::new();
        let wf = consented(
            Workflow::new("test")
                .with_step(WorkflowStep::new("s1", "org.a", "open"))
                .with_step(WorkflowStep::new("s2", "org.b", "process").depends_on("s1")),
        );
        assert!(ctrl.validate(&wf).is_ok());
    }

    #[test]
    fn has_cycle_linear_chain() {
        let steps = vec![
            WorkflowStep::new("a", "org.x", "do"),
            WorkflowStep::new("b", "org.y", "do").depends_on("a"),
            WorkflowStep::new("c", "org.z", "do").depends_on("b"),
        ];
        assert!(!has_cycle(&steps));
    }

    #[test]
    fn has_cycle_detects_simple_cycle() {
        let mut step_a = WorkflowStep::new("a", "org.x", "do");
        step_a.depends_on = vec!["b".to_string()];
        let mut step_b = WorkflowStep::new("b", "org.y", "do");
        step_b.depends_on = vec!["a".to_string()];
        assert!(has_cycle(&[step_a, step_b]));
    }

    #[test]
    fn has_cycle_independent_steps() {
        let steps = vec![
            WorkflowStep::new("a", "org.x", "do"),
            WorkflowStep::new("b", "org.y", "do"),
            WorkflowStep::new("c", "org.z", "do"),
        ];
        assert!(!has_cycle(&steps));
    }

    #[test]
    fn execution_levels_all_independent() {
        let steps = vec![
            WorkflowStep::new("a", "org.x", "do"),
            WorkflowStep::new("b", "org.y", "do"),
            WorkflowStep::new("c", "org.z", "do"),
        ];
        let levels = compute_execution_levels(&steps);
        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0].len(), 3);
    }

    #[test]
    fn execution_levels_linear_chain() {
        let steps = vec![
            WorkflowStep::new("a", "org.x", "do"),
            WorkflowStep::new("b", "org.y", "do").depends_on("a"),
            WorkflowStep::new("c", "org.z", "do").depends_on("b"),
        ];
        let levels = compute_execution_levels(&steps);
        assert_eq!(levels.len(), 3);
        assert_eq!(levels[0], vec!["a"]);
        assert_eq!(levels[1], vec!["b"]);
        assert_eq!(levels[2], vec!["c"]);
    }

    #[test]
    fn execution_levels_diamond() {
        let steps = vec![
            WorkflowStep::new("a", "org.x", "start"),
            WorkflowStep::new("b", "org.y", "left").depends_on("a"),
            WorkflowStep::new("c", "org.z", "right").depends_on("a"),
            WorkflowStep::new("d", "org.w", "merge")
                .depends_on("b")
                .depends_on("c"),
        ];
        let levels = compute_execution_levels(&steps);
        assert_eq!(levels.len(), 3);
        assert_eq!(levels[0], vec!["a"]);
        assert_eq!(levels[1].len(), 2); // b and c in parallel
        assert_eq!(levels[2], vec!["d"]);
    }

    #[test]
    fn execution_levels_empty() {
        let levels = compute_execution_levels(&[]);
        assert!(levels.is_empty());
    }

    #[test]
    fn resolve_params_simple() {
        let mut params = HashMap::new();
        params.insert("path".to_string(), "/tmp/file.txt".to_string());
        let ctx = HashMap::new();
        let resolved = resolve_params(&params, &ctx);
        assert_eq!(resolved["path"], "/tmp/file.txt");
    }

    #[test]
    fn resolve_params_with_context_ref() {
        let mut params = HashMap::new();
        params.insert("input".to_string(), "${prev_output}".to_string());
        let mut ctx = HashMap::new();
        ctx.insert("prev_output".to_string(), "/tmp/data.csv".to_string());
        let resolved = resolve_params(&params, &ctx);
        assert_eq!(resolved["input"], "/tmp/data.csv");
    }

    #[test]
    fn resolve_params_missing_context_keeps_original() {
        let mut params = HashMap::new();
        params.insert("input".to_string(), "${missing_key}".to_string());
        let ctx = HashMap::new();
        let resolved = resolve_params(&params, &ctx);
        assert_eq!(resolved["input"], "${missing_key}");
    }

    #[test]
    fn execute_step_basic() {
        let ctrl = AppController::new();
        let step = WorkflowStep::new("s1", "org.editor", "file.open")
            .with_param("path", "/tmp/doc.txt");
        let result = ctrl.execute_step(&step, &HashMap::new()).unwrap();
        assert!(result.succeeded);
        assert_eq!(result.step_id, "s1");
    }

    #[test]
    fn execute_step_produces_context() {
        let ctrl = AppController::new();
        let step = WorkflowStep::new("s1", "org.export", "pdf.create")
            .produces_key("output_path");
        let result = ctrl.execute_step(&step, &HashMap::new()).unwrap();
        assert!(result.context.contains_key("output_path"));
    }

    #[test]
    fn execute_workflow_simple() {
        let ctrl = AppController::new();
        let wf = consented(
            Workflow::new("simple-test").with_step(WorkflowStep::new("s1", "org.app", "action")),
        );
        let result = ctrl.execute(&wf).unwrap();
        assert!(result.all_succeeded());
        assert_eq!(result.step_results.len(), 1);
        assert!(result.completed);
    }

    #[test]
    fn execute_workflow_with_dependencies() {
        let ctrl = AppController::new();
        let wf = consented(
            Workflow::new("dep-test")
                .with_step(
                    WorkflowStep::new("s1", "org.editor", "open").produces_key("file_handle"),
                )
                .with_step(
                    WorkflowStep::new("s2", "org.export", "convert")
                        .depends_on("s1")
                        .with_param("input", "${file_handle}"),
                ),
        );

        let result = ctrl.execute(&wf).unwrap();
        assert!(result.all_succeeded());
        assert_eq!(result.step_results.len(), 2);
    }

    #[test]
    fn execute_workflow_without_consent_fails() {
        let ctrl = AppController::new();
        let wf = Workflow::new("no-consent")
            .with_step(WorkflowStep::new("s1", "org.app", "do"));
        assert!(ctrl.execute(&wf).is_err());
    }

    #[test]
    fn validate_rejects_cycle() {
        let ctrl = AppController::new();
        let mut step_a = WorkflowStep::new("a", "org.x", "do");
        step_a.depends_on = vec!["b".to_string()];
        let mut step_b = WorkflowStep::new("b", "org.y", "do");
        step_b.depends_on = vec!["a".to_string()];
        let wf = consented(Workflow::new("cyclic").with_step(step_a).with_step(step_b));
        let err = ctrl.validate(&wf).unwrap_err();
        assert!(err.to_string().contains("circular"));
    }

    #[test]
    fn resolve_order_returns_levels() {
        let ctrl = AppController::new();
        let wf = consented(
            Workflow::new("test")
                .with_step(WorkflowStep::new("s1", "org.a", "open"))
                .with_step(WorkflowStep::new("s2", "org.b", "open"))
                .with_step(
                    WorkflowStep::new("s3", "org.c", "merge")
                        .depends_on("s1")
                        .depends_on("s2"),
                ),
        );
        let levels = ctrl.resolve_order(&wf).unwrap();
        assert_eq!(levels.len(), 2);
    }

    #[test]
    fn workflow_serialization_roundtrip() {
        let wf = consented(
            Workflow::new("test")
                .with_step(WorkflowStep::new("s1", "org.app", "do").with_param("key", "value")),
        );
        let json = serde_json::to_string(&wf).unwrap();
        let deserialized: Workflow = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "test");
        assert_eq!(deserialized.steps.len(), 1);
        // ORCH-R1-05: consent is #[serde(skip)] — an in-process capability that
        // never crosses the wire, so a deserialized workflow is always
        // unconsented and a token cannot be forged by sending one.
        assert!(deserialized.consent.is_none());
    }
}
