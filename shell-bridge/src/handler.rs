// SPDX-License-Identifier: MIT

//! WebSocket message dispatch handler.
//!
//! Routes incoming [`Request`] messages to the appropriate backend
//! service by matching on the `method` field. Each method maps to
//! an in-process call on the shared service state.
//!
//! # Method Namespace
//!
//! | Prefix | Backend |
//! |--------|---------|
//! | `inference.*` | AI query routing (die-inference) |
//! | `file_search.*` | Semantic search (semantic-fs) |
//! | `mode.*` | Window mode management |
//! | `timeline.*` | Action timeline (die-orchestrator) |
//! | `learning.*` | Learning suggestions |
//! | `runtime.*` / `tools.*` / `actions.*` | Local daemon runtime loop |

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::RwLock;
use tracing::{info, warn};

use die_inference::router::Router;
use die_inference::{ConfirmationTokenWire, InferenceRequest, RouteOutcome};
use die_learning::LearningError;
use die_orchestrator::learning::{LearningFacade, LearningFacadeError};
use die_orchestrator::timeline::Timeline;
use semantic_fs::indexer::Indexer;

use crate::actions::{self, ActionApiError};
use crate::protocol::{Request, Response};

/// Central message handler for WebSocket requests.
///
/// Holds shared references to all backend services. Each reference
/// uses the same `Arc`-wrapped type as the corresponding D-Bus
/// service, allowing both WebSocket and D-Bus to share state.
///
/// # Examples
///
/// ```
/// use shell_bridge::handler::Handler;
/// use die_inference::router::Router;
/// use die_orchestrator::timeline::Timeline;
/// use semantic_fs::indexer::Indexer;
/// use std::sync::{Arc, Mutex};
/// use tokio::sync::RwLock;
/// use std::collections::HashMap;
///
/// let handler = Handler::new(
///     Arc::new(RwLock::new(Router::new())),
///     Arc::new(Mutex::new(Indexer::in_memory().unwrap())),
///     Arc::new(RwLock::new(HashMap::new())),
///     Arc::new(Mutex::new(Timeline::in_memory().unwrap())),
///     Arc::new(Mutex::new(die_orchestrator::learning::LearningFacade::in_memory().unwrap())),
/// );
/// ```
pub struct Handler {
    /// Inference router (shared with D-Bus InferenceService).
    router: Arc<RwLock<Router>>,
    /// Semantic file indexer (shared with D-Bus FileSearchService).
    indexer: Arc<Mutex<Indexer>>,
    /// Per-window mode map (shared with D-Bus ModeService).
    modes: Arc<RwLock<HashMap<String, String>>>,
    /// Action timeline (shared with D-Bus TimelineService).
    timeline: Arc<Mutex<Timeline>>,
    /// Shared learning facade (shared with the D-Bus LearningService) — one
    /// authoritative accept/dismiss implementation across both transports
    /// instead of duplicated, independently-buggy `Vec<Suggestion>` copies (SVC-5).
    learning: Arc<Mutex<LearningFacade>>,
    /// Server-issued one-shot approval capabilities for controlled local actions.
    approvals: Arc<Mutex<actions::ApprovalRegistry>>,
    /// App-local secret required to mint action approval capabilities.
    bridge_auth_token: Option<String>,
}

impl Handler {
    /// Create a new handler with shared service state.
    ///
    /// # Examples
    ///
    /// ```
    /// use shell_bridge::handler::Handler;
    /// use die_inference::router::Router;
    /// use die_orchestrator::timeline::Timeline;
    /// use semantic_fs::indexer::Indexer;
    /// use std::sync::{Arc, Mutex};
    /// use tokio::sync::RwLock;
    /// use std::collections::HashMap;
    ///
    /// let h = Handler::new(
    ///     Arc::new(RwLock::new(Router::new())),
    ///     Arc::new(Mutex::new(Indexer::in_memory().unwrap())),
    ///     Arc::new(RwLock::new(HashMap::new())),
    ///     Arc::new(Mutex::new(Timeline::in_memory().unwrap())),
    ///     Arc::new(Mutex::new(die_orchestrator::learning::LearningFacade::in_memory().unwrap())),
    /// );
    /// ```
    #[must_use]
    pub fn new(
        router: Arc<RwLock<Router>>,
        indexer: Arc<Mutex<Indexer>>,
        modes: Arc<RwLock<HashMap<String, String>>>,
        timeline: Arc<Mutex<Timeline>>,
        learning: Arc<Mutex<LearningFacade>>,
    ) -> Self {
        Self {
            router,
            indexer,
            modes,
            timeline,
            learning,
            approvals: Arc::new(Mutex::new(actions::ApprovalRegistry::new())),
            bridge_auth_token: load_bridge_auth_token(),
        }
    }

    /// Override the app-local bridge auth token.
    ///
    /// Used by tests and by future embedding surfaces that provision an
    /// authenticated shell session without relying on process environment.
    #[must_use]
    pub fn with_bridge_auth_token(mut self, token: Option<String>) -> Self {
        self.bridge_auth_token = token;
        self
    }

    /// Dispatch a request to the appropriate backend.
    ///
    /// Matches the `method` field against known method names and
    /// routes to the corresponding service call. Returns a
    /// [`Response`] with either the result or an error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use shell_bridge::handler::Handler;
    /// # use shell_bridge::protocol::Request;
    /// # use die_inference::router::Router;
    /// # use die_orchestrator::timeline::Timeline;
    /// # use semantic_fs::indexer::Indexer;
    /// # use std::sync::{Arc, Mutex};
    /// # use tokio::sync::RwLock;
    /// # use std::collections::HashMap;
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let handler = Handler::new(
    ///     Arc::new(RwLock::new(Router::new())),
    ///     Arc::new(Mutex::new(Indexer::in_memory().unwrap())),
    ///     Arc::new(RwLock::new(HashMap::new())),
    ///     Arc::new(Mutex::new(Timeline::in_memory().unwrap())),
    ///     Arc::new(Mutex::new(die_orchestrator::learning::LearningFacade::in_memory().unwrap())),
    /// );
    ///
    /// let req = Request { id: 1, method: "inference.status".to_string(), params: serde_json::Value::Null };
    /// let resp = handler.dispatch(req).await;
    /// assert!(resp.result.is_some());
    /// # });
    /// ```
    pub async fn dispatch(&self, req: Request) -> Response {
        info!(id = req.id, method = %req.method, "dispatching request");

        match req.method.as_str() {
            // Runtime / Tools / Actions
            "runtime.status" => self.handle_runtime_status(req.id).await,
            "tools.capabilities" => self.handle_tools_capabilities(req.id).await,
            "actions.plan" => self.handle_actions_plan(req.id, &req.params).await,
            "actions.approve" => self.handle_actions_approve(req.id, &req.params).await,
            "actions.execute" => self.handle_actions_execute(req.id, &req.params).await,
            "actions.undo" => self.handle_actions_undo(req.id, &req.params).await,

            // ── Inference ──────────────────────────────────
            "inference.query" => self.handle_inference_query(req.id, &req.params).await,
            "inference.status" => self.handle_inference_status(req.id).await,
            "inference.grant_cloud_egress_consent" => {
                self.handle_inference_grant_consent(req.id).await
            }

            // ── File Search ────────────────────────────────
            "file_search.search" => self.handle_file_search(req.id, &req.params).await,

            // ── Mode ───────────────────────────────────────
            "mode.get" => self.handle_mode_get(req.id, &req.params).await,
            "mode.set" => self.handle_mode_set(req.id, &req.params).await,
            "mode.list" => self.handle_mode_list(req.id).await,

            // ── Timeline ───────────────────────────────────
            "timeline.recent" => self.handle_timeline_recent(req.id, &req.params).await,
            "timeline.undo" => self.handle_timeline_undo(req.id, &req.params).await,
            "timeline.count" => self.handle_timeline_count(req.id).await,

            // ── Learning ───────────────────────────────────
            "learning.suggestions" => self.handle_learning_suggestions(req.id).await,
            "learning.detect" => self.handle_learning_detect(req.id).await,
            "learning.accept" => self.handle_learning_accept(req.id, &req.params).await,
            "learning.dismiss" => self.handle_learning_dismiss(req.id, &req.params).await,
            "learning.count" => self.handle_learning_count(req.id).await,

            _ => {
                warn!(method = %req.method, "unknown method");
                Response::err(req.id, -32601, &format!("method not found: {}", req.method))
            }
        }
    }
}

// Runtime / action handlers

impl Handler {
    /// Handle `runtime.status` by summarizing local daemon-owned state.
    async fn handle_runtime_status(&self, id: u64) -> Response {
        let router = self.router.read().await;
        let has_local = router.has_local_model();
        let has_cloud = router.has_cloud();
        drop(router);

        let mode_count = self.modes.read().await.len();

        let (timeline_count, pending_count) = match self.timeline.lock() {
            Ok(tl) => {
                let count = match tl.count() {
                    Ok(count) => count,
                    Err(e) => return Response::err(id, -1, &e.to_string()),
                };
                let pending = match tl.list_pending_actions() {
                    Ok(actions) => actions.len(),
                    Err(e) => return Response::err(id, -1, &e.to_string()),
                };
                (count, pending)
            }
            Err(_) => return Response::err(id, -1, "timeline state unavailable"),
        };

        let (learning_focus, learning_suggestions) = match self.learning.lock() {
            Ok(facade) => (facade.focus_active(), facade.list_suggestions().len()),
            Err(_) => return Response::err(id, -1, "learning state unavailable"),
        };

        Response::ok(
            id,
            serde_json::json!({
                "runtime": "dev-local",
                "bridge": "ready",
                "listen_addr": crate::DEFAULT_ADDR,
                "daemon_required": true,
                "shared_state": {
                    "inference_router": { "has_local": has_local, "has_cloud": has_cloud },
                    "semantic_index": "in_memory",
                    "mode_count": mode_count,
                    "timeline_count": timeline_count,
                    "timeline_pending_count": pending_count,
                    "learning_focus_active": learning_focus,
                    "learning_suggestion_count": learning_suggestions,
                }
            }),
        )
    }

    /// Handle `tools.capabilities`.
    async fn handle_tools_capabilities(&self, id: u64) -> Response {
        Response::ok(id, actions::capabilities_payload())
    }

    /// Handle `actions.plan`.
    async fn handle_actions_plan(&self, id: u64, params: &serde_json::Value) -> Response {
        match actions::plan(params) {
            Ok(plan) => match serde_json::to_value(plan) {
                Ok(value) => Response::ok(id, value),
                Err(e) => Response::err(id, -1, &format!("serialize: {e}")),
            },
            Err(e) => action_error(id, e),
        }
    }

    /// Handle `actions.approve`.
    async fn handle_actions_approve(&self, id: u64, params: &serde_json::Value) -> Response {
        if let Err(e) = self.authorize_approval_mint(params) {
            return action_error(id, e);
        }
        let kind = match actions::approval_kind_for_plan(params) {
            Ok(Some(kind)) => kind,
            Ok(None) => return action_error(id, ActionApiError::MissingParam("repo_path")),
            Err(e) => return action_error(id, e),
        };
        let capability = {
            let mut approvals = match self.approvals.lock() {
                Ok(approvals) => approvals,
                Err(_) => {
                    return action_error(
                        id,
                        ActionApiError::ApprovalInvalid("approval state unavailable".to_string()),
                    );
                }
            };
            approvals.issue(kind)
        };
        match serde_json::to_value(capability) {
            Ok(value) => Response::ok(id, value),
            Err(e) => Response::err(id, -1, &format!("serialize: {e}")),
        }
    }

    fn authorize_approval_mint(
        &self,
        params: &serde_json::Value,
    ) -> Result<(), ActionApiError> {
        if !params
            .get("user_confirmed")
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
        {
            return Err(ActionApiError::UserConfirmationRequired);
        }

        let expected = self
            .bridge_auth_token
            .as_deref()
            .filter(|token| !token.is_empty())
            .ok_or(ActionApiError::BridgeAuthRequired)?;
        let provided = params
            .get("bridge_auth_token")
            .and_then(|value| value.as_str())
            .filter(|token| !token.is_empty())
            .ok_or(ActionApiError::BridgeAuthRequired)?;

        if provided == expected {
            Ok(())
        } else {
            Err(ActionApiError::BridgeAuthInvalid)
        }
    }

    /// Handle `actions.execute`.
    async fn handle_actions_execute(&self, id: u64, params: &serde_json::Value) -> Response {
        let request = match actions::normalize_execute_request(params) {
            Ok(request) => request,
            Err(e) => return action_error(id, e),
        };
        let token = match actions::required_approval_token(params) {
            Ok(token) => token,
            Err(e) => return action_error(id, e),
        };
        {
            let mut approvals = match self.approvals.lock() {
                Ok(approvals) => approvals,
                Err(_) => {
                    return action_error(
                        id,
                        ActionApiError::ApprovalInvalid("approval state unavailable".to_string()),
                    );
                }
            };
            if let Err(e) = approvals.consume_execute(&token, &request) {
                return action_error(id, e);
            }
        }

        match actions::execute(request, &self.timeline, &self.learning).await {
            Ok(receipt) => match serde_json::to_value(receipt) {
                Ok(value) => Response::ok(id, value),
                Err(e) => Response::err(id, -1, &format!("serialize: {e}")),
            },
            Err(e) => action_error(id, e),
        }
    }

    /// Handle `actions.undo`.
    async fn handle_actions_undo(&self, id: u64, params: &serde_json::Value) -> Response {
        let request = match actions::normalize_undo_request(params) {
            Ok(request) => request,
            Err(e) => return action_error(id, e),
        };
        let token = match actions::required_approval_token(params) {
            Ok(token) => token,
            Err(e) => return action_error(id, e),
        };
        {
            let mut approvals = match self.approvals.lock() {
                Ok(approvals) => approvals,
                Err(_) => {
                    return action_error(
                        id,
                        ActionApiError::ApprovalInvalid("approval state unavailable".to_string()),
                    );
                }
            };
            if let Err(e) = approvals.consume_undo(&token, &request) {
                return action_error(id, e);
            }
        }

        match actions::undo(request, &self.timeline).await {
            Ok(receipt) => match serde_json::to_value(receipt) {
                Ok(value) => Response::ok(id, value),
                Err(e) => Response::err(id, -1, &format!("serialize: {e}")),
            },
            Err(e) => action_error(id, e),
        }
    }
}

fn action_error(id: u64, error: ActionApiError) -> Response {
    let code = match error {
        ActionApiError::MissingParam(_)
        | ActionApiError::InvalidRepoPath
        | ActionApiError::InvalidCommand(_)
        | ActionApiError::ApprovalRequired
        | ActionApiError::ApprovalInvalid(_)
        | ActionApiError::BridgeAuthRequired
        | ActionApiError::BridgeAuthInvalid
        | ActionApiError::UserConfirmationRequired => -32602,
        ActionApiError::UnsupportedWorkflow(_) => -32601,
        ActionApiError::TimelineUnavailable
        | ActionApiError::LearningUnavailable
        | ActionApiError::Timeline(_)
        | ActionApiError::Serialization(_) => -1,
    };
    Response::err(id, code, &error.to_string())
}

fn load_bridge_auth_token() -> Option<String> {
    std::env::var("DELPHI_BRIDGE_AUTH_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
}

// ── Inference handlers ─────────────────────────────────────────

impl Handler {
    /// Handle `inference.query` — route a prompt through the inference engine.
    async fn handle_inference_query(&self, id: u64, params: &serde_json::Value) -> Response {
        let prompt = match params.get("prompt").and_then(|v| v.as_str()) {
            Some(p) => p.to_string(),
            None => return Response::err(id, -32602, "missing required param: prompt"),
        };

        let max_tokens = params
            .get("max_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(256) as u32;

        let sensitive = params
            .get("sensitive")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // SVC-1-R1-1: explicit consent token to send a high-privacy-score
        // query (the sanitized version) past the ZKQP confirmation pause. The
        // opaque, HMAC-bound token comes from a prior `confirmation_required`
        // response; absent on the first call. A forged/stale token simply
        // re-pauses — it can't force an unsanitized send (replaces the old
        // caller-forgeable `cloud_confirmed` bool).
        let cloud_confirmation_token = params
            .get("cloud_confirmation_token")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            // Wrap into the redacted-Debug newtype (SVC-1-R1-1-02) at the
            // boundary, so the live token never sits in a bare String field.
            .map(|s| ConfirmationTokenWire::new(s.to_string()));

        let router = self.router.read().await;
        let req = InferenceRequest {
            input: prompt,
            max_tokens,
            sensitive,
            cloud_confirmation_token,
        };

        match router.route(req).await {
            // SVC-1: a cloud query may pause for confirmation. Surface the
            // typed outcome to the shell discriminated by `status` rather than
            // swallowing the pause or pretending it completed.
            Ok(RouteOutcome::Completed(resp)) => Response::ok(
                id,
                serde_json::json!({
                    "status": "completed",
                    "output": resp.output,
                    "tier": format!("{:?}", resp.tier),
                    "model_id": resp.model_id,
                }),
            ),
            Ok(RouteOutcome::CloudConfirmationRequired(c)) => Response::ok(
                id,
                serde_json::json!({
                    "status": "confirmation_required",
                    "privacy_score": c.privacy_score,
                    "sanitized_preview": c.sanitized_preview,
                    // Explicit transport read of the redacted-Debug newtype.
                    "token": c.token.as_str(),
                }),
            ),
            // SVC-2 Piece 2: the egress gateway refused for lack of session
            // destination consent — surfaced as a distinct status so the shell
            // shows the "allow cloud?" opt-in (combinable with the preview).
            // (Granting the consent + the dialog wiring is the next sub-step.)
            Ok(RouteOutcome::DestinationConsentRequired(c)) => Response::ok(
                id,
                serde_json::json!({
                    "status": "destination_consent_required",
                    "privacy_score": c.privacy_score,
                    "sanitized_preview": c.sanitized_preview,
                    "token": c.token.as_str(),
                }),
            ),
            Err(e) => Response::err(id, -1, &e.to_string()),
        }
    }

    /// Handle `inference.status` — check which backends are available.
    async fn handle_inference_status(&self, id: u64) -> Response {
        let router = self.router.read().await;
        Response::ok(
            id,
            serde_json::json!({
                "has_local": router.has_local_model(),
                "has_cloud": router.has_cloud(),
            }),
        )
    }

    /// Handle `inference.grant_cloud_egress_consent` — grant session cloud
    /// destination consent (SVC-2 Piece 2). The shell calls this when the user
    /// accepts the destination opt-in dialog; it arms the egress gateway so
    /// subsequent cloud-routed queries proceed past the
    /// `destination_consent_required` refusal to the privacy pause / send.
    ///
    /// The WebSocket is the shell's own trusted channel, so — like the other
    /// inference handlers — this calls the shared Router directly. The SVC-2
    /// AuthGuard governs the D-Bus boundary (`InferenceService`), not this one;
    /// the WebSocket caller-identity model is the deferred Piece-1b concern.
    async fn handle_inference_grant_consent(&self, id: u64) -> Response {
        self.router.read().await.grant_destination_consent();
        info!("WebSocket grant_cloud_egress_consent — session cloud egress consent granted");
        Response::ok(id, serde_json::json!({ "granted": true }))
    }
}

// ── File search handlers ───────────────────────────────────────

impl Handler {
    /// Handle `file_search.search` — semantic file search.
    async fn handle_file_search(&self, id: u64, params: &serde_json::Value) -> Response {
        let query = match params.get("query").and_then(|v| v.as_str()) {
            Some(q) => q.to_string(),
            None => return Response::err(id, -32602, "missing required param: query"),
        };

        let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;

        let indexer = match self.indexer.lock() {
            Ok(i) => i,
            Err(e) => return Response::err(id, -1, &format!("lock poisoned: {e}")),
        };

        match indexer.search(&query, limit) {
            Ok(results) => {
                let json: Vec<serde_json::Value> = results
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "path": r.path,
                            "filename": r.filename,
                            "score": r.score,
                        })
                    })
                    .collect();
                Response::ok(id, serde_json::json!(json))
            }
            Err(e) => Response::err(id, -1, &e.to_string()),
        }
    }
}

// ── Mode handlers ──────────────────────────────────────────────

impl Handler {
    /// Handle `mode.get` — get a window's current mode.
    async fn handle_mode_get(&self, id: u64, params: &serde_json::Value) -> Response {
        let window_id = match params.get("window_id").and_then(|v| v.as_str()) {
            Some(w) => w.to_string(),
            None => return Response::err(id, -32602, "missing required param: window_id"),
        };

        let modes = self.modes.read().await;
        let mode = modes
            .get(&window_id)
            .cloned()
            .unwrap_or_else(|| "Direct".to_string());

        Response::ok(id, serde_json::json!({ "mode": mode }))
    }

    /// Handle `mode.set` — change a window's mode.
    async fn handle_mode_set(&self, id: u64, params: &serde_json::Value) -> Response {
        let window_id = match params.get("window_id").and_then(|v| v.as_str()) {
            Some(w) => w.to_string(),
            None => return Response::err(id, -32602, "missing required param: window_id"),
        };

        let mode = match params.get("mode").and_then(|v| v.as_str()) {
            Some(m) => m.to_string(),
            None => return Response::err(id, -32602, "missing required param: mode"),
        };

        if !delphi_services::mode::is_valid_mode(&mode) {
            return Response::err(
                id,
                -32602,
                &format!("invalid mode '{mode}'. Valid: Direct, Assisted, Autonomous, Focus"),
            );
        }

        let mut modes = self.modes.write().await;
        modes.insert(window_id, mode.clone());
        // SVC-5-R2-1: arm the learning facade inside the same mode-lock
        // critical section that updated the mode map. The shell-bridge and
        // the D-Bus ModeService both route mode changes through the shared
        // helper so a Focus transition arrives at the facade no matter which
        // transport carried the request.
        if let Err(msg) = delphi_services::mode::apply_focus_from_modes(&modes, &self.learning) {
            return Response::err(id, -32603, &format!("internal: {msg}"));
        }

        Response::ok(id, serde_json::json!({ "mode": mode }))
    }

    /// Handle `mode.list` — list all window modes.
    async fn handle_mode_list(&self, id: u64) -> Response {
        let modes = self.modes.read().await;
        Response::ok(id, serde_json::json!(*modes))
    }
}

// ── Timeline handlers ──────────────────────────────────────────

impl Handler {
    /// Handle `timeline.recent` — get recent actions.
    async fn handle_timeline_recent(&self, id: u64, params: &serde_json::Value) -> Response {
        let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as u32;

        let tl = match self.timeline.lock() {
            Ok(t) => t,
            Err(e) => return Response::err(id, -1, &format!("lock poisoned: {e}")),
        };

        match tl.list_recent(limit) {
            Ok(records) => {
                let json: Vec<serde_json::Value> = records
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "action_id": r.action_id,
                            "description": r.description,
                            "timestamp": r.timestamp,
                            "reversible": r.reversible,
                            "expires_at": r.expires_at,
                            "status": r.status.as_str(),
                            "action_type": r.action_type,
                            "outputs_summary": actions::timeline_outputs_summary(r.outputs.as_deref()),
                        })
                    })
                    .collect();
                Response::ok(id, serde_json::json!(json))
            }
            Err(e) => Response::err(id, -1, &e.to_string()),
        }
    }

    /// Handle `timeline.undo` — undo an action by ID.
    async fn handle_timeline_undo(&self, id: u64, params: &serde_json::Value) -> Response {
        let action_id = match params.get("action_id").and_then(|v| v.as_str()) {
            Some(a) => a.to_string(),
            None => return Response::err(id, -32602, "missing required param: action_id"),
        };

        let tl = match self.timeline.lock() {
            Ok(t) => t,
            Err(e) => return Response::err(id, -1, &format!("lock poisoned: {e}")),
        };

        match tl.preview_undo(&action_id) {
            Ok(cmd) => Response::ok(
                id,
                serde_json::json!({
                    "undo_preview": actions::undo_payload_preview(&cmd),
                    "requires_approval": true,
                    "executed": false,
                    "message": "timeline.undo is a preview; use actions.plan/actions.undo to execute"
                }),
            ),
            Err(e) => Response::err(id, -1, &e.to_string()),
        }
    }

    /// Handle `timeline.count` — get total action count.
    async fn handle_timeline_count(&self, id: u64) -> Response {
        let tl = match self.timeline.lock() {
            Ok(t) => t,
            Err(e) => return Response::err(id, -1, &format!("lock poisoned: {e}")),
        };

        match tl.count() {
            Ok(count) => Response::ok(id, serde_json::json!({ "count": count })),
            Err(e) => Response::err(id, -1, &e.to_string()),
        }
    }
}

// ── Learning handlers ──────────────────────────────────────────

impl Handler {
    /// Handle `learning.suggestions` — pending suggestions via the facade.
    async fn handle_learning_suggestions(&self, id: u64) -> Response {
        let suggestions = match self.learning.lock() {
            Ok(facade) => facade.list_suggestions(),
            Err(_) => return Response::err(id, -1, "learning state unavailable"),
        };
        match serde_json::to_value(&suggestions) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, -1, &format!("serialize: {e}")),
        }
    }

    /// Handle `learning.accept` — accept a suggestion.
    /// Handle `learning.detect` by running metadata-only pattern detection now.
    async fn handle_learning_detect(&self, id: u64) -> Response {
        let (detected_count, suggestions) = {
            let mut facade = match self.learning.lock() {
                Ok(f) => f,
                Err(_) => return Response::err(id, -1, "learning state unavailable"),
            };
            let detected_count = match facade.run_detection() {
                Ok(patterns) => patterns.len(),
                Err(LearningError::NoPatternsFound { .. }) => 0,
                Err(LearningError::ObserverPaused) => {
                    return Response::err(id, -1, "learning observer is paused");
                }
                Err(_) => return Response::err(id, -1, "learning detection failed"),
            };
            (detected_count, facade.list_suggestions())
        };
        match serde_json::to_value(serde_json::json!({
            "detected_count": detected_count,
            "suggestions": suggestions,
        })) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, -1, &format!("serialize: {e}")),
        }
    }

    async fn handle_learning_accept(&self, id: u64, params: &serde_json::Value) -> Response {
        let suggestion_id = match params.get("suggestion_id").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return Response::err(id, -32602, "missing required param: suggestion_id"),
        };

        let result = {
            let mut facade = match self.learning.lock() {
                Ok(f) => f,
                Err(_) => return Response::err(id, -1, "learning state unavailable"),
            };
            facade.accept(&suggestion_id)
        };
        match result {
            Ok(r) => match serde_json::to_value(&r) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, -1, &format!("serialize: {e}")),
            },
            Err(LearningFacadeError::NotFound) => Response::err(id, -1, "suggestion not found"),
            Err(LearningFacadeError::FocusMode) => {
                Response::err(id, -1, "cannot accept suggestions while in Focus mode")
            }
            Err(_) => Response::err(id, -1, "learning operation failed"),
        }
    }

    /// Handle `learning.dismiss` — dismiss a suggestion.
    async fn handle_learning_dismiss(&self, id: u64, params: &serde_json::Value) -> Response {
        let suggestion_id = match params.get("suggestion_id").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return Response::err(id, -32602, "missing required param: suggestion_id"),
        };

        let result = {
            let mut facade = match self.learning.lock() {
                Ok(f) => f,
                Err(_) => return Response::err(id, -1, "learning state unavailable"),
            };
            facade.dismiss(&suggestion_id)
        };
        match result {
            Ok(r) => match serde_json::to_value(&r) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, -1, &format!("serialize: {e}")),
            },
            Err(LearningFacadeError::NotFound) => Response::err(id, -1, "suggestion not found"),
            Err(_) => Response::err(id, -1, "learning operation failed"),
        }
    }

    /// Handle `learning.count` — count of pending suggestions via the facade.
    async fn handle_learning_count(&self, id: u64) -> Response {
        let count = match self.learning.lock() {
            Ok(facade) => facade.list_suggestions().len(),
            Err(_) => return Response::err(id, -1, "learning state unavailable"),
        };
        Response::ok(id, serde_json::json!({ "count": count }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_BRIDGE_AUTH_TOKEN: &str = "test-bridge-auth-token";

    /// Helper to create a handler with default empty services.
    fn test_handler() -> Handler {
        Handler::new(
            Arc::new(RwLock::new(Router::new())),
            Arc::new(Mutex::new(Indexer::in_memory().unwrap())),
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(Mutex::new(Timeline::in_memory().unwrap())),
            Arc::new(Mutex::new(
                die_orchestrator::learning::LearningFacade::in_memory().unwrap(),
            )),
        )
        .with_bridge_auth_token(Some(TEST_BRIDGE_AUTH_TOKEN.to_string()))
    }

    #[tokio::test]
    async fn unknown_method_returns_error() {
        let handler = test_handler();
        let req = Request {
            id: 1,
            method: "nonexistent.method".to_string(),
            params: serde_json::Value::Null,
        };
        let resp = handler.dispatch(req).await;
        assert!(resp.error.is_some());
        assert!(resp.result.is_none());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[tokio::test]
    async fn inference_status_works() {
        let handler = test_handler();
        let req = Request {
            id: 2,
            method: "inference.status".to_string(),
            params: serde_json::Value::Null,
        };
        let resp = handler.dispatch(req).await;
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["has_local"], false);
        assert_eq!(result["has_cloud"], false);
    }

    /// SVC-2 Piece 2b: the WebSocket grant method dispatches and returns
    /// `granted: true`. With no cloud backend configured it is a harmless no-op
    /// on the gateway flag; the dispatch + response contract is what this
    /// verifies (the gateway-arming behavior is covered in die-inference and the
    /// services layer).
    #[tokio::test]
    async fn inference_grant_cloud_egress_consent_works() {
        let handler = test_handler();
        let req = Request {
            id: 7,
            method: "inference.grant_cloud_egress_consent".to_string(),
            params: serde_json::Value::Null,
        };
        let resp = handler.dispatch(req).await;
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap()["granted"], true);
    }

    #[tokio::test]
    async fn inference_query_missing_prompt() {
        let handler = test_handler();
        let req = Request {
            id: 3,
            method: "inference.query".to_string(),
            params: serde_json::json!({}),
        };
        let resp = handler.dispatch(req).await;
        assert!(resp.error.is_some());
        assert!(resp.error.unwrap().message.contains("prompt"));
    }

    #[tokio::test]
    async fn file_search_missing_query() {
        let handler = test_handler();
        let req = Request {
            id: 4,
            method: "file_search.search".to_string(),
            params: serde_json::json!({}),
        };
        let resp = handler.dispatch(req).await;
        assert!(resp.error.is_some());
        assert!(resp.error.unwrap().message.contains("query"));
    }

    #[tokio::test]
    async fn file_search_empty_index() {
        let handler = test_handler();
        let req = Request {
            id: 5,
            method: "file_search.search".to_string(),
            params: serde_json::json!({ "query": "hello", "limit": 5 }),
        };
        let resp = handler.dispatch(req).await;
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert!(result.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn mode_get_default() {
        let handler = test_handler();
        let req = Request {
            id: 6,
            method: "mode.get".to_string(),
            params: serde_json::json!({ "window_id": "win-1" }),
        };
        let resp = handler.dispatch(req).await;
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap()["mode"], "Direct");
    }

    #[tokio::test]
    async fn mode_set_and_get() {
        let handler = test_handler();

        // Set mode
        let set_req = Request {
            id: 7,
            method: "mode.set".to_string(),
            params: serde_json::json!({ "window_id": "win-1", "mode": "Assisted" }),
        };
        let resp = handler.dispatch(set_req).await;
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap()["mode"], "Assisted");

        // Get mode
        let get_req = Request {
            id: 8,
            method: "mode.get".to_string(),
            params: serde_json::json!({ "window_id": "win-1" }),
        };
        let resp = handler.dispatch(get_req).await;
        assert_eq!(resp.result.unwrap()["mode"], "Assisted");
    }

    #[tokio::test]
    async fn mode_set_invalid() {
        let handler = test_handler();
        let req = Request {
            id: 9,
            method: "mode.set".to_string(),
            params: serde_json::json!({ "window_id": "win-1", "mode": "BadMode" }),
        };
        let resp = handler.dispatch(req).await;
        assert!(resp.error.is_some());
        assert!(resp.error.unwrap().message.contains("invalid mode"));
    }

    #[tokio::test]
    async fn mode_list_empty() {
        let handler = test_handler();
        let req = Request {
            id: 10,
            method: "mode.list".to_string(),
            params: serde_json::Value::Null,
        };
        let resp = handler.dispatch(req).await;
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert!(result.as_object().unwrap().is_empty());
    }

    #[tokio::test]
    async fn timeline_recent_empty() {
        let handler = test_handler();
        let req = Request {
            id: 11,
            method: "timeline.recent".to_string(),
            params: serde_json::json!({ "limit": 10 }),
        };
        let resp = handler.dispatch(req).await;
        assert!(resp.error.is_none());
        assert!(resp.result.unwrap().as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn timeline_count_starts_at_zero() {
        let handler = test_handler();
        let req = Request {
            id: 12,
            method: "timeline.count".to_string(),
            params: serde_json::Value::Null,
        };
        let resp = handler.dispatch(req).await;
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap()["count"], 0);
    }

    #[tokio::test]
    async fn learning_suggestions_empty() {
        let handler = test_handler();
        let req = Request {
            id: 13,
            method: "learning.suggestions".to_string(),
            params: serde_json::Value::Null,
        };
        let resp = handler.dispatch(req).await;
        assert!(resp.error.is_none());
        assert!(resp.result.unwrap().as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn learning_count_starts_at_zero() {
        let handler = test_handler();
        let req = Request {
            id: 14,
            method: "learning.count".to_string(),
            params: serde_json::Value::Null,
        };
        let resp = handler.dispatch(req).await;
        assert_eq!(resp.result.unwrap()["count"], 0);
    }

    #[tokio::test]
    async fn learning_accept_nonexistent() {
        let handler = test_handler();
        let req = Request {
            id: 15,
            method: "learning.accept".to_string(),
            params: serde_json::json!({ "suggestion_id": "nope" }),
        };
        let resp = handler.dispatch(req).await;
        assert!(resp.error.is_some());
        assert!(resp.error.unwrap().message.contains("not found"));
    }

    #[tokio::test]
    async fn learning_dismiss_nonexistent() {
        let handler = test_handler();
        let req = Request {
            id: 16,
            method: "learning.dismiss".to_string(),
            params: serde_json::json!({ "suggestion_id": "nope" }),
        };
        let resp = handler.dispatch(req).await;
        assert!(resp.error.is_some());
    }

    #[tokio::test]
    async fn learning_accept_transitions_to_practicing() {
        use die_learning::{EventCategory, LearningEvent};

        // Seed a Proposed suggestion in a shared facade (deterministic
        // firefox→code recipe; see die_orchestrator::learning tests).
        let mut facade = LearningFacade::in_memory().unwrap();
        for i in 0..10 {
            let _ = facade.observe(LearningEvent::at_time(
                EventCategory::AppLaunch,
                "firefox",
                None,
                i * 100,
            ));
            let _ = facade.observe(LearningEvent::at_time(
                EventCategory::AppLaunch,
                "code",
                None,
                i * 100 + 10,
            ));
        }
        let _ = facade.run_detection();
        let suggestion_id = facade
            .list_suggestions()
            .first()
            .expect("seed must produce a pending suggestion")
            .id
            .clone();

        let handler = Handler::new(
            Arc::new(RwLock::new(Router::new())),
            Arc::new(Mutex::new(Indexer::in_memory().unwrap())),
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(Mutex::new(Timeline::in_memory().unwrap())),
            Arc::new(Mutex::new(facade)),
        );

        let accept_req = Request {
            id: 18,
            method: "learning.accept".to_string(),
            params: serde_json::json!({ "suggestion_id": suggestion_id }),
        };
        let resp = handler.dispatch(accept_req).await;
        assert!(resp.error.is_none(), "accept failed: {:?}", resp.error);
        let result = resp.result.unwrap();
        // Strengthened (SVC-5): accept TRANSITIONS to Practicing and records a
        // reversible timeline action — it no longer silently deletes the
        // suggestion (the old broken accept ≡ dismiss behavior).
        assert_eq!(result["new_stage"], "practicing");
        assert!(
            result["action_timeline_id"]
                .as_str()
                .unwrap()
                .starts_with("tl-")
        );
    }

    /// SVC-5-R2-1 cross-transport integration: a Focus mode-change must arm
    /// the [`LearningFacade`] regardless of *which* transport carried the
    /// request. This drives Focus via the shell-bridge `handle_mode_set`
    /// path and clears it via the D-Bus `ModeService::set_mode` path against
    /// the SAME shared facade and modes Arcs.
    ///
    /// **This is the RED→GREEN proof** for SVC-5-R2-1. Pre-round-2, the
    /// transports only called `modes.insert(...)` and the facade stayed
    /// disarmed; the `focus_active() / list_suggestions().is_empty() /
    /// accept → FocusMode` assertions all failed because the gate, though
    /// implemented, was never wired up. Post-round-2 both transports route
    /// the mode change through `apply_focus_from_modes` and the facade
    /// arms/disarms in lock-step with the mode map.
    #[tokio::test]
    async fn focus_arms_facade_through_both_transports() {
        use delphi_services::mode::ModeService;
        use die_learning::{EventCategory, LearningEvent};
        use die_orchestrator::learning::LearningFacadeError;

        // Seed a Proposed suggestion (firefox→code recipe).
        let mut facade = LearningFacade::in_memory().unwrap();
        for i in 0..10 {
            let _ = facade.observe(LearningEvent::at_time(
                EventCategory::AppLaunch,
                "firefox",
                None,
                i * 100,
            ));
            let _ = facade.observe(LearningEvent::at_time(
                EventCategory::AppLaunch,
                "code",
                None,
                i * 100 + 10,
            ));
        }
        let _ = facade.run_detection();
        let suggestion_id = facade
            .list_suggestions()
            .first()
            .expect("seed must produce a pending suggestion")
            .id
            .clone();

        // Shared state for both transports.
        let modes = Arc::new(RwLock::new(HashMap::<String, String>::new()));
        let facade_arc = Arc::new(Mutex::new(facade));

        let handler = Handler::new(
            Arc::new(RwLock::new(Router::new())),
            Arc::new(Mutex::new(Indexer::in_memory().unwrap())),
            modes.clone(),
            Arc::new(Mutex::new(Timeline::in_memory().unwrap())),
            facade_arc.clone(),
        );
        let mode_svc = ModeService::new(
            modes.clone(),
            facade_arc.clone(),
            Arc::new(delphi_services::auth_guard::AuthGuard::dev_in_memory()),
        );

        // Sanity: facade starts disarmed and the seeded suggestion is listed.
        assert!(!facade_arc.lock().unwrap().focus_active());
        assert!(!facade_arc.lock().unwrap().list_suggestions().is_empty());

        // ── Path 1: arm Focus via the shell-bridge (WebSocket) handler ──
        let focus_req = Request {
            id: 100,
            method: "mode.set".to_string(),
            params: serde_json::json!({ "window_id": "win-1", "mode": "Focus" }),
        };
        let focus_resp = handler.dispatch(focus_req).await;
        assert!(
            focus_resp.error.is_none(),
            "handler mode.set failed: {:?}",
            focus_resp.error
        );

        assert!(
            facade_arc.lock().unwrap().focus_active(),
            "shell-bridge mode.set(\"Focus\") must arm the facade (SVC-5-R2-1)"
        );
        assert!(
            facade_arc.lock().unwrap().list_suggestions().is_empty(),
            "armed facade must filter all suggestions"
        );
        let accept_err = facade_arc.lock().unwrap().accept(&suggestion_id);
        assert!(
            matches!(accept_err, Err(LearningFacadeError::FocusMode)),
            "armed facade must reject accept with FocusMode; got: {accept_err:?}"
        );

        // ── Path 2: clear Focus via the D-Bus ModeService ──────────────
        // Build a message Header carrying a sender so the SVC-2 guard can read
        // the caller identity (dev policy → proceed-and-audit, so set_mode runs).
        let setmode_msg = zbus::message::Message::method_call("/org/delphi/Mode", "SetMode")
            .unwrap()
            .sender(":1.5")
            .unwrap()
            .build(&())
            .unwrap();
        mode_svc
            .set_mode(
                setmode_msg.header(),
                "win-1".to_string(),
                "Direct".to_string(),
            )
            .await
            .unwrap();

        assert!(
            !facade_arc.lock().unwrap().focus_active(),
            "ModeService::set_mode(\"Direct\") must disarm the facade (SVC-5-R2-1)"
        );
        assert!(
            facade_arc
                .lock()
                .unwrap()
                .list_suggestions()
                .iter()
                .any(|s| s.id == suggestion_id),
            "disarmed facade must surface the seeded suggestion again"
        );
    }

    fn repo_root() -> String {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("shell-bridge should live under the workspace root")
            .display()
            .to_string()
    }

    async fn approval_token_for(handler: &Handler, id: u64, params: &serde_json::Value) -> String {
        let mut approval_params = params.clone();
        approval_params["bridge_auth_token"] =
            serde_json::Value::String(TEST_BRIDGE_AUTH_TOKEN.to_string());
        approval_params["user_confirmed"] = serde_json::Value::Bool(true);
        let approval = handler
            .dispatch(Request {
                id,
                method: "actions.approve".to_string(),
                params: approval_params,
            })
            .await;
        assert!(
            approval.error.is_none(),
            "approve failed: {:?}",
            approval.error
        );
        approval.result.unwrap()["token"]
            .as_str()
            .expect("approve should mint an approval token")
            .to_string()
    }

    async fn execute_developer_repo_check(handler: &Handler, id: u64) -> Response {
        let mut params = serde_json::json!({
            "workflow": "developer_repo_check",
            "repo_path": repo_root(),
            "timeout_secs": 30
        });
        let token = approval_token_for(handler, id + 10_000, &params).await;
        params["approval_token"] = serde_json::Value::String(token);
        handler
            .dispatch(Request {
                id,
                method: "actions.execute".to_string(),
                params,
            })
            .await
    }

    #[tokio::test]
    async fn runtime_status_works() {
        let handler = test_handler();
        let req = Request {
            id: 30,
            method: "runtime.status".to_string(),
            params: serde_json::Value::Null,
        };
        let resp = handler.dispatch(req).await;
        assert!(
            resp.error.is_none(),
            "runtime.status failed: {:?}",
            resp.error
        );
        let result = resp.result.unwrap();
        assert_eq!(result["runtime"], "dev-local");
        assert_eq!(result["bridge"], "ready");
        assert_eq!(result["daemon_required"], true);
    }

    #[tokio::test]
    async fn tools_capabilities_include_developer_workflow() {
        let handler = test_handler();
        let req = Request {
            id: 31,
            method: "tools.capabilities".to_string(),
            params: serde_json::Value::Null,
        };
        let resp = handler.dispatch(req).await;
        assert!(resp.error.is_none());
        let workflows = resp.result.unwrap()["workflows"]
            .as_array()
            .unwrap()
            .clone();
        assert!(
            workflows
                .iter()
                .any(|workflow| workflow["id"] == "developer_repo_check")
        );
    }

    #[tokio::test]
    async fn actions_execute_refuses_unapproved_execution() {
        let handler = test_handler();
        let req = Request {
            id: 32,
            method: "actions.execute".to_string(),
            params: serde_json::json!({
                "workflow": "developer_repo_check",
                "repo_path": repo_root(),
                "approved": true
            }),
        };
        let resp = handler.dispatch(req).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("approval"));
    }

    #[tokio::test]
    async fn actions_plan_is_preview_only() {
        let handler = test_handler();
        let resp = handler
            .dispatch(Request {
                id: 32_010,
                method: "actions.plan".to_string(),
                params: serde_json::json!({
                    "workflow": "developer_repo_check",
                    "repo_path": repo_root(),
                    "timeout_secs": 30
                }),
            })
            .await;
        assert!(resp.error.is_none(), "plan failed: {:?}", resp.error);
        let result = resp.result.unwrap();
        assert_eq!(result["requires_approval"], true);
        assert_eq!(result["approval"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn actions_approve_requires_bridge_auth_and_user_confirmation() {
        let handler = test_handler();
        let base = serde_json::json!({
            "workflow": "developer_repo_check",
            "repo_path": repo_root(),
            "timeout_secs": 30
        });

        let no_auth = handler
            .dispatch(Request {
                id: 32_020,
                method: "actions.approve".to_string(),
                params: base.clone(),
            })
            .await;
        assert!(no_auth.error.is_some());
        assert!(no_auth.error.unwrap().message.contains("confirmation"));

        let mut no_token = base.clone();
        no_token["user_confirmed"] = serde_json::Value::Bool(true);
        let missing_token = handler
            .dispatch(Request {
                id: 32_021,
                method: "actions.approve".to_string(),
                params: no_token,
            })
            .await;
        assert!(missing_token.error.is_some());
        assert!(missing_token
            .error
            .unwrap()
            .message
            .contains("bridge auth"));

        let mut wrong_token = base.clone();
        wrong_token["user_confirmed"] = serde_json::Value::Bool(true);
        wrong_token["bridge_auth_token"] = serde_json::Value::String("wrong".to_string());
        let wrong = handler
            .dispatch(Request {
                id: 32_022,
                method: "actions.approve".to_string(),
                params: wrong_token,
            })
            .await;
        assert!(wrong.error.is_some());
        assert!(wrong.error.unwrap().message.contains("bridge auth"));
    }

    #[tokio::test]
    async fn actions_execute_rejects_reused_or_mismatched_approval() {
        let handler = test_handler();
        let params = serde_json::json!({
            "workflow": "developer_repo_check",
            "repo_path": repo_root(),
            "timeout_secs": 30
        });

        let token = approval_token_for(&handler, 32_100, &params).await;
        let mut mismatched = params.clone();
        mismatched["timeout_secs"] = serde_json::json!(31);
        mismatched["approval_token"] = serde_json::Value::String(token.clone());
        let mismatch = handler
            .dispatch(Request {
                id: 32_101,
                method: "actions.execute".to_string(),
                params: mismatched,
            })
            .await;
        assert!(mismatch.error.is_some());
        assert!(
            mismatch
                .error
                .unwrap()
                .message
                .contains("different execution request")
        );

        let mut reuse_after_mismatch = params.clone();
        reuse_after_mismatch["approval_token"] = serde_json::Value::String(token);
        let reused = handler
            .dispatch(Request {
                id: 32_102,
                method: "actions.execute".to_string(),
                params: reuse_after_mismatch,
            })
            .await;
        assert!(reused.error.is_some());
        assert!(reused.error.unwrap().message.contains("already used"));

        let mut approved = params;
        let token = approval_token_for(&handler, 32_103, &approved).await;
        approved["approval_token"] = serde_json::Value::String(token.clone());
        let first = handler
            .dispatch(Request {
                id: 32_104,
                method: "actions.execute".to_string(),
                params: approved.clone(),
            })
            .await;
        assert!(first.error.is_none(), "execute failed: {:?}", first.error);

        let second = handler
            .dispatch(Request {
                id: 32_105,
                method: "actions.execute".to_string(),
                params: approved,
            })
            .await;
        assert!(second.error.is_some());
        assert!(second.error.unwrap().message.contains("already used"));
    }

    #[tokio::test]
    async fn developer_workflow_records_terminal_timeline_receipt() {
        let handler = test_handler();
        let resp = execute_developer_repo_check(&handler, 33).await;
        assert!(resp.error.is_none(), "execute failed: {:?}", resp.error);
        let receipt = resp.result.unwrap();
        assert!(
            receipt["timeline_id"].as_str().unwrap().starts_with("tl-"),
            "receipt should include a timeline id"
        );
        assert_eq!(receipt["reversibility"]["undo_available"], false);
        assert_eq!(receipt["learning"]["observed"], true);

        let recent = handler
            .dispatch(Request {
                id: 34,
                method: "timeline.recent".to_string(),
                params: serde_json::json!({ "limit": 1 }),
            })
            .await;
        assert!(recent.error.is_none());
        let actions = recent.result.unwrap().as_array().unwrap().clone();
        assert_eq!(actions.len(), 1);
        assert_ne!(actions[0]["status"], "pending");
        assert_eq!(actions[0]["action_type"], "developer.workflow.repo_check");
        assert!(
            actions[0]["outputs_summary"]["workflow"]
                .as_str()
                .unwrap()
                .contains("developer_repo_check")
        );
    }

    #[tokio::test]
    async fn focus_mode_blocks_workflow_learning_observation() {
        let handler = test_handler();
        let focus = handler
            .dispatch(Request {
                id: 35,
                method: "mode.set".to_string(),
                params: serde_json::json!({ "window_id": "win-focus", "mode": "Focus" }),
            })
            .await;
        assert!(focus.error.is_none());

        let resp = execute_developer_repo_check(&handler, 36).await;
        assert!(resp.error.is_none(), "execute failed: {:?}", resp.error);
        let receipt = resp.result.unwrap();
        assert_eq!(receipt["learning"]["observed"], false);
        assert_eq!(receipt["learning"]["blocked_reason"], "focus_mode");
    }

    #[tokio::test]
    async fn developer_workflow_can_be_observed_and_accepted_to_practice_only() {
        let handler = test_handler();
        for id in 40..43 {
            let resp = execute_developer_repo_check(&handler, id).await;
            assert!(resp.error.is_none(), "execute failed: {:?}", resp.error);
        }

        let detect = handler
            .dispatch(Request {
                id: 44,
                method: "learning.detect".to_string(),
                params: serde_json::Value::Null,
            })
            .await;
        assert!(detect.error.is_none(), "detect failed: {:?}", detect.error);
        let detect_result = detect.result.unwrap();
        let suggestions = detect_result["suggestions"].as_array().unwrap();
        assert!(
            suggestions.iter().any(|s| s["description"]
                .as_str()
                .unwrap()
                .contains("developer_repo_check")),
            "workflow episodes should surface a developer workflow candidate: {suggestions:?}"
        );
        let suggestion_id = suggestions[0]["id"].as_str().unwrap().to_string();

        let accept = handler
            .dispatch(Request {
                id: 45,
                method: "learning.accept".to_string(),
                params: serde_json::json!({ "suggestion_id": suggestion_id }),
            })
            .await;
        assert!(accept.error.is_none(), "accept failed: {:?}", accept.error);
        let accepted = accept.result.unwrap();
        assert_eq!(accepted["new_stage"], "practicing");
        assert_ne!(accepted["new_stage"], "automated");
    }

    #[tokio::test]
    async fn mode_get_missing_window_id() {
        let handler = test_handler();
        let req = Request {
            id: 20,
            method: "mode.get".to_string(),
            params: serde_json::json!({}),
        };
        let resp = handler.dispatch(req).await;
        assert!(resp.error.is_some());
        assert!(resp.error.unwrap().message.contains("window_id"));
    }

    #[tokio::test]
    async fn timeline_undo_missing_action_id() {
        let handler = test_handler();
        let req = Request {
            id: 21,
            method: "timeline.undo".to_string(),
            params: serde_json::json!({}),
        };
        let resp = handler.dispatch(req).await;
        assert!(resp.error.is_some());
        assert!(resp.error.unwrap().message.contains("action_id"));
    }
}
