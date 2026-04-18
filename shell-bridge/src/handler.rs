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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::RwLock;
use tracing::{info, warn};

use die_inference::router::Router;
use die_inference::InferenceRequest;
use die_orchestrator::timeline::Timeline;
use delphi_services::learning::Suggestion;
use semantic_fs::indexer::Indexer;

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
///     Arc::new(RwLock::new(Vec::new())),
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
    /// Learning suggestions (shared with D-Bus LearningService).
    suggestions: Arc<RwLock<Vec<Suggestion>>>,
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
    ///     Arc::new(RwLock::new(Vec::new())),
    /// );
    /// ```
    #[must_use]
    pub fn new(
        router: Arc<RwLock<Router>>,
        indexer: Arc<Mutex<Indexer>>,
        modes: Arc<RwLock<HashMap<String, String>>>,
        timeline: Arc<Mutex<Timeline>>,
        suggestions: Arc<RwLock<Vec<Suggestion>>>,
    ) -> Self {
        Self {
            router,
            indexer,
            modes,
            timeline,
            suggestions,
        }
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
    ///     Arc::new(RwLock::new(Vec::new())),
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
            // ── Inference ──────────────────────────────────
            "inference.query" => self.handle_inference_query(req.id, &req.params).await,
            "inference.status" => self.handle_inference_status(req.id).await,

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

// ── Inference handlers ─────────────────────────────────────────

impl Handler {
    /// Handle `inference.query` — route a prompt through the inference engine.
    async fn handle_inference_query(
        &self,
        id: u64,
        params: &serde_json::Value,
    ) -> Response {
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

        let router = self.router.read().await;
        let req = InferenceRequest {
            input: prompt,
            max_tokens,
            sensitive,
        };

        match router.route(req).await {
            Ok(resp) => Response::ok(
                id,
                serde_json::json!({
                    "output": resp.output,
                    "tier": format!("{:?}", resp.tier),
                    "model_id": resp.model_id,
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
}

// ── File search handlers ───────────────────────────────────────

impl Handler {
    /// Handle `file_search.search` — semantic file search.
    async fn handle_file_search(
        &self,
        id: u64,
        params: &serde_json::Value,
    ) -> Response {
        let query = match params.get("query").and_then(|v| v.as_str()) {
            Some(q) => q.to_string(),
            None => return Response::err(id, -32602, "missing required param: query"),
        };

        let limit = params
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as usize;

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
    async fn handle_mode_get(
        &self,
        id: u64,
        params: &serde_json::Value,
    ) -> Response {
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
    async fn handle_mode_set(
        &self,
        id: u64,
        params: &serde_json::Value,
    ) -> Response {
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
    async fn handle_timeline_recent(
        &self,
        id: u64,
        params: &serde_json::Value,
    ) -> Response {
        let limit = params
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(20) as u32;

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
                        })
                    })
                    .collect();
                Response::ok(id, serde_json::json!(json))
            }
            Err(e) => Response::err(id, -1, &e.to_string()),
        }
    }

    /// Handle `timeline.undo` — undo an action by ID.
    async fn handle_timeline_undo(
        &self,
        id: u64,
        params: &serde_json::Value,
    ) -> Response {
        let action_id = match params.get("action_id").and_then(|v| v.as_str()) {
            Some(a) => a.to_string(),
            None => return Response::err(id, -32602, "missing required param: action_id"),
        };

        let tl = match self.timeline.lock() {
            Ok(t) => t,
            Err(e) => return Response::err(id, -1, &format!("lock poisoned: {e}")),
        };

        match tl.undo_action(&action_id) {
            Ok(cmd) => Response::ok(id, serde_json::json!({ "undo_command": cmd })),
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
    /// Handle `learning.suggestions` — get all active suggestions.
    async fn handle_learning_suggestions(&self, id: u64) -> Response {
        let suggestions = self.suggestions.read().await;
        let json: Vec<serde_json::Value> = suggestions
            .iter()
            .map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "description": s.description,
                    "confidence": s.confidence,
                    "observed_count": s.observed_count,
                })
            })
            .collect();
        Response::ok(id, serde_json::json!(json))
    }

    /// Handle `learning.accept` — accept a suggestion.
    async fn handle_learning_accept(
        &self,
        id: u64,
        params: &serde_json::Value,
    ) -> Response {
        let suggestion_id = match params.get("suggestion_id").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return Response::err(id, -32602, "missing required param: suggestion_id"),
        };

        let mut suggestions = self.suggestions.write().await;
        let before = suggestions.len();
        suggestions.retain(|s| s.id != suggestion_id);

        if suggestions.len() == before {
            return Response::err(
                id,
                -1,
                &format!("suggestion not found: {suggestion_id}"),
            );
        }

        Response::ok(id, serde_json::json!({ "accepted": suggestion_id }))
    }

    /// Handle `learning.dismiss` — dismiss a suggestion.
    async fn handle_learning_dismiss(
        &self,
        id: u64,
        params: &serde_json::Value,
    ) -> Response {
        let suggestion_id = match params.get("suggestion_id").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return Response::err(id, -32602, "missing required param: suggestion_id"),
        };

        let mut suggestions = self.suggestions.write().await;
        let before = suggestions.len();
        suggestions.retain(|s| s.id != suggestion_id);

        if suggestions.len() == before {
            return Response::err(
                id,
                -1,
                &format!("suggestion not found: {suggestion_id}"),
            );
        }

        Response::ok(id, serde_json::json!({ "dismissed": suggestion_id }))
    }

    /// Handle `learning.count` — get active suggestion count.
    async fn handle_learning_count(&self, id: u64) -> Response {
        let suggestions = self.suggestions.read().await;
        Response::ok(
            id,
            serde_json::json!({ "count": suggestions.len() }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a handler with default empty services.
    fn test_handler() -> Handler {
        Handler::new(
            Arc::new(RwLock::new(Router::new())),
            Arc::new(Mutex::new(Indexer::in_memory().unwrap())),
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(Mutex::new(Timeline::in_memory().unwrap())),
            Arc::new(RwLock::new(Vec::new())),
        )
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
    async fn learning_accept_existing() {
        let suggestions = vec![Suggestion {
            id: "sug-001".to_string(),
            description: "Auto-archive reports".to_string(),
            confidence: 0.9,
            observed_count: 5,
        }];
        let handler = Handler::new(
            Arc::new(RwLock::new(Router::new())),
            Arc::new(Mutex::new(Indexer::in_memory().unwrap())),
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(Mutex::new(Timeline::in_memory().unwrap())),
            Arc::new(RwLock::new(suggestions)),
        );

        // Verify suggestion exists
        let count_req = Request {
            id: 17,
            method: "learning.count".to_string(),
            params: serde_json::Value::Null,
        };
        let resp = handler.dispatch(count_req).await;
        assert_eq!(resp.result.unwrap()["count"], 1);

        // Accept it
        let accept_req = Request {
            id: 18,
            method: "learning.accept".to_string(),
            params: serde_json::json!({ "suggestion_id": "sug-001" }),
        };
        let resp = handler.dispatch(accept_req).await;
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap()["accepted"], "sug-001");

        // Verify removed
        let count_req = Request {
            id: 19,
            method: "learning.count".to_string(),
            params: serde_json::Value::Null,
        };
        let resp = handler.dispatch(count_req).await;
        assert_eq!(resp.result.unwrap()["count"], 0);
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
