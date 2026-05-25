// SPDX-License-Identifier: MIT

//! D-Bus Goals interface.
//!
//! Exposes the persistent goal graph over D-Bus. The shell uses this to
//! create, update, and query goals, plus request timeline estimates and
//! find stale or deadline-approaching goals.
//!
//! Interface: `org.delphi.Goals`
//!
//! # Signal emission
//!
//! All four signals (`GoalCreated`, `GoalCompleted`, `GoalDeadlineApproaching`,
//! `GoalStale`) are **declared** here so they appear in the D-Bus introspection
//! XML and external subscribers can register for them. **Emission** is done by
//! the orchestrator daemon, which:
//!
//! - Calls a method on this service
//! - Observes the result
//! - Uses an [`zbus::object_server::InterfaceRef`] to obtain a `SignalEmitter`
//! - Calls the generated emission method on the emitter
//!
//! This keeps the service wrapper pure (unit-testable without a live D-Bus
//! connection) while preserving the complete D-Bus surface.
//!
//! Uses `std::sync::Mutex` (not `tokio::sync`) because `rusqlite::Connection`
//! is `!Send` across await points — see CLAUDE.md Section 3 "D-Bus Service
//! Pattern" rule 6.

use std::str::FromStr;
use std::sync::{Arc, Mutex};

use tracing::info;
use zbus::object_server::SignalEmitter;

use die_orchestrator::goals::{
    DeadlineRisk, Goal, GoalPatch, GoalStore, GoalTimeline, Priority, TimelineBasis,
};

/// D-Bus object path for the Goals interface.
pub const PATH: &str = "/org/delphi/Goals";

/// Sentinel used over D-Bus to mean "no parent goal".
///
/// SQLite `AUTOINCREMENT` ids always start at 1, so 0 is safely unused and
/// avoids the need to introduce a wire-level optional type.
const NO_PARENT: i64 = 0;

/// Goals D-Bus service.
///
/// Wraps the orchestrator [`GoalStore`] and exposes it over D-Bus.
///
/// # Examples
///
/// ```
/// use delphi_services::goals::GoalsService;
/// use die_orchestrator::goals::GoalStore;
/// use std::sync::{Arc, Mutex};
///
/// let store = Arc::new(Mutex::new(GoalStore::in_memory().unwrap()));
/// let svc = GoalsService::new(store);
/// ```
pub struct GoalsService {
    store: Arc<Mutex<GoalStore>>,
}

impl GoalsService {
    /// Create a new goals service.
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::goals::GoalsService;
    /// use die_orchestrator::goals::GoalStore;
    /// use std::sync::{Arc, Mutex};
    ///
    /// let _svc = GoalsService::new(
    ///     Arc::new(Mutex::new(GoalStore::in_memory().unwrap())),
    /// );
    /// ```
    #[must_use]
    pub fn new(store: Arc<Mutex<GoalStore>>) -> Self {
        Self { store }
    }
}

#[zbus::interface(name = "org.delphi.Goals")]
impl GoalsService {
    /// Create a new goal. Returns the new goal id.
    ///
    /// - `title` — required, non-empty.
    /// - `description` — may be empty.
    /// - `priority` — one of `"low"`, `"medium"` (or `"med"`), `"high"`,
    ///   `"critical"` (or `"crit"`), case-insensitive; or the digits
    ///   `"1"`..`"4"`.
    /// - `parent_id` — a positive goal id to set a parent, or `0` for no
    ///   parent.
    /// - `deadline_rfc3339` — an RFC 3339 UTC timestamp (e.g.
    ///   `"2026-05-01T12:00:00Z"`), or the empty string for no deadline.
    ///
    /// If the deadline is provided, it is set in a second step via
    /// [`GoalStore::update_goal`]. If that second step fails (rare — only on
    /// SQLite error), the goal still exists without the deadline and an error
    /// is returned; the caller may retry setting the deadline.
    async fn create_goal(
        &self,
        title: String,
        description: String,
        priority: String,
        parent_id: i64,
        deadline_rfc3339: String,
    ) -> zbus::fdo::Result<i64> {
        info!(title = %title, priority = %priority, "D-Bus create_goal");
        crate::limits::ensure_within(&title, crate::limits::MAX_STRING_BYTES, "title")?;
        crate::limits::ensure_within(&description, crate::limits::MAX_STRING_BYTES, "description")?;
        let priority = Priority::from_str(&priority)
            .map_err(|e| crate::error::map_orchestrator("create goal", e))?;
        let parent = if parent_id == NO_PARENT {
            None
        } else {
            Some(parent_id)
        };
        let deadline = die_orchestrator::goals::parse_optional_deadline_rfc3339(&deadline_rfc3339)
            .map_err(|e| crate::error::map_orchestrator("create goal", e))?;

        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let id = store
            .create_goal(&title, &description, priority, parent)
            .map_err(|e| crate::error::map_orchestrator("goal store operation failed", e))?;

        if let Some(dt) = deadline {
            let patch = GoalPatch {
                deadline: Some(Some(dt)),
                ..Default::default()
            };
            store
                .update_goal(id, patch)
                .map_err(|e| crate::error::map_orchestrator("goal store operation failed", e))?;
        }
        Ok(id)
    }

    /// Update a subset of a goal's fields via a JSON patch.
    ///
    /// The patch is a JSON object. Only keys that are **present** are
    /// updated — keys that are absent leave the field unchanged.
    ///
    /// | Key           | JSON type           | Meaning                                  |
    /// |---------------|---------------------|------------------------------------------|
    /// | `title`       | string              | Replace title.                           |
    /// | `description` | string              | Replace description.                     |
    /// | `priority`    | string              | Replace priority (see `create_goal`).    |
    /// | `status`      | string              | `active`/`paused`/`completed`/`archived`.|
    /// | `deadline`    | string or `null`    | Set to RFC 3339 string, or clear (null). |
    /// | `parent`      | integer or `null`   | Set to new parent id, or clear (null).   |
    ///
    /// An empty object `{}` is a valid no-op patch.
    async fn update_goal(&self, id: i64, patch_json: String) -> zbus::fdo::Result<()> {
        info!(goal_id = id, "D-Bus update_goal");
        crate::limits::ensure_within(&patch_json, crate::limits::MAX_STRING_BYTES, "patch_json")?;
        let patch = GoalPatch::from_json(&patch_json)
            .map_err(|e| crate::error::map_orchestrator("update goal", e))?;
        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        store
            .update_goal(id, patch)
            .map_err(|e| crate::error::map_orchestrator("goal store operation failed", e))
    }

    /// Record progress on a goal.
    ///
    /// `progress` must be in `0..=100`. A value `> 100` is **rejected** with a
    /// typed `InvalidArgs` validation error — it is no longer silently clamped
    /// (SVC-9: silent clamping hid caller bugs; the wire contract now surfaces
    /// out-of-range input instead of masking it).
    async fn update_progress(&self, id: i64, progress: u32) -> zbus::fdo::Result<()> {
        info!(goal_id = id, progress, "D-Bus update_progress");
        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        store
            .update_progress(id, progress)
            .map_err(|e| crate::error::map_orchestrator("goal store operation failed", e))
    }

    /// Fetch a single goal as JSON.
    async fn get_goal(&self, id: i64) -> zbus::fdo::Result<String> {
        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let goal = store
            .get_goal(id)
            .map_err(|e| crate::error::map_orchestrator("goal store operation failed", e))?;
        serde_json::to_string(&goal_to_json(&goal))
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
    }

    /// List all active goals as a JSON array, newest first.
    async fn list_active(&self) -> zbus::fdo::Result<String> {
        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let goals = store
            .list_active()
            .map_err(|e| crate::error::map_orchestrator("goal store operation failed", e))?;
        serialize_goal_list(&goals)
    }

    /// List direct children of a parent goal as a JSON array, newest first.
    async fn list_children(&self, parent_id: i64) -> zbus::fdo::Result<String> {
        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let goals = store
            .list_children(parent_id)
            .map_err(|e| crate::error::map_orchestrator("goal store operation failed", e))?;
        serialize_goal_list(&goals)
    }

    /// List active goals with no activity newer than `inactive_days` ago.
    async fn find_stale(&self, inactive_days: u32) -> zbus::fdo::Result<String> {
        info!(inactive_days, "D-Bus find_stale");
        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let goals = store
            .find_stale(inactive_days)
            .map_err(|e| crate::error::map_orchestrator("goal store operation failed", e))?;
        serialize_goal_list(&goals)
    }

    /// List active goals whose deadline falls within the next `within_days`.
    async fn find_approaching_deadline(&self, within_days: u32) -> zbus::fdo::Result<String> {
        info!(within_days, "D-Bus find_approaching_deadline");
        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let goals = store
            .find_approaching_deadline(within_days)
            .map_err(|e| crate::error::map_orchestrator("goal store operation failed", e))?;
        serialize_goal_list(&goals)
    }

    /// Request a timeline estimate for a goal.
    ///
    /// Pace encoding:
    /// - If `sessions_per_week <= 0.0` or `hours_per_session <= 0.0`, the
    ///   estimator falls back to the priority heuristic and
    ///   `work_hours_remaining` is ignored.
    /// - Otherwise, the estimator uses the learned pace and
    ///   `work_hours_remaining`.
    async fn get_timeline(
        &self,
        id: i64,
        sessions_per_week: f64,
        hours_per_session: f64,
        work_hours_remaining: f64,
    ) -> zbus::fdo::Result<String> {
        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let timeline = store
            .estimate_timeline_from_raw_pace(
                id,
                sessions_per_week,
                hours_per_session,
                work_hours_remaining,
            )
            .map_err(|e| crate::error::map_orchestrator("estimate timeline", e))?;
        serde_json::to_string(&timeline_to_json(&timeline))
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
    }

    /// Total goal count across all statuses.
    async fn count(&self) -> zbus::fdo::Result<u32> {
        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let n = store
            .count()
            .map_err(|e| crate::error::map_orchestrator("goal store operation failed", e))?;
        Ok(n as u32)
    }

    // ── signals (declared only; emission handled by the orchestrator daemon) ──

    /// Emitted when a new goal is created.
    ///
    /// `timestamp` is UTC epoch seconds.
    #[zbus(signal)]
    async fn goal_created(
        signal_emitter: &SignalEmitter<'_>,
        id: i64,
        timestamp: i64,
    ) -> zbus::Result<()>;

    /// Emitted when a goal transitions to
    /// [`GoalStatus::Completed`](die_orchestrator::goals::GoalStatus::Completed).
    ///
    /// `timestamp` is UTC epoch seconds.
    #[zbus(signal)]
    async fn goal_completed(
        signal_emitter: &SignalEmitter<'_>,
        id: i64,
        timestamp: i64,
    ) -> zbus::Result<()>;

    /// Emitted periodically by the orchestrator daemon for each active goal
    /// whose deadline falls within a configured window.
    ///
    /// `days_remaining` is the number of days until the deadline at the
    /// time of emission. `timestamp` is UTC epoch seconds.
    #[zbus(signal)]
    async fn goal_deadline_approaching(
        signal_emitter: &SignalEmitter<'_>,
        id: i64,
        days_remaining: u32,
        timestamp: i64,
    ) -> zbus::Result<()>;

    /// Emitted periodically by the orchestrator daemon for each active goal
    /// that has had no activity in longer than a configured threshold.
    ///
    /// `days_inactive` is the number of days since the last activity (or
    /// creation, if there has been no activity). `timestamp` is UTC epoch
    /// seconds.
    #[zbus(signal)]
    async fn goal_stale(
        signal_emitter: &SignalEmitter<'_>,
        id: i64,
        days_inactive: u32,
        timestamp: i64,
    ) -> zbus::Result<()>;
}

// ────────────────────────────────────────────────────────────────────
// JSON helpers
// ────────────────────────────────────────────────────────────────────

fn goal_to_json(g: &Goal) -> serde_json::Value {
    serde_json::json!({
        "id": g.id,
        "title": g.title,
        "description": g.description,
        "deadline": g.deadline.map(|d| d.to_rfc3339()),
        "priority": priority_as_str(g.priority),
        "parent_goal": g.parent_goal,
        "status": g.status.as_str(),
        "created_at": g.created_at.to_rfc3339(),
        "updated_at": g.updated_at.to_rfc3339(),
        "last_activity": g.last_activity.map(|d| d.to_rfc3339()),
        "progress_estimate": g.progress_estimate,
    })
}

fn priority_as_str(p: Priority) -> &'static str {
    match p {
        Priority::Low => "low",
        Priority::Medium => "medium",
        Priority::High => "high",
        Priority::Critical => "critical",
    }
}

fn timeline_basis_as_str(b: TimelineBasis) -> &'static str {
    match b {
        TimelineBasis::PriorityHeuristic => "priority_heuristic",
        TimelineBasis::Learned => "learned",
    }
}

fn deadline_risk_as_str(r: DeadlineRisk) -> &'static str {
    match r {
        DeadlineRisk::OnTrack => "on_track",
        DeadlineRisk::Tight => "tight",
        DeadlineRisk::AtRisk => "at_risk",
        DeadlineRisk::Missed => "missed",
        DeadlineRisk::NoDeadline => "no_deadline",
    }
}

fn timeline_to_json(t: &GoalTimeline) -> serde_json::Value {
    serde_json::json!({
        "goal_id": t.goal_id,
        "estimated_days": t.estimated_days,
        "estimated_completion": t.estimated_completion.to_rfc3339(),
        "basis": timeline_basis_as_str(t.basis),
        "deadline_risk": deadline_risk_as_str(t.deadline_risk),
    })
}

fn serialize_goal_list(goals: &[Goal]) -> zbus::fdo::Result<String> {
    let arr: Vec<serde_json::Value> = goals.iter().map(goal_to_json).collect();
    serde_json::to_string(&arr)
        .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn mk_svc() -> GoalsService {
        let store = Arc::new(Mutex::new(GoalStore::in_memory().unwrap()));
        GoalsService::new(store)
    }

    #[test]
    fn path_is_valid() {
        assert!(PATH.starts_with("/org/delphi"));
        assert!(PATH.ends_with("Goals"));
    }

    #[test]
    fn service_creation() {
        let _ = mk_svc();
    }

    #[tokio::test]
    async fn count_starts_at_zero() {
        let svc = mk_svc();
        assert_eq!(svc.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn create_goal_returns_positive_id() {
        let svc = mk_svc();
        let id = svc
            .create_goal(
                "Ship v1".to_string(),
                String::new(),
                "high".to_string(),
                0,
                String::new(),
            )
            .await
            .unwrap();
        assert!(id > 0);
        assert_eq!(svc.count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn create_goal_with_parent_and_deadline() {
        let svc = mk_svc();
        let parent = svc
            .create_goal(
                "Book".to_string(),
                String::new(),
                "medium".to_string(),
                0,
                String::new(),
            )
            .await
            .unwrap();
        let child = svc
            .create_goal(
                "Chapter 1".to_string(),
                "draft".to_string(),
                "high".to_string(),
                parent,
                "2026-06-01T00:00:00Z".to_string(),
            )
            .await
            .unwrap();
        assert!(child > parent);

        let goal_json = svc.get_goal(child).await.unwrap();
        assert!(goal_json.contains(r#""deadline":"2026-06-01T00:00:00+00:00""#));
        assert!(goal_json.contains(&format!(r#""parent_goal":{parent}"#)));
    }

    #[tokio::test]
    async fn create_goal_invalid_priority_rejected() {
        let svc = mk_svc();
        let err = svc
            .create_goal(
                "x".to_string(),
                String::new(),
                "ultra".to_string(),
                0,
                String::new(),
            )
            .await
            .unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("priority"), "got: {msg}");
    }

    #[tokio::test]
    async fn create_goal_invalid_deadline_rejected() {
        let svc = mk_svc();
        let err = svc
            .create_goal(
                "x".to_string(),
                String::new(),
                "low".to_string(),
                0,
                "not-a-timestamp".to_string(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("deadline"));
    }

    #[tokio::test]
    async fn create_goal_empty_title_rejected() {
        let svc = mk_svc();
        let err = svc
            .create_goal(
                String::new(),
                String::new(),
                "low".to_string(),
                0,
                String::new(),
            )
            .await
            .unwrap_err();
        // SVC-9: the empty-title rejection is a domain `Validation` whose fields
        // are `&'static str`, so the transport surfaces them as a typed
        // `InvalidArgs` ("bad argument") rather than a content-free `Failed`.
        // No caller content / path can ride the static field+reason.
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
        assert!(
            err.to_string()
                .ends_with("validation failed: title (must not be empty)"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn get_goal_returns_json_with_fields() {
        let svc = mk_svc();
        let id = svc
            .create_goal(
                "Research".to_string(),
                "literature review".to_string(),
                "medium".to_string(),
                0,
                String::new(),
            )
            .await
            .unwrap();
        let json = svc.get_goal(id).await.unwrap();
        assert!(json.contains(&format!(r#""id":{id}"#)));
        assert!(json.contains(r#""title":"Research""#));
        assert!(json.contains(r#""description":"literature review""#));
        assert!(json.contains(r#""priority":"medium""#));
        assert!(json.contains(r#""status":"active""#));
        assert!(json.contains(r#""progress_estimate":0"#));
        // No deadline on this goal.
        assert!(json.contains(r#""deadline":null"#));
        assert!(json.contains(r#""last_activity":null"#));
    }

    #[tokio::test]
    async fn list_active_returns_empty_array_initially() {
        let svc = mk_svc();
        let json = svc.list_active().await.unwrap();
        assert_eq!(json, "[]");
    }

    #[tokio::test]
    async fn list_active_returns_created_goals() {
        let svc = mk_svc();
        svc.create_goal(
            "a".to_string(),
            String::new(),
            "low".to_string(),
            0,
            String::new(),
        )
        .await
        .unwrap();
        svc.create_goal(
            "b".to_string(),
            String::new(),
            "low".to_string(),
            0,
            String::new(),
        )
        .await
        .unwrap();
        let json = svc.list_active().await.unwrap();
        assert!(json.starts_with('['));
        assert!(json.contains(r#""title":"a""#));
        assert!(json.contains(r#""title":"b""#));
    }

    #[tokio::test]
    async fn list_children_filters_by_parent() {
        let svc = mk_svc();
        let parent = svc
            .create_goal(
                "parent".to_string(),
                String::new(),
                "low".to_string(),
                0,
                String::new(),
            )
            .await
            .unwrap();
        let _other = svc
            .create_goal(
                "other".to_string(),
                String::new(),
                "low".to_string(),
                0,
                String::new(),
            )
            .await
            .unwrap();
        svc.create_goal(
            "child".to_string(),
            String::new(),
            "low".to_string(),
            parent,
            String::new(),
        )
        .await
        .unwrap();

        let json = svc.list_children(parent).await.unwrap();
        assert!(json.contains(r#""title":"child""#));
        assert!(!json.contains(r#""title":"other""#));
        assert!(!json.contains(r#""title":"parent""#));
    }

    #[tokio::test]
    async fn update_goal_applies_title_patch() {
        let svc = mk_svc();
        let id = svc
            .create_goal(
                "old".to_string(),
                String::new(),
                "low".to_string(),
                0,
                String::new(),
            )
            .await
            .unwrap();
        svc.update_goal(id, r#"{"title":"new"}"#.to_string())
            .await
            .unwrap();
        let json = svc.get_goal(id).await.unwrap();
        assert!(json.contains(r#""title":"new""#));
    }

    #[tokio::test]
    async fn update_goal_clear_deadline_with_null() {
        let svc = mk_svc();
        let id = svc
            .create_goal(
                "x".to_string(),
                String::new(),
                "low".to_string(),
                0,
                "2026-05-01T00:00:00Z".to_string(),
            )
            .await
            .unwrap();
        svc.update_goal(id, r#"{"deadline":null}"#.to_string())
            .await
            .unwrap();
        let json = svc.get_goal(id).await.unwrap();
        assert!(json.contains(r#""deadline":null"#));
    }

    #[tokio::test]
    async fn update_goal_empty_patch_is_noop() {
        let svc = mk_svc();
        let id = svc
            .create_goal(
                "x".to_string(),
                String::new(),
                "low".to_string(),
                0,
                String::new(),
            )
            .await
            .unwrap();
        svc.update_goal(id, "{}".to_string()).await.unwrap();
        let json = svc.get_goal(id).await.unwrap();
        assert!(json.contains(r#""title":"x""#));
    }

    #[tokio::test]
    async fn update_goal_invalid_json_rejected() {
        let svc = mk_svc();
        let id = svc
            .create_goal(
                "x".to_string(),
                String::new(),
                "low".to_string(),
                0,
                String::new(),
            )
            .await
            .unwrap();
        let err = svc
            .update_goal(id, "not json".to_string())
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("json"));
    }

    #[tokio::test]
    async fn update_goal_non_object_json_rejected() {
        let svc = mk_svc();
        let id = svc
            .create_goal(
                "x".to_string(),
                String::new(),
                "low".to_string(),
                0,
                String::new(),
            )
            .await
            .unwrap();
        let err = svc.update_goal(id, "42".to_string()).await.unwrap_err();
        assert!(err.to_string().to_lowercase().contains("object"));
    }

    #[tokio::test]
    async fn update_goal_nonexistent_id_fails() {
        let svc = mk_svc();
        let err = svc
            .update_goal(9999, r#"{"title":"ghost"}"#.to_string())
            .await
            .unwrap_err();
        // SVC-9: a missing goal is a domain `NotFound { entity: "goal" }`. The
        // entity label is a static string (never the caller-supplied id), so the
        // transport surfaces it as `InvalidArgs("goal not found")` — typed, and
        // with no id / existence-oracle leak.
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
        assert!(err.to_string().ends_with("goal not found"), "got: {err}");
    }

    #[tokio::test]
    async fn update_goal_sets_status_to_completed() {
        let svc = mk_svc();
        let id = svc
            .create_goal(
                "x".to_string(),
                String::new(),
                "low".to_string(),
                0,
                String::new(),
            )
            .await
            .unwrap();
        svc.update_goal(id, r#"{"status":"completed"}"#.to_string())
            .await
            .unwrap();
        let json = svc.get_goal(id).await.unwrap();
        assert!(json.contains(r#""status":"completed""#));
    }

    #[tokio::test]
    async fn update_progress_stores_value() {
        let svc = mk_svc();
        let id = svc
            .create_goal(
                "x".to_string(),
                String::new(),
                "low".to_string(),
                0,
                String::new(),
            )
            .await
            .unwrap();
        svc.update_progress(id, 45).await.unwrap();
        let json = svc.get_goal(id).await.unwrap();
        assert!(json.contains(r#""progress_estimate":45"#));
    }

    #[tokio::test]
    async fn update_progress_rejects_out_of_range() {
        let svc = mk_svc();
        let id = svc
            .create_goal(
                "x".to_string(),
                String::new(),
                "low".to_string(),
                0,
                String::new(),
            )
            .await
            .unwrap();
        // SVC-9: out-of-range progress is a typed domain `Validation`, not a
        // silent clamp. Assert the rejection is typed and the stored value is
        // left untouched (still the create-time default of 0).
        let err = svc.update_progress(id, 500).await.unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
        assert!(
            err.to_string()
                .ends_with("validation failed: progress (must be between 0 and 100)"),
            "got: {err}"
        );
        let json = svc.get_goal(id).await.unwrap();
        assert!(json.contains(r#""progress_estimate":0"#));
    }

    #[tokio::test]
    async fn find_stale_empty_initially() {
        let svc = mk_svc();
        let json = svc.find_stale(30).await.unwrap();
        assert_eq!(json, "[]");
    }

    #[tokio::test]
    async fn find_approaching_deadline_empty_initially() {
        let svc = mk_svc();
        let json = svc.find_approaching_deadline(7).await.unwrap();
        assert_eq!(json, "[]");
    }

    #[tokio::test]
    async fn find_approaching_deadline_picks_up_upcoming() {
        let svc = mk_svc();
        // Create a goal with a deadline 3 days from now.
        let deadline = (Utc::now() + chrono::Duration::days(3)).to_rfc3339();
        let id = svc
            .create_goal(
                "soon".to_string(),
                String::new(),
                "high".to_string(),
                0,
                deadline,
            )
            .await
            .unwrap();
        let json = svc.find_approaching_deadline(7).await.unwrap();
        assert!(json.contains(&format!(r#""id":{id}"#)));
        assert!(json.contains(r#""title":"soon""#));
    }

    #[tokio::test]
    async fn get_timeline_no_history_uses_priority_heuristic() {
        let svc = mk_svc();
        let id = svc
            .create_goal(
                "x".to_string(),
                String::new(),
                "high".to_string(),
                0,
                String::new(),
            )
            .await
            .unwrap();
        // sessions_per_week <= 0 triggers NoHistory; High → 21 days.
        let json = svc.get_timeline(id, 0.0, 0.0, 0.0).await.unwrap();
        assert!(json.contains(r#""estimated_days":21"#));
        assert!(json.contains(r#""basis":"priority_heuristic""#));
        assert!(json.contains(r#""deadline_risk":"no_deadline""#));
    }

    #[tokio::test]
    async fn get_timeline_learned_uses_pace_and_hours() {
        let svc = mk_svc();
        let id = svc
            .create_goal(
                "x".to_string(),
                String::new(),
                "low".to_string(),
                0,
                String::new(),
            )
            .await
            .unwrap();
        // 20 hours, 2 sessions/week of 4 hours each → 18 days (per TimelineEstimator docs).
        let json = svc.get_timeline(id, 2.0, 4.0, 20.0).await.unwrap();
        assert!(json.contains(r#""estimated_days":18"#));
        assert!(json.contains(r#""basis":"learned""#));
    }

    #[tokio::test]
    async fn get_timeline_nonexistent_goal_fails() {
        let svc = mk_svc();
        let err = svc.get_timeline(9999, 0.0, 0.0, 0.0).await.unwrap_err();
        // SVC-9: the timeline estimator fetches the goal first, so a missing goal
        // is the same domain `NotFound { entity: "goal" }` surfaced as the typed
        // `InvalidArgs("goal not found")` — no id / existence-oracle leak.
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
        assert!(err.to_string().ends_with("goal not found"), "got: {err}");
    }
}
