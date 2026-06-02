// SPDX-License-Identifier: MIT

//! D-Bus Goals interface.
//!
//! Exposes the persistent goal graph over D-Bus.
//!
//! Interface: `org.delphi.Goals`
//!
//! SVC-2: every method enforces authorization via the shared [`AuthGuard`] on
//! its first line. The read methods (`get_goal`, `list_active`, `list_children`,
//! `find_stale`, `find_approaching_deadline`, `get_timeline`, `count`) are
//! Autonomous; `create_goal`/`update_goal`/`update_progress` are Confirm. (The
//! four `#[zbus(signal)]` declarations carry no guard.)
//!
//! Uses `std::sync::Mutex` (not `tokio::sync`) because `rusqlite::Connection`
//! is `!Send` across await points — see CLAUDE.md Section 3 rule 6.

use std::str::FromStr;
use std::sync::{Arc, Mutex};

use tracing::info;
use zbus::message::Header;
use zbus::object_server::SignalEmitter;

use die_orchestrator::goals::{
    DeadlineRisk, Goal, GoalPatch, GoalStore, GoalTimeline, Priority, TimelineBasis,
};

use crate::auth_guard::AuthGuard;

/// D-Bus object path for the Goals interface.
pub const PATH: &str = "/org/delphi/Goals";

/// Sentinel used over D-Bus to mean "no parent goal".
const NO_PARENT: i64 = 0;

/// Goals D-Bus service.
///
/// # Examples
///
/// ```
/// use delphi_services::goals::GoalsService;
/// use delphi_services::auth_guard::AuthGuard;
/// use die_orchestrator::goals::GoalStore;
/// use std::sync::{Arc, Mutex};
///
/// let store = Arc::new(Mutex::new(GoalStore::in_memory().unwrap()));
/// let svc = GoalsService::new(store, Arc::new(AuthGuard::dev_in_memory()));
/// ```
pub struct GoalsService {
    store: Arc<Mutex<GoalStore>>,
    guard: Arc<AuthGuard>,
}

impl GoalsService {
    /// Create a new goals service guarded by the shared [`AuthGuard`].
    #[must_use]
    pub fn new(store: Arc<Mutex<GoalStore>>, guard: Arc<AuthGuard>) -> Self {
        Self { store, guard }
    }
}

#[zbus::interface(name = "org.delphi.Goals")]
impl GoalsService {
    /// Create a new goal. Returns the new goal id. See the field docs in the
    /// repository history; `parent_id == 0` means no parent, empty
    /// `deadline_rfc3339` means no deadline.
    async fn create_goal(
        &self,
        #[zbus(header)] header: Header<'_>,
        title: String,
        description: String,
        priority: String,
        parent_id: i64,
        deadline_rfc3339: String,
    ) -> zbus::fdo::Result<i64> {
        self.guard.enforce("goals.create_goal", &header)?;
        crate::limits::ensure_within(&title, crate::limits::MAX_STRING_BYTES, "title")?;
        crate::limits::ensure_within(&description, crate::limits::MAX_STRING_BYTES, "description")?;
        crate::limits::ensure_within(&priority, crate::limits::MAX_STRING_BYTES, "priority")?;
        crate::limits::ensure_within(
            &deadline_rfc3339,
            crate::limits::MAX_STRING_BYTES,
            "deadline_rfc3339",
        )?;
        info!(title = %title, priority = %priority, "D-Bus create_goal");
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
    async fn update_goal(
        &self,
        #[zbus(header)] header: Header<'_>,
        id: i64,
        patch_json: String,
    ) -> zbus::fdo::Result<()> {
        self.guard.enforce("goals.update_goal", &header)?;
        crate::limits::ensure_within(&patch_json, crate::limits::MAX_STRING_BYTES, "patch_json")?;
        info!(goal_id = id, "D-Bus update_goal");
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

    /// Record progress on a goal. `progress` must be in `0..=100`.
    async fn update_progress(
        &self,
        #[zbus(header)] header: Header<'_>,
        id: i64,
        progress: u32,
    ) -> zbus::fdo::Result<()> {
        self.guard.enforce("goals.update_progress", &header)?;
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
    async fn get_goal(&self, #[zbus(header)] header: Header<'_>, id: i64) -> zbus::fdo::Result<String> {
        self.guard.enforce("goals.get_goal", &header)?;
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
    async fn list_active(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<String> {
        self.guard.enforce("goals.list_active", &header)?;
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
    async fn list_children(
        &self,
        #[zbus(header)] header: Header<'_>,
        parent_id: i64,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("goals.list_children", &header)?;
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
    async fn find_stale(
        &self,
        #[zbus(header)] header: Header<'_>,
        inactive_days: u32,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("goals.find_stale", &header)?;
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
    async fn find_approaching_deadline(
        &self,
        #[zbus(header)] header: Header<'_>,
        within_days: u32,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("goals.find_approaching_deadline", &header)?;
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
    async fn get_timeline(
        &self,
        #[zbus(header)] header: Header<'_>,
        id: i64,
        sessions_per_week: f64,
        hours_per_session: f64,
        work_hours_remaining: f64,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("goals.get_timeline", &header)?;
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
    async fn count(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<u32> {
        self.guard.enforce("goals.count", &header)?;
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

    /// Emitted when a new goal is created. `timestamp` is UTC epoch seconds.
    #[zbus(signal)]
    async fn goal_created(
        signal_emitter: &SignalEmitter<'_>,
        id: i64,
        timestamp: i64,
    ) -> zbus::Result<()>;

    /// Emitted when a goal transitions to Completed. `timestamp` is UTC epoch seconds.
    #[zbus(signal)]
    async fn goal_completed(
        signal_emitter: &SignalEmitter<'_>,
        id: i64,
        timestamp: i64,
    ) -> zbus::Result<()>;

    /// Emitted for each active goal whose deadline falls within a window.
    #[zbus(signal)]
    async fn goal_deadline_approaching(
        signal_emitter: &SignalEmitter<'_>,
        id: i64,
        days_remaining: u32,
        timestamp: i64,
    ) -> zbus::Result<()>;

    /// Emitted for each active goal with no recent activity.
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

    use crate::auth::AuthPolicy;
    use crate::auth_guard::completeness::{
        assert_all_methods_classified, assert_behavioral_covers_all, header_msg as msg,
    };

    fn mk_svc() -> GoalsService {
        mk_svc_with(AuthPolicy::dev())
    }

    fn mk_svc_with(policy: AuthPolicy) -> GoalsService {
        let store = Arc::new(Mutex::new(GoalStore::in_memory().unwrap()));
        let guard = Arc::new(AuthGuard::new(
            policy,
            Arc::new(Mutex::new(fortress::audit::AuditLog::in_memory())),
        ));
        GoalsService::new(store, guard)
    }

    /// Create a goal under a dev guard (helper to keep tests terse).
    async fn make_goal(svc: &GoalsService, title: &str, priority: &str, parent: i64, deadline: &str) -> i64 {
        let m = msg(":1.5");
        svc.create_goal(
            m.header(),
            title.to_string(),
            String::new(),
            priority.to_string(),
            parent,
            deadline.to_string(),
        )
        .await
        .unwrap()
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
        let m = msg(":1.5");
        assert_eq!(svc.count(m.header()).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn create_goal_returns_positive_id() {
        let svc = mk_svc();
        let id = make_goal(&svc, "Ship v1", "high", 0, "").await;
        assert!(id > 0);
        let m = msg(":1.5");
        assert_eq!(svc.count(m.header()).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn create_goal_with_parent_and_deadline() {
        let svc = mk_svc();
        let parent = make_goal(&svc, "Book", "medium", 0, "").await;
        let child = make_goal(&svc, "Chapter 1", "high", parent, "2026-06-01T00:00:00Z").await;
        assert!(child > parent);
        let m = msg(":1.5");
        let goal_json = svc.get_goal(m.header(), child).await.unwrap();
        assert!(goal_json.contains(r#""deadline":"2026-06-01T00:00:00+00:00""#));
        assert!(goal_json.contains(&format!(r#""parent_goal":{parent}"#)));
    }

    #[tokio::test]
    async fn create_goal_invalid_priority_rejected() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let err = svc
            .create_goal(m.header(), "x".to_string(), String::new(), "ultra".to_string(), 0, String::new())
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("priority"));
    }

    #[tokio::test]
    async fn create_goal_invalid_deadline_rejected() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let err = svc
            .create_goal(m.header(), "x".to_string(), String::new(), "low".to_string(), 0, "not-a-timestamp".to_string())
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("deadline"));
    }

    #[tokio::test]
    async fn create_goal_empty_title_rejected() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let err = svc
            .create_goal(m.header(), String::new(), String::new(), "low".to_string(), 0, String::new())
            .await
            .unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
        assert!(
            err.to_string().ends_with("validation failed: title (must not be empty)"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn get_goal_returns_json_with_fields() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let id = svc
            .create_goal(m.header(), "Research".to_string(), "literature review".to_string(), "medium".to_string(), 0, String::new())
            .await
            .unwrap();
        let m = msg(":1.5");
        let json = svc.get_goal(m.header(), id).await.unwrap();
        assert!(json.contains(&format!(r#""id":{id}"#)));
        assert!(json.contains(r#""title":"Research""#));
        assert!(json.contains(r#""description":"literature review""#));
        assert!(json.contains(r#""priority":"medium""#));
        assert!(json.contains(r#""status":"active""#));
        assert!(json.contains(r#""progress_estimate":0"#));
        assert!(json.contains(r#""deadline":null"#));
        assert!(json.contains(r#""last_activity":null"#));
    }

    #[tokio::test]
    async fn list_active_returns_empty_array_initially() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let json = svc.list_active(m.header()).await.unwrap();
        assert_eq!(json, "[]");
    }

    #[tokio::test]
    async fn list_active_returns_created_goals() {
        let svc = mk_svc();
        make_goal(&svc, "a", "low", 0, "").await;
        make_goal(&svc, "b", "low", 0, "").await;
        let m = msg(":1.5");
        let json = svc.list_active(m.header()).await.unwrap();
        assert!(json.starts_with('['));
        assert!(json.contains(r#""title":"a""#));
        assert!(json.contains(r#""title":"b""#));
    }

    #[tokio::test]
    async fn list_children_filters_by_parent() {
        let svc = mk_svc();
        let parent = make_goal(&svc, "parent", "low", 0, "").await;
        let _other = make_goal(&svc, "other", "low", 0, "").await;
        make_goal(&svc, "child", "low", parent, "").await;
        let m = msg(":1.5");
        let json = svc.list_children(m.header(), parent).await.unwrap();
        assert!(json.contains(r#""title":"child""#));
        assert!(!json.contains(r#""title":"other""#));
        assert!(!json.contains(r#""title":"parent""#));
    }

    #[tokio::test]
    async fn update_goal_applies_title_patch() {
        let svc = mk_svc();
        let id = make_goal(&svc, "old", "low", 0, "").await;
        let m = msg(":1.5");
        svc.update_goal(m.header(), id, r#"{"title":"new"}"#.to_string()).await.unwrap();
        let m = msg(":1.5");
        let json = svc.get_goal(m.header(), id).await.unwrap();
        assert!(json.contains(r#""title":"new""#));
    }

    #[tokio::test]
    async fn update_goal_clear_deadline_with_null() {
        let svc = mk_svc();
        let id = make_goal(&svc, "x", "low", 0, "2026-05-01T00:00:00Z").await;
        let m = msg(":1.5");
        svc.update_goal(m.header(), id, r#"{"deadline":null}"#.to_string()).await.unwrap();
        let m = msg(":1.5");
        let json = svc.get_goal(m.header(), id).await.unwrap();
        assert!(json.contains(r#""deadline":null"#));
    }

    #[tokio::test]
    async fn update_goal_empty_patch_is_noop() {
        let svc = mk_svc();
        let id = make_goal(&svc, "x", "low", 0, "").await;
        let m = msg(":1.5");
        svc.update_goal(m.header(), id, "{}".to_string()).await.unwrap();
        let m = msg(":1.5");
        let json = svc.get_goal(m.header(), id).await.unwrap();
        assert!(json.contains(r#""title":"x""#));
    }

    #[tokio::test]
    async fn update_goal_invalid_json_rejected() {
        let svc = mk_svc();
        let id = make_goal(&svc, "x", "low", 0, "").await;
        let m = msg(":1.5");
        let err = svc.update_goal(m.header(), id, "not json".to_string()).await.unwrap_err();
        assert!(err.to_string().to_lowercase().contains("json"));
    }

    #[tokio::test]
    async fn update_goal_non_object_json_rejected() {
        let svc = mk_svc();
        let id = make_goal(&svc, "x", "low", 0, "").await;
        let m = msg(":1.5");
        let err = svc.update_goal(m.header(), id, "42".to_string()).await.unwrap_err();
        assert!(err.to_string().to_lowercase().contains("object"));
    }

    #[tokio::test]
    async fn update_goal_nonexistent_id_fails() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let err = svc.update_goal(m.header(), 9999, r#"{"title":"ghost"}"#.to_string()).await.unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
        assert!(err.to_string().ends_with("goal not found"), "got: {err}");
    }

    #[tokio::test]
    async fn update_goal_sets_status_to_completed() {
        let svc = mk_svc();
        let id = make_goal(&svc, "x", "low", 0, "").await;
        let m = msg(":1.5");
        svc.update_goal(m.header(), id, r#"{"status":"completed"}"#.to_string()).await.unwrap();
        let m = msg(":1.5");
        let json = svc.get_goal(m.header(), id).await.unwrap();
        assert!(json.contains(r#""status":"completed""#));
    }

    #[tokio::test]
    async fn update_progress_stores_value() {
        let svc = mk_svc();
        let id = make_goal(&svc, "x", "low", 0, "").await;
        let m = msg(":1.5");
        svc.update_progress(m.header(), id, 45).await.unwrap();
        let m = msg(":1.5");
        let json = svc.get_goal(m.header(), id).await.unwrap();
        assert!(json.contains(r#""progress_estimate":45"#));
    }

    #[tokio::test]
    async fn update_progress_rejects_out_of_range() {
        let svc = mk_svc();
        let id = make_goal(&svc, "x", "low", 0, "").await;
        let m = msg(":1.5");
        let err = svc.update_progress(m.header(), id, 500).await.unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
        assert!(
            err.to_string().ends_with("validation failed: progress (must be between 0 and 100)"),
            "got: {err}"
        );
        let m = msg(":1.5");
        let json = svc.get_goal(m.header(), id).await.unwrap();
        assert!(json.contains(r#""progress_estimate":0"#));
    }

    #[tokio::test]
    async fn find_stale_empty_initially() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let json = svc.find_stale(m.header(), 30).await.unwrap();
        assert_eq!(json, "[]");
    }

    #[tokio::test]
    async fn find_approaching_deadline_empty_initially() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let json = svc.find_approaching_deadline(m.header(), 7).await.unwrap();
        assert_eq!(json, "[]");
    }

    #[tokio::test]
    async fn find_approaching_deadline_picks_up_upcoming() {
        let svc = mk_svc();
        let deadline = (Utc::now() + chrono::Duration::days(3)).to_rfc3339();
        let id = make_goal(&svc, "soon", "high", 0, &deadline).await;
        let m = msg(":1.5");
        let json = svc.find_approaching_deadline(m.header(), 7).await.unwrap();
        assert!(json.contains(&format!(r#""id":{id}"#)));
        assert!(json.contains(r#""title":"soon""#));
    }

    #[tokio::test]
    async fn get_timeline_no_history_uses_priority_heuristic() {
        let svc = mk_svc();
        let id = make_goal(&svc, "x", "high", 0, "").await;
        let m = msg(":1.5");
        let json = svc.get_timeline(m.header(), id, 0.0, 0.0, 0.0).await.unwrap();
        assert!(json.contains(r#""estimated_days":21"#));
        assert!(json.contains(r#""basis":"priority_heuristic""#));
        assert!(json.contains(r#""deadline_risk":"no_deadline""#));
    }

    #[tokio::test]
    async fn get_timeline_learned_uses_pace_and_hours() {
        let svc = mk_svc();
        let id = make_goal(&svc, "x", "low", 0, "").await;
        let m = msg(":1.5");
        let json = svc.get_timeline(m.header(), id, 2.0, 4.0, 20.0).await.unwrap();
        assert!(json.contains(r#""estimated_days":18"#));
        assert!(json.contains(r#""basis":"learned""#));
    }

    #[tokio::test]
    async fn get_timeline_nonexistent_goal_fails() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let err = svc.get_timeline(m.header(), 9999, 0.0, 0.0, 0.0).await.unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
        assert!(err.to_string().ends_with("goal not found"), "got: {err}");
    }

    /// SVC-6-R2-3: every D-Bus `String` parameter is capped *before* logging,
    /// parsing, or storage (after the SVC-2 guard).
    #[tokio::test]
    async fn every_string_param_rejects_oversize() {
        let svc = mk_svc();
        let oversize = "x".repeat(crate::limits::MAX_STRING_BYTES + 1);

        let m = msg(":1.5");
        assert!(matches!(
            svc.create_goal(m.header(), oversize.clone(), String::new(), "low".to_string(), 0, String::new())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.create_goal(m.header(), "t".to_string(), oversize.clone(), "low".to_string(), 0, String::new())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.create_goal(m.header(), "t".to_string(), String::new(), oversize.clone(), 0, String::new())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.create_goal(m.header(), "t".to_string(), String::new(), "low".to_string(), 0, oversize.clone())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.update_goal(m.header(), 1, oversize.clone()).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
    }

    // ── SVC-2 completeness (Decision 3) ──

    #[test]
    fn svc2_every_method_is_classified() {
        use zbus::object_server::Interface;
        let svc = mk_svc();
        let mut xml = String::new();
        svc.introspect_to_writer(&mut xml, 0);
        assert_all_methods_classified("goals", &xml);
    }

    #[tokio::test]
    async fn svc2_every_method_denies_unrecognized_caller_when_deployed() {
        let svc = mk_svc_with(AuthPolicy::deployed());
        let mut exercised: Vec<&str> = Vec::new();

        exercised.push("CreateGoal");
        let m = msg(":1.999");
        assert!(matches!(svc.create_goal(m.header(), "t".to_string(), String::new(), "low".to_string(), 0, String::new()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("UpdateGoal");
        let m = msg(":1.999");
        assert!(matches!(svc.update_goal(m.header(), 1, "{}".to_string()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("UpdateProgress");
        let m = msg(":1.999");
        assert!(matches!(svc.update_progress(m.header(), 1, 10).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("GetGoal");
        let m = msg(":1.999");
        assert!(matches!(svc.get_goal(m.header(), 1).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("ListActive");
        let m = msg(":1.999");
        assert!(matches!(svc.list_active(m.header()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("ListChildren");
        let m = msg(":1.999");
        assert!(matches!(svc.list_children(m.header(), 0).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("FindStale");
        let m = msg(":1.999");
        assert!(matches!(svc.find_stale(m.header(), 30).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("FindApproachingDeadline");
        let m = msg(":1.999");
        assert!(matches!(svc.find_approaching_deadline(m.header(), 7).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("GetTimeline");
        let m = msg(":1.999");
        assert!(matches!(svc.get_timeline(m.header(), 1, 0.0, 0.0, 0.0).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("Count");
        let m = msg(":1.999");
        assert!(matches!(svc.count(m.header()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));

        use zbus::object_server::Interface;
        let mut xml = String::new();
        svc.introspect_to_writer(&mut xml, 0);
        assert_behavioral_covers_all("goals", &xml, &exercised);
    }
}
