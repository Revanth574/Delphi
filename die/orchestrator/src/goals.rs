// SPDX-License-Identifier: MIT

//! Goal graph with deadline intelligence and stale detection.
//!
//! Capability #6 from the spec: a persistent store of what the user is
//! working toward, with parent/child relationships (forest, not DAG —
//! every goal has at most one parent), deadline tracking, and a
//! timeline estimator that learns the user's actual work pace.
//!
//! # Design
//!
//! - Storage: SQLite (single file, WAL mode when backed by disk).
//! - Structure: a forest of goals. Every goal has at most one parent.
//!   This makes cycle checks O(depth) — a linear ancestor walk — and
//!   keeps the schema simple enough that a full tree is a single
//!   recursive CTE.
//! - Timeline estimation has two modes:
//!   1. **No history** — heuristic days per priority band (Critical 7,
//!      High 21, Medium 45, Low 90). These are explicit starting
//!      defaults, not claims about reality. They should be replaced as
//!      soon as real usage data accrues.
//!   2. **Learned** — given `sessions_per_week` and `hours_per_session`
//!      (derived elsewhere from the action timeline), estimate days
//!      from hours-of-work remaining.
//!
//! # Iron Law #5
//!
//! Goals are not actions; they are not reversible via the 24-hour undo
//! window. But every mutation is logged — the orchestrator is expected
//! to mirror goal changes into the action timeline so the user always
//! has a record of "what did Delphi think I was working on a week ago?".

use std::collections::HashSet;
use std::path::Path;
use std::str::FromStr;

use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use tracing::{debug, info};

use crate::OrchestratorError;

/// Numeric identifier for a goal. Auto-incremented by SQLite.
pub type GoalId = i64;

// ────────────────────────────────────────────────────────────────────
// Enums
// ────────────────────────────────────────────────────────────────────

/// Lifecycle state of a goal.
///
/// # Examples
///
/// ```
/// use die_orchestrator::goals::GoalStatus;
/// assert_eq!(GoalStatus::Active.as_str(), "active");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoalStatus {
    /// Being worked on.
    Active,
    /// User paused this goal temporarily.
    Paused,
    /// Finished successfully.
    Completed,
    /// Set aside indefinitely — not "cancelled", just dormant.
    Archived,
}

impl GoalStatus {
    /// Canonical storage string for this status.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::GoalStatus;
    /// assert_eq!(GoalStatus::Completed.as_str(), "completed");
    /// ```
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Completed => "completed",
            Self::Archived => "archived",
        }
    }
}

impl FromStr for GoalStatus {
    type Err = OrchestratorError;

    /// Parse from storage representation.
    ///
    /// Accepts `"active"`, `"paused"`, `"completed"`, `"archived"`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    /// use die_orchestrator::goals::GoalStatus;
    /// assert_eq!(GoalStatus::from_str("active").unwrap(), GoalStatus::Active);
    /// assert!(GoalStatus::from_str("weird").is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(Self::Active),
            "paused" => Ok(Self::Paused),
            "completed" => Ok(Self::Completed),
            "archived" => Ok(Self::Archived),
            other => Err(OrchestratorError::Planning(format!(
                "invalid goal status: {other}"
            ))),
        }
    }
}

/// Urgency band of a goal.
///
/// Ordered: `Low < Medium < High < Critical`. Derived `Ord` is enough for
/// comparisons — no custom impl needed.
///
/// # Examples
///
/// ```
/// use die_orchestrator::goals::Priority;
/// assert!(Priority::Critical > Priority::Low);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(i64)]
pub enum Priority {
    /// Background work. Default timeline estimate: 90 days.
    Low = 1,
    /// Regular work. Default timeline estimate: 45 days.
    Medium = 2,
    /// Time-sensitive. Default timeline estimate: 21 days.
    High = 3,
    /// Urgent. Default timeline estimate: 7 days.
    Critical = 4,
}

impl Priority {
    /// Numeric storage representation (1..=4).
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::Priority;
    /// assert_eq!(Priority::High.as_i64(), 3);
    /// ```
    #[must_use]
    pub const fn as_i64(&self) -> i64 {
        *self as i64
    }
}

impl FromStr for Priority {
    type Err = OrchestratorError;

    /// Parse from human or numeric representation.
    ///
    /// Accepts: `"low"`, `"medium"`/`"med"`, `"high"`, `"critical"`/`"crit"`,
    /// or the digits `"1"`..`"4"` (case-insensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    /// use die_orchestrator::goals::Priority;
    /// assert_eq!(Priority::from_str("high").unwrap(), Priority::High);
    /// assert_eq!(Priority::from_str("4").unwrap(), Priority::Critical);
    /// assert!(Priority::from_str("urgent-ish").is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "low" | "1" => Ok(Self::Low),
            "medium" | "med" | "2" => Ok(Self::Medium),
            "high" | "3" => Ok(Self::High),
            "critical" | "crit" | "4" => Ok(Self::Critical),
            other => Err(OrchestratorError::Planning(format!(
                "invalid priority: {other}"
            ))),
        }
    }
}

impl TryFrom<i64> for Priority {
    type Error = OrchestratorError;

    /// Parse from numeric storage value.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::Priority;
    /// assert_eq!(Priority::try_from(3_i64).unwrap(), Priority::High);
    /// assert!(Priority::try_from(99_i64).is_err());
    /// ```
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Low),
            2 => Ok(Self::Medium),
            3 => Ok(Self::High),
            4 => Ok(Self::Critical),
            other => Err(OrchestratorError::Planning(format!(
                "invalid priority value: {other}"
            ))),
        }
    }
}

/// Whether a goal is on track for its deadline.
///
/// Returned by [`GoalStore::estimate_timeline`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineRisk {
    /// Estimated completion is at least 25% of the way before the deadline.
    OnTrack,
    /// Estimated completion is within the final 25% of the deadline window.
    Tight,
    /// Estimated completion is after the deadline but the goal still has time left.
    AtRisk,
    /// Deadline has already passed.
    Missed,
    /// Goal has no deadline set.
    NoDeadline,
}

/// Source of a timeline estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimelineBasis {
    /// Default heuristic from the priority band.
    PriorityHeuristic,
    /// Derived from observed user work pace.
    Learned,
}

// ────────────────────────────────────────────────────────────────────
// Structs
// ────────────────────────────────────────────────────────────────────

/// A single goal record.
///
/// # Examples
///
/// ```
/// use die_orchestrator::goals::{GoalStore, Priority};
/// let store = GoalStore::in_memory().unwrap();
/// let id = store.create_goal("Ship v1", "", Priority::High, None).unwrap();
/// let g = store.get_goal(id).unwrap();
/// assert_eq!(g.title, "Ship v1");
/// ```
#[derive(Debug, Clone)]
pub struct Goal {
    /// Auto-incremented row id.
    pub id: GoalId,
    /// Short title. Required, non-empty.
    pub title: String,
    /// Longer description. May be empty.
    pub description: String,
    /// Optional deadline. UTC.
    pub deadline: Option<DateTime<Utc>>,
    /// Priority band.
    pub priority: Priority,
    /// Optional parent goal id. Goals form a forest (one parent max).
    pub parent_goal: Option<GoalId>,
    /// Lifecycle state.
    pub status: GoalStatus,
    /// When the goal was first created. UTC.
    pub created_at: DateTime<Utc>,
    /// When the goal last had any field mutated. UTC.
    pub updated_at: DateTime<Utc>,
    /// When the user last did something toward this goal. UTC.
    /// `None` means "never worked on" — stale detection treats it as
    /// "stale starting from `created_at`".
    pub last_activity: Option<DateTime<Utc>>,
    /// Caller-maintained 0..=100 progress estimate.
    pub progress_estimate: u8,
}

/// Partial update for a goal. All fields are optional.
///
/// `None` on a field means "leave it unchanged". `Some(...)` replaces.
/// For `parent_goal`, use `Some(None)` to clear the parent, `Some(Some(id))`
/// to set a new parent.
#[derive(Debug, Default, Clone)]
pub struct GoalPatch {
    pub title: Option<String>,
    pub description: Option<String>,
    pub deadline: Option<Option<DateTime<Utc>>>,
    pub priority: Option<Priority>,
    pub parent_goal: Option<Option<GoalId>>,
    pub status: Option<GoalStatus>,
}

/// Result of [`GoalStore::estimate_timeline`].
#[derive(Debug, Clone)]
pub struct GoalTimeline {
    /// Which goal this estimate is for.
    pub goal_id: GoalId,
    /// Number of days estimated to completion.
    pub estimated_days: u32,
    /// Projected completion date in UTC.
    pub estimated_completion: DateTime<Utc>,
    /// Where the estimate came from.
    pub basis: TimelineBasis,
    /// Risk of missing the deadline (if any).
    pub deadline_risk: DeadlineRisk,
}

/// User's observed work pace, used by [`TimelineEstimator`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UserPace {
    /// No observations yet. Estimator falls back to the priority heuristic.
    NoHistory,
    /// Observed pace from the action timeline.
    Learned {
        /// Distinct work sessions per week. Must be > 0.
        sessions_per_week: f64,
        /// Average hours of focused work per session. Must be > 0.
        hours_per_session: f64,
    },
}

// ────────────────────────────────────────────────────────────────────
// TimelineEstimator — pure function, no state
// ────────────────────────────────────────────────────────────────────

/// Stateless estimator that converts priority + pace into a days figure.
///
/// All heuristic constants live here, in one place, so they are easy to
/// audit and replace.
///
/// # Heuristic origin
///
/// The 7/21/45/90 day defaults are explicit starting values, not claims
/// about reality. They are the midpoint of what a median user might
/// expect when they say "critical / high / medium / low priority" for a
/// goal they have just created. They are intentionally round numbers and
/// are expected to be replaced with per-user learned values as soon as
/// the action timeline has enough data.
pub struct TimelineEstimator;

impl TimelineEstimator {
    /// Default days for the no-history case.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::{Priority, TimelineEstimator};
    /// assert_eq!(TimelineEstimator::heuristic_days(Priority::Critical), 7);
    /// assert_eq!(TimelineEstimator::heuristic_days(Priority::High), 21);
    /// assert_eq!(TimelineEstimator::heuristic_days(Priority::Medium), 45);
    /// assert_eq!(TimelineEstimator::heuristic_days(Priority::Low), 90);
    /// ```
    #[must_use]
    pub const fn heuristic_days(priority: Priority) -> u32 {
        match priority {
            Priority::Critical => 7,
            Priority::High => 21,
            Priority::Medium => 45,
            Priority::Low => 90,
        }
    }

    /// Estimate days using only the priority-heuristic fallback.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::{Priority, TimelineEstimator};
    /// assert_eq!(TimelineEstimator::estimate_no_history(Priority::High), 21);
    /// ```
    #[must_use]
    pub const fn estimate_no_history(priority: Priority) -> u32 {
        Self::heuristic_days(priority)
    }

    /// Estimate days from observed work pace and remaining work hours.
    ///
    /// Returns `None` if `sessions_per_week` or `hours_per_session` is
    /// `<= 0.0` — learned estimates with zero pace would divide by zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::TimelineEstimator;
    /// // 20 hours of work, 2 sessions/week of 4 hours each
    /// // → ceil(20/4) = 5 sessions, at 2 sessions/week → 17.5 days → ceil = 18
    /// let days = TimelineEstimator::estimate_learned(20.0, 2.0, 4.0).unwrap();
    /// assert_eq!(days, 18);
    /// ```
    #[must_use]
    pub fn estimate_learned(
        work_hours_remaining: f64,
        sessions_per_week: f64,
        hours_per_session: f64,
    ) -> Option<u32> {
        if sessions_per_week <= 0.0 || hours_per_session <= 0.0 || work_hours_remaining < 0.0 {
            return None;
        }
        if work_hours_remaining == 0.0 {
            return Some(0);
        }
        let sessions_needed = (work_hours_remaining / hours_per_session).ceil();
        let days_per_session = 7.0 / sessions_per_week;
        let days = (sessions_needed * days_per_session).ceil();
        // Bound the cast — no goal should exceed ~27 years.
        if days >= f64::from(u32::MAX) {
            return Some(u32::MAX);
        }
        Some(days as u32)
    }
}

// ────────────────────────────────────────────────────────────────────
// GoalStore
// ────────────────────────────────────────────────────────────────────

/// SQLite-backed goal store.
///
/// Holds a single connection. Operations are synchronous — goals are
/// few (hundreds at most), so SQLite in WAL mode is plenty.
///
/// # Examples
///
/// ```
/// use die_orchestrator::goals::{GoalStore, Priority};
/// let store = GoalStore::in_memory().unwrap();
/// let id = store.create_goal("Write book", "", Priority::Medium, None).unwrap();
/// assert_eq!(store.count().unwrap(), 1);
/// let _ = id;
/// ```
pub struct GoalStore {
    conn: Connection,
}

impl GoalStore {
    /// Open a goal store at the given path, creating it if needed.
    ///
    /// Enables WAL mode for durable concurrent reads.
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError::Planning`] if the database cannot be
    /// opened or the schema cannot be initialized.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use die_orchestrator::goals::GoalStore;
    /// use std::path::Path;
    /// let store = GoalStore::open(Path::new("/tmp/goals.db")).unwrap();
    /// let _ = store;
    /// ```
    pub fn open(path: &Path) -> Result<Self, OrchestratorError> {
        let conn = Connection::open(path).map_err(|e| {
            OrchestratorError::Planning(format!("failed to open goal db: {e}"))
        })?;
        // Explicit 5s busy_timeout. Project policy per CLAUDE.md (added round 7).
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| OrchestratorError::Planning(format!("goal busy_timeout: {e}")))?;
        // WAL for file-backed stores. Safe to run every open.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| OrchestratorError::Planning(format!("WAL enable failed: {e}")))?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| OrchestratorError::Planning(format!("FK enable failed: {e}")))?;
        let store = Self { conn };
        store.init_schema()?;
        info!("goal store opened at {}", path.display());
        Ok(store)
    }

    /// Create an in-memory store (tests, ephemeral scratch).
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError::Planning`] if schema init fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::GoalStore;
    /// let store = GoalStore::in_memory().unwrap();
    /// assert_eq!(store.count().unwrap(), 0);
    /// ```
    pub fn in_memory() -> Result<Self, OrchestratorError> {
        let conn = Connection::open_in_memory().map_err(|e| {
            OrchestratorError::Planning(format!("failed to create in-memory db: {e}"))
        })?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| OrchestratorError::Planning(format!("FK enable failed: {e}")))?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// Insert a new goal.
    ///
    /// Returns the new goal's id.
    ///
    /// # Errors
    ///
    /// - [`OrchestratorError::Planning`] if `title` is empty.
    /// - [`OrchestratorError::Planning`] if `parent` is set and setting it
    ///   would create a cycle or the parent does not exist.
    /// - [`OrchestratorError::Planning`] on any SQLite failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::{GoalStore, Priority};
    /// let store = GoalStore::in_memory().unwrap();
    /// let id = store.create_goal("Finish draft", "Chapter 1–5", Priority::High, None).unwrap();
    /// assert!(id > 0);
    /// ```
    pub fn create_goal(
        &self,
        title: &str,
        description: &str,
        priority: Priority,
        parent: Option<GoalId>,
    ) -> Result<GoalId, OrchestratorError> {
        if title.trim().is_empty() {
            return Err(OrchestratorError::Planning(
                "goal title must not be empty".to_string(),
            ));
        }
        if let Some(parent_id) = parent
            && !self.goal_exists(parent_id)?
        {
            return Err(OrchestratorError::Planning(format!(
                "parent goal {parent_id} does not exist"
            )));
        }
        let now = current_timestamp();
        self.conn
            .execute(
                "INSERT INTO goals (
                    title, description, deadline_unix, priority,
                    parent_goal_id, status, created_at_unix, updated_at_unix,
                    last_activity_unix, progress_estimate
                ) VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, NULL, 0)",
                params![
                    title,
                    description,
                    priority.as_i64(),
                    parent,
                    GoalStatus::Active.as_str(),
                    now,
                    now,
                ],
            )
            .map_err(|e| OrchestratorError::Planning(format!("insert goal failed: {e}")))?;
        let id = self.conn.last_insert_rowid();
        debug!(goal_id = id, title, "goal created");
        Ok(id)
    }

    /// Fetch a goal by id.
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError::Planning`] if the goal is not found
    /// or the row cannot be parsed.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::{GoalStore, Priority};
    /// let store = GoalStore::in_memory().unwrap();
    /// let id = store.create_goal("t", "", Priority::Low, None).unwrap();
    /// let goal = store.get_goal(id).unwrap();
    /// assert_eq!(goal.priority, Priority::Low);
    /// ```
    pub fn get_goal(&self, id: GoalId) -> Result<Goal, OrchestratorError> {
        self.conn
            .query_row(
                "SELECT id, title, description, deadline_unix, priority,
                        parent_goal_id, status, created_at_unix, updated_at_unix,
                        last_activity_unix, progress_estimate
                 FROM goals WHERE id = ?1",
                params![id],
                row_to_goal,
            )
            .map_err(|e| OrchestratorError::Planning(format!("goal {id} not found: {e}")))?
    }

    /// Update any subset of a goal's fields.
    ///
    /// The `updated_at` timestamp is always bumped. Cycle checks run
    /// when `patch.parent_goal = Some(Some(...))` — setting a new parent.
    ///
    /// # Errors
    ///
    /// - [`OrchestratorError::Planning`] if the goal does not exist.
    /// - [`OrchestratorError::Planning`] if the new parent would create a cycle.
    /// - [`OrchestratorError::Planning`] if the new parent does not exist.
    /// - [`OrchestratorError::Planning`] on any SQLite failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::{GoalPatch, GoalStatus, GoalStore, Priority};
    /// let store = GoalStore::in_memory().unwrap();
    /// let id = store.create_goal("t", "", Priority::Low, None).unwrap();
    /// let mut patch = GoalPatch::default();
    /// patch.status = Some(GoalStatus::Completed);
    /// store.update_goal(id, patch).unwrap();
    /// assert_eq!(store.get_goal(id).unwrap().status, GoalStatus::Completed);
    /// ```
    pub fn update_goal(&self, id: GoalId, patch: GoalPatch) -> Result<(), OrchestratorError> {
        let existing = self.get_goal(id)?;

        // Validate new parent, if any, before writing. `Some(Some(id))` sets
        // a new parent; `Some(None)` clears it; outer `None` leaves it as-is.
        if let Some(Some(parent_id)) = patch.parent_goal {
            if parent_id == id {
                return Err(OrchestratorError::Planning(
                    "a goal cannot be its own parent".to_string(),
                ));
            }
            if !self.goal_exists(parent_id)? {
                return Err(OrchestratorError::Planning(format!(
                    "parent goal {parent_id} does not exist"
                )));
            }
            if self.is_cycle_if_parented(id, parent_id)? {
                return Err(OrchestratorError::Planning(format!(
                    "setting parent of {id} to {parent_id} would create a cycle"
                )));
            }
        }

        let title = patch.title.unwrap_or(existing.title);
        let description = patch.description.unwrap_or(existing.description);
        let deadline = match patch.deadline {
            Some(v) => v,
            None => existing.deadline,
        };
        let priority = patch.priority.unwrap_or(existing.priority);
        let parent_goal = match patch.parent_goal {
            Some(v) => v,
            None => existing.parent_goal,
        };
        let status = patch.status.unwrap_or(existing.status);
        let now = current_timestamp();

        self.conn
            .execute(
                "UPDATE goals SET
                    title = ?1, description = ?2, deadline_unix = ?3,
                    priority = ?4, parent_goal_id = ?5, status = ?6,
                    updated_at_unix = ?7
                 WHERE id = ?8",
                params![
                    title,
                    description,
                    deadline.map(|d| d.timestamp()),
                    priority.as_i64(),
                    parent_goal,
                    status.as_str(),
                    now,
                    id,
                ],
            )
            .map_err(|e| OrchestratorError::Planning(format!("update goal failed: {e}")))?;
        debug!(goal_id = id, "goal updated");
        Ok(())
    }

    /// Record progress on a goal: set `progress_estimate` and stamp `last_activity`.
    ///
    /// `progress` is clamped to `0..=100`.
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError::Planning`] if `progress > 100` or the
    /// goal does not exist.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::{GoalStore, Priority};
    /// let store = GoalStore::in_memory().unwrap();
    /// let id = store.create_goal("t", "", Priority::Low, None).unwrap();
    /// store.update_progress(id, 40).unwrap();
    /// assert_eq!(store.get_goal(id).unwrap().progress_estimate, 40);
    /// ```
    pub fn update_progress(
        &self,
        id: GoalId,
        progress: u8,
    ) -> Result<(), OrchestratorError> {
        if progress > 100 {
            return Err(OrchestratorError::Planning(format!(
                "progress must be 0..=100 (got {progress})"
            )));
        }
        if !self.goal_exists(id)? {
            return Err(OrchestratorError::Planning(format!(
                "goal {id} does not exist"
            )));
        }
        let now = current_timestamp();
        self.conn
            .execute(
                "UPDATE goals SET
                    progress_estimate = ?1,
                    last_activity_unix = ?2,
                    updated_at_unix = ?2
                 WHERE id = ?3",
                params![progress, now, id],
            )
            .map_err(|e| OrchestratorError::Planning(format!("progress update failed: {e}")))?;
        Ok(())
    }

    /// Delete a goal. Children's `parent_goal_id` is set to `NULL` (FK `ON DELETE SET NULL`).
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError::Planning`] on SQLite failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::{GoalStore, Priority};
    /// let store = GoalStore::in_memory().unwrap();
    /// let id = store.create_goal("t", "", Priority::Low, None).unwrap();
    /// store.delete_goal(id).unwrap();
    /// assert_eq!(store.count().unwrap(), 0);
    /// ```
    pub fn delete_goal(&self, id: GoalId) -> Result<(), OrchestratorError> {
        self.conn
            .execute("DELETE FROM goals WHERE id = ?1", params![id])
            .map_err(|e| OrchestratorError::Planning(format!("delete goal failed: {e}")))?;
        Ok(())
    }

    /// All goals currently in [`GoalStatus::Active`], newest first.
    ///
    /// Uses `id DESC` as the stable secondary sort so same-second
    /// inserts are deterministic.
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError::Planning`] on query failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::{GoalStore, Priority};
    /// let store = GoalStore::in_memory().unwrap();
    /// store.create_goal("a", "", Priority::Low, None).unwrap();
    /// store.create_goal("b", "", Priority::Low, None).unwrap();
    /// assert_eq!(store.list_active().unwrap().len(), 2);
    /// ```
    pub fn list_active(&self) -> Result<Vec<Goal>, OrchestratorError> {
        self.list_by_status(GoalStatus::Active)
    }

    /// All goals in the given lifecycle state, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError::Planning`] on query failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::{GoalStatus, GoalStore};
    /// let store = GoalStore::in_memory().unwrap();
    /// assert!(store.list_by_status(GoalStatus::Completed).unwrap().is_empty());
    /// ```
    pub fn list_by_status(&self, status: GoalStatus) -> Result<Vec<Goal>, OrchestratorError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, title, description, deadline_unix, priority,
                        parent_goal_id, status, created_at_unix, updated_at_unix,
                        last_activity_unix, progress_estimate
                 FROM goals WHERE status = ?1
                 ORDER BY created_at_unix DESC, id DESC",
            )
            .map_err(|e| OrchestratorError::Planning(format!("prepare failed: {e}")))?;
        let rows = stmt
            .query_map(params![status.as_str()], row_to_goal)
            .map_err(|e| OrchestratorError::Planning(format!("query failed: {e}")))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| OrchestratorError::Planning(format!("row: {e}")))??);
        }
        Ok(out)
    }

    /// Direct children of `parent`. Excludes the parent itself.
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError::Planning`] on query failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::{GoalStore, Priority};
    /// let store = GoalStore::in_memory().unwrap();
    /// let p = store.create_goal("parent", "", Priority::Low, None).unwrap();
    /// let _c = store.create_goal("child", "", Priority::Low, Some(p)).unwrap();
    /// assert_eq!(store.list_children(p).unwrap().len(), 1);
    /// ```
    pub fn list_children(&self, parent: GoalId) -> Result<Vec<Goal>, OrchestratorError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, title, description, deadline_unix, priority,
                        parent_goal_id, status, created_at_unix, updated_at_unix,
                        last_activity_unix, progress_estimate
                 FROM goals WHERE parent_goal_id = ?1
                 ORDER BY created_at_unix DESC, id DESC",
            )
            .map_err(|e| OrchestratorError::Planning(format!("prepare failed: {e}")))?;
        let rows = stmt
            .query_map(params![parent], row_to_goal)
            .map_err(|e| OrchestratorError::Planning(format!("query failed: {e}")))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| OrchestratorError::Planning(format!("row: {e}")))??);
        }
        Ok(out)
    }

    /// Active goals with no activity (or creation) newer than `inactive_days` ago.
    ///
    /// A goal with `last_activity = NULL` is considered stale if its
    /// `created_at` is older than the cutoff.
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError::Planning`] on query failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::GoalStore;
    /// let store = GoalStore::in_memory().unwrap();
    /// assert!(store.find_stale(30).unwrap().is_empty());
    /// ```
    pub fn find_stale(&self, inactive_days: u32) -> Result<Vec<Goal>, OrchestratorError> {
        let now = current_timestamp();
        let cutoff = now - (i64::from(inactive_days) * 86_400);
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, title, description, deadline_unix, priority,
                        parent_goal_id, status, created_at_unix, updated_at_unix,
                        last_activity_unix, progress_estimate
                 FROM goals
                 WHERE status = 'active'
                   AND COALESCE(last_activity_unix, created_at_unix) < ?1
                 ORDER BY COALESCE(last_activity_unix, created_at_unix) ASC, id ASC",
            )
            .map_err(|e| OrchestratorError::Planning(format!("prepare failed: {e}")))?;
        let rows = stmt
            .query_map(params![cutoff], row_to_goal)
            .map_err(|e| OrchestratorError::Planning(format!("query failed: {e}")))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| OrchestratorError::Planning(format!("row: {e}")))??);
        }
        Ok(out)
    }

    /// Active goals whose deadline falls within the next `within_days`.
    ///
    /// Already-missed deadlines are *not* included; use [`Self::list_active`]
    /// and filter on `deadline < now` for those.
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError::Planning`] on query failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::GoalStore;
    /// let store = GoalStore::in_memory().unwrap();
    /// assert!(store.find_approaching_deadline(7).unwrap().is_empty());
    /// ```
    pub fn find_approaching_deadline(
        &self,
        within_days: u32,
    ) -> Result<Vec<Goal>, OrchestratorError> {
        let now = current_timestamp();
        let horizon = now + (i64::from(within_days) * 86_400);
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, title, description, deadline_unix, priority,
                        parent_goal_id, status, created_at_unix, updated_at_unix,
                        last_activity_unix, progress_estimate
                 FROM goals
                 WHERE status = 'active'
                   AND deadline_unix IS NOT NULL
                   AND deadline_unix >= ?1
                   AND deadline_unix <= ?2
                 ORDER BY deadline_unix ASC, id ASC",
            )
            .map_err(|e| OrchestratorError::Planning(format!("prepare failed: {e}")))?;
        let rows = stmt
            .query_map(params![now, horizon], row_to_goal)
            .map_err(|e| OrchestratorError::Planning(format!("query failed: {e}")))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| OrchestratorError::Planning(format!("row: {e}")))??);
        }
        Ok(out)
    }

    /// Ancestor chain of `id`, nearest parent first.
    ///
    /// Empty if the goal has no parent. Safe against pre-existing cycles
    /// (guards with a visited set — SQLite FK `SET NULL` prevents new
    /// cycles being created, but defense-in-depth is cheap).
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError::Planning`] on query failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::{GoalStore, Priority};
    /// let store = GoalStore::in_memory().unwrap();
    /// let a = store.create_goal("a", "", Priority::Low, None).unwrap();
    /// let b = store.create_goal("b", "", Priority::Low, Some(a)).unwrap();
    /// let anc = store.ancestors(b).unwrap();
    /// assert_eq!(anc.len(), 1);
    /// assert_eq!(anc[0].id, a);
    /// ```
    pub fn ancestors(&self, id: GoalId) -> Result<Vec<Goal>, OrchestratorError> {
        let mut out = Vec::new();
        let mut visited: HashSet<GoalId> = HashSet::new();
        let mut current = self.get_goal(id)?.parent_goal;
        while let Some(parent_id) = current {
            if !visited.insert(parent_id) {
                // Pre-existing cycle: stop to avoid infinite loop.
                break;
            }
            let parent = self.get_goal(parent_id)?;
            current = parent.parent_goal;
            out.push(parent);
        }
        Ok(out)
    }

    /// All descendants of `id`, BFS order.
    ///
    /// Empty if the goal has no children.
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError::Planning`] on query failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::{GoalStore, Priority};
    /// let store = GoalStore::in_memory().unwrap();
    /// let a = store.create_goal("a", "", Priority::Low, None).unwrap();
    /// let _b = store.create_goal("b", "", Priority::Low, Some(a)).unwrap();
    /// let _c = store.create_goal("c", "", Priority::Low, Some(a)).unwrap();
    /// assert_eq!(store.descendants(a).unwrap().len(), 2);
    /// ```
    pub fn descendants(&self, id: GoalId) -> Result<Vec<Goal>, OrchestratorError> {
        let mut out = Vec::new();
        let mut visited: HashSet<GoalId> = HashSet::new();
        let mut frontier: Vec<GoalId> = vec![id];
        visited.insert(id);
        while let Some(current) = frontier.pop() {
            for child in self.list_children(current)? {
                if visited.insert(child.id) {
                    frontier.push(child.id);
                    out.push(child);
                }
            }
        }
        Ok(out)
    }

    /// Would setting `child.parent = proposed_parent` create a cycle?
    ///
    /// Returns `true` when:
    /// 1. `child == proposed_parent` (self-parent).
    /// 2. `child` is already (transitively) an ancestor of `proposed_parent`.
    ///
    /// Walks up parent pointers from `proposed_parent`; any encounter of
    /// `child` means closing that as a cycle. `HashSet` guards against
    /// pre-existing cycles in the data (stop, don't loop forever).
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError::Planning`] if either goal does not exist.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::{GoalStore, Priority};
    /// let store = GoalStore::in_memory().unwrap();
    /// let a = store.create_goal("a", "", Priority::Low, None).unwrap();
    /// let b = store.create_goal("b", "", Priority::Low, Some(a)).unwrap();
    /// // a → b; try a.parent = b. a is an ancestor of b, so this would cycle.
    /// assert!(store.is_cycle_if_parented(a, b).unwrap());
    /// // a → b; setting b.parent = a is fine (already the case).
    /// assert!(!store.is_cycle_if_parented(b, a).unwrap());
    /// ```
    pub fn is_cycle_if_parented(
        &self,
        child: GoalId,
        proposed_parent: GoalId,
    ) -> Result<bool, OrchestratorError> {
        if !self.goal_exists(child)? {
            return Err(OrchestratorError::Planning(format!(
                "child goal {child} does not exist"
            )));
        }
        if !self.goal_exists(proposed_parent)? {
            return Err(OrchestratorError::Planning(format!(
                "proposed parent {proposed_parent} does not exist"
            )));
        }
        if child == proposed_parent {
            return Ok(true);
        }
        let mut visited: HashSet<GoalId> = HashSet::new();
        let mut current: Option<GoalId> = Some(proposed_parent);
        while let Some(node) = current {
            if node == child {
                return Ok(true);
            }
            if !visited.insert(node) {
                // Pre-existing cycle — bail out, do not claim a new cycle.
                return Ok(false);
            }
            current = self
                .conn
                .query_row(
                    "SELECT parent_goal_id FROM goals WHERE id = ?1",
                    params![node],
                    |row| row.get::<_, Option<GoalId>>(0),
                )
                .optional()
                .map_err(|e| OrchestratorError::Planning(format!("cycle-walk failed: {e}")))?
                .flatten();
        }
        Ok(false)
    }

    /// Estimate days to completion for a single goal.
    ///
    /// `work_hours_remaining` is only consulted when `pace` is
    /// [`UserPace::Learned`]. With [`UserPace::NoHistory`], the priority
    /// heuristic is used and `work_hours_remaining` is ignored.
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError::Planning`] if the goal does not exist
    /// or if `pace` is `Learned` with invalid values.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::{GoalStore, Priority, UserPace};
    /// let store = GoalStore::in_memory().unwrap();
    /// let id = store.create_goal("x", "", Priority::High, None).unwrap();
    /// let t = store.estimate_timeline(id, UserPace::NoHistory, 0.0).unwrap();
    /// assert_eq!(t.estimated_days, 21); // High-priority heuristic
    /// ```
    pub fn estimate_timeline(
        &self,
        id: GoalId,
        pace: UserPace,
        work_hours_remaining: f64,
    ) -> Result<GoalTimeline, OrchestratorError> {
        let goal = self.get_goal(id)?;
        let (days, basis) = match pace {
            UserPace::NoHistory => (
                TimelineEstimator::estimate_no_history(goal.priority),
                TimelineBasis::PriorityHeuristic,
            ),
            UserPace::Learned {
                sessions_per_week,
                hours_per_session,
            } => {
                let days = TimelineEstimator::estimate_learned(
                    work_hours_remaining,
                    sessions_per_week,
                    hours_per_session,
                )
                .ok_or_else(|| {
                    OrchestratorError::Planning(
                        "invalid learned pace (must be > 0)".to_string(),
                    )
                })?;
                (days, TimelineBasis::Learned)
            }
        };
        let now = Utc::now();
        let estimated_completion = now + Duration::days(i64::from(days));
        let deadline_risk = compute_deadline_risk(goal.deadline, now, estimated_completion);
        Ok(GoalTimeline {
            goal_id: id,
            estimated_days: days,
            estimated_completion,
            basis,
            deadline_risk,
        })
    }

    /// Total goal count across all statuses.
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError::Planning`] on query failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::goals::GoalStore;
    /// let store = GoalStore::in_memory().unwrap();
    /// assert_eq!(store.count().unwrap(), 0);
    /// ```
    pub fn count(&self) -> Result<usize, OrchestratorError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM goals", [], |row| row.get(0))
            .map_err(|e| OrchestratorError::Planning(format!("count failed: {e}")))?;
        Ok(count as usize)
    }

    // ── internal helpers ────────────────────────────────────────────

    fn goal_exists(&self, id: GoalId) -> Result<bool, OrchestratorError> {
        let found: Option<i64> = self
            .conn
            .query_row("SELECT 1 FROM goals WHERE id = ?1", params![id], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|e| OrchestratorError::Planning(format!("existence check failed: {e}")))?;
        Ok(found.is_some())
    }

    fn init_schema(&self) -> Result<(), OrchestratorError> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS goals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    deadline_unix INTEGER,
                    priority INTEGER NOT NULL CHECK(priority BETWEEN 1 AND 4),
                    parent_goal_id INTEGER,
                    status TEXT NOT NULL,
                    created_at_unix INTEGER NOT NULL,
                    updated_at_unix INTEGER NOT NULL,
                    last_activity_unix INTEGER,
                    progress_estimate INTEGER NOT NULL DEFAULT 0
                        CHECK(progress_estimate BETWEEN 0 AND 100),
                    FOREIGN KEY(parent_goal_id) REFERENCES goals(id) ON DELETE SET NULL
                );
                CREATE INDEX IF NOT EXISTS idx_goals_status ON goals(status);
                CREATE INDEX IF NOT EXISTS idx_goals_parent ON goals(parent_goal_id);
                CREATE INDEX IF NOT EXISTS idx_goals_deadline ON goals(deadline_unix);
                CREATE INDEX IF NOT EXISTS idx_goals_activity ON goals(last_activity_unix);",
            )
            .map_err(|e| OrchestratorError::Planning(format!("schema init failed: {e}")))?;
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

/// Current UTC timestamp in epoch seconds.
fn current_timestamp() -> i64 {
    Utc::now().timestamp()
}

/// Convert an epoch seconds value to a [`DateTime<Utc>`].
fn ts_to_dt(ts: i64) -> Result<DateTime<Utc>, OrchestratorError> {
    DateTime::<Utc>::from_timestamp(ts, 0)
        .ok_or_else(|| OrchestratorError::Planning(format!("invalid timestamp: {ts}")))
}

/// Parse a row into a [`Goal`].
///
/// Returns a `Result<Result<Goal, OrchestratorError>, rusqlite::Error>` so
/// callers can surface both SQLite-level errors and parse-level errors.
fn row_to_goal(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Goal, OrchestratorError>> {
    Ok((|| {
        let id: GoalId = row.get(0).map_err(sql_err)?;
        let title: String = row.get(1).map_err(sql_err)?;
        let description: String = row.get(2).map_err(sql_err)?;
        let deadline_unix: Option<i64> = row.get(3).map_err(sql_err)?;
        let priority_i: i64 = row.get(4).map_err(sql_err)?;
        let parent_goal_id: Option<GoalId> = row.get(5).map_err(sql_err)?;
        let status_s: String = row.get(6).map_err(sql_err)?;
        let created_at_unix: i64 = row.get(7).map_err(sql_err)?;
        let updated_at_unix: i64 = row.get(8).map_err(sql_err)?;
        let last_activity_unix: Option<i64> = row.get(9).map_err(sql_err)?;
        let progress_estimate: i64 = row.get(10).map_err(sql_err)?;

        let priority = Priority::try_from(priority_i)?;
        let status = GoalStatus::from_str(&status_s)?;
        let deadline = match deadline_unix {
            Some(ts) => Some(ts_to_dt(ts)?),
            None => None,
        };
        let last_activity = match last_activity_unix {
            Some(ts) => Some(ts_to_dt(ts)?),
            None => None,
        };
        let created_at = ts_to_dt(created_at_unix)?;
        let updated_at = ts_to_dt(updated_at_unix)?;

        Ok(Goal {
            id,
            title,
            description,
            deadline,
            priority,
            parent_goal: parent_goal_id,
            status,
            created_at,
            updated_at,
            last_activity,
            // SQLite CHECK constraint guarantees 0..=100, but clamp defensively.
            progress_estimate: progress_estimate.clamp(0, 100) as u8,
        })
    })())
}

fn sql_err(e: rusqlite::Error) -> OrchestratorError {
    OrchestratorError::Planning(format!("row read failed: {e}"))
}

fn compute_deadline_risk(
    deadline: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    eta: DateTime<Utc>,
) -> DeadlineRisk {
    let Some(deadline) = deadline else {
        return DeadlineRisk::NoDeadline;
    };
    if deadline < now {
        return DeadlineRisk::Missed;
    }
    if eta > deadline {
        return DeadlineRisk::AtRisk;
    }
    // "Tight" = eta lands in the final 25% of the window.
    let window = (deadline - now).num_seconds().max(1);
    let remaining = (deadline - eta).num_seconds().max(0);
    if remaining * 4 < window {
        DeadlineRisk::Tight
    } else {
        DeadlineRisk::OnTrack
    }
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mk() -> GoalStore {
        GoalStore::in_memory().expect("in-memory store")
    }

    // ---- enums / parsers -----------------------------------------

    #[test]
    fn goal_status_round_trip() {
        for s in [
            GoalStatus::Active,
            GoalStatus::Paused,
            GoalStatus::Completed,
            GoalStatus::Archived,
        ] {
            assert_eq!(GoalStatus::from_str(s.as_str()).unwrap(), s);
        }
        assert!(GoalStatus::from_str("running").is_err());
    }

    #[test]
    fn priority_from_str_accepts_human_and_digits() {
        assert_eq!(Priority::from_str("low").unwrap(), Priority::Low);
        assert_eq!(Priority::from_str("MED").unwrap(), Priority::Medium);
        assert_eq!(Priority::from_str("high").unwrap(), Priority::High);
        assert_eq!(Priority::from_str("Critical").unwrap(), Priority::Critical);
        assert_eq!(Priority::from_str("1").unwrap(), Priority::Low);
        assert_eq!(Priority::from_str("4").unwrap(), Priority::Critical);
        assert!(Priority::from_str("urgent-ish").is_err());
    }

    #[test]
    fn priority_try_from_i64_round_trip() {
        for (i, p) in [
            (1, Priority::Low),
            (2, Priority::Medium),
            (3, Priority::High),
            (4, Priority::Critical),
        ] {
            assert_eq!(Priority::try_from(i).unwrap(), p);
            assert_eq!(p.as_i64(), i);
        }
        assert!(Priority::try_from(0_i64).is_err());
        assert!(Priority::try_from(5_i64).is_err());
    }

    #[test]
    fn priority_ordering() {
        assert!(Priority::Low < Priority::Medium);
        assert!(Priority::Medium < Priority::High);
        assert!(Priority::High < Priority::Critical);
    }

    // ---- CRUD ----------------------------------------------------

    #[test]
    fn empty_store_counts_zero() {
        let store = mk();
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn create_and_get_round_trip() {
        let store = mk();
        let id = store
            .create_goal("Ship v1", "alpha freeze", Priority::High, None)
            .unwrap();
        let g = store.get_goal(id).unwrap();
        assert_eq!(g.id, id);
        assert_eq!(g.title, "Ship v1");
        assert_eq!(g.description, "alpha freeze");
        assert_eq!(g.priority, Priority::High);
        assert_eq!(g.status, GoalStatus::Active);
        assert_eq!(g.progress_estimate, 0);
        assert!(g.deadline.is_none());
        assert!(g.parent_goal.is_none());
        assert!(g.last_activity.is_none());
    }

    #[test]
    fn create_rejects_empty_title() {
        let store = mk();
        assert!(store
            .create_goal("   ", "", Priority::Low, None)
            .is_err());
    }

    #[test]
    fn create_with_missing_parent_fails() {
        let store = mk();
        let err = store
            .create_goal("child", "", Priority::Low, Some(999))
            .unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn update_progress_sets_last_activity() {
        let store = mk();
        let id = store.create_goal("x", "", Priority::Low, None).unwrap();
        assert!(store.get_goal(id).unwrap().last_activity.is_none());
        store.update_progress(id, 25).unwrap();
        let g = store.get_goal(id).unwrap();
        assert_eq!(g.progress_estimate, 25);
        assert!(g.last_activity.is_some());
    }

    #[test]
    fn update_progress_rejects_over_100() {
        let store = mk();
        let id = store.create_goal("x", "", Priority::Low, None).unwrap();
        assert!(store.update_progress(id, 101).is_err());
    }

    #[test]
    fn update_goal_changes_status() {
        let store = mk();
        let id = store.create_goal("x", "", Priority::Low, None).unwrap();
        let patch = GoalPatch {
            status: Some(GoalStatus::Completed),
            ..Default::default()
        };
        store.update_goal(id, patch).unwrap();
        assert_eq!(store.get_goal(id).unwrap().status, GoalStatus::Completed);
    }

    #[test]
    fn update_goal_clears_parent_via_some_none() {
        let store = mk();
        let p = store.create_goal("p", "", Priority::Low, None).unwrap();
        let c = store.create_goal("c", "", Priority::Low, Some(p)).unwrap();
        assert_eq!(store.get_goal(c).unwrap().parent_goal, Some(p));
        let patch = GoalPatch {
            parent_goal: Some(None),
            ..Default::default()
        };
        store.update_goal(c, patch).unwrap();
        assert_eq!(store.get_goal(c).unwrap().parent_goal, None);
    }

    #[test]
    fn delete_removes_row_and_nulls_children_parent() {
        let store = mk();
        let p = store.create_goal("p", "", Priority::Low, None).unwrap();
        let c = store.create_goal("c", "", Priority::Low, Some(p)).unwrap();
        store.delete_goal(p).unwrap();
        assert_eq!(store.count().unwrap(), 1);
        assert_eq!(store.get_goal(c).unwrap().parent_goal, None);
    }

    #[test]
    fn list_by_status_excludes_other_states() {
        let store = mk();
        let a = store.create_goal("a", "", Priority::Low, None).unwrap();
        let _b = store.create_goal("b", "", Priority::Low, None).unwrap();
        let patch = GoalPatch {
            status: Some(GoalStatus::Completed),
            ..Default::default()
        };
        store.update_goal(a, patch).unwrap();
        assert_eq!(store.list_active().unwrap().len(), 1);
        assert_eq!(
            store.list_by_status(GoalStatus::Completed).unwrap().len(),
            1
        );
    }

    // ---- graph ---------------------------------------------------

    #[test]
    fn list_children_returns_only_direct_children() {
        let store = mk();
        let a = store.create_goal("a", "", Priority::Low, None).unwrap();
        let b = store.create_goal("b", "", Priority::Low, Some(a)).unwrap();
        let _c = store.create_goal("c", "", Priority::Low, Some(b)).unwrap();
        let kids = store.list_children(a).unwrap();
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].id, b);
    }

    #[test]
    fn ancestors_walks_up() {
        let store = mk();
        let a = store.create_goal("a", "", Priority::Low, None).unwrap();
        let b = store.create_goal("b", "", Priority::Low, Some(a)).unwrap();
        let c = store.create_goal("c", "", Priority::Low, Some(b)).unwrap();
        let anc = store.ancestors(c).unwrap();
        assert_eq!(anc.len(), 2);
        assert_eq!(anc[0].id, b); // nearest first
        assert_eq!(anc[1].id, a);
    }

    #[test]
    fn descendants_bfs_collects_all() {
        let store = mk();
        let a = store.create_goal("a", "", Priority::Low, None).unwrap();
        let b = store.create_goal("b", "", Priority::Low, Some(a)).unwrap();
        let c = store.create_goal("c", "", Priority::Low, Some(a)).unwrap();
        let _d = store.create_goal("d", "", Priority::Low, Some(b)).unwrap();
        let desc = store.descendants(a).unwrap();
        assert_eq!(desc.len(), 3);
        let ids: HashSet<GoalId> = desc.iter().map(|g| g.id).collect();
        assert!(ids.contains(&b));
        assert!(ids.contains(&c));
    }

    #[test]
    fn cycle_self_parent_detected() {
        let store = mk();
        let a = store.create_goal("a", "", Priority::Low, None).unwrap();
        assert!(store.is_cycle_if_parented(a, a).unwrap());
    }

    #[test]
    fn cycle_direct_loop_detected() {
        let store = mk();
        let a = store.create_goal("a", "", Priority::Low, None).unwrap();
        let b = store.create_goal("b", "", Priority::Low, Some(a)).unwrap();
        // a → b already. Making a's parent = b would close the loop.
        assert!(store.is_cycle_if_parented(a, b).unwrap());
    }

    #[test]
    fn cycle_indirect_loop_detected() {
        let store = mk();
        let a = store.create_goal("a", "", Priority::Low, None).unwrap();
        let b = store.create_goal("b", "", Priority::Low, Some(a)).unwrap();
        let c = store.create_goal("c", "", Priority::Low, Some(b)).unwrap();
        // a → b → c. Making a.parent = c would close a 3-hop loop.
        assert!(store.is_cycle_if_parented(a, c).unwrap());
    }

    #[test]
    fn cycle_deep_10_level_chain_detected() {
        let store = mk();
        let mut prev: Option<GoalId> = None;
        let mut ids = Vec::new();
        for i in 0..10 {
            let id = store
                .create_goal(&format!("g{i}"), "", Priority::Low, prev)
                .unwrap();
            ids.push(id);
            prev = Some(id);
        }
        // Chain: ids[0] → ids[1] → ... → ids[9].
        // Setting ids[0].parent = ids[9] closes a 10-deep loop.
        assert!(store.is_cycle_if_parented(ids[0], ids[9]).unwrap());
        // Sanity: completely fresh goal is fine as a child of ids[9].
        let fresh = store.create_goal("fresh", "", Priority::Low, None).unwrap();
        assert!(!store.is_cycle_if_parented(fresh, ids[9]).unwrap());
    }

    #[test]
    fn cycle_unrelated_goals_no_cycle() {
        let store = mk();
        let a = store.create_goal("a", "", Priority::Low, None).unwrap();
        let b = store.create_goal("b", "", Priority::Low, None).unwrap();
        assert!(!store.is_cycle_if_parented(a, b).unwrap());
        assert!(!store.is_cycle_if_parented(b, a).unwrap());
    }

    #[test]
    fn update_goal_rejects_cycle_on_parent_change() {
        let store = mk();
        let a = store.create_goal("a", "", Priority::Low, None).unwrap();
        let b = store.create_goal("b", "", Priority::Low, Some(a)).unwrap();
        let patch = GoalPatch {
            parent_goal: Some(Some(b)),
            ..Default::default()
        };
        let err = store.update_goal(a, patch).unwrap_err();
        assert!(err.to_string().contains("cycle"));
    }

    #[test]
    fn update_goal_rejects_self_parent() {
        let store = mk();
        let a = store.create_goal("a", "", Priority::Low, None).unwrap();
        let patch = GoalPatch {
            parent_goal: Some(Some(a)),
            ..Default::default()
        };
        let err = store.update_goal(a, patch).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("own parent"));
    }

    // ---- stale + deadline ---------------------------------------

    #[test]
    fn find_stale_excludes_fresh() {
        let store = mk();
        let _a = store.create_goal("fresh", "", Priority::Low, None).unwrap();
        // created just now; cutoff is 30 days ago → excluded.
        assert!(store.find_stale(30).unwrap().is_empty());
    }

    #[test]
    fn find_stale_includes_old_created_at() {
        let store = mk();
        let id = store.create_goal("old", "", Priority::Low, None).unwrap();
        // Force created_at into the past.
        let old = current_timestamp() - (60 * 86_400);
        store
            .conn
            .execute(
                "UPDATE goals SET created_at_unix = ?1, updated_at_unix = ?1 WHERE id = ?2",
                params![old, id],
            )
            .unwrap();
        let stale = store.find_stale(30).unwrap();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].id, id);
    }

    #[test]
    fn find_stale_ignores_completed_goals() {
        let store = mk();
        let id = store.create_goal("old", "", Priority::Low, None).unwrap();
        let old = current_timestamp() - (60 * 86_400);
        store
            .conn
            .execute(
                "UPDATE goals SET created_at_unix = ?1, updated_at_unix = ?1 WHERE id = ?2",
                params![old, id],
            )
            .unwrap();
        let patch = GoalPatch {
            status: Some(GoalStatus::Completed),
            ..Default::default()
        };
        store.update_goal(id, patch).unwrap();
        assert!(store.find_stale(30).unwrap().is_empty());
    }

    #[test]
    fn find_approaching_deadline_hits_soon_deadline() {
        let store = mk();
        let id = store.create_goal("dl", "", Priority::High, None).unwrap();
        // Set deadline 3 days from now.
        let soon = current_timestamp() + (3 * 86_400);
        store
            .conn
            .execute(
                "UPDATE goals SET deadline_unix = ?1 WHERE id = ?2",
                params![soon, id],
            )
            .unwrap();
        let hits = store.find_approaching_deadline(7).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, id);
    }

    #[test]
    fn find_approaching_deadline_excludes_far_future() {
        let store = mk();
        let id = store.create_goal("dl", "", Priority::High, None).unwrap();
        let far = current_timestamp() + (60 * 86_400);
        store
            .conn
            .execute(
                "UPDATE goals SET deadline_unix = ?1 WHERE id = ?2",
                params![far, id],
            )
            .unwrap();
        assert!(store.find_approaching_deadline(7).unwrap().is_empty());
    }

    #[test]
    fn find_approaching_deadline_excludes_no_deadline() {
        let store = mk();
        let _id = store.create_goal("dl", "", Priority::High, None).unwrap();
        assert!(store.find_approaching_deadline(365).unwrap().is_empty());
    }

    // ---- timeline estimator --------------------------------------

    #[test]
    fn heuristic_days_covers_all_priorities() {
        assert_eq!(TimelineEstimator::heuristic_days(Priority::Critical), 7);
        assert_eq!(TimelineEstimator::heuristic_days(Priority::High), 21);
        assert_eq!(TimelineEstimator::heuristic_days(Priority::Medium), 45);
        assert_eq!(TimelineEstimator::heuristic_days(Priority::Low), 90);
    }

    #[test]
    fn learned_estimate_sanity() {
        // 20 hours work, 2 sessions/week × 4 hours = 5 sessions needed, 3.5 days/session
        // → 17.5 → ceil 18.
        let d = TimelineEstimator::estimate_learned(20.0, 2.0, 4.0).unwrap();
        assert_eq!(d, 18);
    }

    #[test]
    fn learned_estimate_rejects_zero_pace() {
        assert!(TimelineEstimator::estimate_learned(10.0, 0.0, 2.0).is_none());
        assert!(TimelineEstimator::estimate_learned(10.0, 2.0, 0.0).is_none());
        assert!(TimelineEstimator::estimate_learned(-1.0, 2.0, 2.0).is_none());
    }

    #[test]
    fn learned_estimate_zero_hours_means_zero_days() {
        assert_eq!(
            TimelineEstimator::estimate_learned(0.0, 2.0, 4.0).unwrap(),
            0
        );
    }

    #[test]
    fn estimate_timeline_no_history_uses_priority() {
        let store = mk();
        let id = store.create_goal("x", "", Priority::High, None).unwrap();
        let t = store
            .estimate_timeline(id, UserPace::NoHistory, 0.0)
            .unwrap();
        assert_eq!(t.estimated_days, 21);
        assert_eq!(t.basis, TimelineBasis::PriorityHeuristic);
        assert_eq!(t.deadline_risk, DeadlineRisk::NoDeadline);
    }

    #[test]
    fn estimate_timeline_learned_uses_pace() {
        let store = mk();
        let id = store.create_goal("x", "", Priority::High, None).unwrap();
        let t = store
            .estimate_timeline(
                id,
                UserPace::Learned {
                    sessions_per_week: 2.0,
                    hours_per_session: 4.0,
                },
                20.0,
            )
            .unwrap();
        assert_eq!(t.estimated_days, 18);
        assert_eq!(t.basis, TimelineBasis::Learned);
    }

    #[test]
    fn estimate_timeline_flags_missed_deadline() {
        let store = mk();
        let id = store.create_goal("x", "", Priority::Low, None).unwrap();
        // Set deadline in the past.
        let past = current_timestamp() - 86_400;
        store
            .conn
            .execute(
                "UPDATE goals SET deadline_unix = ?1 WHERE id = ?2",
                params![past, id],
            )
            .unwrap();
        let t = store
            .estimate_timeline(id, UserPace::NoHistory, 0.0)
            .unwrap();
        assert_eq!(t.deadline_risk, DeadlineRisk::Missed);
    }

    #[test]
    fn estimate_timeline_flags_at_risk() {
        let store = mk();
        // High-priority goal → 21-day heuristic. Give it a 3-day deadline.
        let id = store.create_goal("x", "", Priority::High, None).unwrap();
        let soon = current_timestamp() + (3 * 86_400);
        store
            .conn
            .execute(
                "UPDATE goals SET deadline_unix = ?1 WHERE id = ?2",
                params![soon, id],
            )
            .unwrap();
        let t = store
            .estimate_timeline(id, UserPace::NoHistory, 0.0)
            .unwrap();
        assert_eq!(t.deadline_risk, DeadlineRisk::AtRisk);
    }

    #[test]
    fn estimate_timeline_flags_on_track_for_generous_deadline() {
        let store = mk();
        let id = store.create_goal("x", "", Priority::Low, None).unwrap();
        // Low priority → 90 days. Give 365 day deadline → on track.
        let far = current_timestamp() + (365 * 86_400);
        store
            .conn
            .execute(
                "UPDATE goals SET deadline_unix = ?1 WHERE id = ?2",
                params![far, id],
            )
            .unwrap();
        let t = store
            .estimate_timeline(id, UserPace::NoHistory, 0.0)
            .unwrap();
        assert_eq!(t.deadline_risk, DeadlineRisk::OnTrack);
    }

    // ---- persistence --------------------------------------------

    #[test]
    fn file_backed_persists_across_reopen() {
        let dir = std::env::temp_dir()
            .join(format!("delphi-goals-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("goals.db");

        let id = {
            let s = GoalStore::open(&db).unwrap();
            s.create_goal("persist me", "", Priority::Medium, None)
                .unwrap()
        };

        {
            let s = GoalStore::open(&db).unwrap();
            assert_eq!(s.count().unwrap(), 1);
            let g = s.get_goal(id).unwrap();
            assert_eq!(g.title, "persist me");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_backed_enables_wal_mode() {
        let dir = std::env::temp_dir()
            .join(format!("delphi-goals-wal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("goals.db");
        let s = GoalStore::open(&db).unwrap();
        let mode: String = s
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- ordering / misc ---------------------------------------

    #[test]
    fn same_second_inserts_ordered_deterministically() {
        let store = mk();
        let a = store.create_goal("a", "", Priority::Low, None).unwrap();
        let b = store.create_goal("b", "", Priority::Low, None).unwrap();
        let c = store.create_goal("c", "", Priority::Low, None).unwrap();
        let list = store.list_active().unwrap();
        // created_at_unix DESC, id DESC — so newest id first regardless of
        // whether created_at timestamps are equal.
        assert_eq!(list[0].id, c);
        assert_eq!(list[1].id, b);
        assert_eq!(list[2].id, a);
    }

    #[test]
    fn busy_timeout_pinned_to_5_seconds() {
        // **Codex re-review FIX 20/F21 sibling consistency (round 7):**
        // every public `Connection::open` site in the orchestrator must
        // pin `busy_timeout` explicitly. Asserts `GoalStore::open` does
        // so. See CLAUDE.md SQLite-connection-policy.
        let tmpdir = tempfile::TempDir::new().unwrap();
        let db_path = tmpdir.path().join("goals.db");
        let store = GoalStore::open(&db_path).unwrap();
        let timeout: i64 = store
            .conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            timeout, 5_000,
            "GoalStore::open must pin busy_timeout to 5000ms per CLAUDE.md policy"
        );
    }
}
