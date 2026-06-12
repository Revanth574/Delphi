// SPDX-License-Identifier: MIT

//! Action timeline with 24-hour undo system.
//!
//! Every AI action in Assisted/Autonomous mode creates an `ActionRecord`
//! stored in a local SQLite database. Each record has a 24-hour undo
//! window during which the user can reverse the action.
//!
//! # Iron Law #5
//!
//! "Everything the AI does is reversible. Every Autonomous action has a
//! 24-hour undo window. No irreversible AI action without explicit
//! biometric confirmation."

use std::path::Path;

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::OrchestratorError;
use crate::sqlite::{init_sqlite_connection, map_sqlite_err};

/// Duration of the undo window in seconds (24 hours).
const UNDO_WINDOW_SECS: i64 = 24 * 60 * 60;

/// Lifecycle status for an action timeline entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionStatus {
    /// Action was recorded before execution and has not reached a terminal outcome.
    Pending,
    /// Action completed and can be undone until `expires_at`.
    Complete,
    /// Action partially completed and remains undoable for cleanup.
    PartiallyCompleted,
    /// Action reached a terminal failed state.
    Failed,
    /// Undo is currently in progress.
    Undoing,
    /// Undo completed; the action cannot be undone again.
    Undone,
    /// Audit-only action with no undo operation.
    Irreversible,
}

impl ActionStatus {
    /// Stable database representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Complete => "complete",
            Self::PartiallyCompleted => "partially_completed",
            Self::Failed => "failed",
            Self::Undoing => "undoing",
            Self::Undone => "undone",
            Self::Irreversible => "irreversible",
        }
    }

    fn from_db(value: &str) -> rusqlite::Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "complete" => Ok(Self::Complete),
            "partially_completed" => Ok(Self::PartiallyCompleted),
            "failed" => Ok(Self::Failed),
            "undoing" => Ok(Self::Undoing),
            "undone" => Ok(Self::Undone),
            "irreversible" => Ok(Self::Irreversible),
            other => Err(rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown action status: {other}"),
                )),
            )),
        }
    }

    fn is_reversible_terminal(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Complete | Self::PartiallyCompleted | Self::Failed
        )
    }
}

/// A record of an AI action that can be undone.
///
/// # Examples
///
/// ```
/// use die_orchestrator::timeline::ActionRecord;
///
/// let record = ActionRecord {
///     action_id: "act-001".to_string(),
///     description: "Moved report.pdf to Archive/".to_string(),
///     timestamp: 1712400000,
///     reversible: true,
///     undo_command: "mv /home/user/Archive/report.pdf /home/user/Documents/report.pdf".to_string(),
///     expires_at: 1712400000 + 86400,
///     status: die_orchestrator::timeline::ActionStatus::Complete,
///     action_type: "generic".to_string(),
///     outputs: None,
/// };
/// assert!(record.reversible);
/// ```
#[derive(Debug, Clone)]
pub struct ActionRecord {
    /// Unique action identifier.
    pub action_id: String,
    /// Human-readable description of what was done.
    pub description: String,
    /// When the action was performed (UTC epoch seconds).
    pub timestamp: i64,
    /// Whether this action can be undone.
    pub reversible: bool,
    /// Command to execute to reverse the action.
    pub undo_command: String,
    /// When the undo window expires (UTC epoch seconds).
    pub expires_at: i64,
    /// Current lifecycle state.
    pub status: ActionStatus,
    /// Stable action type, e.g. `workspace.create`.
    pub action_type: String,
    /// Optional serialized outputs or partial-failure details.
    pub outputs: Option<String>,
}

/// Action timeline backed by SQLite.
///
/// # Examples
///
/// ```
/// use die_orchestrator::timeline::Timeline;
///
/// let tl = Timeline::in_memory().unwrap();
/// let id = tl.record_action("Moved file", "mv /a /b").unwrap();
/// assert!(!id.is_empty());
/// ```
pub struct Timeline {
    conn: Connection,
}

impl Timeline {
    /// Open or create a timeline database at the given path.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if the database can't be opened.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use die_orchestrator::timeline::Timeline;
    /// use std::path::Path;
    ///
    /// let tl = Timeline::open(Path::new("/tmp/timeline.db")).unwrap();
    /// ```
    pub fn open(path: &Path) -> Result<Self, OrchestratorError> {
        let conn =
            Connection::open(path).map_err(|e| map_sqlite_err(e, "failed to open timeline db"))?;
        // **Codex re-review FIX 22 (round 8):** route through the
        // shared `init_sqlite_connection` helper (CLAUDE.md SQLite
        // Connection Policy). Round-7 set `busy_timeout` directly
        // here; round-8 unified it across stores.
        init_sqlite_connection(&conn)
            .map_err(|e| map_sqlite_err(e, "timeline init_sqlite_connection"))?;
        let tl = Self { conn };
        tl.init_schema()?;
        info!("timeline database opened at {}", path.display());
        Ok(tl)
    }

    /// Create an in-memory timeline (for testing).
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if SQLite initialization fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::timeline::Timeline;
    /// let tl = Timeline::in_memory().unwrap();
    /// ```
    pub fn in_memory() -> Result<Self, OrchestratorError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| map_sqlite_err(e, "failed to create in-memory db"))?;
        // **Codex re-review FIX 23 (round 8):** in-memory constructor
        // parity. Default `:memory:` databases are private to a single
        // connection per SQLite docs and cannot see cross-connection
        // contention, so `busy_timeout` is functionally a no-op here.
        // Pinning it anyway keeps the init path uniform with `open` —
        // future drift where someone copies an init path and forgets
        // the pragma gets caught by the regression test.
        init_sqlite_connection(&conn).map_err(|e| map_sqlite_err(e, "timeline in_memory init"))?;
        let tl = Self { conn };
        tl.init_schema()?;
        Ok(tl)
    }

    /// Record an AI action with an undo command.
    ///
    /// The undo window is 24 hours from now.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if the database write fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::timeline::Timeline;
    ///
    /// let tl = Timeline::in_memory().unwrap();
    /// let id = tl.record_action("Moved file.txt to Archive/", "mv /Archive/file.txt /file.txt").unwrap();
    /// assert!(id.starts_with("tl-"));
    /// ```
    pub fn record_action(
        &self,
        description: &str,
        undo_command: &str,
    ) -> Result<String, OrchestratorError> {
        let now = current_timestamp();
        let expires_at = now + UNDO_WINDOW_SECS;
        let action_id = format!("tl-{now}-{}", rand_suffix());

        self.conn
            .execute(
                "INSERT INTO actions (
                    action_id, description, timestamp, reversible, undo_command, expires_at,
                    status, action_type, outputs
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)",
                params![
                    action_id,
                    description,
                    now,
                    true,
                    undo_command,
                    expires_at,
                    ActionStatus::Complete.as_str(),
                    "generic"
                ],
            )
            .map_err(|e| map_sqlite_err(e, "failed to record action"))?;

        debug!(action_id = %action_id, description, "action recorded");
        Ok(action_id)
    }

    /// Record a non-reversible action (for audit purposes only).
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if the database write fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::timeline::Timeline;
    ///
    /// let tl = Timeline::in_memory().unwrap();
    /// let id = tl.record_irreversible("Sent email to user@example.com").unwrap();
    /// ```
    pub fn record_irreversible(&self, description: &str) -> Result<String, OrchestratorError> {
        let now = current_timestamp();
        let action_id = format!("tl-{now}-{}", rand_suffix());

        self.conn
            .execute(
                "INSERT INTO actions (
                    action_id, description, timestamp, reversible, undo_command, expires_at,
                    status, action_type, outputs
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)",
                params![
                    action_id,
                    description,
                    now,
                    false,
                    "",
                    now,
                    ActionStatus::Irreversible.as_str(),
                    "generic"
                ],
            )
            .map_err(|e| map_sqlite_err(e, "failed to record action"))?;

        debug!(action_id = %action_id, description, "irreversible action recorded");
        Ok(action_id)
    }

    /// Record an action before it mutates state.
    ///
    /// The `payload` is the undo payload the caller will need later.
    /// For workspace creation this is the workspace root path.
    pub fn record_pending(
        &self,
        action_type: &str,
        payload: &str,
        description: &str,
    ) -> Result<String, OrchestratorError> {
        let now = current_timestamp();
        let expires_at = now + UNDO_WINDOW_SECS;
        let action_id = format!("tl-{now}-{}", rand_suffix());

        self.conn
            .execute(
                "INSERT INTO actions (
                    action_id, description, timestamp, reversible, undo_command, expires_at,
                    status, action_type, outputs
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)",
                params![
                    action_id,
                    description,
                    now,
                    true,
                    payload,
                    expires_at,
                    ActionStatus::Pending.as_str(),
                    action_type
                ],
            )
            .map_err(|e| map_sqlite_err(e, "failed to record pending action"))?;

        debug!(action_id = %action_id, action_type, "pending action recorded");
        Ok(action_id)
    }

    /// Record an audit-only action before it executes.
    ///
    /// Use this for observation or check workflows that must be visible in the
    /// timeline but do not have a meaningful undo operation.
    pub fn record_pending_irreversible(
        &self,
        action_type: &str,
        description: &str,
    ) -> Result<String, OrchestratorError> {
        let now = current_timestamp();
        let action_id = format!("tl-{now}-{}", rand_suffix());

        self.conn
            .execute(
                "INSERT INTO actions (
                    action_id, description, timestamp, reversible, undo_command, expires_at,
                    status, action_type, outputs
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)",
                params![
                    action_id,
                    description,
                    now,
                    false,
                    "",
                    now,
                    ActionStatus::Pending.as_str(),
                    action_type
                ],
            )
            .map_err(|e| map_sqlite_err(e, "failed to record pending irreversible action"))?;

        debug!(action_id = %action_id, action_type, "pending irreversible action recorded");
        Ok(action_id)
    }

    /// Transition a pending action to complete.
    pub fn complete_pending(
        &self,
        action_id: &str,
        outputs: Option<&str>,
    ) -> Result<(), OrchestratorError> {
        self.transition_pending(action_id, ActionStatus::Complete, outputs)
    }

    /// Transition a pending action to failed.
    pub fn fail_pending(
        &self,
        action_id: &str,
        outputs: Option<&str>,
    ) -> Result<(), OrchestratorError> {
        self.transition_pending(action_id, ActionStatus::Failed, outputs)
    }

    /// Transition a pending action to partially completed.
    pub fn mark_pending_partial(
        &self,
        action_id: &str,
        partial_state: &str,
    ) -> Result<(), OrchestratorError> {
        self.transition_pending(
            action_id,
            ActionStatus::PartiallyCompleted,
            Some(partial_state),
        )
    }

    fn transition_pending(
        &self,
        action_id: &str,
        status: ActionStatus,
        outputs: Option<&str>,
    ) -> Result<(), OrchestratorError> {
        let changed = self
            .conn
            .execute(
                "UPDATE actions
                 SET status = ?1, outputs = ?2
                 WHERE action_id = ?3 AND status = ?4",
                params![
                    status.as_str(),
                    outputs,
                    action_id,
                    ActionStatus::Pending.as_str()
                ],
            )
            .map_err(|e| map_sqlite_err(e, "failed to finalize pending action"))?;
        if changed == 0 {
            tracing::debug!(action_id, "complete_pending: action is not pending");
            return Err(OrchestratorError::Conflict {
                domain: "timeline",
                reason: "action is not pending",
            });
        }
        Ok(())
    }

    /// Transition a reversible action to `Undoing` and return its undo payload.
    pub fn begin_undo(&self, action_id: &str) -> Result<String, OrchestratorError> {
        let now = current_timestamp();
        let record = self.get_action(action_id)?;

        if !record.reversible || !record.status.is_reversible_terminal() {
            tracing::debug!(action_id, "action is not reversible");
            return Err(OrchestratorError::Conflict {
                domain: "timeline",
                reason: "action is not reversible",
            });
        }

        if now > record.expires_at {
            tracing::debug!(
                action_id,
                expires_at = record.expires_at,
                "undo window expired"
            );
            return Err(OrchestratorError::Conflict {
                domain: "timeline",
                reason: "undo window expired",
            });
        }

        let changed = self
            .conn
            .execute(
                "UPDATE actions
                 SET status = ?1, undo_restore_status = ?2
                 WHERE action_id = ?3 AND status = ?2 AND reversible = 1",
                params![
                    ActionStatus::Undoing.as_str(),
                    record.status.as_str(),
                    action_id
                ],
            )
            .map_err(|e| map_sqlite_err(e, "failed to mark undoing"))?;
        if changed == 0 {
            tracing::debug!(action_id, "begin_undo: could not enter undoing state");
            return Err(OrchestratorError::Conflict {
                domain: "timeline",
                reason: "action could not enter undoing state",
            });
        }

        Ok(record.undo_command)
    }

    /// Mark a previously begun undo as complete.
    pub fn complete_undo(&self, action_id: &str) -> Result<(), OrchestratorError> {
        let changed = self
            .conn
            .execute(
                "UPDATE actions
                 SET reversible = 0, undo_command = '[UNDONE]', status = ?1,
                     undo_restore_status = NULL
                 WHERE action_id = ?2 AND status = ?3",
                params![
                    ActionStatus::Undone.as_str(),
                    action_id,
                    ActionStatus::Undoing.as_str()
                ],
            )
            .map_err(|e| map_sqlite_err(e, "failed to mark undone"))?;
        if changed == 0 {
            tracing::debug!(action_id, "action is not undoing");
            return Err(OrchestratorError::Conflict {
                domain: "timeline",
                reason: "action is not undoing",
            });
        }
        info!(action_id, "action undone");
        Ok(())
    }

    /// Return an undoing action to its prior reversible state.
    pub fn abort_undo(&self, action_id: &str) -> Result<(), OrchestratorError> {
        let restore_status: Option<String> = self
            .conn
            .query_row(
                "SELECT undo_restore_status FROM actions WHERE action_id = ?1 AND status = ?2",
                params![action_id, ActionStatus::Undoing.as_str()],
                |row| row.get(0),
            )
            .map_err(|e| map_sqlite_err(e, "abort_undo lookup"))?;
        let restore_status =
            restore_status.unwrap_or_else(|| ActionStatus::Complete.as_str().to_string());
        ActionStatus::from_db(&restore_status)
            .map_err(|e| map_sqlite_err(e, "abort_undo restore status"))?;

        let changed = self
            .conn
            .execute(
                "UPDATE actions
                 SET status = ?1, reversible = 1, undo_restore_status = NULL
                 WHERE action_id = ?2 AND status = ?3",
                params![restore_status, action_id, ActionStatus::Undoing.as_str()],
            )
            .map_err(|e| map_sqlite_err(e, "failed to abort undo"))?;
        if changed == 0 {
            tracing::debug!(action_id, "action is not undoing");
            return Err(OrchestratorError::Conflict {
                domain: "timeline",
                reason: "action is not undoing",
            });
        }
        Ok(())
    }

    /// Return the current status for tests and service diagnostics.
    pub fn get_action_status(&self, action_id: &str) -> Result<ActionStatus, OrchestratorError> {
        Ok(self.get_action(action_id)?.status)
    }

    /// Return the undo payload without mutating timeline state.
    ///
    /// This is for planning and UI previews only. Callers that actually run an
    /// undo must use `begin_undo`, execute the reversing operation, then call
    /// `complete_undo` or `abort_undo`.
    pub fn preview_undo(&self, action_id: &str) -> Result<String, OrchestratorError> {
        let now = current_timestamp();
        let record = self.get_action(action_id)?;

        if !record.reversible || !record.status.is_reversible_terminal() {
            tracing::debug!(action_id, "action is not reversible");
            return Err(OrchestratorError::Conflict {
                domain: "timeline",
                reason: "action is not reversible",
            });
        }

        if now > record.expires_at {
            tracing::debug!(
                action_id,
                expires_at = record.expires_at,
                "undo window expired"
            );
            return Err(OrchestratorError::Conflict {
                domain: "timeline",
                reason: "undo window expired",
            });
        }

        Ok(record.undo_command)
    }

    /// List actions still in pending state.
    pub fn list_pending_actions(&self) -> Result<Vec<ActionRecord>, OrchestratorError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT action_id, description, timestamp, reversible, undo_command, expires_at,
                        status, action_type, outputs
                 FROM actions WHERE status = ?1 ORDER BY timestamp DESC",
            )
            .map_err(|e| map_sqlite_err(e, "pending query prepare failed"))?;
        let rows = stmt
            .query_map(
                params![ActionStatus::Pending.as_str()],
                row_to_action_record,
            )
            .map_err(|e| map_sqlite_err(e, "pending query failed"))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| map_sqlite_err(e, "pending row read failed"))?);
        }
        Ok(results)
    }

    fn get_action(&self, action_id: &str) -> Result<ActionRecord, OrchestratorError> {
        use rusqlite::OptionalExtension;
        self.conn
            .query_row(
                "SELECT action_id, description, timestamp, reversible, undo_command, expires_at,
                        status, action_type, outputs
                 FROM actions WHERE action_id = ?1",
                params![action_id],
                row_to_action_record,
            )
            .optional()
            .map_err(|e| map_sqlite_err(e, "action lookup"))?
            .ok_or(OrchestratorError::NotFound { entity: "action" })
    }

    /// Preview the undo payload for an action.
    ///
    /// Returns the undo command if the action is within the 24-hour window.
    /// This compatibility method does not mutate action state. Callers that
    /// actually execute undo must use `begin_undo`, execute the reversing
    /// operation, then call `complete_undo` or `abort_undo`.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if the action is not found,
    /// not reversible, or the undo window has expired.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::timeline::Timeline;
    ///
    /// let tl = Timeline::in_memory().unwrap();
    /// let id = tl.record_action("test", "echo undo").unwrap();
    /// let cmd = tl.undo_action(&id).unwrap();
    /// assert_eq!(cmd, "echo undo");
    /// ```
    pub fn undo_action(&self, action_id: &str) -> Result<String, OrchestratorError> {
        let now = current_timestamp();

        // **Codex re-review FIX 25 (round 9):** the previous
        // `.map_err(|_| Planning("action not found: ..."))` discarded
        // every rusqlite error and unconditionally produced a "not
        // found" message — masking `SQLITE_BUSY`/`SQLITE_LOCKED` as
        // "missing row" when in fact the row is there but the DB is
        // locked. A typed retry on `TransientLock` would look in the
        // wrong place ("does the row exist somewhere else?") instead
        // of doing the right thing (wait + retry this same query).
        //
        // Fix: `.optional()` converts only `QueryReturnedNoRows` →
        // `Ok(None)`; every other rusqlite error propagates as
        // `Err(e)`. Routing those through `map_sqlite_err` preserves
        // `TransientLock` semantics for `DatabaseBusy`/`DatabaseLocked`
        // while still producing a descriptive "action not found"
        // error for the genuine missing-row case via `ok_or_else`.
        use rusqlite::OptionalExtension;
        let record: ActionRecord = self
            .conn
            .query_row(
                "SELECT action_id, description, timestamp, reversible, undo_command, expires_at,
                        status, action_type, outputs
                 FROM actions WHERE action_id = ?1",
                params![action_id],
                |row| {
                    Ok(ActionRecord {
                        action_id: row.get(0)?,
                        description: row.get(1)?,
                        timestamp: row.get(2)?,
                        reversible: row.get(3)?,
                        undo_command: row.get(4)?,
                        expires_at: row.get(5)?,
                        status: ActionStatus::from_db(row.get::<_, String>(6)?.as_str())?,
                        action_type: row.get(7)?,
                        outputs: row.get(8)?,
                    })
                },
            )
            .optional()
            .map_err(|e| map_sqlite_err(e, "undo_action lookup"))?
            .ok_or(OrchestratorError::NotFound { entity: "action" })?;

        if !record.reversible || !record.status.is_reversible_terminal() {
            tracing::debug!(action_id, "action is not reversible");
            return Err(OrchestratorError::Conflict {
                domain: "timeline",
                reason: "action is not reversible",
            });
        }

        if now > record.expires_at {
            tracing::debug!(
                action_id,
                expires_at = record.expires_at,
                "undo window expired"
            );
            return Err(OrchestratorError::Conflict {
                domain: "timeline",
                reason: "undo window expired",
            });
        }

        debug!(
            action_id,
            "undo_action returned undo payload without mutating state"
        );
        Ok(record.undo_command)
    }

    /// List the most recent actions.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if the query fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::timeline::Timeline;
    ///
    /// let tl = Timeline::in_memory().unwrap();
    /// tl.record_action("action 1", "undo 1").unwrap();
    /// tl.record_action("action 2", "undo 2").unwrap();
    /// let recent = tl.list_recent(10).unwrap();
    /// assert_eq!(recent.len(), 2);
    /// ```
    pub fn list_recent(&self, count: u32) -> Result<Vec<ActionRecord>, OrchestratorError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT action_id, description, timestamp, reversible, undo_command, expires_at,
                        status, action_type, outputs
                 FROM actions ORDER BY timestamp DESC LIMIT ?1",
            )
            .map_err(|e| map_sqlite_err(e, "query prepare failed"))?;

        let rows = stmt
            .query_map(params![count], row_to_action_record)
            .map_err(|e| map_sqlite_err(e, "query failed"))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| map_sqlite_err(e, "row read failed"))?);
        }

        Ok(results)
    }

    /// Remove expired actions (older than 24 hours).
    ///
    /// Returns the number of entries removed.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if the deletion fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::timeline::Timeline;
    ///
    /// let tl = Timeline::in_memory().unwrap();
    /// let cleaned = tl.cleanup_expired().unwrap();
    /// assert_eq!(cleaned, 0);
    /// ```
    pub fn cleanup_expired(&self) -> Result<usize, OrchestratorError> {
        let now = current_timestamp();
        let deleted = self
            .conn
            .execute("DELETE FROM actions WHERE expires_at < ?1", params![now])
            .map_err(|e| map_sqlite_err(e, "cleanup failed"))?;

        if deleted > 0 {
            debug!("cleaned up {deleted} expired actions");
        }

        Ok(deleted)
    }

    /// Total number of actions in the timeline.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if the query fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::timeline::Timeline;
    /// let tl = Timeline::in_memory().unwrap();
    /// assert_eq!(tl.count().unwrap(), 0);
    /// ```
    pub fn count(&self) -> Result<usize, OrchestratorError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM actions", [], |row| row.get(0))
            .map_err(|e| map_sqlite_err(e, "count failed"))?;
        Ok(count as usize)
    }

    /// Initialize the SQLite schema.
    fn init_schema(&self) -> Result<(), OrchestratorError> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS actions (
                    action_id TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    reversible INTEGER NOT NULL,
                    undo_command TEXT NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_actions_timestamp ON actions(timestamp);
                CREATE INDEX IF NOT EXISTS idx_actions_expires ON actions(expires_at);",
            )
            .map_err(|e| map_sqlite_err(e, "schema init failed"))?;
        self.ensure_column("status", "TEXT NOT NULL DEFAULT 'complete'")?;
        self.ensure_column("action_type", "TEXT NOT NULL DEFAULT 'generic'")?;
        self.ensure_column("outputs", "TEXT")?;
        self.ensure_column("undo_restore_status", "TEXT")?;
        self.conn
            .execute(
                "UPDATE actions
                 SET status = ?1
                 WHERE reversible = 0 AND undo_command = '[UNDONE]' AND status = ?2",
                params![
                    ActionStatus::Undone.as_str(),
                    ActionStatus::Complete.as_str()
                ],
            )
            .map_err(|e| map_sqlite_err(e, "schema status backfill undone"))?;
        self.conn
            .execute(
                "UPDATE actions
                 SET status = ?1
                 WHERE reversible = 0 AND undo_command != '[UNDONE]' AND status = ?2",
                params![
                    ActionStatus::Irreversible.as_str(),
                    ActionStatus::Complete.as_str()
                ],
            )
            .map_err(|e| map_sqlite_err(e, "schema status backfill irreversible"))?;
        Ok(())
    }

    fn ensure_column(&self, name: &str, ddl: &str) -> Result<(), OrchestratorError> {
        let mut stmt = self
            .conn
            .prepare("PRAGMA table_info(actions)")
            .map_err(|e| map_sqlite_err(e, "schema inspect failed"))?;
        let columns = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|e| map_sqlite_err(e, "schema inspect query failed"))?;
        for column in columns {
            if column.map_err(|e| map_sqlite_err(e, "schema inspect row failed"))? == name {
                return Ok(());
            }
        }

        self.conn
            .execute_batch(&format!("ALTER TABLE actions ADD COLUMN {name} {ddl};"))
            .map_err(|e| map_sqlite_err(e, "schema migration failed"))?;
        Ok(())
    }
}

fn row_to_action_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<ActionRecord> {
    let status = row.get::<_, String>(6)?;
    Ok(ActionRecord {
        action_id: row.get(0)?,
        description: row.get(1)?,
        timestamp: row.get(2)?,
        reversible: row.get(3)?,
        undo_command: row.get(4)?,
        expires_at: row.get(5)?,
        status: ActionStatus::from_db(&status)?,
        action_type: row.get(7)?,
        outputs: row.get(8)?,
    })
}

/// Get current UTC timestamp as epoch seconds.
fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Generate a short random suffix for action IDs.
fn rand_suffix() -> u32 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let s = RandomState::new();
    let mut h = s.build_hasher();
    h.write_u64(current_timestamp() as u64);
    (h.finish() % 1_000_000) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ORCH-R1-07: public-boundary action_id leaks → typed NotFound/Conflict ──
    #[test]
    fn undo_missing_action_is_notfound_no_id_leak_orch_r1_07() {
        let tl = Timeline::in_memory().unwrap();
        let err = tl.undo_action("tl-secret-abc").unwrap_err();
        assert!(
            matches!(err, OrchestratorError::NotFound { entity: "action" }),
            "got {err:?}"
        );
        assert!(
            !err.to_string().contains("tl-secret-abc"),
            "action_id leaked into error Display: {err}"
        );
    }

    #[test]
    fn get_action_status_missing_is_notfound_no_id_leak_orch_r1_07() {
        let tl = Timeline::in_memory().unwrap();
        let err = tl.get_action_status("tl-secret-def").unwrap_err();
        assert!(
            matches!(err, OrchestratorError::NotFound { entity: "action" }),
            "got {err:?}"
        );
        assert!(
            !err.to_string().contains("tl-secret-def"),
            "action_id leaked into error Display: {err}"
        );
    }

    #[test]
    fn undo_irreversible_action_is_conflict_no_id_leak_orch_r1_07() {
        let tl = Timeline::in_memory().unwrap();
        let id = tl.record_irreversible("did a thing").unwrap();
        let err = tl.undo_action(&id).unwrap_err();
        assert!(
            matches!(
                err,
                OrchestratorError::Conflict {
                    domain: "timeline",
                    ..
                }
            ),
            "got {err:?}"
        );
        assert!(
            !err.to_string().contains(&id),
            "action_id leaked into conflict Display: {err}"
        );
    }

    #[test]
    fn create_in_memory_timeline() {
        let tl = Timeline::in_memory().unwrap();
        assert_eq!(tl.count().unwrap(), 0);
    }

    #[test]
    fn record_and_list_actions() {
        let tl = Timeline::in_memory().unwrap();
        tl.record_action("Moved file A", "mv /b /a").unwrap();
        tl.record_action("Moved file B", "mv /c /b").unwrap();

        let recent = tl.list_recent(10).unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(tl.count().unwrap(), 2);
    }

    #[test]
    fn undo_within_window_succeeds() {
        let tl = Timeline::in_memory().unwrap();
        let id = tl.record_action("test action", "echo undone").unwrap();

        let cmd = tl.undo_action(&id).unwrap();
        assert_eq!(cmd, "echo undone");

        // Cannot undo twice.
        assert!(tl.undo_action(&id).is_err());
    }

    #[test]
    fn pending_action_can_complete() {
        let tl = Timeline::in_memory().unwrap();
        let id = tl
            .record_pending("workspace.create", "/tmp/ws", "create ws")
            .unwrap();
        assert_eq!(tl.get_action_status(&id).unwrap(), ActionStatus::Pending);
        tl.complete_pending(&id, Some(r#""Completed""#)).unwrap();
        assert_eq!(tl.get_action_status(&id).unwrap(), ActionStatus::Complete);
    }

    #[test]
    fn pending_irreversible_action_can_complete_without_undo() {
        let tl = Timeline::in_memory().unwrap();
        let id = tl
            .record_pending_irreversible("developer.workflow", "inspect repo")
            .unwrap();
        assert_eq!(tl.get_action_status(&id).unwrap(), ActionStatus::Pending);
        tl.complete_pending(&id, Some(r#"{"ok":true}"#)).unwrap();
        assert_eq!(tl.get_action_status(&id).unwrap(), ActionStatus::Complete);
        let err = tl.undo_action(&id).unwrap_err();
        assert!(
            matches!(
                err,
                OrchestratorError::Conflict {
                    domain: "timeline",
                    ..
                }
            ),
            "irreversible workflow should not produce an undo command: {err:?}"
        );
    }

    #[test]
    fn pending_action_can_fail_terminally() {
        let tl = Timeline::in_memory().unwrap();
        let id = tl
            .record_pending_irreversible("developer.workflow", "inspect repo")
            .unwrap();
        tl.fail_pending(&id, Some(r#"{"ok":false}"#)).unwrap();
        assert_eq!(tl.get_action_status(&id).unwrap(), ActionStatus::Failed);
    }

    #[test]
    fn abort_undo_restores_reversible_status() {
        let tl = Timeline::in_memory().unwrap();
        let id = tl.record_action("test action", "echo undone").unwrap();
        let payload = tl.begin_undo(&id).unwrap();
        assert_eq!(payload, "echo undone");
        assert_eq!(tl.get_action_status(&id).unwrap(), ActionStatus::Undoing);
        tl.abort_undo(&id).unwrap();
        assert_eq!(tl.get_action_status(&id).unwrap(), ActionStatus::Complete);
        assert_eq!(tl.begin_undo(&id).unwrap(), "echo undone");
    }

    #[test]
    fn undo_nonexistent_action_fails() {
        let tl = Timeline::in_memory().unwrap();
        assert!(tl.undo_action("nope").is_err());
    }

    #[test]
    fn irreversible_action_cannot_be_undone() {
        let tl = Timeline::in_memory().unwrap();
        let id = tl.record_irreversible("sent email").unwrap();
        assert!(tl.undo_action(&id).is_err());
    }

    #[test]
    fn cleanup_removes_nothing_when_fresh() {
        let tl = Timeline::in_memory().unwrap();
        tl.record_action("fresh action", "undo").unwrap();
        let cleaned = tl.cleanup_expired().unwrap();
        assert_eq!(cleaned, 0);
    }

    #[test]
    fn action_id_format() {
        let tl = Timeline::in_memory().unwrap();
        let id = tl.record_action("test", "undo").unwrap();
        assert!(id.starts_with("tl-"));
    }

    #[test]
    fn list_recent_respects_limit() {
        let tl = Timeline::in_memory().unwrap();
        for i in 0..5 {
            tl.record_action(&format!("action {i}"), &format!("undo {i}"))
                .unwrap();
        }
        let recent = tl.list_recent(3).unwrap();
        assert_eq!(recent.len(), 3);
    }

    #[test]
    fn file_based_timeline_persists() {
        let dir = std::env::temp_dir().join(format!("delphi-tl-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("timeline.db");

        {
            let tl = Timeline::open(&db_path).unwrap();
            tl.record_action("action A", "undo A").unwrap();
            tl.record_action("action B", "undo B").unwrap();
        }

        {
            let tl = Timeline::open(&db_path).unwrap();
            assert_eq!(tl.count().unwrap(), 2);
            let recent = tl.list_recent(10).unwrap();
            assert_eq!(recent.len(), 2);
        }
    }

    #[test]
    fn busy_timeout_pinned_to_5_seconds() {
        // **Codex re-review FIX 20/F21 sibling consistency (round 7):**
        // every public `Connection::open` site in the orchestrator must
        // pin `busy_timeout` explicitly rather than rely on rusqlite's
        // default (currently 5000ms but documented as "subject to
        // change"). This test asserts `Timeline::open` does so. The
        // value 5000 matches the CLAUDE.md SQLite-connection-policy
        // baseline.
        let tmpdir = tempfile::TempDir::new().unwrap();
        let db_path = tmpdir.path().join("timeline.db");
        let tl = Timeline::open(&db_path).unwrap();
        let timeout: i64 = tl
            .conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            timeout, 5_000,
            "Timeline::open must pin busy_timeout to 5000ms per CLAUDE.md policy"
        );
    }

    #[test]
    fn in_memory_busy_timeout_pinned_to_5_seconds() {
        // **Codex re-review FIX 23 (round 8):** in-memory constructor
        // parity. Default `:memory:` DBs cannot see cross-connection
        // contention so `busy_timeout` is functionally a no-op here,
        // but the policy mandates uniform init to catch future drift
        // (someone copying an init path and forgetting the pragma).
        let tl = Timeline::in_memory().unwrap();
        let timeout: i64 = tl
            .conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            timeout, 5_000,
            "Timeline::in_memory must pin busy_timeout to 5000ms (F23 constructor parity)"
        );
    }

    // ── Codex re-review FIX 22 (round 8): sibling typed routing ──

    #[test]
    fn timeline_routes_database_busy_to_transient_lock() {
        // Sibling consistency: SQLITE_BUSY surfaced from a Timeline
        // rusqlite op must come out as TransientLock so daemons can
        // typed-retry. Pre-F22 this routed to Planning via the
        // direct `map_err(|e| OrchestratorError::Planning(...))`
        // calls that pervaded timeline.rs.
        let err = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some("test".to_string()),
        );
        let mapped = map_sqlite_err(err, "timeline test");
        assert!(
            matches!(mapped, OrchestratorError::TransientLock { .. }),
            "SQLITE_BUSY routed via timeline's shared helper must be TransientLock"
        );
    }

    #[test]
    fn timeline_routes_database_locked_to_transient_lock() {
        let err = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_LOCKED),
            None,
        );
        let mapped = map_sqlite_err(err, "timeline test");
        assert!(matches!(mapped, OrchestratorError::TransientLock { .. }));
    }

    #[test]
    fn timeline_preserves_planning_for_non_lock_sqlite_failures() {
        let err = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
            Some("UNIQUE failed".to_string()),
        );
        let mapped = map_sqlite_err(err, "timeline test");
        assert!(matches!(mapped, OrchestratorError::Planning(_)));
    }

    // ── Codex re-review FIX 25 (round 9): query_row error preservation ──

    #[test]
    fn undo_action_missing_row_returns_notfound_not_transient_lock() {
        // **F25 regression — Part 1 of 2.** Pre-F25, `undo_action`'s bare
        // `.map_err(|_| Planning("action not found: {id}"))` chain produced the
        // not-found error for EVERY rusqlite error, including `SQLITE_BUSY` /
        // `SQLITE_LOCKED`. Post-F25 the missing-row path goes through
        // `.optional() + ok_or_else`, confining it to the genuine
        // `QueryReturnedNoRows` case; the companion `_routes_database_busy_*`
        // test below covers the lock-error half.
        //
        // ORCH-R1-07 then replaced the free-string Planning (which leaked the
        // action_id) with the typed, leak-free `NotFound { entity: "action" }`;
        // the no-leak property is pinned by the `..._no_id_leak_orch_r1_07`
        // test. This test pins the surviving F25 invariant: the missing-row
        // branch stays NotFound, never conflated with the transient-lock branch.
        let tl = Timeline::in_memory().unwrap();
        let err = tl.undo_action("tl-nonexistent-id").unwrap_err();
        assert!(
            matches!(err, OrchestratorError::NotFound { entity: "action" }),
            "missing-row must be NotFound(action), not {err:?} \
             (F25: distinct from TransientLock)"
        );
    }

    #[test]
    fn undo_action_optional_chain_routes_database_busy_to_transient_lock() {
        // **F25 regression — Part 2 of 2.** Pre-F25, `undo_action`'s
        // bare `.map_err(|_| Planning("action not found: {id}"))`
        // discarded the rusqlite error and reported "action not
        // found" for *every* failure mode, including SQLITE_BUSY /
        // SQLITE_LOCKED. A typed caller retrying on `TransientLock`
        // would never see one — they'd see a `Planning` "not found"
        // and look elsewhere for the row instead of waiting + retrying
        // the same query.
        //
        // Post-F25, the chain is:
        //
        //     .query_row(...)        // rusqlite::Result<T>
        //     .optional()            // rusqlite::Result<Option<T>>  (only NoRows → None)
        //     .map_err(|e| map_sqlite_err(e, "undo_action lookup"))?
        //     .ok_or_else(|| Planning("action not found: {id}"))?
        //
        // The undo_action call-site closure is inline and not testable
        // in isolation, so this test exercises the chain semantically:
        // a synthetic `SqliteFailure(SQLITE_BUSY)` threaded through
        // `.optional()` must propagate as `Err` (NOT collapse to
        // `Ok(None)` — that's the rusqlite contract F25 relies on),
        // and the same error routed through `map_sqlite_err` with
        // the call-site's context string must produce `TransientLock`.
        // Together this proves the post-F25 chain is correct for
        // both halves of its case analysis.
        use rusqlite::OptionalExtension;

        let synthetic_busy = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some("test database is locked".to_string()),
        );

        // Step 1: `.optional()` must NOT swallow SqliteFailure(BUSY).
        // If rusqlite ever changes this contract, this assertion trips
        // immediately — the F25 fix would be silently invalidated.
        let optional_result: Result<Option<()>, rusqlite::Error> =
            Err::<(), _>(synthetic_busy).optional();
        let propagated_err = optional_result.expect_err(
            "OptionalExtension::optional must propagate SqliteFailure(BUSY) — \
             F25's correctness depends on this rusqlite contract",
        );

        // Step 2: the propagated error, run through `map_sqlite_err`
        // with the exact context string used at the `undo_action`
        // call site, must produce `TransientLock`.
        let mapped = map_sqlite_err(propagated_err, "undo_action lookup");
        assert!(
            matches!(mapped, OrchestratorError::TransientLock { .. }),
            "SQLITE_BUSY threaded through the F25 undo_action chain must \
             yield TransientLock so daemons can typed-retry, NOT Planning \
             'action not found' (pre-F25 bug); got {mapped:?}"
        );
    }
}
