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

use rusqlite::{params, Connection};
use tracing::{debug, info};

use crate::OrchestratorError;

/// Duration of the undo window in seconds (24 hours).
const UNDO_WINDOW_SECS: i64 = 24 * 60 * 60;

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
        let conn = Connection::open(path)
            .map_err(|e| OrchestratorError::Planning(format!("failed to open timeline db: {e}")))?;
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
            .map_err(|e| OrchestratorError::Planning(format!("failed to create in-memory db: {e}")))?;
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
                "INSERT INTO actions (action_id, description, timestamp, reversible, undo_command, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![action_id, description, now, true, undo_command, expires_at],
            )
            .map_err(|e| OrchestratorError::Planning(format!("failed to record action: {e}")))?;

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
    pub fn record_irreversible(
        &self,
        description: &str,
    ) -> Result<String, OrchestratorError> {
        let now = current_timestamp();
        let action_id = format!("tl-{now}-{}", rand_suffix());

        self.conn
            .execute(
                "INSERT INTO actions (action_id, description, timestamp, reversible, undo_command, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![action_id, description, now, false, "", now],
            )
            .map_err(|e| OrchestratorError::Planning(format!("failed to record action: {e}")))?;

        debug!(action_id = %action_id, description, "irreversible action recorded");
        Ok(action_id)
    }

    /// Attempt to undo an action.
    ///
    /// Returns the undo command if the action is within the 24-hour window.
    /// The caller is responsible for executing the command.
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

        let record: ActionRecord = self
            .conn
            .query_row(
                "SELECT action_id, description, timestamp, reversible, undo_command, expires_at FROM actions WHERE action_id = ?1",
                params![action_id],
                |row| {
                    Ok(ActionRecord {
                        action_id: row.get(0)?,
                        description: row.get(1)?,
                        timestamp: row.get(2)?,
                        reversible: row.get(3)?,
                        undo_command: row.get(4)?,
                        expires_at: row.get(5)?,
                    })
                },
            )
            .map_err(|_| {
                OrchestratorError::Planning(format!("action not found: {action_id}"))
            })?;

        if !record.reversible {
            return Err(OrchestratorError::Planning(format!(
                "action {action_id} is not reversible"
            )));
        }

        if now > record.expires_at {
            return Err(OrchestratorError::Planning(format!(
                "undo window expired for {action_id} (expired at {})",
                record.expires_at
            )));
        }

        // Mark as undone.
        self.conn
            .execute(
                "UPDATE actions SET reversible = 0, undo_command = '[UNDONE]' WHERE action_id = ?1",
                params![action_id],
            )
            .map_err(|e| OrchestratorError::Planning(format!("failed to mark undone: {e}")))?;

        info!(action_id, "action undone");
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
                "SELECT action_id, description, timestamp, reversible, undo_command, expires_at FROM actions ORDER BY timestamp DESC LIMIT ?1",
            )
            .map_err(|e| OrchestratorError::Planning(format!("query prepare failed: {e}")))?;

        let rows = stmt
            .query_map(params![count], |row| {
                Ok(ActionRecord {
                    action_id: row.get(0)?,
                    description: row.get(1)?,
                    timestamp: row.get(2)?,
                    reversible: row.get(3)?,
                    undo_command: row.get(4)?,
                    expires_at: row.get(5)?,
                })
            })
            .map_err(|e| OrchestratorError::Planning(format!("query failed: {e}")))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(
                row.map_err(|e| OrchestratorError::Planning(format!("row read failed: {e}")))?,
            );
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
            .execute(
                "DELETE FROM actions WHERE expires_at < ?1",
                params![now],
            )
            .map_err(|e| OrchestratorError::Planning(format!("cleanup failed: {e}")))?;

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
            .map_err(|e| OrchestratorError::Planning(format!("count failed: {e}")))?;
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
            .map_err(|e| OrchestratorError::Planning(format!("schema init failed: {e}")))?;
        Ok(())
    }
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
            tl.record_action(&format!("action {i}"), &format!("undo {i}")).unwrap();
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
}
