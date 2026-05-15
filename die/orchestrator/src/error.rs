// SPDX-License-Identifier: MIT

//! Error types for the DIE orchestrator.
//!
//! The orchestrator aggregates errors from all downstream crates via
//! `#[from]` conversions. If this file compiles, the entire dependency
//! DAG is proven correct.
//!
//! Per CLAUDE.md Section 8: orchestrator errors must **never** crash
//! the OS. They degrade gracefully to the next available tier or mode.

use die_browser::BrowserError;
use die_inference::InferenceError;
use die_learning::LearningError;
use fortress::FortressError;
use semantic_fs::SemanticFsError;

/// Errors produced by the DIE orchestrator.
///
/// This enum has `From` implementations for all downstream error types,
/// enabling the `?` operator across crate boundaries.
///
/// # Examples
///
/// ```
/// use die_orchestrator::OrchestratorError;
/// use fortress::FortressError;
///
/// let err = FortressError::Tpm("device not found".to_string());
/// let orch_err: OrchestratorError = err.into();
/// assert!(orch_err.to_string().contains("TPM"));
/// ```
#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    /// Intent planning or decomposition failed.
    #[error("planning failed: {0}")]
    Planning(String),

    /// D-Bus communication with the shell failed.
    #[error("D-Bus error: {0}")]
    Dbus(String),

    /// Inference subsystem error (propagated from die-inference).
    #[error("inference error: {0}")]
    Inference(#[from] InferenceError),

    /// Semantic file system error (propagated from semantic-fs).
    #[error("search error: {0}")]
    Search(#[from] SemanticFsError),

    /// Security subsystem error (propagated from fortress).
    #[error("security error: {0}")]
    Security(#[from] FortressError),

    /// Browser engine error (propagated from die-browser).
    #[error("browser error: {0}")]
    Browser(#[from] BrowserError),

    /// Learning engine error (propagated from die-learning).
    #[error("learning error: {0}")]
    Learning(#[from] LearningError),

    /// Ambient environment sensing failed (sysfs/procfs path missing,
    /// malformed sensor output, subprocess error, etc.). Never crashes
    /// the orchestrator — consumers degrade gracefully.
    #[error("environment error: {0}")]
    Environment(String),

    /// SQLite lock contention exhausted the connection's `busy_timeout`.
    /// Surfaced when `map_sqlite_err` translates a
    /// `rusqlite::Error::SqliteFailure` whose `code` is
    /// `ErrorCode::DatabaseBusy` (SQLITE_BUSY — another connection or
    /// process holds an incompatible lock) or `ErrorCode::DatabaseLocked`
    /// (SQLITE_LOCKED — same connection, shared-cache conflict). Both
    /// are transient and retryable.
    ///
    /// **Codex re-review FIX 21 (round 7):** before this variant the
    /// post-F19 backfill path mapped `busy_timeout` exhaustion through
    /// `map_sqlite_err` into `Planning("knowledge sqlite: database is
    /// locked")`. The string survived but the structured rusqlite
    /// `ErrorCode` was lost, so daemons could not distinguish transient
    /// lock contention from genuine schema/logic failures except by
    /// string matching. Routing the two retryable error codes into a
    /// dedicated typed variant lets callers (`KnowledgeStore::open`
    /// internally, and downstream daemons externally) pattern-match
    /// for typed retry policy.
    ///
    /// The full `rusqlite::Error` is preserved as `source` so callers
    /// that want to inspect extended codes (`SQLITE_BUSY_RECOVERY`,
    /// `SQLITE_BUSY_SNAPSHOT`, `SQLITE_LOCKED_SHAREDCACHE`, etc.) can
    /// reach the `ffi::Error` inside. The base `code` field already
    /// masks extended codes to the same `DatabaseBusy`/`DatabaseLocked`
    /// variant per libsqlite3-sys's `Error::new`, so matching on `code`
    /// alone catches both base and extended cases.
    #[error("transient sqlite lock contention: {source}")]
    TransientLock {
        #[source]
        source: rusqlite::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inference_error_converts() {
        let err = InferenceError::Timeout(3000);
        let orch_err: OrchestratorError = err.into();
        assert!(orch_err.to_string().contains("3000"));
    }

    #[test]
    fn semantic_fs_error_converts() {
        let err = SemanticFsError::Indexing("corrupt index".to_string());
        let orch_err: OrchestratorError = err.into();
        assert!(orch_err.to_string().contains("corrupt"));
    }

    #[test]
    fn fortress_error_converts() {
        let err = FortressError::VaultInaccessible("locked".to_string());
        let orch_err: OrchestratorError = err.into();
        assert!(orch_err.to_string().contains("locked"));
    }

    #[test]
    fn browser_error_converts() {
        let err = BrowserError::Timeout { seconds: 30 };
        let orch_err: OrchestratorError = err.into();
        assert!(orch_err.to_string().contains("30"));
    }

    #[test]
    fn learning_error_converts() {
        let err = LearningError::ObserverPaused;
        let orch_err: OrchestratorError = err.into();
        assert!(orch_err.to_string().contains("paused"));
    }

    #[test]
    fn planning_error_is_descriptive() {
        let err = OrchestratorError::Planning(
            "could not decompose intent: ambiguous file reference".to_string(),
        );
        assert!(err.to_string().contains("ambiguous"));
    }
}
