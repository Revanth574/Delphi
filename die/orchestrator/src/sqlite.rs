// SPDX-License-Identifier: MIT

//! Project-wide SQLite connection policy helpers.
//!
//! **Codex re-review FIX 22 (round 8):** every public store in the
//! orchestrator that opens a `rusqlite::Connection` MUST go through
//! this module's two helpers:
//!
//! 1. [`init_sqlite_connection`] — apply the standard
//!    `busy_timeout(5s)` pin (per CLAUDE.md SQLite Connection Policy
//!    rule 1). Idempotent; safe to call on `:memory:` connections
//!    where it's a no-op (per SQLite docs, every `:memory:` database
//!    is distinct from every other, so no cross-connection contention
//!    is possible — but the call site stays uniform for regression
//!    detection: future drift where someone copies an init path and
//!    forgets the pragma gets caught by the `busy_timeout_pinned_to_5_seconds`
//!    tests that exist for every store).
//!
//! 2. [`map_sqlite_err`] — translate `rusqlite::Error` into
//!    `OrchestratorError`. `SqliteFailure` with `DatabaseBusy` /
//!    `DatabaseLocked` (and their extended forms `SQLITE_BUSY_RECOVERY`,
//!    `SQLITE_LOCKED_SHAREDCACHE`, etc., which mask down to the same
//!    base `ErrorCode` per libsqlite3-sys's `Error::new`) route into
//!    [`OrchestratorError::TransientLock`]. All other rusqlite errors
//!    retain the existing `Planning` classification, prefixed by the
//!    caller-supplied context for debug-string preservation.
//!
//! Round 7 added the typed `TransientLock` variant and the retry loop,
//! but only `KnowledgeStore` was wired through the new typed-error
//! mapping. Round 8's F22 finding closed that gap — every public store
//! now routes lock errors through this shared helper so daemons can
//! typed-match for retry regardless of which store reported the error.
//!
//! # Why a free function and not a method on `Connection`
//!
//! rusqlite's `Connection` is a foreign type; we cannot add trait
//! impls or inherent methods to it. A free function in this module is
//! the canonical home — every public store imports it via
//! `crate::sqlite::{init_sqlite_connection, map_sqlite_err}`.

use std::time::Duration;

use rusqlite::{Connection, Error as SqliteError, ErrorCode};

use crate::error::OrchestratorError;

/// **Codex re-review FIX 22 (round 8):** project-wide standard
/// busy_timeout. 5 seconds — long enough that the typical
/// foreign_key_check / migration commit window stays well inside one
/// retry attempt, short enough that a stuck store surfaces
/// `TransientLock` within a bounded retry budget. See CLAUDE.md
/// "SQLite Connection Policy".
pub const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// **Codex re-review FIX 22 (round 8):** apply the project-wide SQLite
/// connection-init policy to `conn`.
///
/// Currently this sets `busy_timeout` to [`SQLITE_BUSY_TIMEOUT`]. The
/// function is the documented single seam for adding future
/// connection-wide policy items (e.g. additional PRAGMAs, foreign-key
/// enforcement defaults). Sibling stores must call this on every
/// connection open — including `:memory:` constructors (F23
/// constructor-parity policy).
///
/// Idempotent — calling it twice on the same connection just resets
/// the busy timeout to the same value.
pub fn init_sqlite_connection(conn: &Connection) -> Result<(), SqliteError> {
    conn.busy_timeout(SQLITE_BUSY_TIMEOUT)
}

/// **Codex re-review FIX 21 (round 7) + FIX 22 (round 8):** map
/// `rusqlite::Error` to the orchestrator's error type per the
/// project-wide SQLite Connection Policy.
///
/// - `SqliteFailure` with `code = DatabaseBusy | DatabaseLocked` →
///   [`OrchestratorError::TransientLock`] carrying the full
///   `rusqlite::Error` as `source`. The base `ErrorCode` mask catches
///   both base and extended busy/locked codes
///   (`SQLITE_BUSY_RECOVERY`, `SQLITE_LOCKED_SHAREDCACHE`, etc.) per
///   libsqlite3-sys's `Error::new` `& 0xff` mask.
/// - All other variants → [`OrchestratorError::Planning`] with the
///   caller-supplied `context` prefix preserved for debug strings.
///
/// `context` is `&str` rather than `&'static str` so dynamic callers
/// can pass `&format!("...")` for per-call-site context — the borrow
/// is consumed within the closure and not retained.
pub fn map_sqlite_err(err: SqliteError, context: &str) -> OrchestratorError {
    if let SqliteError::SqliteFailure(ref ffi_err, _) = err
        && matches!(
            ffi_err.code,
            ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
        )
    {
        return OrchestratorError::TransientLock { source: err };
    }
    OrchestratorError::Planning(format!("{context}: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_sqlite_connection_sets_busy_timeout_to_5_seconds() {
        let conn = Connection::open_in_memory().unwrap();
        init_sqlite_connection(&conn).unwrap();
        let timeout: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(timeout, 5_000);
    }

    #[test]
    fn init_sqlite_connection_is_idempotent() {
        // Calling twice on the same connection must succeed both
        // times and leave busy_timeout at the standard 5s.
        let conn = Connection::open_in_memory().unwrap();
        init_sqlite_connection(&conn).unwrap();
        init_sqlite_connection(&conn).unwrap();
        let timeout: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(timeout, 5_000);
    }

    #[test]
    fn map_sqlite_err_routes_database_busy_to_transient_lock() {
        let err = SqliteError::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some("test".to_string()),
        );
        let mapped = map_sqlite_err(err, "sqlite test");
        assert!(matches!(mapped, OrchestratorError::TransientLock { .. }));
    }

    #[test]
    fn map_sqlite_err_routes_database_locked_to_transient_lock() {
        let err = SqliteError::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_LOCKED),
            None,
        );
        let mapped = map_sqlite_err(err, "sqlite test");
        assert!(matches!(mapped, OrchestratorError::TransientLock { .. }));
    }

    #[test]
    fn map_sqlite_err_preserves_planning_with_context_for_non_lock() {
        let err = SqliteError::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
            Some("UNIQUE failed".to_string()),
        );
        let mapped = map_sqlite_err(err, "my context");
        match mapped {
            OrchestratorError::Planning(msg) => {
                assert!(
                    msg.starts_with("my context:"),
                    "context prefix missing: {msg}"
                );
            }
            other => panic!("expected Planning, got {other:?}"),
        }
    }

    #[test]
    fn map_sqlite_err_preserves_planning_for_non_sqlitefailure_variants() {
        let err = SqliteError::QueryReturnedNoRows;
        let mapped = map_sqlite_err(err, "row read");
        assert!(matches!(mapped, OrchestratorError::Planning(_)));
    }
}
