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

use rusqlite::{Connection, Error as SqliteError};

use crate::error::OrchestratorError;

/// Project-wide standard SQLite `busy_timeout`, re-exported from the shared
/// [`delphi_hardening::pragma_setup`] primitive (leverage pass P2). 5 seconds —
/// see CLAUDE.md "SQLite Connection Policy".
pub use delphi_hardening::pragma_setup::SQLITE_BUSY_TIMEOUT;

/// Apply the project-wide SQLite connection-init policy to `conn` — a thin
/// wrapper over [`delphi_hardening::pragma_setup::init_connection`] (the
/// `busy_timeout` pin + the documented seam for future per-connection policy).
/// Sibling stores must call this on every connection open — including `:memory:`
/// constructors (F23 constructor-parity policy). Idempotent.
///
/// # Errors
///
/// Propagates the `rusqlite` error if setting the pragma fails.
pub fn init_sqlite_connection(conn: &Connection) -> Result<(), SqliteError> {
    delphi_hardening::pragma_setup::init_connection(conn)
}

/// Map `rusqlite::Error` to the orchestrator's error type per the project-wide
/// SQLite Connection Policy.
///
/// The transient-lock CLASSIFICATION is the shared
/// [`delphi_hardening::pragma_setup::is_transient_lock`] predicate (STOP POINT A:
/// the classification is shared, error CONSTRUCTION stays per-crate); this site
/// builds the orchestrator's typed error from it:
///
/// - a transient lock (`DatabaseBusy` / `DatabaseLocked`, incl. extended codes
///   like `SQLITE_BUSY_SNAPSHOT` / `SQLITE_LOCKED_SHAREDCACHE` — the predicate
///   matches the base `ErrorCode`, which libsqlite3-sys masks the extended code
///   down to) → [`OrchestratorError::TransientLock`] carrying the full error.
/// - all other variants → [`OrchestratorError::Planning`] with the
///   caller-supplied `context` prefix preserved.
///
/// `context` is `&str` so dynamic callers can pass `&format!("...")`.
pub fn map_sqlite_err(err: SqliteError, context: &str) -> OrchestratorError {
    if delphi_hardening::pragma_setup::is_transient_lock(&err) {
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
