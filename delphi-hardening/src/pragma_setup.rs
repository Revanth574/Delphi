// SPDX-License-Identifier: MIT

//! Per-connection SQLite policy: the `busy_timeout` pin and the transient-lock
//! classification.
//!
//! # Defect classes foreclosed
//!
//! 1. **Per-connection state assumptions (PRAGMA).** rusqlite's default
//!    `busy_timeout` is documented as "subject to change", so relying on it
//!    leaves a store unable to bound lock-contention waits. [`init_connection`]
//!    pins a documented value on *every* connection — the single sanctioned
//!    place to add future per-connection policy.
//! 2. **Conflating transient contention with genuine failure.** A `SQLITE_BUSY`
//!    / `SQLITE_LOCKED` (and their *extended* forms, e.g. `SQLITE_BUSY_SNAPSHOT`,
//!    `SQLITE_LOCKED_SHAREDCACHE`) is a *retryable* condition, not a logic error.
//!    [`is_transient_lock`] is the one shared classifier so every store routes
//!    lock errors the same way (the F19/F21/F22 lesson).
//!
//! Per STOP POINT A: this is the **predicate** shape — `is_transient_lock`
//! returns a bool; each crate keeps its own thin error-mapping wrapper that
//! constructs its own error type from the classification, so this primitive
//! never depends on any crate's error enum.

use std::time::Duration;

use rusqlite::{Connection, Error as SqliteError, ErrorCode};

/// Project-wide standard SQLite `busy_timeout`. 5 seconds — long enough that a
/// typical migration/commit window stays inside one retry, short enough that a
/// stuck store surfaces a typed transient error within a bounded budget.
pub const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Apply the project-wide connection-init policy to `conn` (currently the
/// [`SQLITE_BUSY_TIMEOUT`] pin). The single documented seam for future
/// connection-wide policy. Idempotent.
///
/// # Errors
///
/// Propagates the `rusqlite` error if setting the pragma fails.
pub fn init_connection(conn: &Connection) -> Result<(), SqliteError> {
    conn.busy_timeout(SQLITE_BUSY_TIMEOUT)
}

/// Classify a `rusqlite::Error` as a *transient lock* (retryable) condition.
///
/// Returns `true` for `SqliteFailure` whose base [`ErrorCode`] is
/// `DatabaseBusy` or `DatabaseLocked`. Because libsqlite3-sys masks the extended
/// result code to its base code (`& 0xff`) when constructing the error, this
/// catches the extended forms too (`SQLITE_BUSY_SNAPSHOT` → `SQLITE_BUSY`,
/// `SQLITE_LOCKED_SHAREDCACHE` → `SQLITE_LOCKED`, etc.). Every other error is
/// non-transient.
///
/// This is a pure predicate (STOP POINT A decision): callers construct their own
/// typed error from the result, so this stays free of any crate's error enum.
#[must_use]
pub fn is_transient_lock(err: &SqliteError) -> bool {
    matches!(
        err,
        SqliteError::SqliteFailure(ffi, _)
            if matches!(ffi.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_connection_pins_busy_timeout_to_5_seconds() {
        let conn = Connection::open_in_memory().unwrap();
        init_connection(&conn).unwrap();
        let timeout: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(timeout, 5_000);
    }

    #[test]
    fn init_connection_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        init_connection(&conn).unwrap();
        init_connection(&conn).unwrap();
        let timeout: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(timeout, 5_000);
    }

    fn sqlite_failure(primary_or_extended: std::os::raw::c_int) -> SqliteError {
        SqliteError::SqliteFailure(rusqlite::ffi::Error::new(primary_or_extended), None)
    }

    #[test]
    fn base_busy_and_locked_are_transient() {
        assert!(is_transient_lock(&sqlite_failure(rusqlite::ffi::SQLITE_BUSY)));
        assert!(is_transient_lock(&sqlite_failure(rusqlite::ffi::SQLITE_LOCKED)));
    }

    #[test]
    fn extended_busy_snapshot_classifies_same_as_base_busy() {
        // The key invariant: an EXTENDED code must classify identically to its
        // base. libsqlite3-sys masks `SQLITE_BUSY_SNAPSHOT` (= SQLITE_BUSY |
        // (2<<8)) down to base `SQLITE_BUSY`, so is_transient_lock must agree
        // with the base classification. Same for SQLITE_LOCKED_SHAREDCACHE.
        assert_eq!(
            is_transient_lock(&sqlite_failure(rusqlite::ffi::SQLITE_BUSY_SNAPSHOT)),
            is_transient_lock(&sqlite_failure(rusqlite::ffi::SQLITE_BUSY)),
        );
        assert!(is_transient_lock(&sqlite_failure(
            rusqlite::ffi::SQLITE_BUSY_SNAPSHOT
        )));
        assert!(is_transient_lock(&sqlite_failure(
            rusqlite::ffi::SQLITE_LOCKED_SHAREDCACHE
        )));
    }

    #[test]
    fn non_lock_errors_are_not_transient() {
        assert!(!is_transient_lock(&sqlite_failure(
            rusqlite::ffi::SQLITE_CONSTRAINT
        )));
        assert!(!is_transient_lock(&SqliteError::QueryReturnedNoRows));
    }
}
