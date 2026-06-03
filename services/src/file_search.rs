// SPDX-License-Identifier: MIT

//! D-Bus FileSearch interface.
//!
//! Exposes semantic file search over D-Bus. The shell sends a natural
//! language query and receives ranked file paths with scores.
//!
//! Interface: `org.delphi.FileSearch`
//!
//! SVC-2: every method enforces authorization via the shared [`AuthGuard`] on
//! its first line (see [`crate::auth_guard`]).

use std::sync::{Arc, Mutex};

use tracing::info;
use zbus::message::Header;

use semantic_fs::indexer::Indexer;

use crate::auth_guard::AuthGuard;

/// D-Bus object path for the FileSearch interface.
pub const PATH: &str = "/org/delphi/FileSearch";

/// FileSearch D-Bus service.
///
/// Wraps the semantic-fs `Indexer` and exposes search over D-Bus.
/// Uses `std::sync::Mutex` because Tantivy's `IndexWriter` is `!Send`.
///
/// # Examples
///
/// ```
/// use delphi_services::file_search::FileSearchService;
/// use delphi_services::auth::AuthPolicy;
/// use delphi_services::auth_guard::AuthGuard;
/// use semantic_fs::indexer::Indexer;
/// use fortress::audit::AuditLog;
/// use std::sync::{Arc, Mutex};
///
/// let indexer = Arc::new(Mutex::new(Indexer::in_memory().unwrap()));
/// let guard = Arc::new(AuthGuard::new(
///     AuthPolicy::dev(),
///     Arc::new(Mutex::new(AuditLog::in_memory())),
/// ));
/// let svc = FileSearchService::new(indexer, guard);
/// ```
pub struct FileSearchService {
    indexer: Arc<Mutex<Indexer>>,
    guard: Arc<AuthGuard>,
}

impl FileSearchService {
    /// Create a new file search service backed by the given indexer, guarded by
    /// the shared [`AuthGuard`].
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::file_search::FileSearchService;
    /// use delphi_services::auth::AuthPolicy;
    /// use delphi_services::auth_guard::AuthGuard;
    /// use semantic_fs::indexer::Indexer;
    /// use fortress::audit::AuditLog;
    /// use std::sync::{Arc, Mutex};
    ///
    /// let svc = FileSearchService::new(
    ///     Arc::new(Mutex::new(Indexer::in_memory().unwrap())),
    ///     Arc::new(AuthGuard::new(
    ///         AuthPolicy::dev(),
    ///         Arc::new(Mutex::new(AuditLog::in_memory())),
    ///     )),
    /// );
    /// ```
    #[must_use]
    pub fn new(indexer: Arc<Mutex<Indexer>>, guard: Arc<AuthGuard>) -> Self {
        Self { indexer, guard }
    }
}

#[zbus::interface(name = "org.delphi.FileSearch")]
impl FileSearchService {
    /// Search for files matching a natural language query.
    ///
    /// Returns a JSON array of `{path, filename, score}` objects.
    async fn search(
        &self,
        #[zbus(header)] header: Header<'_>,
        query: String,
        limit: u32,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("file_search.search", &header)?;
        crate::limits::ensure_within(&query, crate::limits::MAX_STRING_BYTES, "query")?;
        info!(query = %query, limit, "D-Bus file search");

        let indexer = self.indexer.lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let results = indexer
            .search(&query, limit as usize)
            .map_err(|e| crate::error::opaque("file search failed", e))?;

        // Serialize results as JSON for transport over D-Bus.
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

        serde_json::to_string(&json)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialization failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use fortress::audit::AuditLog;

    use crate::auth::AuthPolicy;
    use crate::auth_guard::completeness::{
        assert_all_methods_classified, assert_behavioral_covers_all, header_msg as msg,
    };

    fn mk_svc(policy: AuthPolicy) -> FileSearchService {
        let indexer = Arc::new(Mutex::new(Indexer::in_memory().unwrap()));
        let guard = Arc::new(AuthGuard::new(
            policy,
            Arc::new(Mutex::new(AuditLog::in_memory())),
        ));
        FileSearchService::new(indexer, guard)
    }

    #[test]
    fn path_is_valid() {
        assert!(PATH.starts_with("/org/delphi"));
    }

    #[test]
    fn service_creation() {
        let _svc = mk_svc(AuthPolicy::dev());
    }

    /// SVC-4 (3A.5 F7 class): a failing domain operation must not echo its
    /// error detail across the D-Bus boundary.
    #[tokio::test]
    async fn search_error_does_not_leak_domain_detail() {
        let svc = mk_svc(AuthPolicy::dev());
        let m = msg(":1.5");
        let sentinel = "ZZZSENTINELFIELDZZZ";
        let err = svc
            .search(m.header(), format!("{sentinel}:term"), 5)
            .await
            .expect_err("bogus-field query must error");
        let msg_str = err.to_string();
        assert!(
            !msg_str.contains(sentinel),
            "D-Bus error leaked domain detail: {msg_str}"
        );
    }

    /// SVC-6-R2-3: `search(query)` is capped at the boundary (after the guard).
    #[tokio::test]
    async fn every_string_param_rejects_oversize() {
        let svc = mk_svc(AuthPolicy::dev());
        let m = msg(":1.5");
        let oversize = "x".repeat(crate::limits::MAX_STRING_BYTES + 1);
        assert!(matches!(
            svc.search(m.header(), oversize, 10).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
    }

    // ── SVC-2 completeness (Decision 3) ──

    #[test]
    fn svc2_every_method_is_classified() {
        use zbus::object_server::Interface;
        let svc = mk_svc(AuthPolicy::dev());
        let mut xml = String::new();
        svc.introspect_to_writer(&mut xml, 0);
        assert_all_methods_classified("file_search", &xml);
    }

    #[tokio::test]
    async fn svc2_every_method_denies_unrecognized_caller_when_deployed() {
        let svc = mk_svc(AuthPolicy::deployed());
        let m = msg(":1.999");
        // FileSearchService exposes a single guarded method, so the exercised
        // set is a one-element literal (clippy::vec_init_then_push rejects the
        // Vec::new()+push form for a single immediate push).
        let exercised: Vec<&str> = vec!["Search"];

        assert!(
            matches!(
                svc.search(m.header(), "q".to_string(), 10).await.unwrap_err(),
                zbus::fdo::Error::AccessDenied(_)
            ),
            "search must be guarded"
        );

        use zbus::object_server::Interface;
        let mut xml = String::new();
        svc.introspect_to_writer(&mut xml, 0);
        assert_behavioral_covers_all("file_search", &xml, &exercised);
    }
}
