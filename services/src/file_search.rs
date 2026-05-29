// SPDX-License-Identifier: MIT

//! D-Bus FileSearch interface.
//!
//! Exposes semantic file search over D-Bus. The shell sends a natural
//! language query and receives ranked file paths with scores.
//!
//! Interface: `org.delphi.FileSearch`

use std::sync::{Arc, Mutex};

use tracing::info;

use semantic_fs::indexer::Indexer;

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
/// use semantic_fs::indexer::Indexer;
/// use std::sync::{Arc, Mutex};
///
/// let indexer = Arc::new(Mutex::new(Indexer::in_memory().unwrap()));
/// let svc = FileSearchService::new(indexer);
/// ```
pub struct FileSearchService {
    indexer: Arc<Mutex<Indexer>>,
}

impl FileSearchService {
    /// Create a new file search service backed by the given indexer.
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::file_search::FileSearchService;
    /// use semantic_fs::indexer::Indexer;
    /// use std::sync::{Arc, Mutex};
    ///
    /// let svc = FileSearchService::new(
    ///     Arc::new(Mutex::new(Indexer::in_memory().unwrap())),
    /// );
    /// ```
    #[must_use]
    pub fn new(indexer: Arc<Mutex<Indexer>>) -> Self {
        Self { indexer }
    }
}

#[zbus::interface(name = "org.delphi.FileSearch")]
impl FileSearchService {
    /// Search for files matching a natural language query.
    ///
    /// Returns a JSON array of `{path, filename, score}` objects.
    async fn search(
        &self,
        query: String,
        limit: u32,
    ) -> zbus::fdo::Result<String> {
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

    #[test]
    fn path_is_valid() {
        assert!(PATH.starts_with("/org/delphi"));
    }

    #[test]
    fn service_creation() {
        let indexer = Arc::new(Mutex::new(Indexer::in_memory().unwrap()));
        let _svc = FileSearchService::new(indexer);
    }

    /// SVC-4 (3A.5 F7 class): a failing domain operation must not echo its
    /// error detail across the D-Bus boundary. A query naming a
    /// non-existent field forces a deterministic `SemanticFsError::Search`
    /// from the Tantivy `QueryParser`; the offending token must NOT appear
    /// in the wire error. This test is RED against the pre-fix
    /// `Failed(e.to_string())` mapping and GREEN once the error is
    /// sanitized to a fixed, content-free message.
    #[tokio::test]
    async fn search_error_does_not_leak_domain_detail() {
        let indexer = Arc::new(Mutex::new(Indexer::in_memory().unwrap()));
        let svc = FileSearchService::new(indexer);
        let sentinel = "ZZZSENTINELFIELDZZZ";
        let err = svc
            .search(format!("{sentinel}:term"), 5)
            .await
            .expect_err("bogus-field query must error");
        let msg = err.to_string();
        assert!(
            !msg.contains(sentinel),
            "D-Bus error leaked domain detail: {msg}"
        );
    }

    /// SVC-6-R2-3: `search(query)` is capped at the boundary.
    #[tokio::test]
    async fn every_string_param_rejects_oversize() {
        let indexer = Arc::new(Mutex::new(Indexer::in_memory().unwrap()));
        let svc = FileSearchService::new(indexer);
        let oversize = "x".repeat(crate::limits::MAX_STRING_BYTES + 1);
        assert!(matches!(
            svc.search(oversize, 10).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
    }
}
