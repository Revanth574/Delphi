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
        info!(query = %query, limit, "D-Bus file search");

        let indexer = self.indexer.lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let results = indexer
            .search(&query, limit as usize)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

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
}
