// SPDX-License-Identifier: MIT

//! File indexing module.
//!
//! Watches the file system for changes and maintains a Tantivy full-text
//! search index. In a future phase, this will also maintain a LanceDB
//! vector index for semantic (embedding-based) search.
//!
//! # Performance
//!
//! The indexer must support **1TB+** of content and return search results
//! in **< 500ms** for 1M files (per CLAUDE.md Section 9).

use crate::SemanticFsError;

/// The file indexer service.
///
/// Maintains a Tantivy search index over the user's files. The index
/// is encrypted at rest via the Fortress encryption service.
///
/// # Examples
///
/// ```
/// use semantic_fs::indexer::Indexer;
///
/// let indexer = Indexer::new();
/// // Indexer is ready to be configured with a data directory.
/// ```
pub struct Indexer {
    _initialized: bool,
}

impl Indexer {
    /// Create a new file indexer.
    ///
    /// The indexer starts in an unconfigured state. Call `configure()`
    /// to set the data directory and initialize the Tantivy index.
    ///
    /// # Examples
    ///
    /// ```
    /// use semantic_fs::indexer::Indexer;
    /// let indexer = Indexer::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            _initialized: false,
        }
    }

    /// Search the index for files matching a natural language query.
    ///
    /// # Errors
    ///
    /// Returns `SemanticFsError::Search` if the index is not initialized
    /// or the query cannot be parsed.
    ///
    /// # Examples
    ///
    /// ```
    /// use semantic_fs::indexer::Indexer;
    ///
    /// let indexer = Indexer::new();
    /// let result = indexer.search("tax return 2024");
    /// assert!(result.is_err()); // Index not initialized yet.
    /// ```
    pub fn search(&self, _query: &str) -> Result<Vec<SearchResult>, SemanticFsError> {
        Err(SemanticFsError::Search(
            "index not initialized — call configure() first".to_string(),
        ))
    }
}

impl Default for Indexer {
    fn default() -> Self {
        Self::new()
    }
}

/// A single search result from the file index.
///
/// # Examples
///
/// ```
/// use semantic_fs::indexer::SearchResult;
///
/// let result = SearchResult {
///     path: "/home/user/docs/taxes-2024.pdf".to_string(),
///     score: 0.95,
///     snippet: "Federal tax return for fiscal year 2024...".to_string(),
/// };
/// assert!(result.score > 0.9);
/// ```
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// Absolute path to the matching file.
    pub path: String,
    /// Relevance score (0.0 to 1.0).
    pub score: f64,
    /// A text snippet showing the matching content.
    pub snippet: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_indexer_search_returns_error() {
        let indexer = Indexer::new();
        let err = indexer.search("test query").unwrap_err();
        assert!(err.to_string().contains("not initialized"));
    }

    #[test]
    fn default_is_same_as_new() {
        let _indexer = Indexer::default();
        // No panic — default works.
    }

    #[test]
    fn search_result_fields() {
        let result = SearchResult {
            path: "/test/file.txt".to_string(),
            score: 0.75,
            snippet: "matching text".to_string(),
        };
        assert_eq!(result.score, 0.75);
        assert!(result.path.contains("file.txt"));
    }
}
