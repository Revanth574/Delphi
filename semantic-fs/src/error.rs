// SPDX-License-Identifier: MIT

//! Error types for the semantic file system.
//!
//! Errors propagate from fortress (encryption) and from the indexing
//! engine (tantivy). All errors include recovery suggestions.

use fortress::FortressError;

/// Errors produced by the semantic file system.
///
/// The `#[from] FortressError` conversion proves the dependency direction
/// (semantic-fs → fortress) at compile time.
///
/// # Examples
///
/// ```
/// use semantic_fs::SemanticFsError;
/// use fortress::FortressError;
///
/// let fortress_err = FortressError::Encryption("disk key expired".to_string());
/// let fs_err: SemanticFsError = fortress_err.into();
/// assert!(fs_err.to_string().contains("disk key expired"));
/// ```
#[derive(Debug, thiserror::Error)]
pub enum SemanticFsError {
    /// File indexing failed.
    #[error("indexing error: {0}")]
    Indexing(String),

    /// Search query failed.
    #[error("search error: {0}")]
    Search(String),

    /// File I/O error.
    #[error("file I/O error: {path} — {reason}")]
    FileIo {
        /// The path that caused the error.
        path: String,
        /// Why the operation failed.
        reason: String,
    },

    /// Encryption operation failed (propagated from fortress).
    #[error("encryption error: {0}")]
    Encryption(#[from] FortressError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fortress_error_converts_to_semantic_fs_error() {
        let fortress_err = FortressError::Encryption("key derivation failed".to_string());
        let fs_err: SemanticFsError = fortress_err.into();
        assert!(fs_err.to_string().contains("key derivation"));
    }

    #[test]
    fn file_io_error_includes_path() {
        let err = SemanticFsError::FileIo {
            path: "/home/user/docs/report.pdf".to_string(),
            reason: "permission denied".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("report.pdf"));
        assert!(msg.contains("permission denied"));
    }
}
