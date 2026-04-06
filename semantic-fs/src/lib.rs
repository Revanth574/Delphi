// SPDX-License-Identifier: MIT

//! # Semantic File System
//!
//! A file system layer that provides full-text and vector search over the
//! user's files. Uses [Tantivy](https://github.com/quickwit-oss/tantivy)
//! for text indexing and (in a future phase) LanceDB for vector embeddings.
//!
//! # Architecture
//!
//! The DIE orchestrator accesses files exclusively through `semantic-fs`.
//! Direct filesystem access from the DIE is forbidden per CLAUDE.md Section 4.
//!
//! ```text
//! DIE Orchestrator → Semantic FS → Raw I/O
//!                         ↓
//!                    Fortress (encryption at rest)
//! ```
//!
//! # Modules
//!
//! - [`indexer`] — Tantivy-backed full-text indexing and search
//! - [`watcher`] — Filesystem event watching for incremental re-indexing
//! - [`ignore`] — `.delphiignore` pattern matching
//! - [`error`] — Error types
//!
//! # Performance Budget
//!
//! Semantic file search must return results in **< 500ms** for 1M files.

pub mod error;
pub mod ignore;
pub mod indexer;
pub mod watcher;

pub use error::SemanticFsError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_type_is_accessible() {
        let err = SemanticFsError::Indexing("test".to_string());
        assert!(!err.to_string().is_empty());
    }
}
