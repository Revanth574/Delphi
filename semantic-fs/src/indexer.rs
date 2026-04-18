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

use std::fs;
use std::path::{Path, PathBuf};

use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::{Field, Schema, STORED, TEXT};
use tantivy::schema::Value;
use tantivy::{doc, Directory, Index, IndexReader, IndexWriter, ReloadPolicy, TantivyDocument};
use tracing::{debug, info, warn};
use walkdir::WalkDir;

use crate::ignore::IgnoreRules;
use crate::SemanticFsError;

/// Fields stored in the Tantivy index schema.
#[derive(Debug, Clone, Copy)]
pub struct IndexFields {
    /// Absolute file path.
    pub path: Field,
    /// Full-text body content.
    pub body: Field,
    /// File name (for boosted filename matches).
    pub filename: Field,
}

/// Build the Tantivy schema used by the file index.
///
/// # Examples
///
/// ```
/// use semantic_fs::indexer::build_schema;
/// let (schema, fields) = build_schema();
/// assert_eq!(schema.num_fields(), 3);
/// ```
#[must_use]
pub fn build_schema() -> (Schema, IndexFields) {
    let mut builder = Schema::builder();
    let path = builder.add_text_field("path", STORED);
    let body = builder.add_text_field("body", TEXT);
    let filename = builder.add_text_field("filename", TEXT | STORED);
    let schema = builder.build();
    (
        schema,
        IndexFields {
            path,
            body,
            filename,
        },
    )
}

/// The file indexer service.
///
/// Maintains a Tantivy search index over the user's files. The index
/// is encrypted at rest via the Fortress encryption service (future phase).
///
/// # Examples
///
/// ```no_run
/// use semantic_fs::indexer::Indexer;
/// use std::path::Path;
///
/// let indexer = Indexer::open(Path::new("/tmp/delphi-index")).unwrap();
/// ```
pub struct Indexer {
    index: Index,
    reader: IndexReader,
    writer: IndexWriter,
    fields: IndexFields,
    ignore_rules: IgnoreRules,
}

impl Indexer {
    /// Open or create a Tantivy index at the given directory.
    ///
    /// If the directory does not exist, it will be created. If an index
    /// already exists, it will be opened for appending.
    ///
    /// # Errors
    ///
    /// Returns `SemanticFsError::Indexing` if the index directory cannot
    /// be created or the Tantivy index fails to initialize.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use semantic_fs::indexer::Indexer;
    /// use std::path::Path;
    ///
    /// let indexer = Indexer::open(Path::new("/tmp/delphi-index")).unwrap();
    /// ```
    pub fn open(index_dir: &Path) -> Result<Self, SemanticFsError> {
        let (schema, fields) = build_schema();

        fs::create_dir_all(index_dir).map_err(|e| SemanticFsError::FileIo {
            path: index_dir.display().to_string(),
            reason: e.to_string(),
        })?;

        let dir = tantivy::directory::MmapDirectory::open(index_dir).map_err(|e| {
            SemanticFsError::Indexing(format!("failed to open index directory: {e}"))
        })?;

        let index = if dir_has_index(&dir) {
            Index::open(dir)
                .map_err(|e| SemanticFsError::Indexing(format!("failed to open index: {e}")))?
        } else {
            Index::create(dir, schema.clone(), tantivy::IndexSettings::default())
                .map_err(|e| SemanticFsError::Indexing(format!("failed to create index: {e}")))?
        };

        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommitWithDelay)
            .try_into()
            .map_err(|e| SemanticFsError::Indexing(format!("failed to create reader: {e}")))?;

        // 50 MB heap for the writer — reasonable for incremental indexing.
        let writer = index
            .writer(50_000_000)
            .map_err(|e| SemanticFsError::Indexing(format!("failed to create writer: {e}")))?;

        info!("Tantivy index opened at {}", index_dir.display());

        Ok(Self {
            index,
            reader,
            writer,
            fields,
            ignore_rules: IgnoreRules::default(),
        })
    }

    /// Create an in-memory index (useful for testing).
    ///
    /// # Errors
    ///
    /// Returns `SemanticFsError::Indexing` if index creation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use semantic_fs::indexer::Indexer;
    ///
    /// let indexer = Indexer::in_memory().unwrap();
    /// ```
    pub fn in_memory() -> Result<Self, SemanticFsError> {
        let (schema, fields) = build_schema();
        let index = Index::create_in_ram(schema);

        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()
            .map_err(|e| SemanticFsError::Indexing(format!("failed to create reader: {e}")))?;

        let writer = index
            .writer(15_000_000)
            .map_err(|e| SemanticFsError::Indexing(format!("failed to create writer: {e}")))?;

        Ok(Self {
            index,
            reader,
            writer,
            fields,
            ignore_rules: IgnoreRules::default(),
        })
    }

    /// Load ignore rules from a `.delphiignore` file.
    ///
    /// # Errors
    ///
    /// Returns `SemanticFsError::FileIo` if the file cannot be read.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use semantic_fs::indexer::Indexer;
    /// use std::path::Path;
    ///
    /// let mut indexer = Indexer::in_memory().unwrap();
    /// indexer.load_ignore_rules(Path::new("/home/user/.delphiignore")).unwrap();
    /// ```
    pub fn load_ignore_rules(&mut self, path: &Path) -> Result<(), SemanticFsError> {
        self.ignore_rules = IgnoreRules::from_file(path)?;
        info!("loaded {} ignore rules from {}", self.ignore_rules.len(), path.display());
        Ok(())
    }

    /// Set ignore rules directly (for testing or programmatic use).
    ///
    /// # Examples
    ///
    /// ```
    /// use semantic_fs::indexer::Indexer;
    /// use semantic_fs::ignore::IgnoreRules;
    ///
    /// let mut indexer = Indexer::in_memory().unwrap();
    /// indexer.set_ignore_rules(IgnoreRules::from_patterns(&["*.log", "node_modules"]));
    /// ```
    pub fn set_ignore_rules(&mut self, rules: IgnoreRules) {
        self.ignore_rules = rules;
    }

    /// Index a single file by reading its text content.
    ///
    /// Binary files or files that cannot be read as UTF-8 are silently
    /// skipped with a debug log.
    ///
    /// # Errors
    ///
    /// Returns `SemanticFsError::Indexing` if the writer fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use semantic_fs::indexer::Indexer;
    /// use std::path::Path;
    ///
    /// let mut indexer = Indexer::in_memory().unwrap();
    /// indexer.index_file(Path::new("/home/user/readme.md")).unwrap();
    /// ```
    pub fn index_file(&mut self, path: &Path) -> Result<(), SemanticFsError> {
        if self.ignore_rules.is_ignored(path) {
            debug!("skipping ignored file: {}", path.display());
            return Ok(());
        }

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                debug!("skipping non-text file {}: {}", path.display(), e);
                return Ok(());
            }
        };

        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let abs_path = path.display().to_string();

        self.writer
            .add_document(doc!(
                self.fields.path => abs_path,
                self.fields.body => content,
                self.fields.filename => filename,
            ))
            .map_err(|e| SemanticFsError::Indexing(format!("failed to add document: {e}")))?;

        Ok(())
    }

    /// Recursively index all text files under a root directory.
    ///
    /// Skips files matched by the loaded `.delphiignore` rules and
    /// non-UTF-8 (binary) files.
    ///
    /// # Errors
    ///
    /// Returns `SemanticFsError::Indexing` if committing the index fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use semantic_fs::indexer::Indexer;
    /// use std::path::Path;
    ///
    /// let mut indexer = Indexer::in_memory().unwrap();
    /// let count = indexer.index_directory(Path::new("/home/user/documents")).unwrap();
    /// println!("indexed {count} files");
    /// ```
    pub fn index_directory(&mut self, root: &Path) -> Result<usize, SemanticFsError> {
        let mut count = 0usize;

        // Collect paths first to avoid borrowing self in the iterator closure.
        let ignore = &self.ignore_rules;
        let paths: Vec<PathBuf> = WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !ignore.is_ignored(e.path()))
            .filter_map(|entry| match entry {
                Ok(e) if e.file_type().is_file() => Some(e.into_path()),
                Ok(_) => None,
                Err(e) => {
                    warn!("walk error: {e}");
                    None
                }
            })
            .collect();

        for path in &paths {
            self.index_file(path)?;
            count += 1;
        }

        self.commit()?;
        info!("indexed {count} files under {}", root.display());

        Ok(count)
    }

    /// Commit pending index changes and reload the reader.
    ///
    /// # Errors
    ///
    /// Returns `SemanticFsError::Indexing` if the commit fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use semantic_fs::indexer::Indexer;
    ///
    /// let mut indexer = Indexer::in_memory().unwrap();
    /// indexer.commit().unwrap();
    /// ```
    pub fn commit(&mut self) -> Result<(), SemanticFsError> {
        self.writer
            .commit()
            .map_err(|e| SemanticFsError::Indexing(format!("commit failed: {e}")))?;
        self.reader
            .reload()
            .map_err(|e| SemanticFsError::Indexing(format!("reader reload failed: {e}")))?;
        Ok(())
    }

    /// Search the index for files matching a natural language query.
    ///
    /// Returns up to `limit` results sorted by relevance (BM25 score).
    ///
    /// # Errors
    ///
    /// Returns `SemanticFsError::Search` if the query cannot be parsed
    /// or the search fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use semantic_fs::indexer::Indexer;
    ///
    /// let indexer = Indexer::in_memory().unwrap();
    /// let results = indexer.search("tax return 2024", 10).unwrap();
    /// assert!(results.is_empty()); // Empty index.
    /// ```
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchResult>, SemanticFsError> {
        let searcher = self.reader.searcher();
        let query_parser =
            QueryParser::for_index(&self.index, vec![self.fields.body, self.fields.filename]);

        let parsed = query_parser
            .parse_query(query)
            .map_err(|e| SemanticFsError::Search(format!("invalid query: {e}")))?;

        let top_docs = searcher
            .search(&parsed, &TopDocs::with_limit(limit))
            .map_err(|e| SemanticFsError::Search(format!("search failed: {e}")))?;

        let mut results = Vec::with_capacity(top_docs.len());
        for (score, addr) in top_docs {
            let doc: TantivyDocument = searcher
                .doc(addr)
                .map_err(|e| SemanticFsError::Search(format!("doc retrieval failed: {e}")))?;

            let path = doc
                .get_first(self.fields.path)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let filename = doc
                .get_first(self.fields.filename)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            results.push(SearchResult {
                path,
                filename,
                score: f64::from(score),
            });
        }

        Ok(results)
    }

    /// Return the index fields descriptor (for advanced queries).
    ///
    /// # Examples
    ///
    /// ```
    /// use semantic_fs::indexer::Indexer;
    /// let indexer = Indexer::in_memory().unwrap();
    /// let _fields = indexer.fields();
    /// ```
    #[must_use]
    pub fn fields(&self) -> IndexFields {
        self.fields
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
///     filename: "taxes-2024.pdf".to_string(),
///     score: 0.95,
/// };
/// assert!(result.score > 0.9);
/// ```
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// Absolute path to the matching file.
    pub path: String,
    /// File name of the matching file.
    pub filename: String,
    /// BM25 relevance score.
    pub score: f64,
}

/// Check whether a directory already contains a Tantivy index.
fn dir_has_index(dir: &dyn Directory) -> bool {
    dir.exists(&PathBuf::from("meta.json")).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn schema_has_three_fields() {
        let (schema, _fields) = build_schema();
        assert_eq!(schema.num_fields(), 3);
    }

    #[test]
    fn in_memory_indexer_creates_successfully() {
        let indexer = Indexer::in_memory().unwrap();
        let results = indexer.search("anything", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn index_and_search_single_file() {
        let mut indexer = Indexer::in_memory().unwrap();

        // Create a temp file
        let dir = tempdir("search-single");
        let file_path = dir.join("hello.txt");
        let mut f = fs::File::create(&file_path).unwrap();
        writeln!(f, "The quick brown fox jumps over the lazy dog").unwrap();

        indexer.index_file(&file_path).unwrap();
        indexer.commit().unwrap();

        let results = indexer.search("quick brown fox", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].path.contains("hello.txt"));
        assert!(results[0].score > 0.0);
    }

    #[test]
    fn index_directory_counts_files() {
        let mut indexer = Indexer::in_memory().unwrap();
        let dir = tempdir("dir-count");

        // Create 3 text files
        for name in &["a.txt", "b.txt", "c.md"] {
            let mut f = fs::File::create(dir.join(name)).unwrap();
            writeln!(f, "content of {name}").unwrap();
        }

        let count = indexer.index_directory(&dir).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn ignored_files_are_skipped() {
        let mut indexer = Indexer::in_memory().unwrap();
        indexer.set_ignore_rules(IgnoreRules::from_patterns(&["*.log"]));

        let dir = tempdir("ignored");
        let mut txt = fs::File::create(dir.join("keep.txt")).unwrap();
        writeln!(txt, "important text").unwrap();
        let mut log = fs::File::create(dir.join("debug.log")).unwrap();
        writeln!(log, "debug output").unwrap();

        let count = indexer.index_directory(&dir).unwrap();
        assert_eq!(count, 1);

        indexer.commit().unwrap();
        let results = indexer.search("debug output", 10).unwrap();
        assert!(results.is_empty(), "log file should not be indexed");
    }

    #[test]
    fn search_ranks_by_relevance() {
        let mut indexer = Indexer::in_memory().unwrap();
        let dir = tempdir("relevance");

        // File that strongly matches
        let mut f1 = fs::File::create(dir.join("rust-guide.txt")).unwrap();
        writeln!(f1, "Rust programming language guide for systems development").unwrap();

        // File that weakly matches
        let mut f2 = fs::File::create(dir.join("notes.txt")).unwrap();
        writeln!(f2, "Random notes about cooking and gardening").unwrap();

        indexer.index_directory(&dir).unwrap();

        let results = indexer.search("rust programming", 10).unwrap();
        assert!(!results.is_empty());
        assert!(results[0].path.contains("rust-guide"));
    }

    #[test]
    fn binary_files_are_skipped_gracefully() {
        let mut indexer = Indexer::in_memory().unwrap();
        let dir = tempdir("binary");

        // Write some invalid UTF-8
        let binary_path = dir.join("image.bin");
        fs::write(&binary_path, [0xFF, 0xFE, 0x00, 0x01, 0x80, 0x90]).unwrap();

        // Should not error — just skip
        indexer.index_file(&binary_path).unwrap();
    }

    /// Create a unique temp directory for each test invocation.
    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "delphi-test-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
