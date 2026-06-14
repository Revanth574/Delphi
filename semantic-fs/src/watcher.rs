// SPDX-License-Identifier: MIT

//! File system watcher for incremental indexing.
//!
//! Uses the [`notify`] crate to watch directories for changes and
//! re-index modified files. The watcher runs on a background tokio task
//! and sends file events through a channel.
//!
//! # Architecture
//!
//! ```text
//! notify (OS events) → channel → watcher task → Indexer::index_file()
//! ```
//!
//! NOTE: event debouncing/batching is NOT implemented — each event is forwarded
//! to the indexer and the index is committed after every file (see
//! `process_events`). Debounce + batch-commit (to coalesce editor
//! write-rename-delete save-bursts and avoid a commit storm) is a forward
//! optimization, not current behavior.

use std::path::{Path, PathBuf};
use std::sync::mpsc;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{debug, error, info, warn};

use crate::SemanticFsError;

/// A filesystem event relevant to indexing.
///
/// # Examples
///
/// ```
/// use semantic_fs::watcher::FsEvent;
/// use std::path::PathBuf;
///
/// let event = FsEvent::Modified(PathBuf::from("/home/user/doc.txt"));
/// assert!(matches!(event, FsEvent::Modified(_)));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsEvent {
    /// A file was created or modified and should be (re-)indexed.
    Modified(PathBuf),
    /// A file was removed and should be deleted from the index.
    Removed(PathBuf),
}

/// A file system watcher that emits indexing-relevant events.
///
/// Wraps the platform-native `notify::RecommendedWatcher` and filters
/// events down to create/modify/remove on regular files.
///
/// # Examples
///
/// ```no_run
/// use semantic_fs::watcher::FsWatcher;
/// use std::path::Path;
///
/// let (watcher, rx) = FsWatcher::new().unwrap();
/// // Events will arrive on `rx` as files change.
/// ```
pub struct FsWatcher {
    _watcher: RecommendedWatcher,
}

impl FsWatcher {
    /// Create a new watcher and its event receiver channel.
    ///
    /// The watcher does not watch any paths yet — call [`watch()`](Self::watch)
    /// to add directories.
    ///
    /// # Errors
    ///
    /// Returns `SemanticFsError::Indexing` if the OS watcher cannot be created.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use semantic_fs::watcher::FsWatcher;
    ///
    /// let (watcher, rx) = FsWatcher::new().unwrap();
    /// ```
    pub fn new() -> Result<(Self, mpsc::Receiver<FsEvent>), SemanticFsError> {
        let (tx, rx) = mpsc::channel();

        let watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                match res {
                    Ok(event) => {
                        for fs_event in translate_event(&event) {
                            if tx.send(fs_event).is_err() {
                                // Receiver dropped — stop processing.
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("filesystem watch error: {e}");
                    }
                }
            },
            notify::Config::default(),
        )
        .map_err(|e| SemanticFsError::Indexing(format!("failed to create watcher: {e}")))?;

        info!("filesystem watcher initialized");

        Ok((Self { _watcher: watcher }, rx))
    }

    /// Start watching a directory recursively for file changes.
    ///
    /// # Errors
    ///
    /// Returns `SemanticFsError::FileIo` if the path cannot be watched.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use semantic_fs::watcher::FsWatcher;
    /// use std::path::Path;
    ///
    /// let (mut watcher, rx) = FsWatcher::new().unwrap();
    /// watcher.watch(Path::new("/home/user/documents")).unwrap();
    /// ```
    pub fn watch(&mut self, path: &Path) -> Result<(), SemanticFsError> {
        self._watcher
            .watch(path, RecursiveMode::Recursive)
            .map_err(|e| SemanticFsError::FileIo {
                path: path.display().to_string(),
                reason: format!("watch failed: {e}"),
            })?;

        debug!("watching directory: {}", path.display());
        Ok(())
    }

    /// Stop watching a directory.
    ///
    /// # Errors
    ///
    /// Returns `SemanticFsError::FileIo` if the path cannot be unwatched.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use semantic_fs::watcher::FsWatcher;
    /// use std::path::Path;
    ///
    /// let (mut watcher, _rx) = FsWatcher::new().unwrap();
    /// let dir = Path::new("/home/user/documents");
    /// watcher.watch(dir).unwrap();
    /// watcher.unwatch(dir).unwrap();
    /// ```
    pub fn unwatch(&mut self, path: &Path) -> Result<(), SemanticFsError> {
        self._watcher
            .unwatch(path)
            .map_err(|e| SemanticFsError::FileIo {
                path: path.display().to_string(),
                reason: format!("unwatch failed: {e}"),
            })?;

        debug!("stopped watching directory: {}", path.display());
        Ok(())
    }
}

/// Translate a raw notify event into zero or more indexing-relevant events.
///
/// Filters out directory events, access events, and other noise.
fn translate_event(event: &Event) -> Vec<FsEvent> {
    let mut out = Vec::new();

    match &event.kind {
        EventKind::Create(_) | EventKind::Modify(_) => {
            for path in &event.paths {
                if path.is_file() {
                    out.push(FsEvent::Modified(path.clone()));
                }
            }
        }
        EventKind::Remove(_) => {
            for path in &event.paths {
                out.push(FsEvent::Removed(path.clone()));
            }
        }
        _ => {
            // Access, Other — not relevant for indexing.
        }
    }

    out
}

/// Process events from the watcher channel and re-index files.
///
/// This is a blocking function intended to be run on a dedicated thread
/// or tokio blocking task. It reads events until the channel is closed.
///
/// # Errors
///
/// Logs errors but does not propagate them — the watcher should be
/// resilient to individual file indexing failures.
///
/// # Examples
///
/// ```no_run
/// use semantic_fs::watcher::{FsWatcher, process_events};
/// use semantic_fs::indexer::Indexer;
/// use std::path::Path;
///
/// let (mut watcher, rx) = FsWatcher::new().unwrap();
/// let mut indexer = Indexer::open(Path::new("/tmp/idx")).unwrap();
/// watcher.watch(Path::new("/home/user")).unwrap();
///
/// // This blocks until the channel is closed:
/// process_events(rx, &mut indexer);
/// ```
pub fn process_events(
    rx: mpsc::Receiver<FsEvent>,
    indexer: &mut crate::indexer::Indexer,
) {
    for event in rx {
        match event {
            FsEvent::Modified(path) => {
                debug!("re-indexing modified file: {}", path.display());
                if let Err(e) = indexer.index_file(&path) {
                    error!("failed to index {}: {e}", path.display());
                }
                // Commit after each file for now — batch commits are a future optimization.
                if let Err(e) = indexer.commit() {
                    error!("commit failed after indexing {}: {e}", path.display());
                }
            }
            FsEvent::Removed(path) => {
                debug!("file removed (delete from index not yet implemented): {}", path.display());
                // TODO(phase-2): implement document deletion from Tantivy index
                // Requires tracking doc addresses or using delete_term on the path field.
            }
        }
    }

    info!("watcher event loop terminated (channel closed)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translate_create_event_produces_modified() {
        let event = Event {
            kind: EventKind::Create(notify::event::CreateKind::File),
            paths: vec![],
            attrs: Default::default(),
        };
        // Empty paths — no events produced
        let translated = translate_event(&event);
        assert!(translated.is_empty());
    }

    #[test]
    fn translate_remove_event_produces_removed() {
        let path = PathBuf::from("/tmp/deleted.txt");
        let event = Event {
            kind: EventKind::Remove(notify::event::RemoveKind::File),
            paths: vec![path.clone()],
            attrs: Default::default(),
        };
        let translated = translate_event(&event);
        assert_eq!(translated, vec![FsEvent::Removed(path)]);
    }

    #[test]
    fn translate_access_event_is_ignored() {
        let event = Event {
            kind: EventKind::Access(notify::event::AccessKind::Read),
            paths: vec![PathBuf::from("/tmp/read.txt")],
            attrs: Default::default(),
        };
        let translated = translate_event(&event);
        assert!(translated.is_empty());
    }

    #[test]
    fn fs_event_equality() {
        let a = FsEvent::Modified(PathBuf::from("/a.txt"));
        let b = FsEvent::Modified(PathBuf::from("/a.txt"));
        let c = FsEvent::Removed(PathBuf::from("/a.txt"));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
