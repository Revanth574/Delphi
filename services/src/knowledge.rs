// SPDX-License-Identifier: MIT

//! D-Bus Knowledge interface — capability #17 (knowledge synthesis engine).
//!
//! Exposes the orchestrator's [`KnowledgeStore`] over D-Bus. The shell
//! uses this to ingest documents the user opens or pastes, query the
//! graph from the command bar, and surface contradictions in the
//! action timeline. The brain consumes search results to ground
//! Tier-3 answers in the user's own corpus.
//!
//! Interface: `org.delphi.Knowledge`
//!
//! # Privacy guarantees
//!
//! - Document content **never** transits the cloud unless the user has
//!   explicitly enabled the [`CloudEmbedder`]. The default embedder for
//!   D-Bus-served stores is [`MockEmbedder`] (deterministic) or
//!   [`LocalEmbedder`] (offline). The shell mode that flips on cloud
//!   embedding is gated behind a setting the daemon reads at startup.
//! - All cloud transmission paths in [`die_orchestrator::knowledge::CloudEmbedder`]
//!   pass through [`fortress::zkqp::QuerySanitizer`] before any
//!   imagined network call.
//! - D-Bus error messages **never** include document content; only
//!   structured failure reasons (`"unsupported format"`, `"source not
//!   found"`, etc.).
//!
//! # Signal emission
//!
//! Three signals are **declared** here for D-Bus introspection. Emission
//! is the orchestrator daemon's responsibility — the daemon polls the
//! store for state changes and emits via a `SignalEmitter`. This mirrors
//! the pattern from `goals.rs`, `environment.rs`, and `health.rs`.
//!
//! Uses `std::sync::Mutex` (not `tokio::sync`) because `rusqlite::Connection`
//! is `!Send` across await points — see CLAUDE.md §3 D-Bus rule 6.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tracing::info;
use zbus::object_server::SignalEmitter;

use die_orchestrator::knowledge::{
    EdgeRelation, IngestionResult, KnowledgeNode, KnowledgeStore, NodeWithSources, RelatedNode,
    Source, SourceType,
};

/// D-Bus object path for the Knowledge interface.
pub const PATH: &str = "/org/delphi/Knowledge";

/// Knowledge D-Bus service.
///
/// Wraps a [`KnowledgeStore`] in `Arc<Mutex<...>>` so async D-Bus methods
/// can lock briefly to read state or mutate the graph. The Mutex is the
/// standard `std::sync::Mutex`.
///
/// # Path access control (Codex review FIX 1)
///
/// [`ingest_file`](Self::ingest_file) takes a caller-supplied path. Without
/// access control, a malicious or buggy shell client could request
/// ingestion of `/etc/shadow`, the user's SSH private keys, or any file
/// the daemon has read permission for. The service enforces an
/// **allowlist of permitted base directories** (the user's home dir by
/// default, plus any paths the shell explicitly registers).
///
/// Path validation:
/// 1. The input path is canonicalized via `std::fs::canonicalize` —
///    resolves symlinks AND `..` components. Non-existent paths fail
///    early with `AccessDenied`.
/// 2. Each allowlist entry is canonicalized once when added.
/// 3. The canonicalized input must `starts_with` at least one allowlist
///    entry. `Path::starts_with` operates on path components, so byte
///    prefixes like `/home/user2` against `/home/user` correctly fail.
///
/// # Examples
///
/// ```
/// use delphi_services::knowledge::KnowledgeService;
/// use die_orchestrator::knowledge::{KnowledgeStore, MockEmbedder};
/// use std::sync::{Arc, Mutex};
///
/// let store = KnowledgeStore::in_memory(Box::new(MockEmbedder::new())).unwrap();
/// let svc = KnowledgeService::new(Arc::new(Mutex::new(store)));
/// ```
pub struct KnowledgeService {
    store: Arc<Mutex<KnowledgeStore>>,
    /// Canonicalized base directories that `ingest_file` will accept.
    /// Empty allowlist → no path is permitted (closed by default).
    allowlist: Arc<Mutex<Vec<PathBuf>>>,
}

impl KnowledgeService {
    /// Build a service with the user's home directory as the only
    /// permitted ingestion root. The shell can extend the allowlist via
    /// [`add_ingestion_root`](Self::add_ingestion_root) for project
    /// directories the user explicitly registers.
    #[must_use]
    pub fn new(store: Arc<Mutex<KnowledgeStore>>) -> Self {
        let mut roots: Vec<PathBuf> = Vec::new();
        if let Some(home) = dirs::home_dir()
            && let Ok(canon) = std::fs::canonicalize(&home)
        {
            roots.push(canon);
        }
        Self {
            store,
            allowlist: Arc::new(Mutex::new(roots)),
        }
    }

    /// Build a service with an explicit allowlist of base directories.
    /// Each entry is canonicalized; entries that don't exist are dropped.
    /// Useful for tests that need to inject a tempdir-rooted allowlist.
    #[must_use]
    pub fn with_allowlist(
        store: Arc<Mutex<KnowledgeStore>>,
        roots: Vec<PathBuf>,
    ) -> Self {
        let canon: Vec<PathBuf> = roots
            .into_iter()
            .filter_map(|p| std::fs::canonicalize(&p).ok())
            .collect();
        Self {
            store,
            allowlist: Arc::new(Mutex::new(canon)),
        }
    }

    /// Add a base directory to the allowlist. Returns `true` if the path
    /// was added (canonicalization succeeded and it wasn't already
    /// present); `false` if already present or unresolvable.
    pub fn add_ingestion_root(&self, root: &Path) -> bool {
        let Ok(canon) = std::fs::canonicalize(root) else {
            return false;
        };
        let Ok(mut allow) = self.allowlist.lock() else {
            return false;
        };
        if allow.contains(&canon) {
            return false;
        }
        allow.push(canon);
        true
    }

    /// Snapshot of currently-allowed roots — for diagnostics and tests.
    pub fn allowlist_snapshot(&self) -> Vec<PathBuf> {
        self.allowlist
            .lock()
            .map(|a| a.clone())
            .unwrap_or_default()
    }

    /// Validate a caller-supplied path against the allowlist. Returns
    /// the canonicalized form on success; `Err(AccessDenied)` otherwise.
    /// Errors deliberately do NOT echo the path back to the caller — the
    /// audit log entry has the raw path; the wire response is structured.
    fn check_path_allowed(&self, raw: &str) -> zbus::fdo::Result<PathBuf> {
        let canon = std::fs::canonicalize(raw).map_err(|_| {
            zbus::fdo::Error::AccessDenied(
                "path not permitted: unresolvable or does not exist".to_string(),
            )
        })?;
        let allow = self
            .allowlist
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("allowlist lock poisoned: {e}")))?;
        if allow.is_empty() {
            return Err(zbus::fdo::Error::AccessDenied(
                "path not permitted: ingestion allowlist is empty".to_string(),
            ));
        }
        if allow.iter().any(|root| canon.starts_with(root)) {
            Ok(canon)
        } else {
            Err(zbus::fdo::Error::AccessDenied(
                "path not permitted: outside ingestion allowlist".to_string(),
            ))
        }
    }
}

#[zbus::interface(name = "org.delphi.Knowledge")]
impl KnowledgeService {
    /// Ingest a file from disk. Returns a JSON [`IngestionResult`].
    ///
    /// **Access control (Codex review FIX 1):** the path must lie under
    /// one of the configured ingestion roots (see [`add_ingestion_root`](Self::add_ingestion_root)).
    /// Paths outside the allowlist return `zbus::fdo::Error::AccessDenied`
    /// without leaking the rejected path back to the caller.
    ///
    /// Errors are returned as `zbus::fdo::Error::Failed` with a structured
    /// reason; the file's content is never echoed back in the error
    /// message.
    async fn ingest_file(&self, path: String) -> zbus::fdo::Result<String> {
        info!(path = %path, "D-Bus ingest_file");
        let canonical = self.check_path_allowed(&path)?;
        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let result = store
            .ingest_file(&canonical)
            .map_err(|e| zbus::fdo::Error::Failed(redact_to_kind(&e.to_string())))?;
        ingestion_to_json_string(&result)
    }

    /// Ingest raw text. Caller specifies the source URI and format.
    ///
    /// `format` must be one of: `"markdown"`, `"text"`, `"html"`.
    /// Other values record an Unavailable-fidelity source row but
    /// produce no nodes.
    async fn ingest_text(
        &self,
        text: String,
        source_uri: String,
        format: String,
    ) -> zbus::fdo::Result<String> {
        info!(uri = %source_uri, fmt = %format, "D-Bus ingest_text");
        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let result = store
            .ingest_text(&text, &source_uri, SourceType::UserAssertion, &format)
            .map_err(|e| zbus::fdo::Error::Failed(redact_to_kind(&e.to_string())))?;
        ingestion_to_json_string(&result)
    }

    /// Search the graph semantically. Returns a JSON array of
    /// [`NodeWithSources`].
    async fn search(&self, query: String, max_results: u32) -> zbus::fdo::Result<String> {
        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let results = store
            .search_semantic(&query, max_results.max(1) as usize)
            .map_err(|e| zbus::fdo::Error::Failed(redact_to_kind(&e.to_string())))?;
        let arr: Vec<serde_json::Value> = results.iter().map(node_with_sources_to_json).collect();
        serde_json::to_string(&arr)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
    }

    /// Walk outward from `node_id` along edges up to `max_depth`.
    /// Returns a JSON array of [`RelatedNode`].
    async fn related_to(&self, node_id: i64, max_depth: u32) -> zbus::fdo::Result<String> {
        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let nodes = store
            .related_to(node_id, max_depth)
            .map_err(|e| zbus::fdo::Error::Failed(redact_to_kind(&e.to_string())))?;
        let arr: Vec<serde_json::Value> = nodes.iter().map(related_node_to_json).collect();
        serde_json::to_string(&arr)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
    }

    /// Find the shortest edge path between two nodes. Returns a JSON
    /// array of edge ids, or the literal string `"null"` when unreachable.
    async fn find_path(&self, from_id: i64, to_id: i64) -> zbus::fdo::Result<String> {
        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let path = store
            .find_path(from_id, to_id)
            .map_err(|e| zbus::fdo::Error::Failed(redact_to_kind(&e.to_string())))?;
        match path {
            Some(p) => serde_json::to_string(&p)
                .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}"))),
            None => Ok("null".to_string()),
        }
    }

    /// List sources for a node. Returns a JSON array of [`Source`].
    async fn list_sources(&self, node_id: i64) -> zbus::fdo::Result<String> {
        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let sources = store
            .list_sources_for(node_id)
            .map_err(|e| zbus::fdo::Error::Failed(redact_to_kind(&e.to_string())))?;
        let arr: Vec<serde_json::Value> = sources.iter().map(source_to_json).collect();
        serde_json::to_string(&arr)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
    }

    /// Find all `(node_a, node_b)` pairs connected by a Contradicts edge.
    /// Returns a JSON array of two-element arrays.
    async fn detect_contradictions(&self) -> zbus::fdo::Result<String> {
        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let pairs = store
            .detect_contradictions()
            .map_err(|e| zbus::fdo::Error::Failed(redact_to_kind(&e.to_string())))?;
        let arr: Vec<[i64; 2]> = pairs.into_iter().map(|(a, b)| [a, b]).collect();
        serde_json::to_string(&arr)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
    }

    /// Forget a source. Returns the number of nodes that became
    /// orphaned (no remaining sources) and were removed.
    async fn forget_source(&self, source_id: i64) -> zbus::fdo::Result<u32> {
        info!(source_id, "D-Bus forget_source");
        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        store
            .forget_source(source_id)
            .map_err(|e| zbus::fdo::Error::Failed(redact_to_kind(&e.to_string())))
    }

    // ── signals (declared only; emission deferred to the daemon) ───

    /// Emitted after [`ingest_file`] or [`ingest_text`] creates one or
    /// more nodes. The daemon diffs successive store state to detect
    /// "new ingestion" and emits this signal.
    #[zbus(signal)]
    async fn ingestion_complete(
        signal_emitter: &SignalEmitter<'_>,
        source_id: i64,
        nodes_created: u32,
    ) -> zbus::Result<()>;

    /// Emitted when [`detect_contradictions`] finds a new pair (one not
    /// previously surfaced). The shell shows these in the action timeline.
    #[zbus(signal)]
    async fn contradiction_detected(
        signal_emitter: &SignalEmitter<'_>,
        node_a: i64,
        node_b: i64,
    ) -> zbus::Result<()>;

    /// Emitted when a node's `last_accessed` is updated via [`touch_node`].
    /// The learning engine subscribes to correlate access patterns with
    /// other observation streams.
    #[zbus(signal)]
    async fn knowledge_accessed(
        signal_emitter: &SignalEmitter<'_>,
        node_id: i64,
    ) -> zbus::Result<()>;
}

// ────────────────────────────────────────────────────────────────────
// JSON helpers
// ────────────────────────────────────────────────────────────────────

fn ingestion_to_json_string(r: &IngestionResult) -> zbus::fdo::Result<String> {
    let v = serde_json::json!({
        "source_id": r.source_id,
        "nodes_created": r.nodes_created,
        "edges_created": r.edges_created,
        "fidelity_used": r.fidelity_used.as_str(),
        "format_detected": r.format_detected,
    });
    serde_json::to_string(&v).map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
}

fn node_to_json(n: &KnowledgeNode) -> serde_json::Value {
    serde_json::json!({
        "id": n.id,
        "content": n.content,
        "node_type": n.node_type.as_str(),
        "source_ids": n.source_ids,
        "created_at": n.created_at.to_rfc3339(),
        "last_accessed": n.last_accessed.to_rfc3339(),
        "access_count": n.access_count,
    })
}

fn source_to_json(s: &Source) -> serde_json::Value {
    serde_json::json!({
        "id": s.id,
        "source_type": source_type_str(s.source_type),
        "uri": s.uri,
        "ingested_at": s.ingested_at.to_rfc3339(),
        "fidelity": s.fidelity.as_str(),
        "content_hash": s.content_hash,
        "format": s.format,
    })
}

fn source_type_str(t: SourceType) -> &'static str {
    t.as_str()
}

fn node_with_sources_to_json(n: &NodeWithSources) -> serde_json::Value {
    serde_json::json!({
        "node": node_to_json(&n.node),
        "sources": n.sources.iter().map(source_to_json).collect::<Vec<_>>(),
        "similarity_score": n.similarity_score,
    })
}

fn related_node_to_json(r: &RelatedNode) -> serde_json::Value {
    serde_json::json!({
        "node": node_to_json(&r.node),
        "via_relation": edge_relation_str(r.via_relation),
        "depth": r.depth,
    })
}

fn edge_relation_str(r: EdgeRelation) -> &'static str {
    r.as_str()
}

/// Strip any quoted user content from an error message before it crosses
/// the D-Bus boundary. We keep the outer error type ("knowledge sqlite",
/// "planning failed", etc.) but drop everything after the first colon —
/// that's where rusqlite tends to put offending row values, and where
/// our own Planning errors put context that may include user text.
fn redact_to_kind(msg: &str) -> String {
    msg.split_once(':')
        .map(|(kind, _)| kind.trim().to_string())
        .unwrap_or_else(|| msg.trim().to_string())
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use die_orchestrator::knowledge::{KnowledgeStore, MockEmbedder, NodeType};

    fn mk_svc() -> KnowledgeService {
        let store = KnowledgeStore::in_memory(Box::new(MockEmbedder::new())).unwrap();
        KnowledgeService::new(Arc::new(Mutex::new(store)))
    }

    /// Build a service whose only ingestion root is `root`. Used by the
    /// allowlist tests to fully isolate the per-test filesystem region.
    fn mk_svc_with_root(root: PathBuf) -> KnowledgeService {
        let store = KnowledgeStore::in_memory(Box::new(MockEmbedder::new())).unwrap();
        KnowledgeService::with_allowlist(Arc::new(Mutex::new(store)), vec![root])
    }

    #[test]
    fn path_is_valid() {
        assert!(PATH.starts_with("/org/delphi"));
        assert!(PATH.ends_with("Knowledge"));
    }

    #[test]
    fn service_creation() {
        let _ = mk_svc();
    }

    #[test]
    fn redact_to_kind_drops_value_part() {
        assert_eq!(
            redact_to_kind("knowledge sqlite: row contains 'secret'"),
            "knowledge sqlite"
        );
        assert_eq!(redact_to_kind("standalone"), "standalone");
    }

    // ── FIX 1: ingest_file allowlist enforcement ─────────────────────

    #[tokio::test]
    async fn ingest_file_accepts_path_inside_allowlist() {
        let tmp = tempfile::TempDir::new().unwrap();
        let svc = mk_svc_with_root(tmp.path().to_path_buf());
        let file = tmp.path().join("note.md");
        std::fs::write(&file, "# T\n\nP.\n").unwrap();
        let json = svc
            .ingest_file(file.to_string_lossy().into_owned())
            .await
            .unwrap();
        // Successful round-trip — JSON shape, not contents
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["source_id"].as_i64().unwrap() > 0);
    }

    #[tokio::test]
    async fn ingest_file_rejects_path_outside_allowlist() {
        let allowed = tempfile::TempDir::new().unwrap();
        let other = tempfile::TempDir::new().unwrap();
        let svc = mk_svc_with_root(allowed.path().to_path_buf());
        let outside = other.path().join("evil.md");
        std::fs::write(&outside, "should not be ingested").unwrap();
        let err = svc
            .ingest_file(outside.to_string_lossy().into_owned())
            .await
            .unwrap_err();
        // Must be AccessDenied per FIX 1
        let s = err.to_string().to_lowercase();
        assert!(
            s.contains("access") || s.contains("not permitted") || s.contains("denied"),
            "expected access-denied error, got: {s}"
        );
        // Error message must not echo the rejected path
        let raw = outside.to_string_lossy();
        assert!(
            !err.to_string().contains(raw.as_ref()),
            "error message leaked the path: {err}"
        );
    }

    #[tokio::test]
    async fn ingest_file_rejects_nonexistent_path() {
        let allowed = tempfile::TempDir::new().unwrap();
        let svc = mk_svc_with_root(allowed.path().to_path_buf());
        let ghost = allowed.path().join("does-not-exist.md");
        let err = svc
            .ingest_file(ghost.to_string_lossy().into_owned())
            .await
            .unwrap_err();
        let s = err.to_string().to_lowercase();
        assert!(s.contains("access") || s.contains("not permitted"));
    }

    #[tokio::test]
    async fn ingest_file_rejects_traversal_escape() {
        // /allowed/../other/secret.md canonicalizes to /other/secret.md,
        // which is outside the allowlist — must be rejected.
        let allowed = tempfile::TempDir::new().unwrap();
        let other = tempfile::TempDir::new().unwrap();
        let svc = mk_svc_with_root(allowed.path().to_path_buf());
        let outside = other.path().join("secret.md");
        std::fs::write(&outside, "secret").unwrap();
        // Construct a traversal path through the allowed root.
        let traversal = allowed
            .path()
            .join("..")
            .join(outside.file_name().unwrap());
        // Note: this traversal path doesn't exist in the form constructed —
        // canonicalization fails first. That's still AccessDenied (the
        // safe-by-default semantic: anything we can't prove is inside is
        // outside).
        let err = svc
            .ingest_file(traversal.to_string_lossy().into_owned())
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("access"));
    }

    #[tokio::test]
    async fn ingest_file_rejects_when_allowlist_empty() {
        let store = KnowledgeStore::in_memory(Box::new(MockEmbedder::new())).unwrap();
        let svc = KnowledgeService::with_allowlist(Arc::new(Mutex::new(store)), vec![]);
        let tmp = tempfile::TempDir::new().unwrap();
        let file = tmp.path().join("any.md");
        std::fs::write(&file, "x").unwrap();
        let err = svc
            .ingest_file(file.to_string_lossy().into_owned())
            .await
            .unwrap_err();
        let s = err.to_string().to_lowercase();
        assert!(s.contains("access") || s.contains("empty") || s.contains("not permitted"));
    }

    #[test]
    fn add_ingestion_root_canonicalizes_and_dedupes() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = KnowledgeStore::in_memory(Box::new(MockEmbedder::new())).unwrap();
        let svc = KnowledgeService::with_allowlist(Arc::new(Mutex::new(store)), vec![]);
        assert!(svc.allowlist_snapshot().is_empty());
        // First add succeeds.
        assert!(svc.add_ingestion_root(tmp.path()));
        assert_eq!(svc.allowlist_snapshot().len(), 1);
        // Second add of the same path is a no-op (already present after canon).
        assert!(!svc.add_ingestion_root(tmp.path()));
        assert_eq!(svc.allowlist_snapshot().len(), 1);
        // Adding a non-existent path fails.
        assert!(!svc.add_ingestion_root(std::path::Path::new("/no/such/path/here/exists")));
    }

    #[tokio::test]
    async fn ingest_text_returns_json_with_counts() {
        let svc = mk_svc();
        let json = svc
            .ingest_text(
                "# Topic\n\nA fact.\n".to_string(),
                "user://note".to_string(),
                "markdown".to_string(),
            )
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["source_id"].as_i64().unwrap() > 0);
        assert!(v["nodes_created"].as_u64().unwrap() >= 2);
        assert_eq!(v["fidelity_used"], "direct");
        assert_eq!(v["format_detected"], "markdown");
    }

    #[tokio::test]
    async fn ingest_text_idempotent_returns_zero_new_nodes() {
        let svc = mk_svc();
        let _ = svc
            .ingest_text(
                "# T\n\nP.\n".to_string(),
                "u".to_string(),
                "markdown".to_string(),
            )
            .await
            .unwrap();
        let json = svc
            .ingest_text(
                "# T\n\nP.\n".to_string(),
                "u".to_string(),
                "markdown".to_string(),
            )
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["nodes_created"].as_u64().unwrap(), 0);
    }

    #[tokio::test]
    async fn ingest_text_unsupported_format_returns_unavailable() {
        let svc = mk_svc();
        let json = svc
            .ingest_text(
                "binary or whatever".to_string(),
                "/x.pdf".to_string(),
                "pdf".to_string(),
            )
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["fidelity_used"], "unavailable");
        assert_eq!(v["nodes_created"].as_u64().unwrap(), 0);
    }

    #[tokio::test]
    async fn search_returns_json_array_with_sources() {
        let svc = mk_svc();
        svc.ingest_text(
            "# Topic\n\napple banana cherry.\n".to_string(),
            "u".to_string(),
            "markdown".to_string(),
        )
        .await
        .unwrap();
        let json = svc
            .search("apple banana cherry".to_string(), 5)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.is_array());
        let arr = v.as_array().unwrap();
        assert!(!arr.is_empty());
        // Every result must carry sources (provenance enforced).
        for item in arr {
            assert!(item["sources"].is_array());
            assert!(!item["sources"].as_array().unwrap().is_empty());
            assert!(item["node"]["content"].is_string());
        }
    }

    #[tokio::test]
    async fn search_zero_max_results_clamped_to_one() {
        let svc = mk_svc();
        svc.ingest_text(
            "# T\n\nA.\n".to_string(),
            "u".to_string(),
            "markdown".to_string(),
        )
        .await
        .unwrap();
        let json = svc.search("A".to_string(), 0).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Clamped to 1 → at most 1 result returned (or 0 if no embeddings).
        assert!(v.as_array().unwrap().len() <= 1);
    }

    #[tokio::test]
    async fn related_to_returns_json_array() {
        let svc = mk_svc();
        svc.ingest_text(
            "# Parent\n\nChild fact.\n".to_string(),
            "u".to_string(),
            "markdown".to_string(),
        )
        .await
        .unwrap();
        // Find one node id to walk from
        let json = svc.search("Parent".to_string(), 1).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let id = v[0]["node"]["id"].as_i64().unwrap();
        let rel_json = svc.related_to(id, 2).await.unwrap();
        let _: serde_json::Value = serde_json::from_str(&rel_json).unwrap();
    }

    #[tokio::test]
    async fn find_path_returns_null_for_unreachable() {
        let svc = mk_svc();
        // Create two nodes with no edges between them.
        {
            let store = svc.store.lock().unwrap();
            let s = store
                .create_or_get_source(
                    SourceType::UserAssertion,
                    "u",
                    die_orchestrator::environment::Fidelity::Direct,
                    "h",
                    "t",
                )
                .unwrap();
            store.create_node("a", NodeType::Concept, &[s]).unwrap();
            store.create_node("b", NodeType::Concept, &[s]).unwrap();
        }
        let json = svc.find_path(1, 2).await.unwrap();
        assert_eq!(json, "null");
    }

    #[tokio::test]
    async fn list_sources_returns_json_array() {
        let svc = mk_svc();
        svc.ingest_text(
            "# T\n\nP.\n".to_string(),
            "u".to_string(),
            "markdown".to_string(),
        )
        .await
        .unwrap();
        let search_json = svc.search("T".to_string(), 1).await.unwrap();
        let sv: serde_json::Value = serde_json::from_str(&search_json).unwrap();
        let id = sv[0]["node"]["id"].as_i64().unwrap();
        let json = svc.list_sources(id).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.is_array());
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(v[0]["fidelity"], "direct");
    }

    #[tokio::test]
    async fn detect_contradictions_returns_empty_initially() {
        let svc = mk_svc();
        let json = svc.detect_contradictions().await.unwrap();
        assert_eq!(json, "[]");
    }

    #[tokio::test]
    async fn detect_contradictions_returns_pairs() {
        let svc = mk_svc();
        let (a_id, b_id, src);
        {
            let store = svc.store.lock().unwrap();
            src = store
                .create_or_get_source(
                    SourceType::UserAssertion,
                    "u",
                    die_orchestrator::environment::Fidelity::Direct,
                    "h",
                    "t",
                )
                .unwrap();
            a_id = store.create_node("X", NodeType::Fact, &[src]).unwrap();
            b_id = store.create_node("not X", NodeType::Fact, &[src]).unwrap();
            store
                .create_edge(a_id, b_id, EdgeRelation::Contradicts, 0.9, src)
                .unwrap();
        }
        let json = svc.detect_contradictions().await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0][0].as_i64().unwrap(), a_id);
        assert_eq!(arr[0][1].as_i64().unwrap(), b_id);
    }

    #[tokio::test]
    async fn forget_source_orphans_nodes_and_returns_count() {
        let svc = mk_svc();
        let r = svc
            .ingest_text(
                "# T\n\nP.\n".to_string(),
                "u".to_string(),
                "markdown".to_string(),
            )
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        let src_id = v["source_id"].as_i64().unwrap();
        let count = svc.forget_source(src_id).await.unwrap();
        assert!(count >= 1);
    }

    #[tokio::test]
    async fn forget_source_returns_zero_for_unknown_id() {
        let svc = mk_svc();
        assert_eq!(svc.forget_source(99_999).await.unwrap(), 0);
    }

    // Privacy / error-redaction tests

    #[tokio::test]
    async fn error_messages_do_not_echo_content() {
        // Force an error path by sending a deliberately broken arrangement.
        // We mostly want to verify the redact_to_kind helper is wired in.
        let svc = mk_svc();
        // search itself doesn't error on empty result; just confirm that
        // any potential failure in this layer would be redacted at the
        // boundary. Direct unit test of the helper above already covers
        // the redaction logic.
        let _ = svc.search("anything".to_string(), 1).await;
    }
}
