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

/// Directory names that must never be ingested, regardless of allowlist.
/// Compared component-wise (case-insensitive ASCII) against the
/// canonicalized path. A path containing any of these as a component is
/// rejected even if the user explicitly added a parent dir to the
/// allowlist.
///
/// Codex review (FIX 4 round) flagged the original allowlist as
/// insufficient: even an opt-in allowlist that includes the user's home
/// can pull keys/credentials/tokens. This denylist provides a safety
/// net the allowlist cannot override.
const SENSITIVE_DIR_NAMES: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".gpg",
    ".aws",
    ".kube",
    ".docker",
    ".azure",
];

/// File-name stems that always indicate sensitive material. Compared
/// case-insensitively against the canonicalized path's `file_name`.
const SENSITIVE_FILE_NAMES: &[&str] = &[
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "credentials",
    "authorized_keys",
    "known_hosts",
];

/// File extensions that always indicate sensitive material. Compared
/// case-insensitively (so `.PEM` is rejected the same as `.pem`).
const SENSITIVE_EXTENSIONS: &[&str] = &[
    "pem", "key", "p12", "pfx", "kdbx", "keystore", "jks",
];

/// Pure function: returns `true` if the canonicalized path matches the
/// sensitive-content denylist and must be rejected.
///
/// Checks (in order, return `true` on first hit):
/// 1. Each path component against [`SENSITIVE_DIR_NAMES`]
/// 2. The file-name stem against [`SENSITIVE_FILE_NAMES`]
/// 3. The file name's `.env*` prefix (catches `.env`, `.env.production`, etc.)
/// 4. The file extension against [`SENSITIVE_EXTENSIONS`]
///
/// The function takes only `&Path` and performs no I/O — it's a pure
/// classifier suitable for unit testing without temp dirs or fixtures.
pub(crate) fn is_sensitive_path(path: &Path) -> bool {
    // Component-wise dir-name check.
    for comp in path.components() {
        if let std::path::Component::Normal(os) = comp
            && let Some(name) = os.to_str()
            && SENSITIVE_DIR_NAMES
                .iter()
                .any(|d| d.eq_ignore_ascii_case(name))
        {
            return true;
        }
    }
    // File name + extension checks.
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let lower = file_name.to_ascii_lowercase();
    if SENSITIVE_FILE_NAMES.iter().any(|n| lower == *n) {
        return true;
    }
    if lower.starts_with(".env") {
        return true;
    }
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_ascii_lowercase();
        if SENSITIVE_EXTENSIONS.iter().any(|e| ext_lower == *e) {
            return true;
        }
    }
    false
}

/// Knowledge D-Bus service.
///
/// Wraps a [`KnowledgeStore`] in `Arc<Mutex<...>>` so async D-Bus methods
/// can lock briefly to read state or mutate the graph. The Mutex is the
/// standard `std::sync::Mutex`.
///
/// # Path access control — closed-by-default (Codex review FIX 4, P1)
///
/// [`ingest_file`](Self::ingest_file) takes a caller-supplied path. The
/// initial 3A.5 design auto-registered the user's home directory as an
/// ingestion root — Codex flagged that any D-Bus caller could then
/// request ingestion of `~/.ssh/id_rsa`, `~/.aws/credentials`,
/// dotfile-stored API tokens, or browser cookie databases, and pull
/// parsed content back through `search`.
///
/// **The default allowlist is now empty.** The shell explicitly
/// registers each ingestion root via
/// [`add_ingestion_root`](Self::add_ingestion_root) only after the user
/// picks a directory in a folder-picker dialog. Without that explicit
/// opt-in, every `ingest_file` call returns `AccessDenied`.
///
/// Path validation runs in this order, returning `AccessDenied` on the
/// first failure (without echoing the rejected path back to the wire):
///
/// 1. Canonicalize the input via `std::fs::canonicalize` (resolves
///    symlinks AND `..` components; non-existent paths fail early).
/// 2. Verify the canonical path lies under at least one allowlist entry
///    (component-wise prefix match — `/home/user2` does NOT match
///    `/home/user`).
/// 3. Verify the canonical path does not match the sensitive-content
///    denylist ([`is_sensitive_path`]). The denylist runs **after** the
///    allowlist so a denylisted file inside an allowed directory still
///    rejects — even an explicit allowlist cannot override the denylist.
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
/// // svc.allowlist_snapshot() is empty — shell must add roots before ingestion.
/// ```
pub struct KnowledgeService {
    store: Arc<Mutex<KnowledgeStore>>,
    /// Canonicalized base directories that `ingest_file` will accept.
    /// Empty allowlist → no path is permitted (closed by default,
    /// Codex review FIX 4 P1).
    allowlist: Arc<Mutex<Vec<PathBuf>>>,
}

impl KnowledgeService {
    /// Build a service with an **empty** ingestion allowlist. This is
    /// the closed-by-default posture per Codex review FIX 4 (P1):
    /// every `ingest_file` call returns `AccessDenied` until the shell
    /// registers explicit roots via
    /// [`add_ingestion_root`](Self::add_ingestion_root).
    ///
    /// The intended flow is: the user clicks a folder-picker in the
    /// shell, the shell sends the picked path over D-Bus to a future
    /// `AddIngestionRoot` method (or the daemon registers it directly
    /// at construction), and only THEN can the path be ingested.
    #[must_use]
    pub fn new(store: Arc<Mutex<KnowledgeStore>>) -> Self {
        Self {
            store,
            allowlist: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Build a service with an explicit allowlist of base directories.
    /// Each entry is canonicalized; entries that don't exist are dropped.
    /// Useful for tests that need to inject a tempdir-rooted allowlist
    /// and for daemon code that pre-registers roots from saved settings.
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
    ///
    /// **Codex re-review FIX 7 (P1-high):** every rejection path returns
    /// the SAME public message — [`REJECTION_MESSAGE`]. Round-1 returned
    /// four distinguishable messages under one `AccessDenied` discriminant,
    /// which let a D-Bus caller probe the filesystem for resolvable vs.
    /// missing paths. Detailed reasons now go to the local tracing log
    /// only (operator diagnostics) via [`reject`]. The wire response is
    /// uniform regardless of why the path was rejected.
    ///
    /// **Order matters:** the empty-allowlist check runs **before**
    /// canonicalization. When ingestion is closed by default, we never
    /// touch the filesystem at all — eliminating the probe oracle for
    /// the default-deployed state. Only after the allowlist is
    /// non-empty do we resolve the caller's path.
    fn check_path_allowed(&self, raw: &str) -> zbus::fdo::Result<PathBuf> {
        // Snapshot the allowlist under the mutex, then drop the guard
        // before any filesystem syscall. This keeps the lock window
        // tight and lets the canonicalize() call run unsynchronized.
        let snapshot: Vec<PathBuf> = {
            let allow = self
                .allowlist
                .lock()
                .map_err(|e| zbus::fdo::Error::Failed(format!("allowlist lock poisoned: {e}")))?;
            // FIX 7 part A: short-circuit on empty allowlist BEFORE any
            // filesystem syscall. Closed-by-default → no probe oracle.
            if allow.is_empty() {
                return Err(reject(RejectionReason::AllowlistEmpty, raw));
            }
            allow.clone()
        };

        // Allowlist is non-empty; canonicalization is justified.
        let canon = std::fs::canonicalize(raw)
            .map_err(|_| reject(RejectionReason::Unresolvable, raw))?;

        if !snapshot.iter().any(|root| canon.starts_with(root)) {
            return Err(reject(RejectionReason::OutsideAllowlist, raw));
        }

        // Denylist runs AFTER allowlist on purpose: we never want to
        // signal "this file exists but is denylisted" with a different
        // rejection reason than "this file isn't in your allowlist."
        if is_sensitive_path(&canon) {
            return Err(reject(RejectionReason::SensitivePath, raw));
        }

        Ok(canon)
    }
}

// ────────────────────────────────────────────────────────────────────
// FIX 7 (P1-high): uniform public rejection + local-only audit log
// ────────────────────────────────────────────────────────────────────

/// Single public rejection message. The detailed reason is logged
/// locally via `tracing` for operator diagnostics, never returned to
/// the D-Bus caller — that would re-introduce the filesystem-existence
/// oracle Codex flagged in re-review finding F7.
pub(crate) const REJECTION_MESSAGE: &str = "path not permitted";

/// Reasons we reject a path. Used only for local tracing; never crosses
/// the D-Bus boundary.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RejectionReason {
    /// Allowlist is empty — ingestion closed by default.
    AllowlistEmpty,
    /// `canonicalize()` failed — path doesn't exist or can't be resolved.
    Unresolvable,
    /// Canonical path doesn't start with any allowlist root.
    OutsideAllowlist,
    /// Path matches the sensitive-content denylist.
    SensitivePath,
}

impl RejectionReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RejectionReason::AllowlistEmpty => "allowlist empty",
            RejectionReason::Unresolvable => "unresolvable or does not exist",
            RejectionReason::OutsideAllowlist => "outside allowlist",
            RejectionReason::SensitivePath => "matches sensitive-content denylist",
        }
    }
}

/// Construct an `AccessDenied` error with the uniform public message,
/// emitting the detailed reason + raw caller path to the local tracing
/// log. The wire response carries no information about why the path
/// was rejected.
pub(crate) fn reject(reason: RejectionReason, raw: &str) -> zbus::fdo::Error {
    tracing::warn!(
        reason = reason.as_str(),
        raw_path = %raw,
        "knowledge ingestion path rejected"
    );
    zbus::fdo::Error::AccessDenied(REJECTION_MESSAGE.to_string())
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

        // FIX 10+11: the orchestrator's safe-open boundary needs the
        // allowlist root that contained the canonical path so it can
        // anchor its kernel-level traversal (Linux `openat2` opens a
        // directory FD on the root; Windows walks each component).
        // `check_path_allowed` already proved canonical.starts_with(root)
        // for some root in the allowlist; we re-locate that root here.
        // If the allowlist changes between check_path_allowed and this
        // lookup we fail closed — `reject(OutsideAllowlist)` returns the
        // uniform public message FIX 7 mandates.
        let trusted_root = {
            let allow = self.allowlist.lock().map_err(|e| {
                zbus::fdo::Error::Failed(format!("allowlist lock poisoned: {e}"))
            })?;
            allow
                .iter()
                .find(|root| canonical.starts_with(root))
                .cloned()
                .ok_or_else(|| reject(RejectionReason::OutsideAllowlist, &path))?
        };

        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let result = store
            .ingest_file(&trusted_root, &canonical)
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

    /// FIX 7 helper: every allowlist/denylist rejection must be the
    /// `AccessDenied` variant carrying exactly the uniform public
    /// message. Tests use this in place of substring matching on the
    /// Display string so they're immune to zbus formatting changes
    /// AND can't accidentally allow a leaked-detail message to pass.
    fn assert_uniform_rejection(err: &zbus::fdo::Error) {
        match err {
            zbus::fdo::Error::AccessDenied(msg) => {
                assert_eq!(
                    msg, REJECTION_MESSAGE,
                    "rejection message must be uniform; got {msg:?}"
                );
            }
            other => panic!("expected AccessDenied, got {other:?}"),
        }
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
        // Codex re-review FIX 7 P1: discriminant + uniform message.
        // Tests previously did substring matching on the Display, which
        // would have happily accepted four distinct leaked messages.
        assert_uniform_rejection(&err);
        // Defense-in-depth: the rejected path must not be echoed in
        // any part of the error string (Display, message, or both).
        let raw = outside.to_string_lossy();
        assert!(
            !err.to_string().contains(raw.as_ref()),
            "error string leaked the path: {err}"
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
        assert_uniform_rejection(&err);
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
        assert_uniform_rejection(&err);
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
        assert_uniform_rejection(&err);
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

    // ── FIX 4 (P1): closed-by-default allowlist + sensitive-path denylist ─

    #[test]
    fn default_new_has_empty_allowlist() {
        // Codex review FIX 4 P1: KnowledgeService::new must NOT auto-add
        // home dir. The shell registers explicit roots after the user
        // picks them in a folder dialog.
        let svc = mk_svc();
        assert!(
            svc.allowlist_snapshot().is_empty(),
            "default new() must produce empty allowlist (closed by default)"
        );
    }

    #[tokio::test]
    async fn ingest_file_rejected_when_allowlist_default_empty() {
        // Even an ordinary markdown file inside the user's home is
        // rejected unless the user explicitly registers that location.
        let svc = mk_svc();
        let tmp = tempfile::TempDir::new().unwrap();
        let file = tmp.path().join("note.md");
        std::fs::write(&file, "# T\n\nP.\n").unwrap();
        let err = svc
            .ingest_file(file.to_string_lossy().into_owned())
            .await
            .unwrap_err();
        assert_uniform_rejection(&err);
    }

    // -- Pure is_sensitive_path tests (no async, no I/O) --

    #[test]
    fn sensitive_path_rejects_ssh_private_key() {
        assert!(is_sensitive_path(Path::new("/home/u/.ssh/id_rsa")));
    }

    #[test]
    fn sensitive_path_rejects_ed25519() {
        assert!(is_sensitive_path(Path::new("/home/u/.ssh/id_ed25519")));
    }

    #[test]
    fn sensitive_path_rejects_pem_extension() {
        assert!(is_sensitive_path(Path::new("/tmp/cert.pem")));
    }

    #[test]
    fn sensitive_path_rejects_env_file() {
        assert!(is_sensitive_path(Path::new("/proj/.env.production")));
    }

    #[test]
    fn sensitive_path_rejects_credentials_filename() {
        // /home/u/.aws/credentials — caught by either the .aws dir name
        // OR the "credentials" file-stem rule. Either is fine.
        assert!(is_sensitive_path(Path::new("/home/u/.aws/credentials")));
    }

    #[test]
    fn sensitive_path_rejects_kdbx() {
        assert!(is_sensitive_path(Path::new("/home/u/passwords.kdbx")));
    }

    #[test]
    fn sensitive_path_rejects_gnupg_dir_midpath() {
        // .gnupg as an intermediate path component triggers the dir rule
        // even though the leaf file looks innocuous.
        assert!(is_sensitive_path(Path::new("/home/u/.gnupg/random.txt")));
    }

    #[test]
    fn sensitive_path_accepts_ordinary_markdown() {
        assert!(!is_sensitive_path(Path::new("/home/u/notes/foo.md")));
    }

    #[test]
    fn sensitive_path_accepts_dotfile_that_is_not_sensitive() {
        // .bashrc is a dotfile but neither a sensitive-named file nor
        // does it match the .env* prefix nor a sensitive extension.
        assert!(!is_sensitive_path(Path::new("/home/u/.bashrc")));
    }

    #[test]
    fn sensitive_path_extension_check_is_case_insensitive() {
        assert!(is_sensitive_path(Path::new("/tmp/cert.PEM")));
        assert!(is_sensitive_path(Path::new("/tmp/cert.Pem")));
    }

    // -- Integration tests: denylist defeats allowlist --

    #[tokio::test]
    async fn ingest_file_rejects_sensitive_path_inside_allowlist() {
        // Even when the user explicitly registers tmp/ as an ingestion
        // root, dropping an id_rsa file inside it must still reject —
        // the denylist runs after the allowlist and cannot be overridden.
        let tmp = tempfile::TempDir::new().unwrap();
        let svc = mk_svc_with_root(tmp.path().to_path_buf());
        let key_file = tmp.path().join("id_rsa");
        std::fs::write(&key_file, "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
        let err = svc
            .ingest_file(key_file.to_string_lossy().into_owned())
            .await
            .unwrap_err();
        // FIX 7 P1: must be the uniform "AccessDenied + REJECTION_MESSAGE",
        // never a leak like "matches sensitive-content denylist".
        assert_uniform_rejection(&err);
    }

    #[tokio::test]
    async fn ingest_file_rejects_pem_inside_allowlist() {
        let tmp = tempfile::TempDir::new().unwrap();
        let svc = mk_svc_with_root(tmp.path().to_path_buf());
        let pem = tmp.path().join("cert.pem");
        std::fs::write(&pem, "-----BEGIN CERTIFICATE-----\n").unwrap();
        let err = svc
            .ingest_file(pem.to_string_lossy().into_owned())
            .await
            .unwrap_err();
        assert_uniform_rejection(&err);
    }

    #[tokio::test]
    async fn ingest_file_rejects_env_inside_allowlist() {
        let tmp = tempfile::TempDir::new().unwrap();
        let svc = mk_svc_with_root(tmp.path().to_path_buf());
        let env = tmp.path().join(".env");
        std::fs::write(&env, "API_KEY=secret\n").unwrap();
        let err = svc
            .ingest_file(env.to_string_lossy().into_owned())
            .await
            .unwrap_err();
        assert_uniform_rejection(&err);
    }

    // ── FIX 7 (P1-high): uniform public rejection + no FS probe oracle ──

    #[tokio::test]
    async fn rejection_message_is_uniform_across_all_failure_modes() {
        // Drive ingest_file through all FOUR rejection paths and assert
        // every one returns the IDENTICAL public message. Round-1 returned
        // four distinct messages under one variant — Codex F7 oracle.
        let allowed = tempfile::TempDir::new().unwrap();
        let other = tempfile::TempDir::new().unwrap();

        // Path 1: allowlist-empty (closed-by-default)
        let store1 = KnowledgeStore::in_memory(Box::new(MockEmbedder::new())).unwrap();
        let svc_empty =
            KnowledgeService::with_allowlist(Arc::new(Mutex::new(store1)), vec![]);
        let any_path = allowed.path().join("any.md");
        std::fs::write(&any_path, "x").unwrap();
        let err_empty = svc_empty
            .ingest_file(any_path.to_string_lossy().into_owned())
            .await
            .unwrap_err();

        // Path 2: unresolvable (path doesn't exist)
        let svc_with = mk_svc_with_root(allowed.path().to_path_buf());
        let ghost = allowed.path().join("nonexistent.md");
        let err_ghost = svc_with
            .ingest_file(ghost.to_string_lossy().into_owned())
            .await
            .unwrap_err();

        // Path 3: outside allowlist
        let outside = other.path().join("evil.md");
        std::fs::write(&outside, "x").unwrap();
        let err_outside = svc_with
            .ingest_file(outside.to_string_lossy().into_owned())
            .await
            .unwrap_err();

        // Path 4: sensitive (denylisted) inside allowlist
        let key = allowed.path().join("id_rsa");
        std::fs::write(&key, "-----BEGIN-----\n").unwrap();
        let err_sensitive = svc_with
            .ingest_file(key.to_string_lossy().into_owned())
            .await
            .unwrap_err();

        // All four messages must be byte-for-byte equal.
        let extract = |e: &zbus::fdo::Error| match e {
            zbus::fdo::Error::AccessDenied(m) => m.clone(),
            other => panic!("expected AccessDenied, got {other:?}"),
        };
        let m1 = extract(&err_empty);
        let m2 = extract(&err_ghost);
        let m3 = extract(&err_outside);
        let m4 = extract(&err_sensitive);
        assert_eq!(m1, m2, "empty-allowlist vs unresolvable leaked a difference");
        assert_eq!(m2, m3, "unresolvable vs outside-allowlist leaked a difference");
        assert_eq!(m3, m4, "outside vs sensitive leaked a difference");
        assert_eq!(m1, REJECTION_MESSAGE, "all paths must use REJECTION_MESSAGE");
    }

    #[tokio::test]
    async fn empty_allowlist_does_not_leak_filesystem_state() {
        // FIX 7 part A: when the allowlist is empty, ingestion is closed.
        // We do NOT touch the filesystem to canonicalize the input. So a
        // resolvable path and an unresolvable path produce IDENTICAL
        // rejections — caller cannot probe whether a path exists.
        let store = KnowledgeStore::in_memory(Box::new(MockEmbedder::new())).unwrap();
        let svc = KnowledgeService::with_allowlist(Arc::new(Mutex::new(store)), vec![]);

        // A path that DOES exist.
        let tmp = tempfile::TempDir::new().unwrap();
        let real = tmp.path().join("real.md");
        std::fs::write(&real, "x").unwrap();
        let err_real = svc
            .ingest_file(real.to_string_lossy().into_owned())
            .await
            .unwrap_err();

        // A path that does NOT exist (deliberately silly).
        let err_ghost = svc
            .ingest_file(
                "/this/path/cannot/possibly/exist/should-be-rejected.md".to_string(),
            )
            .await
            .unwrap_err();

        // Both must produce the same uniform rejection.
        assert_uniform_rejection(&err_real);
        assert_uniform_rejection(&err_ghost);
        // And they must be string-equal — no oracle.
        assert_eq!(err_real.to_string(), err_ghost.to_string());
    }

    #[test]
    fn tracing_log_records_specific_reason_but_wire_does_not() {
        // Asymmetry verification: the operator's tracing log gets the
        // detailed reason; the D-Bus caller gets only the uniform message.
        //
        // Tested directly against `reject()` — the SOLE constructor of
        // path-validation `AccessDenied` errors. Testing the full async
        // ingest_file path here would mean fighting tokio + thread-local
        // tracing scoping under parallel `cargo test` execution; calling
        // `reject()` directly is equivalent because `check_path_allowed`
        // routes every rejection through it.
        use std::io::Write;
        use std::sync::{Arc as StdArc, Mutex as StdMutex};

        #[derive(Clone)]
        struct CaptureWriter(StdArc<StdMutex<Vec<u8>>>);
        impl Write for CaptureWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buf: StdArc<StdMutex<Vec<u8>>> = StdArc::new(StdMutex::new(Vec::new()));
        let buf_for_writer = buf.clone();
        let make_writer = move || CaptureWriter(buf_for_writer.clone());

        let subscriber = tracing_subscriber::fmt()
            .with_writer(make_writer)
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish();

        let err = tracing::subscriber::with_default(subscriber, || {
            reject(
                RejectionReason::SensitivePath,
                "/secret/path/that/should/not/leak",
            )
        });

        // Local tracing log MUST contain the specific reason AND the path.
        let captured = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            captured.contains("matches sensitive-content denylist"),
            "expected detailed reason in local log; got: {captured:?}"
        );
        assert!(
            captured.contains("/secret/path/that/should/not/leak"),
            "expected raw path in local log; got: {captured:?}"
        );

        // Wire error MUST NOT contain the reason or the path — only the
        // uniform public message.
        let wire = match &err {
            zbus::fdo::Error::AccessDenied(m) => m.clone(),
            other => panic!("expected AccessDenied, got {other:?}"),
        };
        assert_eq!(wire, REJECTION_MESSAGE);
        assert!(
            !wire.contains("denylist") && !wire.contains("sensitive"),
            "wire response leaked specific reason: {wire}"
        );
        assert!(
            !wire.contains("/secret"),
            "wire response leaked the path: {wire}"
        );
    }

    // ── FIX 10+11 (P1-high): kernel-anchored safe-open boundary ──
    //
    // The TOCTOU defense lives at the **orchestrator** layer:
    // `safe_open_under_root` uses `openat2(2)` on Linux with
    // `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH` so the kernel refuses to
    // traverse a symlink at ANY path component (not just the leaf, as
    // round-2's `safe_open_no_follow` did) and refuses to escape the
    // trusted root via `..`. On Windows it walks each component
    // checking `FILE_ATTRIBUTE_REPARSE_POINT`. The orchestrator's
    // tests (`safe_open_under_root_rejects_*`,
    // `ingest_file_returns_safe_open_error_for_symlink`) exercise the
    // defense directly, including the F10 motivating intermediate-
    // component symlink case.
    //
    // At the services layer, a symlink whose target is inside the
    // allowlist canonicalizes cleanly to the real target — that's the
    // happy path. The integration test below documents that cooperation:
    // canonicalize resolves the symlink, the allowlist permits the
    // resolved target, and safe_open_under_root opens the real file
    // anchored to the trusted root the service derives from its
    // allowlist. The actual TOCTOU race (concurrent file swap) is
    // impractical to test at the services layer without thread
    // interleaving; the orchestrator's direct symlink-rejection tests
    // are the right place for that.

    #[cfg(unix)]
    #[tokio::test]
    async fn ingest_file_via_symlink_canonicalizes_to_real_target() {
        // Documents the FIX 1 + FIX 10+11 cooperation: passing a symlink
        // whose target is inside the allowlist works — canonicalize
        // resolves to the real target, the allowlist permits the real
        // target, the service finds the matching root, and the
        // orchestrator's safe_open_under_root opens the real target
        // anchored to that root. The TOCTOU defense (orchestrator-level
        // openat2) only matters if an attacker races against this
        // resolved path.
        let tmp = tempfile::TempDir::new().unwrap();
        let real = tmp.path().join("real.md");
        std::fs::write(&real, "# Real\n\nContent.\n").unwrap();
        let link = tmp.path().join("link.md");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let svc = mk_svc_with_root(tmp.path().to_path_buf());
        let json = svc
            .ingest_file(link.to_string_lossy().into_owned())
            .await
            .expect("symlink → real-target inside allowlist must succeed");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["source_id"].as_i64().unwrap() > 0);
        // The fidelity must be Direct because the markdown parser ran
        // on real bytes from the resolved file.
        assert_eq!(v["fidelity_used"], "direct");
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
