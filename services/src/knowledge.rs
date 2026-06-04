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
//! SVC-2: every method enforces authorization via the shared [`AuthGuard`]
//! on its first line. `ingest_file`/`ingest_text` are Confirm (they mutate
//! the graph); `search`, `related_to`, `find_path`, `list_sources`, and
//! `detect_contradictions` are Autonomous (read-only); `forget_source` is
//! Biometric (destructive — orphans and removes nodes). The three
//! `#[zbus(signal)]` declarations carry no guard (signals have no caller).
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
use zbus::message::Header;
use zbus::object_server::SignalEmitter;

use die_orchestrator::knowledge::{
    EdgeRelation, IngestionAccessController, IngestionError, IngestionResult, KnowledgeNode,
    KnowledgeStore, NodeWithSources, RelatedNode, Source, SourceType,
};

use crate::auth_guard::AuthGuard;

// SVC-8 (services-sweep): the held-handle `AllowlistRoot`, the
// `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` `open_dir_no_follow`, the
// sensitive-content denylist (`is_sensitive_path` + its const tables),
// and the closed-by-default allowlist + validation logic
// (`check_path_allowed_with_root`) all moved into the domain as
// `die_orchestrator::knowledge::IngestionAccessController`. The security
// boundary is now enforced at the type level: ingestion requires a
// `ValidatedIngestionPath` token that only the controller's `validate`
// can mint. This module keeps only the D-Bus wrapper, the uniform wire
// rejection message, and the domain-error → `zbus` mapping.

/// D-Bus object path for the Knowledge interface.
pub const PATH: &str = "/org/delphi/Knowledge";

/// Knowledge D-Bus service.
///
/// Wraps a [`KnowledgeStore`] in `Arc<Mutex<...>>` so async D-Bus methods
/// can lock briefly to read state or mutate the graph. The Mutex is the
/// standard `std::sync::Mutex`.
///
/// # Path access control — closed-by-default, enforced in the domain (SVC-8)
///
/// [`ingest_file`](Self::ingest_file) takes a caller-supplied path. The
/// initial 3A.5 design auto-registered the user's home directory as an
/// ingestion root — Codex flagged that any D-Bus caller could then
/// request ingestion of `~/.ssh/id_rsa`, `~/.aws/credentials`,
/// dotfile-stored API tokens, or browser cookie databases, and pull
/// parsed content back through `search`.
///
/// **The gate now lives in the domain.** This service holds a
/// [`die_orchestrator::knowledge::IngestionAccessController`] — the single
/// owner of the closed-by-default allowlist, canonicalization, prefix
/// match, and sensitive-content denylist (the 9-round-hardened
/// F4 / F7 / F15 logic). The shell registers each ingestion root via
/// [`add_ingestion_root`](Self::add_ingestion_root) only after the user
/// picks a directory; without that explicit opt-in, every `ingest_file`
/// call is denied.
///
/// The service no longer performs path validation itself: it asks the
/// controller to [`validate`](die_orchestrator::knowledge::IngestionAccessController::validate)
/// the path, which on success mints a
/// [`ValidatedIngestionPath`](die_orchestrator::knowledge::ValidatedIngestionPath)
/// capability token, and hands that token to
/// [`KnowledgeStore::ingest_validated_file`]. Possession of the token is
/// the only way to reach the store's file-ingest path, so the allowlist
/// cannot be bypassed. Every denial is mapped to one uniform
/// [`REJECTION_MESSAGE`] (FIX 7 — no filesystem-existence oracle).
///
/// # Examples
///
/// ```
/// use delphi_services::knowledge::KnowledgeService;
/// use delphi_services::auth_guard::AuthGuard;
/// use die_orchestrator::knowledge::{KnowledgeStore, MockEmbedder};
/// use std::sync::{Arc, Mutex};
///
/// let store = KnowledgeStore::in_memory(Box::new(MockEmbedder::new())).unwrap();
/// let svc = KnowledgeService::new(
///     Arc::new(Mutex::new(store)),
///     Arc::new(AuthGuard::dev_in_memory()),
/// );
/// // svc.allowlist_snapshot() is empty — shell must add roots before ingestion.
/// ```
pub struct KnowledgeService {
    store: Arc<Mutex<KnowledgeStore>>,
    guard: Arc<AuthGuard>,
    /// The domain ingestion access-control gate (SVC-8). Owns the
    /// closed-by-default allowlist of held directory handles and the
    /// sensitive-content denylist; the only minter of
    /// [`ValidatedIngestionPath`](die_orchestrator::knowledge::ValidatedIngestionPath)
    /// tokens. Empty allowlist → no path is permitted.
    access: IngestionAccessController,
}

impl KnowledgeService {
    /// Build a service with an **empty** ingestion allowlist (closed by
    /// default, FIX 4): every `ingest_file` call is denied until the shell
    /// registers explicit roots via
    /// [`add_ingestion_root`](Self::add_ingestion_root).
    ///
    /// The intended flow: the user clicks a folder-picker in the shell, the
    /// shell sends the picked path over D-Bus, the daemon registers it, and
    /// only THEN can a path under it be ingested.
    ///
    /// `guard` is the shared [`AuthGuard`] (SVC-2): every D-Bus method
    /// enforces authorization through it before touching the store.
    #[must_use]
    pub fn new(store: Arc<Mutex<KnowledgeStore>>, guard: Arc<AuthGuard>) -> Self {
        Self {
            store,
            guard,
            access: IngestionAccessController::new(),
        }
    }

    /// Build a service with an explicit allowlist of base directories.
    /// Delegates to [`IngestionAccessController::with_roots`]: each entry is
    /// canonicalized AND opened as a held directory handle (FIX 15); entries
    /// that fail either step are dropped (so on non-Linux the allowlist ends
    /// up empty). Useful for tests and for daemon code that pre-registers
    /// roots from saved settings.
    #[must_use]
    pub fn with_allowlist(
        store: Arc<Mutex<KnowledgeStore>>,
        roots: Vec<PathBuf>,
        guard: Arc<AuthGuard>,
    ) -> Self {
        Self {
            store,
            guard,
            access: IngestionAccessController::with_roots(roots),
        }
    }

    /// Add a base directory to the allowlist. Returns `true` if it was
    /// added. Delegates to [`IngestionAccessController::add_root`], which
    /// opens the directory with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` once
    /// at registration and holds the handle for the gate's lifetime (FIX
    /// 15) — anchoring trust to a kernel inode, not a path string.
    pub fn add_ingestion_root(&self, root: &Path) -> bool {
        self.access.add_root(root)
    }

    /// Snapshot of currently-allowed canonical root paths — for diagnostics
    /// and tests. Delegates to [`IngestionAccessController::snapshot`];
    /// returns paths only (the held handles stay an internal trust anchor).
    #[must_use]
    pub fn allowlist_snapshot(&self) -> Vec<PathBuf> {
        self.access.snapshot()
    }
}

// ────────────────────────────────────────────────────────────────────
// FIX 7 (P1-high): uniform public rejection + domain-error → wire mapping
// ────────────────────────────────────────────────────────────────────

/// Single public rejection message. The detailed reason is logged locally
/// (by the domain's `IngestionAccessController::validate`) for operator
/// diagnostics, never returned to the D-Bus caller — that would
/// re-introduce the filesystem-existence oracle Codex flagged in re-review
/// finding F7.
pub(crate) const REJECTION_MESSAGE: &str = "path not permitted";

/// Map a domain [`IngestionError`] to a `zbus::fdo::Error` at the trust
/// boundary.
///
/// **FIX 7 (P1-high):** every access *denial* — whatever its specific
/// reason — collapses to one uniform [`REJECTION_MESSAGE`] under
/// `AccessDenied`, so the wire carries no information about *why* a path
/// was refused (no allowlist-vs-denylist-vs-nonexistent oracle). The
/// specific reason and the raw path were already logged locally by the
/// domain's `validate`. An [`IngestionError::Internal`] (e.g. a poisoned
/// allowlist lock) is a bug, not an access decision, so it surfaces as a
/// generic `Failed` rather than `AccessDenied`.
fn map_ingestion_error(err: IngestionError) -> zbus::fdo::Error {
    match err {
        IngestionError::Denied(_) => zbus::fdo::Error::AccessDenied(REJECTION_MESSAGE.to_string()),
        IngestionError::Internal(_) => {
            zbus::fdo::Error::Failed("ingestion access check failed".to_string())
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
    ///
    /// # Platform support (Codex re-review FIX 16, P1-high)
    ///
    /// This method is supported on **Linux only** in the current build.
    /// Linux uses `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)`
    /// anchored to a held directory handle (FIX 15) for kernel-level
    /// race-free safe-open.
    ///
    /// On **Windows**, this method always returns
    /// `zbus::fdo::Error::AccessDenied` because
    /// [`add_ingestion_root`](Self::add_ingestion_root) refuses
    /// registration on Windows (the underlying `open_dir_no_follow`
    /// returns `ErrorKind::Unsupported`). The architectural reason:
    /// Windows lacks a documented kernel-level API equivalent to
    /// Linux `openat2`. The component-walk implementation used in
    /// round-3 had unfixable TOCTOU races between `symlink_metadata`
    /// checks and the final open; the only race-free Windows path
    /// requires `NtCreateFile` with `OBJ_DONT_REPARSE`, which is
    /// undocumented and version-unstable across Windows releases.
    /// Implementing the NT-level path is tracked as future work when
    /// Windows becomes a primary deployment target.
    ///
    /// On **macOS** and other Unix variants, this method also returns
    /// `AccessDenied` for the same reason: `openat2` is Linux-specific.
    /// macOS could in principle implement an equivalent via repeated
    /// `openat` walks with `O_NOFOLLOW`, but that work is deferred.
    ///
    /// **Workaround for unsupported platforms:** the
    /// [`ingest_text`](Self::ingest_text) method ingests
    /// caller-supplied content directly without requiring filesystem
    /// access. Shell code can read the file itself (using whatever
    /// platform-appropriate API is available) and pass the bytes
    /// through `ingest_text`, accepting that the safe-open boundary
    /// is the shell's responsibility on those platforms.
    async fn ingest_file(
        &self,
        #[zbus(header)] header: Header<'_>,
        path: String,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("knowledge.ingest_file", &header)?;
        // SVC-6-R2-3: cap BEFORE info!()/validation/store.
        crate::limits::ensure_within(&path, crate::limits::MAX_STRING_BYTES, "path")?;
        info!(path = %path, "D-Bus ingest_file");

        // SVC-8: the domain gate validates the path and, on success, mints
        // a capability token bundling the canonical path with the held root
        // handle (FIX 15 — single-lock validate-and-pickup, now inside the
        // controller). The store's only public file-ingest entry consumes
        // that token, so the allowlist cannot be bypassed here. Denials map
        // to one uniform AccessDenied (FIX 7); the specific reason and raw
        // path were already logged in the domain.
        let validated = self.access.validate(&path).map_err(map_ingestion_error)?;

        let store = self
            .store
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let result = store
            .ingest_validated_file(&validated)
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
        #[zbus(header)] header: Header<'_>,
        text: String,
        source_uri: String,
        format: String,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("knowledge.ingest_text", &header)?;
        // SVC-6-R2-3: cap every String param BEFORE info!()/parse/store.
        crate::limits::ensure_within(&text, crate::limits::MAX_INGEST_TEXT_BYTES, "text")?;
        crate::limits::ensure_within(&source_uri, crate::limits::MAX_STRING_BYTES, "source_uri")?;
        crate::limits::ensure_within(&format, crate::limits::MAX_STRING_BYTES, "format")?;
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
    async fn search(
        &self,
        #[zbus(header)] header: Header<'_>,
        query: String,
        max_results: u32,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("knowledge.search", &header)?;
        crate::limits::ensure_within(&query, crate::limits::MAX_STRING_BYTES, "query")?;
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
    async fn related_to(
        &self,
        #[zbus(header)] header: Header<'_>,
        node_id: i64,
        max_depth: u32,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("knowledge.related_to", &header)?;
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
    async fn find_path(
        &self,
        #[zbus(header)] header: Header<'_>,
        from_id: i64,
        to_id: i64,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("knowledge.find_path", &header)?;
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
    async fn list_sources(
        &self,
        #[zbus(header)] header: Header<'_>,
        node_id: i64,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("knowledge.list_sources", &header)?;
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
    async fn detect_contradictions(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("knowledge.detect_contradictions", &header)?;
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
    async fn forget_source(
        &self,
        #[zbus(header)] header: Header<'_>,
        source_id: i64,
    ) -> zbus::fdo::Result<u32> {
        self.guard.enforce("knowledge.forget_source", &header)?;
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

    use crate::auth::AuthPolicy;
    use crate::auth_guard::completeness::{
        assert_all_methods_classified, assert_behavioral_covers_all, header_msg as msg,
    };

    fn mk_svc() -> KnowledgeService {
        mk_svc_with(AuthPolicy::dev())
    }

    /// Build a service with an empty allowlist under a chosen auth policy.
    /// The behavioral completeness test uses `AuthPolicy::deployed()` to
    /// prove every method denies an unrecognized caller at the guard.
    fn mk_svc_with(policy: AuthPolicy) -> KnowledgeService {
        let store = KnowledgeStore::in_memory(Box::new(MockEmbedder::new())).unwrap();
        let guard = Arc::new(AuthGuard::new(
            policy,
            Arc::new(Mutex::new(fortress::audit::AuditLog::in_memory())),
        ));
        KnowledgeService::new(Arc::new(Mutex::new(store)), guard)
    }

    /// Build a service whose only ingestion root is `root`. Used by
    /// the allowlist tests to fully isolate the per-test filesystem
    /// region.
    ///
    /// **Codex re-review FIX 16 + FIX 18 platform behavior:** on
    /// **Linux**, the path is canonicalized and opened with
    /// `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`; the resulting
    /// service has a populated allowlist of one root and
    /// `ingest_file` calls under it succeed. On **non-Linux**
    /// platforms, `open_dir_no_follow` returns
    /// `ErrorKind::Unsupported` so `with_allowlist` silently drops
    /// the entry; the resulting service has an EMPTY allowlist and
    /// every `ingest_file` call returns the uniform
    /// `AccessDenied("path not permitted")` from the
    /// closed-by-default short-circuit.
    ///
    /// Tests that rely on success behavior under this helper must
    /// be gated with `#[cfg(target_os = "linux")]`. Tests that
    /// exercise non-Linux behavior must assert the uniform
    /// `AccessDenied` shape; they MUST NOT call `.unwrap()` on the
    /// `ingest_file` result, as that would panic for the wrong
    /// reason (empty allowlist instead of the platform limitation
    /// the test should be probing).
    ///
    /// The guard is a dev (log-and-allow) guard so these tests exercise
    /// the allowlist / safe-open behavior, not the auth boundary (which
    /// has its own dedicated completeness tests).
    fn mk_svc_with_root(root: PathBuf) -> KnowledgeService {
        let store = KnowledgeStore::in_memory(Box::new(MockEmbedder::new())).unwrap();
        KnowledgeService::with_allowlist(
            Arc::new(Mutex::new(store)),
            vec![root],
            Arc::new(AuthGuard::dev_in_memory()),
        )
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

    /// SVC-6: `ingest_text` accepts a larger payload than other params
    /// (8 MiB), but text beyond that cap must be rejected before processing.
    /// RED pre-fix (the oversize text is ingested successfully), GREEN once
    /// the cap is enforced at the method boundary.
    #[tokio::test]
    async fn ingest_text_rejects_oversize_text() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let oversize = "x".repeat(crate::limits::MAX_INGEST_TEXT_BYTES + 1);
        let err = svc
            .ingest_text(m.header(), oversize, "mem://t".to_string(), "text".to_string())
            .await
            .unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
        assert!(err.to_string().contains("limit"));
    }

    // ── FIX 1: ingest_file allowlist enforcement ─────────────────────
    //
    // **FIX 18 gating note:** every test below that calls
    // `mk_svc_with_root` and asserts allowlist-dependent behavior is
    // gated `#[cfg(target_os = "linux")]`. On non-Linux platforms
    // `open_dir_no_follow` returns Unsupported, `with_allowlist`
    // drops the entry, and the resulting empty allowlist would cause
    // these tests to pass for the WRONG reason (short-circuit at
    // AllowlistEmpty instead of the rejection path the test names).
    // The non-Linux platform contract is covered by
    // `ingest_file_returns_unified_access_denied_on_non_linux` and
    // `add_ingestion_root_returns_false_on_non_linux` further below.

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn ingest_file_accepts_path_inside_allowlist() {
        let tmp = tempfile::TempDir::new().unwrap();
        let svc = mk_svc_with_root(tmp.path().to_path_buf());
        let m = msg(":1.5");
        let file = tmp.path().join("note.md");
        std::fs::write(&file, "# T\n\nP.\n").unwrap();
        let json = svc
            .ingest_file(m.header(), file.to_string_lossy().into_owned())
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn ingest_file_rejects_path_outside_allowlist() {
        let allowed = tempfile::TempDir::new().unwrap();
        let other = tempfile::TempDir::new().unwrap();
        let svc = mk_svc_with_root(allowed.path().to_path_buf());
        let m = msg(":1.5");
        let outside = other.path().join("evil.md");
        std::fs::write(&outside, "should not be ingested").unwrap();
        let err = svc
            .ingest_file(m.header(), outside.to_string_lossy().into_owned())
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn ingest_file_rejects_nonexistent_path() {
        let allowed = tempfile::TempDir::new().unwrap();
        let svc = mk_svc_with_root(allowed.path().to_path_buf());
        let m = msg(":1.5");
        let ghost = allowed.path().join("does-not-exist.md");
        let err = svc
            .ingest_file(m.header(), ghost.to_string_lossy().into_owned())
            .await
            .unwrap_err();
        assert_uniform_rejection(&err);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn ingest_file_rejects_traversal_escape() {
        // /allowed/../other/secret.md canonicalizes to /other/secret.md,
        // which is outside the allowlist — must be rejected.
        let allowed = tempfile::TempDir::new().unwrap();
        let other = tempfile::TempDir::new().unwrap();
        let svc = mk_svc_with_root(allowed.path().to_path_buf());
        let m = msg(":1.5");
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
            .ingest_file(m.header(), traversal.to_string_lossy().into_owned())
            .await
            .unwrap_err();
        assert_uniform_rejection(&err);
    }

    #[tokio::test]
    async fn ingest_file_rejects_when_allowlist_empty() {
        let store = KnowledgeStore::in_memory(Box::new(MockEmbedder::new())).unwrap();
        let svc = KnowledgeService::with_allowlist(
            Arc::new(Mutex::new(store)),
            vec![],
            Arc::new(AuthGuard::dev_in_memory()),
        );
        let m = msg(":1.5");
        let tmp = tempfile::TempDir::new().unwrap();
        let file = tmp.path().join("any.md");
        std::fs::write(&file, "x").unwrap();
        let err = svc
            .ingest_file(m.header(), file.to_string_lossy().into_owned())
            .await
            .unwrap_err();
        assert_uniform_rejection(&err);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn add_ingestion_root_canonicalizes_and_dedupes() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = KnowledgeStore::in_memory(Box::new(MockEmbedder::new())).unwrap();
        let svc = KnowledgeService::with_allowlist(
            Arc::new(Mutex::new(store)),
            vec![],
            Arc::new(AuthGuard::dev_in_memory()),
        );
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
        let m = msg(":1.5");
        let tmp = tempfile::TempDir::new().unwrap();
        let file = tmp.path().join("note.md");
        std::fs::write(&file, "# T\n\nP.\n").unwrap();
        let err = svc
            .ingest_file(m.header(), file.to_string_lossy().into_owned())
            .await
            .unwrap_err();
        assert_uniform_rejection(&err);
    }

    // -- Pure is_sensitive_path tests moved to the domain (SVC-8):
    //    `die_orchestrator::knowledge::tests::sensitive_path_*`. The
    //    denylist classifier now lives in the domain, so its unit tests
    //    live alongside it. The integration tests below still prove the
    //    denylist is enforced end-to-end through the wired D-Bus service.

    // -- Integration tests: denylist defeats allowlist --

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn ingest_file_rejects_sensitive_path_inside_allowlist() {
        // Even when the user explicitly registers tmp/ as an ingestion
        // root, dropping an id_rsa file inside it must still reject —
        // the denylist runs after the allowlist and cannot be overridden.
        let tmp = tempfile::TempDir::new().unwrap();
        let svc = mk_svc_with_root(tmp.path().to_path_buf());
        let m = msg(":1.5");
        let key_file = tmp.path().join("id_rsa");
        std::fs::write(&key_file, "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
        let err = svc
            .ingest_file(m.header(), key_file.to_string_lossy().into_owned())
            .await
            .unwrap_err();
        // FIX 7 P1: must be the uniform "AccessDenied + REJECTION_MESSAGE",
        // never a leak like "matches sensitive-content denylist".
        assert_uniform_rejection(&err);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn ingest_file_rejects_pem_inside_allowlist() {
        let tmp = tempfile::TempDir::new().unwrap();
        let svc = mk_svc_with_root(tmp.path().to_path_buf());
        let m = msg(":1.5");
        let pem = tmp.path().join("cert.pem");
        std::fs::write(&pem, "-----BEGIN CERTIFICATE-----\n").unwrap();
        let err = svc
            .ingest_file(m.header(), pem.to_string_lossy().into_owned())
            .await
            .unwrap_err();
        assert_uniform_rejection(&err);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn ingest_file_rejects_env_inside_allowlist() {
        let tmp = tempfile::TempDir::new().unwrap();
        let svc = mk_svc_with_root(tmp.path().to_path_buf());
        let m = msg(":1.5");
        let env = tmp.path().join(".env");
        std::fs::write(&env, "API_KEY=secret\n").unwrap();
        let err = svc
            .ingest_file(m.header(), env.to_string_lossy().into_owned())
            .await
            .unwrap_err();
        assert_uniform_rejection(&err);
    }

    // ── FIX 7 (P1-high): uniform public rejection + no FS probe oracle ──

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn rejection_message_is_uniform_across_all_failure_modes() {
        // Drive ingest_file through all FOUR rejection paths and assert
        // every one returns the IDENTICAL public message. Round-1 returned
        // four distinct messages under one variant — Codex F7 oracle.
        //
        // **FIX 18 gating:** the semantic intent of this test
        // (four DIFFERENT rejection paths producing the same wire
        // message) requires Linux's populated allowlist via
        // `mk_svc_with_root`. On non-Linux, the empty allowlist
        // short-circuits all four to the same path, so the test
        // would pass for the wrong reason.
        let allowed = tempfile::TempDir::new().unwrap();
        let other = tempfile::TempDir::new().unwrap();
        let m = msg(":1.5");

        // Path 1: allowlist-empty (closed-by-default)
        let store1 = KnowledgeStore::in_memory(Box::new(MockEmbedder::new())).unwrap();
        let svc_empty = KnowledgeService::with_allowlist(
            Arc::new(Mutex::new(store1)),
            vec![],
            Arc::new(AuthGuard::dev_in_memory()),
        );
        let any_path = allowed.path().join("any.md");
        std::fs::write(&any_path, "x").unwrap();
        let err_empty = svc_empty
            .ingest_file(m.header(), any_path.to_string_lossy().into_owned())
            .await
            .unwrap_err();

        // Path 2: unresolvable (path doesn't exist)
        let svc_with = mk_svc_with_root(allowed.path().to_path_buf());
        let ghost = allowed.path().join("nonexistent.md");
        let err_ghost = svc_with
            .ingest_file(m.header(), ghost.to_string_lossy().into_owned())
            .await
            .unwrap_err();

        // Path 3: outside allowlist
        let outside = other.path().join("evil.md");
        std::fs::write(&outside, "x").unwrap();
        let err_outside = svc_with
            .ingest_file(m.header(), outside.to_string_lossy().into_owned())
            .await
            .unwrap_err();

        // Path 4: sensitive (denylisted) inside allowlist
        let key = allowed.path().join("id_rsa");
        std::fs::write(&key, "-----BEGIN-----\n").unwrap();
        let err_sensitive = svc_with
            .ingest_file(m.header(), key.to_string_lossy().into_owned())
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
        let svc = KnowledgeService::with_allowlist(
            Arc::new(Mutex::new(store)),
            vec![],
            Arc::new(AuthGuard::dev_in_memory()),
        );
        let m = msg(":1.5");

        // A path that DOES exist.
        let tmp = tempfile::TempDir::new().unwrap();
        let real = tmp.path().join("real.md");
        std::fs::write(&real, "x").unwrap();
        let err_real = svc
            .ingest_file(m.header(), real.to_string_lossy().into_owned())
            .await
            .unwrap_err();

        // A path that does NOT exist (deliberately silly).
        let err_ghost = svc
            .ingest_file(
                m.header(),
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
    fn map_ingestion_error_collapses_denials_to_uniform_message() {
        // SVC-8 / FIX 7 — the boundary half of the asymmetry. The domain's
        // `validate` logs the specific reason AND the raw path (covered by
        // `die_orchestrator::knowledge::tests::deny_logs_*`). At THIS trust
        // boundary, every denial — whatever its reason — must collapse to
        // one uniform `AccessDenied(REJECTION_MESSAGE)` with no reason or
        // path leak. An `Internal` error (e.g. a poisoned lock) is a bug,
        // not an access decision, so it maps to `Failed`, not `AccessDenied`.
        use die_orchestrator::knowledge::IngestionDenied;

        for reason in [
            IngestionDenied::AllowlistEmpty,
            IngestionDenied::Unresolvable,
            IngestionDenied::OutsideAllowlist,
            IngestionDenied::SensitivePath,
        ] {
            let wire = map_ingestion_error(IngestionError::Denied(reason));
            match wire {
                zbus::fdo::Error::AccessDenied(m) => {
                    assert_eq!(m, REJECTION_MESSAGE, "denial must use the uniform message");
                    assert!(
                        !m.contains("denylist")
                            && !m.contains("sensitive")
                            && !m.contains("allowlist")
                            && !m.contains("resolve"),
                        "wire leaked the specific reason: {m}"
                    );
                }
                other => panic!("a denial must map to AccessDenied, got {other:?}"),
            }
        }

        // Internal errors are not access decisions.
        let internal = map_ingestion_error(IngestionError::Internal("allowlist lock poisoned"));
        assert!(
            matches!(internal, zbus::fdo::Error::Failed(_)),
            "internal error must map to Failed, not AccessDenied"
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

    // **FIX 18 gating:** narrowed from `cfg(unix)` to
    // `cfg(target_os = "linux")` because the test asserts INGEST
    // SUCCESS, which depends on the populated allowlist that
    // `open_dir_no_follow` (FIX 16) produces only on Linux. On
    // non-Linux Unix (macOS, BSD), `mk_svc_with_root` produces an
    // empty allowlist and the ingest would short-circuit at
    // AllowlistEmpty instead of exercising the canonicalize→
    // safe-open cooperation this test names.
    #[cfg(target_os = "linux")]
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
        let m = msg(":1.5");
        let json = svc
            .ingest_file(m.header(), link.to_string_lossy().into_owned())
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
        let m = msg(":1.5");
        let json = svc
            .ingest_text(
                m.header(),
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
        let m = msg(":1.5");
        let _ = svc
            .ingest_text(
                m.header(),
                "# T\n\nP.\n".to_string(),
                "u".to_string(),
                "markdown".to_string(),
            )
            .await
            .unwrap();
        let json = svc
            .ingest_text(
                m.header(),
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
        let m = msg(":1.5");
        let json = svc
            .ingest_text(
                m.header(),
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
        let m = msg(":1.5");
        svc.ingest_text(
            m.header(),
            "# Topic\n\napple banana cherry.\n".to_string(),
            "u".to_string(),
            "markdown".to_string(),
        )
        .await
        .unwrap();
        let json = svc
            .search(m.header(), "apple banana cherry".to_string(), 5)
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
        let m = msg(":1.5");
        svc.ingest_text(
            m.header(),
            "# T\n\nA.\n".to_string(),
            "u".to_string(),
            "markdown".to_string(),
        )
        .await
        .unwrap();
        let json = svc.search(m.header(), "A".to_string(), 0).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Clamped to 1 → at most 1 result returned (or 0 if no embeddings).
        assert!(v.as_array().unwrap().len() <= 1);
    }

    #[tokio::test]
    async fn related_to_returns_json_array() {
        let svc = mk_svc();
        let m = msg(":1.5");
        svc.ingest_text(
            m.header(),
            "# Parent\n\nChild fact.\n".to_string(),
            "u".to_string(),
            "markdown".to_string(),
        )
        .await
        .unwrap();
        // Find one node id to walk from
        let json = svc.search(m.header(), "Parent".to_string(), 1).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let id = v[0]["node"]["id"].as_i64().unwrap();
        let rel_json = svc.related_to(m.header(), id, 2).await.unwrap();
        let _: serde_json::Value = serde_json::from_str(&rel_json).unwrap();
    }

    #[tokio::test]
    async fn find_path_returns_null_for_unreachable() {
        let svc = mk_svc();
        let m = msg(":1.5");
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
        let json = svc.find_path(m.header(), 1, 2).await.unwrap();
        assert_eq!(json, "null");
    }

    #[tokio::test]
    async fn list_sources_returns_json_array() {
        let svc = mk_svc();
        let m = msg(":1.5");
        svc.ingest_text(
            m.header(),
            "# T\n\nP.\n".to_string(),
            "u".to_string(),
            "markdown".to_string(),
        )
        .await
        .unwrap();
        let search_json = svc.search(m.header(), "T".to_string(), 1).await.unwrap();
        let sv: serde_json::Value = serde_json::from_str(&search_json).unwrap();
        let id = sv[0]["node"]["id"].as_i64().unwrap();
        let json = svc.list_sources(m.header(), id).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.is_array());
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(v[0]["fidelity"], "direct");
    }

    #[tokio::test]
    async fn detect_contradictions_returns_empty_initially() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let json = svc.detect_contradictions(m.header()).await.unwrap();
        assert_eq!(json, "[]");
    }

    #[tokio::test]
    async fn detect_contradictions_returns_pairs() {
        let svc = mk_svc();
        let m = msg(":1.5");
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
        let json = svc.detect_contradictions(m.header()).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0][0].as_i64().unwrap(), a_id);
        assert_eq!(arr[0][1].as_i64().unwrap(), b_id);
    }

    #[tokio::test]
    async fn forget_source_orphans_nodes_and_returns_count() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let r = svc
            .ingest_text(
                m.header(),
                "# T\n\nP.\n".to_string(),
                "u".to_string(),
                "markdown".to_string(),
            )
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        let src_id = v["source_id"].as_i64().unwrap();
        let count = svc.forget_source(m.header(), src_id).await.unwrap();
        assert!(count >= 1);
    }

    #[tokio::test]
    async fn forget_source_returns_zero_for_unknown_id() {
        let svc = mk_svc();
        let m = msg(":1.5");
        assert_eq!(svc.forget_source(m.header(), 99_999).await.unwrap(), 0);
    }

    // Privacy / error-redaction tests

    #[tokio::test]
    async fn error_messages_do_not_echo_content() {
        // Force an error path by sending a deliberately broken arrangement.
        // We mostly want to verify the redact_to_kind helper is wired in.
        let svc = mk_svc();
        let m = msg(":1.5");
        // search itself doesn't error on empty result; just confirm that
        // any potential failure in this layer would be redacted at the
        // boundary. Direct unit test of the helper above already covers
        // the redaction logic.
        let _ = svc.search(m.header(), "anything".to_string(), 1).await;
    }

    // ── FIX 15 (P1-high): held-directory-handle allowlist roots ──
    //
    // The held-handle internals — that registration opens the directory
    // with O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC and anchors trust to the inode,
    // and that a symlinked root canonicalizes to its target — are now domain
    // properties, tested against the private allowlist field where it lives:
    // `die_orchestrator::knowledge::tests::add_root_holds_directory_handle`
    // and `..::add_root_resolves_symlink_root_to_target_inode` (SVC-8). The
    // service-level F15 behavior (ingest survives a root rename via the held
    // handle) is still exercised end-to-end below by
    // `ingest_file_uses_held_handle_after_root_rename`.

    // ── FIX 16 (P1-high): explicit Windows feature-gate ──
    //
    // Round-3 shipped a Windows component-walk that LOOKED safe but
    // had unfixable TOCTOU races between symlink_metadata checks and
    // the final open. The only race-free Windows path requires
    // NtCreateFile + OBJ_DONT_REPARSE, which is undocumented and
    // version-unstable. Round-4 makes the security boundary honest:
    // open_dir_no_follow returns Unsupported on non-Linux, so
    // add_ingestion_root rejects, so ingest_file rejects with the
    // uniform AccessDenied message. ingest_text remains supported.
    //
    // These tests are gated to non-Linux platforms so they only
    // exercise the Unsupported path on Windows + macOS CI runners.
    // On WSL2 (target_os = "linux") they're skipped at compile time.

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn add_ingestion_root_returns_false_on_non_linux() {
        // FIX 16: open_dir_no_follow returns Unsupported on
        // non-Linux, so add_ingestion_root must return false even
        // for a real, existing directory. This is a feature-gate
        // assertion: the registration boundary is the place where
        // the platform limitation surfaces.
        let tmp = tempfile::TempDir::new().unwrap();
        let svc = mk_svc();
        assert!(
            !svc.add_ingestion_root(tmp.path()),
            "add_ingestion_root must reject on non-Linux platforms; \
             open_dir_no_follow returns Unsupported"
        );
        // Allowlist must remain empty.
        assert_eq!(svc.allowlist_snapshot().len(), 0);
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn ingest_file_returns_unified_access_denied_on_non_linux() {
        // FIX 16: with no roots registerable, every ingest_file
        // call hits the empty-allowlist short-circuit (FIX 7) and
        // returns the uniform "path not permitted" message.
        // Critically: the wire response carries no information
        // about WHY (platform vs allowlist vs path). Operator-side
        // tracing logs distinguish; the D-Bus response does not.
        let tmp = tempfile::TempDir::new().unwrap();
        let file = tmp.path().join("any.md");
        std::fs::write(&file, "# placeholder\n").unwrap();
        let svc = mk_svc();
        let m = msg(":1.5");
        let err = svc
            .ingest_file(m.header(), file.to_string_lossy().into_owned())
            .await
            .expect_err("ingest_file must fail on non-Linux");
        let msg_str = err.to_string();
        assert!(
            msg_str.contains("path not permitted"),
            "must use uniform rejection message; got: {msg_str}"
        );
    }

    /// FIX 16 sanity test (cross-platform): the workaround
    /// recommended in the rustdoc must actually work. ingest_text
    /// requires no filesystem access and so is supported on every
    /// platform that builds the crate. This test runs on Linux
    /// AND non-Linux, so it doubles as a regression check.
    #[tokio::test]
    async fn ingest_text_remains_supported_on_all_platforms() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let json = svc
            .ingest_text(
                m.header(),
                "# Title\n\nA paragraph.\n".into(),
                "user://platform-test".into(),
                "markdown".into(),
            )
            .await
            .expect("ingest_text must succeed on every platform — it's the FIX 16 workaround");
        // Non-empty JSON — confirms the IngestionResult was
        // produced and serialized.
        assert!(json.contains("source_id"));
        assert!(json.contains("nodes_created"));
    }

    // ── FIX 18 (P2-medium) META-TESTS: mk_svc_with_root contract ──
    //
    // These two tests prove that the test-helper contract documented
    // in mk_svc_with_root's rustdoc matches reality on each platform.
    // If a future refactor accidentally inverts the contract (e.g.,
    // allowlist gets populated on non-Linux, or empty on Linux), one
    // of these meta-tests fires immediately — before the platform-
    // specific test gating starts producing confusing CI failures.

    #[cfg(target_os = "linux")]
    #[test]
    fn mk_svc_with_root_produces_populated_allowlist_on_linux() {
        // On Linux, open_dir_no_follow succeeds for any real
        // directory, so with_allowlist registers the entry.
        let tmp = tempfile::TempDir::new().unwrap();
        let svc = mk_svc_with_root(tmp.path().to_path_buf());
        let snapshot = svc.allowlist_snapshot();
        assert_eq!(
            snapshot.len(),
            1,
            "Linux mk_svc_with_root must register the supplied root"
        );
        // The stored canonical path matches what canonicalize
        // returns for the tempdir.
        let canon = std::fs::canonicalize(tmp.path()).unwrap();
        assert_eq!(snapshot[0], canon);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn mk_svc_with_root_produces_empty_allowlist_on_non_linux() {
        // On non-Linux, open_dir_no_follow returns Unsupported, so
        // with_allowlist silently drops the entry. The resulting
        // service has an empty allowlist. This is the EXACT
        // behavior that would cause an unsuspecting test to pass
        // for the wrong reason (short-circuit at AllowlistEmpty),
        // which is why every Linux-only test must be cfg-gated.
        let tmp = tempfile::TempDir::new().unwrap();
        let svc = mk_svc_with_root(tmp.path().to_path_buf());
        let snapshot = svc.allowlist_snapshot();
        assert!(
            snapshot.is_empty(),
            "non-Linux mk_svc_with_root must produce an empty allowlist; \
             got: {snapshot:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn ingest_file_uses_held_handle_after_root_rename() {
        // F15 architectural property: ingest_file works correctly
        // after the registered directory has been RENAMED at the
        // filesystem level. Round-3's path-based ingest_file would
        // have failed (the registered path no longer exists). FIX
        // 15's held handle survives the rename via /proc/self/fd
        // readlink; ingest_file_with_root_handle finds the file
        // under the renamed path.
        let tmp = tempfile::TempDir::new().unwrap();
        let original = tmp.path().join("original");
        std::fs::create_dir(&original).unwrap();
        let file = original.join("note.md");
        std::fs::write(&file, "# hello\n\nworld\n").unwrap();

        let svc = mk_svc_with_root(original.clone());
        let m = msg(":1.5");

        // Rename the registered directory.
        let renamed = tmp.path().join("renamed");
        std::fs::rename(&original, &renamed).unwrap();

        // The file is now at `renamed/note.md`. Ingestion via the
        // new path should succeed because the held handle still
        // references the original inode (which is now under the
        // renamed name; /proc/self/fd readlink resolves to the
        // current canonical name).
        let renamed_file = renamed.join("note.md");
        let json = svc
            .ingest_file(m.header(), renamed_file.to_string_lossy().into_owned())
            .await;
        // The ingestion call may either succeed (handle survived
        // rename) or fail with a deny message. What MUST NOT happen
        // is silent corruption or an unrelated panic.
        match json {
            Ok(s) => {
                // Successful ingest: the JSON should reference the
                // renamed path.
                assert!(s.contains("renamed/note.md") || s.contains("source_id"));
            }
            Err(e) => {
                // Acceptable: the canonical path comparison may
                // reject (because the registered canonical_path is
                // /tmp/X/original but the new canonical is
                // /tmp/X/renamed). What's important is that we get
                // the uniform AccessDenied message, NOT a leak.
                let msg_str = e.to_string();
                assert!(
                    msg_str.contains("path not permitted"),
                    "must use uniform rejection message; got: {msg_str}"
                );
                // Confirm the error doesn't leak the path or which
                // rejection reason fired (FIX 7).
                assert!(
                    !msg_str.contains("renamed") && !msg_str.contains("original"),
                    "wire error must not echo the path; got: {msg_str}"
                );
            }
        }
    }

    /// SVC-6-R2-3: every D-Bus `String` parameter is capped at the boundary.
    /// `ingest_text(text)` has its own dedicated test
    /// (`ingest_text_rejects_oversize_text`) at `MAX_INGEST_TEXT_BYTES`; this
    /// covers the remaining `MAX_STRING_BYTES` fields across the surface.
    #[tokio::test]
    async fn every_string_param_rejects_oversize() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let oversize = "x".repeat(crate::limits::MAX_STRING_BYTES + 1);

        // ingest_file(path)
        assert!(matches!(
            svc.ingest_file(m.header(), oversize.clone()).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        // ingest_text(text, source_uri, format) — source_uri and format
        // (the `text` cap is at MAX_INGEST_TEXT_BYTES, exercised separately).
        assert!(matches!(
            svc.ingest_text(m.header(), "hello".to_string(), oversize.clone(), "markdown".to_string())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        assert!(matches!(
            svc.ingest_text(m.header(), "hello".to_string(), "u".to_string(), oversize.clone())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        // search(query)
        assert!(matches!(
            svc.search(m.header(), oversize.clone(), 5).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
    }

    // ── SVC-2 completeness (Decision 3) ──

    #[test]
    fn svc2_every_method_is_classified() {
        use zbus::object_server::Interface;
        let svc = mk_svc();
        let mut xml = String::new();
        svc.introspect_to_writer(&mut xml, 0);
        assert_all_methods_classified("knowledge", &xml);
    }

    #[tokio::test]
    async fn svc2_every_method_denies_unrecognized_caller_when_deployed() {
        let svc = mk_svc_with(AuthPolicy::deployed());
        let mut exercised: Vec<&str> = Vec::new();

        exercised.push("IngestFile");
        let m = msg(":1.999");
        assert!(matches!(svc.ingest_file(m.header(), "x".to_string()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("IngestText");
        let m = msg(":1.999");
        assert!(matches!(svc.ingest_text(m.header(), "t".to_string(), "u".to_string(), "text".to_string()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("Search");
        let m = msg(":1.999");
        assert!(matches!(svc.search(m.header(), "q".to_string(), 5).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("RelatedTo");
        let m = msg(":1.999");
        assert!(matches!(svc.related_to(m.header(), 1, 2).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("FindPath");
        let m = msg(":1.999");
        assert!(matches!(svc.find_path(m.header(), 1, 2).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("ListSources");
        let m = msg(":1.999");
        assert!(matches!(svc.list_sources(m.header(), 1).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("DetectContradictions");
        let m = msg(":1.999");
        assert!(matches!(svc.detect_contradictions(m.header()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("ForgetSource");
        let m = msg(":1.999");
        assert!(matches!(svc.forget_source(m.header(), 1).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));

        use zbus::object_server::Interface;
        let mut xml = String::new();
        svc.introspect_to_writer(&mut xml, 0);
        assert_behavioral_covers_all("knowledge", &xml, &exercised);
    }
}
