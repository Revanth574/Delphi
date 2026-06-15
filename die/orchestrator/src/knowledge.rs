// SPDX-License-Identifier: MIT

//! Knowledge synthesis engine — capability #17.
//!
//! Builds a personal knowledge graph from documents the user reads, notes
//! they write, conversations with Delphi (in a future task), and web
//! research output. Queryable: "what do I know about X?" returns relevant
//! nodes with **source citations** — every claim traceable to its origin.
//!
//! # Architectural principle: associative memory without confabulation
//!
//! Human associative memory is the inspiration: ideas connected by meaning,
//! not location. But the human brain *also* confabulates — it reconstructs
//! plausible details to fill gaps, biases recall toward emotional content,
//! and forgets selectively.
//!
//! This graph deliberately keeps the associative-retrieval property
//! (semantic search over node content) while excluding confabulation by
//! construction:
//!
//! - **Every node has at least one [`Source`].** A node without a source is
//!   not permitted at the API level; the constructors reject empty source
//!   lists. That alone makes it impossible to "remember" something without
//!   provenance.
//! - **Sources carry a [`Fidelity`] tag.** Consumers know whether a claim
//!   came from a `Direct`-fidelity SQLite read of the user's own notes, a
//!   `Subprocess`-fidelity HTML scrape, or an `Unavailable`-fidelity
//!   placeholder.
//! - **Sources also carry a content hash.** Re-ingesting the same content
//!   doesn't create duplicate nodes; ingesting changed content produces a
//!   *new* source row so the user can see which version of the file each
//!   claim came from.
//! - **Edges carry their own source.** A relationship "X relates to Y" is
//!   itself a claim that must trace back to wherever it was asserted —
//!   typically the same document where X and Y appeared together.
//!
//! # Fidelity levels supported (per Iron Law #13)
//!
//! ## Markdown / plain text ingestion
//!
//! 1. **`pulldown-cmark` AST** (preferred, current) — `Fidelity::Direct`.
//!    Pure-Rust CommonMark parser; gives heading hierarchy, paragraphs,
//!    code blocks, and link text. Used by [`parse_markdown_to_concepts`].
//! 2. **Plain-text line splitting** (declared, fallback) — `Fidelity::Direct`
//!    for the bytes themselves but lossy on structure. Used as fallback
//!    when pulldown-cmark fails or for `.txt` files.
//!
//! ## HTML / web content ingestion
//!
//! 1. **JSON-LD / OpenGraph extraction** (declared, future augmentation) —
//!    when present, would yield `Fidelity::Direct` semantic data.
//! 2. **Readability-mode extraction** (declared, future) — `Fidelity::Subprocess`
//!    quality if running an external readability tool.
//! 3. **`scraper` DOM parsing** (preferred, current) — `Fidelity::Direct`
//!    for the bytes; pure-Rust html5ever-backed parser. Used by
//!    [`parse_html_to_concepts`].
//! 4. **Plain-text tag stripping** (declared, last resort) — `Fidelity::Direct`
//!    on bytes but loses everything structural.
//!
//! ## PDF ingestion
//!
//! 1. **Tagged PDF structure** (declared, future) — `Fidelity::Direct` if
//!    the PDF is tagged; requires lopdf or similar. Not implemented in
//!    this task — too heavy a dep for our current needs.
//! 2. **`pdf-extract` Rust crate** (declared, future) — `Fidelity::Subprocess`
//!    in spirit (it shells out to a wrapped library); not added to the
//!    workspace yet.
//! 3. **`pdftotext` (poppler) subprocess** (declared, future).
//! 4. **OCR via tesseract** (declared, future, opt-in).
//!
//! On the current dev system, PDF ingestion returns `Fidelity::Unavailable`
//! and the format-detector advises that no extractor is present. Code is
//! structured so the levels can be added without changing the public API.
//!
//! ## DOCX ingestion
//!
//! 1. **Direct ZIP+XML parsing** (declared, future) — `Fidelity::Direct`
//!    once we add a parser. Same future-work treatment as PDF.
//!
//! ## Conversation history (self-ingestion, future task)
//!
//! 1. **Direct read from `crate::conversation::ConversationStore`**
//!    (declared, wired in a future session) — `Fidelity::Direct`. We're
//!    reading our own SQLite, no external interpretation involved.
//!
//! ## Embeddings
//!
//! 1. **Local model via candle / sentence-transformers** (declared, future) —
//!    `Fidelity::Direct` privacy-wise (computation never leaves the device).
//! 2. **Cloud embedding API behind ZKQP** (current, opt-in via feature
//!    flag — disabled by default) — `Fidelity::Subprocess` because the
//!    request flows through a sanitization step in
//!    [`fortress::zkqp::QuerySanitizer`] before transmission. **MUST NOT**
//!    be enabled without explicit user action; cloud transmission of user
//!    document content is a privacy decision the user owns.
//! 3. **Cached embedding from prior ingestion** (current) — `Fidelity::Direct`
//!    if the cached source was Direct, otherwise propagated from the source.
//! 4. **Mock deterministic embedding** (current, tests-only) —
//!    `Fidelity::Subprocess` (deterministic but not semantically
//!    meaningful). Used by [`MockEmbedder`] for unit tests.
//!
//! When no embedder is available, ingestion still proceeds; affected nodes
//! simply lack vector entries and are excluded from semantic search results.
//! This is the graceful-degradation path: text-graph queries (related-to,
//! find-path, contradiction detection) continue to work without embeddings.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::OrchestratorError;
use crate::environment::Fidelity;

/// Default embedding dimension for the [`MockEmbedder`] and as the canonical
/// dimension when no other constraint exists.
pub const DEFAULT_EMBEDDING_DIMENSION: usize = 32;

/// Maximum bytes accepted for a single ingestion — file or in-memory text
/// (ORCH-R1-04, live ingestion DoS). Enforced at every public ingest entry;
/// the file-read path additionally bounds the read with [`std::io::Read::take`]
/// so a hostile or streaming file (e.g. a special file that reports length 0
/// yet streams unbounded) can never be slurped whole into memory. 10 MiB
/// matches the workspace content cap (`workspace::validator::MAX_TOTAL_CONTENT_BYTES`).
pub const MAX_INGEST_BYTES: usize = 10 * 1024 * 1024;

/// Maximum number of concepts (graph nodes) a single document may yield
/// (ORCH-R1-04). A document that parses to more than this is rejected before
/// any node is created, rather than flooding the graph.
pub const MAX_CONCEPTS: usize = 50_000;

/// Maximum byte length of a single concept's text — one graph node
/// (ORCH-R1-04). A concept longer than this is rejected rather than stored as
/// an unbounded node.
pub const MAX_CONCEPT_TEXT_LEN: usize = 64 * 1024;

/// The single sanctioned byte-cap guard for ingestion (ORCH-R1-04). EVERY
/// ingest entry routes its size check through this one function, so the cap
/// value and the rejection cannot drift across entries — the weakest entry is
/// the DoS vector (the SVC-2 completeness lesson: one shared guard, not per-site
/// copies). `len` is the in-memory byte length; detail goes to tracing and the
/// typed error carries no caller content (SVC-9 / R1-07).
fn enforce_ingest_byte_cap(len: usize, uri: &str) -> Result<(), OrchestratorError> {
    if len > MAX_INGEST_BYTES {
        warn!(len, cap = MAX_INGEST_BYTES, uri, "ingestion input exceeds byte cap; rejected");
        return Err(OrchestratorError::Validation {
            domain: "knowledge",
            field: "content",
            reason: "exceeds maximum ingestion size",
        });
    }
    Ok(())
}

/// The single sanctioned concept-explosion guard for ingestion (ORCH-R1-04):
/// bounds the concept count and any single concept's text length, so a hostile
/// document cannot flood the graph or store an unbounded node. Called once, at
/// the sole parse site (`ingest_text`); a helper so the caps stay greppable and
/// testable alongside the byte-cap guard.
fn enforce_concept_caps(concepts: &[RawConcept], uri: &str) -> Result<(), OrchestratorError> {
    if concepts.len() > MAX_CONCEPTS {
        warn!(
            count = concepts.len(),
            cap = MAX_CONCEPTS,
            uri,
            "ingestion produced too many concepts; rejected"
        );
        return Err(OrchestratorError::Validation {
            domain: "knowledge",
            field: "concept_count",
            reason: "document produced too many concepts",
        });
    }
    if let Some(oversize) = concepts.iter().find(|c| c.text.len() > MAX_CONCEPT_TEXT_LEN) {
        warn!(
            len = oversize.text.len(),
            cap = MAX_CONCEPT_TEXT_LEN,
            uri,
            "ingestion concept exceeds max length; rejected"
        );
        return Err(OrchestratorError::Validation {
            domain: "knowledge",
            field: "concept_text",
            reason: "a concept exceeds maximum length",
        });
    }
    Ok(())
}

/// Schema for the knowledge SQLite database. Applied idempotently on every
/// open via `IF NOT EXISTS`.
///
/// **Codex review FIX 5 (P2):** the source uniqueness key is
/// `(uri, content_hash, format)` — NOT `(uri, content_hash)`. The earlier
/// 2-column key let a caller's first ingestion of a `(uri, content)` pair
/// under a wrong format (e.g. `pdf` → `Fidelity::Unavailable`, no nodes)
/// silently shadow a corrected later re-ingest under the right format
/// (e.g. `markdown` → `Fidelity::Direct`, with parsed nodes). The third
/// column ensures the corrected re-ingest creates a new source row with
/// its own fidelity, leaving the bad row to be `forget_source`'d
/// independently. Same `(uri, content, format)` triple is still
/// idempotent — the intended semantic for repeat ingestion.
///
/// **Codex re-review FIX 12 (P1-high):** the `PRAGMA foreign_keys = ON`
/// statement is **NOT** part of this schema DDL. SQLite foreign-key
/// enforcement is a per-connection setting (and defaults to OFF), not a
/// per-database setting. Putting the pragma here only enabled FKs on the
/// connection that first ran the schema; every reopen and every new
/// background-worker connection silently inherited the default-OFF
/// state. The pragma now lives in [`KnowledgeStore::init_schema`] which
/// runs on every `Connection::open` boundary.
const SCHEMA_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_type TEXT NOT NULL,
    uri TEXT NOT NULL,
    ingested_at_unix INTEGER NOT NULL,
    fidelity TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    format TEXT NOT NULL,
    UNIQUE(uri, content_hash, format)
);

CREATE INDEX IF NOT EXISTS idx_sources_uri ON sources(uri);
CREATE INDEX IF NOT EXISTS idx_sources_format ON sources(format);
CREATE INDEX IF NOT EXISTS idx_sources_ingested ON sources(ingested_at_unix);

CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    node_type TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    last_accessed_unix INTEGER NOT NULL,
    access_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_nodes_accessed ON nodes(last_accessed_unix);

CREATE TABLE IF NOT EXISTS node_sources (
    node_id INTEGER NOT NULL,
    source_id INTEGER NOT NULL,
    PRIMARY KEY(node_id, source_id),
    FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY(source_id) REFERENCES sources(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_node INTEGER NOT NULL,
    to_node INTEGER NOT NULL,
    relation TEXT NOT NULL,
    confidence REAL NOT NULL,
    source_id INTEGER NOT NULL,
    created_at_unix INTEGER NOT NULL,
    FOREIGN KEY(from_node) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY(to_node) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY(source_id) REFERENCES sources(id) ON DELETE CASCADE,
    CHECK(confidence >= 0.0 AND confidence <= 1.0),
    CHECK(from_node != to_node)
);

CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_node);
CREATE INDEX IF NOT EXISTS idx_edges_to ON edges(to_node);
CREATE INDEX IF NOT EXISTS idx_edges_relation ON edges(relation);

CREATE TABLE IF NOT EXISTS embeddings (
    node_id INTEGER PRIMARY KEY,
    dimension INTEGER NOT NULL,
    vector BLOB NOT NULL,
    fidelity TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
);
"#;

/// **Codex re-review FIX 9 (P2-medium):** version-tracked schema epoch.
///
/// The `schema_version` table records every applied schema epoch as a
/// row whose primary key is the integer version. The highest version is
/// the current state. New databases land at [`CURRENT_SCHEMA_VERSION`]
/// in a single fresh install; existing databases from earlier epochs
/// step up via migration functions (e.g. [`migrate_epoch_1_to_2`]).
///
/// A future epoch ≥ 3 will add another `migrate_epoch_2_to_3` and
/// extend the match arm in [`KnowledgeStore::init_schema`]. Don't
/// generalize prematurely — a one-shot per-epoch function is easier to
/// reason about than a migration framework.
const SCHEMA_VERSION_TABLE_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);
"#;

/// Current schema epoch. Bumped whenever the schema changes in a way
/// existing databases must catch up to.
///
/// - Epoch 1: round-1 layout (commits bd554bf / 2b3ca3e), with
///   `UNIQUE(uri, content_hash)` on `sources`.
/// - Epoch 2: post-FIX-5 layout (commit c3147b9), with
///   `UNIQUE(uri, content_hash, format)` on `sources`.
const CURRENT_SCHEMA_VERSION: i64 = 2;

/// **Codex re-review FIX 20 (round 7) + FIX 24 (round 8):** maximum
/// attempts the [`KnowledgeStore::open`] retry loop makes before
/// surfacing [`OrchestratorError::TransientLock`] to the caller.
///
/// The retry only fires on `TransientLock` (per F21). Any other
/// `OrchestratorError` short-circuits immediately. The retry loop's
/// guard is `attempt < MAX_OPEN_ATTEMPTS - 1`, so this constant
/// counts attempts (initial + retries), and the number of
/// inter-attempt sleeps is `MAX_OPEN_ATTEMPTS - 1`.
///
/// **F24 (round 8):** previously 5, which gave only 4 inter-attempt
/// sleeps (100, 200, 400, 800 ms) and made the documented final
/// 1600 ms sleep — plus [`MAX_BACKOFF_MS`] — unreachable. Bumped to
/// 6 so the documented `100 → 200 → 400 → 800 → 1600 ms` sequence
/// fully fires. With the default 5 s per-attempt `busy_timeout` plus
/// the exponential backoff between attempts (100 + 200 + 400 + 800 +
/// 1600 ms = 3.1 s total inter-attempt sleep), worst-case opener
/// latency under sustained contention is `6 × 5 s + 3.1 s ≈ 33 s`
/// before a typed `TransientLock` reaches the caller. Callers still
/// get a typed error they can interpret rather than a string-matched
/// lockup.
pub const MAX_OPEN_ATTEMPTS: usize = 6;

/// **Codex re-review FIX 20 (round 7):** initial backoff for the
/// retry-with-backoff loop in [`KnowledgeStore::open`]. Doubled each
/// retry attempt (100 → 200 → 400 → 800 → 1600) and capped at
/// [`MAX_BACKOFF_MS`] to keep total inter-attempt sleep bounded.
pub const INITIAL_BACKOFF_MS: u64 = 100;

/// **Codex re-review FIX 20 (round 7):** ceiling for the exponentially-
/// growing backoff. Bound on inter-attempt sleep so a long-stuck
/// database surfaces `TransientLock` in finite time rather than
/// growing the per-retry sleep unboundedly.
pub const MAX_BACKOFF_MS: u64 = 2_000;

// ────────────────────────────────────────────────────────────────────
// Type aliases + enums
// ────────────────────────────────────────────────────────────────────

pub type NodeId = i64;
pub type EdgeId = i64;
pub type SourceId = i64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeType {
    Concept,
    Fact,
    Person,
    Project,
    Opinion,
}

impl NodeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeType::Concept => "concept",
            NodeType::Fact => "fact",
            NodeType::Person => "person",
            NodeType::Project => "project",
            NodeType::Opinion => "opinion",
        }
    }
}

impl FromStr for NodeType {
    type Err = OrchestratorError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "concept" => Ok(NodeType::Concept),
            "fact" => Ok(NodeType::Fact),
            "person" => Ok(NodeType::Person),
            "project" => Ok(NodeType::Project),
            "opinion" => Ok(NodeType::Opinion),
            other => Err(OrchestratorError::Planning(format!(
                "unknown node type: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeRelation {
    RelatesTo,
    Contradicts,
    Supports,
    PartOf,
    DependsOn,
    CreatedBy,
    SimilarTo,
}

impl EdgeRelation {
    pub fn as_str(&self) -> &'static str {
        match self {
            EdgeRelation::RelatesTo => "relates_to",
            EdgeRelation::Contradicts => "contradicts",
            EdgeRelation::Supports => "supports",
            EdgeRelation::PartOf => "part_of",
            EdgeRelation::DependsOn => "depends_on",
            EdgeRelation::CreatedBy => "created_by",
            EdgeRelation::SimilarTo => "similar_to",
        }
    }

    /// Edges of these relations must form a DAG. Cycle prevention runs
    /// before insertion.
    pub fn is_acyclic(&self) -> bool {
        matches!(self, EdgeRelation::PartOf | EdgeRelation::DependsOn)
    }
}

impl FromStr for EdgeRelation {
    type Err = OrchestratorError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "relates_to" => Ok(EdgeRelation::RelatesTo),
            "contradicts" => Ok(EdgeRelation::Contradicts),
            "supports" => Ok(EdgeRelation::Supports),
            "part_of" => Ok(EdgeRelation::PartOf),
            "depends_on" => Ok(EdgeRelation::DependsOn),
            "created_by" => Ok(EdgeRelation::CreatedBy),
            "similar_to" => Ok(EdgeRelation::SimilarTo),
            other => Err(OrchestratorError::Planning(format!(
                "unknown edge relation: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceType {
    LocalFile,
    WebPage,
    Conversation,
    UserAssertion,
}

impl SourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SourceType::LocalFile => "local_file",
            SourceType::WebPage => "web_page",
            SourceType::Conversation => "conversation",
            SourceType::UserAssertion => "user_assertion",
        }
    }
}

impl FromStr for SourceType {
    type Err = OrchestratorError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "local_file" => Ok(SourceType::LocalFile),
            "web_page" => Ok(SourceType::WebPage),
            "conversation" => Ok(SourceType::Conversation),
            "user_assertion" => Ok(SourceType::UserAssertion),
            other => Err(OrchestratorError::Planning(format!(
                "unknown source type: {other}"
            ))),
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Domain structs
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Source {
    pub id: SourceId,
    pub source_type: SourceType,
    pub uri: String,
    pub ingested_at: DateTime<Utc>,
    pub fidelity: Fidelity,
    pub content_hash: String,
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnowledgeNode {
    pub id: NodeId,
    pub content: String,
    pub node_type: NodeType,
    pub source_ids: Vec<SourceId>,
    pub created_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
    pub access_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnowledgeEdge {
    pub id: EdgeId,
    pub from_id: NodeId,
    pub to_id: NodeId,
    pub relation: EdgeRelation,
    pub confidence: f32,
    pub source_id: SourceId,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeWithSources {
    pub node: KnowledgeNode,
    pub sources: Vec<Source>,
    pub similarity_score: Option<f32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelatedNode {
    pub node: KnowledgeNode,
    pub via_relation: EdgeRelation,
    pub depth: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct IngestionResult {
    pub source_id: SourceId,
    pub nodes_created: u32,
    pub edges_created: u32,
    pub fidelity_used: Fidelity,
    pub format_detected: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RawConcept {
    pub text: String,
    pub node_type: NodeType,
    pub depth: u32,
    pub parent_text: Option<String>,
}

// ────────────────────────────────────────────────────────────────────
// Embedder trait + implementations
// ────────────────────────────────────────────────────────────────────

/// Trait for any embedding backend. Implementors return a vector AND the
/// fidelity at which it was produced — `Direct` for a local model,
/// `Subprocess` for a sanitized cloud call, `Unavailable` when no model
/// is reachable.
pub trait Embedder: Send + Sync {
    fn embed(&self, text: &str) -> Result<(Vec<f32>, Fidelity), OrchestratorError>;
    fn dimension(&self) -> usize;
}

/// Deterministic hash-based embedder. Not semantically meaningful — same
/// text produces the same vector, similar text produces unrelated vectors.
/// Used only by tests where we want reproducible behavior.
pub struct MockEmbedder {
    dimension: usize,
}

impl MockEmbedder {
    pub fn new() -> Self {
        Self {
            dimension: DEFAULT_EMBEDDING_DIMENSION,
        }
    }

    pub fn with_dimension(dimension: usize) -> Self {
        Self {
            dimension: dimension.max(1),
        }
    }
}

impl Default for MockEmbedder {
    fn default() -> Self {
        Self::new()
    }
}

impl Embedder for MockEmbedder {
    fn embed(&self, text: &str) -> Result<(Vec<f32>, Fidelity), OrchestratorError> {
        // SHA-256 of the input, expanded into a vector of f32s in [-1, 1].
        // Same input → same output (deterministic). Sufficient for testing
        // storage + similarity round-trips, not for real semantic search.
        let mut hasher = Sha256::new();
        hasher.update(text.as_bytes());
        let mut seed = hasher.finalize().to_vec();
        // Stretch to required length via repeat-hashing.
        while seed.len() < self.dimension * 4 {
            let mut h = Sha256::new();
            h.update(&seed);
            seed.extend_from_slice(&h.finalize());
        }
        let mut vector = Vec::with_capacity(self.dimension);
        for chunk in seed.chunks_exact(4).take(self.dimension) {
            let bits = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            // Map u32 → f32 in [-1, 1].
            let v = (bits as f32 / u32::MAX as f32) * 2.0 - 1.0;
            vector.push(v);
        }
        Ok((vector, Fidelity::Subprocess))
    }

    fn dimension(&self) -> usize {
        self.dimension
    }
}

/// STUB (not built): local model-based embedder. `embed()` returns an empty
/// vector with `Fidelity::Unavailable` when no model file is configured. To be
/// replaced with a real candle-based embedder in a future task.
pub struct LocalEmbedder {
    model_path: Option<PathBuf>,
    dimension: usize,
}

impl LocalEmbedder {
    pub fn unavailable() -> Self {
        Self {
            model_path: None,
            dimension: DEFAULT_EMBEDDING_DIMENSION,
        }
    }

    pub fn with_model(model_path: PathBuf, dimension: usize) -> Self {
        Self {
            model_path: Some(model_path),
            dimension: dimension.max(1),
        }
    }

    pub fn has_model(&self) -> bool {
        self.model_path.as_ref().is_some_and(|p| p.exists())
    }
}

impl Default for LocalEmbedder {
    fn default() -> Self {
        Self::unavailable()
    }
}

impl Embedder for LocalEmbedder {
    fn embed(&self, _text: &str) -> Result<(Vec<f32>, Fidelity), OrchestratorError> {
        // Real local-model inference is a future task. Until then, return
        // an empty vector with Unavailable fidelity so callers can degrade.
        if self.has_model() {
            // Future: call into candle here.
            return Err(OrchestratorError::Planning(
                "local embedder model loaded but inference not yet implemented".to_string(),
            ));
        }
        Ok((Vec::new(), Fidelity::Unavailable))
    }

    fn dimension(&self) -> usize {
        self.dimension
    }
}

/// Cloud embedder gated behind an explicit feature flag. Sends content to
/// an external API only after passing through [`fortress::zkqp::QuerySanitizer`]
/// for PII redaction.
///
/// **Default state: disabled.** Construction with `enabled = false` returns
/// `Fidelity::Unavailable` from every call. Enabling requires explicit
/// user opt-in (a setting the shell exposes; not auto-flipped by code).
pub struct CloudEmbedder {
    enabled: bool,
    sanitizer: Arc<fortress::zkqp::QuerySanitizer>,
    dimension: usize,
}

impl CloudEmbedder {
    /// Construct the disabled stub. This is the safe default; enabling
    /// requires explicit user opt-in via [`enable`](Self::enable).
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            sanitizer: Arc::new(fortress::zkqp::QuerySanitizer::new()),
            dimension: DEFAULT_EMBEDDING_DIMENSION,
        }
    }

    /// Construct an enabled cloud embedder with a fresh sanitizer.
    /// Real cloud transmission is still a future task — for now this just
    /// proves the ZKQP integration path is wired correctly.
    pub fn enabled(dimension: usize) -> Self {
        Self {
            enabled: true,
            sanitizer: Arc::new(fortress::zkqp::QuerySanitizer::new()),
            dimension: dimension.max(1),
        }
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }

    pub fn disable(&mut self) {
        self.enabled = false;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Number of times sanitization has been invoked — used by tests to
    /// verify that cloud transmission goes through ZKQP.
    pub fn sanitizer(&self) -> &fortress::zkqp::QuerySanitizer {
        &self.sanitizer
    }
}

impl Embedder for CloudEmbedder {
    fn embed(&self, text: &str) -> Result<(Vec<f32>, Fidelity), OrchestratorError> {
        if !self.enabled {
            // Strict default: never call out without explicit user opt-in.
            return Ok((Vec::new(), Fidelity::Unavailable));
        }
        // CRITICAL: sanitize BEFORE any imagined transmission. This is the
        // ZKQP gate that CLAUDE.md §10 mandates. The `safe_to_sanitize`
        // flag is the scorer's verdict on whether the privacy score is low
        // enough for autonomous transmission; if it's false, the caller
        // (or human) must explicitly confirm before transmitting.
        let sanitized = self.sanitizer.sanitize(text);
        if sanitized.requires_confirmation() {
            return Err(OrchestratorError::Planning(format!(
                "cloud embedding refused: privacy score {} requires user confirmation",
                sanitized.score().total
            )));
        }
        // Real network call happens here in a future task. For now return
        // an empty vector tagged Subprocess to indicate the pathway exists.
        // SVC-1 NOTE: when the real embedding network call lands, this is a
        // SECOND cloud-egress path (alongside CloudEgressGateway for
        // completions) and should get the same structural capability gate —
        // today it sanitizes correctly but the egress is not yet
        // type-enforced because there is no transmission yet.
        debug!(
            sanitized_len = sanitized.sanitized_text().len(),
            pii_count = sanitized.pii_count(),
            score = sanitized.score().total,
            "cloud embedder ZKQP gate passed (no real transmission yet)"
        );
        // Explicit drop: SanitizationResult contains the in-memory PII map
        // which CLAUDE.md §10 requires us to release as soon as we no
        // longer need it.
        drop(sanitized);
        Ok((vec![0.0_f32; self.dimension], Fidelity::Subprocess))
    }

    fn dimension(&self) -> usize {
        self.dimension
    }
}

/// In-memory cache wrapper. Looks up by content; falls through to the
/// inner embedder on miss.
pub struct CachingEmbedder {
    inner: Box<dyn Embedder>,
    cache: Mutex<HashMap<String, (Vec<f32>, Fidelity)>>,
}

impl CachingEmbedder {
    pub fn wrap(inner: Box<dyn Embedder>) -> Self {
        Self {
            inner,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn cache_size(&self) -> usize {
        self.cache.lock().map(|c| c.len()).unwrap_or(0)
    }
}

impl Embedder for CachingEmbedder {
    fn embed(&self, text: &str) -> Result<(Vec<f32>, Fidelity), OrchestratorError> {
        if let Ok(cache) = self.cache.lock()
            && let Some(hit) = cache.get(text)
        {
            return Ok(hit.clone());
        }
        let result = self.inner.embed(text)?;
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(text.to_string(), result.clone());
        }
        Ok(result)
    }

    fn dimension(&self) -> usize {
        self.inner.dimension()
    }
}

// ────────────────────────────────────────────────────────────────────
// Pure parsers
// ────────────────────────────────────────────────────────────────────

/// Parse markdown into a flat list of [`RawConcept`]s. Headings become
/// [`NodeType::Concept`] entries; paragraphs and list items become
/// [`NodeType::Fact`] entries. Code blocks are excluded from the concept
/// stream by default — they're useful as references but rarely express
/// the kind of semantic claim we want to anchor in the graph.
pub fn parse_markdown_to_concepts(content: &str) -> Vec<RawConcept> {
    use pulldown_cmark::{Event, Parser, Tag, TagEnd};

    let mut out = Vec::new();
    let mut current_text = String::new();
    let mut in_code_block = false;
    let mut current_kind: Option<(NodeType, u32)> = None; // (type, depth)
    let mut last_heading_text: Option<String> = None;
    let mut last_parent_for_paragraph: Option<String> = None;

    let parser = Parser::new(content);
    for event in parser {
        match event {
            Event::Start(Tag::Heading { level, .. }) => {
                flush_concept(
                    &mut out,
                    &mut current_text,
                    &mut current_kind,
                    &mut last_parent_for_paragraph,
                );
                let depth = heading_depth(level);
                current_kind = Some((NodeType::Concept, depth));
            }
            Event::End(TagEnd::Heading(_)) => {
                let text = current_text.trim().to_string();
                if !text.is_empty() {
                    last_heading_text = Some(text.clone());
                    last_parent_for_paragraph = Some(text.clone());
                }
                flush_concept(
                    &mut out,
                    &mut current_text,
                    &mut current_kind,
                    &mut last_parent_for_paragraph,
                );
            }
            Event::Start(Tag::Paragraph) | Event::Start(Tag::Item) => {
                flush_concept(
                    &mut out,
                    &mut current_text,
                    &mut current_kind,
                    &mut last_parent_for_paragraph,
                );
                let depth = last_heading_text.as_ref().map(|_| 1).unwrap_or(0) + 1;
                current_kind = Some((NodeType::Fact, depth));
                last_parent_for_paragraph = last_heading_text.clone();
            }
            Event::End(TagEnd::Paragraph) | Event::End(TagEnd::Item) => {
                flush_concept(
                    &mut out,
                    &mut current_text,
                    &mut current_kind,
                    &mut last_parent_for_paragraph,
                );
            }
            Event::Start(Tag::CodeBlock(_)) => {
                in_code_block = true;
            }
            Event::End(TagEnd::CodeBlock) => {
                in_code_block = false;
                current_text.clear();
            }
            Event::Text(t) => {
                if !in_code_block {
                    current_text.push_str(&t);
                }
            }
            Event::Code(c) => {
                if !in_code_block {
                    current_text.push_str(&c);
                }
            }
            Event::SoftBreak | Event::HardBreak => {
                if !in_code_block {
                    current_text.push(' ');
                }
            }
            _ => {}
        }
    }
    flush_concept(
        &mut out,
        &mut current_text,
        &mut current_kind,
        &mut last_parent_for_paragraph,
    );
    out
}

fn flush_concept(
    out: &mut Vec<RawConcept>,
    buf: &mut String,
    kind: &mut Option<(NodeType, u32)>,
    parent: &mut Option<String>,
) {
    if let Some((node_type, depth)) = kind.take() {
        let text = buf.trim().to_string();
        if !text.is_empty() {
            out.push(RawConcept {
                text,
                node_type,
                depth,
                parent_text: parent.clone(),
            });
        }
    }
    buf.clear();
}

fn heading_depth(level: pulldown_cmark::HeadingLevel) -> u32 {
    use pulldown_cmark::HeadingLevel;
    match level {
        HeadingLevel::H1 => 1,
        HeadingLevel::H2 => 2,
        HeadingLevel::H3 => 3,
        HeadingLevel::H4 => 4,
        HeadingLevel::H5 => 5,
        HeadingLevel::H6 => 6,
    }
}

/// Parse HTML into a flat list of [`RawConcept`]s using `scraper`'s DOM.
/// `<h1>`..`<h6>` become Concepts; `<p>` and `<li>` become Facts; `<title>`
/// becomes a top-level Concept.
pub fn parse_html_to_concepts(content: &str) -> Vec<RawConcept> {
    use scraper::{Html, Selector};

    let mut out = Vec::new();
    let document = Html::parse_document(content);

    if let Ok(sel) = Selector::parse("title")
        && let Some(el) = document.select(&sel).next()
    {
        let text = collect_text(el).trim().to_string();
        if !text.is_empty() {
            out.push(RawConcept {
                text,
                node_type: NodeType::Concept,
                depth: 0,
                parent_text: None,
            });
        }
    }

    let heading_levels = [
        ("h1", 1u32),
        ("h2", 2),
        ("h3", 3),
        ("h4", 4),
        ("h5", 5),
        ("h6", 6),
    ];
    for (tag, depth) in heading_levels {
        let Ok(sel) = Selector::parse(tag) else {
            continue;
        };
        for el in document.select(&sel) {
            let text = collect_text(el).trim().to_string();
            if !text.is_empty() {
                out.push(RawConcept {
                    text,
                    node_type: NodeType::Concept,
                    depth,
                    parent_text: None,
                });
            }
        }
    }
    if let Ok(sel) = Selector::parse("p, li") {
        for el in document.select(&sel) {
            let text = collect_text(el).trim().to_string();
            if !text.is_empty() {
                out.push(RawConcept {
                    text,
                    node_type: NodeType::Fact,
                    depth: 2,
                    parent_text: None,
                });
            }
        }
    }
    out
}

fn collect_text(element: scraper::ElementRef<'_>) -> String {
    element.text().collect::<Vec<_>>().join(" ")
}

/// Detect format by extension; falls back to magic-byte sniffing for a few
/// common types when the extension is missing or ambiguous.
pub fn detect_format(path: &Path, content_head: &[u8]) -> &'static str {
    let by_ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    if let Some(ext) = by_ext.as_deref() {
        match ext {
            "md" | "markdown" => return "markdown",
            "html" | "htm" => return "html",
            "txt" => return "text",
            "pdf" => return "pdf",
            "docx" => return "docx",
            "json" => return "json",
            _ => {}
        }
    }
    // Magic bytes fallback.
    if content_head.starts_with(b"%PDF-") {
        return "pdf";
    }
    if content_head.starts_with(b"PK\x03\x04") {
        // Could be docx (ZIP-based). Without inspecting inner structure we
        // can't be sure; default to docx for *.docx extension already
        // handled above. Otherwise treat as zip→unknown.
        return "zip";
    }
    if content_head.starts_with(b"<!DOCTYPE html") || content_head.starts_with(b"<html") {
        return "html";
    }
    "text"
}

/// SHA-256 over content bytes, returned as a lowercase hex string. Used as
/// the dedup key for sources.
pub fn content_hash(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

// ────────────────────────────────────────────────────────────────────
// BLOB encoding for embeddings
// ────────────────────────────────────────────────────────────────────

fn vector_to_blob(v: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 4);
    for f in v {
        out.extend_from_slice(&f.to_le_bytes());
    }
    out
}

fn blob_to_vector(blob: &[u8], dimension: usize) -> Result<Vec<f32>, OrchestratorError> {
    if blob.len() != dimension * 4 {
        return Err(OrchestratorError::Planning(format!(
            "embedding blob length {} doesn't match dimension {}",
            blob.len(),
            dimension * 4
        )));
    }
    let mut out = Vec::with_capacity(dimension);
    for chunk in blob.chunks_exact(4) {
        out.push(f32::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3],
        ]));
    }
    Ok(out)
}

/// Cosine similarity between two equal-length f32 vectors. Returns 0.0 when
/// either vector has zero magnitude (avoids NaN); returns `None` when the
/// dimensions differ.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> Option<f32> {
    if a.len() != b.len() || a.is_empty() {
        return None;
    }
    let mut dot = 0.0_f32;
    let mut na = 0.0_f32;
    let mut nb = 0.0_f32;
    for i in 0..a.len() {
        dot += a[i] * b[i];
        na += a[i] * a[i];
        nb += b[i] * b[i];
    }
    let denom = na.sqrt() * nb.sqrt();
    if denom == 0.0 {
        Some(0.0)
    } else {
        Some(dot / denom)
    }
}

// ────────────────────────────────────────────────────────────────────
// KnowledgeStore
// ────────────────────────────────────────────────────────────────────

/// Top-level store. Owns the SQLite connection and the embedder behind a
/// `Box<dyn Embedder>`. Mutex around the connection is a `std::sync::Mutex`
/// (not `tokio::sync`) per CLAUDE.md §3 D-Bus rule 6 — `rusqlite::Connection`
/// is `!Send` across await points.
pub struct KnowledgeStore {
    conn: Arc<Mutex<Connection>>,
    embedder: Box<dyn Embedder>,
}

impl KnowledgeStore {
    /// Open or create a knowledge graph at `db_path`. WAL mode enabled.
    ///
    /// **Codex re-review FIX 20 (round 7):** the open+backfill sequence
    /// is wrapped in [`retry_with_backoff`], a retry-with-exponential-
    /// backoff loop that re-attempts only on
    /// [`OrchestratorError::TransientLock`]. F19's `BEGIN IMMEDIATE` plus
    /// `busy_timeout(5s)` serialize concurrent backfillers correctly
    /// when the winner releases within 5s, but a slow
    /// `PRAGMA foreign_key_check` (large unversioned graph) or any
    /// writer holding the DB longer than 5s caused the loser's
    /// `BEGIN IMMEDIATE` to surface `SQLITE_BUSY` at BEGIN — failing
    /// a legitimate opener against a valid DB. The retry catches that
    /// `TransientLock`, sleeps with exponential backoff (100, 200, 400,
    /// 800, 1600 ms; jittered), and reattempts. Worst-case opener
    /// latency under sustained contention is bounded by
    /// [`MAX_OPEN_ATTEMPTS`].
    ///
    /// The embedder is consumed only after a connection is in hand
    /// (i.e. after the retry loop completes successfully), so a failed
    /// attempt doesn't leak it.
    pub fn open(
        db_path: &Path,
        embedder: Box<dyn Embedder>,
    ) -> Result<Self, OrchestratorError> {
        let conn = retry_with_backoff(|| try_open_and_backfill_once(db_path))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            embedder,
        })
    }

    pub fn in_memory(embedder: Box<dyn Embedder>) -> Result<Self, OrchestratorError> {
        // **Codex re-review FIX 22 + FIX 23 (round 8):** in-memory
        // databases are private to a single connection per SQLite docs
        // (*"Every :memory: database is distinct from every other"*),
        // so cross-connection lock contention is impossible and the
        // retry loop is unnecessary. But the connection-init pragma
        // still goes through `crate::sqlite::init_sqlite_connection`
        // for constructor-parity (F23) — future drift where someone
        // copies an init path and forgets the pragma is caught by the
        // `busy_timeout_pinned_to_5_seconds` regression test.
        let mut conn = Connection::open_in_memory().map_err(map_sqlite_err)?;
        crate::sqlite::init_sqlite_connection(&conn).map_err(map_sqlite_err)?;
        Self::init_schema(&mut conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            embedder,
        })
    }

    /// Initialize the schema for a fresh database, or migrate an
    /// existing one to the current schema version.
    ///
    /// **Codex re-review FIX 9 (P2-medium):** the round-1 implementation
    /// applied the schema unconditionally via `CREATE TABLE IF NOT EXISTS`,
    /// which is a no-op when the table already exists. A database created
    /// by an earlier branch tip kept the OLD `UNIQUE(uri, content_hash)`
    /// constraint, so the FIX 5 pdf→markdown recovery path silently broke
    /// for those stores. This method now branches on a schema version
    /// table:
    ///
    /// - **Fresh DB** (version table empty): apply [`SCHEMA_DDL`] in full,
    ///   record [`CURRENT_SCHEMA_VERSION`].
    /// - **Epoch 1** (round-1 layout, old `(uri, content_hash)` unique key):
    ///   run [`migrate_epoch_1_to_2`] which rebuilds `sources` with the
    ///   new 3-column unique key inside a transaction, preserving `id`
    ///   values so `node_sources` foreign keys stay valid.
    /// - **Epoch 2** (current): no-op.
    /// - **Unknown future epoch**: refuse to open with a clear error
    ///   (forward-compat guard).
    ///
    /// **Codex re-review FIX 12 (P1-high):** SQLite foreign-key enforcement
    /// is a **per-connection** setting (defaults to OFF). Round-2 set the
    /// pragma inside `SCHEMA_DDL`, which only fires once per connection on
    /// fresh-database setup; every reopen and every short-lived background
    /// connection inherited the default OFF state, so `node_sources` and
    /// `edges` cascade-delete behavior was silently disabled in production
    /// while passing tests in single-connection unit fixtures. The pragma
    /// is now set + verified at the **opening** of `init_schema`, which
    /// runs on every `Connection::open` and `open_in_memory` boundary.
    /// If the SQLite build cannot honor the pragma we refuse to open
    /// rather than silently proceed without provenance integrity.
    fn init_schema(conn: &mut Connection) -> Result<(), OrchestratorError> {
        // FIX 12 part A: enable FK enforcement on this specific connection.
        // The pragma is per-connection in SQLite — putting it in SCHEMA_DDL
        // only set it on the connection that first created the schema.
        conn.execute_batch("PRAGMA journal_mode = WAL;")
            .map_err(map_sqlite_err)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(map_sqlite_err)?;

        // FIX 12 part B: verify the pragma actually took effect. A SQLite
        // build compiled with `SQLITE_OMIT_FOREIGN_KEY` silently ignores
        // the pragma; opening such a database without enforcement would
        // let `node_sources` / `edges` rows orphan their parents. The
        // knowledge graph's "every node has at least one source" invariant
        // depends on FK cascade behavior — refuse to open if enforcement
        // is unavailable.
        let fk_enabled: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .map_err(map_sqlite_err)?;
        if fk_enabled != 1 {
            return Err(OrchestratorError::Planning(
                "SQLite foreign-key enforcement could not be enabled on this \
                 connection — this build of SQLite cannot guarantee provenance \
                 integrity; refusing to open the knowledge store"
                    .to_string(),
            ));
        }

        conn.execute_batch(SCHEMA_VERSION_TABLE_DDL)
            .map_err(map_sqlite_err)?;

        // Recorded version: the authoritative source if present.
        let recorded: Option<i64> = conn
            .query_row(
                "SELECT MAX(version) FROM schema_version",
                [],
                |r| r.get::<_, Option<i64>>(0),
            )
            .optional()
            .map_err(map_sqlite_err)?
            .flatten();

        // Inferred version: necessary for legacy epoch-1 databases that
        // predate this version-tracking change. Their schema_version
        // table is empty (because we just created it) but the existing
        // `sources` table still has the old 2-column unique key. We
        // must detect and migrate THAT case, not treat it as fresh.
        let inferred = infer_schema_version(conn)?;

        let version = recorded.unwrap_or(inferred);

        match version {
            0 => {
                // Truly fresh: no sources table, no recorded version.
                conn.execute_batch(SCHEMA_DDL).map_err(map_sqlite_err)?;
                conn.execute(
                    "INSERT INTO schema_version (version) VALUES (?1)",
                    params![CURRENT_SCHEMA_VERSION],
                )
                .map_err(map_sqlite_err)?;
            }
            1 => {
                // Epoch-1 detected by inference (no recorded version)
                // OR by an explicit recorded version=1 (theoretical;
                // round-1 didn't write any version row).
                migrate_epoch_1_to_2(conn)?;
            }
            v if v == CURRENT_SCHEMA_VERSION => {
                // Already current by structure. If the version row is
                // missing (schema is correct but unrecorded), the
                // database may have come from a previous incomplete
                // migration that committed the schema rebuild but
                // never wrote the version row — see Codex re-review
                // FIX 17.
                //
                // **FIX 17 (P1-high):** before backfilling the version
                // row we MUST verify referential integrity. `PRAGMA
                // foreign_keys = ON` set above does NOT validate
                // existing orphan rows — it only enforces FK
                // constraints on NEW inserts/updates. A database left
                // structurally epoch-2 with orphaned `node_sources` /
                // `edges` rows (the round-3 broken-migration scenario)
                // would otherwise be permanently marked "valid
                // epoch-2" on the next open, silently accepting the
                // corruption. The backfill helper runs
                // `PRAGMA foreign_key_check` and the version row
                // insert inside a single transaction so the database
                // is either "version=2 with verified clean integrity"
                // or "no version row at all" — never the corrupt-
                // but-marked-clean middle state.
                // **Codex re-review FIX 19 (P2-medium):** this
                // `recorded.is_none()` test is the OPTIMISTIC half of
                // a double-checked-locking pair. It runs here WITHOUT
                // a write lock — cheap, and on the overwhelmingly
                // common path (already-versioned database) it
                // correctly skips the backfill with zero locking
                // cost. But it is NOT authoritative: between this
                // read and the backfill helper's `BEGIN IMMEDIATE`, a
                // concurrent opener of the same file may have
                // completed the backfill. The AUTHORITATIVE half is
                // inside `backfill_version_with_integrity_check`,
                // which re-reads `schema_version` while holding the
                // RESERVED write lock and no-ops if a peer already
                // wrote the row. Never treat this outer check as
                // proof that the row is absent.
                if recorded.is_none() {
                    backfill_version_with_integrity_check(conn)?;
                }
            }
            v => {
                return Err(OrchestratorError::Planning(format!(
                    "knowledge schema version {v} is newer than this binary supports (max {CURRENT_SCHEMA_VERSION}); refusing to open"
                )));
            }
        }
        Ok(())
    }

    pub fn embedder_dimension(&self) -> usize {
        self.embedder.dimension()
    }

    // ── Source CRUD ────────────────────────────────────────────────────

    /// Insert a source row, or return the existing id when
    /// `(uri, content_hash, format)` already matches — idempotency by
    /// construction.
    ///
    /// **Codex review FIX 5 (P2):** the lookup matches on the full
    /// 3-tuple, not just `(uri, content_hash)`. Re-ingesting the same
    /// `(uri, bytes)` pair under a *different* format yields a separate
    /// source row instead of silently shadowing the prior row.
    pub fn create_or_get_source(
        &self,
        source_type: SourceType,
        uri: &str,
        fidelity: Fidelity,
        content_hash: &str,
        format: &str,
    ) -> Result<SourceId, OrchestratorError> {
        let conn = self.conn.lock().map_err(map_lock_err)?;
        if let Some(id) = conn
            .query_row(
                "SELECT id FROM sources WHERE uri = ?1 AND content_hash = ?2 AND format = ?3",
                params![uri, content_hash, format],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(map_sqlite_err)?
        {
            return Ok(id);
        }
        let now = Utc::now().timestamp();
        conn.execute(
            "INSERT INTO sources (source_type, uri, ingested_at_unix, fidelity, content_hash, format)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                source_type.as_str(),
                uri,
                now,
                fidelity.as_str(),
                content_hash,
                format,
            ],
        )
        .map_err(map_sqlite_err)?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_source(&self, id: SourceId) -> Result<Source, OrchestratorError> {
        let conn = self.conn.lock().map_err(map_lock_err)?;
        let row = conn
            .query_row(
                "SELECT id, source_type, uri, ingested_at_unix, fidelity, content_hash, format
                 FROM sources WHERE id = ?1",
                params![id],
                row_to_source,
            )
            .map_err(map_sqlite_err)?;
        Ok(row)
    }

    // ── Node CRUD ─────────────────────────────────────────────────────

    /// Create a node and link it to at least one source. **Empty
    /// `source_ids` is rejected** — that's the confabulation defense.
    /// If embedding generation fails, the node is still created (graceful
    /// degradation; semantic search will skip it).
    pub fn create_node(
        &self,
        content: &str,
        node_type: NodeType,
        source_ids: &[SourceId],
    ) -> Result<NodeId, OrchestratorError> {
        if source_ids.is_empty() {
            return Err(OrchestratorError::Planning(
                "cannot create knowledge node without at least one source".to_string(),
            ));
        }
        let now = Utc::now().timestamp();
        let mut conn = self.conn.lock().map_err(map_lock_err)?;
        let tx = conn.transaction().map_err(map_sqlite_err)?;
        tx.execute(
            "INSERT INTO nodes (content, node_type, created_at_unix, last_accessed_unix, access_count)
             VALUES (?1, ?2, ?3, ?3, 0)",
            params![content, node_type.as_str(), now],
        )
        .map_err(map_sqlite_err)?;
        let node_id = tx.last_insert_rowid();
        for src in source_ids {
            tx.execute(
                "INSERT OR IGNORE INTO node_sources (node_id, source_id) VALUES (?1, ?2)",
                params![node_id, src],
            )
            .map_err(map_sqlite_err)?;
        }
        tx.commit().map_err(map_sqlite_err)?;
        drop(conn);

        // Best-effort embedding. Failures are logged and ignored; node
        // already exists, only its semantic-search visibility is affected.
        match self.embedder.embed(content) {
            Ok((vec, fid)) if !vec.is_empty() => {
                if let Err(e) = self.store_embedding(node_id, &vec, fid) {
                    debug!(node_id, "embedding store failed: {e}");
                }
            }
            Ok(_) => {
                debug!(node_id, "embedder unavailable; node has no vector");
            }
            Err(e) => {
                debug!(node_id, "embed failed: {e}");
            }
        }
        Ok(node_id)
    }

    fn store_embedding(
        &self,
        node_id: NodeId,
        vector: &[f32],
        fidelity: Fidelity,
    ) -> Result<(), OrchestratorError> {
        let now = Utc::now().timestamp();
        let blob = vector_to_blob(vector);
        let conn = self.conn.lock().map_err(map_lock_err)?;
        conn.execute(
            "INSERT OR REPLACE INTO embeddings (node_id, dimension, vector, fidelity, created_at_unix)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![node_id, vector.len() as i64, blob, fidelity.as_str(), now],
        )
        .map_err(map_sqlite_err)?;
        Ok(())
    }

    pub fn get_node(&self, id: NodeId) -> Result<KnowledgeNode, OrchestratorError> {
        let conn = self.conn.lock().map_err(map_lock_err)?;
        let mut node = conn
            .query_row(
                "SELECT id, content, node_type, created_at_unix, last_accessed_unix, access_count
                 FROM nodes WHERE id = ?1",
                params![id],
                row_to_node,
            )
            .map_err(map_sqlite_err)?;
        let mut stmt = conn
            .prepare("SELECT source_id FROM node_sources WHERE node_id = ?1")
            .map_err(map_sqlite_err)?;
        let rows = stmt
            .query_map(params![id], |r| r.get::<_, i64>(0))
            .map_err(map_sqlite_err)?;
        for row in rows {
            node.source_ids.push(row.map_err(map_sqlite_err)?);
        }
        Ok(node)
    }

    pub fn touch_node(&self, id: NodeId) -> Result<(), OrchestratorError> {
        let now = Utc::now().timestamp();
        let conn = self.conn.lock().map_err(map_lock_err)?;
        conn.execute(
            "UPDATE nodes SET last_accessed_unix = ?1, access_count = access_count + 1 WHERE id = ?2",
            params![now, id],
        )
        .map_err(map_sqlite_err)?;
        Ok(())
    }

    /// List nodes filtered by type, newest first.
    ///
    /// **Codex review FIX 6 (P2):** every returned `KnowledgeNode` has
    /// its `source_ids` hydrated from the `node_sources` join table —
    /// the module-level invariant ("every node has at least one
    /// `Source`, the confabulation defense") would otherwise be
    /// broken by this listing path.
    pub fn search_by_type(
        &self,
        node_type: NodeType,
        limit: usize,
    ) -> Result<Vec<KnowledgeNode>, OrchestratorError> {
        let conn = self.conn.lock().map_err(map_lock_err)?;
        let mut stmt = conn
            .prepare(
                "SELECT id, content, node_type, created_at_unix, last_accessed_unix, access_count
                 FROM nodes WHERE node_type = ?1
                 ORDER BY created_at_unix DESC, id DESC
                 LIMIT ?2",
            )
            .map_err(map_sqlite_err)?;
        let rows = stmt
            .query_map(params![node_type.as_str(), limit as i64], row_to_node)
            .map_err(map_sqlite_err)?;
        let mut out = Vec::new();
        for row in rows {
            let mut node = row.map_err(map_sqlite_err)?;
            node.source_ids = self
                .list_sources_for_locked(&conn, node.id)?
                .into_iter()
                .map(|s| s.id)
                .collect();
            out.push(node);
        }
        Ok(out)
    }

    // ── Edges + cycle prevention ─────────────────────────────────────

    pub fn create_edge(
        &self,
        from_id: NodeId,
        to_id: NodeId,
        relation: EdgeRelation,
        confidence: f32,
        source_id: SourceId,
    ) -> Result<EdgeId, OrchestratorError> {
        if from_id == to_id {
            return Err(OrchestratorError::Planning(
                "self-edge rejected".to_string(),
            ));
        }
        if !(0.0..=1.0).contains(&confidence) {
            return Err(OrchestratorError::Planning(format!(
                "edge confidence {confidence} out of [0.0, 1.0]"
            )));
        }
        if relation.is_acyclic() && self.would_create_cycle(from_id, to_id, relation)? {
            // ORCH-R2-03: typed, leak-free — caller-held node ids go to tracing.
            warn!(
                relation = relation.as_str(),
                from = %from_id,
                to = %to_id,
                "create_edge: edge would create a cycle"
            );
            return Err(OrchestratorError::Conflict {
                domain: "knowledge",
                reason: "edge would create a cycle",
            });
        }
        let now = Utc::now().timestamp();
        let conn = self.conn.lock().map_err(map_lock_err)?;
        conn.execute(
            "INSERT INTO edges (from_node, to_node, relation, confidence, source_id, created_at_unix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                from_id,
                to_id,
                relation.as_str(),
                confidence as f64,
                source_id,
                now,
            ],
        )
        .map_err(map_sqlite_err)?;
        Ok(conn.last_insert_rowid())
    }

    fn would_create_cycle(
        &self,
        from_id: NodeId,
        to_id: NodeId,
        relation: EdgeRelation,
    ) -> Result<bool, OrchestratorError> {
        // BFS forward from to_id along the same relation; if we reach
        // from_id, the new edge would close a cycle.
        let conn = self.conn.lock().map_err(map_lock_err)?;
        let mut seen: HashSet<NodeId> = HashSet::new();
        let mut queue: VecDeque<NodeId> = VecDeque::new();
        queue.push_back(to_id);
        let mut stmt = conn
            .prepare("SELECT to_node FROM edges WHERE from_node = ?1 AND relation = ?2")
            .map_err(map_sqlite_err)?;
        while let Some(current) = queue.pop_front() {
            if !seen.insert(current) {
                continue;
            }
            if current == from_id {
                return Ok(true);
            }
            let rows = stmt
                .query_map(params![current, relation.as_str()], |r| r.get::<_, i64>(0))
                .map_err(map_sqlite_err)?;
            for r in rows {
                queue.push_back(r.map_err(map_sqlite_err)?);
            }
        }
        Ok(false)
    }

    pub fn get_edge(&self, id: EdgeId) -> Result<KnowledgeEdge, OrchestratorError> {
        let conn = self.conn.lock().map_err(map_lock_err)?;
        conn.query_row(
            "SELECT id, from_node, to_node, relation, confidence, source_id, created_at_unix
             FROM edges WHERE id = ?1",
            params![id],
            row_to_edge,
        )
        .map_err(map_sqlite_err)
    }

    pub fn list_edges_from(&self, node_id: NodeId) -> Result<Vec<KnowledgeEdge>, OrchestratorError> {
        let conn = self.conn.lock().map_err(map_lock_err)?;
        let mut stmt = conn
            .prepare(
                "SELECT id, from_node, to_node, relation, confidence, source_id, created_at_unix
                 FROM edges WHERE from_node = ?1
                 ORDER BY created_at_unix DESC, id DESC",
            )
            .map_err(map_sqlite_err)?;
        let rows = stmt
            .query_map(params![node_id], row_to_edge)
            .map_err(map_sqlite_err)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(map_sqlite_err)?);
        }
        Ok(out)
    }

    // ── Querying ──────────────────────────────────────────────────────

    /// Compute query embedding, then rank all stored embeddings by cosine
    /// similarity. O(N) in node count — sufficient for the < 100K-node
    /// regime; LanceDB-style HNSW index becomes valuable beyond that.
    pub fn search_semantic(
        &self,
        query: &str,
        max_results: usize,
    ) -> Result<Vec<NodeWithSources>, OrchestratorError> {
        let (q_vec, _q_fidelity) = self.embedder.embed(query)?;
        if q_vec.is_empty() {
            // No embedder available; degrade to fallback below.
            return self.fallback_keyword_search(query, max_results);
        }
        let conn = self.conn.lock().map_err(map_lock_err)?;
        let mut stmt = conn
            .prepare(
                "SELECT n.id, n.content, n.node_type, n.created_at_unix, n.last_accessed_unix, n.access_count,
                        e.dimension, e.vector
                 FROM nodes n
                 INNER JOIN embeddings e ON e.node_id = n.id",
            )
            .map_err(map_sqlite_err)?;
        let rows = stmt
            .query_map([], |row| {
                let node = row_to_node(row)?;
                let dim: i64 = row.get(6)?;
                let blob: Vec<u8> = row.get(7)?;
                Ok((node, dim as usize, blob))
            })
            .map_err(map_sqlite_err)?;

        let mut scored: Vec<(KnowledgeNode, f32)> = Vec::new();
        for r in rows {
            let (node, dim, blob) = r.map_err(map_sqlite_err)?;
            let v = match blob_to_vector(&blob, dim) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let sim = match cosine_similarity(&q_vec, &v) {
                Some(s) => s,
                None => continue,
            };
            scored.push((node, sim));
        }
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(max_results);

        // Hydrate sources for each hit.
        let mut out = Vec::new();
        for (mut node, sim) in scored {
            let sources = self.list_sources_for_locked(&conn, node.id)?;
            node.source_ids = sources.iter().map(|s| s.id).collect();
            out.push(NodeWithSources {
                node,
                sources,
                similarity_score: Some(sim),
            });
        }
        Ok(out)
    }

    fn fallback_keyword_search(
        &self,
        query: &str,
        max_results: usize,
    ) -> Result<Vec<NodeWithSources>, OrchestratorError> {
        let conn = self.conn.lock().map_err(map_lock_err)?;
        let pattern = format!("%{}%", query.to_lowercase());
        let mut stmt = conn
            .prepare(
                "SELECT id, content, node_type, created_at_unix, last_accessed_unix, access_count
                 FROM nodes WHERE LOWER(content) LIKE ?1
                 ORDER BY created_at_unix DESC, id DESC
                 LIMIT ?2",
            )
            .map_err(map_sqlite_err)?;
        let rows = stmt
            .query_map(params![pattern, max_results as i64], row_to_node)
            .map_err(map_sqlite_err)?;
        let mut out = Vec::new();
        for r in rows {
            let mut node = r.map_err(map_sqlite_err)?;
            let sources = self.list_sources_for_locked(&conn, node.id)?;
            node.source_ids = sources.iter().map(|s| s.id).collect();
            out.push(NodeWithSources {
                node,
                sources,
                similarity_score: None,
            });
        }
        Ok(out)
    }

    /// Walk outward from `start` along *any* relation up to `max_depth`.
    pub fn related_to(
        &self,
        start: NodeId,
        max_depth: u32,
    ) -> Result<Vec<RelatedNode>, OrchestratorError> {
        if max_depth == 0 {
            return Ok(Vec::new());
        }
        let conn = self.conn.lock().map_err(map_lock_err)?;
        let mut visited: HashSet<NodeId> = HashSet::new();
        visited.insert(start);
        let mut frontier: Vec<(NodeId, u32)> = vec![(start, 0)];
        let mut out = Vec::new();
        let mut stmt = conn
            .prepare(
                "SELECT to_node, relation FROM edges WHERE from_node = ?1",
            )
            .map_err(map_sqlite_err)?;
        while let Some((current, depth)) = frontier.pop() {
            if depth >= max_depth {
                continue;
            }
            let rows = stmt
                .query_map(params![current], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
                })
                .map_err(map_sqlite_err)?;
            for r in rows {
                let (to_id, rel_str) = r.map_err(map_sqlite_err)?;
                if !visited.insert(to_id) {
                    continue;
                }
                let relation = EdgeRelation::from_str(&rel_str)?;
                let mut node = conn
                    .query_row(
                        "SELECT id, content, node_type, created_at_unix, last_accessed_unix, access_count
                         FROM nodes WHERE id = ?1",
                        params![to_id],
                        row_to_node,
                    )
                    .map_err(map_sqlite_err)?;
                node.source_ids = self
                    .list_sources_for_locked(&conn, to_id)?
                    .into_iter()
                    .map(|s| s.id)
                    .collect();
                out.push(RelatedNode {
                    node,
                    via_relation: relation,
                    depth: depth + 1,
                });
                frontier.push((to_id, depth + 1));
            }
        }
        Ok(out)
    }

    /// Shortest edge path from `from` to `to`, treating the graph as
    /// **undirected** for traversal. Returns the sequence of edge ids
    /// connecting the two nodes, or `None` when unreachable.
    ///
    /// **Codex review FIX 3:** the BFS walks both outgoing AND incoming
    /// edges at each node — an edge `A → B` is reachable in either
    /// direction. Edge ids alone identify edges (callers can look up
    /// direction via [`get_edge`](Self::get_edge) if needed), so the
    /// returned `Vec<EdgeId>` semantics are unchanged.
    pub fn find_path(
        &self,
        from: NodeId,
        to: NodeId,
    ) -> Result<Option<Vec<EdgeId>>, OrchestratorError> {
        if from == to {
            return Ok(Some(Vec::new()));
        }
        let conn = self.conn.lock().map_err(map_lock_err)?;
        let mut parent: HashMap<NodeId, (NodeId, EdgeId)> = HashMap::new();
        let mut queue: VecDeque<NodeId> = VecDeque::new();
        queue.push_back(from);
        let mut visited: HashSet<NodeId> = HashSet::new();
        visited.insert(from);
        // UNION ALL to walk in both directions: at each node, collect
        // every edge incident to it regardless of direction.
        let mut stmt = conn
            .prepare(
                "SELECT id, to_node AS neighbor FROM edges WHERE from_node = ?1
                 UNION ALL
                 SELECT id, from_node AS neighbor FROM edges WHERE to_node = ?1",
            )
            .map_err(map_sqlite_err)?;
        while let Some(current) = queue.pop_front() {
            if current == to {
                let mut path = Vec::new();
                let mut cur = current;
                while let Some(&(prev, edge_id)) = parent.get(&cur) {
                    path.push(edge_id);
                    cur = prev;
                    if cur == from {
                        break;
                    }
                }
                path.reverse();
                return Ok(Some(path));
            }
            let rows = stmt
                .query_map(params![current], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
                })
                .map_err(map_sqlite_err)?;
            for r in rows {
                let (edge_id, neighbor) = r.map_err(map_sqlite_err)?;
                if visited.insert(neighbor) {
                    parent.insert(neighbor, (current, edge_id));
                    queue.push_back(neighbor);
                }
            }
        }
        Ok(None)
    }

    /// All nodes that are connected to `node_id` via a `Contradicts` edge in
    /// either direction.
    pub fn contradictions_for(&self, node_id: NodeId) -> Result<Vec<NodeId>, OrchestratorError> {
        let conn = self.conn.lock().map_err(map_lock_err)?;
        let mut stmt = conn
            .prepare(
                "SELECT to_node FROM edges WHERE from_node = ?1 AND relation = 'contradicts'
                 UNION
                 SELECT from_node FROM edges WHERE to_node = ?1 AND relation = 'contradicts'",
            )
            .map_err(map_sqlite_err)?;
        let rows = stmt
            .query_map(params![node_id], |r| r.get::<_, i64>(0))
            .map_err(map_sqlite_err)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(map_sqlite_err)?);
        }
        Ok(out)
    }

    pub fn detect_contradictions(&self) -> Result<Vec<(NodeId, NodeId)>, OrchestratorError> {
        let conn = self.conn.lock().map_err(map_lock_err)?;
        let mut stmt = conn
            .prepare(
                "SELECT from_node, to_node FROM edges WHERE relation = 'contradicts'
                 ORDER BY id ASC",
            )
            .map_err(map_sqlite_err)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))
            .map_err(map_sqlite_err)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(map_sqlite_err)?);
        }
        Ok(out)
    }

    pub fn list_sources_for(&self, node_id: NodeId) -> Result<Vec<Source>, OrchestratorError> {
        let conn = self.conn.lock().map_err(map_lock_err)?;
        self.list_sources_for_locked(&conn, node_id)
    }

    fn list_sources_for_locked(
        &self,
        conn: &Connection,
        node_id: NodeId,
    ) -> Result<Vec<Source>, OrchestratorError> {
        let mut stmt = conn
            .prepare(
                "SELECT s.id, s.source_type, s.uri, s.ingested_at_unix, s.fidelity, s.content_hash, s.format
                 FROM sources s
                 INNER JOIN node_sources ns ON ns.source_id = s.id
                 WHERE ns.node_id = ?1",
            )
            .map_err(map_sqlite_err)?;
        let rows = stmt
            .query_map(params![node_id], row_to_source)
            .map_err(map_sqlite_err)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(map_sqlite_err)?);
        }
        Ok(out)
    }

    /// List every node linked to `source_id`.
    ///
    /// **Codex review FIX 6 (P2):** each returned node has its
    /// `source_ids` fully hydrated — including sources OTHER than the
    /// queried `source_id`. A node may participate in multiple sources;
    /// callers must see the complete provenance set, not just the
    /// matching one.
    pub fn list_nodes_from_source(
        &self,
        source_id: SourceId,
    ) -> Result<Vec<KnowledgeNode>, OrchestratorError> {
        let conn = self.conn.lock().map_err(map_lock_err)?;
        let mut stmt = conn
            .prepare(
                "SELECT n.id, n.content, n.node_type, n.created_at_unix, n.last_accessed_unix, n.access_count
                 FROM nodes n
                 INNER JOIN node_sources ns ON ns.node_id = n.id
                 WHERE ns.source_id = ?1
                 ORDER BY n.id ASC",
            )
            .map_err(map_sqlite_err)?;
        let rows = stmt
            .query_map(params![source_id], row_to_node)
            .map_err(map_sqlite_err)?;
        let mut out = Vec::new();
        for r in rows {
            let mut node = r.map_err(map_sqlite_err)?;
            node.source_ids = self
                .list_sources_for_locked(&conn, node.id)?
                .into_iter()
                .map(|s| s.id)
                .collect();
            out.push(node);
        }
        Ok(out)
    }

    /// Remove a source. Cascades: edges that cite the source are deleted
    /// (FK), node_sources rows are deleted (FK), and any nodes that became
    /// orphaned (no remaining sources) are explicitly deleted. Returns the
    /// count of orphaned nodes that were removed.
    pub fn forget_source(&self, source_id: SourceId) -> Result<u32, OrchestratorError> {
        let mut conn = self.conn.lock().map_err(map_lock_err)?;
        let tx = conn.transaction().map_err(map_sqlite_err)?;
        // Find nodes that are about to become source-less.
        let mut orphans: Vec<NodeId> = Vec::new();
        {
            let mut stmt = tx
                .prepare(
                    "SELECT node_id FROM node_sources
                     WHERE source_id = ?1
                     AND node_id NOT IN (
                         SELECT node_id FROM node_sources WHERE source_id != ?1
                     )",
                )
                .map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(params![source_id], |r| r.get::<_, i64>(0))
                .map_err(map_sqlite_err)?;
            for r in rows {
                orphans.push(r.map_err(map_sqlite_err)?);
            }
        }
        // Delete the source. CASCADE removes node_sources rows and any
        // edges whose source_id pointed at this source.
        tx.execute("DELETE FROM sources WHERE id = ?1", params![source_id])
            .map_err(map_sqlite_err)?;
        // Explicitly delete the orphaned nodes (CASCADE then handles their
        // edges and embeddings).
        for n in &orphans {
            tx.execute("DELETE FROM nodes WHERE id = ?1", params![n])
                .map_err(map_sqlite_err)?;
        }
        tx.commit().map_err(map_sqlite_err)?;
        Ok(orphans.len() as u32)
    }

    pub fn count_nodes(&self) -> Result<u32, OrchestratorError> {
        let conn = self.conn.lock().map_err(map_lock_err)?;
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM nodes", [], |r| r.get(0))
            .map_err(map_sqlite_err)?;
        Ok(n as u32)
    }

    pub fn count_sources(&self) -> Result<u32, OrchestratorError> {
        let conn = self.conn.lock().map_err(map_lock_err)?;
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM sources", [], |r| r.get(0))
            .map_err(map_sqlite_err)?;
        Ok(n as u32)
    }

    pub fn count_edges(&self) -> Result<u32, OrchestratorError> {
        let conn = self.conn.lock().map_err(map_lock_err)?;
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM edges", [], |r| r.get(0))
            .map_err(map_sqlite_err)?;
        Ok(n as u32)
    }

    // ── Ingestion pipeline ───────────────────────────────────────────

    /// Ingest raw text under a stated format. Caller chooses the format
    /// — typically resolved by [`detect_format`]. Idempotent: re-ingesting
    /// the same `(source_uri, content)` pair returns the existing source's
    /// nodes without re-creating them.
    ///
    /// **Fidelity provenance (Codex review FIX 2):** the source row's
    /// fidelity reflects whether we actually extracted concepts, not the
    /// caller's optimistic assumption. We ask `parse_concepts` first;
    /// for unsupported formats (pdf/docx/unknown) we tag the new source
    /// row `Fidelity::Unavailable`. On idempotent re-ingest we re-read
    /// the stored source's fidelity and format rather than echoing the
    /// caller's input.
    pub fn ingest_text(
        &self,
        text: &str,
        source_uri: &str,
        source_type: SourceType,
        format: &str,
    ) -> Result<IngestionResult, OrchestratorError> {
        // ORCH-R1-04: every ingest entry routes through the SAME shared cap
        // guards — one choke-point, no per-entry drift (SVC-2 completeness).
        enforce_ingest_byte_cap(text.len(), source_uri)?;
        let hash = content_hash(text.as_bytes());
        // Determine fidelity FIRST. The parser knows whether it can
        // actually extract concepts for this format; we honor its verdict.
        let (concepts, fidelity_used) = self.parse_concepts(text, format);
        // Bound concept explosion BEFORE any node is created (shared guard).
        enforce_concept_caps(&concepts, source_uri)?;
        let pre_count = self.count_sources()?;
        let source_id = self.create_or_get_source(
            source_type,
            source_uri,
            fidelity_used,
            &hash,
            format,
        )?;
        let post_count = self.count_sources()?;
        // If the source already existed (idempotent re-ingest), don't
        // re-create nodes — return the existing structure as a no-op.
        // Re-fetch the stored source so the response reflects the source
        // row's recorded provenance, not the current caller's input.
        if pre_count == post_count {
            let stored = self.get_source(source_id)?;
            return Ok(IngestionResult {
                source_id,
                nodes_created: 0,
                edges_created: 0,
                fidelity_used: stored.fidelity,
                format_detected: stored.format,
            });
        }
        let mut nodes_created = 0_u32;
        let mut text_to_id: HashMap<String, NodeId> = HashMap::new();
        for c in &concepts {
            let id = self.create_node(&c.text, c.node_type, &[source_id])?;
            text_to_id.insert(c.text.clone(), id);
            nodes_created += 1;
        }
        // Build PartOf edges: each concept whose parent_text matches a
        // previously-created node becomes part_of that node. Skip if the
        // edge would create a cycle (impossible by construction here, but
        // create_edge enforces it anyway).
        let mut edges_created = 0_u32;
        for c in &concepts {
            let Some(parent) = c.parent_text.as_ref() else {
                continue;
            };
            let Some(&parent_id) = text_to_id.get(parent) else {
                continue;
            };
            let Some(&child_id) = text_to_id.get(&c.text) else {
                continue;
            };
            if parent_id == child_id {
                continue;
            }
            match self.create_edge(child_id, parent_id, EdgeRelation::PartOf, 0.9, source_id) {
                Ok(_) => edges_created += 1,
                Err(e) => debug!("part_of edge skipped: {e}"),
            }
        }
        info!(
            source_id,
            nodes_created, edges_created, "knowledge ingestion complete"
        );
        Ok(IngestionResult {
            source_id,
            nodes_created,
            edges_created,
            fidelity_used,
            format_detected: format.to_string(),
        })
    }

    fn parse_concepts(&self, text: &str, format: &str) -> (Vec<RawConcept>, Fidelity) {
        match format {
            "markdown" | "text" => (parse_markdown_to_concepts(text), Fidelity::Direct),
            "html" => (parse_html_to_concepts(text), Fidelity::Direct),
            "pdf" | "docx" => (Vec::new(), Fidelity::Unavailable),
            _ => (Vec::new(), Fidelity::Unavailable),
        }
    }

    /// Read a file from disk via the safe-open boundary, detect the
    /// format, and ingest. Returns `Fidelity::Unavailable` for formats
    /// we can't currently extract.
    ///
    /// **Codex re-review FIX 15 (P1-high):** `trusted_root` is now a
    /// **held directory handle**, not a re-resolvable path string.
    /// Round-3 took `trusted_root: &Path` and called
    /// `std::fs::File::open(trusted_root)` inside `safe_open_under_root`;
    /// this re-resolved the path at every ingest call, so an attacker
    /// who controlled the parent of an allowlist entry could swap the
    /// entry for a symlink between registration and use, and `openat2`
    /// would then anchor `RESOLVE_BENEATH` to the symlink target
    /// instead of the originally-approved root — an allowlist escape.
    ///
    /// The new contract: the services layer opens the directory once
    /// at registration time with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`
    /// and holds the resulting `File` for the service's lifetime.
    /// That handle is the trust anchor — it references a kernel
    /// inode, not a path string. `safe_open_under_root_handle` uses
    /// `openat2(dirfd=root_handle.as_raw_fd(), ...)` to atomically
    /// resolve `target` relative to that inode, even if the path
    /// string that originally opened the inode has since been swapped.
    ///
    /// **Codex re-review FIX 10+11 (P1-high) — retained:** Linux
    /// uses `openat2(2)` with `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`
    /// to atomically reject symlinks at ANY component and refuse
    /// `..` escapes from the trusted root.
    ///
    /// # Platform support
    ///
    /// This function is supported on **Linux only** in the current
    /// build. Windows and other Unix variants return
    /// `ErrorKind::Unsupported`. See `safe_open_under_root_handle`
    /// for the platform-support rationale.
    ///
    /// **SVC-8 (services-sweep): crate-internal.** This is the raw
    /// safe-open primitive — it trusts that `trusted_root_handle` already
    /// cleared the ingestion access-control gate. It is `pub(crate)` so no
    /// external crate can reach it with a fabricated handle; cross-crate
    /// callers must go through
    /// [`ingest_validated_file`](Self::ingest_validated_file), which only
    /// accepts an [`IngestionAccessController`]-issued
    /// [`ValidatedIngestionPath`]. The domain's own safe-open tests still
    /// exercise this primitive directly.
    pub(crate) fn ingest_file_with_root_handle(
        &self,
        trusted_root_handle: &std::fs::File,
        target: &Path,
    ) -> Result<IngestionResult, OrchestratorError> {
        use std::io::Read;
        let file = safe_open_under_root_handle(trusted_root_handle, target)
            .map_err(|e| {
                warn!(path = %target.display(), "could not safely open file for ingestion");
                OrchestratorError::Planning(format!("could not safely open file for ingestion: {e}"))
            })?;
        // ORCH-R1-04: bound the read to MAX_INGEST_BYTES + 1 so a special or
        // streaming file (which can report length 0 yet stream unbounded) is
        // never slurped whole into memory, then route the size DECISION through
        // the SAME shared byte-cap guard every entry uses (no per-entry drift —
        // SVC-2 completeness: one choke-point, not per-site copies).
        let mut bytes = Vec::new();
        file.take(MAX_INGEST_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| {
                warn!(path = %target.display(), "could not read file for ingestion");
                OrchestratorError::Planning(format!("could not read file for ingestion: {e}"))
            })?;
        let uri = target.to_string_lossy().to_string();
        enforce_ingest_byte_cap(bytes.len(), &uri)?;
        let head = &bytes[..bytes.len().min(64)];
        let format = detect_format(target, head);
        self.ingest_bytes(&bytes, &uri, format)
    }

    /// Ingest a file proven safe by the ingestion access-control gate —
    /// **the only public, cross-crate file-ingest entry point** (SVC-8).
    ///
    /// A [`ValidatedIngestionPath`] can only be produced by
    /// [`IngestionAccessController::validate`], which enforces the
    /// closed-by-default allowlist, canonicalization, prefix match, and
    /// sensitive-content denylist (the 9-round-hardened F4 / F7 / F15
    /// gate). Possession of the token therefore *is* proof that the path
    /// cleared every check — there is no public way to ingest a file
    /// without one, so the allowlist can no longer be bypassed by a caller
    /// that fabricates a raw directory handle (the pre-SVC-8 hole: the
    /// allowlist lived in the transport, and the domain ingested any file
    /// it was handed).
    ///
    /// The token carries the held root handle that anchored the decision
    /// (FIX 15 — Unix open-fd semantics: the kernel inode the handle
    /// references stays valid for the token's lifetime even if the path
    /// string is renamed or swapped), so this hands that exact handle to
    /// the `openat2`-backed safe-open boundary with no re-resolution.
    ///
    /// # Errors
    ///
    /// Propagates [`OrchestratorError::Planning`] from the safe-open
    /// boundary (e.g. the file vanished between validation and open) or
    /// from byte ingestion. Access decisions never reach here — a denied
    /// path fails earlier at [`IngestionAccessController::validate`].
    pub fn ingest_validated_file(
        &self,
        validated: &ValidatedIngestionPath,
    ) -> Result<IngestionResult, OrchestratorError> {
        self.ingest_file_with_root_handle(&validated.root_handle, &validated.canonical)
    }

    /// Pure bytes-in path. Extracted from the old `ingest_file` body so
    /// any caller that already has a validated bytes source can ingest
    /// without re-touching the filesystem.
    ///
    /// FIX 8: this function never receives a `Path` — only the bytes
    /// already read through the safe-open boundary. There's no second
    /// filesystem round-trip from here.
    pub fn ingest_bytes(
        &self,
        bytes: &[u8],
        uri: &str,
        format: &str,
    ) -> Result<IngestionResult, OrchestratorError> {
        // ORCH-R1-04: same shared byte-cap guard as every other ingest entry —
        // covers direct callers and the unsupported-format branch below that
        // content-hashes bytes without parsing (an unbounded hash is a CPU DoS).
        enforce_ingest_byte_cap(bytes.len(), uri)?;
        match format {
            "markdown" | "text" | "html" => {
                let text = std::str::from_utf8(bytes).map_err(|e| {
                    OrchestratorError::Planning(format!("non-UTF-8 input: {e}"))
                })?;
                self.ingest_text(text, uri, SourceType::LocalFile, format)
            }
            other => {
                // Record the source even though we can't extract concepts —
                // the user can see we tried. Fidelity::Unavailable.
                let hash = content_hash(bytes);
                let source_id = self.create_or_get_source(
                    SourceType::LocalFile,
                    uri,
                    Fidelity::Unavailable,
                    &hash,
                    other,
                )?;
                Ok(IngestionResult {
                    source_id,
                    nodes_created: 0,
                    edges_created: 0,
                    fidelity_used: Fidelity::Unavailable,
                    format_detected: other.to_string(),
                })
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// FIX 15 (P1-high): handle-anchored kernel-level safe open
// (supersedes round-3 FIX 10+11 / safe_open_under_root)
// ────────────────────────────────────────────────────────────────────

/// Open `target` for reading, anchored to a held directory handle
/// for the trusted root. Refuses to traverse ANY symlink/reparse
/// point between the held root and the target.
///
/// **Why this exists** (Codex re-review FIX 15, P1-high):
/// round-3's `safe_open_under_root(trusted_root: &Path, target: &Path)`
/// took the trusted root as a path string and called
/// `std::fs::File::open(trusted_root)` to get a directory FD for
/// `openat2`. This re-resolved the path at every ingest call. An
/// attacker with write access to the parent of an allowlist entry
/// could swap the entry for a symlink AFTER `add_ingestion_root`'s
/// canonicalization but BEFORE this open — at which point `openat2`'s
/// `RESOLVE_BENEATH` would happily anchor to the symlink target
/// rather than the originally-approved directory, allowing an
/// allowlist escape.
///
/// The fix: the trusted root is passed as a **held `&File`** that
/// the services layer opens once at registration time with
/// `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` and retains for the
/// service's lifetime. The handle's identity (kernel inode behind
/// the fd) is the trust anchor, not a re-resolvable path string.
/// `safe_open_under_root_handle` uses the handle's raw fd as
/// `dirfd` for `openat2`, anchoring all path resolution to that
/// inode. Even if the original path string has been swapped for a
/// symlink in the meantime, the held fd still references the
/// original inode and the kernel walks from there.
///
/// **Codex re-review FIX 10+11 (P1-high) — retained:** the resolve
/// flags are `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`, which
/// atomically reject symlinks at any component and refuse `..`
/// escapes from the trusted root.
///
/// # Platform support
///
/// This function is supported on **Linux only** in the current build.
///
/// - **Linux** (`target_os = "linux"`): `openat2(2)` with
///   `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`, anchored to the held
///   directory FD. Kernel-level atomicity: resolution and open are
///   one syscall. Stable since kernel 5.6 (verified via
///   `libc::SYS_openat2 = 437` in libc 0.2.186).
///
/// - **Windows**: returns `ErrorKind::Unsupported`. Round-3's
///   component-walk implementation had unfixable TOCTOU races
///   between `symlink_metadata` checks and the final open; the only
///   race-free Windows path requires `NtCreateFile` with
///   `OBJ_DONT_REPARSE`, which is undocumented and version-unstable
///   across Windows releases. See FIX 16 commit message for the
///   full architectural-decision rationale. Windows users can
///   ingest content via the `ingest_text` D-Bus method which
///   doesn't require filesystem access.
///
/// - **Other targets** (macOS, BSD, etc.): returns
///   `ErrorKind::Unsupported`. `openat2` is Linux-specific. macOS
///   could in principle implement an equivalent via repeated
///   `openat` walks with `O_NOFOLLOW`, but that work is deferred
///   until macOS becomes a deployment target.
///
/// # Caller invariants
///
/// 1. `trusted_root_handle` must have been opened with `O_DIRECTORY |
///    O_NOFOLLOW | O_CLOEXEC` at registration time (see
///    `services::knowledge::open_dir_no_follow`). The
///    `O_NOFOLLOW` flag makes the registration-time canonical
///    path the trust anchor; even if that path is later replaced
///    by a symlink, the held fd still references the original inode.
/// 2. `target` should already be canonicalized; this function
///    re-validates that target lies under the held root by
///    consulting `/proc/self/fd/<n>` to find the current canonical
///    path of the held inode.
pub fn safe_open_under_root_handle(
    trusted_root_handle: &std::fs::File,
    target: &Path,
) -> std::io::Result<std::fs::File> {
    // Thin wrapper over the shared openat2 primitive (leverage pass P2): the
    // race-free safe-open guts (openat2 RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH +
    // /proc/self/fd re-validation) now live in
    // `delphi_hardening::safe_open::open_beneath`, lifted byte-identically. This
    // site keeps the knowledge-domain non-Linux Unsupported message (the message
    // is domain-specific, so the generic primitive takes it as a parameter).
    // ValidatedIngestionPath and its path-safety test suite are unchanged — the
    // unforgeable `TrustedRoot` capability newtype is a tracked follow-up (see
    // docs/DEFECT_CLASSES.md, capability-type pattern: invariants enforced by
    // convention should be enforced by an unforgeable type).
    delphi_hardening::safe_open::open_beneath(trusted_root_handle, target, SAFE_OPEN_UNSUPPORTED_MSG)
}

/// Verbatim non-Linux `Unsupported` message for knowledge file ingestion, passed
/// to the shared safe-open primitive. The message is the *behavior* on non-Linux
/// platforms. Two tests pin it in BOTH dimensions (DEFECT_CLASSES #14 — a
/// const-only pin covers only one form): `safe_open_unsupported_message_is_verbatim`
/// checks the constant TEXT is unchanged (every platform), and — on non-Linux only —
/// `safe_open_under_root_handle_emits_unsupported_on_non_linux` CALLS the wrapper and
/// asserts the EMITTED error is `Unsupported` carrying this exact string. So the
/// byte-identical extraction cannot silently drift in either dimension.
const SAFE_OPEN_UNSUPPORTED_MSG: &str = "knowledge file ingestion is supported on Linux only in this build. \
     Linux uses openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH) anchored to a \
     held directory handle for kernel-level race-free safe-open. Windows \
     lacks a documented kernel-level equivalent (NtCreateFile + \
     OBJ_DONT_REPARSE is undocumented and version-unstable); macOS support \
     via repeated openat walks is deferred. Use the ingest_text D-Bus \
     method to ingest content without filesystem access.";

/// **Codex re-review FIX 9 (P2-medium):** infer the schema epoch from
/// the actual `sources` table SQL when no `schema_version` row is
/// recorded.
///
/// Round-1 databases (commits `bd554bf` / `2b3ca3e`) predate the
/// `schema_version` table, so on first reopen by a binary that knows
/// about epochs, the `MAX(version)` query returns NULL but the schema
/// itself is at epoch 1. We must detect that and migrate, NOT treat it
/// as a fresh install (which would no-op the schema and leave the bug
/// unfixed — exactly the scenario Codex named).
///
/// Returns:
/// - `0`: no `sources` table exists (truly fresh database).
/// - `1`: `sources` has `UNIQUE(uri, content_hash)` (round-1 layout).
/// - `2`: `sources` has `UNIQUE(uri, content_hash, format)` (current).
/// - `Err`: unrecognized schema (refuse to open rather than corrupt).
fn infer_schema_version(conn: &Connection) -> Result<i64, OrchestratorError> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sources'",
            [],
            |r| r.get(0),
        )
        .map_err(map_sqlite_err)?;
    if count == 0 {
        return Ok(0);
    }
    let create_sql: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='sources'",
            [],
            |r| r.get(0),
        )
        .map_err(map_sqlite_err)?;
    if create_sql.contains("UNIQUE(uri, content_hash, format)") {
        Ok(2)
    } else if create_sql.contains("UNIQUE(uri, content_hash)") {
        Ok(1)
    } else {
        Err(OrchestratorError::Planning(format!(
            "unrecognized sources schema; refusing to open (first 120 chars: {})",
            create_sql.chars().take(120).collect::<String>()
        )))
    }
}

/// **Codex re-review FIX 13 (P1-high):** rebuild the `sources` table
/// with the new `UNIQUE(uri, content_hash, format)` key while
/// **preserving foreign-key integrity** for `node_sources` and `edges`,
/// the `sqlite_sequence` AUTOINCREMENT counter, and the indexes.
///
/// # Why this is harder than it looks
///
/// Round-2's migration used the natural-looking sequence
/// `RENAME sources → sources_old; CREATE sources (new); INSERT; DROP sources_old`.
/// That sequence is BROKEN under modern SQLite (≥ 3.25 with default
/// `legacy_alter_table = OFF`):
///
/// 1. The first `ALTER TABLE sources RENAME TO sources_old` causes
///    SQLite to **rewrite child FK metadata** on `node_sources` and
///    `edges` so their `REFERENCES sources` becomes `REFERENCES sources_old`.
/// 2. The fresh `CREATE TABLE sources` then has no children pointing
///    at it.
/// 3. `DROP TABLE sources_old` then orphans the children's FK
///    references — they point at a table that no longer exists. With
///    FK enforcement OFF (which round-2 didn't set, so it depended on
///    the connection-default), the DROP succeeds silently and
///    referential integrity is permanently corrupted.
///
/// The round-2 tests didn't catch this because they only seeded rows
/// in `sources` itself; without `node_sources` or `edges` rows, no
/// dangling FK reference was ever observable.
///
/// # The fix: order matters
///
/// The correct sequence keeps the parent table named `sources`
/// throughout, so child FK metadata never gets rewritten:
///
/// 1. **`PRAGMA foreign_keys = OFF`** *before* `BEGIN`. SQLite
///    silently ignores this PRAGMA when a transaction is active, so
///    setting it inside `BEGIN ... COMMIT` is a no-op. The disable
///    must happen on the connection BEFORE the transaction starts.
///    It's required because the `DROP TABLE sources` step would
///    otherwise fail (or trigger cascade) on the active FK refs from
///    children.
/// 2. **`BEGIN IMMEDIATE`** — atomic boundary for the rebuild.
/// 3. **`CREATE TABLE sources_new`** with the 3-column unique key.
///    Children still reference `sources` (untouched).
/// 4. **`INSERT INTO sources_new SELECT * FROM sources`** with
///    explicit column list and IDs. The ID preservation is what
///    keeps children's FK target values valid after step 6.
/// 5. **Preserve `sqlite_sequence`** by reading the original counter
///    for `sources` and stashing it for re-application after step 6.
///    SQLite's AUTOINCREMENT counter lives in the `sqlite_sequence`
///    internal table; without explicit handling, it would reset on
///    DROP and the next inserted source would re-use a freed id.
/// 6. **`DROP TABLE sources`** — at this point children's FK metadata
///    still says `REFERENCES sources`, but no `sources` table exists.
///    The references are temporarily dangling; FK-OFF prevents this
///    from being rejected.
/// 7. **`ALTER TABLE sources_new RENAME TO sources`** — the children's
///    FK target name (`sources`) is now bound to the new table.
///    Children's FK metadata is NOT rewritten because we're renaming
///    `sources_new`, which has no inbound FK references.
/// 8. **Re-apply** the stashed `sqlite_sequence` row.
/// 9. **Recreate** the three sources indexes.
/// 10. **`COMMIT`**.
/// 11. **`PRAGMA foreign_keys = ON`** — restore enforcement.
/// 12. **`PRAGMA foreign_key_check`** — verify no orphan rows. If any
///     exist, refuse to mark the migration complete.
/// 13. Insert the version-2 row in `schema_version` (unchanged from
///     round-2; idempotent via `INSERT OR IGNORE`).
///
/// # Atomicity
///
/// If any statement inside `BEGIN ... COMMIT` fails, SQLite rolls back
/// the transaction and the database stays at epoch 1. The PRAGMA
/// changes outside the transaction are per-connection: re-enabling FK
/// after a rollback is harmless because the original schema is
/// untouched. If the post-commit `foreign_key_check` reports orphan
/// rows (which would indicate the migration logic is wrong), we return
/// `Err` without writing the version-2 row, leaving the database in
/// epoch-2 schema with a missing version row — a recoverable state
/// the next call to `init_schema` will diagnose explicitly.
///
/// # Why `&mut Connection`?
///
/// `rusqlite::Connection::transaction()` requires an exclusive
/// mutable borrow because the returned `Transaction` holds a borrow
/// against the connection for its lifetime. The change in signature
/// from `&Connection` to `&mut Connection` propagates one level up
/// to `init_schema`, which already owns the connection at that point
/// (it's called from `KnowledgeStore::open` immediately after
/// `Connection::open`). No public API change.
/// **Codex re-review FIX 17 (P1-high):** atomically backfill the
/// `schema_version` row for a database whose schema is already
/// structurally at [`CURRENT_SCHEMA_VERSION`] but has no recorded
/// version row.
///
/// # Why this exists
///
/// A database can reach this state in two ways:
/// 1. **Round-3 broken migration.** Round-3 ran
///    `PRAGMA foreign_key_check` and wrote the version row AFTER
///    `tx.commit()`. If the post-commit FK check found violations,
///    the function returned `Err` — but the schema rebuild had
///    already committed. The database was left structurally epoch-2
///    with no version row.
/// 2. **Operator schema repair.** An operator may have rebuilt
///    `sources` via direct SQL while restoring from backup and
///    forgotten to insert the version row. Same shape.
///
/// Round-4's `init_schema` "current epoch" arm noticed this missing
/// version row and inserted version=2 unconditionally. But `PRAGMA
/// foreign_keys = ON` (FIX 12) does NOT validate existing orphan
/// rows — it only enforces FK constraints on subsequent
/// inserts/updates. So a database with orphan `node_sources` /
/// `edges` from the round-3 path was permanently marked "valid
/// epoch-2" on the very next open, accepting the corruption.
///
/// **F17 fix:** run `PRAGMA foreign_key_check` AND the version-row
/// INSERT inside a single transaction. Rusqlite's
/// `DropBehavior::Rollback` guarantees that any failure (including
/// the FK check returning violations) reverts the entire operation
/// atomically. The database is then either:
/// - fully epoch-2 with verified clean integrity AND a recorded
///   version row, or
/// - exactly the input state — no version row, no other side
///   effects.
///
/// Operator can then either repair the orphan rows via direct SQL
/// or restore from backup before reopening.
///
/// **Codex re-review FIX 19 (P2-medium):** the transaction is opened
/// `BEGIN IMMEDIATE` and the helper re-reads `schema_version` under
/// that write lock before doing any work. This makes the helper safe
/// under concurrent opens of the same database file — two openers
/// serialize at BEGIN, and whichever loses the lock race re-reads the
/// now-present version row and returns Ok rather than colliding on
/// the INSERT. See the inline comments for the full rationale.
fn backfill_version_with_integrity_check(
    conn: &mut Connection,
) -> Result<(), OrchestratorError> {
    // **Codex re-review FIX 19 (P2-medium) — concurrent-open race.**
    //
    // Round-5 opened this with the rusqlite DEFAULT (DEFERRED)
    // transaction. A DEFERRED transaction takes its RESERVED write
    // lock only on the first WRITE statement — not at BEGIN. Two
    // openers of the same clean unversioned epoch-2 DB could
    // therefore both pass the outer `recorded.is_none()` check in
    // `init_schema`, both run `foreign_key_check` under independent
    // SHARED locks (SHARED readers coexist), and then race on the
    // version-row INSERT: one wins the RESERVED lock and commits,
    // the other gets SQLITE_BUSY ("database is locked") or a UNIQUE
    // violation — failing a legitimate opener against a database
    // that was already structurally valid.
    //
    // FIX 19: open with `TransactionBehavior::Immediate` (BEGIN
    // IMMEDIATE). This acquires the RESERVED write lock at BEGIN,
    // BEFORE any read. Concurrent backfillers serialize at BEGIN —
    // exactly one acquires RESERVED, the other receives SQLITE_BUSY
    // at the BEGIN statement, which the connection's `busy_timeout`
    // (set in `KnowledgeStore::open`) retries until the winner
    // commits and releases the lock.
    //
    // Atomicity is unchanged from FIX 14 / FIX 17: any `?`-early-exit
    // drops the Transaction, whose rusqlite default
    // `DropBehavior::Rollback` reverts every step.
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(map_sqlite_err)?;

    // FIX 19 — double-checked locking, AUTHORITATIVE half. The outer
    // `recorded.is_none()` check in `init_schema` ran WITHOUT a write
    // lock, so a concurrent opener may have completed the backfill in
    // the window between that check and our BEGIN IMMEDIATE. Re-read
    // `schema_version` now that we hold RESERVED:
    //   - `Some(CURRENT_SCHEMA_VERSION)`: a peer finished the backfill
    //     first. We have written nothing; commit the (empty)
    //     transaction to release the write lock promptly and return
    //     Ok — the database is valid and versioned.
    //   - `Some(other)`: unexpected schema drift under the write lock.
    //     Roll back (Transaction Drop) and surface a mismatch error
    //     rather than silently proceeding.
    //   - `None`: still unversioned under the write lock — proceed
    //     with the FK check + version insert below. The INSERT stays
    //     a plain INSERT (not OR IGNORE) precisely because we just
    //     confirmed `None` while holding the exclusive write intent:
    //     no peer can insert the row before we commit.
    let recorded_under_lock: Option<i64> = tx
        .query_row(
            "SELECT MAX(version) FROM schema_version",
            [],
            |r| r.get::<_, Option<i64>>(0),
        )
        .optional()
        .map_err(map_sqlite_err)?
        .flatten();
    match recorded_under_lock {
        Some(v) if v == CURRENT_SCHEMA_VERSION => {
            // A concurrent opener completed the backfill in the
            // check → BEGIN window. Nothing to write; commit the
            // empty transaction to release the write lock promptly.
            tx.commit().map_err(map_sqlite_err)?;
            return Ok(());
        }
        Some(v) => {
            // Drop on `tx` rolls back. In practice unreachable —
            // `init_schema` only routes here when the structure is
            // already `CURRENT_SCHEMA_VERSION` and `recorded` was
            // `None` — but surfacing it loudly guards against future
            // schema-drift bugs instead of silently proceeding.
            return Err(OrchestratorError::Planning(format!(
                "schema_version unexpectedly holds version {v} under the write lock \
                 (expected no row or {CURRENT_SCHEMA_VERSION}); refusing to backfill"
            )));
        }
        None => {
            // Still unversioned under the write lock — fall through
            // to the FK check + version insert below.
        }
    }

    // PRAGMA foreign_key_check is a SELECT-shaped diagnostic (not
    // a state-mutating pragma like `foreign_keys = ON/OFF`), so it
    // IS valid inside transactions. Returns one row per orphan:
    // (child_table, child_rowid, parent_table, fk_index).
    let violations: Vec<(String, i64, String, i64)> = {
        let mut stmt = tx
            .prepare("PRAGMA foreign_key_check")
            .map_err(map_sqlite_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .map_err(map_sqlite_err)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(map_sqlite_err)?
    };

    if !violations.is_empty() {
        // Drop on `tx` triggers automatic ROLLBACK — no version row
        // is written; the database stays unversioned-but-
        // structurally-current. Listing the first few violations
        // in the error message helps the operator diagnose; this
        // is a local error (not crossed-D-Bus per FIX 7) so
        // referencing row identities is safe.
        let preview: Vec<_> = violations.iter().take(3).collect();
        return Err(OrchestratorError::Planning(format!(
            "schema appears current (epoch {}) but has {} foreign-key violation(s) \
             from a prior incomplete migration (first {} shown): {:?}; \
             refusing to backfill schema_version. Repair orphan rows via direct SQL \
             before reopening, or restore from backup.",
            CURRENT_SCHEMA_VERSION,
            violations.len(),
            preview.len(),
            preview
        )));
    }

    // FK check clean — record the version row inside the same
    // transaction. If a row already exists (e.g., from a concurrent
    // init by another connection), the PRIMARY KEY conflict fails
    // here and the rollback covers both steps. We use plain INSERT
    // (not OR IGNORE): this branch only runs when recorded.is_none(),
    // so any existing row is a logic bug we want to surface.
    tx.execute(
        "INSERT INTO schema_version (version) VALUES (?1)",
        params![CURRENT_SCHEMA_VERSION],
    )
    .map_err(map_sqlite_err)?;

    tx.commit().map_err(map_sqlite_err)?;
    Ok(())
}

fn migrate_epoch_1_to_2(conn: &mut Connection) -> Result<(), OrchestratorError> {
    // **Codex re-review FIX 14 (P1-high) — atomicity of integrity check.**
    //
    // Round-3 ran `PRAGMA foreign_key_check` AFTER `tx.commit()` and
    // wrote the version row in a separate post-commit statement. If
    // the FK check found pre-existing orphan rows (or errored), the
    // function returned `Err`, but the database was already at
    // epoch-2 structure with no recorded version. On the next open,
    // `infer_schema_version` would observe the 3-column UNIQUE key,
    // classify the database as epoch-2 by structure, and the
    // current-epoch branch of `init_schema` would silently backfill
    // the version row WITHOUT rerunning the integrity check —
    // accepting a corrupted graph.
    //
    // The FIX 14 boundary: schema rebuild + integrity check + version
    // row write are now ONE atomic transaction. Any failure of any
    // step rolls everything back via Transaction's `Drop::drop` →
    // `finish_()` → `rollback_()` (rusqlite default `DropBehavior::Rollback`).
    // The database is then either:
    //   - fully epoch-2 with clean integrity AND a recorded version, or
    //   - fully epoch-1, untouched.
    // No middle state exists where infer_schema_version could be
    // fooled into backfilling a bad rebuild.
    //
    // SQLite supports `PRAGMA foreign_key_check` inside transactions
    // (it's a SELECT-shaped diagnostic, not a state-mutating PRAGMA
    // like `foreign_keys = ON/OFF` which IS silently ignored inside
    // tx). Verified against SQLite docs and via the test below.

    // Disable FK enforcement BEFORE BEGIN. PRAGMA foreign_keys = ON/OFF
    // is silently ignored inside a transaction; the disable must
    // happen on the connection first. We need it OFF so that the
    // DROP/RENAME shuffle below (which temporarily orphans child
    // FK references) doesn't trip enforcement during the rebuild.
    conn.execute_batch("PRAGMA foreign_keys = OFF;")
        .map_err(map_sqlite_err)?;

    // Run the migration body inside an immediately-invoked closure
    // so we can use `?` for early exits and let the Transaction's
    // Drop impl roll back automatically on the error path. The
    // closure captures `conn` by mutable borrow only for the
    // transaction's lifetime — once it returns (Ok or Err) the
    // borrow ends and we can re-enable FK enforcement.
    let migration_result: Result<(), OrchestratorError> = (|| {
        let tx = conn.transaction().map_err(map_sqlite_err)?;

        // Stash the original AUTOINCREMENT counter for `sources` so
        // we can re-apply it after the DROP+RENAME. If sqlite_sequence
        // has no row (table never had inserts), the Option is None
        // and we leave the counter alone — nothing to preserve.
        let original_seq: Option<i64> = tx
            .query_row(
                "SELECT seq FROM sqlite_sequence WHERE name = 'sources'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_sqlite_err)?;

        // Build the new sources table under a temporary name. Child
        // FK metadata on `node_sources` and `edges` still references
        // the literal name "sources" — untouched.
        tx.execute_batch(
            r#"
            CREATE TABLE sources_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_type TEXT NOT NULL,
                uri TEXT NOT NULL,
                ingested_at_unix INTEGER NOT NULL,
                fidelity TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                format TEXT NOT NULL,
                UNIQUE(uri, content_hash, format)
            );
            "#,
        )
        .map_err(map_sqlite_err)?;

        // Copy rows verbatim with explicit IDs so `node_sources.source_id`
        // and `edges.source_id` resolve correctly after the rename.
        tx.execute_batch(
            r#"
            INSERT INTO sources_new (id, source_type, uri, ingested_at_unix, fidelity, content_hash, format)
                SELECT id, source_type, uri, ingested_at_unix, fidelity, content_hash, format
                FROM sources;
            "#,
        )
        .map_err(map_sqlite_err)?;

        // DROP old sources, then RENAME sources_new → sources.
        // Children's FK metadata stays bound to the literal name
        // "sources" throughout — never gets rewritten — and resolves
        // correctly after the RENAME restores the target name.
        tx.execute_batch("DROP TABLE sources;")
            .map_err(map_sqlite_err)?;
        tx.execute_batch("ALTER TABLE sources_new RENAME TO sources;")
            .map_err(map_sqlite_err)?;

        // Re-apply the stashed AUTOINCREMENT counter. SQLite tracks
        // sqlite_sequence rows by name; after the RENAME above, the
        // row name will already be "sources". INSERT OR REPLACE
        // handles both the "sqlite_sequence row exists for sources"
        // and "no row yet" cases.
        if let Some(seq) = original_seq {
            tx.execute(
                "INSERT OR REPLACE INTO sqlite_sequence (name, seq) VALUES ('sources', ?1)",
                params![seq],
            )
            .map_err(map_sqlite_err)?;
        }

        // Recreate the three indexes that lived on epoch-1's sources.
        // These were dropped along with the old table.
        tx.execute_batch(
            r#"
            CREATE INDEX idx_sources_uri ON sources(uri);
            CREATE INDEX idx_sources_format ON sources(format);
            CREATE INDEX idx_sources_ingested ON sources(ingested_at_unix);
            "#,
        )
        .map_err(map_sqlite_err)?;

        // FIX 14 part A: run `PRAGMA foreign_key_check` INSIDE the
        // transaction. The query returns one row per orphaned child,
        // so an empty result set means clean integrity.
        //
        // We collect into a Vec so we can release the borrow on `tx`
        // before the version-row insert below (rusqlite's prepared
        // statement holds an immutable borrow on `tx` for its
        // lifetime, which would conflict with `tx.execute()`).
        let violations: Vec<(String, i64, String, i64)> = {
            let mut stmt = tx
                .prepare("PRAGMA foreign_key_check")
                .map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?, // child table name
                        r.get::<_, i64>(1)?,    // child rowid
                        r.get::<_, String>(2)?, // parent table name
                        r.get::<_, i64>(3)?,    // FK index
                    ))
                })
                .map_err(map_sqlite_err)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(map_sqlite_err)?
        };
        if !violations.is_empty() {
            // Returning Err here triggers Transaction::Drop →
            // finish_() → rollback_(), reverting the entire schema
            // rebuild AND ensuring no version row gets written.
            // The error message is local-only (not crossed-D-Bus per
            // FIX 7) so listing the violation count + first 3 entries
            // for operator diagnostics is safe.
            let preview: Vec<_> = violations.iter().take(3).collect();
            return Err(OrchestratorError::Planning(format!(
                "schema migration would leave {} foreign-key violation(s) \
                 (first {} shown): {:?}; aborting and rolling back to epoch 1",
                violations.len(),
                preview.len(),
                preview
            )));
        }

        // FIX 14 part B: write the version row INSIDE the same
        // transaction. Either we commit with version=2 AND clean
        // integrity together, or both roll back together. There's
        // no window where infer_schema_version sees epoch-2
        // structure without a recorded version, so the
        // current-epoch backfill path can never accept a corrupt
        // graph silently.
        //
        // Plain INSERT (not OR IGNORE): a fresh epoch-1 → epoch-2
        // migration on a database that already has a version row
        // is a logic bug we want to surface, not paper over. The
        // init_schema match arm guarantees this branch only runs
        // when version is inferred as 1 with no recorded row.
        tx.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            params![CURRENT_SCHEMA_VERSION],
        )
        .map_err(map_sqlite_err)?;

        // Atomic commit boundary. If any prior `?` returned Err,
        // we never reach here and Drop rolls back. If commit itself
        // fails (extremely rare — SQLITE_FULL, I/O error), the
        // Drop on the partly-committed Transaction will also try to
        // roll back; even if both fail, the database file's atomic
        // journal mechanism guarantees that on next open SQLite
        // recovers to either pre-tx or post-commit state, never
        // partial.
        tx.commit().map_err(map_sqlite_err)?;
        Ok(())
    })();

    // Re-enable FK enforcement on this connection regardless of
    // migration outcome. After a successful commit this just
    // restores normal operating mode for subsequent queries; after
    // a rollback it brings the connection back into the same FK-on
    // state that init_schema set at the top of the call. Subsequent
    // `Connection::open` calls also re-enable via FIX 12's
    // init_schema verification step.
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .map_err(map_sqlite_err)?;

    migration_result
}

// ────────────────────────────────────────────────────────────────────
// Row helpers + error mappers
// ────────────────────────────────────────────────────────────────────

fn row_to_source(row: &rusqlite::Row<'_>) -> rusqlite::Result<Source> {
    let id: i64 = row.get(0)?;
    let st: String = row.get(1)?;
    let uri: String = row.get(2)?;
    let ts: i64 = row.get(3)?;
    let fid: String = row.get(4)?;
    let hash: String = row.get(5)?;
    let format: String = row.get(6)?;
    Ok(Source {
        id,
        source_type: SourceType::from_str(&st)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(SimpleErr(e.to_string()))))?,
        uri,
        ingested_at: DateTime::<Utc>::from_timestamp(ts, 0).unwrap_or_else(Utc::now),
        fidelity: parse_fidelity(&fid),
        content_hash: hash,
        format,
    })
}

fn row_to_node(row: &rusqlite::Row<'_>) -> rusqlite::Result<KnowledgeNode> {
    let id: i64 = row.get(0)?;
    let content: String = row.get(1)?;
    let nt: String = row.get(2)?;
    let created: i64 = row.get(3)?;
    let accessed: i64 = row.get(4)?;
    let count: i64 = row.get(5)?;
    Ok(KnowledgeNode {
        id,
        content,
        node_type: NodeType::from_str(&nt)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(SimpleErr(e.to_string()))))?,
        source_ids: Vec::new(),
        created_at: DateTime::<Utc>::from_timestamp(created, 0).unwrap_or_else(Utc::now),
        last_accessed: DateTime::<Utc>::from_timestamp(accessed, 0).unwrap_or_else(Utc::now),
        access_count: count.max(0) as u32,
    })
}

fn row_to_edge(row: &rusqlite::Row<'_>) -> rusqlite::Result<KnowledgeEdge> {
    let id: i64 = row.get(0)?;
    let from_id: i64 = row.get(1)?;
    let to_id: i64 = row.get(2)?;
    let rel: String = row.get(3)?;
    let conf: f64 = row.get(4)?;
    let src: i64 = row.get(5)?;
    let created: i64 = row.get(6)?;
    Ok(KnowledgeEdge {
        id,
        from_id,
        to_id,
        relation: EdgeRelation::from_str(&rel)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(SimpleErr(e.to_string()))))?,
        confidence: conf as f32,
        source_id: src,
        created_at: DateTime::<Utc>::from_timestamp(created, 0).unwrap_or_else(Utc::now),
    })
}

fn parse_fidelity(s: &str) -> Fidelity {
    match s {
        "direct" => Fidelity::Direct,
        "native_api" => Fidelity::NativeApi,
        "subprocess" => Fidelity::Subprocess,
        _ => Fidelity::Unavailable,
    }
}

/// **Codex re-review FIX 20 (round 7):** the single-attempt open path
/// extracted from [`KnowledgeStore::open`] for the retry loop.
///
/// Opens a connection at `db_path`, applies the project-standard
/// `busy_timeout` policy (5s, explicit per CLAUDE.md SQLite policy
/// rather than relying on rusqlite's default which is documented as
/// "subject to change"), and runs `init_schema` — which may route into
/// the backfill helper that opens `BEGIN IMMEDIATE` and can therefore
/// surface [`OrchestratorError::TransientLock`] under contention.
///
/// On `TransientLock` the caller (`retry_with_backoff`) sleeps and
/// reattempts; on any other error the caller short-circuits and
/// propagates the error unchanged.
fn try_open_and_backfill_once(db_path: &Path) -> Result<Connection, OrchestratorError> {
    let mut conn = Connection::open(db_path).map_err(map_sqlite_err)?;
    // **Codex re-review FIX 22 (round 8):** route through the shared
    // `crate::sqlite::init_sqlite_connection` helper rather than
    // calling `conn.busy_timeout` directly. Single seam for the
    // project-wide connection-init policy.
    crate::sqlite::init_sqlite_connection(&conn).map_err(map_sqlite_err)?;
    KnowledgeStore::init_schema(&mut conn)?;
    Ok(conn)
}

/// **Codex re-review FIX 20 (round 7):** retry-with-exponential-backoff
/// loop. Re-attempts `op` only when it returns
/// [`OrchestratorError::TransientLock`]; any other error short-circuits
/// immediately. Sleeps `INITIAL_BACKOFF_MS`, doubles up to
/// `MAX_BACKOFF_MS`, gives up after `MAX_OPEN_ATTEMPTS` attempts and
/// surfaces the most recent `TransientLock` unchanged so callers can
/// still pattern-match for typed retry.
///
/// **Jitter:** drawn from `SystemTime::now()`'s sub-second nanoseconds
/// modulo `backoff_ms / 2`. This gives a per-call non-deterministic
/// 0..50% jitter without pulling in the `rand` crate as a new
/// orchestrator dep — the nanosecond precision naturally desyncs
/// threads that fall into the retry path at the same instant. If the
/// system clock is unavailable (shouldn't happen on Linux/Windows),
/// jitter falls back to 0 and the exponential backoff alone provides
/// desync over multiple attempts.
///
/// Generic over `T` so the same retry mechanism can be unit-tested
/// with `T = ()` (driven by a mock closure) without opening an actual
/// database connection.
fn retry_with_backoff<T, F>(mut op: F) -> Result<T, OrchestratorError>
where
    F: FnMut() -> Result<T, OrchestratorError>,
{
    let mut attempt: usize = 0;
    let mut backoff_ms: u64 = INITIAL_BACKOFF_MS;
    loop {
        match op() {
            Ok(v) => return Ok(v),
            Err(OrchestratorError::TransientLock { .. })
                if attempt < MAX_OPEN_ATTEMPTS - 1 =>
            {
                let jitter_nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| u64::from(d.subsec_nanos()))
                    .unwrap_or(0);
                let jitter = jitter_nanos % (backoff_ms / 2).max(1);
                std::thread::sleep(std::time::Duration::from_millis(
                    backoff_ms.saturating_add(jitter),
                ));
                attempt += 1;
                backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Translate a `rusqlite::Error` into the orchestrator's error type.
///
/// **Codex re-review FIX 22 (round 8):** this is now a thin wrapper
/// around the shared [`crate::sqlite::map_sqlite_err`] helper — the
/// canonical project-wide mapping per the CLAUDE.md SQLite Connection
/// Policy. The wrapper preserves the historical "knowledge sqlite"
/// context prefix on `Planning` errors so existing test message
/// assertions stay stable; lock errors (which round through
/// `TransientLock` regardless of context) are routed identically to
/// the shared helper.
///
/// All knowledge.rs call sites continue to call this as
/// `map_sqlite_err(e)` (single-arg form); the context is implicit.
/// Sibling stores in `timeline.rs`, `goals.rs`, `conversation.rs` call
/// the shared helper directly with per-store / per-call-site context
/// strings.
fn map_sqlite_err(e: rusqlite::Error) -> OrchestratorError {
    crate::sqlite::map_sqlite_err(e, "knowledge sqlite")
}

fn map_lock_err<T>(_: std::sync::PoisonError<T>) -> OrchestratorError {
    OrchestratorError::Planning("knowledge store lock poisoned".to_string())
}

#[derive(Debug)]
struct SimpleErr(String);
impl std::fmt::Display for SimpleErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for SimpleErr {}

// ────────────────────────────────────────────────────────────────────
// Ingestion access control (services-sweep SVC-8)
//
// The closed-by-default allowlist, sensitive-content denylist,
// canonicalization, and held-directory-handle machinery used to live in
// the `delphi-services` transport (`services/src/knowledge.rs`). SVC-8
// relocates the security boundary into the domain so the policy is
// enforced at the type level: `KnowledgeStore::ingest_validated_file`
// only accepts a `ValidatedIngestionPath`, and the sole constructor of
// that token is `IngestionAccessController::validate`. A transport — or
// any future domain caller — therefore cannot ingest a file without
// first clearing the full gate; the allowlist can no longer be bypassed
// by fabricating a raw directory handle. This preserves the
// 9-round-hardened F4 (closed-by-default), F7 (uniform rejection / no
// filesystem-existence oracle), and F15 (held-handle, single-lock atomic
// validate-and-pickup) properties from Task 3A.5; their regression tests
// move here with the logic.
// ────────────────────────────────────────────────────────────────────

/// Directory names that must never be ingested, regardless of allowlist.
/// Compared component-wise (case-insensitive ASCII) against the
/// canonicalized path. A path containing any of these as a component is
/// rejected even if the user explicitly added a parent dir to the
/// allowlist.
///
/// Codex review (FIX 4 round) flagged the original allowlist as
/// insufficient: even an opt-in allowlist that includes the user's home
/// can pull keys/credentials/tokens. This denylist provides a safety net
/// the allowlist cannot override.
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
/// Takes only `&Path` and performs no I/O — a pure classifier suitable
/// for unit testing without temp dirs or fixtures.
#[must_use]
pub fn is_sensitive_path(path: &Path) -> bool {
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

/// An allowlisted ingestion root, anchored to a held directory handle
/// rather than a re-resolvable path string (Codex re-review FIX 15,
/// P1-high).
///
/// The handle's identity (the kernel inode behind the fd) is the trust
/// anchor — it survives renames, resists symlink swaps, and is what the
/// `openat2` safe-open passes as its `dirfd`. Opening the directory ONCE
/// at registration (with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`) closes
/// the round-3 race where `safe_open_under_root` re-opened a path string
/// that an attacker could swap for a symlink between registration and
/// use. `Arc<File>` lets the token clone the handle cheaply; the fd
/// closes when the last clone drops.
#[derive(Debug, Clone)]
struct AllowlistRoot {
    /// Canonical path captured at registration time. Used for the
    /// `starts_with` allowlist prefix check.
    canonical_path: PathBuf,
    /// Held directory handle. On Linux opened with `O_DIRECTORY |
    /// O_NOFOLLOW | O_CLOEXEC`; on non-Linux platforms registration
    /// itself fails so this is never constructed there.
    dir_handle: Arc<std::fs::File>,
}

/// Open a directory at `path` with no-follow + close-on-exec semantics,
/// producing the held handle that anchors an [`AllowlistRoot`].
///
/// **Linux**: `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`. `O_NOFOLLOW`
/// rejects a final-component symlink (so the registered path itself
/// cannot be a symlink); `O_DIRECTORY` rejects regular files at the
/// registered path; `O_CLOEXEC` keeps the fd from surviving a
/// `fork+exec` (defense in depth against fd leakage to subprocess
/// managers).
///
/// **Non-Linux**: returns `ErrorKind::Unsupported` (FIX 16). Windows'
/// kernel-level path-anchored opens require undocumented NT APIs we do
/// not depend on at this build stage, and macOS support via repeated
/// `openat` walks is deferred.
fn open_dir_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "knowledge ingestion requires Linux (O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC). \
             Windows and other Unix variants are not supported in this build — see \
             FIX 16 rationale. Use ingest_text instead.",
        ))
    }
}

/// Why an ingestion path was denied. Used for **local audit logging
/// only** — the transport collapses every variant to a single uniform
/// wire message so no filesystem-existence oracle leaks across the bus
/// (Codex re-review FIX 7, P1-high).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestionDenied {
    /// Allowlist is empty — ingestion closed by default (FIX 4).
    AllowlistEmpty,
    /// `canonicalize()` failed — path doesn't exist or can't be resolved.
    Unresolvable,
    /// Canonical path doesn't start with any allowlist root.
    OutsideAllowlist,
    /// Path matches the sensitive-content denylist ([`is_sensitive_path`]).
    SensitivePath,
}

impl IngestionDenied {
    /// Short, stable label for the structured tracing audit field. These
    /// exact strings are asserted by the audit-log regression test, so
    /// keep them stable.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            IngestionDenied::AllowlistEmpty => "allowlist empty",
            IngestionDenied::Unresolvable => "unresolvable or does not exist",
            IngestionDenied::OutsideAllowlist => "outside allowlist",
            IngestionDenied::SensitivePath => "matches sensitive-content denylist",
        }
    }
}

impl std::fmt::Display for IngestionDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::error::Error for IngestionDenied {}

/// Failure from [`IngestionAccessController::validate`].
///
/// Two classes, deliberately distinct so the transport can map them to
/// different wire shapes:
///
/// - [`IngestionError::Denied`] — the access-control gate refused the
///   path. The inner [`IngestionDenied`] reason is for local audit only;
///   the transport collapses **every** denial to one uniform
///   `AccessDenied` message (FIX 7 — no filesystem-existence oracle).
/// - [`IngestionError::Internal`] — an invariant failed (e.g. the
///   allowlist mutex was poisoned by a panicking thread). A bug, not an
///   access decision, so the transport surfaces it as a generic failure
///   rather than "your path isn't allowed".
#[derive(Debug)]
pub enum IngestionError {
    /// The path was denied by the access-control gate.
    Denied(IngestionDenied),
    /// An internal invariant failed (e.g. a poisoned allowlist lock).
    Internal(&'static str),
}

impl std::fmt::Display for IngestionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngestionError::Denied(r) => write!(f, "ingestion denied: {r}"),
            IngestionError::Internal(m) => write!(f, "ingestion access check failed: {m}"),
        }
    }
}

impl std::error::Error for IngestionError {}

/// Log a denial (audit) and wrap it as an [`IngestionError::Denied`].
///
/// This is the domain analog of the transport's former `reject()`: the
/// detailed reason **and the raw caller path** go to the local `tracing`
/// log for operator diagnostics; the returned error carries only the
/// [`IngestionDenied`] category (no path), and the transport will discard
/// even that in favour of one uniform wire message.
fn deny(reason: IngestionDenied, raw: &str) -> IngestionError {
    tracing::warn!(
        reason = reason.as_str(),
        raw_path = %raw,
        "knowledge ingestion path rejected"
    );
    IngestionError::Denied(reason)
}

/// A capability token proving a path cleared the full ingestion
/// access-control gate, bundled with the held directory handle that
/// anchored the decision (SVC-8).
///
/// **The only constructor is [`IngestionAccessController::validate`].**
/// Fields are private, so a caller cannot fabricate a token to bypass the
/// gate — and [`KnowledgeStore::ingest_validated_file`] requires one, so
/// possession of a token *is* proof of authorization (the capability
/// pattern).
///
/// In-flight, the token holds an `Arc<File>` for the trusted root — Unix
/// open-fd semantics: the kernel inode the handle references stays valid
/// for the token's lifetime even if the path string is renamed or swapped
/// (FIX 15).
#[derive(Debug, Clone)]
pub struct ValidatedIngestionPath {
    canonical: PathBuf,
    root_handle: Arc<std::fs::File>,
}

impl ValidatedIngestionPath {
    /// The canonicalized path that cleared the gate. (The held root
    /// handle is intentionally not exposed — it is an internal trust
    /// anchor, mirroring [`IngestionAccessController::snapshot`].)
    #[must_use]
    pub fn canonical(&self) -> &Path {
        &self.canonical
    }
}

/// The ingestion access-control gate: a closed-by-default allowlist of
/// held directory handles plus the sensitive-content denylist (SVC-8).
///
/// Owns the security policy that used to live in the transport. The only
/// way to obtain a [`ValidatedIngestionPath`] — and therefore the only
/// way to reach [`KnowledgeStore::ingest_validated_file`] — is
/// [`validate`](Self::validate).
///
/// # Examples
///
/// ```
/// use die_orchestrator::knowledge::IngestionAccessController;
///
/// // Closed by default: an empty allowlist denies every path.
/// let gate = IngestionAccessController::new();
/// assert!(gate.snapshot().is_empty());
/// assert!(gate.validate("/etc/passwd").is_err());
/// ```
#[derive(Debug, Default)]
pub struct IngestionAccessController {
    /// Allowlisted base directories, anchored to held directory handles.
    /// Empty → no path is permitted (closed by default, FIX 4).
    allowlist: Mutex<Vec<AllowlistRoot>>,
}

impl IngestionAccessController {
    /// Build a gate with an **empty** allowlist (closed by default, FIX
    /// 4): every [`validate`](Self::validate) call returns
    /// [`IngestionDenied::AllowlistEmpty`] until a root is registered via
    /// [`add_root`](Self::add_root).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a gate with an explicit allowlist of base directories. Each
    /// entry is canonicalized AND opened as a held directory handle (FIX
    /// 15); entries that fail either step are silently dropped (so on
    /// non-Linux, where `open_dir_no_follow` is unsupported, the result is
    /// an empty allowlist). Useful for tests and for daemon code that
    /// pre-registers roots from saved settings.
    #[must_use]
    pub fn with_roots(roots: Vec<PathBuf>) -> Self {
        let entries: Vec<AllowlistRoot> = roots
            .into_iter()
            .filter_map(|p| {
                let canon = std::fs::canonicalize(&p).ok()?;
                let handle = open_dir_no_follow(&canon).ok()?;
                Some(AllowlistRoot {
                    canonical_path: canon,
                    dir_handle: Arc::new(handle),
                })
            })
            .collect();
        Self {
            allowlist: Mutex::new(entries),
        }
    }

    /// Add a base directory to the allowlist. Returns `true` if the path
    /// was added (canonicalization AND directory-handle open both
    /// succeeded and it wasn't already present); `false` otherwise.
    ///
    /// The directory is opened with `O_DIRECTORY | O_NOFOLLOW |
    /// O_CLOEXEC` ONCE at registration time and the handle retained for
    /// the gate's lifetime (FIX 15), anchoring trust to a kernel inode
    /// rather than a re-resolvable path string. `O_NOFOLLOW` means the
    /// registered path itself cannot be a symlink; combined with the
    /// `canonicalize` call, this gives "canonical path AND no-follow open"
    /// at registration.
    pub fn add_root(&self, root: &Path) -> bool {
        let Ok(canon) = std::fs::canonicalize(root) else {
            return false;
        };
        let Ok(handle) = open_dir_no_follow(&canon) else {
            return false;
        };
        let Ok(mut allow) = self.allowlist.lock() else {
            return false;
        };
        if allow.iter().any(|entry| entry.canonical_path == canon) {
            return false;
        }
        allow.push(AllowlistRoot {
            canonical_path: canon,
            dir_handle: Arc::new(handle),
        });
        true
    }

    /// Snapshot of currently-allowed canonical root paths — for
    /// diagnostics and tests. Returns paths only; the held handles are
    /// intentionally not exposed (they are an internal trust anchor).
    #[must_use]
    pub fn snapshot(&self) -> Vec<PathBuf> {
        self.allowlist
            .lock()
            .map(|a| a.iter().map(|e| e.canonical_path.clone()).collect())
            .unwrap_or_default()
    }

    /// Validate a caller-supplied path against the allowlist + denylist
    /// and, on success, issue a [`ValidatedIngestionPath`] carrying the
    /// matching root's held directory handle.
    ///
    /// **Order matters (FIX 7):** the empty-allowlist check runs BEFORE
    /// canonicalization, so a closed-by-default gate performs no
    /// filesystem syscall and cannot be used as an existence oracle.
    ///
    /// **Single-lock atomicity (FIX 15):** the allowlist lock is held
    /// through the empty-check, canonicalization, prefix match, AND
    /// handle pickup, so a concurrent [`add_root`](Self::add_root) cannot
    /// reshape the allowlist between the prefix match and the handle
    /// clone — the returned `Arc<File>` is guaranteed to be the handle
    /// that gated this request.
    ///
    /// # Errors
    ///
    /// - [`IngestionError::Denied`] with the specific [`IngestionDenied`]
    ///   reason (logged locally; the transport surfaces a uniform
    ///   message). Returned for empty allowlist, unresolvable path,
    ///   outside-allowlist, or sensitive-content-denylist hits.
    /// - [`IngestionError::Internal`] if the allowlist mutex is poisoned.
    pub fn validate(&self, raw: &str) -> Result<ValidatedIngestionPath, IngestionError> {
        // Hold the lock through validation AND handle pickup so a
        // concurrent add_root cannot reshape the allowlist between the
        // prefix match and the handle clone (FIX 15).
        let allow = self.allowlist.lock().map_err(|_| {
            tracing::error!("knowledge ingestion allowlist mutex poisoned");
            IngestionError::Internal("allowlist lock poisoned")
        })?;

        // FIX 7 part A: short-circuit on empty allowlist BEFORE any
        // filesystem syscall. Closed-by-default → no probe oracle.
        if allow.is_empty() {
            return Err(deny(IngestionDenied::AllowlistEmpty, raw));
        }

        // Allowlist is non-empty; canonicalization is justified. The lock
        // is held during this syscall — preferable to round-3's race
        // where the lock dropped between the prefix match and handle clone.
        let canon =
            std::fs::canonicalize(raw).map_err(|_| deny(IngestionDenied::Unresolvable, raw))?;

        // Find the matching root and clone its Arc<File>. Both the
        // canonical_path (prefix match) and the dir_handle (for the
        // safe-open) come from the same AllowlistRoot, eliminating any
        // chance of a path/handle mismatch.
        let matched = allow
            .iter()
            .find(|entry| canon.starts_with(&entry.canonical_path))
            .ok_or_else(|| deny(IngestionDenied::OutsideAllowlist, raw))?;
        let root_handle = Arc::clone(&matched.dir_handle);

        // FIX 4 retained: denylist runs AFTER allowlist so we never signal
        // "this file exists but is denylisted" with a different rejection
        // reason than "this file isn't in your allowlist".
        if is_sensitive_path(&canon) {
            return Err(deny(IngestionDenied::SensitivePath, raw));
        }

        Ok(ValidatedIngestionPath {
            canonical: canon,
            root_handle,
        })
    }
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ── ORCH-R1-07: ingest open/read failures must not leak the file path ──
    #[cfg(target_os = "linux")]
    #[test]
    fn ingest_missing_file_does_not_leak_path_orch_r1_07() {
        let tmp = TempDir::new().unwrap();
        let trusted_root = std::fs::canonicalize(tmp.path()).unwrap();
        let trusted_root_handle = open_test_root_handle(&trusted_root);
        let target = trusted_root.join("nonexistent-secret-file.md");
        let s = store();
        let err = s
            .ingest_file_with_root_handle(&trusted_root_handle, &target)
            .unwrap_err();
        assert!(
            !err.to_string().contains("nonexistent-secret-file"),
            "ingest path leaked into error Display: {err}"
        );
    }
    use tempfile::TempDir;

    // ── SVC-8: ingestion access control (relocated from the transport) ──
    //
    // The closed-by-default allowlist, sensitive-content denylist,
    // canonicalization, and held-directory-handle gate moved here from
    // `delphi-services`. These regression tests moved with the logic;
    // against the pre-SVC-8 domain they fail to compile (the types did
    // not exist), which is the relocation's RED signal. The genuinely new
    // hardening — the domain itself now enforces the denylist, so a
    // sensitive file inside an allowed root is refused *before* any
    // ingest is reachable — is locked in by
    // `validate_rejects_sensitive_file_inside_allowed_root` (pre-SVC-8
    // the domain had no denylist; `ingest_file_with_root_handle` would
    // have ingested an `id_rsa` handed to it).

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
        assert!(is_sensitive_path(Path::new("/home/u/.aws/credentials")));
    }

    #[test]
    fn sensitive_path_rejects_kdbx() {
        assert!(is_sensitive_path(Path::new("/home/u/passwords.kdbx")));
    }

    #[test]
    fn sensitive_path_rejects_gnupg_dir_midpath() {
        assert!(is_sensitive_path(Path::new("/home/u/.gnupg/random.txt")));
    }

    #[test]
    fn sensitive_path_accepts_ordinary_markdown() {
        assert!(!is_sensitive_path(Path::new("/home/u/notes/foo.md")));
    }

    #[test]
    fn sensitive_path_accepts_dotfile_that_is_not_sensitive() {
        assert!(!is_sensitive_path(Path::new("/home/u/.bashrc")));
    }

    #[test]
    fn sensitive_path_extension_check_is_case_insensitive() {
        assert!(is_sensitive_path(Path::new("/tmp/cert.PEM")));
        assert!(is_sensitive_path(Path::new("/tmp/cert.Pem")));
    }

    // -- IngestionAccessController: construction + registration --

    #[test]
    fn controller_new_has_empty_allowlist() {
        let gate = IngestionAccessController::new();
        assert!(
            gate.snapshot().is_empty(),
            "new() must be closed by default (empty allowlist)"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn add_root_canonicalizes_and_dedupes() {
        let tmp = TempDir::new().unwrap();
        let gate = IngestionAccessController::new();
        assert!(gate.add_root(tmp.path()));
        assert_eq!(gate.snapshot().len(), 1);
        // Second add of the same path is a no-op after canonicalization.
        assert!(!gate.add_root(tmp.path()));
        assert_eq!(gate.snapshot().len(), 1);
        // A non-existent path fails to register.
        assert!(!gate.add_root(Path::new("/no/such/path/here/exists")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn add_root_holds_directory_handle() {
        // FIX 15: the registered root is anchored to a held O_DIRECTORY
        // handle, not just a PathBuf. Inspect the private allowlist field
        // (same-crate test) and confirm the handle is a directory.
        let tmp = TempDir::new().unwrap();
        let gate = IngestionAccessController::new();
        assert!(gate.add_root(tmp.path()));
        let allow = gate.allowlist.lock().unwrap();
        assert_eq!(allow.len(), 1);
        let meta = allow[0]
            .dir_handle
            .metadata()
            .expect("held handle must be queryable");
        assert!(
            meta.is_dir(),
            "held handle must be a directory (O_DIRECTORY enforced at open)"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn add_root_resolves_symlink_root_to_target_inode() {
        // A symlinked root path canonicalizes to its target; the stored
        // canonical_path is the resolved target and the handle anchors to
        // that inode (so a later swap of the symlink cannot redirect it).
        let tmp = TempDir::new().unwrap();
        let real_dir = tmp.path().join("real_dir");
        std::fs::create_dir(&real_dir).unwrap();
        let symlink_dir = tmp.path().join("symlink_to_real");
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

        let gate = IngestionAccessController::new();
        assert!(
            gate.add_root(&symlink_dir),
            "registering a symlink should canonicalize to the target and succeed"
        );
        let real_canon = std::fs::canonicalize(&real_dir).unwrap();
        let allow = gate.allowlist.lock().unwrap();
        assert_eq!(allow[0].canonical_path, real_canon);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn with_roots_populates_allowlist_on_linux() {
        let tmp = TempDir::new().unwrap();
        let gate = IngestionAccessController::with_roots(vec![tmp.path().to_path_buf()]);
        let snapshot = gate.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0], std::fs::canonicalize(tmp.path()).unwrap());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn with_roots_empty_on_non_linux() {
        // open_dir_no_follow returns Unsupported on non-Linux, so
        // with_roots silently drops the entry → empty allowlist.
        let tmp = TempDir::new().unwrap();
        let gate = IngestionAccessController::with_roots(vec![tmp.path().to_path_buf()]);
        assert!(gate.snapshot().is_empty());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn add_root_returns_false_on_non_linux() {
        let tmp = TempDir::new().unwrap();
        let gate = IngestionAccessController::new();
        assert!(
            !gate.add_root(tmp.path()),
            "add_root must reject on non-Linux (open_dir_no_follow Unsupported)"
        );
        assert!(gate.snapshot().is_empty());
    }

    // -- validate() behavior --

    #[test]
    fn validate_denies_when_allowlist_empty() {
        let gate = IngestionAccessController::new();
        let err = gate.validate("/etc/passwd").unwrap_err();
        assert!(matches!(
            err,
            IngestionError::Denied(IngestionDenied::AllowlistEmpty)
        ));
    }

    #[test]
    fn validate_empty_allowlist_does_not_probe_filesystem() {
        // FIX 7 part A: with an empty allowlist, a path that exists and a
        // path that does not BOTH deny with the same variant and without
        // any canonicalize() syscall — no filesystem-existence oracle.
        let gate = IngestionAccessController::new();
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real.md");
        std::fs::write(&real, "x").unwrap();
        let e_real = gate.validate(&real.to_string_lossy()).unwrap_err();
        let e_ghost = gate.validate("/no/such/path/ever.md").unwrap_err();
        assert!(matches!(
            e_real,
            IngestionError::Denied(IngestionDenied::AllowlistEmpty)
        ));
        assert!(matches!(
            e_ghost,
            IngestionError::Denied(IngestionDenied::AllowlistEmpty)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn validate_accepts_path_inside_allowlist() {
        let tmp = TempDir::new().unwrap();
        let gate = IngestionAccessController::with_roots(vec![tmp.path().to_path_buf()]);
        let file = tmp.path().join("note.md");
        std::fs::write(&file, "# T\n").unwrap();
        let token = gate
            .validate(&file.to_string_lossy())
            .expect("a file inside the allowlist must validate");
        assert_eq!(token.canonical(), std::fs::canonicalize(&file).unwrap().as_path());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn validate_denies_path_outside_allowlist() {
        let allowed = TempDir::new().unwrap();
        let other = TempDir::new().unwrap();
        let gate = IngestionAccessController::with_roots(vec![allowed.path().to_path_buf()]);
        let outside = other.path().join("evil.md");
        std::fs::write(&outside, "x").unwrap();
        let err = gate.validate(&outside.to_string_lossy()).unwrap_err();
        assert!(matches!(
            err,
            IngestionError::Denied(IngestionDenied::OutsideAllowlist)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn validate_denies_unresolvable_path() {
        let allowed = TempDir::new().unwrap();
        let gate = IngestionAccessController::with_roots(vec![allowed.path().to_path_buf()]);
        let ghost = allowed.path().join("does-not-exist.md");
        let err = gate.validate(&ghost.to_string_lossy()).unwrap_err();
        assert!(matches!(
            err,
            IngestionError::Denied(IngestionDenied::Unresolvable)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn validate_rejects_sensitive_file_inside_allowed_root() {
        // SVC-8 CORE PROPERTY: the domain now enforces the denylist. The
        // file is inside an explicitly-allowed root, yet validate() must
        // refuse it with SensitivePath — even an explicit allowlist cannot
        // override the denylist. Pre-SVC-8 the domain had no denylist at
        // all, so this is the regression that locks the relocation's value.
        let tmp = TempDir::new().unwrap();
        let gate = IngestionAccessController::with_roots(vec![tmp.path().to_path_buf()]);
        let key = tmp.path().join("id_rsa");
        std::fs::write(&key, "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
        let err = gate.validate(&key.to_string_lossy()).unwrap_err();
        assert!(matches!(
            err,
            IngestionError::Denied(IngestionDenied::SensitivePath)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn validate_traversal_escape_is_denied() {
        // /allowed/../other canonicalizes outside the allowlist (or fails
        // to resolve) — either way it must deny, never validate.
        let allowed = TempDir::new().unwrap();
        let other = TempDir::new().unwrap();
        let gate = IngestionAccessController::with_roots(vec![allowed.path().to_path_buf()]);
        let outside = other.path().join("secret.md");
        std::fs::write(&outside, "secret").unwrap();
        let traversal = allowed.path().join("..").join(outside.file_name().unwrap());
        let err = gate.validate(&traversal.to_string_lossy()).unwrap_err();
        assert!(matches!(err, IngestionError::Denied(_)));
    }

    // -- ingest_validated_file: the capability path end-to-end --

    #[cfg(target_os = "linux")]
    #[test]
    fn ingest_validated_file_round_trips_via_token() {
        let tmp = TempDir::new().unwrap();
        let gate = IngestionAccessController::with_roots(vec![tmp.path().to_path_buf()]);
        let file = tmp.path().join("note.md");
        std::fs::write(&file, "# Title\n\nA fact.\n").unwrap();
        let token = gate.validate(&file.to_string_lossy()).unwrap();

        let store = KnowledgeStore::in_memory(Box::new(MockEmbedder::new())).unwrap();
        let result = store
            .ingest_validated_file(&token)
            .expect("validated token must ingest");
        assert!(result.source_id > 0);
        assert_eq!(result.fidelity_used, Fidelity::Direct);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn validate_via_symlink_canonicalizes_to_real_target() {
        // A symlink whose target is inside the allowlist validates: the
        // canonical path is the real target, anchored to the matching root.
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real.md");
        std::fs::write(&real, "# Real\n\nContent.\n").unwrap();
        let link = tmp.path().join("link.md");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let gate = IngestionAccessController::with_roots(vec![tmp.path().to_path_buf()]);
        let token = gate
            .validate(&link.to_string_lossy())
            .expect("symlink → real target inside allowlist must validate");
        assert_eq!(token.canonical(), std::fs::canonicalize(&real).unwrap().as_path());
    }

    // -- audit-log asymmetry: detailed reason + path to the log, neither
    //    the path (here) nor anything (at the transport) to the caller --

    #[test]
    fn deny_logs_specific_reason_and_path_but_error_omits_path() {
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
            deny(
                IngestionDenied::SensitivePath,
                "/secret/path/that/should/not/leak",
            )
        });

        // Local audit log MUST carry the specific reason AND the raw path.
        let captured = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            captured.contains("matches sensitive-content denylist"),
            "expected detailed reason in local log; got: {captured:?}"
        );
        assert!(
            captured.contains("/secret/path/that/should/not/leak"),
            "expected raw path in local log; got: {captured:?}"
        );
        // The returned domain error carries the reason category (for local
        // use) but MUST NOT carry the path — the transport then discards
        // even the reason in favour of a uniform wire message.
        assert!(
            !err.to_string().contains("/secret/path"),
            "domain error leaked the path: {err}"
        );
    }

    fn store() -> KnowledgeStore {
        KnowledgeStore::in_memory(Box::new(MockEmbedder::new())).unwrap()
    }

    // ── Enum stability ────────────────────────────────────────────────

    #[test]
    fn node_type_strings_round_trip() {
        for t in [
            NodeType::Concept,
            NodeType::Fact,
            NodeType::Person,
            NodeType::Project,
            NodeType::Opinion,
        ] {
            assert_eq!(NodeType::from_str(t.as_str()).unwrap(), t);
        }
        assert!(NodeType::from_str("garbage").is_err());
    }

    #[test]
    fn edge_relation_strings_round_trip() {
        for r in [
            EdgeRelation::RelatesTo,
            EdgeRelation::Contradicts,
            EdgeRelation::Supports,
            EdgeRelation::PartOf,
            EdgeRelation::DependsOn,
            EdgeRelation::CreatedBy,
            EdgeRelation::SimilarTo,
        ] {
            assert_eq!(EdgeRelation::from_str(r.as_str()).unwrap(), r);
        }
    }

    #[test]
    fn edge_relation_acyclic_set() {
        assert!(EdgeRelation::PartOf.is_acyclic());
        assert!(EdgeRelation::DependsOn.is_acyclic());
        assert!(!EdgeRelation::RelatesTo.is_acyclic());
        assert!(!EdgeRelation::Contradicts.is_acyclic());
    }

    #[test]
    fn source_type_strings_round_trip() {
        for s in [
            SourceType::LocalFile,
            SourceType::WebPage,
            SourceType::Conversation,
            SourceType::UserAssertion,
        ] {
            assert_eq!(SourceType::from_str(s.as_str()).unwrap(), s);
        }
    }

    // ── content_hash + detect_format ──────────────────────────────────

    #[test]
    fn content_hash_is_deterministic() {
        let a = content_hash(b"hello");
        let b = content_hash(b"hello");
        let c = content_hash(b"world");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64); // 32 bytes hex
    }

    #[test]
    fn detect_format_by_extension() {
        assert_eq!(detect_format(Path::new("a.md"), &[]), "markdown");
        assert_eq!(detect_format(Path::new("a.html"), &[]), "html");
        assert_eq!(detect_format(Path::new("a.txt"), &[]), "text");
        assert_eq!(detect_format(Path::new("a.pdf"), &[]), "pdf");
        assert_eq!(detect_format(Path::new("a.docx"), &[]), "docx");
    }

    #[test]
    fn detect_format_by_magic_bytes() {
        assert_eq!(detect_format(Path::new("noext"), b"%PDF-1.4"), "pdf");
        assert_eq!(
            detect_format(Path::new("noext"), b"<!DOCTYPE html>"),
            "html"
        );
        assert_eq!(detect_format(Path::new("noext"), b"plain text"), "text");
    }

    // ── Markdown parser ───────────────────────────────────────────────

    #[test]
    fn markdown_parser_extracts_heading_and_paragraph() {
        let md = "# Title\n\nThis is a paragraph about the topic.\n";
        let concepts = parse_markdown_to_concepts(md);
        assert!(concepts.iter().any(|c| c.text == "Title" && c.node_type == NodeType::Concept));
        assert!(
            concepts
                .iter()
                .any(|c| c.text.starts_with("This is") && c.node_type == NodeType::Fact)
        );
    }

    #[test]
    fn markdown_parser_handles_nested_headings() {
        let md = "# Top\n\n## Sub\n\nContent.\n";
        let concepts = parse_markdown_to_concepts(md);
        let depths: Vec<u32> = concepts
            .iter()
            .filter(|c| c.node_type == NodeType::Concept)
            .map(|c| c.depth)
            .collect();
        assert!(depths.contains(&1));
        assert!(depths.contains(&2));
    }

    #[test]
    fn markdown_parser_excludes_code_blocks() {
        let md = "# H\n\n```rust\nfn foo() {}\n```\n\nProse.\n";
        let concepts = parse_markdown_to_concepts(md);
        assert!(!concepts.iter().any(|c| c.text.contains("fn foo()")));
        assert!(concepts.iter().any(|c| c.text == "Prose."));
    }

    #[test]
    fn markdown_parser_handles_no_headings() {
        let md = "Just one paragraph with no headings whatsoever.\n";
        let concepts = parse_markdown_to_concepts(md);
        assert!(!concepts.is_empty());
        assert!(concepts.iter().all(|c| c.node_type == NodeType::Fact));
    }

    #[test]
    fn markdown_parser_assigns_parent_text() {
        let md = "# Topic\n\nA fact about the topic.\n";
        let concepts = parse_markdown_to_concepts(md);
        let fact = concepts
            .iter()
            .find(|c| c.node_type == NodeType::Fact)
            .unwrap();
        assert_eq!(fact.parent_text.as_deref(), Some("Topic"));
    }

    // ── HTML parser ───────────────────────────────────────────────────

    #[test]
    fn html_parser_extracts_title_and_paragraphs() {
        let html = "<html><head><title>Doc Title</title></head><body><h1>Hello</h1><p>World.</p></body></html>";
        let concepts = parse_html_to_concepts(html);
        assert!(concepts.iter().any(|c| c.text == "Doc Title"));
        assert!(concepts.iter().any(|c| c.text == "Hello"));
        assert!(concepts.iter().any(|c| c.text == "World."));
    }

    #[test]
    fn html_parser_handles_malformed_input() {
        // Should not panic.
        let html = "<html><body><p>unclosed";
        let _ = parse_html_to_concepts(html);
    }

    #[test]
    fn html_parser_extracts_list_items() {
        let html = "<ul><li>First</li><li>Second</li></ul>";
        let concepts = parse_html_to_concepts(html);
        assert!(concepts.iter().any(|c| c.text == "First"));
        assert!(concepts.iter().any(|c| c.text == "Second"));
    }

    // ── Vector encoding + similarity ──────────────────────────────────

    #[test]
    fn vector_to_blob_round_trip() {
        let v = vec![1.0_f32, -0.5, 0.0, 7.25];
        let blob = vector_to_blob(&v);
        assert_eq!(blob.len(), 16);
        let decoded = blob_to_vector(&blob, 4).unwrap();
        for (a, b) in v.iter().zip(decoded.iter()) {
            assert!((a - b).abs() < 1e-6);
        }
    }

    #[test]
    fn blob_to_vector_rejects_wrong_size() {
        let blob = vec![0_u8; 8];
        assert!(blob_to_vector(&blob, 4).is_err());
    }

    #[test]
    fn cosine_similarity_identical_vectors_equals_one() {
        let v = vec![1.0, 2.0, 3.0];
        let s = cosine_similarity(&v, &v).unwrap();
        assert!((s - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_similarity_orthogonal_vectors_equals_zero() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        let s = cosine_similarity(&a, &b).unwrap();
        assert!(s.abs() < 1e-6);
    }

    #[test]
    fn cosine_similarity_zero_vector_returns_zero_not_nan() {
        let a = vec![0.0, 0.0, 0.0];
        let b = vec![1.0, 2.0, 3.0];
        assert_eq!(cosine_similarity(&a, &b), Some(0.0));
    }

    #[test]
    fn cosine_similarity_dimension_mismatch_returns_none() {
        let a = vec![1.0, 2.0];
        let b = vec![1.0, 2.0, 3.0];
        assert!(cosine_similarity(&a, &b).is_none());
    }

    // ── MockEmbedder ──────────────────────────────────────────────────

    #[test]
    fn mock_embedder_is_deterministic() {
        let e = MockEmbedder::new();
        let (a, _) = e.embed("hello").unwrap();
        let (b, _) = e.embed("hello").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn mock_embedder_different_inputs_different_vectors() {
        let e = MockEmbedder::new();
        let (a, _) = e.embed("foo").unwrap();
        let (b, _) = e.embed("bar").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn mock_embedder_dimension_matches() {
        let e = MockEmbedder::with_dimension(16);
        let (v, _) = e.embed("hi").unwrap();
        assert_eq!(v.len(), 16);
        assert_eq!(e.dimension(), 16);
    }

    // ── LocalEmbedder (stub) ──────────────────────────────────────────

    #[test]
    fn local_embedder_unavailable_by_default() {
        let e = LocalEmbedder::unavailable();
        let (v, fid) = e.embed("anything").unwrap();
        assert!(v.is_empty());
        assert_eq!(fid, Fidelity::Unavailable);
    }

    // ── CloudEmbedder + ZKQP gate ─────────────────────────────────────

    #[test]
    fn cloud_embedder_disabled_by_default() {
        let e = CloudEmbedder::disabled();
        assert!(!e.is_enabled());
        let (v, fid) = e.embed("user data").unwrap();
        assert!(v.is_empty());
        assert_eq!(fid, Fidelity::Unavailable);
    }

    #[test]
    fn cloud_embedder_enable_disable_round_trip() {
        let mut e = CloudEmbedder::disabled();
        assert!(!e.is_enabled());
        e.enable();
        assert!(e.is_enabled());
        e.disable();
        assert!(!e.is_enabled());
    }

    #[test]
    fn cloud_embedder_when_enabled_sanitizes_via_zkqp() {
        // Enabling alone shouldn't break — sanitizer runs internally.
        // The fidelity returned is Subprocess (path is wired) but the vector
        // is a stub zero vector until real cloud transmission lands.
        let e = CloudEmbedder::enabled(8);
        let (v, fid) = e.embed("benign content").unwrap();
        assert_eq!(v.len(), 8);
        assert_eq!(fid, Fidelity::Subprocess);
    }

    // ── CachingEmbedder ───────────────────────────────────────────────

    #[test]
    fn caching_embedder_reuses_cached_results() {
        let inner = Box::new(MockEmbedder::new());
        let cached = CachingEmbedder::wrap(inner);
        let _ = cached.embed("x").unwrap();
        let _ = cached.embed("x").unwrap();
        let _ = cached.embed("y").unwrap();
        assert_eq!(cached.cache_size(), 2);
    }

    // ── KnowledgeStore: source provenance enforcement ─────────────────

    #[test]
    fn create_node_rejects_empty_sources() {
        let s = store();
        let err = s.create_node("orphan", NodeType::Concept, &[]).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("source"));
    }

    #[test]
    fn create_node_with_source_succeeds() {
        let s = store();
        let src = s
            .create_or_get_source(
                SourceType::UserAssertion,
                "user://tester",
                Fidelity::Direct,
                "abc",
                "text",
            )
            .unwrap();
        let id = s
            .create_node("a fact", NodeType::Fact, &[src])
            .unwrap();
        assert!(id > 0);
        let node = s.get_node(id).unwrap();
        assert_eq!(node.content, "a fact");
        assert_eq!(node.source_ids, vec![src]);
    }

    // ── Source idempotency ───────────────────────────────────────────

    #[test]
    fn create_or_get_source_returns_existing_for_same_uri_hash() {
        let s = store();
        let a = s
            .create_or_get_source(SourceType::LocalFile, "/p", Fidelity::Direct, "h1", "md")
            .unwrap();
        let b = s
            .create_or_get_source(SourceType::LocalFile, "/p", Fidelity::Direct, "h1", "md")
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(s.count_sources().unwrap(), 1);
    }

    #[test]
    fn create_or_get_source_distinguishes_by_hash() {
        let s = store();
        let a = s
            .create_or_get_source(SourceType::LocalFile, "/p", Fidelity::Direct, "h1", "md")
            .unwrap();
        let b = s
            .create_or_get_source(SourceType::LocalFile, "/p", Fidelity::Direct, "h2", "md")
            .unwrap();
        assert_ne!(a, b);
        assert_eq!(s.count_sources().unwrap(), 2);
    }

    // ── FIX 5 (P2): format participates in source uniqueness key ─────

    #[test]
    fn create_or_get_source_distinguishes_by_format() {
        // Codex review FIX 5 P2: same (uri, content_hash) under different
        // formats must produce distinct source rows so a corrected
        // re-ingest doesn't silently shadow the bad row.
        let s = store();
        let a = s
            .create_or_get_source(SourceType::LocalFile, "/p", Fidelity::Direct, "h1", "markdown")
            .unwrap();
        let b = s
            .create_or_get_source(SourceType::LocalFile, "/p", Fidelity::Direct, "h1", "html")
            .unwrap();
        assert_ne!(a, b, "different formats must produce distinct source rows");
        assert_eq!(s.count_sources().unwrap(), 2);
    }

    #[test]
    fn ingest_text_same_bytes_different_format_creates_separate_sources() {
        // The motivating Codex scenario: caller first ingests bytes as
        // pdf (Unavailable, no nodes), then re-ingests the same bytes as
        // markdown (Direct, with parsed nodes). Both source rows must
        // exist with their own fidelity.
        let s = store();
        let bytes = "# Title\n\nA paragraph.\n";
        let pdf_result = s
            .ingest_text(bytes, "/note", SourceType::LocalFile, "pdf")
            .unwrap();
        let md_result = s
            .ingest_text(bytes, "/note", SourceType::LocalFile, "markdown")
            .unwrap();
        assert_ne!(
            pdf_result.source_id, md_result.source_id,
            "different format on same (uri, content) → distinct sources"
        );
        assert_eq!(s.count_sources().unwrap(), 2);
        // First (pdf) row is Unavailable
        let pdf_src = s.get_source(pdf_result.source_id).unwrap();
        assert_eq!(pdf_src.fidelity, Fidelity::Unavailable);
        // Second (markdown) row is Direct
        let md_src = s.get_source(md_result.source_id).unwrap();
        assert_eq!(md_src.fidelity, Fidelity::Direct);
    }

    #[test]
    fn ingest_text_corrected_format_extracts_nodes() {
        // Same setup; the markdown re-ingest must produce ≥ 2 nodes
        // (parser worked) while the pdf row remains node-less.
        let s = store();
        let bytes = "# Title\n\nA paragraph.\n";
        let pdf_result = s
            .ingest_text(bytes, "/note", SourceType::LocalFile, "pdf")
            .unwrap();
        let md_result = s
            .ingest_text(bytes, "/note", SourceType::LocalFile, "markdown")
            .unwrap();
        assert_eq!(pdf_result.nodes_created, 0, "pdf path extracts no nodes");
        assert!(
            md_result.nodes_created >= 2,
            "markdown path extracts heading + paragraph"
        );
        let pdf_nodes = s.list_nodes_from_source(pdf_result.source_id).unwrap();
        assert!(pdf_nodes.is_empty(), "pdf source still has 0 linked nodes");
        let md_nodes = s.list_nodes_from_source(md_result.source_id).unwrap();
        assert!(md_nodes.len() >= 2, "markdown source has parsed nodes");
    }

    #[test]
    fn ingest_text_same_bytes_same_format_still_idempotent() {
        // Guard: identical (uri, bytes, format) triple must still
        // dedupe to a single source row with nodes_created: 0 on
        // the second call.
        let s = store();
        let r1 = s
            .ingest_text("# T\n\nP.\n", "/x", SourceType::LocalFile, "markdown")
            .unwrap();
        let r2 = s
            .ingest_text("# T\n\nP.\n", "/x", SourceType::LocalFile, "markdown")
            .unwrap();
        assert_eq!(r1.source_id, r2.source_id);
        assert_eq!(r2.nodes_created, 0);
        assert_eq!(s.count_sources().unwrap(), 1);
    }

    // ── Edge constraints ──────────────────────────────────────────────

    #[test]
    fn create_edge_rejects_self_edge() {
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        let n = s.create_node("x", NodeType::Concept, &[src]).unwrap();
        assert!(s
            .create_edge(n, n, EdgeRelation::RelatesTo, 1.0, src)
            .is_err());
    }

    #[test]
    fn create_edge_rejects_out_of_range_confidence() {
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        let a = s.create_node("a", NodeType::Concept, &[src]).unwrap();
        let b = s.create_node("b", NodeType::Concept, &[src]).unwrap();
        assert!(s
            .create_edge(a, b, EdgeRelation::RelatesTo, 1.5, src)
            .is_err());
        assert!(s
            .create_edge(a, b, EdgeRelation::RelatesTo, -0.1, src)
            .is_err());
    }

    #[test]
    fn create_edge_part_of_cycle_prevented() {
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        let a = s.create_node("a", NodeType::Concept, &[src]).unwrap();
        let b = s.create_node("b", NodeType::Concept, &[src]).unwrap();
        let c = s.create_node("c", NodeType::Concept, &[src]).unwrap();
        s.create_edge(a, b, EdgeRelation::PartOf, 0.9, src).unwrap();
        s.create_edge(b, c, EdgeRelation::PartOf, 0.9, src).unwrap();
        // a -> b -> c is fine. Now c -> a would form a cycle.
        let err = s
            .create_edge(c, a, EdgeRelation::PartOf, 0.9, src)
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("cycle"));
    }

    #[test]
    fn create_edge_relates_to_cycle_allowed() {
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        let a = s.create_node("a", NodeType::Concept, &[src]).unwrap();
        let b = s.create_node("b", NodeType::Concept, &[src]).unwrap();
        s.create_edge(a, b, EdgeRelation::RelatesTo, 0.5, src).unwrap();
        // Reverse direction should succeed for non-acyclic relations.
        s.create_edge(b, a, EdgeRelation::RelatesTo, 0.5, src).unwrap();
    }

    #[test]
    fn create_edge_cycle_is_conflict_no_node_id_leak_orch_r2_03() {
        // ORCH-R2-03: the cycle error formatted caller node ids (positional {}).
        // Now typed Conflict; ids to tracing.
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        let a = s.create_node("alpha", NodeType::Concept, &[src]).unwrap();
        let b = s.create_node("beta", NodeType::Concept, &[src]).unwrap();
        s.create_edge(a, b, EdgeRelation::PartOf, 0.9, src).unwrap();
        let err = s
            .create_edge(b, a, EdgeRelation::PartOf, 0.9, src)
            .unwrap_err();
        assert!(
            matches!(err, OrchestratorError::Conflict { domain: "knowledge", .. }),
            "a cycle-forming edge must be a knowledge Conflict, got {err:?}"
        );
        assert!(
            !err.to_string().contains(&a.to_string())
                && !err.to_string().contains(&b.to_string()),
            "node id leaked into Display: {err}"
        );
    }

    // ── Semantic search ───────────────────────────────────────────────

    #[test]
    fn search_semantic_returns_top_k() {
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        let _a = s.create_node("apple banana", NodeType::Fact, &[src]).unwrap();
        let _b = s.create_node("apple banana", NodeType::Fact, &[src]).unwrap();
        let _c = s.create_node("totally unrelated content", NodeType::Fact, &[src]).unwrap();
        let results = s.search_semantic("apple banana", 2).unwrap();
        assert_eq!(results.len(), 2);
        // Top-2 should both include "apple banana" since they have identical
        // mock embeddings.
        for r in &results {
            assert!(r.similarity_score.is_some());
            assert!(r.node.content.contains("apple"));
        }
    }

    #[test]
    fn search_semantic_carries_sources() {
        let s = store();
        let src = s
            .create_or_get_source(
                SourceType::LocalFile,
                "/file.md",
                Fidelity::Direct,
                "hash1",
                "markdown",
            )
            .unwrap();
        let _ = s.create_node("a fact", NodeType::Fact, &[src]).unwrap();
        let r = s.search_semantic("a fact", 1).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].sources.len(), 1);
        assert_eq!(r[0].sources[0].uri, "/file.md");
        assert_eq!(r[0].sources[0].fidelity, Fidelity::Direct);
    }

    // ── related_to + find_path ───────────────────────────────────────

    #[test]
    fn related_to_walks_outward() {
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        let a = s.create_node("a", NodeType::Concept, &[src]).unwrap();
        let b = s.create_node("b", NodeType::Concept, &[src]).unwrap();
        let c = s.create_node("c", NodeType::Concept, &[src]).unwrap();
        s.create_edge(a, b, EdgeRelation::RelatesTo, 1.0, src).unwrap();
        s.create_edge(b, c, EdgeRelation::RelatesTo, 1.0, src).unwrap();
        let related = s.related_to(a, 2).unwrap();
        assert_eq!(related.len(), 2);
        let ids: Vec<NodeId> = related.iter().map(|r| r.node.id).collect();
        assert!(ids.contains(&b));
        assert!(ids.contains(&c));
    }

    #[test]
    fn related_to_respects_max_depth() {
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        let a = s.create_node("a", NodeType::Concept, &[src]).unwrap();
        let b = s.create_node("b", NodeType::Concept, &[src]).unwrap();
        let c = s.create_node("c", NodeType::Concept, &[src]).unwrap();
        s.create_edge(a, b, EdgeRelation::RelatesTo, 1.0, src).unwrap();
        s.create_edge(b, c, EdgeRelation::RelatesTo, 1.0, src).unwrap();
        let related = s.related_to(a, 1).unwrap();
        assert_eq!(related.len(), 1);
        assert_eq!(related[0].node.id, b);
    }

    #[test]
    fn find_path_returns_shortest() {
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        let a = s.create_node("a", NodeType::Concept, &[src]).unwrap();
        let b = s.create_node("b", NodeType::Concept, &[src]).unwrap();
        let c = s.create_node("c", NodeType::Concept, &[src]).unwrap();
        s.create_edge(a, b, EdgeRelation::RelatesTo, 1.0, src).unwrap();
        s.create_edge(b, c, EdgeRelation::RelatesTo, 1.0, src).unwrap();
        let path = s.find_path(a, c).unwrap().unwrap();
        assert_eq!(path.len(), 2);
    }

    #[test]
    fn find_path_returns_none_when_unreachable() {
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        let a = s.create_node("a", NodeType::Concept, &[src]).unwrap();
        let b = s.create_node("b", NodeType::Concept, &[src]).unwrap();
        // No edges → unreachable
        assert!(s.find_path(a, b).unwrap().is_none());
    }

    #[test]
    fn find_path_traverses_edge_in_reverse_direction() {
        // Codex review FIX 3: with only edge A→B, find_path(B, A) must
        // return a path of length 1 (the edge id of A→B). The graph is
        // treated as undirected for traversal even though edges store
        // direction.
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        let a = s.create_node("a", NodeType::Concept, &[src]).unwrap();
        let b = s.create_node("b", NodeType::Concept, &[src]).unwrap();
        let edge = s
            .create_edge(a, b, EdgeRelation::RelatesTo, 1.0, src)
            .unwrap();
        let path = s.find_path(b, a).unwrap().unwrap();
        assert_eq!(path.len(), 1, "B→A should reach A via the A→B edge");
        assert_eq!(
            path[0], edge,
            "returned edge id must identify the actual stored edge"
        );
    }

    #[test]
    fn find_path_uses_shortest_across_mixed_directions() {
        // Three nodes, two edges, mixed directions: A→B and C→B.
        // Path A↔B↔C exists with length 2; both legs traversed in
        // reverse for the second one.
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        let a = s.create_node("a", NodeType::Concept, &[src]).unwrap();
        let b = s.create_node("b", NodeType::Concept, &[src]).unwrap();
        let c = s.create_node("c", NodeType::Concept, &[src]).unwrap();
        s.create_edge(a, b, EdgeRelation::RelatesTo, 1.0, src).unwrap();
        s.create_edge(c, b, EdgeRelation::RelatesTo, 1.0, src).unwrap();
        let path = s.find_path(a, c).unwrap().unwrap();
        assert_eq!(path.len(), 2);
    }

    #[test]
    fn find_path_same_node_returns_empty() {
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        let a = s.create_node("a", NodeType::Concept, &[src]).unwrap();
        let path = s.find_path(a, a).unwrap().unwrap();
        assert!(path.is_empty());
    }

    // ── Contradictions ───────────────────────────────────────────────

    #[test]
    fn contradictions_for_returns_directly_connected() {
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        let a = s.create_node("a", NodeType::Fact, &[src]).unwrap();
        let b = s.create_node("not a", NodeType::Fact, &[src]).unwrap();
        s.create_edge(a, b, EdgeRelation::Contradicts, 0.9, src).unwrap();
        let conflicts = s.contradictions_for(a).unwrap();
        assert_eq!(conflicts, vec![b]);
        // And reverse-direction works:
        let conflicts_b = s.contradictions_for(b).unwrap();
        assert_eq!(conflicts_b, vec![a]);
    }

    #[test]
    fn detect_contradictions_lists_all_pairs() {
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        let a = s.create_node("a", NodeType::Fact, &[src]).unwrap();
        let b = s.create_node("b", NodeType::Fact, &[src]).unwrap();
        let c = s.create_node("c", NodeType::Fact, &[src]).unwrap();
        s.create_edge(a, b, EdgeRelation::Contradicts, 0.9, src).unwrap();
        s.create_edge(a, c, EdgeRelation::Contradicts, 0.9, src).unwrap();
        let pairs = s.detect_contradictions().unwrap();
        assert_eq!(pairs.len(), 2);
    }

    // ── forget_source cascade ────────────────────────────────────────

    #[test]
    fn forget_source_orphans_nodes_correctly() {
        let s = store();
        let s1 = s
            .create_or_get_source(SourceType::LocalFile, "/a.md", Fidelity::Direct, "h1", "md")
            .unwrap();
        let s2 = s
            .create_or_get_source(SourceType::LocalFile, "/b.md", Fidelity::Direct, "h2", "md")
            .unwrap();
        // Node only referenced by s1 → orphaned when s1 forgotten.
        let only_s1 = s.create_node("only s1", NodeType::Fact, &[s1]).unwrap();
        // Node referenced by both s1 and s2 → survives.
        let both = s.create_node("both", NodeType::Fact, &[s1, s2]).unwrap();
        let orphans = s.forget_source(s1).unwrap();
        assert_eq!(orphans, 1);
        // Only-s1 node is gone.
        assert!(s.get_node(only_s1).is_err());
        // Both-source node survives but loses s1.
        let survivor = s.get_node(both).unwrap();
        assert_eq!(survivor.source_ids, vec![s2]);
    }

    #[test]
    fn forget_source_returns_zero_for_nonexistent() {
        let s = store();
        assert_eq!(s.forget_source(9999).unwrap(), 0);
    }

    // ── Ingestion pipeline ────────────────────────────────────────────

    #[test]
    fn ingest_text_markdown_creates_nodes_and_edges() {
        let s = store();
        let md = "# Topic\n\nA paragraph.\n\nAnother paragraph.\n";
        let result = s.ingest_text(md, "user://note1", SourceType::UserAssertion, "markdown").unwrap();
        assert!(result.nodes_created >= 3);
        assert!(result.edges_created >= 1); // at least one part_of edge
        assert_eq!(result.fidelity_used, Fidelity::Direct);
        assert_eq!(result.format_detected, "markdown");
    }

    #[test]
    fn ingest_text_html_creates_nodes() {
        let s = store();
        let html = "<html><head><title>T</title></head><body><h1>H</h1><p>Body.</p></body></html>";
        let result = s.ingest_text(html, "https://x", SourceType::WebPage, "html").unwrap();
        assert!(result.nodes_created >= 2);
        assert_eq!(result.fidelity_used, Fidelity::Direct);
    }

    #[test]
    fn ingest_text_idempotent_for_same_content() {
        let s = store();
        let md = "# T\n\nP.\n";
        let r1 = s.ingest_text(md, "u", SourceType::UserAssertion, "markdown").unwrap();
        let r2 = s.ingest_text(md, "u", SourceType::UserAssertion, "markdown").unwrap();
        assert_eq!(r1.source_id, r2.source_id);
        assert_eq!(r2.nodes_created, 0);
        assert_eq!(r2.edges_created, 0);
    }

    #[test]
    fn ingest_text_changed_content_creates_new_source() {
        let s = store();
        let r1 = s
            .ingest_text("# A", "u", SourceType::UserAssertion, "markdown")
            .unwrap();
        let r2 = s
            .ingest_text("# B", "u", SourceType::UserAssertion, "markdown")
            .unwrap();
        assert_ne!(r1.source_id, r2.source_id);
    }

    #[test]
    fn ingest_text_unsupported_format_yields_unavailable() {
        let s = store();
        let result = s
            .ingest_text("dummy", "/a.pdf", SourceType::LocalFile, "pdf")
            .unwrap();
        assert_eq!(result.fidelity_used, Fidelity::Unavailable);
        assert_eq!(result.nodes_created, 0);
    }

    #[test]
    fn ingest_text_unsupported_format_records_unavailable_in_source_row() {
        // Codex review FIX 2: the source row's fidelity must reflect what
        // the parser could actually extract — not Direct optimism.
        let s = store();
        let result = s
            .ingest_text("dummy", "/a.pdf", SourceType::LocalFile, "pdf")
            .unwrap();
        let stored = s.get_source(result.source_id).unwrap();
        assert_eq!(
            stored.fidelity,
            Fidelity::Unavailable,
            "source row must inherit parser's Unavailable verdict"
        );
        assert_eq!(stored.format, "pdf");
    }

    #[test]
    fn ingest_text_idempotent_returns_stored_fidelity_not_caller_input() {
        // Codex review FIX 2: re-ingesting an already-stored Unavailable
        // source must report Unavailable on the second call — not the
        // caller's current input.
        let s = store();
        let r1 = s
            .ingest_text("dummy", "/a.pdf", SourceType::LocalFile, "pdf")
            .unwrap();
        assert_eq!(r1.fidelity_used, Fidelity::Unavailable);
        let r2 = s
            .ingest_text("dummy", "/a.pdf", SourceType::LocalFile, "pdf")
            .unwrap();
        assert_eq!(r2.source_id, r1.source_id, "idempotent reuse expected");
        assert_eq!(r2.nodes_created, 0);
        assert_eq!(
            r2.fidelity_used,
            Fidelity::Unavailable,
            "idempotent path must echo stored fidelity, not Direct"
        );
        assert_eq!(r2.format_detected, "pdf");
    }

    #[test]
    fn ingest_file_round_trip() {
        // FIX 10+11: ingest_file now requires `trusted_root` so the
        // safe-open boundary anchors to a held directory handle (FIX 15).
        // Tests open the TempDir directly via OpenOptions with O_DIRECTORY |
        // O_NOFOLLOW | O_CLOEXEC so the test handle mirrors the
        // production flow (the services-side `open_dir_no_follow`
        // produces this same handle shape at registration time).
        let tmp = TempDir::new().unwrap();
        let trusted_root = std::fs::canonicalize(tmp.path()).unwrap();
        let trusted_root_handle = open_test_root_handle(&trusted_root);
        let path = trusted_root.join("note.md");
        std::fs::write(&path, "# Hello\n\nWorld.\n").unwrap();
        let s = store();
        let result = s
            .ingest_file_with_root_handle(&trusted_root_handle, &path)
            .unwrap();
        assert!(result.nodes_created >= 2);
        assert_eq!(result.format_detected, "markdown");
        assert_eq!(result.fidelity_used, Fidelity::Direct);
    }

    #[test]
    fn ingest_file_pdf_records_unavailable_source() {
        let tmp = TempDir::new().unwrap();
        let trusted_root = std::fs::canonicalize(tmp.path()).unwrap();
        let trusted_root_handle = open_test_root_handle(&trusted_root);
        let path = trusted_root.join("doc.pdf");
        std::fs::write(&path, b"%PDF-1.4\nfake").unwrap();
        let s = store();
        let result = s
            .ingest_file_with_root_handle(&trusted_root_handle, &path)
            .unwrap();
        assert_eq!(result.fidelity_used, Fidelity::Unavailable);
        assert_eq!(result.nodes_created, 0);
        // Source should still be recorded (provenance for "we tried").
        assert!(result.source_id > 0);
        let src = s.get_source(result.source_id).unwrap();
        assert_eq!(src.fidelity, Fidelity::Unavailable);
    }

    // ── ORCH-R1-04: ingestion resource caps (live DoS) ────────────────
    // RED against pre-fix: without the caps each ingest path returns Ok, so
    // `unwrap_err()` panics. The field-specific match also fails RED if pre-fix
    // errored for an unrelated reason. Sizes go to tracing only; the typed
    // Validation error carries no caller content (SVC-9 / aligns with R1-07).

    #[test]
    fn ingest_text_rejects_oversize_input_orch_r1_04() {
        let s = store();
        let huge = "a".repeat(MAX_INGEST_BYTES + 1);
        let err = s
            .ingest_text(&huge, "uri://oversize", SourceType::LocalFile, "markdown")
            .unwrap_err();
        assert!(
            matches!(
                err,
                OrchestratorError::Validation { domain: "knowledge", field: "content", .. }
            ),
            "oversize text must be rejected with a content Validation error, got {err:?}"
        );
    }

    #[test]
    fn ingest_text_rejects_concept_explosion_orch_r1_04() {
        let s = store();
        // Distinct headings → one Concept each, comfortably under the byte cap.
        let mut doc = String::new();
        for i in 0..=MAX_CONCEPTS {
            doc.push_str(&format!("# h{i}\n\n"));
        }
        assert!(
            doc.len() < MAX_INGEST_BYTES,
            "concept-explosion doc must stay under the byte cap to isolate the count cap"
        );
        let err = s
            .ingest_text(&doc, "uri://many", SourceType::LocalFile, "markdown")
            .unwrap_err();
        assert!(
            matches!(
                err,
                OrchestratorError::Validation { domain: "knowledge", field: "concept_count", .. }
            ),
            "a doc exceeding MAX_CONCEPTS must be rejected, got {err:?}"
        );
    }

    #[test]
    fn ingest_text_rejects_oversize_concept_orch_r1_04() {
        let s = store();
        // One paragraph longer than the per-concept cap: 1 concept, under byte cap.
        let para = "a".repeat(MAX_CONCEPT_TEXT_LEN + 1);
        assert!(para.len() < MAX_INGEST_BYTES);
        let err = s
            .ingest_text(&para, "uri://longconcept", SourceType::LocalFile, "markdown")
            .unwrap_err();
        assert!(
            matches!(
                err,
                OrchestratorError::Validation { domain: "knowledge", field: "concept_text", .. }
            ),
            "an over-long concept must be rejected, got {err:?}"
        );
    }

    #[test]
    fn ingest_bytes_rejects_oversize_input_orch_r1_04() {
        let s = store();
        let huge = vec![b'a'; MAX_INGEST_BYTES + 1];
        let err = s.ingest_bytes(&huge, "uri://bytes", "markdown").unwrap_err();
        assert!(
            matches!(
                err,
                OrchestratorError::Validation { domain: "knowledge", field: "content", .. }
            ),
            "oversize bytes must be rejected, got {err:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ingest_file_rejects_oversize_file_orch_r1_04() {
        // The headline R1-04 vector: a file larger than the cap must be refused
        // at the read boundary, never slurped whole into memory.
        let tmp = TempDir::new().unwrap();
        let trusted_root = std::fs::canonicalize(tmp.path()).unwrap();
        let trusted_root_handle = open_test_root_handle(&trusted_root);
        let path = trusted_root.join("huge.md");
        std::fs::write(&path, vec![b'a'; MAX_INGEST_BYTES + 1]).unwrap();
        let s = store();
        let err = s
            .ingest_file_with_root_handle(&trusted_root_handle, &path)
            .unwrap_err();
        assert!(
            matches!(
                err,
                OrchestratorError::Validation { domain: "knowledge", field: "content", .. }
            ),
            "an oversize file must be rejected at the read boundary, got {err:?}"
        );
    }

    #[test]
    fn all_ingest_entries_share_the_byte_cap_orch_r1_04() {
        // ORCH-R1-04 round-2: every ingest entry routes the byte cap through the
        // SAME shared guard (enforce_ingest_byte_cap), so an over-cap input is
        // rejected with the IDENTICAL typed error at every entry. This is a
        // drift-regression guard: a future divergence (one entry's cap drifting)
        // breaks it — the weakest entry is the DoS vector (SVC-2 completeness:
        // one guard, not per-site copies).
        let s = store();
        let over = vec![b'a'; MAX_INGEST_BYTES + 1];
        let over_text = std::str::from_utf8(&over).expect("'a' bytes are valid UTF-8");
        let mut errs = vec![
            s.ingest_text(over_text, "uri://t", SourceType::LocalFile, "markdown")
                .unwrap_err(),
            s.ingest_bytes(&over, "uri://b", "markdown").unwrap_err(),
        ];
        #[cfg(target_os = "linux")]
        {
            let tmp = TempDir::new().unwrap();
            let root = std::fs::canonicalize(tmp.path()).unwrap();
            let handle = open_test_root_handle(&root);
            let path = root.join("over.md");
            std::fs::write(&path, &over).unwrap();
            errs.push(s.ingest_file_with_root_handle(&handle, &path).unwrap_err());
        }
        for e in &errs {
            assert!(
                matches!(
                    e,
                    OrchestratorError::Validation { domain: "knowledge", field: "content", .. }
                ),
                "every ingest entry must reject over-cap input with the same content Validation; \
                 a divergence here is a cap-drift finding. got {e:?}"
            );
        }
    }

    // ── FIX 15 (P1-high): handle-anchored safe-open boundary
    //    (supersedes round-3 path-based tests, retains FIX 10+11 invariants) ──

    /// Open a tempdir as a directory handle in the same shape that
    /// services-side `open_dir_no_follow` produces. Used by FIX 15
    /// orchestrator tests so they don't depend on the services crate.
    #[cfg(target_os = "linux")]
    fn open_test_root_handle(path: &Path) -> std::fs::File {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .expect("open_test_root_handle: O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC must succeed")
    }
    #[cfg(not(target_os = "linux"))]
    fn open_test_root_handle(path: &Path) -> std::fs::File {
        // Non-Linux test path: the surrounding tests are
        // cfg-gated to Linux anyway, but a fallback open is needed
        // so non-Linux test compilations succeed.
        std::fs::File::open(path).expect("open_test_root_handle fallback")
    }

    /// CONST-VALUE guard (runs on EVERY platform — the constant is
    /// platform-independent): asserts the `SAFE_OPEN_UNSUPPORTED_MSG` text is
    /// unchanged. This is NOT the emitted-message behavioral proof — it only
    /// compares the constant to its literal, never calls the wrapper, so on its own
    /// it would not catch the wrapper emitting a *different* error (DEFECT_CLASSES
    /// #14: a const-only pin covers one form). The behavioral pin — call the wrapper
    /// and assert the EMITTED Unsupported error — is
    /// `safe_open_under_root_handle_emits_unsupported_on_non_linux` (cfg-gated to
    /// non-Linux, where that path runs).
    #[test]
    fn safe_open_unsupported_message_is_verbatim() {
        assert_eq!(
            SAFE_OPEN_UNSUPPORTED_MSG,
            "knowledge file ingestion is supported on Linux only in this build. \
             Linux uses openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH) anchored to a \
             held directory handle for kernel-level race-free safe-open. Windows \
             lacks a documented kernel-level equivalent (NtCreateFile + \
             OBJ_DONT_REPARSE is undocumented and version-unstable); macOS support \
             via repeated openat walks is deferred. Use the ingest_text D-Bus \
             method to ingest content without filesystem access."
        );
    }

    // Linux-gated: on non-Linux the wrapper returns Unsupported (the emitted-message
    // pin below covers that path), so a success-expecting test only makes sense on
    // Linux. Restoring this gate is R1-01: it drifted OFF during the P2 lift, so on
    // non-Linux this test would `.expect("real file must open")` against a path that
    // correctly returns Unsupported and panic (the F18 platform-gating class).
    #[cfg(target_os = "linux")]
    #[test]
    fn safe_open_under_root_handle_accepts_real_file() {
        // Sanity: a regular file under the held trusted root must open.
        let tmp = TempDir::new().unwrap();
        let trusted_root = std::fs::canonicalize(tmp.path()).unwrap();
        let trusted_root_handle = open_test_root_handle(&trusted_root);
        let path = trusted_root.join("real.md");
        std::fs::write(&path, "# Hello\n\nWorld.\n").unwrap();
        use std::io::Read;
        let mut file = safe_open_under_root_handle(&trusted_root_handle, &path)
            .expect("real file must open");
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "# Hello\n\nWorld.\n");
    }

    /// The REAL emitted-message pin for the non-Linux path (R1-01 / DEFECT_CLASSES
    /// #14): CALL the wrapper and assert it returns `ErrorKind::Unsupported` carrying
    /// the exact verbatim message — not merely that the constant equals a literal.
    /// cfg-gated to non-Linux because the Unsupported behavior only manifests there
    /// (on Linux the wrapper does the real `openat2`). On this Linux host / CI it is
    /// compile-checked but does NOT execute; it runs on macOS / Windows. Grounded in
    /// `open_beneath`'s non-Linux branch, which returns
    /// `io::Error::new(ErrorKind::Unsupported, unsupported_msg)`.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn safe_open_under_root_handle_emits_unsupported_on_non_linux() {
        // The wrapper takes a &File handle; on non-Linux the primitive ignores it and
        // returns Unsupported, so any real regular file serves as the handle (avoids
        // opening a directory, which is not portable).
        let tmp = TempDir::new().unwrap();
        let handle_path = tmp.path().join("handle");
        std::fs::write(&handle_path, b"x").unwrap();
        let handle = std::fs::File::open(&handle_path).unwrap();
        let target = tmp.path().join("anything.md");
        let err = safe_open_under_root_handle(&handle, &target)
            .expect_err("non-Linux must return Unsupported, never open a file");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(err.to_string(), SAFE_OPEN_UNSUPPORTED_MSG);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn safe_open_under_root_handle_rejects_target_outside_root() {
        // Defense in depth: even when the caller mistakenly supplies
        // a target outside the held root's current canonical path,
        // safe_open_under_root_handle must refuse via the
        // strip_prefix check (which uses /proc/self/fd readlink to
        // resolve the held inode's CURRENT canonical path).
        let tmp = TempDir::new().unwrap();
        let trusted_root = std::fs::canonicalize(tmp.path()).unwrap();
        let trusted_root_handle = open_test_root_handle(&trusted_root);
        let other = TempDir::new().unwrap();
        let outside = std::fs::canonicalize(other.path())
            .unwrap()
            .join("outside.md");
        std::fs::write(&outside, "outside").unwrap();
        let err = safe_open_under_root_handle(&trusted_root_handle, &outside)
            .expect_err("target outside root must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn safe_open_under_root_handle_rejects_leaf_symlink_via_openat2() {
        // FIX 10 retained: final-component symlink rejected with ELOOP
        // by openat2 RESOLVE_NO_SYMLINKS.
        let tmp = TempDir::new().unwrap();
        let trusted_root = std::fs::canonicalize(tmp.path()).unwrap();
        let trusted_root_handle = open_test_root_handle(&trusted_root);
        let real = trusted_root.join("real.md");
        std::fs::write(&real, "innocent content").unwrap();
        let link = trusted_root.join("link.md");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = safe_open_under_root_handle(&trusted_root_handle, &link)
            .expect_err("leaf symlink must be rejected");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "expected ELOOP from RESOLVE_NO_SYMLINKS at leaf, got {err:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn safe_open_under_root_handle_rejects_intermediate_symlink_via_openat2() {
        // FIX 10 retained: intermediate-component symlink rejected
        // with ELOOP by openat2 RESOLVE_NO_SYMLINKS.
        let tmp = TempDir::new().unwrap();
        let trusted_root = std::fs::canonicalize(tmp.path()).unwrap();
        let trusted_root_handle = open_test_root_handle(&trusted_root);
        let real_dir = trusted_root.join("real_dir");
        std::fs::create_dir(&real_dir).unwrap();
        let leaf = real_dir.join("leaf.md");
        std::fs::write(&leaf, "secret-but-allowed").unwrap();
        let link_dir = trusted_root.join("link_dir");
        std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();
        let through_link = link_dir.join("leaf.md");

        let err = safe_open_under_root_handle(&trusted_root_handle, &through_link)
            .expect_err("intermediate-component symlink must be rejected");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "expected ELOOP from RESOLVE_NO_SYMLINKS at intermediate, got {err:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn safe_open_under_root_handle_rejects_dotdot_escape_via_openat2() {
        // FIX 10 retained: RESOLVE_BENEATH guard against `..` escapes.
        let tmp = TempDir::new().unwrap();
        let trusted_root = std::fs::canonicalize(tmp.path()).unwrap();
        let trusted_root_handle = open_test_root_handle(&trusted_root);
        let target_inside = trusted_root.join("a").join("..").join("..");
        let err = safe_open_under_root_handle(&trusted_root_handle, &target_inside)
            .expect_err("dotdot escape must be rejected by RESOLVE_BENEATH");
        assert!(
            err.raw_os_error().is_some(),
            "expected an os error from RESOLVE_BENEATH/openat2, got {err:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ingest_file_with_root_handle_returns_safe_open_error_for_symlink() {
        // End-to-end via KnowledgeStore::ingest_file_with_root_handle.
        // Confirms no source row is created when the kernel rejects.
        let tmp = TempDir::new().unwrap();
        let trusted_root = std::fs::canonicalize(tmp.path()).unwrap();
        let trusted_root_handle = open_test_root_handle(&trusted_root);
        let real = trusted_root.join("real.md");
        std::fs::write(&real, "# T\n\nP.\n").unwrap();
        let link = trusted_root.join("link.md");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let s = store();
        let before = s.count_sources().unwrap();
        let err = s
            .ingest_file_with_root_handle(&trusted_root_handle, &link)
            .expect_err("symlink ingest must fail");
        assert!(
            err.to_string().contains("could not safely open"),
            "expected safe-open error, got: {err}"
        );
        let after = s.count_sources().unwrap();
        assert_eq!(
            before, after,
            "no source row may be created when safe-open rejects"
        );
    }

    // ── FIX 15 (P1-high) NEW tests: handle anchoring properties ──

    #[cfg(target_os = "linux")]
    #[test]
    fn safe_open_under_root_handle_resolves_path_after_root_rename() {
        // The /proc/self/fd readlink trick. Open a directory handle,
        // then rename the directory at the path level. The held
        // handle still references the original inode; the kernel
        // updates `/proc/self/fd/<n>` to reflect the current path.
        // safe_open_under_root_handle must still find files under
        // the renamed path because it reads the current canonical
        // path via /proc/self/fd, not via the original path string.
        //
        // This test directly proves the F15 architectural property:
        // the trust anchor is the inode behind the fd, not a path
        // string — survives renames.
        let tmp = TempDir::new().unwrap();
        let original_dir = std::fs::canonicalize(tmp.path()).unwrap().join("orig");
        std::fs::create_dir(&original_dir).unwrap();
        std::fs::write(original_dir.join("file.md"), "# content\n").unwrap();
        let trusted_root_handle = open_test_root_handle(&original_dir);

        // Rename the directory at the filesystem level. The held
        // handle still references the original inode.
        let renamed_dir = std::fs::canonicalize(tmp.path()).unwrap().join("renamed");
        std::fs::rename(&original_dir, &renamed_dir).unwrap();

        // safe_open_under_root_handle must still resolve files under
        // the held inode's CURRENT canonical path (via
        // /proc/self/fd readlink). The target uses the new name.
        let target = renamed_dir.join("file.md");
        let mut file = safe_open_under_root_handle(&trusted_root_handle, &target)
            .expect("file under renamed root must open via held handle");
        use std::io::Read;
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "# content\n");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn safe_open_under_root_handle_immune_to_path_swap_attack() {
        // F15 motivating attack scenario. Simulate an attacker who
        // swaps the registered path for a symlink AFTER the handle
        // is opened. The held handle still references the original
        // inode, so safe_open_under_root_handle must still resolve
        // under that inode and not under the symlink target.
        //
        // Setup:
        //   tmp/parent/allowed_root/safe.md   ← legitimate file
        //   tmp/attacker/forbidden.md         ← what attacker wants us to read
        //
        // After registration, attacker:
        //   - removes tmp/parent/allowed_root
        //   - replaces it with a symlink → tmp/attacker
        //
        // Under round-3's path-based safe_open_under_root, the
        // re-resolution at ingest time would have followed the
        // symlink and ingested forbidden.md. Under FIX 15's held
        // handle, the kernel-side dirfd is still bound to the
        // original allowed_root inode, so the swap is inert — but
        // the file is gone from the inode's view, so the open
        // returns ENOENT (the file truly no longer exists at the
        // anchored inode), NOT a successful open of forbidden.md.
        let tmp = TempDir::new().unwrap();
        let tmp_canon = std::fs::canonicalize(tmp.path()).unwrap();
        let parent = tmp_canon.join("parent");
        std::fs::create_dir(&parent).unwrap();
        let allowed_root = parent.join("allowed_root");
        std::fs::create_dir(&allowed_root).unwrap();
        std::fs::write(allowed_root.join("safe.md"), "# safe content\n").unwrap();

        // Open the handle BEFORE the swap.
        let trusted_root_handle = open_test_root_handle(&allowed_root);

        // Attacker: remove allowed_root, replace with a symlink to
        // a directory containing a file with the same leaf name but
        // forbidden content.
        let attacker_dir = tmp_canon.join("attacker");
        std::fs::create_dir(&attacker_dir).unwrap();
        std::fs::write(attacker_dir.join("safe.md"), "# FORBIDDEN content\n").unwrap();
        std::fs::remove_dir_all(&allowed_root).unwrap();
        std::os::unix::fs::symlink(&attacker_dir, &allowed_root).unwrap();

        // Attempt to ingest "allowed_root/safe.md". With round-3's
        // path-based safe_open, the open would have followed the
        // symlink and read FORBIDDEN content. With FIX 15's held
        // handle, the held inode IS the original (now-deleted)
        // allowed_root directory, so the file lookup fails — the
        // attacker's file is unreachable from the held fd.
        //
        // The expected error is ENOENT (the legitimate file is gone
        // from the held inode's view). What MUST NOT happen is a
        // successful open of attacker_dir/safe.md.
        let target = allowed_root.join("safe.md");
        let result = safe_open_under_root_handle(&trusted_root_handle, &target);
        assert!(
            result.is_err(),
            "must not return Ok — that would mean we read attacker's file"
        );
        let err = result.unwrap_err();
        // Confirm we did NOT silently read the attacker's content.
        // An Ok result here would be the F15 vulnerability.
        assert_ne!(
            err.kind(),
            std::io::ErrorKind::Other,
            "unexpected error kind suggesting we may have followed the symlink: {err:?}"
        );
    }

    #[test]
    fn ingest_bytes_path_still_works() {
        // Direct call to ingest_bytes with markdown content must produce
        // the same shape as the path-based ingest_file used to (full
        // pipeline: create source row + parse concepts + persist nodes).
        let s = store();
        let bytes = b"# Title\n\nA paragraph of text.\n";
        let result = s
            .ingest_bytes(bytes, "user://note", "markdown")
            .unwrap();
        assert!(result.source_id > 0);
        assert!(result.nodes_created >= 2);
        assert_eq!(result.fidelity_used, Fidelity::Direct);
        assert_eq!(result.format_detected, "markdown");
    }

    // ── Storage round-trips ──────────────────────────────────────────

    #[test]
    fn store_open_persists_nodes_across_reopen() {
        let tmp = TempDir::new().unwrap();
        let path: PathBuf = tmp.path().join("k.db");
        let src_id;
        let node_id;
        {
            let s = KnowledgeStore::open(&path, Box::new(MockEmbedder::new())).unwrap();
            src_id = s
                .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
                .unwrap();
            node_id = s.create_node("persist me", NodeType::Fact, &[src_id]).unwrap();
        }
        let s2 = KnowledgeStore::open(&path, Box::new(MockEmbedder::new())).unwrap();
        let n = s2.get_node(node_id).unwrap();
        assert_eq!(n.content, "persist me");
        assert_eq!(n.source_ids, vec![src_id]);
    }

    #[test]
    fn touch_node_increments_access_count() {
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        let n = s.create_node("x", NodeType::Concept, &[src]).unwrap();
        assert_eq!(s.get_node(n).unwrap().access_count, 0);
        s.touch_node(n).unwrap();
        s.touch_node(n).unwrap();
        assert_eq!(s.get_node(n).unwrap().access_count, 2);
    }

    #[test]
    fn search_by_type_filters_results() {
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        s.create_node("c1", NodeType::Concept, &[src]).unwrap();
        s.create_node("c2", NodeType::Concept, &[src]).unwrap();
        s.create_node("f1", NodeType::Fact, &[src]).unwrap();
        let concepts = s.search_by_type(NodeType::Concept, 10).unwrap();
        assert_eq!(concepts.len(), 2);
        let facts = s.search_by_type(NodeType::Fact, 10).unwrap();
        assert_eq!(facts.len(), 1);
    }

    #[test]
    fn list_nodes_from_source_returns_only_matching() {
        // Codex review FIX 6 P2: tightened to also assert source_ids is
        // populated (the previous version asserted content but not
        // provenance, leaving a hole the invariant fix closes).
        let s = store();
        let s1 = s
            .create_or_get_source(SourceType::LocalFile, "/a", Fidelity::Direct, "h1", "md")
            .unwrap();
        let s2 = s
            .create_or_get_source(SourceType::LocalFile, "/b", Fidelity::Direct, "h2", "md")
            .unwrap();
        s.create_node("from s1", NodeType::Fact, &[s1]).unwrap();
        s.create_node("from s2", NodeType::Fact, &[s2]).unwrap();
        let from_s1 = s.list_nodes_from_source(s1).unwrap();
        assert_eq!(from_s1.len(), 1);
        assert_eq!(from_s1[0].content, "from s1");
        assert!(
            !from_s1[0].source_ids.is_empty(),
            "provenance invariant: source_ids must not be empty"
        );
        assert!(from_s1[0].source_ids.contains(&s1));
    }

    // ── FIX 6 (P2): hydrate source_ids on listing methods ─────────────

    #[test]
    fn search_by_type_hydrates_source_ids() {
        // Codex review FIX 6 P2: row_to_node leaves source_ids empty;
        // search_by_type must hydrate before returning.
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        s.create_node("c1", NodeType::Concept, &[src]).unwrap();
        let nodes = s.search_by_type(NodeType::Concept, 10).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(
            nodes[0].source_ids,
            vec![src],
            "search_by_type must hydrate source_ids — provenance invariant"
        );
    }

    #[test]
    fn search_by_type_hydrates_multiple_sources() {
        // A node linked to two sources must surface both ids when
        // returned by search_by_type.
        let s = store();
        let src_a = s
            .create_or_get_source(SourceType::LocalFile, "/a", Fidelity::Direct, "h1", "md")
            .unwrap();
        let src_b = s
            .create_or_get_source(SourceType::LocalFile, "/b", Fidelity::Direct, "h2", "md")
            .unwrap();
        s.create_node("dual", NodeType::Concept, &[src_a, src_b])
            .unwrap();
        let nodes = s.search_by_type(NodeType::Concept, 10).unwrap();
        assert_eq!(nodes.len(), 1);
        let mut ids = nodes[0].source_ids.clone();
        ids.sort();
        let mut expected = vec![src_a, src_b];
        expected.sort();
        assert_eq!(ids, expected);
    }

    #[test]
    fn list_nodes_from_source_hydrates_source_ids() {
        // A node linked to two sources, queried via list_nodes_from_source
        // for ONE of them, must still return BOTH source ids — the
        // returned KnowledgeNode is the full provenance picture, not
        // filtered to the queried source.
        let s = store();
        let src_a = s
            .create_or_get_source(SourceType::LocalFile, "/a", Fidelity::Direct, "h1", "md")
            .unwrap();
        let src_b = s
            .create_or_get_source(SourceType::LocalFile, "/b", Fidelity::Direct, "h2", "md")
            .unwrap();
        s.create_node("dual", NodeType::Fact, &[src_a, src_b]).unwrap();
        let nodes = s.list_nodes_from_source(src_a).unwrap();
        assert_eq!(nodes.len(), 1);
        let mut ids = nodes[0].source_ids.clone();
        ids.sort();
        let mut expected = vec![src_a, src_b];
        expected.sort();
        assert_eq!(
            ids, expected,
            "list_nodes_from_source must return full provenance, not just queried source"
        );
    }

    #[test]
    fn search_by_type_hydration_works_when_node_only_has_one_source() {
        // Smoke test: minimum-source case (every node has at least one
        // source by construction; this verifies the hydrator handles
        // the 1-source path correctly with no extra/missing entries).
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        for i in 0..3 {
            s.create_node(&format!("n{i}"), NodeType::Fact, &[src])
                .unwrap();
        }
        let nodes = s.search_by_type(NodeType::Fact, 10).unwrap();
        assert_eq!(nodes.len(), 3);
        for n in &nodes {
            assert_eq!(
                n.source_ids,
                vec![src],
                "every node must carry exactly the one source it was created with"
            );
        }
    }

    #[test]
    fn count_helpers_match_inserts() {
        let s = store();
        let src = s
            .create_or_get_source(SourceType::UserAssertion, "u", Fidelity::Direct, "h", "t")
            .unwrap();
        let a = s.create_node("a", NodeType::Concept, &[src]).unwrap();
        let b = s.create_node("b", NodeType::Concept, &[src]).unwrap();
        s.create_edge(a, b, EdgeRelation::RelatesTo, 0.5, src).unwrap();
        assert_eq!(s.count_sources().unwrap(), 1);
        assert_eq!(s.count_nodes().unwrap(), 2);
        assert_eq!(s.count_edges().unwrap(), 1);
    }

    // ── FIX 9 (P2-medium): explicit schema migration with version table ──
    //
    // Tests construct an "epoch 1" database in-memory by applying the
    // round-1 DDL by hand, populate some sources rows, then call
    // `KnowledgeStore::open_with_existing_connection` (a thin shim around
    // `init_schema`). Assertions verify:
    //   * row preservation (id values survive the migration)
    //   * schema_version is recorded as 2 after migration
    //   * the new UNIQUE(uri, content_hash, format) constraint is in
    //     effect (reflected in sqlite_master)
    //   * end-to-end: the FIX 5 pdf→markdown recovery now works on a
    //     migrated store
    //   * idempotency: running init twice doesn't duplicate version rows

    /// The exact round-1 DDL, frozen as a const for the migration tests.
    /// Must match commit `c3147b9`'s post-FIX-5 schema MINUS the version
    /// table — so `UNIQUE(uri, content_hash)` rather than the new
    /// 3-column key.
    ///
    /// **FIX 12 invariant**: the pragma is intentionally OUT of this DDL.
    /// Tests that need FK enforcement must set it themselves on the test
    /// connection, mirroring what [`KnowledgeStore::init_schema`] does
    /// for production callers.
    const OLD_SCHEMA_DDL_FOR_TESTS: &str = r#"
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_type TEXT NOT NULL,
    uri TEXT NOT NULL,
    ingested_at_unix INTEGER NOT NULL,
    fidelity TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    format TEXT NOT NULL,
    UNIQUE(uri, content_hash)
);

CREATE INDEX IF NOT EXISTS idx_sources_uri ON sources(uri);
CREATE INDEX IF NOT EXISTS idx_sources_format ON sources(format);
CREATE INDEX IF NOT EXISTS idx_sources_ingested ON sources(ingested_at_unix);

CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    node_type TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    last_accessed_unix INTEGER NOT NULL,
    access_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_nodes_accessed ON nodes(last_accessed_unix);

CREATE TABLE IF NOT EXISTS node_sources (
    node_id INTEGER NOT NULL,
    source_id INTEGER NOT NULL,
    PRIMARY KEY(node_id, source_id),
    FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY(source_id) REFERENCES sources(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_node INTEGER NOT NULL,
    to_node INTEGER NOT NULL,
    relation TEXT NOT NULL,
    confidence REAL NOT NULL,
    source_id INTEGER NOT NULL,
    created_at_unix INTEGER NOT NULL,
    FOREIGN KEY(from_node) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY(to_node) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY(source_id) REFERENCES sources(id) ON DELETE CASCADE,
    CHECK(confidence >= 0.0 AND confidence <= 1.0),
    CHECK(from_node != to_node)
);

CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_node);
CREATE INDEX IF NOT EXISTS idx_edges_to ON edges(to_node);
CREATE INDEX IF NOT EXISTS idx_edges_relation ON edges(relation);

CREATE TABLE IF NOT EXISTS embeddings (
    node_id INTEGER PRIMARY KEY,
    dimension INTEGER NOT NULL,
    vector BLOB NOT NULL,
    fidelity TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
);
"#;

    /// Build an "epoch 1" in-memory database with the round-1 schema
    /// and a couple of seeded `sources` rows. Returns a `Connection`
    /// that has NOT yet been through `init_schema` from the new code.
    fn make_epoch_1_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(OLD_SCHEMA_DDL_FOR_TESTS).unwrap();
        // Seed two sources rows with deliberate ids so we can verify
        // they survive the migration verbatim.
        conn.execute(
            "INSERT INTO sources (id, source_type, uri, ingested_at_unix, fidelity, content_hash, format)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![1_i64, "local_file", "/note.md", 100_i64, "direct", "hash-a", "markdown"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sources (id, source_type, uri, ingested_at_unix, fidelity, content_hash, format)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![2_i64, "local_file", "/doc.pdf", 200_i64, "unavailable", "hash-b", "pdf"],
        )
        .unwrap();
        conn
    }

    /// Build an "epoch 1" in-memory database with the round-1 schema
    /// AND a fully-populated graph: sources, nodes, node_sources
    /// mappings, and edges. The migration tests for FIX 13 need this
    /// fixture because round-2's tests only seeded `sources`, which
    /// hid the FK-reference dangling bug Codex F13 named — without
    /// child rows, no FK violation was observable.
    ///
    /// Layout (all rows have explicit IDs so post-migration assertions
    /// can address them by ID):
    /// - sources: id 1 (markdown), id 5 (pdf) — non-contiguous IDs
    ///   exercise the AUTOINCREMENT-counter preservation case.
    /// - nodes: id 1 (concept "alpha"), id 2 (fact "beta")
    /// - node_sources: (1,1), (1,5), (2,5)
    /// - edges: id 10 (1→2 "relates_to" via source 1)
    fn make_epoch_1_db_with_full_graph() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        // Round-1 used PRAGMA foreign_keys = ON inside SCHEMA_DDL,
        // which made the test connection inherit FK enforcement when
        // it executed OLD_SCHEMA_DDL_FOR_TESTS. After FIX 12 that
        // pragma was hoisted out of the DDL, so tests must set it
        // explicitly here to mirror the historical epoch-1 reality.
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn.execute_batch(OLD_SCHEMA_DDL_FOR_TESTS).unwrap();

        // Sources with deliberate IDs (1, 5) — non-contiguous to
        // exercise the AUTOINCREMENT preservation invariant.
        conn.execute(
            "INSERT INTO sources (id, source_type, uri, ingested_at_unix, fidelity, content_hash, format)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![1_i64, "local_file", "/note.md", 100_i64, "direct", "hash-a", "markdown"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sources (id, source_type, uri, ingested_at_unix, fidelity, content_hash, format)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![5_i64, "local_file", "/doc.pdf", 200_i64, "unavailable", "hash-b", "pdf"],
        )
        .unwrap();
        // Force the AUTOINCREMENT counter to 5 (matches the second
        // insert above; SQLite would already track this, but we
        // assert it explicitly so the test is robust to insert order).
        conn.execute(
            "INSERT OR REPLACE INTO sqlite_sequence (name, seq) VALUES ('sources', 5)",
            [],
        )
        .unwrap();

        // Nodes
        conn.execute(
            "INSERT INTO nodes (id, content, node_type, created_at_unix, last_accessed_unix)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1_i64, "alpha", "concept", 100_i64, 100_i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO nodes (id, content, node_type, created_at_unix, last_accessed_unix)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![2_i64, "beta", "fact", 200_i64, 200_i64],
        )
        .unwrap();

        // node_sources mappings — these are the FK references that
        // the round-2 broken migration would orphan.
        conn.execute(
            "INSERT INTO node_sources (node_id, source_id) VALUES (?1, ?2)",
            params![1_i64, 1_i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO node_sources (node_id, source_id) VALUES (?1, ?2)",
            params![1_i64, 5_i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO node_sources (node_id, source_id) VALUES (?1, ?2)",
            params![2_i64, 5_i64],
        )
        .unwrap();

        // Edge with FK to sources — the second flavor of FK reference
        // that the migration must preserve.
        conn.execute(
            "INSERT INTO edges (id, from_node, to_node, relation, confidence, source_id, created_at_unix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![10_i64, 1_i64, 2_i64, "relates_to", 0.9_f64, 1_i64, 100_i64],
        )
        .unwrap();

        conn
    }

    /// Build a deliberately-corrupt epoch-1 database that contains an
    /// orphan `node_sources` row referencing a `source_id` that does
    /// not exist in `sources`. This is the FIX 14 motivating fixture:
    /// a database that survived the round-2 FK gap (where FK
    /// enforcement was per-connection-defaulted instead of
    /// universally on) could plausibly contain such orphans.
    ///
    /// **Construction trick:** we set `PRAGMA foreign_keys = OFF` on
    /// the temporary fixture connection, do the orphaning insert,
    /// then leave the connection in that state. Round-3's migration
    /// would happily accept this database without surfacing the
    /// corruption — exactly the silent-acceptance path F14 describes.
    /// Round-4's atomic-tx migration must REJECT it via the in-tx
    /// `foreign_key_check`.
    fn make_corrupt_epoch_1_db(path: &std::path::Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        // FK off so we can construct the orphan row without rejection.
        conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        conn.execute_batch(OLD_SCHEMA_DDL_FOR_TESTS).unwrap();

        // One valid source.
        conn.execute(
            "INSERT INTO sources (id, source_type, uri, ingested_at_unix, fidelity, content_hash, format)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![1_i64, "local_file", "/real.md", 100_i64, "direct", "hash-real", "markdown"],
        )
        .unwrap();

        // One valid node.
        conn.execute(
            "INSERT INTO nodes (id, content, node_type, created_at_unix, last_accessed_unix)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1_i64, "real-content", "fact", 100_i64, 100_i64],
        )
        .unwrap();

        // Valid mapping (1, 1) — node 1 cites the real source 1.
        conn.execute(
            "INSERT INTO node_sources (node_id, source_id) VALUES (?1, ?2)",
            params![1_i64, 1_i64],
        )
        .unwrap();

        // ORPHAN: node 1 cites a source 99999 that doesn't exist.
        // FK is OFF so this insert succeeds. With FK ON it would
        // have been rejected. This row is what the in-tx
        // `foreign_key_check` must surface.
        conn.execute(
            "INSERT INTO node_sources (node_id, source_id) VALUES (?1, ?2)",
            params![1_i64, 99999_i64],
        )
        .unwrap();

        conn
    }

    /// Build a database in the exact "round-3 broken migration"
    /// shape that FIX 17 protects against: epoch-2 schema
    /// (3-column UNIQUE), `schema_version` table present but
    /// EMPTY (no version row), and an orphan `node_sources` row
    /// referencing a non-existent source.
    ///
    /// This fixture reproduces what round-3's migration would have
    /// left on disk after committing the schema rebuild but
    /// raising an error on the post-commit FK check. Round-4's
    /// migration path (FIX 14) closed that gap for the epoch-1 →
    /// epoch-2 transition, but the round-4 backfill arm in
    /// init_schema would still silently bless this database as
    /// version=2 — that's the F17 vulnerability.
    fn make_unversioned_corrupt_epoch_2_db(path: &std::path::Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        // FK OFF so we can construct the orphan row.
        conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        // Apply epoch-2 schema in full but DO NOT insert the
        // schema_version row. Note: SCHEMA_VERSION_TABLE_DDL is
        // also applied so the table exists but is empty — exactly
        // the "structure says current, recorded says nothing"
        // state F17 names.
        conn.execute_batch(SCHEMA_VERSION_TABLE_DDL).unwrap();
        conn.execute_batch(SCHEMA_DDL).unwrap();
        // (Deliberately NO INSERT INTO schema_version.)

        // Seed one valid source + node + linkage.
        conn.execute(
            "INSERT INTO sources (id, source_type, uri, ingested_at_unix, fidelity, content_hash, format)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![1_i64, "local_file", "/real.md", 100_i64, "direct", "hash-real", "markdown"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO nodes (id, content, node_type, created_at_unix, last_accessed_unix)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1_i64, "content", "fact", 100_i64, 100_i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO node_sources (node_id, source_id) VALUES (?1, ?2)",
            params![1_i64, 1_i64],
        )
        .unwrap();

        // ORPHAN ROW: node 1 cites a source 99999 that doesn't
        // exist. FK OFF lets this insert succeed. With FK enforced
        // and PRAGMA foreign_key_check, this is the violation the
        // backfill helper must surface.
        conn.execute(
            "INSERT INTO node_sources (node_id, source_id) VALUES (?1, ?2)",
            params![1_i64, 99999_i64],
        )
        .unwrap();

        conn
    }

    /// Build a **clean** database in the structurally-current-but-no-
    /// version-row state: epoch-2 schema (3-column UNIQUE),
    /// `schema_version` table present but EMPTY, one valid
    /// source + node + mapping, and NO orphan rows.
    ///
    /// This is the input the F19 concurrent-backfill regression test
    /// drives two threads against: `init_schema` sees
    /// `recorded.is_none()` with structure already at
    /// [`CURRENT_SCHEMA_VERSION`], so it routes into
    /// [`backfill_version_with_integrity_check`] — and that helper
    /// must survive being executed concurrently by two openers of
    /// the same file.
    ///
    /// Mirrors [`make_unversioned_corrupt_epoch_2_db`] minus the
    /// orphan row (naming follows the `make_*` fixture convention
    /// established in rounds 4–5).
    fn make_clean_unversioned_epoch_2_db(path: &std::path::Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        // Pre-set WAL mode so the on-disk file is already in WAL
        // when the concurrent openers touch it. `journal_mode` is a
        // persistent per-DATABASE property (unlike per-connection
        // `foreign_keys`), so one set here sticks. Without this, the
        // two openers in the concurrent regression test would ALSO
        // contend on `init_schema`'s own `PRAGMA journal_mode = WAL`,
        // and the test could fail on HEAD for the wrong reason
        // (journal-mode contention) instead of the actual F19 race
        // (the schema_version backfill INSERT).
        conn.execute_batch("PRAGMA journal_mode = WAL;").unwrap();
        // FK OFF only so the fixture build itself is unconstrained;
        // the seeded graph below is fully valid, so a later
        // `foreign_key_check` returns clean.
        conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        // Apply the epoch-2 schema in full. The schema_version table
        // exists but stays EMPTY — exactly the "structure says
        // current, recorded says nothing" state init_schema's
        // backfill arm handles.
        conn.execute_batch(SCHEMA_VERSION_TABLE_DDL).unwrap();
        conn.execute_batch(SCHEMA_DDL).unwrap();
        // (Deliberately NO INSERT INTO schema_version.)

        // Seed one valid source + node + linkage. No orphans, so the
        // backfill helper's FK check passes and it proceeds to the
        // version-row insert — the step F19's race corrupts.
        conn.execute(
            "INSERT INTO sources (id, source_type, uri, ingested_at_unix, fidelity, content_hash, format)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![1_i64, "local_file", "/clean.md", 100_i64, "direct", "hash-clean", "markdown"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO nodes (id, content, node_type, created_at_unix, last_accessed_unix)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1_i64, "content", "fact", 100_i64, 100_i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO node_sources (node_id, source_id) VALUES (?1, ?2)",
            params![1_i64, 1_i64],
        )
        .unwrap();

        conn
    }

    /// Read the recorded schema version directly from the table.
    /// Returns `None` if the table doesn't exist OR exists but is empty.
    /// This tolerates the pre-migration test condition where the
    /// `schema_version` table hasn't been created yet.
    fn read_recorded_version(conn: &Connection) -> Option<i64> {
        // First check whether the table exists; bail to None if not.
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if exists == 0 {
            return None;
        }
        conn.query_row("SELECT MAX(version) FROM schema_version", [], |r| {
            r.get::<_, Option<i64>>(0)
        })
        .optional()
        .unwrap()
        .flatten()
    }

    /// Read the `sources` CREATE statement from sqlite_master so tests
    /// can verify the unique key changed.
    fn read_sources_sql(conn: &Connection) -> String {
        conn.query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='sources'",
            [],
            |r| r.get::<_, String>(0),
        )
        .unwrap()
    }

    #[test]
    fn migration_from_epoch_1_to_2_preserves_rows() {
        let mut conn = make_epoch_1_db();
        // Pre-migration: epoch 1, recorded_version=None, 2 rows present.
        assert!(read_sources_sql(&conn).contains("UNIQUE(uri, content_hash)"));
        assert!(!read_sources_sql(&conn).contains("UNIQUE(uri, content_hash, format)"));
        assert_eq!(read_recorded_version(&conn), None);

        // Run init_schema (the migration entry point).
        KnowledgeStore::init_schema(&mut conn).unwrap();

        // Post-migration assertions:
        // (a) version is now 2
        assert_eq!(read_recorded_version(&conn), Some(2));
        // (b) sources schema is now the 3-column key
        assert!(
            read_sources_sql(&conn).contains("UNIQUE(uri, content_hash, format)"),
            "sources table must be at epoch 2 after migration"
        );
        // (c) row IDs survived verbatim
        let row1: (String, String, String) = conn
            .query_row(
                "SELECT uri, content_hash, format FROM sources WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(row1, ("/note.md".into(), "hash-a".into(), "markdown".into()));
        let row2_uri: String = conn
            .query_row("SELECT uri FROM sources WHERE id = 2", [], |r| r.get(0))
            .unwrap();
        assert_eq!(row2_uri, "/doc.pdf");
        // (d) row count unchanged
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM sources", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn migration_from_epoch_1_unblocks_corrected_format_reingest() {
        // The motivating Codex F9 scenario: a database created at epoch 1
        // had the same (uri, content_hash) under one format. After
        // migration to epoch 2, ingesting the same bytes under a
        // DIFFERENT format must succeed — the FIX 5 recovery path now
        // works for migrated stores.
        let mut conn = make_epoch_1_db();
        KnowledgeStore::init_schema(&mut conn).unwrap();
        // Now the table accepts a third row distinguished only by format.
        let result = conn.execute(
            "INSERT INTO sources (id, source_type, uri, ingested_at_unix, fidelity, content_hash, format)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![3_i64, "local_file", "/note.md", 300_i64, "direct", "hash-a", "html"],
        );
        assert!(
            result.is_ok(),
            "epoch-2 schema must accept (uri, hash, format) triple distinct only by format; got {result:?}"
        );
    }

    #[test]
    fn fresh_database_starts_at_current_schema_version() {
        // Empty in-memory DB → init_schema → version 2 recorded, all
        // tables created, no migration attempted.
        let mut conn = Connection::open_in_memory().unwrap();
        KnowledgeStore::init_schema(&mut conn).unwrap();
        assert_eq!(read_recorded_version(&conn), Some(CURRENT_SCHEMA_VERSION));
        assert!(read_sources_sql(&conn).contains("UNIQUE(uri, content_hash, format)"));
        // Indexes are present
        let idx_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name LIKE 'idx_sources%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(idx_count >= 3, "expected the three sources indexes");
    }

    #[test]
    fn schema_version_newer_than_supported_refuses_to_open() {
        // Forward-compat guard: a database written by a future binary
        // (recording a higher version) must not be opened blindly. The
        // current binary refuses with a clear error rather than risking
        // data corruption against an unknown schema.
        let mut conn = Connection::open_in_memory().unwrap();
        // Apply the current schema (so init_schema doesn't trip on
        // missing tables) then write a sentinel future version.
        conn.execute_batch(SCHEMA_VERSION_TABLE_DDL).unwrap();
        conn.execute_batch(SCHEMA_DDL).unwrap();
        conn.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            params![99_i64],
        )
        .unwrap();
        // Now init_schema must refuse.
        let err = KnowledgeStore::init_schema(&mut conn).expect_err("must refuse newer schema");
        let msg = err.to_string();
        assert!(
            msg.contains("newer"),
            "expected forward-compat error, got: {msg}"
        );
        assert!(msg.contains("99"), "expected the version number in the error");
    }

    #[test]
    fn migration_is_idempotent() {
        // Running init_schema twice on a fresh database must not
        // duplicate version rows or mutate the schema.
        let mut conn = Connection::open_in_memory().unwrap();
        KnowledgeStore::init_schema(&mut conn).unwrap();
        let first_version_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(first_version_count, 1);

        KnowledgeStore::init_schema(&mut conn).unwrap();
        let second_version_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            second_version_count, 1,
            "second init must not append a duplicate version row"
        );
        assert_eq!(read_recorded_version(&conn), Some(CURRENT_SCHEMA_VERSION));
    }

    // ── FIX 12 (P1-high): per-connection foreign-key enforcement ──────

    /// Helper: read `PRAGMA foreign_keys` from a connection.
    fn read_fk_pragma(conn: &Connection) -> i64 {
        conn.query_row("PRAGMA foreign_keys", [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn fk_enforcement_active_after_init_schema() {
        // After init_schema, the very connection used to set up the schema
        // must have FK enforcement ON. This is the trivial-but-required
        // baseline: prior to FIX 12, the pragma was buried in SCHEMA_DDL
        // and only fired when a fresh-database CREATE path ran; this test
        // confirms init_schema itself is now responsible for the pragma.
        let mut conn = Connection::open_in_memory().unwrap();
        KnowledgeStore::init_schema(&mut conn).unwrap();
        assert_eq!(
            read_fk_pragma(&conn),
            1,
            "FK enforcement must be ON after init_schema"
        );
    }

    #[test]
    fn fk_enforcement_active_after_close_and_reopen() {
        // FIX 12 motivating case: round-2 set the pragma in SCHEMA_DDL.
        // SQLite's CREATE TABLE IF NOT EXISTS is a no-op on the second
        // open, so the pragma never re-ran on the new connection — the
        // database file silently lost FK enforcement on every reopen
        // (the failure mode that wasn't visible in single-connection
        // tests). This test uses NamedTempFile to materialize a real
        // database file, drops the first connection, opens a fresh one,
        // and checks the pragma on THE NEW connection.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        // First open: create the schema.
        {
            let mut conn = Connection::open(&path).unwrap();
            KnowledgeStore::init_schema(&mut conn).unwrap();
            assert_eq!(read_fk_pragma(&conn), 1, "first open must enforce FKs");
        }
        // Second open: schema already exists, version row is recorded.
        // We explicitly turn FK enforcement OFF on this fresh connection
        // BEFORE running init_schema — this simulates a SQLite build where
        // FK defaults OFF (the historical SQLite default; some builds
        // override the default ON, which is why we can't use the default
        // alone as a probe). After init_schema runs, the pragma MUST be
        // ON, proving init_schema actively enforces the invariant rather
        // than relying on whatever the connection happened to start with.
        let mut conn2 = Connection::open(&path).unwrap();
        conn2
            .execute_batch("PRAGMA foreign_keys = OFF;")
            .expect("must be able to set pragma");
        assert_eq!(
            read_fk_pragma(&conn2),
            0,
            "explicit OFF must take effect on this connection"
        );
        KnowledgeStore::init_schema(&mut conn2).unwrap();
        assert_eq!(
            read_fk_pragma(&conn2),
            1,
            "FK enforcement must be re-applied on every connection by init_schema"
        );
    }

    #[test]
    fn fk_cascade_actually_deletes_dependent_rows() {
        // Behavioral test: confirm the pragma's effect is observable, not
        // just the pragma's REPORTED value. Without FK enforcement, a
        // DELETE on `sources` would orphan `node_sources` rows. With
        // enforcement, ON DELETE CASCADE removes them.
        let mut conn = Connection::open_in_memory().unwrap();
        KnowledgeStore::init_schema(&mut conn).unwrap();

        // Seed: one source, one node, one node_sources mapping row.
        conn.execute(
            "INSERT INTO sources (source_type, uri, ingested_at_unix, fidelity, content_hash, format)
             VALUES ('local_file', 'u', 0, 'direct', 'h', 'markdown')",
            [],
        )
        .unwrap();
        let source_id: i64 = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO nodes (content, node_type, created_at_unix, last_accessed_unix)
             VALUES ('n', 'fact', 0, 0)",
            [],
        )
        .unwrap();
        let node_id: i64 = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO node_sources (node_id, source_id) VALUES (?1, ?2)",
            params![node_id, source_id],
        )
        .unwrap();
        let mapping_count_before: i64 = conn
            .query_row("SELECT COUNT(*) FROM node_sources", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mapping_count_before, 1, "seeded one mapping row");

        // Delete the source. Cascade must remove the mapping.
        conn.execute("DELETE FROM sources WHERE id = ?1", params![source_id])
            .unwrap();
        let mapping_count_after: i64 = conn
            .query_row("SELECT COUNT(*) FROM node_sources", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            mapping_count_after, 0,
            "ON DELETE CASCADE must remove dependent node_sources rows; \
             if this fails, FK enforcement is OFF on this connection"
        );
    }

    #[test]
    fn fk_violation_is_rejected_at_insert_time() {
        // Inverse behavioral test: with FK enforcement ON, inserting a
        // node_sources row pointing at a NONEXISTENT source must fail
        // immediately. Without enforcement, the row would silently insert
        // and the graph would carry phantom provenance.
        let mut conn = Connection::open_in_memory().unwrap();
        KnowledgeStore::init_schema(&mut conn).unwrap();

        // Insert a node so the node_id side is valid.
        conn.execute(
            "INSERT INTO nodes (content, node_type, created_at_unix, last_accessed_unix)
             VALUES ('n', 'fact', 0, 0)",
            [],
        )
        .unwrap();
        let node_id: i64 = conn.last_insert_rowid();

        // source_id = 999 doesn't exist. With FK enforcement, this insert
        // must fail.
        let result = conn.execute(
            "INSERT INTO node_sources (node_id, source_id) VALUES (?1, ?2)",
            params![node_id, 999_i64],
        );
        assert!(
            result.is_err(),
            "FK enforcement must reject node_sources row pointing at nonexistent source; \
             got Ok which means enforcement is OFF"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("FOREIGN KEY") || err_msg.to_lowercase().contains("constraint"),
            "expected a FOREIGN KEY constraint error, got: {err_msg}"
        );
    }

    // ── FIX 13 (P1-high): SQLite-correct migration with FK preservation ──
    //
    // Round-2's migration sequence (RENAME → CREATE → INSERT → DROP)
    // silently broke `node_sources` and `edges` FK references because
    // SQLite's modern ALTER RENAME rewrites child FK metadata to point
    // at the renamed parent, and then the DROP of the renamed parent
    // orphans those references. The bug was invisible in round-2's
    // tests because they only seeded `sources` rows. These tests use
    // the new `make_epoch_1_db_with_full_graph` fixture, which seeds
    // all four related tables, then assert that every FK relation
    // resolves correctly after migration.

    /// Helper: count rows in a table.
    fn row_count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    /// Helper: count `PRAGMA foreign_key_check` rows. Returns 0 when
    /// referential integrity is intact, > 0 otherwise.
    fn fk_check_violation_count(conn: &Connection) -> usize {
        let mut stmt = conn.prepare("PRAGMA foreign_key_check").unwrap();
        stmt.query_map([], |_| Ok(()))
            .unwrap()
            .filter_map(|r| r.ok())
            .count()
    }

    #[test]
    fn migration_preserves_node_sources_fk_after_rebuild() {
        // The F13 motivating case: round-2 left node_sources with
        // dangling FK references after the DROP+RENAME shuffle. With
        // FIX 13's CREATE → INSERT → DROP → RENAME sequence, every
        // node_sources row's source_id must still resolve to an
        // existing sources.id after migration.
        let mut conn = make_epoch_1_db_with_full_graph();
        let mappings_before = row_count(&conn, "node_sources");
        assert_eq!(
            mappings_before, 3,
            "fixture should seed 3 node_sources rows"
        );

        KnowledgeStore::init_schema(&mut conn).unwrap();

        let mappings_after = row_count(&conn, "node_sources");
        assert_eq!(
            mappings_after, 3,
            "every node_sources row must survive the migration; \
             round-2's RENAME-first sequence would have left them dangling"
        );

        // Every node_sources row must point to an existing sources row.
        let orphans: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM node_sources ns
                 LEFT JOIN sources s ON s.id = ns.source_id
                 WHERE s.id IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            orphans, 0,
            "no node_sources row may reference a deleted source after migration"
        );
    }

    #[test]
    fn migration_preserves_edges_source_fk_after_rebuild() {
        // Same F13 case, the second FK relation: edges.source_id.
        // Round-2's broken migration also dangled edge → source
        // references. The fixture seeds one edge with source_id=1;
        // after migration that reference must still resolve.
        let mut conn = make_epoch_1_db_with_full_graph();
        let edge_count_before = row_count(&conn, "edges");
        assert_eq!(edge_count_before, 1, "fixture seeds 1 edge");

        KnowledgeStore::init_schema(&mut conn).unwrap();

        let edge_count_after = row_count(&conn, "edges");
        assert_eq!(edge_count_after, 1, "edge row must survive migration");

        let edge_source_id: i64 = conn
            .query_row("SELECT source_id FROM edges WHERE id = 10", [], |r| r.get(0))
            .unwrap();
        assert_eq!(edge_source_id, 1, "edge's source_id must survive verbatim");

        // The source must exist for the edge's FK to resolve.
        let source_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sources WHERE id = ?1",
                params![edge_source_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(source_exists, 1, "edge's source must still exist");
    }

    #[test]
    fn migration_passes_foreign_key_check_after_completion() {
        // Independent referential-integrity verification: after
        // migration, `PRAGMA foreign_key_check` must report ZERO
        // violations across the entire database. Round-2's broken
        // migration would surface multiple violations here (one per
        // dangling node_sources row + one per dangling edge).
        let mut conn = make_epoch_1_db_with_full_graph();
        KnowledgeStore::init_schema(&mut conn).unwrap();
        let violations = fk_check_violation_count(&conn);
        assert_eq!(
            violations, 0,
            "PRAGMA foreign_key_check must report zero violations after migration; \
             a non-zero count means dangling FK references survived"
        );
    }

    #[test]
    fn migration_preserves_autoincrement_counter() {
        // F13 also names the AUTOINCREMENT counter as a preservation
        // requirement. The fixture's sources rows have IDs 1 and 5
        // (non-contiguous, with sqlite_sequence forced to 5).
        // After migration, inserting a new source must yield ID 6
        // — NOT 2 (which is what would happen if the counter reset).
        let mut conn = make_epoch_1_db_with_full_graph();
        // Pre-migration sanity: counter is 5.
        let counter_before: i64 = conn
            .query_row(
                "SELECT seq FROM sqlite_sequence WHERE name = 'sources'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(counter_before, 5, "fixture sets sqlite_sequence to 5");

        KnowledgeStore::init_schema(&mut conn).unwrap();

        // Post-migration: counter must still be 5.
        let counter_after: i64 = conn
            .query_row(
                "SELECT seq FROM sqlite_sequence WHERE name = 'sources'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            counter_after, 5,
            "AUTOINCREMENT counter must survive the migration (was 5, became {counter_after})"
        );

        // Behavioral check: inserting a new source without specifying
        // ID must yield 6, proving the counter is in effect.
        conn.execute(
            "INSERT INTO sources (source_type, uri, ingested_at_unix, fidelity, content_hash, format)
             VALUES ('local_file', '/new.md', 300, 'direct', 'hash-c', 'markdown')",
            [],
        )
        .unwrap();
        let new_id: i64 = conn.last_insert_rowid();
        assert_eq!(
            new_id, 6,
            "next AUTOINCREMENT insert must yield 6 (counter+1), got {new_id}; \
             a value of 2 would mean the counter reset on DROP"
        );
    }

    #[test]
    fn migration_recreates_three_indexes() {
        // Round-2's migration recreated the three sources indexes.
        // FIX 13 retains that, but with a different sequence that
        // could regress the index recreation if the developer
        // forgot. This test independently verifies all three exist
        // after migration.
        let mut conn = make_epoch_1_db_with_full_graph();
        KnowledgeStore::init_schema(&mut conn).unwrap();
        let names: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master \
                 WHERE type='index' AND tbl_name='sources' \
                 ORDER BY name",
            )
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .filter_map(|n| n.ok())
            .collect();
        // SQLite auto-creates an internal `sqlite_autoindex_sources_*`
        // index for the UNIQUE constraint, so we filter to the named
        // ones we explicitly created in SCHEMA_DDL / migration.
        let named: Vec<&String> = names
            .iter()
            .filter(|n| n.starts_with("idx_sources_"))
            .collect();
        assert_eq!(
            named.len(),
            3,
            "expected exactly 3 named idx_sources_* indexes, got {named:?}"
        );
        assert!(named.iter().any(|n| n.as_str() == "idx_sources_uri"));
        assert!(named.iter().any(|n| n.as_str() == "idx_sources_format"));
        assert!(named.iter().any(|n| n.as_str() == "idx_sources_ingested"));
    }

    #[test]
    fn migration_preserves_node_data_unmodified() {
        // The migration touches only `sources`. Verify that nothing
        // in `nodes` was disturbed — content, type, timestamps,
        // access_count must all match the pre-migration values.
        let mut conn = make_epoch_1_db_with_full_graph();
        let alpha_before: (String, String, i64, i64) = conn
            .query_row(
                "SELECT content, node_type, created_at_unix, last_accessed_unix \
                 FROM nodes WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();

        KnowledgeStore::init_schema(&mut conn).unwrap();

        let alpha_after: (String, String, i64, i64) = conn
            .query_row(
                "SELECT content, node_type, created_at_unix, last_accessed_unix \
                 FROM nodes WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            alpha_before, alpha_after,
            "nodes row 1 must survive migration unchanged"
        );
    }

    #[test]
    fn migration_keeps_cascade_delete_working_post_migration() {
        // After migration, deleting a source must cascade to
        // node_sources and edges. This proves FK enforcement is
        // active AND points at the right tables — round-2's broken
        // migration would have left node_sources pointing at a
        // dropped table, so this DELETE would silently no-op the
        // cascade.
        let mut conn = make_epoch_1_db_with_full_graph();
        KnowledgeStore::init_schema(&mut conn).unwrap();

        // Delete source 5 — this should cascade to:
        //   - node_sources rows (1,5) and (2,5)
        //   - no edges (the only edge has source_id=1, not 5)
        let deleted = conn
            .execute("DELETE FROM sources WHERE id = ?1", params![5_i64])
            .unwrap();
        assert_eq!(deleted, 1);

        let mappings_after: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM node_sources WHERE source_id = 5",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            mappings_after, 0,
            "ON DELETE CASCADE must remove dependent node_sources rows after migration; \
             non-zero count would indicate FK enforcement is OFF or pointed at the wrong table"
        );

        // The OTHER node_sources row (1,1) should still be present.
        let surviving: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM node_sources WHERE source_id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(surviving, 1, "unrelated node_sources row must survive");
    }

    #[test]
    fn migration_records_version_2_after_full_graph_rebuild() {
        // Independent verification that the schema_version row gets
        // written ONLY after a successful migration (not before, not
        // half-done). Tests FIX 13's step 13.
        let mut conn = make_epoch_1_db_with_full_graph();
        assert_eq!(read_recorded_version(&conn), None, "epoch-1 has no version row");
        KnowledgeStore::init_schema(&mut conn).unwrap();
        assert_eq!(
            read_recorded_version(&conn),
            Some(CURRENT_SCHEMA_VERSION),
            "post-migration version must be recorded"
        );
    }

    #[test]
    fn migration_widens_unique_key_to_three_columns() {
        // The FIX 5 motivating recovery path. With epoch-1's old
        // 2-column key, a second source row with the same (uri, hash)
        // under a different format would be rejected. With the
        // 3-column key after migration, it's accepted.
        let mut conn = make_epoch_1_db_with_full_graph();
        KnowledgeStore::init_schema(&mut conn).unwrap();

        // Insert a source with the SAME uri and hash as id=1, but
        // a DIFFERENT format. Old key would reject; new key accepts.
        let result = conn.execute(
            "INSERT INTO sources (source_type, uri, ingested_at_unix, fidelity, content_hash, format)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params!["local_file", "/note.md", 999_i64, "direct", "hash-a", "html"],
        );
        assert!(
            result.is_ok(),
            "post-migration schema must accept (uri, hash, format) triple distinct only by format; \
             got {result:?}"
        );
        // Sanity: the new row got auto-assigned ID 6 (counter
        // started at 5 + 1).
        let new_id: i64 = conn.last_insert_rowid();
        assert_eq!(new_id, 6, "AUTOINCREMENT must continue from preserved counter");
    }

    // ── FIX 14 (P1-high): atomic FK check + version row inside tx ──
    //
    // Round-3 ran `PRAGMA foreign_key_check` and the version-row
    // INSERT after `tx.commit()`. A failed FK check returned Err but
    // the database was already structurally epoch-2 with no version
    // row — and `init_schema` would silently backfill version=2 on
    // next open via the current-epoch arm, accepting a corrupt graph.
    // Round-4 puts the rebuild + integrity check + version row in
    // ONE atomic transaction, so the database is either fully
    // epoch-2-with-clean-integrity-AND-version, or fully epoch-1.

    #[test]
    fn migration_with_pre_existing_orphan_aborts_atomically() {
        // F14 motivating case. The fixture has an orphan node_sources
        // row referencing source_id=99999 (which doesn't exist).
        // Round-3 would have committed the schema rebuild, then
        // raised an error on the post-commit FK check, leaving the
        // database structurally epoch-2 with no version row.
        // Round-4's atomic transaction must roll the entire rebuild
        // back, leaving epoch-1 untouched.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        // Drop the fixture's connection so we get a clean reopen.
        drop(make_corrupt_epoch_1_db(&path));

        // Now open via KnowledgeStore::init_schema. The migration
        // should detect the orphan via the in-tx FK check and roll
        // back, returning Err.
        let mut conn = Connection::open(&path).unwrap();
        let err = KnowledgeStore::init_schema(&mut conn)
            .expect_err("migration must abort when fixture has orphan rows");
        let msg = err.to_string();
        assert!(
            msg.contains("foreign-key violation"),
            "expected the FK violation error message, got: {msg}"
        );

        // CRITICAL ASSERTION: the database is still epoch-1 — the
        // 3-column UNIQUE constraint must NOT be present, and there
        // is no `schema_version` row. Round-3's bug was that the
        // 3-column key WAS present (commit happened) and the version
        // row was missing, which then got silently backfilled.
        let sources_sql = read_sources_sql(&conn);
        assert!(
            sources_sql.contains("UNIQUE(uri, content_hash)")
                && !sources_sql.contains("UNIQUE(uri, content_hash, format)"),
            "ROLLBACK must restore epoch-1 schema; got: {sources_sql}"
        );
        assert_eq!(
            read_recorded_version(&conn),
            None,
            "no version row may be written when migration aborts"
        );
    }

    #[test]
    fn migration_aborted_open_does_not_silently_succeed_on_retry() {
        // The atomicity invariant means a SECOND open on the same
        // corrupted database must produce the SAME error — not a
        // silent acceptance. Round-3's bug was that the second open
        // would see epoch-2 structure (because round-3 committed
        // the rebuild) and backfill version=2 without rerunning the
        // FK check. Round-4's rollback ensures the corruption is
        // still visible and the migration still fails.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(make_corrupt_epoch_1_db(&path));

        // First attempt: fails as expected.
        {
            let mut conn = Connection::open(&path).unwrap();
            let _ = KnowledgeStore::init_schema(&mut conn).expect_err("first attempt fails");
        }
        // Second attempt: must ALSO fail — no silent backfill.
        let mut conn = Connection::open(&path).unwrap();
        let err = KnowledgeStore::init_schema(&mut conn)
            .expect_err("second attempt must also fail; no silent backfill");
        assert!(
            err.to_string().contains("foreign-key violation"),
            "second attempt must surface the same corruption diagnostic"
        );
    }

    #[test]
    fn migration_succeeds_after_operator_repairs_orphans() {
        // Operator-recovery path: a database with orphan rows can
        // be brought back into compliance by deleting the orphans
        // (or repointing them at valid sources). After that, the
        // migration must succeed normally. This proves the F14
        // boundary is "reject corruption, allow recovery" rather
        // than "permanently brick the database".
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(make_corrupt_epoch_1_db(&path));

        // First open fails — the FIX 14 detection.
        {
            let mut conn = Connection::open(&path).unwrap();
            let _ = KnowledgeStore::init_schema(&mut conn).expect_err("orphan present");

            // Operator repairs the corruption directly via SQL.
            // FK is back ON after the failed migration (the
            // unconditional re-enable) so we have to disable it
            // again to delete the orphan without trying to enforce
            // its (impossible) FK.
            conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
            conn.execute(
                "DELETE FROM node_sources WHERE source_id = 99999",
                [],
            )
            .unwrap();
        }

        // Second open: migration now succeeds.
        let mut conn = Connection::open(&path).unwrap();
        KnowledgeStore::init_schema(&mut conn)
            .expect("migration must succeed after orphan repair");
        assert_eq!(
            read_recorded_version(&conn),
            Some(CURRENT_SCHEMA_VERSION),
            "version row must be recorded after successful migration"
        );
        assert!(
            read_sources_sql(&conn).contains("UNIQUE(uri, content_hash, format)"),
            "schema must be at epoch-2 after successful migration"
        );
    }

    #[test]
    fn migration_rollback_leaves_no_sources_new_artifact() {
        // Defense-in-depth: a rolled-back migration must leave NO
        // `sources_new` table behind. The Drop-rollback machinery
        // is supposed to reverse every CREATE inside the
        // transaction, but verifying it directly catches any
        // future regression where someone moves a CREATE outside
        // the transaction by mistake.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(make_corrupt_epoch_1_db(&path));

        let mut conn = Connection::open(&path).unwrap();
        let _ = KnowledgeStore::init_schema(&mut conn).expect_err("orphan triggers rollback");

        // No `sources_new` artifact may exist.
        let sources_new_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sources_new'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            sources_new_count, 0,
            "rolled-back migration must not leave sources_new table behind"
        );

        // The original `sources` table must still exist.
        let sources_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sources'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            sources_count, 1,
            "original sources table must survive rollback"
        );
    }

    // ── FIX 17 (P1-high): atomic backfill with FK check ──
    //
    // Round-4's FIX 14 made the migration path atomic. F17 surfaced
    // the sibling vulnerability in the backfill path: a database
    // whose schema is structurally current but has no version row
    // (the round-3 broken-migration shape) was being silently
    // marked valid epoch-2 on the next open, accepting any orphan
    // rows that survived. F17 routes the backfill through
    // backfill_version_with_integrity_check, which runs PRAGMA
    // foreign_key_check + the version-row INSERT inside ONE
    // transaction so the database is either "version=2 with
    // verified integrity" or "no version row at all".

    #[test]
    fn unversioned_current_schema_with_orphans_refuses_backfill() {
        // F17 motivating regression. The fixture is the exact
        // round-3 broken-migration shape: epoch-2 structure, no
        // version row, orphan node_sources. The backfill helper
        // must detect via PRAGMA foreign_key_check and refuse.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(make_unversioned_corrupt_epoch_2_db(&path));

        let mut conn = Connection::open(&path).unwrap();
        let err = KnowledgeStore::init_schema(&mut conn)
            .expect_err("init_schema must refuse to bless a corrupt-but-current db");
        let msg = err.to_string();
        assert!(
            msg.contains("foreign-key violation") && msg.contains("refusing to backfill"),
            "expected the FK-violation diagnostic; got: {msg}"
        );

        // CRITICAL: the schema_version table is still empty.
        // Round-3 would have left the version row in place after
        // the FK check failed (because the bare INSERT happened
        // first). FIX 17's atomic transaction must roll back the
        // version-row insert AS WELL.
        assert_eq!(
            read_recorded_version(&conn),
            None,
            "no version row may be written when backfill aborts"
        );
    }

    #[test]
    fn unversioned_current_schema_orphan_repaired_then_succeeds() {
        // Operator-recovery path. After the first init_schema
        // fails, the operator removes the orphan row, then a
        // second init_schema succeeds and records the version row.
        // This proves the F17 boundary is "reject corruption,
        // allow recovery" — not "permanently brick the database".
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(make_unversioned_corrupt_epoch_2_db(&path));

        // First attempt: fails.
        {
            let mut conn = Connection::open(&path).unwrap();
            let _ = KnowledgeStore::init_schema(&mut conn)
                .expect_err("orphan present, must fail");

            // Operator repairs via direct SQL. FIX 12 turned FK
            // back ON after the failed init_schema, so we have to
            // disable it again to delete the orphan without
            // triggering enforcement on the (impossible) FK.
            conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
            conn.execute(
                "DELETE FROM node_sources WHERE source_id = 99999",
                [],
            )
            .unwrap();
        }

        // Second attempt: now clean, must succeed and record v=2.
        let mut conn = Connection::open(&path).unwrap();
        KnowledgeStore::init_schema(&mut conn)
            .expect("init_schema must succeed after orphan repair");
        assert_eq!(
            read_recorded_version(&conn),
            Some(CURRENT_SCHEMA_VERSION),
            "version row must be recorded after successful backfill"
        );
    }

    #[test]
    fn unversioned_current_schema_clean_succeeds_backfill() {
        // Happy path for the same code branch: a database in the
        // structurally-current-but-no-version-row state with NO
        // orphan rows. backfill_version_with_integrity_check must
        // run the FK check (which returns clean), then insert
        // version=2. Subsequent operations work normally and a
        // second init_schema is a no-op (version is already 2).
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        // Build a clean unversioned-but-current fixture: apply the
        // full schema, insert one valid source + node + mapping,
        // but no version row and no orphans.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
            conn.execute_batch(SCHEMA_VERSION_TABLE_DDL).unwrap();
            conn.execute_batch(SCHEMA_DDL).unwrap();
            conn.execute(
                "INSERT INTO sources (id, source_type, uri, ingested_at_unix, fidelity, content_hash, format)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![1_i64, "local_file", "/clean.md", 100_i64, "direct", "hash", "markdown"],
            ).unwrap();
            conn.execute(
                "INSERT INTO nodes (id, content, node_type, created_at_unix, last_accessed_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![1_i64, "content", "fact", 100_i64, 100_i64],
            ).unwrap();
            conn.execute(
                "INSERT INTO node_sources (node_id, source_id) VALUES (?1, ?2)",
                params![1_i64, 1_i64],
            ).unwrap();
        }

        // First init_schema: clean FK check, backfill happens.
        let mut conn = Connection::open(&path).unwrap();
        KnowledgeStore::init_schema(&mut conn)
            .expect("init_schema must succeed on clean unversioned db");
        assert_eq!(read_recorded_version(&conn), Some(CURRENT_SCHEMA_VERSION));

        // Second init_schema: recorded.is_none() is now false, so
        // the backfill branch isn't taken. No double-insert, no
        // duplicate-PK error.
        KnowledgeStore::init_schema(&mut conn)
            .expect("second init_schema must be a no-op");
        let version_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version_count, 1, "no duplicate version row on second open");
    }

    #[test]
    fn aborted_backfill_does_not_silently_succeed_on_retry() {
        // Atomicity property: a SECOND init_schema on the same
        // corrupt-unversioned db must produce the SAME error — no
        // silent acceptance on retry. This is the round-3 → round-5
        // regression test: if the rollback weren't truly atomic
        // (e.g., the version-row insert leaked outside the
        // transaction), the second attempt would see a recorded
        // version=2 and skip the backfill branch entirely, silently
        // accepting the corrupt graph.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(make_unversioned_corrupt_epoch_2_db(&path));

        // First attempt: fails as expected.
        {
            let mut conn = Connection::open(&path).unwrap();
            let _ = KnowledgeStore::init_schema(&mut conn).expect_err("first attempt fails");
        }
        // Second attempt: MUST also fail — the version row must
        // still be missing.
        let mut conn = Connection::open(&path).unwrap();
        let err = KnowledgeStore::init_schema(&mut conn)
            .expect_err("second attempt must also fail; no silent backfill");
        assert!(
            err.to_string().contains("foreign-key violation"),
            "second attempt must surface the same corruption"
        );
        assert_eq!(
            read_recorded_version(&conn),
            None,
            "no version row may have been written across the two failed attempts"
        );
    }

    #[test]
    fn schema_version_backfill_survives_concurrent_open() {
        // ── Codex re-review FIX 19 (P2-medium) regression ──
        //
        // Round-5's `backfill_version_with_integrity_check` opened the
        // rusqlite DEFAULT (DEFERRED) transaction. A DEFERRED txn
        // acquires a RESERVED write lock only on the first WRITE
        // statement — not at BEGIN. Two openers of the same clean
        // unversioned epoch-2 DB therefore both:
        //   1. passed the outer `recorded.is_none()` check in init_schema,
        //   2. opened their own DEFERRED transactions (no lock yet),
        //   3. ran `PRAGMA foreign_key_check` under independent SHARED
        //      locks (SHARED readers coexist), both observing clean,
        //   4. raced on `INSERT INTO schema_version` — the winner took
        //      RESERVED and committed version=2; the loser either hit
        //      SQLITE_BUSY mid-write (HEAD set no `busy_timeout`, so
        //      SQLITE_BUSY surfaced immediately with no retry) or, if
        //      it arrived just after the winner committed, hit a
        //      UNIQUE/PRIMARY KEY violation on the version row.
        // Either way a *legitimate* opener failed against a database
        // that was already structurally valid — a self-inflicted
        // availability regression versus the prior `INSERT OR IGNORE`.
        //
        // The fix: the helper now opens with
        // `TransactionBehavior::Immediate` (BEGIN IMMEDIATE — RESERVED
        // acquired at BEGIN, before any read), so concurrent
        // backfillers serialize at BEGIN; the loser gets SQLITE_BUSY
        // there and the `busy_timeout` set in `KnowledgeStore::open`
        // retries it. After acquiring the write lock the helper
        // re-reads `schema_version` under that lock — double-checked
        // locking — and if the winner already wrote version=2 it
        // commits a no-op and returns Ok. Both openers succeed.
        //
        // Test methodology: a single un-synchronised pair of opens can
        // serialise by luck (opener A finishes the whole open, writes
        // version=2, and only THEN does opener B read `recorded`,
        // seeing Some(2) and skipping the backfill branch entirely —
        // no race). A `Barrier` releases both threads into
        // `KnowledgeStore::open` simultaneously so they reach the
        // `SELECT MAX(version)` → backfill → INSERT window together,
        // and the loop runs it against many fresh DBs so the contended
        // window is hit reliably. On 8e7775a (pre-fix) at least one
        // iteration fails; with the fix every iteration passes.
        const ITERATIONS: usize = 24;
        for iter in 0..ITERATIONS {
            let tmpdir = TempDir::new().unwrap();
            let db_path = tmpdir.path().join("kg.db");
            // Fresh clean unversioned epoch-2 DB each iteration. The
            // fixture pre-sets WAL so the only thing the two openers
            // can contend on is the backfill INSERT — i.e. F19, not
            // journal-mode setup.
            drop(make_clean_unversioned_epoch_2_db(&db_path));

            let barrier = Arc::new(std::sync::Barrier::new(2));
            let p1 = db_path.clone();
            let p2 = db_path.clone();
            let b1 = Arc::clone(&barrier);
            let b2 = Arc::clone(&barrier);

            // Each thread maps the result to `Result<(), String>` so
            // the closure return type is unconditionally `Send`,
            // independent of whether `KnowledgeStore` /
            // `OrchestratorError` are `Send`. The opened store is
            // dropped immediately — the assertion is purely "did the
            // open (and therefore init_schema → backfill) succeed".
            let t1 = std::thread::spawn(move || {
                b1.wait();
                KnowledgeStore::open(&p1, Box::new(MockEmbedder::new()))
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            });
            let t2 = std::thread::spawn(move || {
                b2.wait();
                KnowledgeStore::open(&p2, Box::new(MockEmbedder::new()))
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            });

            let r1 = t1.join().expect("opener thread 1 must not panic");
            let r2 = t2.join().expect("opener thread 2 must not panic");
            assert!(
                r1.is_ok(),
                "iteration {iter}: opener 1 failed against a structurally-valid db: {r1:?}"
            );
            assert!(
                r2.is_ok(),
                "iteration {iter}: opener 2 failed against a structurally-valid db: {r2:?}"
            );

            // After both openers, `schema_version` must hold EXACTLY
            // one row, value 2 — no duplicate row, no missing row.
            let conn = Connection::open(&db_path).unwrap();
            let rows: Vec<i64> = conn
                .prepare("SELECT version FROM schema_version")
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(
                rows,
                vec![2],
                "iteration {iter}: schema_version must hold exactly one row = [2]"
            );
        }
    }

    // ── Codex re-review FIX 26 (round 9): in_memory constructor parity ──

    #[test]
    fn knowledge_in_memory_busy_timeout_pinned_to_5_seconds() {
        // **Codex re-review FIX 26 (round 9):** round-8 added
        // `init_sqlite_connection` to `KnowledgeStore::in_memory` (and
        // even left a self-referential comment pointing at "the
        // `busy_timeout_pinned_to_5_seconds` regression test") but the
        // matching regression test was never actually written — the
        // three siblings (Timeline, ConversationStore, GoalStore) all
        // got theirs in FIX 23 round 8, leaving KnowledgeStore as the
        // only store without constructor-parity coverage.
        //
        // The default `:memory:` database is private to a single
        // connection per SQLite docs (*"Every :memory: database is
        // distinct from every other"*), so cross-connection lock
        // contention is impossible and the pragma is functionally a
        // no-op at runtime. The test exists as a regression detector
        // against future drift: someone copy-pasting an init path and
        // forgetting `init_sqlite_connection` will trip this assertion
        // immediately rather than degrading the SQLite policy silently
        // across the workspace.
        let store = KnowledgeStore::in_memory(Box::new(MockEmbedder::new())).unwrap();
        let conn = store.conn.lock().unwrap();
        let timeout: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            timeout, 5_000,
            "KnowledgeStore::in_memory must pin busy_timeout to 5000ms (F26 constructor parity)"
        );
    }

    // ── Codex re-review FIX 21 (round 7) regression — typed error mapping ──

    #[test]
    fn map_sqlite_err_routes_database_busy_to_transient_lock() {
        // SQLITE_BUSY (different connection/process holds incompatible
        // lock) must surface as `TransientLock`, not `Planning`. Round-6
        // left `busy_timeout` exhaustion as `Planning("...database is
        // locked")`, requiring daemons to string-match for retry
        // decisions. F21 routes it through a typed variant so callers
        // can pattern-match.
        let err = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some("test database is locked".to_string()),
        );
        let mapped = map_sqlite_err(err);
        assert!(
            matches!(mapped, OrchestratorError::TransientLock { .. }),
            "SQLITE_BUSY must map to TransientLock; got {mapped:?}"
        );
    }

    #[test]
    fn map_sqlite_err_routes_database_locked_to_transient_lock() {
        // SQLITE_LOCKED (same connection / shared cache conflict) is
        // also transient and retryable, so it routes to the same typed
        // variant as SQLITE_BUSY. Both lock-class error codes share the
        // `DatabaseBusy | DatabaseLocked` pattern in `map_sqlite_err`.
        let err = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_LOCKED),
            None,
        );
        let mapped = map_sqlite_err(err);
        assert!(
            matches!(mapped, OrchestratorError::TransientLock { .. }),
            "SQLITE_LOCKED must map to TransientLock; got {mapped:?}"
        );
    }

    #[test]
    fn map_sqlite_err_preserves_planning_for_non_lock_failures() {
        // Non-busy/non-locked SqliteFailure (e.g. SQLITE_CONSTRAINT
        // for FK / UNIQUE violations, SQLITE_CORRUPT, etc.) must keep
        // the existing `Planning` classification. The F21 change is a
        // narrow routing of the two retryable lock codes, NOT a
        // wholesale reclassification of every SQLite error.
        let err = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
            Some("UNIQUE constraint failed".to_string()),
        );
        let mapped = map_sqlite_err(err);
        assert!(
            matches!(mapped, OrchestratorError::Planning(_)),
            "SQLITE_CONSTRAINT must stay Planning; got {mapped:?}"
        );
    }

    #[test]
    fn map_sqlite_err_preserves_planning_for_non_sqlitefailure_variants() {
        // `rusqlite::Error` has many non-`SqliteFailure` variants
        // (QueryReturnedNoRows, InvalidColumnIndex, etc.). The F21
        // routing only touches `SqliteFailure` with the lock codes;
        // every other Error variant must continue to map to Planning.
        let err = rusqlite::Error::QueryReturnedNoRows;
        let mapped = map_sqlite_err(err);
        assert!(
            matches!(mapped, OrchestratorError::Planning(_)),
            "QueryReturnedNoRows must stay Planning; got {mapped:?}"
        );
    }

    #[test]
    fn open_or_init_survives_n_thread_contention() {
        // ── Codex re-review FIX 20 (P2-medium) regression ──
        //
        // F19's BEGIN IMMEDIATE + 5s `busy_timeout` serialize concurrent
        // backfillers correctly *as long as the winning opener releases
        // the write lock within the 5s busy window*. If the winner holds
        // RESERVED through a long `PRAGMA foreign_key_check` (large
        // unversioned graph) or any other writer holds the DB longer
        // than 5s, the loser's `BEGIN IMMEDIATE` exhausts its busy
        // timeout and surfaces SQLITE_BUSY at BEGIN — failing a
        // legitimate opener against a valid DB. F19 closed the
        // *insert race*; this finding pushes it out to a *bounded
        // lock-wait race*.
        //
        // The fix: `KnowledgeStore::open` wraps the open+backfill
        // sequence in a retry-with-backoff loop that matches only on
        // `OrchestratorError::TransientLock` (new F21 typed variant)
        // and sleeps with exponential backoff between attempts.
        //
        // ── Iron Law #9 test design ──
        //
        // The small seeded fixture's `foreign_key_check` finishes in
        // microseconds, so an unaided N-thread `open` test does NOT
        // exceed the 5s `busy_timeout` and PASSES even on 6f3f5c8 —
        // verified empirically on this WSL2 box. A test that doesn't
        // reproduce the bug is worse than no test.
        //
        // To deterministically force a >5s contention WITHOUT
        // touching production code (no test-only sleep injected into
        // `backfill_version_with_integrity_check`), this test takes
        // the production lock from an independent connection in the
        // test thread itself: opens a second `Connection` on the same
        // file, issues `BEGIN IMMEDIATE`, sleeps past the 5s window,
        // then commits. While the test holds RESERVED, every opener
        // thread's `BEGIN IMMEDIATE` inside the backfill blocks via
        // its own `busy_timeout`. On 6f3f5c8 the openers' 5s timeout
        // expires before the lock-holder releases → SQLITE_BUSY →
        // their opens fail (the F20 bug). On the post-fix code the
        // retry-with-backoff loop reattempts after a short sleep,
        // catches the lock release shortly after, and succeeds.
        //
        // Hold time = 5300ms — just past `busy_timeout` but short
        // enough that the post-fix retry (initial 100ms backoff) catches
        // the release within its second 5s window. Test wall-clock ≈ 5.4s.
        const HOLD_MS: u64 = 5_300;
        const N_THREADS: usize = 4;

        let tmpdir = TempDir::new().unwrap();
        let db_path = tmpdir.path().join("kg.db");
        drop(make_clean_unversioned_epoch_2_db(&db_path));

        // Open the lock-holder connection in this test thread. Set a
        // 0ms busy_timeout so the holder itself doesn't sit waiting
        // (no one else holds RESERVED yet at this moment, so BEGIN
        // IMMEDIATE acquires immediately).
        let mut holder = Connection::open(&db_path).unwrap();
        holder.busy_timeout(std::time::Duration::from_millis(0)).unwrap();
        let holder_tx = holder
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .expect("lock holder must acquire RESERVED on uncontended DB");

        // Spawn opener threads, barrier-synced. Barrier size is
        // N_THREADS + 1 (the workers + the test thread); the test
        // thread releases the workers AFTER the holder transaction
        // is open and the lock is reserved.
        let barrier = Arc::new(std::sync::Barrier::new(N_THREADS + 1));
        let handles: Vec<std::thread::JoinHandle<Result<(), String>>> = (0..N_THREADS)
            .map(|i| {
                let p = db_path.clone();
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    KnowledgeStore::open(&p, Box::new(MockEmbedder::new()))
                        .map(|_| ())
                        .map_err(|e| format!("thread {i}: {e}"))
                })
            })
            .collect();

        // Release the workers (lock still held by this thread), then
        // hold past the 5s busy_timeout window.
        barrier.wait();
        std::thread::sleep(std::time::Duration::from_millis(HOLD_MS));

        // Release the production lock so retrying workers can finally
        // acquire RESERVED.
        holder_tx.commit().expect("holder commit must succeed");
        drop(holder);

        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().expect("thread must not panic"))
            .collect();
        for r in &results {
            assert!(
                r.is_ok(),
                "opener failed against a valid DB (F20 regression): {r:?}"
            );
        }

        // Exactly one schema_version row = [2] after all four opens.
        let conn = Connection::open(&db_path).unwrap();
        let rows: Vec<i64> = conn
            .prepare("SELECT version FROM schema_version")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows, vec![2]);
    }

    // ── Codex re-review FIX 24 (round 8): retry budget off-by-one ──

    #[test]
    fn retry_with_backoff_invokes_op_exactly_max_open_attempts_under_transient_lock() {
        // F24 regression. Round-7 set `MAX_OPEN_ATTEMPTS = 5`, which
        // produced only 4 inter-attempt sleeps (100, 200, 400, 800),
        // making the documented final 1600ms sleep and the
        // `MAX_BACKOFF_MS = 2000` cap unreachable. Round-8 bumps the
        // constant to 6 so the documented `100 → 200 → 400 → 800 →
        // 1600 ms` sequence fully fires (5 sleeps across 6 attempts).
        //
        // This test directly drives `retry_with_backoff` with a
        // closure that always returns `TransientLock` and counts
        // invocations, asserting exactly `MAX_OPEN_ATTEMPTS` calls
        // before the helper propagates the last `TransientLock` to
        // the caller. Generic over `T = ()` so no real DB is needed.
        //
        // Wall-clock: the test sleeps the full backoff sequence
        // (100+200+400+800+1600 = 3100 ms) before propagating. Not
        // the fastest unit test, but it's the only way to verify the
        // retry count and sleep sequence are honored end-to-end.
        let count = std::sync::atomic::AtomicUsize::new(0);
        let result: Result<(), OrchestratorError> = retry_with_backoff(|| {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Synthesize a TransientLock with a real SqliteFailure
            // payload — the retry helper only inspects the variant
            // discriminant, not the inner Error contents.
            let synth = rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
                Some("synthetic".to_string()),
            );
            Err(OrchestratorError::TransientLock { source: synth })
        });

        let attempts = count.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            attempts, MAX_OPEN_ATTEMPTS,
            "retry_with_backoff must invoke op exactly MAX_OPEN_ATTEMPTS times under \
             sustained TransientLock; got {attempts}"
        );
        assert!(
            matches!(result, Err(OrchestratorError::TransientLock { .. })),
            "retry_with_backoff must surface TransientLock after exhausting retries; got {result:?}"
        );
    }

    #[test]
    fn retry_with_backoff_short_circuits_on_non_transient_error() {
        // Defense-in-depth complement to the F24 attempt-count test.
        // The retry loop must NEVER retry non-`TransientLock` errors;
        // a `Planning` error should propagate immediately on the
        // first attempt. Combined with the F24 test above this pins
        // both ends of the retry contract.
        let count = std::sync::atomic::AtomicUsize::new(0);
        let result: Result<(), OrchestratorError> = retry_with_backoff(|| {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(OrchestratorError::Planning("not retryable".to_string()))
        });

        let attempts = count.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            attempts, 1,
            "retry_with_backoff must short-circuit on non-TransientLock errors; \
             got {attempts} attempts"
        );
        assert!(matches!(result, Err(OrchestratorError::Planning(_))));
    }
}
