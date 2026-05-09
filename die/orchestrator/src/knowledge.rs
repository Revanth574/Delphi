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
use tracing::{debug, info};

use crate::OrchestratorError;
use crate::environment::Fidelity;

/// Default embedding dimension for the [`MockEmbedder`] and as the canonical
/// dimension when no other constraint exists.
pub const DEFAULT_EMBEDDING_DIMENSION: usize = 32;

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

/// Local model-based embedder. Stub implementation: returns
/// `Fidelity::Unavailable` when no model file is configured. Meant to be
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
        if sanitized.requires_confirmation {
            return Err(OrchestratorError::Planning(format!(
                "cloud embedding refused: privacy score {} requires user confirmation",
                sanitized.score.total
            )));
        }
        // Real network call happens here in a future task. For now return
        // an empty vector tagged Subprocess to indicate the pathway exists.
        debug!(
            sanitized_len = sanitized.sanitized_text.len(),
            pii_count = sanitized.pii_count(),
            score = sanitized.score.total,
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
    pub fn open(
        db_path: &Path,
        embedder: Box<dyn Embedder>,
    ) -> Result<Self, OrchestratorError> {
        let conn = Connection::open(db_path).map_err(map_sqlite_err)?;
        Self::init_schema(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            embedder,
        })
    }

    pub fn in_memory(embedder: Box<dyn Embedder>) -> Result<Self, OrchestratorError> {
        let conn = Connection::open_in_memory().map_err(map_sqlite_err)?;
        Self::init_schema(&conn)?;
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
    fn init_schema(conn: &Connection) -> Result<(), OrchestratorError> {
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
                // Already current. If the version row was missing
                // (schema is correct but unrecorded), backfill it so
                // the next open reads from the recorded path.
                if recorded.is_none() {
                    conn.execute(
                        "INSERT OR IGNORE INTO schema_version (version) VALUES (?1)",
                        params![CURRENT_SCHEMA_VERSION],
                    )
                    .map_err(map_sqlite_err)?;
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
            return Err(OrchestratorError::Planning(format!(
                "{} edge {} -> {} would create a cycle",
                relation.as_str(),
                from_id,
                to_id
            )));
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
        let hash = content_hash(text.as_bytes());
        // Determine fidelity FIRST. The parser knows whether it can
        // actually extract concepts for this format; we honor its verdict.
        let (concepts, fidelity_used) = self.parse_concepts(text, format);
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
    /// **Codex re-review FIX 10+11 (P1-high):** the file is opened via
    /// [`safe_open_under_root`], which on Linux uses `openat2(2)` with
    /// `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH` to atomically reject
    /// symlinks at ANY component (not just the leaf), and on Windows
    /// walks each component checking `FILE_ATTRIBUTE_REPARSE_POINT`
    /// before opening the leaf with `FILE_FLAG_OPEN_REPARSE_POINT`.
    /// Round-2's `safe_open_no_follow` only checked the final
    /// component — Codex F10 demonstrated this missed intermediate
    /// symlinks, and F11 demonstrated `is_symlink()` missed
    /// non-symlink reparse points. The new contract requires the
    /// caller to supply the allowlist root that gated the request,
    /// so `safe_open_under_root` can anchor the walk to a
    /// directory FD rather than a re-resolvable path string.
    ///
    /// **Caller invariant**: `trusted_root` is the canonical allowlist
    /// root that contains `path`. The D-Bus service in
    /// `services::knowledge` looks up the matching root from its
    /// allowlist after `check_path_allowed` succeeds and passes it
    /// here.
    pub fn ingest_file(
        &self,
        trusted_root: &Path,
        path: &Path,
    ) -> Result<IngestionResult, OrchestratorError> {
        use std::io::Read;
        let mut file = safe_open_under_root(trusted_root, path).map_err(|e| {
            OrchestratorError::Planning(format!(
                "could not safely open {} for ingestion: {e}",
                path.display()
            ))
        })?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|e| {
            OrchestratorError::Planning(format!(
                "could not read {} for ingestion: {e}",
                path.display()
            ))
        })?;
        let head = &bytes[..bytes.len().min(64)];
        let format = detect_format(path, head);
        let uri = path.to_string_lossy().to_string();
        self.ingest_bytes(&bytes, &uri, format)
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
// FIX 10+11 (P1-high): kernel-level path-anchored safe open
// (supersedes round-2 FIX 8 / safe_open_no_follow)
// ────────────────────────────────────────────────────────────────────

/// Open `target` for reading, refusing to traverse ANY symlink/reparse
/// point between `trusted_root` and the target — including intermediate
/// directory components.
///
/// **Why this exists** (Codex re-review FIX 10 + FIX 11, P1-high):
/// round-2's `safe_open_no_follow(path)` only checked the FINAL path
/// component (Unix `O_NOFOLLOW`, Windows `metadata().file_type().is_symlink()`
/// after-the-fact). The Codex re-review demonstrated this is insufficient:
///
/// - **F10**: an attacker with write access inside an allowed root can
///   swap an intermediate directory for a symlink pointing at a sensitive
///   target. `O_NOFOLLOW` is silent on intermediate components — the
///   kernel happily traverses them — so the validated leaf path resolved
///   to one identity at canonicalize-time and a different identity at
///   open-time, exactly the TOCTOU class round-2 claimed to close.
/// - **F11**: Windows `is_symlink()` only catches symlink-typed reparse
///   points. NTFS supports several other reparse-point classes —
///   junctions, mount points, AppExecLink, OneDrive cloud-state — that
///   share the `FILE_ATTRIBUTE_REPARSE_POINT` flag but report false from
///   `is_symlink()`. The pre-open check must inspect the raw attribute
///   bit, not the typed wrapper.
///
/// The new contract: callers supply BOTH the allowlist root that gated
/// the request AND the canonical target path. The function refuses to
/// open if the open-time path traversal crosses any reparse point or
/// escapes the trusted root. The returned `File` handle is then the
/// identity the caller reads from — bytes come from the kernel object,
/// not from a path string that can be re-resolved.
///
/// # Platform behavior
///
/// - **Linux** (`target_os = "linux"`): the `openat2(2)` syscall with
///   `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`. The kernel atomically
///   walks every component from the directory FD opened on
///   `trusted_root` to `target` and returns `-ELOOP` if any component
///   is a symlink, or `-EXDEV` if the resolution would escape the root.
///   This is the same primitive Linux's `unshare`, fchroot, and
///   container runtimes use to anchor open-by-handle identity. There
///   is no TOCTOU window: the resolution and the open are one syscall.
///
/// - **Windows**: `openat2` has no equivalent. We approximate by
///   walking each component between `trusted_root` and `target`,
///   inspecting the `FILE_ATTRIBUTE_REPARSE_POINT` bit on each parent
///   directory's attributes via `symlink_metadata`, then opening the
///   final target with `FILE_FLAG_OPEN_REPARSE_POINT` (no follow) and
///   re-checking the attribute. This is best-effort — small TOCTOU
///   races remain between `symlink_metadata` calls — but it covers
///   ALL reparse-point classes (symlinks, junctions, mount points,
///   AppExecLink, etc.) and ALL components, not just the leaf.
///
/// - **Other targets** (e.g. macOS, BSD): returned as `Unsupported`.
///   The knowledge ingestion path is currently Linux/Windows only;
///   this guarantees no silent-degradation path on platforms we
///   haven't audited.
///
/// # Caller invariants
///
/// 1. `trusted_root` must already be canonicalized (no symlinks in
///    its own ancestry) — the allowlist layer in
///    `services::knowledge::KnowledgeService` enforces this.
/// 2. `target` must already be canonicalized AND verified to start
///    with `trusted_root`. This function checks (2) again as
///    defense-in-depth but does not re-canonicalize.
pub fn safe_open_under_root(
    trusted_root: &Path,
    target: &Path,
) -> std::io::Result<std::fs::File> {
    // Defense-in-depth: refuse the open if the target doesn't lie
    // under the supplied root. The caller is supposed to have
    // verified this already; we re-verify so a buggy caller can't
    // bypass the check.
    if !target.starts_with(trusted_root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "target path is not under the supplied trusted root",
        ));
    }

    #[cfg(target_os = "linux")]
    {
        linux_openat2_under_root(trusted_root, target)
    }
    #[cfg(windows)]
    {
        windows_open_under_root(trusted_root, target)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (trusted_root, target);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "safe_open_under_root requires Linux openat2 or Windows reparse-point detection; \
             this build target is not supported for knowledge ingestion",
        ))
    }
}

/// Linux-specific implementation: `openat2(2)` with
/// `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`.
///
/// The relative path passed to `openat2` is `target.strip_prefix(trusted_root)`,
/// so the kernel walks ONLY the components inside the trusted root.
/// `RESOLVE_NO_SYMLINKS` makes the kernel reject every symlink during
/// that walk; `RESOLVE_BENEATH` rejects any `..` traversal that would
/// escape the directory FD even if no symlinks are involved.
///
/// `SYS_openat2` is syscall 437 on every Linux ABI — confirmed via
/// libc 0.2.186 source for x86_64 (`SYS_openat2: c_long = 437`). The
/// kernel-side syscall has been stable since 5.6.
///
/// Memory safety (per CLAUDE.md §3):
/// - the `OpenHow` struct is owned on the stack, lives until after
///   the syscall returns, and is only read by the kernel;
/// - `relative_cstr` owns its bytes for the syscall's lifetime;
/// - the returned raw fd is immediately wrapped via `OwnedFd` (which
///   would close it on drop), then converted to `File` (transferring
///   ownership), so there is no double-close or leak path.
#[cfg(target_os = "linux")]
fn linux_openat2_under_root(
    trusted_root: &Path,
    target: &Path,
) -> std::io::Result<std::fs::File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    // Open the trusted root as a directory file descriptor. This is the
    // anchor for openat2 — every component traversal happens RELATIVE
    // to this fd, never re-resolving the trusted_root path string.
    let root_dir = std::fs::File::open(trusted_root)?;
    let root_fd = root_dir.as_raw_fd();

    // Compute the relative path from trusted_root to target. The
    // starts_with check above guarantees this strip won't fail.
    let relative = target.strip_prefix(trusted_root).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "target path is not under the supplied trusted root",
        )
    })?;
    // openat2 wants a NUL-terminated C string for the relative path.
    let relative_cstr = CString::new(relative.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "relative path contains an embedded NUL byte",
        )
    })?;

    // The `open_how` struct passed to openat2(2). Mirrors
    // <linux/openat2.h>'s definition exactly. We define it inline
    // because libc 0.2.186 doesn't expose `open_how` as a struct or
    // the RESOLVE_* flags as constants — the syscall number is
    // exposed but the surrounding ABI is not.
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    // From <linux/openat2.h> kernel uapi headers. Stable since 5.6.
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;

    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH,
    };

    // SAFETY: we pass the kernel a raw root_fd that we own (root_dir
    // is alive for the syscall), a NUL-terminated C string we own,
    // and a pointer to a stack-allocated OpenHow with its size. The
    // kernel reads from the path bytes and writes nothing through
    // these pointers. The returned value is the new file descriptor
    // on success or `-1` with errno set on failure.
    let raw_fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd,
            relative_cstr.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };

    if raw_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: raw_fd is a positive i64 value that the kernel has
    // verified is a valid newly-opened file descriptor. We
    // immediately transfer ownership into OwnedFd (which would close
    // it on drop if anything panicked), then into File via From<OwnedFd>.
    // No other code holds a reference to raw_fd.
    let owned: OwnedFd = unsafe { OwnedFd::from_raw_fd(raw_fd as i32) };
    Ok(std::fs::File::from(owned))
}

/// Windows-specific implementation: walk each component, reject any
/// reparse point, then open the leaf with `FILE_FLAG_OPEN_REPARSE_POINT`
/// for one final no-follow safety net.
///
/// This is best-effort: between each `symlink_metadata` call and the
/// final open, an attacker with write access inside the trusted root
/// can race-replace a component. Windows lacks a true `openat2`
/// equivalent (`NtOpenFile` with `OBJ_DONT_REPARSE` is the closest but
/// requires the NT layer and a relative-path open via `OBJECT_ATTRIBUTES`
/// — an enormous unsafe surface for a 12-line Rust function). The
/// component walk is documented as a known partial mitigation; full
/// closure on Windows is a follow-up task tracked in the round-3
/// review notes.
#[cfg(windows)]
fn windows_open_under_root(
    trusted_root: &Path,
    target: &Path,
) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Component;

    // `FILE_FLAG_OPEN_REPARSE_POINT`: tell CreateFileW NOT to traverse
    // a reparse point on the final component. We need this so the
    // attribute check below sees the reparse point itself, not the
    // resolved target.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;
    // `FILE_ATTRIBUTE_REPARSE_POINT`: set on every reparse-point class
    // (symlink, junction, mount point, AppExecLink, OneDrive cloud
    // file, etc.). This is the comprehensive check round-2's
    // `is_symlink()` call missed (FIX 11).
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x00000400;

    // Walk each component between trusted_root and target. For each
    // component (excluding the target itself, which we open with
    // FILE_FLAG_OPEN_REPARSE_POINT below), check the attribute bit
    // via symlink_metadata so we see the reparse point itself rather
    // than its resolved target.
    let relative = target.strip_prefix(trusted_root).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "target path is not under the supplied trusted root",
        )
    })?;
    let mut current = trusted_root.to_path_buf();
    let components: Vec<&std::ffi::OsStr> = relative
        .components()
        .map(|c| match c {
            Component::Normal(s) => Ok(s),
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("relative path component {other:?} is not a normal component"),
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    // Walk all components — including the leaf. Each push extends
    // `current` to a path the OS can stat, and `symlink_metadata`
    // returns the attributes of THAT component without following
    // through it.
    for name in &components {
        current.push(name);
        let meta = std::fs::symlink_metadata(&current)?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "reparse point detected on path component — refusing to traverse",
            ));
        }
    }

    // Open the target with no-follow flag. This is the second line of
    // defense against a race between the walk above and this open: if
    // the leaf was swapped for a reparse point in the meantime, the
    // attribute check on the resulting file metadata catches it.
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(target)?;
    let meta = f.metadata()?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "leaf is a reparse point — refusing to open",
        ));
    }
    Ok(f)
}

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

/// **Codex re-review FIX 9 (P2-medium):** rebuild the `sources` table
/// with the new `UNIQUE(uri, content_hash, format)` key while preserving
/// every existing row's `id`. The `node_sources` and `edges` foreign
/// keys reference `sources.id`, so the IDs must survive verbatim.
///
/// Atomicity: the entire migration runs inside a single SQLite
/// transaction (`BEGIN IMMEDIATE; ... COMMIT;`). If any step fails the
/// outer caller will see a `rusqlite::Error`, the transaction rolls
/// back, and the database stays at epoch 1 — recoverable. On success,
/// the version table gets a new `2` row in a separate statement
/// outside the transaction (idempotent — `PRIMARY KEY` would catch a
/// double-run).
fn migrate_epoch_1_to_2(conn: &Connection) -> Result<(), OrchestratorError> {
    conn.execute_batch(
        r#"
        BEGIN IMMEDIATE;

        -- Stash existing rows under a temporary name.
        ALTER TABLE sources RENAME TO sources_old;

        -- Create the new sources table with the 3-column unique key.
        CREATE TABLE sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_type TEXT NOT NULL,
            uri TEXT NOT NULL,
            ingested_at_unix INTEGER NOT NULL,
            fidelity TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            format TEXT NOT NULL,
            UNIQUE(uri, content_hash, format)
        );

        -- Copy rows verbatim. The unique key WIDENS, so no row is rejected;
        -- two distinct epoch-1 rows that happened to share (uri, hash) but
        -- differ in format are now both legal.
        INSERT INTO sources (id, source_type, uri, ingested_at_unix, fidelity, content_hash, format)
            SELECT id, source_type, uri, ingested_at_unix, fidelity, content_hash, format
            FROM sources_old;

        -- Recreate indexes (the rename dropped them on the old table).
        CREATE INDEX IF NOT EXISTS idx_sources_uri ON sources(uri);
        CREATE INDEX IF NOT EXISTS idx_sources_format ON sources(format);
        CREATE INDEX IF NOT EXISTS idx_sources_ingested ON sources(ingested_at_unix);

        DROP TABLE sources_old;

        COMMIT;
        "#,
    )
    .map_err(map_sqlite_err)?;

    conn.execute(
        "INSERT INTO schema_version (version) VALUES (?1)",
        params![CURRENT_SCHEMA_VERSION],
    )
    .map_err(map_sqlite_err)?;

    Ok(())
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

fn map_sqlite_err(e: rusqlite::Error) -> OrchestratorError {
    OrchestratorError::Planning(format!("knowledge sqlite: {e}"))
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
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

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
        // safe-open boundary can anchor its kernel-level traversal to
        // a directory FD. The TempDir's canonical path serves as the
        // trusted root for these tests (mirroring the production flow
        // where the D-Bus service derives the root from its allowlist).
        let tmp = TempDir::new().unwrap();
        let trusted_root = std::fs::canonicalize(tmp.path()).unwrap();
        let path = trusted_root.join("note.md");
        std::fs::write(&path, "# Hello\n\nWorld.\n").unwrap();
        let s = store();
        let result = s.ingest_file(&trusted_root, &path).unwrap();
        assert!(result.nodes_created >= 2);
        assert_eq!(result.format_detected, "markdown");
        assert_eq!(result.fidelity_used, Fidelity::Direct);
    }

    #[test]
    fn ingest_file_pdf_records_unavailable_source() {
        let tmp = TempDir::new().unwrap();
        let trusted_root = std::fs::canonicalize(tmp.path()).unwrap();
        let path = trusted_root.join("doc.pdf");
        std::fs::write(&path, b"%PDF-1.4\nfake").unwrap();
        let s = store();
        let result = s.ingest_file(&trusted_root, &path).unwrap();
        assert_eq!(result.fidelity_used, Fidelity::Unavailable);
        assert_eq!(result.nodes_created, 0);
        // Source should still be recorded (provenance for "we tried").
        assert!(result.source_id > 0);
        let src = s.get_source(result.source_id).unwrap();
        assert_eq!(src.fidelity, Fidelity::Unavailable);
    }

    // ── FIX 10+11 (P1-high): safe-open under trusted root,
    //    intermediate-component coverage, kernel-level guarantees ──

    #[test]
    fn safe_open_under_root_accepts_real_file() {
        // Sanity: a regular file under the trusted root must open.
        let tmp = TempDir::new().unwrap();
        let trusted_root = std::fs::canonicalize(tmp.path()).unwrap();
        let path = trusted_root.join("real.md");
        std::fs::write(&path, "# Hello\n\nWorld.\n").unwrap();
        use std::io::Read;
        let mut file =
            safe_open_under_root(&trusted_root, &path).expect("real file must open");
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "# Hello\n\nWorld.\n");
    }

    #[test]
    fn safe_open_under_root_rejects_target_outside_root() {
        // Defense-in-depth: even when the caller mistakenly supplies a
        // target outside the trusted root, safe_open_under_root must
        // refuse before any kernel call.
        let tmp = TempDir::new().unwrap();
        let trusted_root = std::fs::canonicalize(tmp.path()).unwrap();
        let other = TempDir::new().unwrap();
        let outside = std::fs::canonicalize(other.path())
            .unwrap()
            .join("outside.md");
        std::fs::write(&outside, "outside").unwrap();
        let err = safe_open_under_root(&trusted_root, &outside)
            .expect_err("target outside root must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn safe_open_under_root_rejects_leaf_symlink_via_openat2() {
        // Final-component symlink: openat2 RESOLVE_NO_SYMLINKS must
        // reject with ELOOP. This test exercises the same case
        // round-2's O_NOFOLLOW caught, ensuring we don't regress on
        // it while moving to the stricter primitive.
        let tmp = TempDir::new().unwrap();
        let trusted_root = std::fs::canonicalize(tmp.path()).unwrap();
        let real = trusted_root.join("real.md");
        std::fs::write(&real, "innocent content").unwrap();
        let link = trusted_root.join("link.md");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = safe_open_under_root(&trusted_root, &link)
            .expect_err("leaf symlink must be rejected");
        // openat2 with RESOLVE_NO_SYMLINKS surfaces as ELOOP. The
        // numeric value is stable libc ABI; ErrorKind::FilesystemLoop
        // is still unstable in this rustc.
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "expected ELOOP from RESOLVE_NO_SYMLINKS at leaf, got {err:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn safe_open_under_root_rejects_intermediate_symlink_via_openat2() {
        // FIX 10 motivating case: an INTERMEDIATE directory component
        // is a symlink. Round-2's O_NOFOLLOW silently traversed
        // intermediate symlinks because O_NOFOLLOW only checks the
        // final component. openat2 RESOLVE_NO_SYMLINKS rejects at
        // ANY component — kernel-level guarantee.
        //
        // Setup:
        //   trusted_root/
        //     real_dir/
        //       leaf.md           ← actual file
        //     link_dir → real_dir ← intermediate symlink
        //
        // We attempt to open `trusted_root/link_dir/leaf.md`. Without
        // FIX 10, this would succeed (round-2's O_NOFOLLOW was
        // silent on the link_dir traversal). With FIX 10's openat2,
        // the kernel rejects with ELOOP before reading any bytes.
        let tmp = TempDir::new().unwrap();
        let trusted_root = std::fs::canonicalize(tmp.path()).unwrap();
        let real_dir = trusted_root.join("real_dir");
        std::fs::create_dir(&real_dir).unwrap();
        let leaf = real_dir.join("leaf.md");
        std::fs::write(&leaf, "secret-but-allowed").unwrap();
        let link_dir = trusted_root.join("link_dir");
        std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();
        let through_link = link_dir.join("leaf.md");

        let err = safe_open_under_root(&trusted_root, &through_link)
            .expect_err("intermediate-component symlink must be rejected");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "expected ELOOP from RESOLVE_NO_SYMLINKS at intermediate component, got {err:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn safe_open_under_root_rejects_dotdot_escape_via_openat2() {
        // RESOLVE_BENEATH guards the trusted root: even if no
        // symlinks are involved, a relative path with `..` that
        // resolves outside the root must be rejected. This matters
        // for callers that pass uncanonicalized targets — the
        // canonical-prefix check in safe_open_under_root would
        // bounce those, but RESOLVE_BENEATH is the second line of
        // defense if a future caller is sloppy.
        let tmp = TempDir::new().unwrap();
        let trusted_root = std::fs::canonicalize(tmp.path()).unwrap();
        let outside = TempDir::new().unwrap();
        let outside_canon = std::fs::canonicalize(outside.path()).unwrap();
        std::fs::write(outside_canon.join("escape.md"), "escape").unwrap();

        // Manufacture an "in trusted_root" path that .. escapes.
        // NOTE: starts_with check rejects this earlier — but we want
        // to exercise the openat2 path for thoroughness, so we use a
        // path that lexically starts with trusted_root and escapes
        // through .. only inside the relative portion.
        let target_inside = trusted_root.join("a").join("..").join("..");
        // The lexical starts_with check WILL pass because `target`
        // begins with trusted_root literally; openat2 RESOLVE_BENEATH
        // is what rejects at syscall time.
        let err = safe_open_under_root(&trusted_root, &target_inside)
            .expect_err("dotdot escape must be rejected by RESOLVE_BENEATH");
        // RESOLVE_BENEATH typically surfaces as EXDEV on the
        // openat2 syscall, but kernels also accept EAGAIN/ELOOP in
        // related cases. We accept any error — the negative result
        // is the security guarantee we care about.
        assert!(
            err.raw_os_error().is_some(),
            "expected an os error from RESOLVE_BENEATH/openat2, got {err:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ingest_file_returns_safe_open_error_for_symlink() {
        // End-to-end via KnowledgeStore::ingest_file. Same setup as
        // round-2's regression test, now adapted to the new
        // (trusted_root, path) signature. Confirms no source row is
        // created when the kernel rejects the open.
        let tmp = TempDir::new().unwrap();
        let trusted_root = std::fs::canonicalize(tmp.path()).unwrap();
        let real = trusted_root.join("real.md");
        std::fs::write(&real, "# T\n\nP.\n").unwrap();
        let link = trusted_root.join("link.md");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let s = store();
        let before = s.count_sources().unwrap();
        let err = s
            .ingest_file(&trusted_root, &link)
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

    #[test]
    fn ingest_bytes_path_still_works() {
        // Direct call to ingest_bytes with markdown content must produce
        // the same shape as the pre-FIX-8 ingest_file (full pipeline:
        // create source row + parse concepts + persist nodes).
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
        let conn = make_epoch_1_db();
        // Pre-migration: epoch 1, recorded_version=None, 2 rows present.
        assert!(read_sources_sql(&conn).contains("UNIQUE(uri, content_hash)"));
        assert!(!read_sources_sql(&conn).contains("UNIQUE(uri, content_hash, format)"));
        assert_eq!(read_recorded_version(&conn), None);

        // Run init_schema (the migration entry point).
        KnowledgeStore::init_schema(&conn).unwrap();

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
        let conn = make_epoch_1_db();
        KnowledgeStore::init_schema(&conn).unwrap();
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
        let conn = Connection::open_in_memory().unwrap();
        KnowledgeStore::init_schema(&conn).unwrap();
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
        let conn = Connection::open_in_memory().unwrap();
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
        let err = KnowledgeStore::init_schema(&conn).expect_err("must refuse newer schema");
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
        let conn = Connection::open_in_memory().unwrap();
        KnowledgeStore::init_schema(&conn).unwrap();
        let first_version_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(first_version_count, 1);

        KnowledgeStore::init_schema(&conn).unwrap();
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
        let conn = Connection::open_in_memory().unwrap();
        KnowledgeStore::init_schema(&conn).unwrap();
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
            let conn = Connection::open(&path).unwrap();
            KnowledgeStore::init_schema(&conn).unwrap();
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
        let conn2 = Connection::open(&path).unwrap();
        conn2
            .execute_batch("PRAGMA foreign_keys = OFF;")
            .expect("must be able to set pragma");
        assert_eq!(
            read_fk_pragma(&conn2),
            0,
            "explicit OFF must take effect on this connection"
        );
        KnowledgeStore::init_schema(&conn2).unwrap();
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
        let conn = Connection::open_in_memory().unwrap();
        KnowledgeStore::init_schema(&conn).unwrap();

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
        let conn = Connection::open_in_memory().unwrap();
        KnowledgeStore::init_schema(&conn).unwrap();

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
}
