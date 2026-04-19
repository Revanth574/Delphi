// SPDX-License-Identifier: MIT

//! Persistent conversation memory with reference resolution and tiering.
//!
//! Conversations are stored as a chain of `(user_message, assistant_response,
//! timestamp, context_snapshot)` tuples in a local SQLite database with FTS5
//! full-text search. Memory is tiered:
//!
//! - **Last 24 hours:** full verbatim context available
//! - **Last 7 days:** summarized via `SummaryGenerator`
//! - **Older:** keyword-searchable only (FTS5)
//!
//! The `forget_today`, `forget_older_than`, and `forget_topic` operations
//! support the user sovereignty principle — conversations are the user's,
//! not Delphi's, and they can erase any slice of history at any time.
//!
//! # Privacy
//!
//! Per CLAUDE.md Section 4: conversation data **NEVER** leaves the device.
//! Cloud queries are stateless — each is independent, no conversation
//! history is sent to cloud.
//!
//! # Examples
//!
//! ```
//! use die_orchestrator::conversation::{ConversationStore, MessageRole};
//!
//! let store = ConversationStore::in_memory().unwrap();
//! let conv_id = store.start_conversation(Some("Design session")).unwrap();
//! store.add_message(&conv_id, MessageRole::User, "What's convergence?", None).unwrap();
//! store.add_message(&conv_id, MessageRole::Assistant, "In machine learning...", None).unwrap();
//!
//! let recent = store.recent_messages(&conv_id, 10).unwrap();
//! assert_eq!(recent.len(), 2);
//! ```

use std::path::{Path, PathBuf};
use std::str::FromStr;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::OrchestratorError;

/// Duration of the "verbatim tier" in seconds (24 hours).
const VERBATIM_WINDOW_SECS: i64 = 24 * 60 * 60;

/// Duration of the "summary tier" in seconds (7 days).
const SUMMARY_WINDOW_SECS: i64 = 7 * 24 * 60 * 60;

/// Role of a message author.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageRole {
    /// The human user.
    User,
    /// The Delphi assistant.
    Assistant,
    /// A system prompt or instruction.
    System,
}

impl MessageRole {
    /// Canonical string representation for storage.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::System => "system",
        }
    }
}

impl FromStr for MessageRole {
    type Err = OrchestratorError;

    /// Parse from storage representation.
    ///
    /// Accepts `"user"`, `"assistant"`, or `"system"`. Any other value is
    /// rejected with `OrchestratorError::Planning`.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::conversation::MessageRole;
    /// use std::str::FromStr;
    ///
    /// assert_eq!(MessageRole::from_str("user").unwrap(), MessageRole::User);
    /// assert!(MessageRole::from_str("alien").is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(Self::User),
            "assistant" => Ok(Self::Assistant),
            "system" => Ok(Self::System),
            other => Err(OrchestratorError::Planning(format!(
                "unknown message role: {other}"
            ))),
        }
    }
}

/// Snapshot of system state at the moment a message was sent.
///
/// Used for reference resolution — when the user says "that file from
/// yesterday," the stored `active_files` lets us resolve which file.
///
/// # Examples
///
/// ```
/// use die_orchestrator::conversation::ContextSnapshot;
///
/// let ctx = ContextSnapshot {
///     active_files: vec!["/home/user/report.pdf".into()],
///     running_apps: vec!["Firefox".into()],
///     current_project: Some("delphi".into()),
///     recent_actions: vec!["Opened report.pdf".into()],
/// };
/// let json = ctx.to_json().unwrap();
/// assert!(json.contains("report.pdf"));
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContextSnapshot {
    /// Files open in the shell at message time.
    pub active_files: Vec<String>,
    /// Running app names at message time.
    pub running_apps: Vec<String>,
    /// The active project, if any.
    pub current_project: Option<String>,
    /// The last few action timeline entries.
    pub recent_actions: Vec<String>,
}

impl ContextSnapshot {
    /// Serialize to JSON for storage in SQLite.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if serialization fails.
    pub fn to_json(&self) -> Result<String, OrchestratorError> {
        serde_json::to_string(self).map_err(|e| {
            OrchestratorError::Planning(format!("context snapshot serialization failed: {e}"))
        })
    }

    /// Deserialize from JSON.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if deserialization fails.
    pub fn from_json(s: &str) -> Result<Self, OrchestratorError> {
        serde_json::from_str(s).map_err(|e| {
            OrchestratorError::Planning(format!("context snapshot deserialization failed: {e}"))
        })
    }
}

/// A conversation is a sequence of messages bound to a timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversation {
    /// Unique conversation identifier.
    pub id: String,
    /// UTC epoch seconds when the conversation began.
    pub started_at: i64,
    /// Optional human-readable title.
    pub title: Option<String>,
    /// Optional rolled-up summary (populated by tiering).
    pub summary: Option<String>,
}

/// A single message within a conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Unique message identifier.
    pub id: String,
    /// Conversation this message belongs to.
    pub conversation_id: String,
    /// Who sent the message.
    pub role: MessageRole,
    /// Message body.
    pub content: String,
    /// Optional context snapshot at send time (JSON-encoded in storage).
    pub context: Option<ContextSnapshot>,
    /// UTC epoch seconds when the message was sent.
    pub timestamp: i64,
}

/// Generator of rolled-up summaries for the 7-day tier.
///
/// Implementations will typically wrap Tier 1 local inference. Tests can
/// inject a mock that returns a deterministic string.
pub trait SummaryGenerator {
    /// Produce a summary of the given messages.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if summary generation fails
    /// (e.g., inference model unavailable). The caller should degrade
    /// gracefully — a failed summary should not break context building.
    fn summarize(&self, messages: &[Message]) -> Result<String, OrchestratorError>;
}

/// SQLite-backed persistent conversation memory.
///
/// Uses WAL mode so the shell can read conversation history while the
/// orchestrator is writing new messages concurrently.
///
/// # Examples
///
/// ```
/// use die_orchestrator::conversation::{ConversationStore, MessageRole};
///
/// let store = ConversationStore::in_memory().unwrap();
/// let cid = store.start_conversation(Some("hello")).unwrap();
/// assert!(cid.starts_with("conv-"));
/// ```
pub struct ConversationStore {
    conn: Connection,
}

impl ConversationStore {
    /// Default on-disk location for the conversation database.
    ///
    /// Resolves to `{data_local_dir}/delphi/encrypted/conversations.db`.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if `dirs::data_local_dir()`
    /// returns `None` (platform without a standard data directory).
    pub fn default_path() -> Result<PathBuf, OrchestratorError> {
        let base = dirs::data_local_dir().ok_or_else(|| {
            OrchestratorError::Planning(
                "no data_local_dir available on this platform".to_string(),
            )
        })?;
        Ok(base.join("delphi").join("encrypted").join("conversations.db"))
    }

    /// Open or create a conversation store at the given path.
    ///
    /// Creates the parent directory if it does not exist. Initializes the
    /// schema and enables WAL mode.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if the directory cannot be
    /// created or the database cannot be opened.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use die_orchestrator::conversation::ConversationStore;
    /// use std::path::Path;
    ///
    /// let store = ConversationStore::open(Path::new("/tmp/conv.db")).unwrap();
    /// ```
    pub fn open(path: &Path) -> Result<Self, OrchestratorError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                OrchestratorError::Planning(format!(
                    "failed to create conversation dir {}: {e}",
                    parent.display()
                ))
            })?;
        }
        let conn = Connection::open(path).map_err(|e| {
            OrchestratorError::Planning(format!("failed to open conversation db: {e}"))
        })?;
        let store = Self { conn };
        store.configure_pragmas()?;
        store.init_schema()?;
        info!("conversation store opened at {}", path.display());
        Ok(store)
    }

    /// Create an in-memory conversation store (for testing).
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if SQLite init fails.
    pub fn in_memory() -> Result<Self, OrchestratorError> {
        let conn = Connection::open_in_memory().map_err(|e| {
            OrchestratorError::Planning(format!("failed to create in-memory db: {e}"))
        })?;
        let store = Self { conn };
        // WAL mode cannot be enabled on in-memory databases; skip pragmas.
        store.init_schema()?;
        Ok(store)
    }

    /// Begin a new conversation.
    ///
    /// Returns the new conversation's ID.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` on database failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::conversation::ConversationStore;
    ///
    /// let store = ConversationStore::in_memory().unwrap();
    /// let id = store.start_conversation(Some("About convergence")).unwrap();
    /// assert!(id.starts_with("conv-"));
    /// ```
    pub fn start_conversation(
        &self,
        title: Option<&str>,
    ) -> Result<String, OrchestratorError> {
        let now = current_timestamp();
        let conv_id = format!("conv-{now}-{}", rand_suffix());

        self.conn
            .execute(
                "INSERT INTO conversations (id, started_at, title, summary) VALUES (?1, ?2, ?3, NULL)",
                params![conv_id, now, title],
            )
            .map_err(|e| {
                OrchestratorError::Planning(format!("failed to create conversation: {e}"))
            })?;

        debug!(conversation_id = %conv_id, title, "conversation started");
        Ok(conv_id)
    }

    /// Append a message to an existing conversation.
    ///
    /// Returns the new message's ID.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if the conversation does not
    /// exist or the write fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::conversation::{ConversationStore, MessageRole};
    ///
    /// let store = ConversationStore::in_memory().unwrap();
    /// let cid = store.start_conversation(None).unwrap();
    /// let mid = store.add_message(&cid, MessageRole::User, "hi", None).unwrap();
    /// assert!(mid.starts_with("msg-"));
    /// ```
    pub fn add_message(
        &self,
        conversation_id: &str,
        role: MessageRole,
        content: &str,
        context: Option<&ContextSnapshot>,
    ) -> Result<String, OrchestratorError> {
        self.ensure_conversation_exists(conversation_id)?;

        let now = current_timestamp();
        let msg_id = format!("msg-{now}-{}", rand_suffix());
        let ctx_json = match context {
            Some(c) => Some(c.to_json()?),
            None => None,
        };

        self.conn
            .execute(
                "INSERT INTO messages (id, conversation_id, role, content, context_json, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![msg_id, conversation_id, role.as_str(), content, ctx_json, now],
            )
            .map_err(|e| OrchestratorError::Planning(format!("failed to insert message: {e}")))?;

        self.conn
            .execute(
                "INSERT INTO messages_fts (rowid, content) VALUES ((SELECT last_insert_rowid()), ?1)",
                params![content],
            )
            .map_err(|e| OrchestratorError::Planning(format!("fts insert failed: {e}")))?;

        debug!(message_id = %msg_id, conversation_id, role = role.as_str(), "message added");
        Ok(msg_id)
    }

    /// Fetch a conversation record by ID.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if the conversation is not
    /// found.
    pub fn get_conversation(&self, id: &str) -> Result<Conversation, OrchestratorError> {
        self.conn
            .query_row(
                "SELECT id, started_at, title, summary FROM conversations WHERE id = ?1",
                params![id],
                |row| {
                    Ok(Conversation {
                        id: row.get(0)?,
                        started_at: row.get(1)?,
                        title: row.get(2)?,
                        summary: row.get(3)?,
                    })
                },
            )
            .map_err(|_| OrchestratorError::Planning(format!("conversation not found: {id}")))
    }

    /// Fetch the most recent messages from a conversation (newest first).
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` on database failure.
    pub fn recent_messages(
        &self,
        conversation_id: &str,
        limit: u32,
    ) -> Result<Vec<Message>, OrchestratorError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, conversation_id, role, content, context_json, timestamp \
                 FROM messages WHERE conversation_id = ?1 ORDER BY timestamp DESC, rowid DESC LIMIT ?2",
            )
            .map_err(|e| OrchestratorError::Planning(format!("query prepare failed: {e}")))?;

        let rows = stmt
            .query_map(params![conversation_id, limit], row_to_message)
            .map_err(|e| OrchestratorError::Planning(format!("query failed: {e}")))?;

        collect_messages(rows)
    }

    /// Full-text search across all stored messages.
    ///
    /// Uses FTS5 MATCH syntax. Special characters in `query` should be
    /// escaped by the caller if the query is derived from untrusted input.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if the FTS query is malformed
    /// or the database read fails.
    pub fn search(&self, query: &str, limit: u32) -> Result<Vec<Message>, OrchestratorError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT m.id, m.conversation_id, m.role, m.content, m.context_json, m.timestamp \
                 FROM messages m \
                 JOIN messages_fts f ON f.rowid = m.rowid \
                 WHERE messages_fts MATCH ?1 \
                 ORDER BY m.timestamp DESC LIMIT ?2",
            )
            .map_err(|e| OrchestratorError::Planning(format!("search prepare failed: {e}")))?;

        let rows = stmt
            .query_map(params![query, limit], row_to_message)
            .map_err(|e| OrchestratorError::Planning(format!("search failed: {e}")))?;

        collect_messages(rows)
    }

    /// List conversations in reverse chronological order.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` on database failure.
    pub fn list_conversations(
        &self,
        limit: u32,
    ) -> Result<Vec<Conversation>, OrchestratorError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, started_at, title, summary FROM conversations \
                 ORDER BY started_at DESC, rowid DESC LIMIT ?1",
            )
            .map_err(|e| OrchestratorError::Planning(format!("list prepare failed: {e}")))?;

        let rows = stmt
            .query_map(params![limit], |row| {
                Ok(Conversation {
                    id: row.get(0)?,
                    started_at: row.get(1)?,
                    title: row.get(2)?,
                    summary: row.get(3)?,
                })
            })
            .map_err(|e| OrchestratorError::Planning(format!("list failed: {e}")))?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| {
                OrchestratorError::Planning(format!("conversation row read failed: {e}"))
            })?);
        }
        Ok(out)
    }

    /// Delete all messages sent since UTC midnight today.
    ///
    /// Also deletes conversations that have no remaining messages.
    /// Returns the number of messages deleted.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` on database failure.
    pub fn forget_today(&self) -> Result<usize, OrchestratorError> {
        let now = current_timestamp();
        let today_start = utc_midnight(now);
        self.forget_since(today_start)
    }

    /// Delete all messages older than `days` days.
    ///
    /// Returns the number of messages deleted.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` on database failure.
    pub fn forget_older_than(&self, days: u32) -> Result<usize, OrchestratorError> {
        let cutoff = current_timestamp() - (days as i64 * 24 * 60 * 60);
        let deleted = self
            .conn
            .execute(
                "DELETE FROM messages WHERE timestamp < ?1",
                params![cutoff],
            )
            .map_err(|e| OrchestratorError::Planning(format!("forget_older_than failed: {e}")))?;
        self.rebuild_fts()?;
        self.gc_empty_conversations()?;
        info!(days, deleted, "forget_older_than executed");
        Ok(deleted)
    }

    /// Delete all messages matching a topic keyword via FTS5.
    ///
    /// Returns the number of messages deleted.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if the FTS query fails or the
    /// deletion fails.
    pub fn forget_topic(&self, topic: &str) -> Result<usize, OrchestratorError> {
        let deleted = self
            .conn
            .execute(
                "DELETE FROM messages WHERE rowid IN \
                 (SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?1)",
                params![topic],
            )
            .map_err(|e| OrchestratorError::Planning(format!("forget_topic failed: {e}")))?;
        self.rebuild_fts()?;
        self.gc_empty_conversations()?;
        info!(topic, deleted, "forget_topic executed");
        Ok(deleted)
    }

    /// Build a context prompt applying the three-tier memory model.
    ///
    /// - Last 24 hours: verbatim messages
    /// - Last 7 days: summarized via `generator`
    /// - Older: replaced by a search-hint header
    ///
    /// The prompt is newline-separated plain text, suitable for prepending
    /// to a user query before Tier 1/2 inference.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` on database failure. Summary
    /// generation errors propagate from `generator`.
    pub fn build_context_prompt(
        &self,
        conversation_id: &str,
        generator: &dyn SummaryGenerator,
    ) -> Result<String, OrchestratorError> {
        let now = current_timestamp();
        let verbatim_cutoff = now - VERBATIM_WINDOW_SECS;
        let summary_cutoff = now - SUMMARY_WINDOW_SECS;

        let verbatim = self.messages_since(conversation_id, verbatim_cutoff)?;
        let summarizable =
            self.messages_between(conversation_id, summary_cutoff, verbatim_cutoff)?;
        let older = self.count_messages_before(conversation_id, summary_cutoff)?;

        let mut parts: Vec<String> = Vec::new();
        if older > 0 {
            parts.push(format!(
                "[{older} older messages available via search]"
            ));
        }
        if !summarizable.is_empty() {
            let summary = generator.summarize(&summarizable)?;
            parts.push(format!("[summary of last 7 days]\n{summary}"));
        }
        for msg in verbatim.iter().rev() {
            parts.push(format!("{}: {}", msg.role.as_str(), msg.content));
        }
        Ok(parts.join("\n"))
    }

    /// Total number of messages across all conversations.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` on database failure.
    pub fn count(&self) -> Result<usize, OrchestratorError> {
        let c: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
            .map_err(|e| OrchestratorError::Planning(format!("count failed: {e}")))?;
        Ok(c as usize)
    }

    /// Total number of conversations.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` on database failure.
    pub fn conversation_count(&self) -> Result<usize, OrchestratorError> {
        let c: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM conversations", [], |r| r.get(0))
            .map_err(|e| OrchestratorError::Planning(format!("conv count failed: {e}")))?;
        Ok(c as usize)
    }

    // ---- internal helpers ----

    fn configure_pragmas(&self) -> Result<(), OrchestratorError> {
        // WAL enables concurrent readers while one writer is active.
        let _: String = self
            .conn
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .map_err(|e| OrchestratorError::Planning(format!("WAL enable failed: {e}")))?;
        self.conn
            .execute_batch("PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;")
            .map_err(|e| OrchestratorError::Planning(format!("pragma set failed: {e}")))?;
        Ok(())
    }

    fn init_schema(&self) -> Result<(), OrchestratorError> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS conversations (
                    id TEXT PRIMARY KEY,
                    started_at INTEGER NOT NULL,
                    title TEXT,
                    summary TEXT
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    context_json TEXT,
                    timestamp INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conversation_id);
                CREATE INDEX IF NOT EXISTS idx_messages_time ON messages(timestamp);
                CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(content);",
            )
            .map_err(|e| OrchestratorError::Planning(format!("schema init failed: {e}")))?;
        Ok(())
    }

    fn ensure_conversation_exists(&self, id: &str) -> Result<(), OrchestratorError> {
        let n: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM conversations WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .map_err(|e| OrchestratorError::Planning(format!("existence check failed: {e}")))?;
        if n == 0 {
            return Err(OrchestratorError::Planning(format!(
                "conversation not found: {id}"
            )));
        }
        Ok(())
    }

    fn forget_since(&self, since: i64) -> Result<usize, OrchestratorError> {
        let deleted = self
            .conn
            .execute(
                "DELETE FROM messages WHERE timestamp >= ?1",
                params![since],
            )
            .map_err(|e| OrchestratorError::Planning(format!("forget_since failed: {e}")))?;
        self.rebuild_fts()?;
        self.gc_empty_conversations()?;
        info!(since, deleted, "forget_since executed");
        Ok(deleted)
    }

    fn rebuild_fts(&self) -> Result<(), OrchestratorError> {
        // Standalone FTS5 table needs manual resync after DELETEs on the
        // source table. For correctness after forget operations we drop
        // and repopulate; volume is low (<100k messages typical).
        self.conn
            .execute_batch(
                "DELETE FROM messages_fts; \
                 INSERT INTO messages_fts (rowid, content) \
                 SELECT rowid, content FROM messages;",
            )
            .map_err(|e| OrchestratorError::Planning(format!("fts rebuild failed: {e}")))?;
        Ok(())
    }

    fn gc_empty_conversations(&self) -> Result<(), OrchestratorError> {
        self.conn
            .execute(
                "DELETE FROM conversations WHERE id NOT IN \
                 (SELECT DISTINCT conversation_id FROM messages)",
                [],
            )
            .map_err(|e| OrchestratorError::Planning(format!("gc failed: {e}")))?;
        Ok(())
    }

    fn messages_since(
        &self,
        conversation_id: &str,
        since: i64,
    ) -> Result<Vec<Message>, OrchestratorError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, conversation_id, role, content, context_json, timestamp \
                 FROM messages WHERE conversation_id = ?1 AND timestamp >= ?2 \
                 ORDER BY timestamp DESC, rowid DESC",
            )
            .map_err(|e| OrchestratorError::Planning(format!("msgs_since prepare: {e}")))?;
        let rows = stmt
            .query_map(params![conversation_id, since], row_to_message)
            .map_err(|e| OrchestratorError::Planning(format!("msgs_since query: {e}")))?;
        collect_messages(rows)
    }

    fn messages_between(
        &self,
        conversation_id: &str,
        start: i64,
        end: i64,
    ) -> Result<Vec<Message>, OrchestratorError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, conversation_id, role, content, context_json, timestamp \
                 FROM messages WHERE conversation_id = ?1 AND timestamp >= ?2 AND timestamp < ?3 \
                 ORDER BY timestamp ASC",
            )
            .map_err(|e| OrchestratorError::Planning(format!("msgs_between prepare: {e}")))?;
        let rows = stmt
            .query_map(params![conversation_id, start, end], row_to_message)
            .map_err(|e| OrchestratorError::Planning(format!("msgs_between query: {e}")))?;
        collect_messages(rows)
    }

    fn count_messages_before(
        &self,
        conversation_id: &str,
        before: i64,
    ) -> Result<usize, OrchestratorError> {
        let c: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE conversation_id = ?1 AND timestamp < ?2",
                params![conversation_id, before],
                |row| row.get(0),
            )
            .map_err(|e| OrchestratorError::Planning(format!("count_before failed: {e}")))?;
        Ok(c as usize)
    }
}

// ---- row helpers ----

fn row_to_message(row: &rusqlite::Row) -> rusqlite::Result<Message> {
    let role_str: String = row.get(2)?;
    let role = MessageRole::from_str(&role_str).unwrap_or(MessageRole::System);
    let ctx_json: Option<String> = row.get(4)?;
    let context = ctx_json
        .as_deref()
        .and_then(|s| ContextSnapshot::from_json(s).ok());
    Ok(Message {
        id: row.get(0)?,
        conversation_id: row.get(1)?,
        role,
        content: row.get(3)?,
        context,
        timestamp: row.get(5)?,
    })
}

fn collect_messages<F>(
    rows: rusqlite::MappedRows<'_, F>,
) -> Result<Vec<Message>, OrchestratorError>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<Message>,
{
    let mut out = Vec::new();
    for row in rows {
        out.push(
            row.map_err(|e| OrchestratorError::Planning(format!("message row read failed: {e}")))?,
        );
    }
    Ok(out)
}

/// Current UTC timestamp in epoch seconds.
fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Given a UTC epoch-seconds value, return the start of that UTC day.
fn utc_midnight(ts: i64) -> i64 {
    ts - (ts.rem_euclid(86_400))
}

/// Random-ish suffix for generated IDs.
fn rand_suffix() -> u32 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let s = RandomState::new();
    let mut h = s.build_hasher();
    h.write_u64(current_timestamp() as u64);
    h.write_u64(std::process::id() as u64);
    (h.finish() % 1_000_000) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Mock summarizer for testing tier 2 prompt building.
    struct MockSummary;
    impl SummaryGenerator for MockSummary {
        fn summarize(&self, messages: &[Message]) -> Result<String, OrchestratorError> {
            Ok(format!("mock-summary-of-{}-messages", messages.len()))
        }
    }

    // ---- Tier 1: schema and basic CRUD ----

    #[test]
    fn create_in_memory_store() {
        let store = ConversationStore::in_memory().unwrap();
        assert_eq!(store.count().unwrap(), 0);
        assert_eq!(store.conversation_count().unwrap(), 0);
    }

    #[test]
    fn start_conversation_creates_row() {
        let store = ConversationStore::in_memory().unwrap();
        let id = store.start_conversation(Some("test session")).unwrap();
        assert!(id.starts_with("conv-"));
        let conv = store.get_conversation(&id).unwrap();
        assert_eq!(conv.title.as_deref(), Some("test session"));
        assert_eq!(store.conversation_count().unwrap(), 1);
    }

    #[test]
    fn add_message_crud_round_trip() {
        let store = ConversationStore::in_memory().unwrap();
        let cid = store.start_conversation(None).unwrap();
        store
            .add_message(&cid, MessageRole::User, "hello", None)
            .unwrap();
        store
            .add_message(&cid, MessageRole::Assistant, "hi there", None)
            .unwrap();
        let recent = store.recent_messages(&cid, 10).unwrap();
        assert_eq!(recent.len(), 2);
        // Newest first ordering:
        assert_eq!(recent[0].content, "hi there");
        assert_eq!(recent[0].role, MessageRole::Assistant);
        assert_eq!(recent[1].content, "hello");
    }

    #[test]
    fn add_message_to_missing_conversation_fails() {
        let store = ConversationStore::in_memory().unwrap();
        let err = store
            .add_message("conv-nope", MessageRole::User, "x", None)
            .unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn get_conversation_not_found() {
        let store = ConversationStore::in_memory().unwrap();
        assert!(store.get_conversation("conv-missing").is_err());
    }

    // ---- Tier 2: FTS search ----

    #[test]
    fn fts_search_finds_exact_keyword() {
        let store = ConversationStore::in_memory().unwrap();
        let cid = store.start_conversation(None).unwrap();
        store
            .add_message(&cid, MessageRole::User, "I love convergence theory", None)
            .unwrap();
        store
            .add_message(&cid, MessageRole::Assistant, "Me too!", None)
            .unwrap();
        let hits = store.search("convergence", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].content.contains("convergence"));
    }

    #[test]
    fn fts_search_returns_empty_when_no_match() {
        let store = ConversationStore::in_memory().unwrap();
        let cid = store.start_conversation(None).unwrap();
        store
            .add_message(&cid, MessageRole::User, "hello", None)
            .unwrap();
        let hits = store.search("quantum", 10).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn fts_search_respects_limit() {
        let store = ConversationStore::in_memory().unwrap();
        let cid = store.start_conversation(None).unwrap();
        for i in 0..5 {
            store
                .add_message(
                    &cid,
                    MessageRole::User,
                    &format!("convergence point {i}"),
                    None,
                )
                .unwrap();
        }
        let hits = store.search("convergence", 3).unwrap();
        assert_eq!(hits.len(), 3);
    }

    // ---- Tier 3: context snapshot round-trip ----

    #[test]
    fn context_snapshot_json_round_trip() {
        let ctx = ContextSnapshot {
            active_files: vec!["/a.txt".into(), "/b.txt".into()],
            running_apps: vec!["firefox".into()],
            current_project: Some("delphi".into()),
            recent_actions: vec!["opened file".into()],
        };
        let json = ctx.to_json().unwrap();
        let parsed = ContextSnapshot::from_json(&json).unwrap();
        assert_eq!(parsed, ctx);
    }

    #[test]
    fn context_snapshot_persists_through_message() {
        let store = ConversationStore::in_memory().unwrap();
        let cid = store.start_conversation(None).unwrap();
        let ctx = ContextSnapshot {
            active_files: vec!["/report.pdf".into()],
            running_apps: vec!["reader".into()],
            current_project: None,
            recent_actions: vec![],
        };
        store
            .add_message(&cid, MessageRole::User, "summarize", Some(&ctx))
            .unwrap();
        let msgs = store.recent_messages(&cid, 1).unwrap();
        assert_eq!(msgs[0].context, Some(ctx));
    }

    // ---- Tier 4: list and count ----

    #[test]
    fn list_conversations_reverse_chronological() {
        let store = ConversationStore::in_memory().unwrap();
        let a = store.start_conversation(Some("first")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let b = store.start_conversation(Some("second")).unwrap();
        let list = store.list_conversations(10).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, b);
        assert_eq!(list[1].id, a);
    }

    #[test]
    fn list_conversations_empty_returns_empty() {
        let store = ConversationStore::in_memory().unwrap();
        assert!(store.list_conversations(10).unwrap().is_empty());
    }

    // ---- Tier 5: forget operations ----

    #[test]
    fn forget_topic_removes_matching_messages() {
        let store = ConversationStore::in_memory().unwrap();
        let cid = store.start_conversation(None).unwrap();
        store
            .add_message(&cid, MessageRole::User, "quantum mechanics", None)
            .unwrap();
        store
            .add_message(&cid, MessageRole::User, "classical physics", None)
            .unwrap();
        let deleted = store.forget_topic("quantum").unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(store.count().unwrap(), 1);
        let remaining = store.recent_messages(&cid, 10).unwrap();
        assert!(remaining[0].content.contains("classical"));
    }

    #[test]
    fn forget_older_than_deletes_by_age() {
        let store = ConversationStore::in_memory().unwrap();
        let cid = store.start_conversation(None).unwrap();
        store
            .add_message(&cid, MessageRole::User, "fresh", None)
            .unwrap();
        // Backdate one message by directly manipulating the timestamp.
        let ancient = current_timestamp() - (10 * 24 * 60 * 60);
        store
            .conn
            .execute(
                "INSERT INTO messages (id, conversation_id, role, content, context_json, timestamp) \
                 VALUES ('msg-ancient', ?1, 'user', 'old content', NULL, ?2)",
                params![cid, ancient],
            )
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO messages_fts (rowid, content) VALUES ((SELECT rowid FROM messages WHERE id='msg-ancient'), 'old content')",
                [],
            )
            .unwrap();
        let deleted = store.forget_older_than(7).unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn forget_today_removes_messages_since_midnight() {
        let store = ConversationStore::in_memory().unwrap();
        let cid = store.start_conversation(None).unwrap();
        store
            .add_message(&cid, MessageRole::User, "today's message", None)
            .unwrap();
        // Insert a message backdated to yesterday.
        let yesterday = current_timestamp() - (48 * 60 * 60);
        store
            .conn
            .execute(
                "INSERT INTO messages (id, conversation_id, role, content, context_json, timestamp) \
                 VALUES ('msg-yday', ?1, 'user', 'yesterday', NULL, ?2)",
                params![cid, yesterday],
            )
            .unwrap();
        let deleted = store.forget_today().unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(store.count().unwrap(), 1);
        let remaining = store.recent_messages(&cid, 10).unwrap();
        assert_eq!(remaining[0].content, "yesterday");
    }

    #[test]
    fn forget_operations_gc_empty_conversations() {
        let store = ConversationStore::in_memory().unwrap();
        let cid = store.start_conversation(Some("disposable")).unwrap();
        store
            .add_message(&cid, MessageRole::User, "something", None)
            .unwrap();
        let _ = store.forget_topic("something").unwrap();
        assert_eq!(store.conversation_count().unwrap(), 0);
    }

    // ---- Tier 6: context prompt and tiering ----

    #[test]
    fn context_prompt_uses_verbatim_for_recent() {
        let store = ConversationStore::in_memory().unwrap();
        let cid = store.start_conversation(None).unwrap();
        store
            .add_message(&cid, MessageRole::User, "hello", None)
            .unwrap();
        store
            .add_message(&cid, MessageRole::Assistant, "hi", None)
            .unwrap();
        let prompt = store.build_context_prompt(&cid, &MockSummary).unwrap();
        assert!(prompt.contains("user: hello"));
        assert!(prompt.contains("assistant: hi"));
        assert!(!prompt.contains("[summary"));
        assert!(!prompt.contains("older"));
    }

    #[test]
    fn context_prompt_summarizes_middle_tier() {
        let store = ConversationStore::in_memory().unwrap();
        let cid = store.start_conversation(None).unwrap();
        // Backdate a message to 3 days ago (in the 7-day summary window).
        let three_days = current_timestamp() - (3 * 24 * 60 * 60);
        store
            .conn
            .execute(
                "INSERT INTO messages (id, conversation_id, role, content, context_json, timestamp) \
                 VALUES ('msg-t2', ?1, 'user', 'three days ago text', NULL, ?2)",
                params![cid, three_days],
            )
            .unwrap();
        store
            .add_message(&cid, MessageRole::User, "fresh", None)
            .unwrap();
        let prompt = store.build_context_prompt(&cid, &MockSummary).unwrap();
        assert!(prompt.contains("mock-summary-of-1-messages"));
        assert!(prompt.contains("fresh"));
    }

    #[test]
    fn context_prompt_shows_search_hint_for_old() {
        let store = ConversationStore::in_memory().unwrap();
        let cid = store.start_conversation(None).unwrap();
        let ten_days = current_timestamp() - (10 * 24 * 60 * 60);
        store
            .conn
            .execute(
                "INSERT INTO messages (id, conversation_id, role, content, context_json, timestamp) \
                 VALUES ('msg-old', ?1, 'user', 'ancient history', NULL, ?2)",
                params![cid, ten_days],
            )
            .unwrap();
        let prompt = store.build_context_prompt(&cid, &MockSummary).unwrap();
        assert!(prompt.contains("[1 older messages available via search]"));
        assert!(!prompt.contains("ancient history"));
    }

    // ---- Tier 7: persistence, paths, and pragmas ----

    #[test]
    fn default_path_points_to_encrypted_dir() {
        let path = ConversationStore::default_path().unwrap();
        let s = path.to_string_lossy();
        assert!(s.contains("delphi"));
        assert!(s.contains("encrypted"));
        assert!(s.ends_with("conversations.db"));
    }

    #[test]
    fn file_based_store_persists_across_reopen() {
        let dir = std::env::temp_dir()
            .join(format!("delphi-conv-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = dir.join("c.db");
        {
            let store = ConversationStore::open(&db).unwrap();
            let cid = store.start_conversation(Some("persisted")).unwrap();
            store
                .add_message(&cid, MessageRole::User, "hello", None)
                .unwrap();
        }
        {
            let store = ConversationStore::open(&db).unwrap();
            assert_eq!(store.count().unwrap(), 1);
            assert_eq!(store.conversation_count().unwrap(), 1);
        }
    }

    #[test]
    fn wal_mode_enabled_on_disk_store() {
        let dir = std::env::temp_dir()
            .join(format!("delphi-wal-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = dir.join("w.db");
        let store = ConversationStore::open(&db).unwrap();
        let mode: String = store
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
    }

    #[test]
    fn role_parse_round_trip() {
        for r in [MessageRole::User, MessageRole::Assistant, MessageRole::System] {
            let parsed = MessageRole::from_str(r.as_str()).unwrap();
            assert_eq!(parsed, r);
        }
        assert!(MessageRole::from_str("alien").is_err());
    }

    #[test]
    fn utc_midnight_is_floor() {
        let t = 1_700_000_000_i64; // arbitrary
        let m = utc_midnight(t);
        assert!(m <= t);
        assert_eq!(m % 86_400, 0);
    }
}
