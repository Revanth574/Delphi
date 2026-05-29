// SPDX-License-Identifier: MIT

//! D-Bus Conversation interface.
//!
//! Exposes the persistent conversation memory over D-Bus. The shell uses
//! this to append messages, search across history, and honor user
//! "forget" commands.
//!
//! Interface: `org.delphi.Conversation`
//!
//! Uses `std::sync::Mutex` (not `tokio::sync`) because `rusqlite::Connection`
//! is `!Send` across await points — see CLAUDE.md Section 3 "D-Bus Service
//! Pattern" rule 6.

use std::str::FromStr;
use std::sync::{Arc, Mutex};

use tracing::info;

use die_orchestrator::conversation::{ConversationStore, MessageRole};

/// D-Bus object path for the Conversation interface.
pub const PATH: &str = "/org/delphi/Conversation";

/// Conversation D-Bus service.
///
/// Wraps the orchestrator `ConversationStore` and exposes it over D-Bus.
///
/// # Examples
///
/// ```
/// use delphi_services::conversation::ConversationService;
/// use die_orchestrator::conversation::ConversationStore;
/// use std::sync::{Arc, Mutex};
///
/// let store = Arc::new(Mutex::new(ConversationStore::in_memory().unwrap()));
/// let svc = ConversationService::new(store);
/// ```
pub struct ConversationService {
    store: Arc<Mutex<ConversationStore>>,
}

impl ConversationService {
    /// Create a new conversation service.
    #[must_use]
    pub fn new(store: Arc<Mutex<ConversationStore>>) -> Self {
        Self { store }
    }
}

#[zbus::interface(name = "org.delphi.Conversation")]
impl ConversationService {
    /// Start a new conversation. Returns the new conversation ID.
    ///
    /// Pass an empty string for `title` to leave it untitled.
    async fn start_conversation(&self, title: String) -> zbus::fdo::Result<String> {
        // SVC-6-R2-3: cap BEFORE info!()/parse/store.
        crate::limits::ensure_within(&title, crate::limits::MAX_STRING_BYTES, "title")?;
        info!(title = %title, "D-Bus start_conversation");
        let store = self.store.lock().map_err(|e| {
            zbus::fdo::Error::Failed(format!("lock poisoned: {e}"))
        })?;
        let title_opt = if title.is_empty() { None } else { Some(title.as_str()) };
        store
            .start_conversation(title_opt)
            .map_err(|e| crate::error::opaque("conversation store operation failed", e))
    }

    /// Append a message to a conversation.
    ///
    /// `role` must be one of `"user"`, `"assistant"`, `"system"`.
    /// Returns the new message ID.
    async fn add_message(
        &self,
        conversation_id: String,
        role: String,
        content: String,
    ) -> zbus::fdo::Result<String> {
        // SVC-6-R2-3: cap every String param BEFORE any parse/store.
        crate::limits::ensure_within(
            &conversation_id,
            crate::limits::MAX_STRING_BYTES,
            "conversation_id",
        )?;
        crate::limits::ensure_within(&role, crate::limits::MAX_STRING_BYTES, "role")?;
        crate::limits::ensure_within(&content, crate::limits::MAX_STRING_BYTES, "content")?;
        let role = MessageRole::from_str(&role)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;
        let store = self.store.lock().map_err(|e| {
            zbus::fdo::Error::Failed(format!("lock poisoned: {e}"))
        })?;
        store
            .add_message(&conversation_id, role, &content, None)
            .map_err(|e| crate::error::opaque("conversation store operation failed", e))
    }

    /// Fetch the most recent messages from a conversation as JSON.
    async fn recent_messages(
        &self,
        conversation_id: String,
        limit: u32,
    ) -> zbus::fdo::Result<String> {
        crate::limits::ensure_within(
            &conversation_id,
            crate::limits::MAX_STRING_BYTES,
            "conversation_id",
        )?;
        let store = self.store.lock().map_err(|e| {
            zbus::fdo::Error::Failed(format!("lock poisoned: {e}"))
        })?;
        let msgs = store
            .recent_messages(&conversation_id, limit)
            .map_err(|e| crate::error::opaque("conversation store operation failed", e))?;
        let json: Vec<serde_json::Value> = msgs
            .iter()
            .map(|m| {
                serde_json::json!({
                    "id": m.id,
                    "conversation_id": m.conversation_id,
                    "role": m.role.as_str(),
                    "content": m.content,
                    "timestamp": m.timestamp,
                })
            })
            .collect();
        serde_json::to_string(&json)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
    }

    /// Full-text search across all stored messages.
    async fn search(&self, query: String, limit: u32) -> zbus::fdo::Result<String> {
        crate::limits::ensure_within(&query, crate::limits::MAX_STRING_BYTES, "query")?;
        info!(query = %query, "D-Bus conversation search");
        let store = self.store.lock().map_err(|e| {
            zbus::fdo::Error::Failed(format!("lock poisoned: {e}"))
        })?;
        let hits = store
            .search(&query, limit)
            .map_err(|e| crate::error::opaque("conversation store operation failed", e))?;
        let json: Vec<serde_json::Value> = hits
            .iter()
            .map(|m| {
                serde_json::json!({
                    "id": m.id,
                    "conversation_id": m.conversation_id,
                    "role": m.role.as_str(),
                    "content": m.content,
                    "timestamp": m.timestamp,
                })
            })
            .collect();
        serde_json::to_string(&json)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
    }

    /// List conversations in reverse chronological order as JSON.
    async fn list_conversations(&self, limit: u32) -> zbus::fdo::Result<String> {
        let store = self.store.lock().map_err(|e| {
            zbus::fdo::Error::Failed(format!("lock poisoned: {e}"))
        })?;
        let convs = store
            .list_conversations(limit)
            .map_err(|e| crate::error::opaque("conversation store operation failed", e))?;
        let json: Vec<serde_json::Value> = convs
            .iter()
            .map(|c| {
                serde_json::json!({
                    "id": c.id,
                    "started_at": c.started_at,
                    "title": c.title,
                    "summary": c.summary,
                })
            })
            .collect();
        serde_json::to_string(&json)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
    }

    /// Delete all messages sent since UTC midnight today.
    /// Returns the number of messages deleted.
    async fn forget_today(&self) -> zbus::fdo::Result<u32> {
        info!("D-Bus forget_today");
        let store = self.store.lock().map_err(|e| {
            zbus::fdo::Error::Failed(format!("lock poisoned: {e}"))
        })?;
        store
            .forget_today()
            .map(|n| n as u32)
            .map_err(|e| crate::error::opaque("conversation store operation failed", e))
    }

    /// Delete all messages matching the given topic via FTS.
    /// Returns the number of messages deleted.
    async fn forget_topic(&self, topic: String) -> zbus::fdo::Result<u32> {
        crate::limits::ensure_within(&topic, crate::limits::MAX_STRING_BYTES, "topic")?;
        info!(topic = %topic, "D-Bus forget_topic");
        let store = self.store.lock().map_err(|e| {
            zbus::fdo::Error::Failed(format!("lock poisoned: {e}"))
        })?;
        store
            .forget_topic(&topic)
            .map(|n| n as u32)
            .map_err(|e| crate::error::opaque("conversation store operation failed", e))
    }

    /// Delete messages older than `days` days.
    /// Returns the number of messages deleted.
    async fn forget_older_than(&self, days: u32) -> zbus::fdo::Result<u32> {
        info!(days, "D-Bus forget_older_than");
        let store = self.store.lock().map_err(|e| {
            zbus::fdo::Error::Failed(format!("lock poisoned: {e}"))
        })?;
        store
            .forget_older_than(days)
            .map(|n| n as u32)
            .map_err(|e| crate::error::opaque("conversation store operation failed", e))
    }

    /// Total number of stored messages across all conversations.
    async fn count(&self) -> zbus::fdo::Result<u32> {
        let store = self.store.lock().map_err(|e| {
            zbus::fdo::Error::Failed(format!("lock poisoned: {e}"))
        })?;
        store
            .count()
            .map(|n| n as u32)
            .map_err(|e| crate::error::opaque("conversation store operation failed", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_svc() -> ConversationService {
        let store = Arc::new(Mutex::new(ConversationStore::in_memory().unwrap()));
        ConversationService::new(store)
    }

    #[test]
    fn path_is_valid() {
        assert!(PATH.starts_with("/org/delphi"));
        assert!(PATH.ends_with("Conversation"));
    }

    #[test]
    fn service_creation() {
        let _ = mk_svc();
    }

    #[tokio::test]
    async fn count_starts_at_zero() {
        let svc = mk_svc();
        assert_eq!(svc.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn start_and_add_message_round_trip() {
        let svc = mk_svc();
        let cid = svc
            .start_conversation("My Session".to_string())
            .await
            .unwrap();
        assert!(cid.starts_with("conv-"));
        let mid = svc
            .add_message(cid.clone(), "user".to_string(), "hello".to_string())
            .await
            .unwrap();
        assert!(mid.starts_with("msg-"));
        assert_eq!(svc.count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn empty_title_stored_as_null() {
        let svc = mk_svc();
        let cid = svc.start_conversation(String::new()).await.unwrap();
        let list_json = svc.list_conversations(10).await.unwrap();
        assert!(list_json.contains(&cid));
        // JSON `null` (not "null" string) for untitled conversations.
        assert!(list_json.contains(r#""title":null"#));
    }

    #[tokio::test]
    async fn invalid_role_is_rejected() {
        let svc = mk_svc();
        let cid = svc.start_conversation(String::new()).await.unwrap();
        let err = svc
            .add_message(cid, "alien".to_string(), "x".to_string())
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("role"));
    }

    #[tokio::test]
    async fn recent_messages_returns_json_array() {
        let svc = mk_svc();
        let cid = svc.start_conversation(String::new()).await.unwrap();
        svc.add_message(cid.clone(), "user".into(), "hi".into())
            .await
            .unwrap();
        let json = svc.recent_messages(cid, 10).await.unwrap();
        assert!(json.starts_with('['));
        assert!(json.contains("\"role\":\"user\""));
        assert!(json.contains("\"content\":\"hi\""));
    }

    #[tokio::test]
    async fn search_returns_empty_array_when_no_match() {
        let svc = mk_svc();
        let cid = svc.start_conversation(String::new()).await.unwrap();
        svc.add_message(cid, "user".into(), "hello world".into())
            .await
            .unwrap();
        let json = svc.search("quantum".to_string(), 10).await.unwrap();
        assert_eq!(json, "[]");
    }

    #[tokio::test]
    async fn forget_today_returns_deleted_count() {
        let svc = mk_svc();
        let cid = svc.start_conversation(String::new()).await.unwrap();
        svc.add_message(cid, "user".into(), "hello".into())
            .await
            .unwrap();
        let deleted = svc.forget_today().await.unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(svc.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn forget_topic_returns_deleted_count() {
        let svc = mk_svc();
        let cid = svc.start_conversation(String::new()).await.unwrap();
        svc.add_message(cid.clone(), "user".into(), "quantum mechanics".into())
            .await
            .unwrap();
        svc.add_message(cid, "user".into(), "classical physics".into())
            .await
            .unwrap();
        let deleted = svc.forget_topic("quantum".to_string()).await.unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(svc.count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn forget_older_than_accepts_zero() {
        let svc = mk_svc();
        // 0 days ≡ delete nothing (timestamps must be <cutoff, and cutoff=now).
        let deleted = svc.forget_older_than(0).await.unwrap();
        assert_eq!(deleted, 0);
    }

    /// SVC-6-R2-3: every D-Bus `String` parameter is capped *before* logging,
    /// parsing, or storage. Enumerates the full surface of [`ConversationService`].
    #[tokio::test]
    async fn every_string_param_rejects_oversize() {
        let svc = mk_svc();
        let oversize = "x".repeat(crate::limits::MAX_STRING_BYTES + 1);

        // start_conversation(title)
        assert!(matches!(
            svc.start_conversation(oversize.clone()).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        // add_message(conversation_id, role, content) — each String position.
        assert!(matches!(
            svc.add_message(oversize.clone(), "user".to_string(), "c".to_string())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        assert!(matches!(
            svc.add_message("c1".to_string(), oversize.clone(), "c".to_string())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        assert!(matches!(
            svc.add_message("c1".to_string(), "user".to_string(), oversize.clone())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        // recent_messages(conversation_id)
        assert!(matches!(
            svc.recent_messages(oversize.clone(), 10).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        // search(query)
        assert!(matches!(
            svc.search(oversize.clone(), 10).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        // forget_topic(topic)
        assert!(matches!(
            svc.forget_topic(oversize.clone()).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
    }
}
