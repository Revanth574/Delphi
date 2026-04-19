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
        info!(title = %title, "D-Bus start_conversation");
        let store = self.store.lock().map_err(|e| {
            zbus::fdo::Error::Failed(format!("lock poisoned: {e}"))
        })?;
        let title_opt = if title.is_empty() { None } else { Some(title.as_str()) };
        store
            .start_conversation(title_opt)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
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
        let role = MessageRole::from_str(&role)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;
        let store = self.store.lock().map_err(|e| {
            zbus::fdo::Error::Failed(format!("lock poisoned: {e}"))
        })?;
        store
            .add_message(&conversation_id, role, &content, None)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    /// Fetch the most recent messages from a conversation as JSON.
    async fn recent_messages(
        &self,
        conversation_id: String,
        limit: u32,
    ) -> zbus::fdo::Result<String> {
        let store = self.store.lock().map_err(|e| {
            zbus::fdo::Error::Failed(format!("lock poisoned: {e}"))
        })?;
        let msgs = store
            .recent_messages(&conversation_id, limit)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
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
        info!(query = %query, "D-Bus conversation search");
        let store = self.store.lock().map_err(|e| {
            zbus::fdo::Error::Failed(format!("lock poisoned: {e}"))
        })?;
        let hits = store
            .search(&query, limit)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
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
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
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
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    /// Delete all messages matching the given topic via FTS.
    /// Returns the number of messages deleted.
    async fn forget_topic(&self, topic: String) -> zbus::fdo::Result<u32> {
        info!(topic = %topic, "D-Bus forget_topic");
        let store = self.store.lock().map_err(|e| {
            zbus::fdo::Error::Failed(format!("lock poisoned: {e}"))
        })?;
        store
            .forget_topic(&topic)
            .map(|n| n as u32)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
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
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    /// Total number of stored messages across all conversations.
    async fn count(&self) -> zbus::fdo::Result<u32> {
        let store = self.store.lock().map_err(|e| {
            zbus::fdo::Error::Failed(format!("lock poisoned: {e}"))
        })?;
        store
            .count()
            .map(|n| n as u32)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
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
}
