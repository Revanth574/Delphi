// SPDX-License-Identifier: MIT

//! D-Bus Conversation interface.
//!
//! Exposes the persistent conversation memory over D-Bus.
//!
//! Interface: `org.delphi.Conversation`
//!
//! SVC-2: every method enforces authorization via the shared [`AuthGuard`] on
//! its first line. `recent_messages`/`search`/`list_conversations`/`count` are
//! Autonomous; `start_conversation`/`add_message` are Confirm;
//! `forget_today`/`forget_topic`/`forget_older_than` are the destructive
//! Biometric tier (proceed-and-audit — see `AuthGuard::enforce`).
//!
//! Uses `std::sync::Mutex` (not `tokio::sync`) because `rusqlite::Connection`
//! is `!Send` across await points — see CLAUDE.md Section 3 rule 6.

use std::str::FromStr;
use std::sync::{Arc, Mutex};

use tracing::info;
use zbus::message::Header;

use die_orchestrator::conversation::{ConversationStore, MessageRole};

use crate::auth_guard::AuthGuard;

/// D-Bus object path for the Conversation interface.
pub const PATH: &str = "/org/delphi/Conversation";

/// Conversation D-Bus service.
///
/// # Examples
///
/// ```
/// use delphi_services::conversation::ConversationService;
/// use delphi_services::auth_guard::AuthGuard;
/// use die_orchestrator::conversation::ConversationStore;
/// use std::sync::{Arc, Mutex};
///
/// let store = Arc::new(Mutex::new(ConversationStore::in_memory().unwrap()));
/// let svc = ConversationService::new(store, Arc::new(AuthGuard::dev_in_memory()));
/// ```
pub struct ConversationService {
    store: Arc<Mutex<ConversationStore>>,
    guard: Arc<AuthGuard>,
}

impl ConversationService {
    /// Create a new conversation service guarded by the shared [`AuthGuard`].
    #[must_use]
    pub fn new(store: Arc<Mutex<ConversationStore>>, guard: Arc<AuthGuard>) -> Self {
        Self { store, guard }
    }
}

#[zbus::interface(name = "org.delphi.Conversation")]
impl ConversationService {
    /// Start a new conversation. Returns the new conversation ID.
    async fn start_conversation(
        &self,
        #[zbus(header)] header: Header<'_>,
        title: String,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("conversation.start_conversation", &header)?;
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

    /// Append a message to a conversation. `role` ∈ {user, assistant, system}.
    async fn add_message(
        &self,
        #[zbus(header)] header: Header<'_>,
        conversation_id: String,
        role: String,
        content: String,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("conversation.add_message", &header)?;
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
        #[zbus(header)] header: Header<'_>,
        conversation_id: String,
        limit: u32,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("conversation.recent_messages", &header)?;
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
    async fn search(
        &self,
        #[zbus(header)] header: Header<'_>,
        query: String,
        limit: u32,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("conversation.search", &header)?;
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
    async fn list_conversations(
        &self,
        #[zbus(header)] header: Header<'_>,
        limit: u32,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("conversation.list_conversations", &header)?;
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

    /// Delete all messages sent since UTC midnight today. Returns the count.
    async fn forget_today(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<u32> {
        self.guard.enforce("conversation.forget_today", &header)?;
        info!("D-Bus forget_today");
        let store = self.store.lock().map_err(|e| {
            zbus::fdo::Error::Failed(format!("lock poisoned: {e}"))
        })?;
        store
            .forget_today()
            .map(|n| n as u32)
            .map_err(|e| crate::error::opaque("conversation store operation failed", e))
    }

    /// Delete all messages matching the given topic via FTS. Returns the count.
    async fn forget_topic(
        &self,
        #[zbus(header)] header: Header<'_>,
        topic: String,
    ) -> zbus::fdo::Result<u32> {
        self.guard.enforce("conversation.forget_topic", &header)?;
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

    /// Delete messages older than `days` days. Returns the count.
    async fn forget_older_than(
        &self,
        #[zbus(header)] header: Header<'_>,
        days: u32,
    ) -> zbus::fdo::Result<u32> {
        self.guard.enforce("conversation.forget_older_than", &header)?;
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
    async fn count(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<u32> {
        self.guard.enforce("conversation.count", &header)?;
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

    use crate::auth::AuthPolicy;
    use crate::auth_guard::completeness::{
        assert_all_methods_classified, assert_behavioral_covers_all, header_msg as msg,
    };

    fn mk_svc() -> ConversationService {
        mk_svc_with(AuthPolicy::dev())
    }

    fn mk_svc_with(policy: AuthPolicy) -> ConversationService {
        let store = Arc::new(Mutex::new(ConversationStore::in_memory().unwrap()));
        let guard = Arc::new(AuthGuard::new(
            policy,
            Arc::new(Mutex::new(fortress::audit::AuditLog::in_memory())),
        ));
        ConversationService::new(store, guard)
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
        let m = msg(":1.5");
        assert_eq!(svc.count(m.header()).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn start_and_add_message_round_trip() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let cid = svc
            .start_conversation(m.header(), "My Session".to_string())
            .await
            .unwrap();
        assert!(cid.starts_with("conv-"));
        let m = msg(":1.5");
        let mid = svc
            .add_message(m.header(), cid.clone(), "user".to_string(), "hello".to_string())
            .await
            .unwrap();
        assert!(mid.starts_with("msg-"));
        let m = msg(":1.5");
        assert_eq!(svc.count(m.header()).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn empty_title_stored_as_null() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let cid = svc.start_conversation(m.header(), String::new()).await.unwrap();
        let m = msg(":1.5");
        let list_json = svc.list_conversations(m.header(), 10).await.unwrap();
        assert!(list_json.contains(&cid));
        assert!(list_json.contains(r#""title":null"#));
    }

    #[tokio::test]
    async fn invalid_role_is_rejected() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let cid = svc.start_conversation(m.header(), String::new()).await.unwrap();
        let m = msg(":1.5");
        let err = svc
            .add_message(m.header(), cid, "alien".to_string(), "x".to_string())
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("role"));
    }

    #[tokio::test]
    async fn recent_messages_returns_json_array() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let cid = svc.start_conversation(m.header(), String::new()).await.unwrap();
        let m = msg(":1.5");
        svc.add_message(m.header(), cid.clone(), "user".into(), "hi".into())
            .await
            .unwrap();
        let m = msg(":1.5");
        let json = svc.recent_messages(m.header(), cid, 10).await.unwrap();
        assert!(json.starts_with('['));
        assert!(json.contains("\"role\":\"user\""));
        assert!(json.contains("\"content\":\"hi\""));
    }

    #[tokio::test]
    async fn search_returns_empty_array_when_no_match() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let cid = svc.start_conversation(m.header(), String::new()).await.unwrap();
        let m = msg(":1.5");
        svc.add_message(m.header(), cid, "user".into(), "hello world".into())
            .await
            .unwrap();
        let m = msg(":1.5");
        let json = svc.search(m.header(), "quantum".to_string(), 10).await.unwrap();
        assert_eq!(json, "[]");
    }

    #[tokio::test]
    async fn forget_today_returns_deleted_count() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let cid = svc.start_conversation(m.header(), String::new()).await.unwrap();
        let m = msg(":1.5");
        svc.add_message(m.header(), cid, "user".into(), "hello".into())
            .await
            .unwrap();
        let m = msg(":1.5");
        let deleted = svc.forget_today(m.header()).await.unwrap();
        assert_eq!(deleted, 1);
        let m = msg(":1.5");
        assert_eq!(svc.count(m.header()).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn forget_topic_returns_deleted_count() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let cid = svc.start_conversation(m.header(), String::new()).await.unwrap();
        let m = msg(":1.5");
        svc.add_message(m.header(), cid.clone(), "user".into(), "quantum mechanics".into())
            .await
            .unwrap();
        let m = msg(":1.5");
        svc.add_message(m.header(), cid, "user".into(), "classical physics".into())
            .await
            .unwrap();
        let m = msg(":1.5");
        let deleted = svc.forget_topic(m.header(), "quantum".to_string()).await.unwrap();
        assert_eq!(deleted, 1);
        let m = msg(":1.5");
        assert_eq!(svc.count(m.header()).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn forget_older_than_accepts_zero() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let deleted = svc.forget_older_than(m.header(), 0).await.unwrap();
        assert_eq!(deleted, 0);
    }

    /// SVC-6-R2-3: every D-Bus `String` parameter is capped *before* logging,
    /// parsing, or storage (after the SVC-2 guard).
    #[tokio::test]
    async fn every_string_param_rejects_oversize() {
        let svc = mk_svc();
        let oversize = "x".repeat(crate::limits::MAX_STRING_BYTES + 1);

        let m = msg(":1.5");
        assert!(matches!(
            svc.start_conversation(m.header(), oversize.clone()).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.add_message(m.header(), oversize.clone(), "user".to_string(), "c".to_string())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.add_message(m.header(), "c1".to_string(), oversize.clone(), "c".to_string())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.add_message(m.header(), "c1".to_string(), "user".to_string(), oversize.clone())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.recent_messages(m.header(), oversize.clone(), 10).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.search(m.header(), oversize.clone(), 10).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.forget_topic(m.header(), oversize.clone()).await.unwrap_err(),
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
        assert_all_methods_classified("conversation", &xml);
    }

    #[tokio::test]
    async fn svc2_every_method_denies_unrecognized_caller_when_deployed() {
        let svc = mk_svc_with(AuthPolicy::deployed());
        let mut exercised: Vec<&str> = Vec::new();

        exercised.push("StartConversation");
        let m = msg(":1.999");
        assert!(matches!(svc.start_conversation(m.header(), "t".to_string()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("AddMessage");
        let m = msg(":1.999");
        assert!(matches!(svc.add_message(m.header(), "c".to_string(), "user".to_string(), "x".to_string()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("RecentMessages");
        let m = msg(":1.999");
        assert!(matches!(svc.recent_messages(m.header(), "c".to_string(), 10).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("Search");
        let m = msg(":1.999");
        assert!(matches!(svc.search(m.header(), "q".to_string(), 10).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("ListConversations");
        let m = msg(":1.999");
        assert!(matches!(svc.list_conversations(m.header(), 10).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("ForgetToday");
        let m = msg(":1.999");
        assert!(matches!(svc.forget_today(m.header()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("ForgetTopic");
        let m = msg(":1.999");
        assert!(matches!(svc.forget_topic(m.header(), "t".to_string()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("ForgetOlderThan");
        let m = msg(":1.999");
        assert!(matches!(svc.forget_older_than(m.header(), 1).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("Count");
        let m = msg(":1.999");
        assert!(matches!(svc.count(m.header()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));

        use zbus::object_server::Interface;
        let mut xml = String::new();
        svc.introspect_to_writer(&mut xml, 0);
        assert_behavioral_covers_all("conversation", &xml, &exercised);
    }
}
