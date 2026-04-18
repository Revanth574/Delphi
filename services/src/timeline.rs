// SPDX-License-Identifier: MIT

//! D-Bus ActionTimeline interface.
//!
//! Exposes the 24-hour undo timeline over D-Bus. The shell can list
//! recent actions and trigger undo operations.
//!
//! Interface: `org.delphi.Timeline`

use std::sync::{Arc, Mutex};

use tracing::info;

use die_orchestrator::timeline::Timeline;

/// D-Bus object path for the Timeline interface.
pub const PATH: &str = "/org/delphi/Timeline";

/// Timeline D-Bus service.
///
/// Wraps the orchestrator `Timeline` and exposes it over D-Bus.
/// Uses `std::sync::Mutex` instead of `tokio::sync::RwLock` because
/// `rusqlite::Connection` is `!Send`. SQLite operations are fast
/// enough that blocking is acceptable.
///
/// # Examples
///
/// ```
/// use delphi_services::timeline::TimelineService;
/// use die_orchestrator::timeline::Timeline;
/// use std::sync::{Arc, Mutex};
///
/// let tl = Arc::new(Mutex::new(Timeline::in_memory().unwrap()));
/// let svc = TimelineService::new(tl);
/// ```
pub struct TimelineService {
    timeline: Arc<Mutex<Timeline>>,
}

impl TimelineService {
    /// Create a new timeline service.
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::timeline::TimelineService;
    /// use die_orchestrator::timeline::Timeline;
    /// use std::sync::{Arc, Mutex};
    ///
    /// let svc = TimelineService::new(
    ///     Arc::new(Mutex::new(Timeline::in_memory().unwrap())),
    /// );
    /// ```
    #[must_use]
    pub fn new(timeline: Arc<Mutex<Timeline>>) -> Self {
        Self { timeline }
    }
}

#[zbus::interface(name = "org.delphi.Timeline")]
impl TimelineService {
    /// Get the most recent actions.
    ///
    /// Returns a JSON array of action records.
    async fn get_recent(&self, limit: u32) -> zbus::fdo::Result<String> {
        let tl = self.timeline.lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let records = tl
            .list_recent(limit)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let json: Vec<serde_json::Value> = records
            .iter()
            .map(|r| {
                serde_json::json!({
                    "action_id": r.action_id,
                    "description": r.description,
                    "timestamp": r.timestamp,
                    "reversible": r.reversible,
                    "expires_at": r.expires_at,
                })
            })
            .collect();

        serde_json::to_string(&json)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialization failed: {e}")))
    }

    /// Undo an action by ID.
    ///
    /// Returns the undo command that was executed.
    async fn undo(&self, action_id: String) -> zbus::fdo::Result<String> {
        info!(action_id = %action_id, "D-Bus undo request");

        let tl = self.timeline.lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        tl.undo_action(&action_id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    /// Get the total action count.
    async fn count(&self) -> zbus::fdo::Result<u32> {
        let tl = self.timeline.lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let count = tl
            .count()
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(count as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_is_valid() {
        assert!(PATH.starts_with("/org/delphi"));
    }

    #[test]
    fn service_creation() {
        let tl = Arc::new(Mutex::new(Timeline::in_memory().unwrap()));
        let _svc = TimelineService::new(tl);
    }

    #[tokio::test]
    async fn get_recent_empty() {
        let tl = Arc::new(Mutex::new(Timeline::in_memory().unwrap()));
        let svc = TimelineService::new(tl);
        let json = svc.get_recent(10).await.unwrap();
        assert_eq!(json, "[]");
    }

    #[tokio::test]
    async fn count_starts_at_zero() {
        let tl = Arc::new(Mutex::new(Timeline::in_memory().unwrap()));
        let svc = TimelineService::new(tl);
        let count = svc.count().await.unwrap();
        assert_eq!(count, 0);
    }
}
