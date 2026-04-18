// SPDX-License-Identifier: MIT

//! D-Bus Learning interface.
//!
//! Exposes the Universal Learning Loop's suggestion system over D-Bus.
//! The shell displays learned task suggestions; the user can accept
//! or dismiss them.
//!
//! Interface: `org.delphi.Learning`
//!
//! # Learning Loop
//!
//! ```text
//! OBSERVE → MODEL → PROPOSE → PRACTICE → REFINE → AUTOMATE → EVOLVE
//! ```

use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::info;

/// D-Bus object path for the Learning interface.
pub const PATH: &str = "/org/delphi/Learning";

/// A learning suggestion proposed to the user.
///
/// # Examples
///
/// ```
/// use delphi_services::learning::Suggestion;
///
/// let s = Suggestion {
///     id: "sug-001".to_string(),
///     description: "I noticed you archive reports weekly. Want me to do it?".to_string(),
///     confidence: 0.85,
///     observed_count: 5,
/// };
/// assert!(s.confidence > 0.5);
/// ```
#[derive(Debug, Clone)]
pub struct Suggestion {
    /// Unique suggestion identifier.
    pub id: String,
    /// Human-readable description of the proposed automation.
    pub description: String,
    /// Confidence level (0.0–1.0).
    pub confidence: f64,
    /// Number of times the task was observed.
    pub observed_count: u32,
}

/// Learning D-Bus service.
///
/// Stores and serves learning suggestions. In a future phase, this
/// will be backed by the full learning engine with observation and
/// behavioral modeling.
///
/// # Examples
///
/// ```
/// use delphi_services::learning::LearningService;
/// use std::sync::Arc;
/// use tokio::sync::RwLock;
///
/// let svc = LearningService::new(Arc::new(RwLock::new(Vec::new())));
/// ```
pub struct LearningService {
    suggestions: Arc<RwLock<Vec<Suggestion>>>,
}

impl LearningService {
    /// Create a new learning service.
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::learning::LearningService;
    /// use std::sync::Arc;
    /// use tokio::sync::RwLock;
    ///
    /// let svc = LearningService::new(Arc::new(RwLock::new(Vec::new())));
    /// ```
    #[must_use]
    pub fn new(suggestions: Arc<RwLock<Vec<Suggestion>>>) -> Self {
        Self { suggestions }
    }
}

#[zbus::interface(name = "org.delphi.Learning")]
impl LearningService {
    /// Get all active suggestions.
    ///
    /// Returns a JSON array of suggestion objects.
    async fn get_suggestions(&self) -> zbus::fdo::Result<String> {
        let suggestions = self.suggestions.read().await;
        let json: Vec<serde_json::Value> = suggestions
            .iter()
            .map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "description": s.description,
                    "confidence": s.confidence,
                    "observed_count": s.observed_count,
                })
            })
            .collect();

        serde_json::to_string(&json)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialization failed: {e}")))
    }

    /// Accept a suggestion (enable the automation).
    async fn accept_suggestion(&self, suggestion_id: String) -> zbus::fdo::Result<()> {
        info!(suggestion_id = %suggestion_id, "suggestion accepted");

        let mut suggestions = self.suggestions.write().await;
        suggestions.retain(|s| s.id != suggestion_id);
        Ok(())
    }

    /// Dismiss a suggestion (don't automate this).
    async fn dismiss_suggestion(&self, suggestion_id: String) -> zbus::fdo::Result<()> {
        info!(suggestion_id = %suggestion_id, "suggestion dismissed");

        let mut suggestions = self.suggestions.write().await;
        suggestions.retain(|s| s.id != suggestion_id);
        Ok(())
    }

    /// Get the count of active suggestions.
    async fn suggestion_count(&self) -> zbus::fdo::Result<u32> {
        let suggestions = self.suggestions.read().await;
        Ok(suggestions.len() as u32)
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
    fn suggestion_fields() {
        let s = Suggestion {
            id: "sug-001".to_string(),
            description: "Archive reports".to_string(),
            confidence: 0.9,
            observed_count: 7,
        };
        assert_eq!(s.observed_count, 7);
        assert!(s.confidence > 0.5);
    }

    #[tokio::test]
    async fn empty_suggestions() {
        let svc = LearningService::new(Arc::new(RwLock::new(Vec::new())));
        let json = svc.get_suggestions().await.unwrap();
        assert_eq!(json, "[]");
        assert_eq!(svc.suggestion_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn accept_removes_suggestion() {
        let suggestions = vec![Suggestion {
            id: "sug-001".to_string(),
            description: "test".to_string(),
            confidence: 0.8,
            observed_count: 3,
        }];
        let svc = LearningService::new(Arc::new(RwLock::new(suggestions)));

        assert_eq!(svc.suggestion_count().await.unwrap(), 1);
        svc.accept_suggestion("sug-001".to_string()).await.unwrap();
        assert_eq!(svc.suggestion_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn dismiss_removes_suggestion() {
        let suggestions = vec![Suggestion {
            id: "sug-002".to_string(),
            description: "test".to_string(),
            confidence: 0.6,
            observed_count: 2,
        }];
        let svc = LearningService::new(Arc::new(RwLock::new(suggestions)));

        svc.dismiss_suggestion("sug-002".to_string())
            .await
            .unwrap();
        assert_eq!(svc.suggestion_count().await.unwrap(), 0);
    }
}
