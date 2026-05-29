// SPDX-License-Identifier: MIT

//! D-Bus Learning interface.
//!
//! Thin transport over the domain [`LearningFacade`] (services-sweep finding
//! SVC-5). All suggestion semantics — accept (`Proposed → Practicing`,
//! recorded as a reversible action), dismiss (`→ Dismissed` + tombstone), and
//! Focus gating — live in `die_orchestrator::learning`; this file just locks,
//! calls, and serializes. The *same* `Arc<Mutex<LearningFacade>>` is shared
//! with the WebSocket bridge (`shell-bridge`) so both transports operate on one
//! authoritative state instead of duplicated, independently-buggy copies.
//!
//! Interface: `org.delphi.Learning`
//!
//! Methods return JSON strings (the richer `AcceptSuggestionResult` /
//! `DismissSuggestionResult` carry state the previous `()`-returning methods
//! could not). Uses `std::sync::Mutex` (not `tokio`) because the facade embeds
//! a `Timeline` whose `rusqlite::Connection` is `!Send`; no method holds the
//! lock across an `.await`.

use std::sync::{Arc, Mutex};

use tracing::info;

use die_orchestrator::learning::{LearningFacade, LearningFacadeError};

/// D-Bus object path for the Learning interface.
pub const PATH: &str = "/org/delphi/Learning";

/// Learning D-Bus service — a thin pass-through to the shared domain facade.
///
/// # Examples
///
/// ```
/// use delphi_services::learning::LearningService;
/// use die_orchestrator::learning::LearningFacade;
/// use std::sync::{Arc, Mutex};
///
/// let facade = LearningFacade::in_memory().unwrap();
/// let svc = LearningService::new(Arc::new(Mutex::new(facade)));
/// ```
pub struct LearningService {
    facade: Arc<Mutex<LearningFacade>>,
}

impl LearningService {
    /// Wrap a shared [`LearningFacade`] for D-Bus exposure.
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::learning::LearningService;
    /// use die_orchestrator::learning::LearningFacade;
    /// use std::sync::{Arc, Mutex};
    ///
    /// let svc = LearningService::new(Arc::new(Mutex::new(
    ///     LearningFacade::in_memory().unwrap(),
    /// )));
    /// ```
    #[must_use]
    pub fn new(facade: Arc<Mutex<LearningFacade>>) -> Self {
        Self { facade }
    }

    fn lock(&self) -> zbus::fdo::Result<std::sync::MutexGuard<'_, LearningFacade>> {
        self.facade
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("learning facade lock poisoned: {e}")))
    }
}

/// Translate a facade error into a sanitized D-Bus error. `FocusMode` and
/// `NotFound` carry no caller/server detail, so their fixed messages are safe
/// to surface; engine/timeline internals are routed through the SVC-4
/// [`opaque`](crate::error::opaque) sanitizer.
fn map_learning_error(e: LearningFacadeError) -> zbus::fdo::Error {
    match e {
        LearningFacadeError::FocusMode => {
            zbus::fdo::Error::Failed("cannot accept suggestions while in Focus mode".to_string())
        }
        LearningFacadeError::NotFound => {
            zbus::fdo::Error::InvalidArgs("suggestion not found".to_string())
        }
        other => crate::error::opaque("learning operation failed", other),
    }
}

#[zbus::interface(name = "org.delphi.Learning")]
impl LearningService {
    /// Pending suggestions as a JSON array of `LearningSuggestion`.
    async fn get_suggestions(&self) -> zbus::fdo::Result<String> {
        let suggestions = {
            let facade = self.lock()?;
            facade.list_suggestions()
        };
        serde_json::to_string(&suggestions)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
    }

    /// Accept a suggestion (`Proposed → Practicing`). Returns a JSON
    /// `AcceptSuggestionResult` (includes the reversible action-timeline id).
    async fn accept_suggestion(&self, suggestion_id: String) -> zbus::fdo::Result<String> {
        crate::limits::ensure_within(
            &suggestion_id,
            crate::limits::MAX_STRING_BYTES,
            "suggestion_id",
        )?;
        info!(suggestion_id = %suggestion_id, "D-Bus accept_suggestion");
        let result = {
            let mut facade = self.lock()?;
            facade.accept(&suggestion_id).map_err(map_learning_error)?
        };
        serde_json::to_string(&result)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
    }

    /// Dismiss a suggestion (`→ Dismissed` + tombstone). Returns a JSON
    /// `DismissSuggestionResult`.
    async fn dismiss_suggestion(&self, suggestion_id: String) -> zbus::fdo::Result<String> {
        crate::limits::ensure_within(
            &suggestion_id,
            crate::limits::MAX_STRING_BYTES,
            "suggestion_id",
        )?;
        info!(suggestion_id = %suggestion_id, "D-Bus dismiss_suggestion");
        let result = {
            let mut facade = self.lock()?;
            facade.dismiss(&suggestion_id).map_err(map_learning_error)?
        };
        serde_json::to_string(&result)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
    }

    /// Count of pending (non-tombstoned, non-Focus-suppressed) suggestions.
    async fn suggestion_count(&self) -> zbus::fdo::Result<u32> {
        let count = {
            let facade = self.lock()?;
            facade.list_suggestions().len()
        };
        Ok(count as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use die_orchestrator::learning::LearningFacade;

    fn svc() -> LearningService {
        LearningService::new(Arc::new(Mutex::new(LearningFacade::in_memory().unwrap())))
    }

    #[test]
    fn path_is_valid() {
        assert!(PATH.starts_with("/org/delphi"));
        assert!(PATH.ends_with("Learning"));
    }

    #[tokio::test]
    async fn get_suggestions_empty_is_json_array() {
        let s = svc();
        assert_eq!(s.get_suggestions().await.unwrap(), "[]");
        assert_eq!(s.suggestion_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn accept_unknown_id_is_not_found_without_leak() {
        let s = svc();
        let err = s
            .accept_suggestion("pat-9999".to_string())
            .await
            .unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
        assert!(err.to_string().ends_with("suggestion not found"));
    }

    #[tokio::test]
    async fn dismiss_unknown_id_is_not_found() {
        let s = svc();
        let err = s
            .dismiss_suggestion("pat-9999".to_string())
            .await
            .unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
    }

    #[tokio::test]
    async fn accept_in_focus_is_rejected_clearly() {
        // A facade in Focus rejects accept before any id lookup, so no seeded
        // pattern is needed to exercise the FocusMode -> Failed mapping.
        let mut facade = LearningFacade::in_memory().unwrap();
        facade.enter_focus();
        let s = LearningService::new(Arc::new(Mutex::new(facade)));
        let err = s
            .accept_suggestion("anything".to_string())
            .await
            .unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::Failed(_)));
        assert!(err.to_string().contains("Focus mode"));
    }

    /// SVC-6-R2-3: every D-Bus `String` parameter is capped at the boundary.
    #[tokio::test]
    async fn every_string_param_rejects_oversize() {
        let svc = LearningService::new(Arc::new(Mutex::new(
            LearningFacade::in_memory().unwrap(),
        )));
        let oversize = "x".repeat(crate::limits::MAX_STRING_BYTES + 1);
        assert!(matches!(
            svc.accept_suggestion(oversize.clone()).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        assert!(matches!(
            svc.dismiss_suggestion(oversize).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
    }
}
