// SPDX-License-Identifier: MIT

//! Learning facade — domain home for suggestion accept/dismiss semantics
//! (services-sweep finding SVC-5).
//!
//! # Why this exists
//!
//! Suggestion state and accept/dismiss logic were duplicated across two
//! transport layers (the D-Bus `LearningService` and the WebSocket
//! `shell-bridge::Handler`), each holding an `Arc<RwLock<Vec<Suggestion>>>`
//! and each implementing `accept` and `dismiss` *identically* (both just
//! deleted the suggestion — "accept" never enabled anything). This facade
//! moves the semantics into the domain so both transports become thin
//! pass-throughs to one authoritative implementation:
//!
//! - **accept**: `Proposed → Practicing` (preserving the engine's safety-stage
//!   progression; it does NOT jump to `Automated`), recorded as a reversible
//!   24-hour action in the [`Timeline`] (Iron Law #5).
//! - **dismiss**: `→ Dismissed` plus an in-memory tombstone keyed on the
//!   pattern's description, so the same pattern is not re-proposed after a
//!   later detection pass.
//!
//! # Focus / category gating (in the domain, not the transport)
//!
//! - **Focus mode** ≡ the engine being paused (`!LearningEngine::is_active()`;
//!   the engine documents `pause()` as "Focus mode"). In Focus: [`list_suggestions`]
//!   returns none and [`accept`](LearningFacade::accept) is rejected, but
//!   [`dismiss`](LearningFacade::dismiss) is still allowed (the user may always
//!   clear a suggestion).
//! - **Category gating is observation-only this round** (SVC-5 decision): events
//!   of a disabled category are never recorded, so no suggestion forms to gate.
//!   Suggestion-level *retro*-filtering (suppressing a suggestion formed before
//!   its category was disabled) needs an `EventCategory` on `die_learning::Pattern`
//!   and is deferred to Phase 3B.0a/3B.1 — see PROGRESS.md.
//!
//! # Persistence
//!
//! In-memory for this round (the engine's `HashMap` + the tombstone set).
//! Durable, Fortress-encrypted storage is Phase 3B.1+.

use std::collections::HashSet;

use die_learning::engine::{PatternStage, TrackedPattern};
use die_learning::{LearningEngine, LearningError};
use serde::Serialize;
use tracing::info;

use crate::error::OrchestratorError;
use crate::timeline::Timeline;

/// Errors from the learning facade.
///
/// Self-contained: this does not depend on the typed `OrchestratorError`
/// variants introduced later in SVC-9, so SVC-5 ships independently. The
/// transport maps each variant to a fixed, non-leaky D-Bus error.
#[derive(Debug, thiserror::Error)]
pub enum LearningFacadeError {
    /// Accept was attempted while the engine is paused (Focus mode).
    #[error("cannot accept suggestions while in Focus mode")]
    FocusMode,
    /// No pending suggestion with the given id.
    #[error("suggestion not found")]
    NotFound,
    /// The underlying learning engine rejected the operation.
    #[error("learning engine error: {0}")]
    Engine(#[from] LearningError),
    /// Recording the accept action to the timeline failed.
    #[error("timeline error: {0}")]
    Timeline(#[from] OrchestratorError),
}

/// A learning suggestion surfaced to the user (DTO crossing the bus as JSON).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LearningSuggestion {
    /// Stable pattern id (e.g. `pat-0001`).
    pub id: String,
    /// Human-readable description of the proposed automation.
    pub description: String,
    /// Detection confidence (0.0–1.0).
    pub confidence: f64,
    /// How many times the pattern was observed.
    pub observed_count: u32,
    /// Current lifecycle stage (`proposed`/`practicing`/…).
    pub stage: String,
}

/// Result of accepting a suggestion.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AcceptSuggestionResult {
    /// The accepted suggestion's id.
    pub suggestion_id: String,
    /// The stage after acceptance (`practicing`).
    pub new_stage: String,
    /// The reversible action-timeline id recorded for this acceptance.
    pub action_timeline_id: String,
}

/// Result of dismissing a suggestion.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DismissSuggestionResult {
    /// The dismissed suggestion's id.
    pub suggestion_id: String,
    /// Whether a tombstone was recorded (suppresses re-proposal).
    pub tombstoned: bool,
}

/// Wire-stable lowercase name for a pattern stage.
#[must_use]
fn stage_str(stage: PatternStage) -> &'static str {
    match stage {
        PatternStage::Proposed => "proposed",
        PatternStage::Practicing => "practicing",
        PatternStage::Refining => "refining",
        PatternStage::Automated => "automated",
        PatternStage::Dismissed => "dismissed",
    }
}

/// Map a tracked pattern to the wire DTO.
fn to_suggestion(p: &TrackedPattern) -> LearningSuggestion {
    LearningSuggestion {
        id: p.id.clone(),
        description: p.pattern.description.clone(),
        confidence: p.pattern.confidence,
        observed_count: p.pattern.occurrences,
        stage: stage_str(p.stage).to_string(),
    }
}

/// Domain facade over [`LearningEngine`] + the action [`Timeline`].
///
/// Wrap in `Arc<std::sync::Mutex<LearningFacade>>` for sharing across the
/// D-Bus and WebSocket transports — `std::sync::Mutex` (not `tokio`) because
/// the embedded `Timeline` holds a `!Send`-guard `rusqlite::Connection`; no
/// method holds the lock across an `.await`.
pub struct LearningFacade {
    engine: LearningEngine,
    timeline: Timeline,
    /// Descriptions of dismissed patterns — suppress re-proposal of the same
    /// pattern after a later detection pass (in-memory; durable = 3B.1+).
    tombstones: HashSet<String>,
}

impl LearningFacade {
    /// Build a facade from an existing engine and timeline.
    #[must_use]
    pub fn new(engine: LearningEngine, timeline: Timeline) -> Self {
        Self {
            engine,
            timeline,
            tombstones: HashSet::new(),
        }
    }

    /// Build a facade with a fresh engine and an in-memory timeline.
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError`] if the in-memory timeline cannot be opened.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::learning::LearningFacade;
    ///
    /// let facade = LearningFacade::in_memory().unwrap();
    /// assert!(facade.list_suggestions().is_empty());
    /// ```
    pub fn in_memory() -> Result<Self, OrchestratorError> {
        Ok(Self::new(LearningEngine::new(), Timeline::in_memory()?))
    }

    /// Mutable access to the underlying engine, for observation wiring and
    /// Focus/category control (`observe`, `pause`/`resume`, `disable_category`).
    ///
    /// `accept`/`dismiss` MUST go through the facade (not the engine directly)
    /// so the timeline record and tombstone semantics are applied.
    pub fn engine_mut(&mut self) -> &mut LearningEngine {
        &mut self.engine
    }

    /// Whether Focus mode is active (the engine is paused).
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::learning::LearningFacade;
    ///
    /// let mut facade = LearningFacade::in_memory().unwrap();
    /// assert!(!facade.focus_active());
    /// facade.enter_focus();
    /// assert!(facade.focus_active());
    /// ```
    #[must_use]
    pub fn focus_active(&self) -> bool {
        !self.engine.is_active()
    }

    /// Enter Focus mode — pause observation and suppress suggestions.
    pub fn enter_focus(&mut self) {
        self.engine.pause();
    }

    /// Leave Focus mode.
    pub fn leave_focus(&mut self) {
        self.engine.resume();
    }

    /// List pending suggestions. Returns none in Focus mode; tombstoned
    /// (previously dismissed) patterns are suppressed.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::learning::LearningFacade;
    ///
    /// let facade = LearningFacade::in_memory().unwrap();
    /// assert!(facade.list_suggestions().is_empty());
    /// ```
    #[must_use]
    pub fn list_suggestions(&self) -> Vec<LearningSuggestion> {
        if self.focus_active() {
            return Vec::new();
        }
        self.engine
            .pending_suggestions()
            .into_iter()
            .filter(|p| !self.tombstones.contains(&p.pattern.description))
            .map(to_suggestion)
            .collect()
    }

    /// Accept a pending suggestion: `Proposed → Practicing`, recorded as a
    /// reversible action. Rejected in Focus mode.
    ///
    /// # Errors
    ///
    /// - [`LearningFacadeError::FocusMode`] if the engine is paused.
    /// - [`LearningFacadeError::NotFound`] if no pending suggestion has `id`.
    /// - [`LearningFacadeError::Timeline`] if recording the action fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::learning::{LearningFacade, LearningFacadeError};
    ///
    /// let mut facade = LearningFacade::in_memory().unwrap();
    /// assert!(matches!(facade.accept("pat-9999"), Err(LearningFacadeError::NotFound)));
    /// ```
    pub fn accept(&mut self, id: &str) -> Result<AcceptSuggestionResult, LearningFacadeError> {
        if self.focus_active() {
            return Err(LearningFacadeError::FocusMode);
        }
        // Only a still-Proposed suggestion is acceptable; capture its
        // description before the immutable borrow ends.
        let description = match self.engine.get_pattern(id) {
            Some(p) if p.stage == PatternStage::Proposed => p.pattern.description.clone(),
            _ => return Err(LearningFacadeError::NotFound),
        };

        // Record-before-mutate (Iron Law #5): the acceptance is a reversible
        // 24-hour action whose undo command dismisses the same suggestion.
        let action_timeline_id = self.timeline.record_action(
            &format!("Accepted automation suggestion: {description}"),
            &format!("learning.dismiss {id}"),
        )?;

        self.engine.accept_pattern(id)?;
        info!(suggestion_id = %id, %action_timeline_id, "suggestion accepted (Practicing)");
        Ok(AcceptSuggestionResult {
            suggestion_id: id.to_string(),
            new_stage: stage_str(PatternStage::Practicing).to_string(),
            action_timeline_id,
        })
    }

    /// Dismiss a suggestion: `→ Dismissed` plus a tombstone so the same
    /// pattern is not re-proposed. Allowed even in Focus mode.
    ///
    /// # Errors
    ///
    /// [`LearningFacadeError::NotFound`] if no suggestion has `id`.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::learning::{LearningFacade, LearningFacadeError};
    ///
    /// let mut facade = LearningFacade::in_memory().unwrap();
    /// assert!(matches!(facade.dismiss("pat-9999"), Err(LearningFacadeError::NotFound)));
    /// ```
    pub fn dismiss(&mut self, id: &str) -> Result<DismissSuggestionResult, LearningFacadeError> {
        let description = match self.engine.get_pattern(id) {
            Some(p) => p.pattern.description.clone(),
            None => return Err(LearningFacadeError::NotFound),
        };
        self.engine.dismiss_pattern(id)?;
        self.tombstones.insert(description);
        info!(suggestion_id = %id, "suggestion dismissed (tombstoned)");
        Ok(DismissSuggestionResult {
            suggestion_id: id.to_string(),
            tombstoned: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use die_learning::{EventCategory, LearningEvent};

    /// Deterministically seed one Proposed suggestion. Feeding N≥3 repetitions
    /// of the `firefox → code` app sequence guarantees a significant
    /// `AppSequence` pattern: for window size 2 the pair occurs `N` times with
    /// confidence `N/(2N-1) > 0.5` (see `die_learning::pattern::detect_app_sequences`).
    /// Asserts (does not skip) that the seed produced a suggestion.
    fn seeded() -> (LearningFacade, String) {
        let mut facade = LearningFacade::in_memory().unwrap();
        for i in 0..10 {
            let _ = facade.engine_mut().observe(LearningEvent::at_time(
                EventCategory::AppLaunch,
                "firefox",
                None,
                i * 100,
            ));
            let _ = facade.engine_mut().observe(LearningEvent::at_time(
                EventCategory::AppLaunch,
                "code",
                None,
                i * 100 + 10,
            ));
        }
        let detected = facade
            .engine_mut()
            .run_detection()
            .expect("firefox→code repetition must yield a significant pattern");
        assert!(!detected.is_empty(), "seed recipe failed to produce a pattern");
        let id = facade
            .list_suggestions()
            .first()
            .expect("a proposed suggestion should be listed")
            .id
            .clone();
        (facade, id)
    }

    #[test]
    fn accept_moves_to_practicing_and_returns_timeline_id() {
        let (mut facade, id) = seeded();
        let result = facade.accept(&id).unwrap();
        assert_eq!(result.suggestion_id, id);
        assert_eq!(result.new_stage, "practicing");
        assert!(
            result.action_timeline_id.starts_with("tl-"),
            "accept must return a real timeline action id: {}",
            result.action_timeline_id
        );
        // Engine state reflects the transition.
        assert_eq!(
            facade.engine_mut().get_pattern(&id).unwrap().stage,
            PatternStage::Practicing
        );
    }

    #[test]
    fn dismiss_moves_to_dismissed_and_tombstones() {
        let (mut facade, id) = seeded();
        let result = facade.dismiss(&id).unwrap();
        assert_eq!(result.suggestion_id, id);
        assert!(result.tombstoned);
        assert_eq!(
            facade.engine_mut().get_pattern(&id).unwrap().stage,
            PatternStage::Dismissed
        );
    }

    #[test]
    fn accept_and_dismiss_are_distinct() {
        // The SVC-5 root cause: accept and dismiss were identical. They must
        // now drive different terminal stages.
        let (mut facade_a, id_a) = seeded();
        facade_a.accept(&id_a).unwrap();
        let (mut facade_d, id_d) = seeded();
        facade_d.dismiss(&id_d).unwrap();
        assert_eq!(
            facade_a.engine_mut().get_pattern(&id_a).unwrap().stage,
            PatternStage::Practicing
        );
        assert_eq!(
            facade_d.engine_mut().get_pattern(&id_d).unwrap().stage,
            PatternStage::Dismissed
        );
    }

    #[test]
    fn list_returns_none_in_focus() {
        let (mut facade, _id) = seeded();
        assert!(!facade.list_suggestions().is_empty());
        facade.enter_focus();
        assert!(facade.list_suggestions().is_empty());
        facade.leave_focus();
        assert!(!facade.list_suggestions().is_empty());
    }

    #[test]
    fn accept_blocked_in_focus() {
        let (mut facade, id) = seeded();
        facade.enter_focus();
        assert!(matches!(facade.accept(&id), Err(LearningFacadeError::FocusMode)));
        // The suggestion is untouched (still Proposed).
        assert_eq!(
            facade.engine_mut().get_pattern(&id).unwrap().stage,
            PatternStage::Proposed
        );
    }

    #[test]
    fn dismiss_allowed_in_focus() {
        let (mut facade, id) = seeded();
        facade.enter_focus();
        let result = facade.dismiss(&id).unwrap();
        assert!(result.tombstoned);
        assert_eq!(
            facade.engine_mut().get_pattern(&id).unwrap().stage,
            PatternStage::Dismissed
        );
    }

    #[test]
    fn tombstone_suppresses_reproposal_after_redetection() {
        let (mut facade, id) = seeded();
        // Capture the EXACT description we dismiss. The seed recipe yields
        // several overlapping patterns (window sizes 2..=5), so the tombstone
        // and assertion must key on the exact description, not a shared
        // substring like "firefox → code".
        let desc = facade
            .list_suggestions()
            .into_iter()
            .find(|s| s.id == id)
            .expect("seeded suggestion present")
            .description;
        facade.dismiss(&id).unwrap();
        assert!(
            facade.list_suggestions().iter().all(|s| s.description != desc),
            "dismissed suggestion still listed"
        );
        // Re-detect the SAME pattern (same firefox→code description). A fresh
        // detection pass assigns new ids, but the tombstone (keyed on
        // description) must keep it out of the surfaced list.
        for i in 0..10 {
            let _ = facade.engine_mut().observe(LearningEvent::at_time(
                EventCategory::AppLaunch,
                "firefox",
                None,
                1000 + i * 100,
            ));
            let _ = facade.engine_mut().observe(LearningEvent::at_time(
                EventCategory::AppLaunch,
                "code",
                None,
                1000 + i * 100 + 10,
            ));
        }
        let _ = facade.engine_mut().run_detection();
        assert!(
            facade.list_suggestions().iter().all(|s| s.description != desc),
            "a tombstoned pattern (desc={desc:?}) was re-proposed"
        );
    }

    #[test]
    fn disabled_category_events_are_not_observed() {
        // Observation-only category gating (SVC-5 decision): events of a
        // disabled category are rejected, so no pattern (hence no suggestion)
        // can form from them.
        let mut facade = LearningFacade::in_memory().unwrap();
        facade.engine_mut().disable_category(EventCategory::FileAccess);
        let rejected = facade.engine_mut().observe(LearningEvent::new(
            EventCategory::FileAccess,
            "/secret/path",
            None,
        ));
        assert!(rejected.is_err(), "disabled-category event must be rejected");
        assert!(facade.list_suggestions().is_empty());
    }

    #[test]
    fn unknown_id_is_not_found() {
        let mut facade = LearningFacade::in_memory().unwrap();
        assert!(matches!(facade.accept("nope"), Err(LearningFacadeError::NotFound)));
        assert!(matches!(facade.dismiss("nope"), Err(LearningFacadeError::NotFound)));
    }
}
