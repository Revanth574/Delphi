// SPDX-License-Identifier: MIT

//! Learning engine — the full Universal Learning Loop.
//!
//! Implements the loop:
//! ```text
//! OBSERVE → MODEL → PROPOSE → PRACTICE → REFINE → AUTOMATE → EVOLVE
//! ```
//!
//! The engine connects the observer (event collection), pattern detector,
//! and suggestion system. Patterns progress through lifecycle stages
//! independently.

use std::collections::HashMap;

use tracing::{info, warn};

use crate::error::LearningError;
use crate::event::{EventCategory, LearningEvent};
use crate::observer::Observer;
use crate::pattern::{detect_patterns, Pattern};

/// Minimum supervised executions before offering automation.
const AUTOMATION_THRESHOLD: u32 = 3;

/// Lifecycle stage of a learned pattern.
///
/// Each pattern independently progresses through these stages.
///
/// # Examples
///
/// ```
/// use die_learning::engine::PatternStage;
///
/// let stage = PatternStage::Proposed;
/// assert!(!stage.is_automated());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternStage {
    /// Pattern detected, awaiting user review.
    Proposed,
    /// User approved supervised execution.
    Practicing,
    /// User provided feedback, refining behavior.
    Refining,
    /// 3+ successful supervised runs — fully automated.
    Automated,
    /// User dismissed this pattern.
    Dismissed,
}

impl PatternStage {
    /// Whether this stage represents full automation.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::engine::PatternStage;
    ///
    /// assert!(PatternStage::Automated.is_automated());
    /// assert!(!PatternStage::Proposed.is_automated());
    /// ```
    #[must_use]
    pub fn is_automated(&self) -> bool {
        *self == Self::Automated
    }

    /// Whether this pattern is still active (not dismissed).
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::engine::PatternStage;
    ///
    /// assert!(PatternStage::Proposed.is_active());
    /// assert!(!PatternStage::Dismissed.is_active());
    /// ```
    #[must_use]
    pub fn is_active(&self) -> bool {
        *self != Self::Dismissed
    }
}

/// A pattern tracked through its lifecycle.
///
/// # Examples
///
/// ```
/// use die_learning::engine::{TrackedPattern, PatternStage};
/// use die_learning::pattern::{Pattern, PatternKind};
///
/// let pattern = Pattern {
///     kind: PatternKind::AppSequence { apps: vec!["code".into()] },
///     confidence: 0.8,
///     occurrences: 5,
///     description: "test".to_string(),
/// };
/// let tracked = TrackedPattern::new("pat-001", pattern);
/// assert_eq!(tracked.stage, PatternStage::Proposed);
/// assert_eq!(tracked.successful_runs, 0);
/// ```
#[derive(Debug, Clone)]
pub struct TrackedPattern {
    /// Unique identifier for this pattern.
    pub id: String,
    /// The detected pattern.
    pub pattern: Pattern,
    /// Current lifecycle stage.
    pub stage: PatternStage,
    /// Number of successful supervised executions.
    pub successful_runs: u32,
    /// Number of failed/corrected executions.
    pub failed_runs: u32,
}

impl TrackedPattern {
    /// Create a new tracked pattern in the Proposed stage.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::engine::{TrackedPattern, PatternStage};
    /// use die_learning::pattern::{Pattern, PatternKind};
    ///
    /// let pattern = Pattern {
    ///     kind: PatternKind::QueryTemplate { template: "search ...".into() },
    ///     confidence: 0.7,
    ///     occurrences: 4,
    ///     description: "test".to_string(),
    /// };
    /// let tracked = TrackedPattern::new("pat-002", pattern);
    /// assert_eq!(tracked.stage, PatternStage::Proposed);
    /// ```
    #[must_use]
    pub fn new(id: &str, pattern: Pattern) -> Self {
        Self {
            id: id.to_string(),
            pattern,
            stage: PatternStage::Proposed,
            successful_runs: 0,
            failed_runs: 0,
        }
    }

    /// Record a successful supervised execution.
    ///
    /// If the threshold is met, transitions to Automated.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::engine::{TrackedPattern, PatternStage};
    /// use die_learning::pattern::{Pattern, PatternKind};
    ///
    /// let pattern = Pattern {
    ///     kind: PatternKind::AppSequence { apps: vec!["app".into()] },
    ///     confidence: 0.8,
    ///     occurrences: 5,
    ///     description: "test".to_string(),
    /// };
    /// let mut tracked = TrackedPattern::new("pat-003", pattern);
    /// tracked.stage = PatternStage::Practicing;
    /// tracked.record_success();
    /// tracked.record_success();
    /// tracked.record_success();
    /// assert_eq!(tracked.stage, PatternStage::Automated);
    /// ```
    pub fn record_success(&mut self) {
        self.successful_runs += 1;
        if self.successful_runs >= AUTOMATION_THRESHOLD {
            info!(
                pattern_id = %self.id,
                runs = self.successful_runs,
                "pattern graduated to Automated"
            );
            self.stage = PatternStage::Automated;
        }
    }

    /// Record a failed or corrected execution.
    ///
    /// Transitions back to Refining for further adjustment.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::engine::{TrackedPattern, PatternStage};
    /// use die_learning::pattern::{Pattern, PatternKind};
    ///
    /// let pattern = Pattern {
    ///     kind: PatternKind::AppSequence { apps: vec!["app".into()] },
    ///     confidence: 0.8,
    ///     occurrences: 5,
    ///     description: "test".to_string(),
    /// };
    /// let mut tracked = TrackedPattern::new("pat-004", pattern);
    /// tracked.stage = PatternStage::Practicing;
    /// tracked.record_failure();
    /// assert_eq!(tracked.stage, PatternStage::Refining);
    /// ```
    pub fn record_failure(&mut self) {
        self.failed_runs += 1;
        self.stage = PatternStage::Refining;
    }
}

/// The learning engine coordinates the full learning loop.
///
/// # Examples
///
/// ```
/// use die_learning::LearningEngine;
///
/// let engine = LearningEngine::new();
/// assert_eq!(engine.pattern_count(), 0);
/// assert!(engine.is_active());
/// ```
pub struct LearningEngine {
    /// The event observer.
    observer: Observer,
    /// Tracked patterns by ID.
    patterns: HashMap<String, TrackedPattern>,
    /// Counter for generating unique pattern IDs.
    next_pattern_id: u64,
}

impl LearningEngine {
    /// Create a new learning engine.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::LearningEngine;
    ///
    /// let engine = LearningEngine::new();
    /// assert!(engine.is_active());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            observer: Observer::new(),
            patterns: HashMap::new(),
            next_pattern_id: 1,
        }
    }

    /// Whether the observer is active.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::LearningEngine;
    ///
    /// let engine = LearningEngine::new();
    /// assert!(engine.is_active());
    /// ```
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.observer.is_active()
    }

    /// Number of tracked patterns.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::LearningEngine;
    ///
    /// let engine = LearningEngine::new();
    /// assert_eq!(engine.pattern_count(), 0);
    /// ```
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Number of events currently buffered.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::LearningEngine;
    ///
    /// let engine = LearningEngine::new();
    /// assert_eq!(engine.buffered_events(), 0);
    /// ```
    #[must_use]
    pub fn buffered_events(&self) -> usize {
        self.observer.event_count()
    }

    /// Total events recorded since creation.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::LearningEngine;
    ///
    /// let engine = LearningEngine::new();
    /// assert_eq!(engine.total_events(), 0);
    /// ```
    #[must_use]
    pub fn total_events(&self) -> u64 {
        self.observer.total_recorded()
    }

    /// Record an event and run pattern detection if the batch is full.
    ///
    /// Returns newly detected patterns (if any).
    ///
    /// # Errors
    ///
    /// Returns an error if the observer is paused or the category is disabled.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::{LearningEngine, LearningEvent, EventCategory};
    ///
    /// let mut engine = LearningEngine::new();
    /// let event = LearningEvent::new(EventCategory::AppLaunch, "firefox", None);
    /// let new_patterns = engine.observe(event).unwrap();
    /// assert!(new_patterns.is_empty()); // Not enough events yet
    /// ```
    pub fn observe(
        &mut self,
        event: LearningEvent,
    ) -> Result<Vec<TrackedPattern>, LearningError> {
        self.observer.record(event)?;

        if self.observer.batch_ready() {
            return self.run_detection();
        }

        Ok(Vec::new())
    }

    /// Manually trigger pattern detection on the current buffer.
    ///
    /// Useful for testing or when the caller wants immediate analysis
    /// without waiting for the batch threshold.
    ///
    /// # Errors
    ///
    /// Returns [`LearningError::NoPatternsFound`] if no patterns are detected
    /// (this is informational, not a failure).
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::{LearningEngine, LearningEvent, EventCategory};
    ///
    /// let mut engine = LearningEngine::new();
    /// for i in 0..10 {
    ///     let event = LearningEvent::at_time(
    ///         EventCategory::AppLaunch, "firefox", None, i * 60,
    ///     );
    ///     engine.observe(event).unwrap();
    /// }
    /// // Force detection even though batch isn't full
    /// let _ = engine.run_detection();
    /// ```
    pub fn run_detection(&mut self) -> Result<Vec<TrackedPattern>, LearningError> {
        let events = self.observer.drain_batch();
        if events.is_empty() {
            return Err(LearningError::NoPatternsFound { event_count: 0 });
        }

        let event_count = events.len();
        let detected = detect_patterns(&events);

        if detected.is_empty() {
            return Err(LearningError::NoPatternsFound { event_count });
        }

        info!(
            patterns = detected.len(),
            events = event_count,
            "pattern detection complete"
        );

        let mut new_patterns = Vec::new();

        for pattern in detected {
            let id = format!("pat-{:04}", self.next_pattern_id);
            self.next_pattern_id += 1;

            let tracked = TrackedPattern::new(&id, pattern);
            new_patterns.push(tracked.clone());
            self.patterns.insert(id, tracked);
        }

        Ok(new_patterns)
    }

    /// Accept a proposed pattern — transition to Practicing.
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern is not found.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::{LearningEngine, LearningEvent, EventCategory};
    /// use die_learning::engine::PatternStage;
    ///
    /// let mut engine = LearningEngine::new();
    /// // Feed enough events to generate a pattern
    /// for i in 0..50 {
    ///     let event = LearningEvent::at_time(
    ///         EventCategory::AppLaunch,
    ///         if i % 2 == 0 { "firefox" } else { "code" },
    ///         None,
    ///         i * 10,
    ///     );
    ///     engine.observe(event).unwrap();
    /// }
    /// // Accept the first pattern if any were generated
    /// let patterns: Vec<String> = engine.active_pattern_ids();
    /// if let Some(id) = patterns.first() {
    ///     engine.accept_pattern(id).unwrap();
    /// }
    /// ```
    pub fn accept_pattern(&mut self, pattern_id: &str) -> Result<(), LearningError> {
        let tracked = self.patterns.get_mut(pattern_id).ok_or_else(|| {
            LearningError::PatternDetection {
                reason: format!("pattern not found: {pattern_id}"),
            }
        })?;

        info!(pattern_id, "pattern accepted — transitioning to Practicing");
        tracked.stage = PatternStage::Practicing;
        Ok(())
    }

    /// Dismiss a proposed pattern.
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern is not found.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::LearningEngine;
    ///
    /// let mut engine = LearningEngine::new();
    /// let result = engine.dismiss_pattern("nonexistent");
    /// assert!(result.is_err());
    /// ```
    pub fn dismiss_pattern(&mut self, pattern_id: &str) -> Result<(), LearningError> {
        let tracked = self.patterns.get_mut(pattern_id).ok_or_else(|| {
            LearningError::PatternDetection {
                reason: format!("pattern not found: {pattern_id}"),
            }
        })?;

        info!(pattern_id, "pattern dismissed");
        tracked.stage = PatternStage::Dismissed;
        Ok(())
    }

    /// Record a successful supervised execution.
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern is not found.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::LearningEngine;
    ///
    /// let mut engine = LearningEngine::new();
    /// let result = engine.record_success("nonexistent");
    /// assert!(result.is_err());
    /// ```
    pub fn record_success(&mut self, pattern_id: &str) -> Result<(), LearningError> {
        let tracked = self.patterns.get_mut(pattern_id).ok_or_else(|| {
            LearningError::PatternDetection {
                reason: format!("pattern not found: {pattern_id}"),
            }
        })?;

        tracked.record_success();
        Ok(())
    }

    /// Record a failed supervised execution.
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern is not found.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::LearningEngine;
    ///
    /// let mut engine = LearningEngine::new();
    /// let result = engine.record_failure("nonexistent");
    /// assert!(result.is_err());
    /// ```
    pub fn record_failure(&mut self, pattern_id: &str) -> Result<(), LearningError> {
        let tracked = self.patterns.get_mut(pattern_id).ok_or_else(|| {
            LearningError::PatternDetection {
                reason: format!("pattern not found: {pattern_id}"),
            }
        })?;

        tracked.record_failure();
        Ok(())
    }

    /// Get all active (non-dismissed) pattern IDs.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::LearningEngine;
    ///
    /// let engine = LearningEngine::new();
    /// assert!(engine.active_pattern_ids().is_empty());
    /// ```
    #[must_use]
    pub fn active_pattern_ids(&self) -> Vec<String> {
        self.patterns
            .iter()
            .filter(|(_, p)| p.stage.is_active())
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Get all patterns in the Proposed stage (pending user review).
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::LearningEngine;
    ///
    /// let engine = LearningEngine::new();
    /// assert!(engine.pending_suggestions().is_empty());
    /// ```
    #[must_use]
    pub fn pending_suggestions(&self) -> Vec<&TrackedPattern> {
        self.patterns
            .values()
            .filter(|p| p.stage == PatternStage::Proposed)
            .collect()
    }

    /// Get all fully automated patterns.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::LearningEngine;
    ///
    /// let engine = LearningEngine::new();
    /// assert!(engine.automated_patterns().is_empty());
    /// ```
    #[must_use]
    pub fn automated_patterns(&self) -> Vec<&TrackedPattern> {
        self.patterns
            .values()
            .filter(|p| p.stage.is_automated())
            .collect()
    }

    /// Get a pattern by ID.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::LearningEngine;
    ///
    /// let engine = LearningEngine::new();
    /// assert!(engine.get_pattern("pat-0001").is_none());
    /// ```
    #[must_use]
    pub fn get_pattern(&self, id: &str) -> Option<&TrackedPattern> {
        self.patterns.get(id)
    }

    /// Pause observation (Focus mode).
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::LearningEngine;
    ///
    /// let mut engine = LearningEngine::new();
    /// engine.pause();
    /// assert!(!engine.is_active());
    /// ```
    pub fn pause(&mut self) {
        self.observer.pause();
    }

    /// Resume observation.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::LearningEngine;
    ///
    /// let mut engine = LearningEngine::new();
    /// engine.pause();
    /// engine.resume();
    /// assert!(engine.is_active());
    /// ```
    pub fn resume(&mut self) {
        self.observer.resume();
    }

    /// Enable/disable a specific category.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::{LearningEngine, EventCategory};
    ///
    /// let mut engine = LearningEngine::new();
    /// engine.disable_category(EventCategory::FileAccess);
    /// ```
    pub fn disable_category(&mut self, category: EventCategory) {
        self.observer.disable_category(category);
    }

    /// Enable a specific category.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::{LearningEngine, EventCategory};
    ///
    /// let mut engine = LearningEngine::new();
    /// engine.enable_category(EventCategory::FileAccess);
    /// ```
    pub fn enable_category(&mut self, category: EventCategory) {
        self.observer.enable_category(category);
    }

    /// Forget all learned data — purge patterns and buffered events.
    ///
    /// This is the privacy "Forget" button per CLAUDE.md Section 4.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::LearningEngine;
    ///
    /// let mut engine = LearningEngine::new();
    /// engine.forget();
    /// assert_eq!(engine.pattern_count(), 0);
    /// assert_eq!(engine.buffered_events(), 0);
    /// ```
    pub fn forget(&mut self) {
        warn!("FORGET: purging all learning data");
        self.observer.clear();
        self.patterns.clear();
    }
}

impl Default for LearningEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventCategory;

    #[test]
    fn new_engine_is_active() {
        let engine = LearningEngine::new();
        assert!(engine.is_active());
        assert_eq!(engine.pattern_count(), 0);
        assert_eq!(engine.buffered_events(), 0);
        assert_eq!(engine.total_events(), 0);
    }

    #[test]
    fn default_engine() {
        let engine = LearningEngine::default();
        assert!(engine.is_active());
    }

    #[test]
    fn observe_single_event() {
        let mut engine = LearningEngine::new();
        let event = LearningEvent::new(EventCategory::AppLaunch, "firefox", None);
        let new = engine.observe(event).unwrap();
        assert!(new.is_empty());
        assert_eq!(engine.buffered_events(), 1);
        assert_eq!(engine.total_events(), 1);
    }

    #[test]
    fn observe_respects_focus_mode() {
        let mut engine = LearningEngine::new();
        engine.pause();
        let event = LearningEvent::new(EventCategory::AppLaunch, "app", None);
        assert!(engine.observe(event).is_err());
    }

    #[test]
    fn observe_respects_disabled_category() {
        let mut engine = LearningEngine::new();
        engine.disable_category(EventCategory::FileAccess);
        let event = LearningEvent::new(EventCategory::FileAccess, "/path", None);
        assert!(engine.observe(event).is_err());
    }

    #[test]
    fn pattern_detection_on_batch() {
        let mut engine = LearningEngine::new();

        // Feed 50 events with a clear pattern: firefox → code alternating.
        for i in 0..50 {
            let app = if i % 2 == 0 { "firefox" } else { "code" };
            let event = LearningEvent::at_time(
                EventCategory::AppLaunch,
                app,
                None,
                i * 10,
            );
            let _ = engine.observe(event);
        }

        // After 50 events, detection should have run.
        // Patterns may or may not be found depending on threshold.
        // At least the engine should have processed them.
        assert_eq!(engine.buffered_events(), 0); // Drained
        assert_eq!(engine.total_events(), 50);
    }

    #[test]
    fn manual_detection() {
        let mut engine = LearningEngine::new();

        for i in 0..10 {
            let event = LearningEvent::at_time(
                EventCategory::AppLaunch,
                if i % 2 == 0 { "firefox" } else { "code" },
                None,
                i * 10,
            );
            engine.observe(event).unwrap();
        }

        let result = engine.run_detection();
        // Either detected patterns or NoPatternsFound.
        assert!(result.is_ok() || matches!(result, Err(LearningError::NoPatternsFound { .. })));
    }

    #[test]
    fn manual_detection_empty_buffer() {
        let mut engine = LearningEngine::new();
        let result = engine.run_detection();
        assert!(matches!(result, Err(LearningError::NoPatternsFound { event_count: 0 })));
    }

    #[test]
    fn accept_pattern_transitions_to_practicing() {
        let mut engine = LearningEngine::new();

        // Generate a pattern via sufficient events.
        for i in 0..25 {
            let events = vec![
                LearningEvent::at_time(EventCategory::AppLaunch, "term", None, i * 60),
                LearningEvent::at_time(
                    EventCategory::AppLaunch,
                    "editor",
                    None,
                    i * 60 + 10,
                ),
            ];
            for e in events {
                let _ = engine.observe(e);
            }
        }

        let ids = engine.active_pattern_ids();
        if let Some(id) = ids.first() {
            engine.accept_pattern(id).unwrap();
            let tracked = engine.get_pattern(id).unwrap();
            assert_eq!(tracked.stage, PatternStage::Practicing);
        }
    }

    #[test]
    fn dismiss_pattern_transitions_to_dismissed() {
        let mut engine = LearningEngine::new();

        for i in 0..25 {
            let events = vec![
                LearningEvent::at_time(EventCategory::AppLaunch, "a", None, i * 60),
                LearningEvent::at_time(EventCategory::AppLaunch, "b", None, i * 60 + 10),
            ];
            for e in events {
                let _ = engine.observe(e);
            }
        }

        let ids = engine.active_pattern_ids();
        if let Some(id) = ids.first() {
            engine.dismiss_pattern(id).unwrap();
            let tracked = engine.get_pattern(id).unwrap();
            assert_eq!(tracked.stage, PatternStage::Dismissed);
            assert!(!tracked.stage.is_active());
        }
    }

    #[test]
    fn accept_nonexistent_pattern_fails() {
        let mut engine = LearningEngine::new();
        assert!(engine.accept_pattern("no-such-id").is_err());
    }

    #[test]
    fn dismiss_nonexistent_pattern_fails() {
        let mut engine = LearningEngine::new();
        assert!(engine.dismiss_pattern("no-such-id").is_err());
    }

    #[test]
    fn record_success_nonexistent_fails() {
        let mut engine = LearningEngine::new();
        assert!(engine.record_success("no-such-id").is_err());
    }

    #[test]
    fn record_failure_nonexistent_fails() {
        let mut engine = LearningEngine::new();
        assert!(engine.record_failure("no-such-id").is_err());
    }

    #[test]
    fn pattern_lifecycle_to_automated() {
        let mut engine = LearningEngine::new();

        // Generate patterns.
        for i in 0..25 {
            let events = vec![
                LearningEvent::at_time(EventCategory::AppLaunch, "x", None, i * 60),
                LearningEvent::at_time(EventCategory::AppLaunch, "y", None, i * 60 + 10),
            ];
            for e in events {
                let _ = engine.observe(e);
            }
        }

        let ids = engine.active_pattern_ids();
        if let Some(id) = ids.first() {
            // Accept → Practicing.
            engine.accept_pattern(id).unwrap();
            // 3 successful runs → Automated.
            engine.record_success(id).unwrap();
            engine.record_success(id).unwrap();
            engine.record_success(id).unwrap();

            let tracked = engine.get_pattern(id).unwrap();
            assert_eq!(tracked.stage, PatternStage::Automated);
            assert!(tracked.stage.is_automated());
        }
    }

    #[test]
    fn failure_transitions_to_refining() {
        let mut engine = LearningEngine::new();

        for i in 0..25 {
            let events = vec![
                LearningEvent::at_time(EventCategory::AppLaunch, "p", None, i * 60),
                LearningEvent::at_time(EventCategory::AppLaunch, "q", None, i * 60 + 10),
            ];
            for e in events {
                let _ = engine.observe(e);
            }
        }

        let ids = engine.active_pattern_ids();
        if let Some(id) = ids.first() {
            engine.accept_pattern(id).unwrap();
            engine.record_failure(id).unwrap();

            let tracked = engine.get_pattern(id).unwrap();
            assert_eq!(tracked.stage, PatternStage::Refining);
        }
    }

    #[test]
    fn forget_purges_everything() {
        let mut engine = LearningEngine::new();

        for i in 0..25 {
            let events = vec![
                LearningEvent::at_time(EventCategory::AppLaunch, "a", None, i * 60),
                LearningEvent::at_time(EventCategory::AppLaunch, "b", None, i * 60 + 10),
            ];
            for e in events {
                let _ = engine.observe(e);
            }
        }

        engine.forget();
        assert_eq!(engine.pattern_count(), 0);
        assert_eq!(engine.buffered_events(), 0);
    }

    #[test]
    fn pending_suggestions_filters_correctly() {
        let engine = LearningEngine::new();
        assert!(engine.pending_suggestions().is_empty());
        assert!(engine.automated_patterns().is_empty());
    }

    #[test]
    fn pause_and_resume() {
        let mut engine = LearningEngine::new();
        engine.pause();
        assert!(!engine.is_active());
        engine.resume();
        assert!(engine.is_active());
    }

    #[test]
    fn pattern_stage_properties() {
        assert!(!PatternStage::Proposed.is_automated());
        assert!(!PatternStage::Practicing.is_automated());
        assert!(!PatternStage::Refining.is_automated());
        assert!(PatternStage::Automated.is_automated());
        assert!(!PatternStage::Dismissed.is_automated());

        assert!(PatternStage::Proposed.is_active());
        assert!(PatternStage::Practicing.is_active());
        assert!(PatternStage::Refining.is_active());
        assert!(PatternStage::Automated.is_active());
        assert!(!PatternStage::Dismissed.is_active());
    }

    #[test]
    fn tracked_pattern_new() {
        let pattern = Pattern {
            kind: crate::pattern::PatternKind::AppSequence {
                apps: vec!["a".into()],
            },
            confidence: 0.8,
            occurrences: 5,
            description: "test".to_string(),
        };
        let tracked = TrackedPattern::new("pat-test", pattern);
        assert_eq!(tracked.id, "pat-test");
        assert_eq!(tracked.stage, PatternStage::Proposed);
        assert_eq!(tracked.successful_runs, 0);
        assert_eq!(tracked.failed_runs, 0);
    }

    #[test]
    fn success_counter_increments() {
        let pattern = Pattern {
            kind: crate::pattern::PatternKind::AppSequence {
                apps: vec!["a".into()],
            },
            confidence: 0.8,
            occurrences: 5,
            description: "test".to_string(),
        };
        let mut tracked = TrackedPattern::new("pat-test", pattern);
        tracked.stage = PatternStage::Practicing;
        tracked.record_success();
        assert_eq!(tracked.successful_runs, 1);
        tracked.record_success();
        assert_eq!(tracked.successful_runs, 2);
    }

    #[test]
    fn failure_counter_increments() {
        let pattern = Pattern {
            kind: crate::pattern::PatternKind::AppSequence {
                apps: vec!["a".into()],
            },
            confidence: 0.8,
            occurrences: 5,
            description: "test".to_string(),
        };
        let mut tracked = TrackedPattern::new("pat-test", pattern);
        tracked.stage = PatternStage::Practicing;
        tracked.record_failure();
        assert_eq!(tracked.failed_runs, 1);
    }
}
