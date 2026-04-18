// SPDX-License-Identifier: MIT

//! Action observer for the learning engine.
//!
//! Records user actions as metadata-only events. Respects category
//! filtering (users can disable categories) and Focus mode (pauses
//! all observation).
//!
//! # Boundaries (CLAUDE.md Section 4)
//!
//! - MUST NOT record events for disabled categories
//! - MUST NOT access file contents — metadata only
//! - MUST pause completely in Focus mode
//! - ALL stored data MUST be encrypted via Fortress

use std::collections::HashSet;

use tracing::{info, warn};

use crate::error::LearningError;
use crate::event::{EventCategory, LearningEvent};

/// Batch size that triggers pattern detection.
pub const BATCH_SIZE: usize = 50;

/// The observer collects events and buffers them for pattern detection.
///
/// # Examples
///
/// ```
/// use die_learning::{Observer, EventCategory, LearningEvent};
///
/// let mut observer = Observer::new();
/// assert!(observer.is_active());
///
/// let event = LearningEvent::new(EventCategory::AppLaunch, "firefox", None);
/// observer.record(event).unwrap();
/// assert_eq!(observer.event_count(), 1);
/// ```
pub struct Observer {
    /// Buffered events awaiting pattern detection.
    events: Vec<LearningEvent>,
    /// Categories the user has enabled for observation.
    enabled_categories: HashSet<EventCategory>,
    /// Whether observation is active (false in Focus mode).
    active: bool,
    /// Total events recorded since creation (including drained batches).
    total_recorded: u64,
    /// Whether the live learning indicator should be shown.
    show_indicator: bool,
}

impl Observer {
    /// Create a new observer with all categories enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::Observer;
    ///
    /// let observer = Observer::new();
    /// assert!(observer.is_active());
    /// assert_eq!(observer.event_count(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            enabled_categories: EventCategory::all().iter().copied().collect(),
            active: true,
            total_recorded: 0,
            show_indicator: true,
        }
    }

    /// Whether the observer is actively recording events.
    ///
    /// Returns `false` when Focus mode is active.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::Observer;
    ///
    /// let mut observer = Observer::new();
    /// assert!(observer.is_active());
    /// observer.pause();
    /// assert!(!observer.is_active());
    /// ```
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Number of events currently buffered.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::Observer;
    ///
    /// let observer = Observer::new();
    /// assert_eq!(observer.event_count(), 0);
    /// ```
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Total events recorded since creation.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::Observer;
    ///
    /// let observer = Observer::new();
    /// assert_eq!(observer.total_recorded(), 0);
    /// ```
    #[must_use]
    pub fn total_recorded(&self) -> u64 {
        self.total_recorded
    }

    /// Whether the live learning indicator is enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::Observer;
    ///
    /// let observer = Observer::new();
    /// assert!(observer.show_indicator());
    /// ```
    #[must_use]
    pub fn show_indicator(&self) -> bool {
        self.show_indicator && self.active
    }

    /// Set whether to show the live learning indicator.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::Observer;
    ///
    /// let mut observer = Observer::new();
    /// observer.set_show_indicator(false);
    /// assert!(!observer.show_indicator());
    /// ```
    pub fn set_show_indicator(&mut self, show: bool) {
        self.show_indicator = show;
    }

    /// Record an event.
    ///
    /// Rejects the event if the observer is paused or the event's
    /// category is disabled.
    ///
    /// # Errors
    ///
    /// Returns [`LearningError::ObserverPaused`] if Focus mode is active.
    /// Returns [`LearningError::CategoryDisabled`] if the category is off.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::{Observer, EventCategory, LearningEvent};
    ///
    /// let mut observer = Observer::new();
    /// let event = LearningEvent::new(EventCategory::AppLaunch, "code", None);
    /// observer.record(event).unwrap();
    /// assert_eq!(observer.event_count(), 1);
    /// ```
    pub fn record(&mut self, event: LearningEvent) -> Result<(), LearningError> {
        if !self.active {
            return Err(LearningError::ObserverPaused);
        }

        if !self.enabled_categories.contains(&event.category) {
            return Err(LearningError::CategoryDisabled {
                category: event.category.as_str().to_string(),
            });
        }

        self.events.push(event);
        self.total_recorded += 1;
        Ok(())
    }

    /// Whether the buffer has reached the batch size for pattern detection.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::Observer;
    ///
    /// let observer = Observer::new();
    /// assert!(!observer.batch_ready());
    /// ```
    #[must_use]
    pub fn batch_ready(&self) -> bool {
        self.events.len() >= BATCH_SIZE
    }

    /// Drain the event buffer for pattern detection.
    ///
    /// Returns all buffered events and clears the buffer. Call this
    /// when [`batch_ready`] returns `true`.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::{Observer, EventCategory, LearningEvent};
    ///
    /// let mut observer = Observer::new();
    /// for i in 0..5 {
    ///     let event = LearningEvent::at_time(EventCategory::AppLaunch, "app", None, i);
    ///     observer.record(event).unwrap();
    /// }
    /// let batch = observer.drain_batch();
    /// assert_eq!(batch.len(), 5);
    /// assert_eq!(observer.event_count(), 0);
    /// ```
    pub fn drain_batch(&mut self) -> Vec<LearningEvent> {
        std::mem::take(&mut self.events)
    }

    /// Pause observation (Focus mode).
    ///
    /// While paused, all `record()` calls return `ObserverPaused`.
    /// The event buffer is preserved for when observation resumes.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::{Observer, EventCategory, LearningEvent};
    ///
    /// let mut observer = Observer::new();
    /// observer.pause();
    /// assert!(!observer.is_active());
    ///
    /// let event = LearningEvent::new(EventCategory::AppLaunch, "app", None);
    /// assert!(observer.record(event).is_err());
    /// ```
    pub fn pause(&mut self) {
        if self.active {
            info!("learning observer paused (Focus mode)");
            self.active = false;
        }
    }

    /// Resume observation after Focus mode ends.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::Observer;
    ///
    /// let mut observer = Observer::new();
    /// observer.pause();
    /// observer.resume();
    /// assert!(observer.is_active());
    /// ```
    pub fn resume(&mut self) {
        if !self.active {
            info!("learning observer resumed");
            self.active = true;
        }
    }

    /// Enable a specific event category for observation.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::{Observer, EventCategory};
    ///
    /// let mut observer = Observer::new();
    /// observer.disable_category(EventCategory::AiQuery);
    /// observer.enable_category(EventCategory::AiQuery);
    /// assert!(observer.is_category_enabled(EventCategory::AiQuery));
    /// ```
    pub fn enable_category(&mut self, category: EventCategory) {
        info!(category = category.as_str(), "learning category enabled");
        self.enabled_categories.insert(category);
    }

    /// Disable a specific event category.
    ///
    /// Events for this category will be rejected by `record()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::{Observer, EventCategory};
    ///
    /// let mut observer = Observer::new();
    /// observer.disable_category(EventCategory::FileAccess);
    /// assert!(!observer.is_category_enabled(EventCategory::FileAccess));
    /// ```
    pub fn disable_category(&mut self, category: EventCategory) {
        warn!(category = category.as_str(), "learning category disabled");
        self.enabled_categories.remove(&category);
    }

    /// Whether a specific category is enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::{Observer, EventCategory};
    ///
    /// let observer = Observer::new();
    /// assert!(observer.is_category_enabled(EventCategory::AppLaunch));
    /// ```
    #[must_use]
    pub fn is_category_enabled(&self, category: EventCategory) -> bool {
        self.enabled_categories.contains(&category)
    }

    /// Number of enabled categories.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::Observer;
    ///
    /// let observer = Observer::new();
    /// assert_eq!(observer.enabled_category_count(), 5);
    /// ```
    #[must_use]
    pub fn enabled_category_count(&self) -> usize {
        self.enabled_categories.len()
    }

    /// Clear all buffered events (used by "Forget" purge).
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::{Observer, EventCategory, LearningEvent};
    ///
    /// let mut observer = Observer::new();
    /// let event = LearningEvent::new(EventCategory::AppLaunch, "app", None);
    /// observer.record(event).unwrap();
    /// observer.clear();
    /// assert_eq!(observer.event_count(), 0);
    /// ```
    pub fn clear(&mut self) {
        warn!("learning observer buffer cleared (Forget)");
        self.events.clear();
    }
}

impl Default for Observer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_observer_is_active() {
        let observer = Observer::new();
        assert!(observer.is_active());
        assert_eq!(observer.event_count(), 0);
        assert_eq!(observer.total_recorded(), 0);
        assert!(observer.show_indicator());
    }

    #[test]
    fn default_observer_all_categories_enabled() {
        let observer = Observer::default();
        assert_eq!(observer.enabled_category_count(), 5);
        for cat in EventCategory::all() {
            assert!(observer.is_category_enabled(*cat));
        }
    }

    #[test]
    fn record_increments_count() {
        let mut observer = Observer::new();
        let event = LearningEvent::new(EventCategory::AppLaunch, "firefox", None);
        observer.record(event).unwrap();
        assert_eq!(observer.event_count(), 1);
        assert_eq!(observer.total_recorded(), 1);
    }

    #[test]
    fn record_multiple_events() {
        let mut observer = Observer::new();
        for i in 0..10 {
            let event = LearningEvent::at_time(
                EventCategory::AppLaunch,
                &format!("app_{i}"),
                None,
                i,
            );
            observer.record(event).unwrap();
        }
        assert_eq!(observer.event_count(), 10);
        assert_eq!(observer.total_recorded(), 10);
    }

    #[test]
    fn pause_prevents_recording() {
        let mut observer = Observer::new();
        observer.pause();
        assert!(!observer.is_active());

        let event = LearningEvent::new(EventCategory::AppLaunch, "app", None);
        let result = observer.record(event);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), LearningError::ObserverPaused));
    }

    #[test]
    fn resume_allows_recording() {
        let mut observer = Observer::new();
        observer.pause();
        observer.resume();
        assert!(observer.is_active());

        let event = LearningEvent::new(EventCategory::AppLaunch, "app", None);
        observer.record(event).unwrap();
        assert_eq!(observer.event_count(), 1);
    }

    #[test]
    fn disabled_category_rejects_events() {
        let mut observer = Observer::new();
        observer.disable_category(EventCategory::FileAccess);

        let event = LearningEvent::new(EventCategory::FileAccess, "/path", None);
        let result = observer.record(event);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            LearningError::CategoryDisabled { .. }
        ));
    }

    #[test]
    fn enable_category_after_disable() {
        let mut observer = Observer::new();
        observer.disable_category(EventCategory::AiQuery);
        assert!(!observer.is_category_enabled(EventCategory::AiQuery));

        observer.enable_category(EventCategory::AiQuery);
        assert!(observer.is_category_enabled(EventCategory::AiQuery));

        let event = LearningEvent::new(EventCategory::AiQuery, "query", None);
        observer.record(event).unwrap();
    }

    #[test]
    fn batch_ready_at_threshold() {
        let mut observer = Observer::new();
        for i in 0..BATCH_SIZE {
            let event = LearningEvent::at_time(
                EventCategory::AppLaunch,
                "app",
                None,
                i as i64,
            );
            observer.record(event).unwrap();
        }
        assert!(observer.batch_ready());
    }

    #[test]
    fn batch_not_ready_below_threshold() {
        let mut observer = Observer::new();
        for i in 0..(BATCH_SIZE - 1) {
            let event = LearningEvent::at_time(
                EventCategory::AppLaunch,
                "app",
                None,
                i as i64,
            );
            observer.record(event).unwrap();
        }
        assert!(!observer.batch_ready());
    }

    #[test]
    fn drain_batch_clears_buffer() {
        let mut observer = Observer::new();
        for i in 0..10 {
            let event = LearningEvent::at_time(
                EventCategory::AppLaunch,
                "app",
                None,
                i,
            );
            observer.record(event).unwrap();
        }

        let batch = observer.drain_batch();
        assert_eq!(batch.len(), 10);
        assert_eq!(observer.event_count(), 0);
        // Total recorded is preserved.
        assert_eq!(observer.total_recorded(), 10);
    }

    #[test]
    fn clear_empties_buffer() {
        let mut observer = Observer::new();
        let event = LearningEvent::new(EventCategory::AppLaunch, "app", None);
        observer.record(event).unwrap();
        observer.clear();
        assert_eq!(observer.event_count(), 0);
    }

    #[test]
    fn indicator_off_when_paused() {
        let mut observer = Observer::new();
        assert!(observer.show_indicator());
        observer.pause();
        assert!(!observer.show_indicator());
    }

    #[test]
    fn indicator_can_be_disabled() {
        let mut observer = Observer::new();
        observer.set_show_indicator(false);
        assert!(!observer.show_indicator());
    }

    #[test]
    fn pause_preserves_buffer() {
        let mut observer = Observer::new();
        let event = LearningEvent::new(EventCategory::AppLaunch, "app", None);
        observer.record(event).unwrap();
        observer.pause();
        // Buffer should still have the event.
        assert_eq!(observer.event_count(), 1);
    }

    #[test]
    fn enabled_category_count_tracks_changes() {
        let mut observer = Observer::new();
        assert_eq!(observer.enabled_category_count(), 5);
        observer.disable_category(EventCategory::AppLaunch);
        assert_eq!(observer.enabled_category_count(), 4);
        observer.disable_category(EventCategory::FileAccess);
        assert_eq!(observer.enabled_category_count(), 3);
    }
}
