// SPDX-License-Identifier: MIT

//! Event types for the learning observer.
//!
//! Events capture **metadata only** — never file contents, never user
//! input text, never sensitive data. This is a hard boundary per
//! CLAUDE.md Section 4:
//!
//! > The learning engine MUST NOT access file contents — it observes
//! > metadata only (app name, file path, timestamp, action type).

use serde::{Deserialize, Serialize};

/// Categories of observable events.
///
/// Users can disable individual categories. The observer **must not**
/// record events for disabled categories, even temporarily.
///
/// # Examples
///
/// ```
/// use die_learning::EventCategory;
///
/// let cat = EventCategory::AppLaunch;
/// assert_eq!(cat.as_str(), "app_launch");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventCategory {
    /// Application launched or focused.
    AppLaunch,
    /// File opened, moved, renamed, or deleted (path only).
    FileAccess,
    /// AI query submitted via command bar.
    AiQuery,
    /// UI mode changed (Direct, Assisted, Autonomous, Focus).
    ModeChange,
    /// Window created, closed, or resized.
    WindowManagement,
}

impl EventCategory {
    /// String representation for storage and display.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::EventCategory;
    ///
    /// assert_eq!(EventCategory::FileAccess.as_str(), "file_access");
    /// assert_eq!(EventCategory::AiQuery.as_str(), "ai_query");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AppLaunch => "app_launch",
            Self::FileAccess => "file_access",
            Self::AiQuery => "ai_query",
            Self::ModeChange => "mode_change",
            Self::WindowManagement => "window_management",
        }
    }

    /// All defined categories.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::EventCategory;
    ///
    /// assert_eq!(EventCategory::all().len(), 5);
    /// ```
    #[must_use]
    pub fn all() -> &'static [EventCategory] {
        &[
            Self::AppLaunch,
            Self::FileAccess,
            Self::AiQuery,
            Self::ModeChange,
            Self::WindowManagement,
        ]
    }
}

/// A single observed event (metadata only).
///
/// Events are the atomic unit of observation. The learning engine
/// collects these and analyzes them in batches of 50 for pattern
/// detection.
///
/// # Examples
///
/// ```
/// use die_learning::{LearningEvent, EventCategory};
///
/// let event = LearningEvent::new(
///     EventCategory::AppLaunch,
///     "firefox",
///     Some("win-001"),
/// );
/// assert_eq!(event.category, EventCategory::AppLaunch);
/// assert_eq!(event.source, "firefox");
/// assert!(event.timestamp > 0);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningEvent {
    /// Event category.
    pub category: EventCategory,
    /// Source identifier (app name, file path, query hash — never raw content).
    pub source: String,
    /// Optional window identifier.
    pub window_id: Option<String>,
    /// Optional secondary data (e.g., target path for file move).
    pub metadata: Option<String>,
    /// Unix timestamp (seconds since epoch, UTC).
    pub timestamp: i64,
}

impl LearningEvent {
    /// Create a new event with the current timestamp.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::{LearningEvent, EventCategory};
    ///
    /// let event = LearningEvent::new(
    ///     EventCategory::FileAccess,
    ///     "/home/user/report.pdf",
    ///     None,
    /// );
    /// assert_eq!(event.category, EventCategory::FileAccess);
    /// ```
    #[must_use]
    pub fn new(category: EventCategory, source: &str, window_id: Option<&str>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        Self {
            category,
            source: source.to_string(),
            window_id: window_id.map(String::from),
            metadata: None,
            timestamp,
        }
    }

    /// Create a new event with metadata.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::{LearningEvent, EventCategory};
    ///
    /// let event = LearningEvent::with_metadata(
    ///     EventCategory::FileAccess,
    ///     "/home/user/report.pdf",
    ///     None,
    ///     "/home/user/archive/report.pdf",
    /// );
    /// assert_eq!(event.metadata.as_deref(), Some("/home/user/archive/report.pdf"));
    /// ```
    #[must_use]
    pub fn with_metadata(
        category: EventCategory,
        source: &str,
        window_id: Option<&str>,
        metadata: &str,
    ) -> Self {
        let mut event = Self::new(category, source, window_id);
        event.metadata = Some(metadata.to_string());
        event
    }

    /// Create an event with a specific timestamp (for testing/replay).
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::{LearningEvent, EventCategory};
    ///
    /// let event = LearningEvent::at_time(
    ///     EventCategory::AppLaunch,
    ///     "code",
    ///     None,
    ///     1700000000,
    /// );
    /// assert_eq!(event.timestamp, 1700000000);
    /// ```
    #[must_use]
    pub fn at_time(
        category: EventCategory,
        source: &str,
        window_id: Option<&str>,
        timestamp: i64,
    ) -> Self {
        Self {
            category,
            source: source.to_string(),
            window_id: window_id.map(String::from),
            metadata: None,
            timestamp,
        }
    }

    /// Hour of day (0–23) extracted from the timestamp.
    ///
    /// Used by time-based pattern detection. Assumes UTC.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::{LearningEvent, EventCategory};
    ///
    /// // 1700000000 = 2023-11-14 22:13:20 UTC
    /// let event = LearningEvent::at_time(
    ///     EventCategory::AppLaunch,
    ///     "app",
    ///     None,
    ///     1700000000,
    /// );
    /// assert_eq!(event.hour_of_day(), 22);
    /// ```
    #[must_use]
    pub fn hour_of_day(&self) -> u32 {
        // Seconds into the day, UTC.
        let secs_into_day = self.timestamp.rem_euclid(86400) as u32;
        secs_into_day / 3600
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_category_as_str() {
        assert_eq!(EventCategory::AppLaunch.as_str(), "app_launch");
        assert_eq!(EventCategory::FileAccess.as_str(), "file_access");
        assert_eq!(EventCategory::AiQuery.as_str(), "ai_query");
        assert_eq!(EventCategory::ModeChange.as_str(), "mode_change");
        assert_eq!(EventCategory::WindowManagement.as_str(), "window_management");
    }

    #[test]
    fn all_categories_count() {
        assert_eq!(EventCategory::all().len(), 5);
    }

    #[test]
    fn event_new_has_timestamp() {
        let event = LearningEvent::new(EventCategory::AppLaunch, "firefox", None);
        assert!(event.timestamp > 0);
        assert_eq!(event.category, EventCategory::AppLaunch);
        assert_eq!(event.source, "firefox");
        assert!(event.window_id.is_none());
        assert!(event.metadata.is_none());
    }

    #[test]
    fn event_with_window_id() {
        let event = LearningEvent::new(EventCategory::AppLaunch, "code", Some("win-42"));
        assert_eq!(event.window_id.as_deref(), Some("win-42"));
    }

    #[test]
    fn event_with_metadata() {
        let event = LearningEvent::with_metadata(
            EventCategory::FileAccess,
            "/src/main.rs",
            None,
            "/archive/main.rs",
        );
        assert_eq!(event.metadata.as_deref(), Some("/archive/main.rs"));
    }

    #[test]
    fn event_at_time() {
        let event = LearningEvent::at_time(EventCategory::AiQuery, "search", None, 1700000000);
        assert_eq!(event.timestamp, 1700000000);
    }

    #[test]
    fn hour_of_day_extraction() {
        // 1700000000 = 2023-11-14 22:13:20 UTC
        let event =
            LearningEvent::at_time(EventCategory::AppLaunch, "app", None, 1700000000);
        assert_eq!(event.hour_of_day(), 22);
    }

    #[test]
    fn hour_of_day_midnight() {
        // Midnight UTC = timestamp divisible by 86400
        let event = LearningEvent::at_time(EventCategory::AppLaunch, "app", None, 86400);
        assert_eq!(event.hour_of_day(), 0);
    }

    #[test]
    fn hour_of_day_noon() {
        // Noon UTC = 12 * 3600 = 43200 seconds into the day
        let event =
            LearningEvent::at_time(EventCategory::AppLaunch, "app", None, 86400 + 43200);
        assert_eq!(event.hour_of_day(), 12);
    }

    #[test]
    fn event_serialization_roundtrip() {
        let event = LearningEvent::with_metadata(
            EventCategory::FileAccess,
            "/home/user/doc.txt",
            Some("win-1"),
            "/archive/doc.txt",
        );
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: LearningEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.source, event.source);
        assert_eq!(deserialized.category, event.category);
        assert_eq!(deserialized.metadata, event.metadata);
    }

    #[test]
    fn category_serialization() {
        let cat = EventCategory::AiQuery;
        let json = serde_json::to_string(&cat).unwrap();
        let deserialized: EventCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, cat);
    }
}
