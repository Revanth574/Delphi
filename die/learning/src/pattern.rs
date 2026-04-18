// SPDX-License-Identifier: MIT

//! Pattern types and detection logic.
//!
//! The learning engine recognizes 5 pattern types from observed events.
//! Detection runs every 50 events with a budget of < 200ms per CLAUDE.md
//! Section 9. All patterns are metadata-only — no file contents.
//!
//! # Pattern Types
//!
//! 1. **AppSequence** — apps launched in a repeated order
//! 2. **TimeBasedRoutine** — actions at consistent times of day
//! 3. **FileOrganization** — file move/rename with similar paths
//! 4. **QueryTemplate** — repeated similar AI queries
//! 5. **WorkSession** — co-occurring app+file sets

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::event::{EventCategory, LearningEvent};

/// Minimum occurrences before a pattern is considered significant.
const MIN_OCCURRENCES: u32 = 3;

/// Minimum confidence threshold for reporting a pattern.
const MIN_CONFIDENCE: f64 = 0.5;

/// Maximum sequence length to search for in app sequences.
const MAX_SEQUENCE_LEN: usize = 5;

/// A detected behavioral pattern.
///
/// # Examples
///
/// ```
/// use die_learning::pattern::{Pattern, PatternKind};
///
/// let pattern = Pattern {
///     kind: PatternKind::AppSequence {
///         apps: vec!["firefox".into(), "code".into()],
///     },
///     confidence: 0.85,
///     occurrences: 7,
///     description: "You often open Firefox then VS Code".to_string(),
/// };
/// assert!(pattern.is_significant());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    /// What type of pattern was detected.
    pub kind: PatternKind,
    /// Confidence score (0.0–1.0).
    pub confidence: f64,
    /// How many times this pattern was observed.
    pub occurrences: u32,
    /// Human-readable description for the suggestion.
    pub description: String,
}

impl Pattern {
    /// Whether this pattern meets the threshold for a suggestion.
    ///
    /// Requires both minimum occurrences and minimum confidence.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::pattern::{Pattern, PatternKind};
    ///
    /// let weak = Pattern {
    ///     kind: PatternKind::AppSequence { apps: vec!["app".into()] },
    ///     confidence: 0.3,
    ///     occurrences: 2,
    ///     description: "weak pattern".to_string(),
    /// };
    /// assert!(!weak.is_significant());
    ///
    /// let strong = Pattern {
    ///     kind: PatternKind::AppSequence { apps: vec!["app".into()] },
    ///     confidence: 0.8,
    ///     occurrences: 5,
    ///     description: "strong pattern".to_string(),
    /// };
    /// assert!(strong.is_significant());
    /// ```
    #[must_use]
    pub fn is_significant(&self) -> bool {
        self.occurrences >= MIN_OCCURRENCES && self.confidence >= MIN_CONFIDENCE
    }
}

/// The specific type of detected pattern.
///
/// # Examples
///
/// ```
/// use die_learning::pattern::PatternKind;
///
/// let kind = PatternKind::TimeBasedRoutine {
///     hour: 9,
///     action: "launch slack".to_string(),
/// };
/// assert!(matches!(kind, PatternKind::TimeBasedRoutine { .. }));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternKind {
    /// A sequence of apps launched in order.
    AppSequence {
        /// Ordered list of app identifiers.
        apps: Vec<String>,
    },

    /// An action that happens at a consistent time of day.
    TimeBasedRoutine {
        /// Hour of day (0–23, UTC).
        hour: u32,
        /// What action is performed.
        action: String,
    },

    /// A file organization pattern (move/rename to specific locations).
    FileOrganization {
        /// Source path pattern.
        source_pattern: String,
        /// Destination path pattern.
        dest_pattern: String,
    },

    /// A repeated AI query with similar structure.
    QueryTemplate {
        /// The template (common prefix/structure).
        template: String,
    },

    /// A set of apps/files that are opened together.
    WorkSession {
        /// Apps in this session.
        apps: Vec<String>,
        /// Files commonly opened.
        files: Vec<String>,
    },
}

/// Detect patterns in a batch of events.
///
/// Runs all 5 detectors and returns patterns that meet the
/// significance threshold.
///
/// # Performance
///
/// Must complete in < 200ms for 50 events per CLAUDE.md Section 9.
///
/// # Examples
///
/// ```
/// use die_learning::{LearningEvent, EventCategory};
/// use die_learning::pattern::detect_patterns;
///
/// let events: Vec<LearningEvent> = (0..10)
///     .flat_map(|i| {
///         vec![
///             LearningEvent::at_time(EventCategory::AppLaunch, "firefox", None, i * 100),
///             LearningEvent::at_time(EventCategory::AppLaunch, "code", None, i * 100 + 10),
///         ]
///     })
///     .collect();
///
/// let patterns = detect_patterns(&events);
/// // With 10 repetitions of firefox→code, should detect a sequence
/// assert!(!patterns.is_empty());
/// ```
#[must_use]
pub fn detect_patterns(events: &[LearningEvent]) -> Vec<Pattern> {
    let mut patterns = Vec::new();

    patterns.extend(detect_app_sequences(events));
    patterns.extend(detect_time_routines(events));
    patterns.extend(detect_file_organization(events));
    patterns.extend(detect_query_templates(events));
    patterns.extend(detect_work_sessions(events));

    // Only return significant patterns.
    patterns.retain(|p| p.is_significant());
    patterns
}

/// Detect repeated app launch sequences.
///
/// Uses a sliding window approach: for each window size 2..=MAX_SEQUENCE_LEN,
/// count how many times each subsequence appears.
///
/// # Examples
///
/// ```
/// use die_learning::{LearningEvent, EventCategory};
/// use die_learning::pattern::detect_app_sequences;
///
/// let events: Vec<LearningEvent> = (0..5)
///     .flat_map(|i| {
///         vec![
///             LearningEvent::at_time(EventCategory::AppLaunch, "term", None, i * 60),
///             LearningEvent::at_time(EventCategory::AppLaunch, "editor", None, i * 60 + 10),
///         ]
///     })
///     .collect();
///
/// let patterns = detect_app_sequences(&events);
/// assert!(patterns.iter().any(|p| p.occurrences >= 3));
/// ```
#[must_use]
pub fn detect_app_sequences(events: &[LearningEvent]) -> Vec<Pattern> {
    let app_events: Vec<&LearningEvent> = events
        .iter()
        .filter(|e| e.category == EventCategory::AppLaunch)
        .collect();

    if app_events.len() < 2 {
        return Vec::new();
    }

    let mut patterns = Vec::new();

    for window_size in 2..=MAX_SEQUENCE_LEN.min(app_events.len()) {
        let mut sequence_counts: HashMap<Vec<&str>, u32> = HashMap::new();

        for window in app_events.windows(window_size) {
            let seq: Vec<&str> = window.iter().map(|e| e.source.as_str()).collect();
            *sequence_counts.entry(seq).or_insert(0) += 1;
        }

        for (seq, count) in sequence_counts {
            if count >= MIN_OCCURRENCES {
                let apps: Vec<String> = seq.iter().map(|s| (*s).to_string()).collect();
                let confidence =
                    f64::from(count) / (app_events.len() - window_size + 1) as f64;
                let description = format!(
                    "You often launch {} in sequence",
                    apps.join(" → ")
                );

                patterns.push(Pattern {
                    kind: PatternKind::AppSequence { apps },
                    confidence,
                    occurrences: count,
                    description,
                });
            }
        }
    }

    patterns
}

/// Detect time-based routines.
///
/// Groups events by hour-of-day and finds actions that consistently
/// occur at the same hour.
///
/// # Examples
///
/// ```
/// use die_learning::{LearningEvent, EventCategory};
/// use die_learning::pattern::detect_time_routines;
///
/// // 5 events at 9am UTC (hour 9)
/// let events: Vec<LearningEvent> = (0..5)
///     .map(|day| {
///         // 9am UTC = 9 * 3600 = 32400 seconds into the day
///         let ts = day * 86400 + 32400;
///         LearningEvent::at_time(EventCategory::AppLaunch, "slack", None, ts)
///     })
///     .collect();
///
/// let patterns = detect_time_routines(&events);
/// assert!(patterns.iter().any(|p| p.occurrences >= 3));
/// ```
#[must_use]
pub fn detect_time_routines(events: &[LearningEvent]) -> Vec<Pattern> {
    // Group by (hour, source) → count.
    let mut hour_action_counts: HashMap<(u32, &str), u32> = HashMap::new();

    for event in events {
        let hour = event.hour_of_day();
        *hour_action_counts
            .entry((hour, &event.source))
            .or_insert(0) += 1;
    }

    let mut patterns = Vec::new();

    for ((hour, action), count) in &hour_action_counts {
        if *count >= MIN_OCCURRENCES {
            let confidence = f64::from(*count) / events.len() as f64;
            let description = format!(
                "You regularly run '{action}' around {hour}:00 UTC"
            );

            patterns.push(Pattern {
                kind: PatternKind::TimeBasedRoutine {
                    hour: *hour,
                    action: action.to_string(),
                },
                confidence: (confidence * 3.0).min(1.0), // Boost time patterns
                occurrences: *count,
                description,
            });
        }
    }

    patterns
}

/// Detect file organization patterns.
///
/// Looks for file move/rename events with similar source→destination
/// path structures.
///
/// # Examples
///
/// ```
/// use die_learning::{LearningEvent, EventCategory};
/// use die_learning::pattern::detect_file_organization;
///
/// let events: Vec<LearningEvent> = (0..4)
///     .map(|i| {
///         LearningEvent::with_metadata(
///             EventCategory::FileAccess,
///             &format!("/downloads/report_{i}.pdf"),
///             None,
///             &format!("/archive/reports/report_{i}.pdf"),
///         )
///     })
///     .collect();
///
/// let patterns = detect_file_organization(&events);
/// assert!(patterns.iter().any(|p| p.occurrences >= 3));
/// ```
#[must_use]
pub fn detect_file_organization(events: &[LearningEvent]) -> Vec<Pattern> {
    // Only look at file events that have metadata (source → dest moves).
    let move_events: Vec<&LearningEvent> = events
        .iter()
        .filter(|e| e.category == EventCategory::FileAccess && e.metadata.is_some())
        .collect();

    if move_events.len() < MIN_OCCURRENCES as usize {
        return Vec::new();
    }

    // Group by (source_dir, dest_dir) → count.
    let mut dir_pair_counts: HashMap<(&str, &str), u32> = HashMap::new();

    for event in &move_events {
        let source_dir = parent_dir(&event.source);
        let dest_dir = event
            .metadata
            .as_deref()
            .map(parent_dir)
            .unwrap_or("");

        if !source_dir.is_empty() && !dest_dir.is_empty() {
            *dir_pair_counts
                .entry((source_dir, dest_dir))
                .or_insert(0) += 1;
        }
    }

    let mut patterns = Vec::new();

    for ((source, dest), count) in &dir_pair_counts {
        if *count >= MIN_OCCURRENCES {
            let confidence = f64::from(*count) / move_events.len() as f64;
            let description = format!(
                "You often move files from {source} to {dest}"
            );

            patterns.push(Pattern {
                kind: PatternKind::FileOrganization {
                    source_pattern: source.to_string(),
                    dest_pattern: dest.to_string(),
                },
                confidence,
                occurrences: *count,
                description,
            });
        }
    }

    patterns
}

/// Detect repeated AI query templates.
///
/// Groups queries by their first word (intent keyword) and counts
/// repetitions.
///
/// # Examples
///
/// ```
/// use die_learning::{LearningEvent, EventCategory};
/// use die_learning::pattern::detect_query_templates;
///
/// let events: Vec<LearningEvent> = (0..5)
///     .map(|i| {
///         LearningEvent::at_time(
///             EventCategory::AiQuery,
///             &format!("summarize document_{i}.pdf"),
///             None,
///             i * 100,
///         )
///     })
///     .collect();
///
/// let patterns = detect_query_templates(&events);
/// assert!(patterns.iter().any(|p| p.occurrences >= 3));
/// ```
#[must_use]
pub fn detect_query_templates(events: &[LearningEvent]) -> Vec<Pattern> {
    let query_events: Vec<&LearningEvent> = events
        .iter()
        .filter(|e| e.category == EventCategory::AiQuery)
        .collect();

    if query_events.len() < MIN_OCCURRENCES as usize {
        return Vec::new();
    }

    // Group by first word (intent verb).
    let mut prefix_counts: HashMap<&str, u32> = HashMap::new();

    for event in &query_events {
        let prefix = event
            .source
            .split_whitespace()
            .next()
            .unwrap_or("");

        if !prefix.is_empty() {
            *prefix_counts.entry(prefix).or_insert(0) += 1;
        }
    }

    let mut patterns = Vec::new();

    for (prefix, count) in &prefix_counts {
        if *count >= MIN_OCCURRENCES {
            let confidence = f64::from(*count) / query_events.len() as f64;
            let description = format!(
                "You frequently ask queries starting with '{prefix}'"
            );

            patterns.push(Pattern {
                kind: PatternKind::QueryTemplate {
                    template: format!("{prefix} ..."),
                },
                confidence,
                occurrences: *count,
                description,
            });
        }
    }

    patterns
}

/// Detect work session patterns.
///
/// Identifies sets of apps that are frequently active within the same
/// time window (5-minute sessions).
///
/// # Examples
///
/// ```
/// use die_learning::{LearningEvent, EventCategory};
/// use die_learning::pattern::detect_work_sessions;
///
/// let events: Vec<LearningEvent> = (0..4)
///     .flat_map(|session| {
///         let base = session * 3600; // 1 hour apart
///         vec![
///             LearningEvent::at_time(EventCategory::AppLaunch, "code", None, base),
///             LearningEvent::at_time(EventCategory::AppLaunch, "terminal", None, base + 30),
///             LearningEvent::at_time(EventCategory::FileAccess, "/project/main.rs", None, base + 60),
///         ]
///     })
///     .collect();
///
/// let patterns = detect_work_sessions(&events);
/// // Should detect code+terminal as a work session
/// assert!(!patterns.is_empty());
/// ```
#[must_use]
pub fn detect_work_sessions(events: &[LearningEvent]) -> Vec<Pattern> {
    // Session window: 5 minutes.
    const SESSION_WINDOW_SECS: i64 = 300;

    if events.len() < MIN_OCCURRENCES as usize {
        return Vec::new();
    }

    // Split events into sessions based on time gaps.
    let mut sessions: Vec<Vec<&LearningEvent>> = Vec::new();
    let mut current_session: Vec<&LearningEvent> = Vec::new();

    let mut sorted_events: Vec<&LearningEvent> = events.iter().collect();
    sorted_events.sort_by_key(|e| e.timestamp);

    for event in sorted_events {
        if let Some(last) = current_session.last()
            && event.timestamp - last.timestamp > SESSION_WINDOW_SECS
        {
            if current_session.len() >= 2 {
                sessions.push(std::mem::take(&mut current_session));
            } else {
                current_session.clear();
            }
        }
        current_session.push(event);
    }
    if current_session.len() >= 2 {
        sessions.push(current_session);
    }

    // Count co-occurring app pairs across sessions.
    let mut pair_counts: HashMap<(String, String), u32> = HashMap::new();

    for session in &sessions {
        let apps: Vec<&str> = session
            .iter()
            .filter(|e| e.category == EventCategory::AppLaunch)
            .map(|e| e.source.as_str())
            .collect();

        // Deduplicate within session.
        let mut unique_apps: Vec<&str> = apps.clone();
        unique_apps.sort();
        unique_apps.dedup();

        for i in 0..unique_apps.len() {
            for j in (i + 1)..unique_apps.len() {
                let pair = (
                    unique_apps[i].to_string(),
                    unique_apps[j].to_string(),
                );
                *pair_counts.entry(pair).or_insert(0) += 1;
            }
        }
    }

    let mut patterns = Vec::new();

    for ((app_a, app_b), count) in &pair_counts {
        if *count >= MIN_OCCURRENCES {
            let confidence = f64::from(*count) / sessions.len().max(1) as f64;
            let description = format!(
                "You often use {app_a} and {app_b} together"
            );

            // Collect files from sessions where both apps appear.
            let mut session_files: Vec<String> = Vec::new();
            for session in &sessions {
                let session_apps: Vec<&str> = session
                    .iter()
                    .filter(|e| e.category == EventCategory::AppLaunch)
                    .map(|e| e.source.as_str())
                    .collect();

                if session_apps.contains(&app_a.as_str())
                    && session_apps.contains(&app_b.as_str())
                {
                    for e in session.iter().filter(|e| {
                        e.category == EventCategory::FileAccess
                    }) {
                        if !session_files.contains(&e.source) {
                            session_files.push(e.source.clone());
                        }
                    }
                }
            }
            session_files.truncate(5); // Keep top 5 files

            patterns.push(Pattern {
                kind: PatternKind::WorkSession {
                    apps: vec![app_a.clone(), app_b.clone()],
                    files: session_files,
                },
                confidence: confidence.min(1.0),
                occurrences: *count,
                description,
            });
        }
    }

    patterns
}

/// Extract parent directory from a path string.
fn parent_dir(path: &str) -> &str {
    match path.rfind('/') {
        Some(pos) => &path[..pos],
        None => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_significance_threshold() {
        let weak = Pattern {
            kind: PatternKind::AppSequence {
                apps: vec!["a".into()],
            },
            confidence: 0.3,
            occurrences: 2,
            description: "weak".to_string(),
        };
        assert!(!weak.is_significant());

        let strong = Pattern {
            kind: PatternKind::AppSequence {
                apps: vec!["a".into()],
            },
            confidence: 0.8,
            occurrences: 5,
            description: "strong".to_string(),
        };
        assert!(strong.is_significant());
    }

    #[test]
    fn significance_needs_both_thresholds() {
        // High confidence but low count.
        let high_conf = Pattern {
            kind: PatternKind::AppSequence {
                apps: vec!["a".into()],
            },
            confidence: 0.9,
            occurrences: 1,
            description: "test".to_string(),
        };
        assert!(!high_conf.is_significant());

        // High count but low confidence.
        let high_count = Pattern {
            kind: PatternKind::AppSequence {
                apps: vec!["a".into()],
            },
            confidence: 0.1,
            occurrences: 10,
            description: "test".to_string(),
        };
        assert!(!high_count.is_significant());
    }

    #[test]
    fn detect_app_sequence_basic() {
        let events: Vec<LearningEvent> = (0..5)
            .flat_map(|i| {
                vec![
                    LearningEvent::at_time(
                        EventCategory::AppLaunch,
                        "firefox",
                        None,
                        i * 60,
                    ),
                    LearningEvent::at_time(
                        EventCategory::AppLaunch,
                        "code",
                        None,
                        i * 60 + 10,
                    ),
                ]
            })
            .collect();

        let patterns = detect_app_sequences(&events);
        assert!(!patterns.is_empty());

        let seq_pattern = patterns
            .iter()
            .find(|p| matches!(&p.kind, PatternKind::AppSequence { apps } if apps.len() == 2));
        assert!(seq_pattern.is_some());
        assert!(seq_pattern.unwrap().occurrences >= 3);
    }

    #[test]
    fn detect_app_sequence_too_few_events() {
        let events = vec![LearningEvent::at_time(
            EventCategory::AppLaunch,
            "firefox",
            None,
            0,
        )];
        let patterns = detect_app_sequences(&events);
        assert!(patterns.is_empty());
    }

    #[test]
    fn detect_time_routine_basic() {
        // 5 events at 9am UTC across different days.
        let events: Vec<LearningEvent> = (0..5)
            .map(|day| {
                let ts = day * 86400 + 32400; // 9am UTC
                LearningEvent::at_time(EventCategory::AppLaunch, "slack", None, ts)
            })
            .collect();

        let patterns = detect_time_routines(&events);
        assert!(!patterns.is_empty());

        let time_pattern = patterns
            .iter()
            .find(|p| matches!(&p.kind, PatternKind::TimeBasedRoutine { hour: 9, .. }));
        assert!(time_pattern.is_some());
    }

    #[test]
    fn detect_time_routine_scattered_times() {
        // Events at different hours — no pattern.
        let events: Vec<LearningEvent> = (0..5)
            .map(|i| {
                let ts = i * 3600; // Each at a different hour
                LearningEvent::at_time(EventCategory::AppLaunch, "app", None, ts)
            })
            .collect();

        let patterns = detect_time_routines(&events);
        // Each hour has only 1 occurrence — below threshold.
        assert!(patterns.is_empty());
    }

    #[test]
    fn detect_file_organization_basic() {
        let events: Vec<LearningEvent> = (0..4)
            .map(|i| {
                LearningEvent::with_metadata(
                    EventCategory::FileAccess,
                    &format!("/downloads/file_{i}.pdf"),
                    None,
                    &format!("/archive/docs/file_{i}.pdf"),
                )
            })
            .collect();

        let patterns = detect_file_organization(&events);
        assert!(!patterns.is_empty());
        assert!(patterns[0].description.contains("/downloads"));
    }

    #[test]
    fn detect_file_organization_no_metadata() {
        let events: Vec<LearningEvent> = (0..5)
            .map(|i| {
                LearningEvent::at_time(
                    EventCategory::FileAccess,
                    &format!("/downloads/file_{i}"),
                    None,
                    i * 100,
                )
            })
            .collect();

        // No metadata = no move patterns.
        let patterns = detect_file_organization(&events);
        assert!(patterns.is_empty());
    }

    #[test]
    fn detect_query_template_basic() {
        let events: Vec<LearningEvent> = (0..5)
            .map(|i| {
                LearningEvent::at_time(
                    EventCategory::AiQuery,
                    &format!("summarize document_{i}.pdf"),
                    None,
                    i * 100,
                )
            })
            .collect();

        let patterns = detect_query_templates(&events);
        assert!(!patterns.is_empty());
        assert!(patterns[0].description.contains("summarize"));
    }

    #[test]
    fn detect_query_template_diverse_queries() {
        let events = vec![
            LearningEvent::at_time(EventCategory::AiQuery, "search docs", None, 0),
            LearningEvent::at_time(EventCategory::AiQuery, "translate text", None, 100),
            LearningEvent::at_time(EventCategory::AiQuery, "format code", None, 200),
        ];

        // Each prefix appears once — below threshold.
        let patterns = detect_query_templates(&events);
        assert!(patterns.is_empty());
    }

    #[test]
    fn detect_work_session_basic() {
        let events: Vec<LearningEvent> = (0..4)
            .flat_map(|session| {
                let base = session * 3600;
                vec![
                    LearningEvent::at_time(
                        EventCategory::AppLaunch,
                        "code",
                        None,
                        base,
                    ),
                    LearningEvent::at_time(
                        EventCategory::AppLaunch,
                        "terminal",
                        None,
                        base + 30,
                    ),
                    LearningEvent::at_time(
                        EventCategory::FileAccess,
                        "/project/main.rs",
                        None,
                        base + 60,
                    ),
                ]
            })
            .collect();

        let patterns = detect_work_sessions(&events);
        assert!(!patterns.is_empty());

        let session_pattern = patterns.iter().find(|p| {
            matches!(&p.kind, PatternKind::WorkSession { apps, .. } if apps.contains(&"code".to_string()))
        });
        assert!(session_pattern.is_some());
    }

    #[test]
    fn detect_work_session_no_overlap() {
        // Each app in a completely different time window.
        let events = vec![
            LearningEvent::at_time(EventCategory::AppLaunch, "app_a", None, 0),
            LearningEvent::at_time(EventCategory::AppLaunch, "app_b", None, 10000),
        ];

        let patterns = detect_work_sessions(&events);
        assert!(patterns.is_empty());
    }

    #[test]
    fn detect_patterns_integration() {
        // Mix of events that should produce at least one pattern.
        let events: Vec<LearningEvent> = (0..5)
            .flat_map(|i| {
                let base = i * 86400 + 32400; // 9am each day
                vec![
                    LearningEvent::at_time(
                        EventCategory::AppLaunch,
                        "firefox",
                        None,
                        base,
                    ),
                    LearningEvent::at_time(
                        EventCategory::AppLaunch,
                        "code",
                        None,
                        base + 30,
                    ),
                    LearningEvent::at_time(
                        EventCategory::AiQuery,
                        "summarize report",
                        None,
                        base + 120,
                    ),
                ]
            })
            .collect();

        let patterns = detect_patterns(&events);
        assert!(!patterns.is_empty());
        // All returned patterns should be significant.
        assert!(patterns.iter().all(|p| p.is_significant()));
    }

    #[test]
    fn detect_patterns_empty_events() {
        let patterns = detect_patterns(&[]);
        assert!(patterns.is_empty());
    }

    #[test]
    fn parent_dir_extraction() {
        assert_eq!(parent_dir("/home/user/file.txt"), "/home/user");
        assert_eq!(parent_dir("/root"), "");
        assert_eq!(parent_dir("file.txt"), "");
    }

    #[test]
    fn pattern_serialization_roundtrip() {
        let pattern = Pattern {
            kind: PatternKind::AppSequence {
                apps: vec!["firefox".into(), "code".into()],
            },
            confidence: 0.85,
            occurrences: 7,
            description: "test pattern".to_string(),
        };
        let json = serde_json::to_string(&pattern).unwrap();
        let deserialized: Pattern = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.occurrences, 7);
    }

    #[test]
    fn pattern_kind_variants() {
        // Verify all 5 variants can be constructed.
        let _seq = PatternKind::AppSequence {
            apps: vec!["a".into()],
        };
        let _time = PatternKind::TimeBasedRoutine {
            hour: 9,
            action: "test".to_string(),
        };
        let _file = PatternKind::FileOrganization {
            source_pattern: "/src".to_string(),
            dest_pattern: "/dst".to_string(),
        };
        let _query = PatternKind::QueryTemplate {
            template: "search ...".to_string(),
        };
        let _session = PatternKind::WorkSession {
            apps: vec!["a".into()],
            files: vec!["/f".into()],
        };
    }
}
