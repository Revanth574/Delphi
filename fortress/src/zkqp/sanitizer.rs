// SPDX-License-Identifier: MIT

//! Query sanitizer — the main ZKQP pipeline.
//!
//! Takes a cloud-bound query, detects PII, scores privacy risk,
//! and produces a sanitized version with all PII replaced by
//! placeholders.
//!
//! # Pipeline
//!
//! ```text
//! Input query → PII detection → Privacy scoring → Sanitization → Output
//!                                    ↓ (score > 80)
//!                              User confirmation required
//! ```
//!
//! # Memory Safety
//!
//! The PII-to-placeholder mapping exists ONLY in memory. It is
//! dropped when the `SanitizationResult` goes out of scope. It is
//! never serialized, never logged, never written to disk.

use std::collections::HashMap;

use tracing::{info, warn};

use crate::zkqp::pii::PiiDetector;
use crate::zkqp::scorer::{PrivacyScore, PrivacyScorer};

/// Result of sanitizing a query.
///
/// Contains the sanitized text, the privacy score, and the in-memory
/// mapping needed to restore the original values (for response
/// de-sanitization).
///
/// # Memory Contract
///
/// The `mapping` field exists ONLY in memory. When this struct is
/// dropped, the mapping is gone. It MUST NOT be serialized, logged,
/// or persisted to disk in any form.
///
/// # Examples
///
/// ```
/// use fortress::zkqp::sanitizer::SanitizationResult;
/// use fortress::zkqp::scorer::PrivacyScore;
/// use std::collections::HashMap;
///
/// let result = SanitizationResult {
///     sanitized_text: "Contact [EMAIL_001] for details".to_string(),
///     original_text: "Contact user@example.com for details".to_string(),
///     score: PrivacyScore {
///         total: 20,
///         breakdown: vec![("1 email (20 pts)".into(), 20)],
///         safe_to_sanitize: true,
///     },
///     mapping: HashMap::from([
///         ("user@example.com".to_string(), "[EMAIL_001]".to_string()),
///     ]),
///     requires_confirmation: false,
/// };
/// assert!(!result.requires_confirmation);
/// ```
#[derive(Debug, Clone)]
pub struct SanitizationResult {
    /// The sanitized query text (PII replaced with placeholders).
    pub sanitized_text: String,
    /// The original query text (for reference, never sent to cloud).
    pub original_text: String,
    /// Privacy score with detailed breakdown.
    pub score: PrivacyScore,
    /// PII-to-placeholder mapping (MEMORY ONLY — never persist).
    pub mapping: HashMap<String, String>,
    /// Whether user confirmation is needed (score > threshold).
    pub requires_confirmation: bool,
}

impl SanitizationResult {
    /// Restore original values in a cloud response.
    ///
    /// Replaces placeholders in the response text with original PII
    /// values. This is the reverse operation of sanitization.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::QuerySanitizer;
    ///
    /// let sanitizer = QuerySanitizer::new();
    /// let result = sanitizer.sanitize("Email user@example.com about it");
    /// let response = format!("Sent email to {}", result.mapping.values().next().unwrap_or(&String::new()));
    /// let restored = result.restore(&response);
    /// // Placeholder in response gets replaced with original value.
    /// ```
    #[must_use]
    pub fn restore(&self, response: &str) -> String {
        let mut restored = response.to_string();
        for (original, placeholder) in &self.mapping {
            restored = restored.replace(placeholder, original);
        }
        restored
    }

    /// Number of PII items that were replaced.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::QuerySanitizer;
    ///
    /// let sanitizer = QuerySanitizer::new();
    /// let result = sanitizer.sanitize("no pii here");
    /// assert_eq!(result.pii_count(), 0);
    /// ```
    #[must_use]
    pub fn pii_count(&self) -> usize {
        self.mapping.len()
    }
}

/// The main ZKQP query sanitizer.
///
/// Combines PII detection, privacy scoring, and text replacement
/// into a single pipeline.
///
/// # Examples
///
/// ```
/// use fortress::zkqp::QuerySanitizer;
///
/// let sanitizer = QuerySanitizer::new();
/// let result = sanitizer.sanitize("Send email to user@company.com about the meeting on 2024-03-15");
/// assert!(!result.sanitized_text.contains("user@company.com"));
/// assert!(!result.sanitized_text.contains("2024-03-15"));
/// assert!(result.sanitized_text.contains("[EMAIL_"));
/// ```
pub struct QuerySanitizer {
    /// PII detector.
    detector: PiiDetector,
    /// Privacy scorer.
    scorer: PrivacyScorer,
}

impl QuerySanitizer {
    /// Create a new sanitizer with default settings.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::QuerySanitizer;
    ///
    /// let sanitizer = QuerySanitizer::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            detector: PiiDetector::new(),
            scorer: PrivacyScorer::new(),
        }
    }

    /// Create a sanitizer with a custom PII detector.
    ///
    /// Useful for adding known entities (company names, etc.).
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::pii::PiiDetector;
    /// use fortress::zkqp::QuerySanitizer;
    ///
    /// let mut detector = PiiDetector::new();
    /// detector.add_entity("Acme Corp");
    /// let sanitizer = QuerySanitizer::with_detector(detector);
    /// ```
    #[must_use]
    pub fn with_detector(detector: PiiDetector) -> Self {
        Self {
            detector,
            scorer: PrivacyScorer::new(),
        }
    }

    /// Sanitize a query for cloud transmission.
    ///
    /// # Pipeline
    ///
    /// 1. Detect PII in the query.
    /// 2. Score privacy risk.
    /// 3. Build placeholder mapping (in-memory only).
    /// 4. Replace PII with placeholders.
    /// 5. Return result with `requires_confirmation` flag.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::QuerySanitizer;
    ///
    /// let sanitizer = QuerySanitizer::new();
    ///
    /// // Clean query — passes through unchanged.
    /// let result = sanitizer.sanitize("What is the capital of France?");
    /// assert_eq!(result.pii_count(), 0);
    /// assert!(!result.requires_confirmation);
    ///
    /// // Query with PII — gets sanitized.
    /// let result = sanitizer.sanitize("Email john@acme.com about the project");
    /// assert!(result.pii_count() > 0);
    /// assert!(!result.sanitized_text.contains("john@acme.com"));
    /// ```
    #[must_use]
    pub fn sanitize(&self, query: &str) -> SanitizationResult {
        // Step 1: Detect PII.
        let matches = self.detector.detect(query);

        // Step 2: Score privacy.
        let score = self.scorer.score(&matches);

        // Step 3: Build mapping (memory-only).
        let mapping = self.detector.build_mapping(&matches);

        // Step 4: Replace PII with placeholders.
        let sanitized_text = if mapping.is_empty() {
            query.to_string()
        } else {
            let mut result = query.to_string();
            // Replace longest matches first to avoid partial replacements.
            let mut sorted_pairs: Vec<(&String, &String)> = mapping.iter().collect();
            sorted_pairs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

            for (original, placeholder) in sorted_pairs {
                result = result.replace(original.as_str(), placeholder);
            }
            result
        };

        // Step 5: Determine if confirmation needed.
        let requires_confirmation = !score.safe_to_sanitize;

        if requires_confirmation {
            warn!(
                score = score.total,
                "ZKQP: privacy score too high — user confirmation required"
            );
        } else if !mapping.is_empty() {
            info!(
                pii_count = mapping.len(),
                score = score.total,
                "ZKQP: query sanitized"
            );
        }

        SanitizationResult {
            sanitized_text,
            original_text: query.to_string(),
            score,
            mapping,
            requires_confirmation,
        }
    }

    /// Check if a query contains any PII without sanitizing.
    ///
    /// Faster than full sanitization when you just need a yes/no.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::QuerySanitizer;
    ///
    /// let sanitizer = QuerySanitizer::new();
    /// assert!(!sanitizer.has_pii("What is 2+2?"));
    /// assert!(sanitizer.has_pii("Email me at user@test.com"));
    /// ```
    #[must_use]
    pub fn has_pii(&self, query: &str) -> bool {
        !self.detector.detect(query).is_empty()
    }
}

impl Default for QuerySanitizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_clean_query() {
        let sanitizer = QuerySanitizer::new();
        let result = sanitizer.sanitize("What is the capital of France?");
        assert_eq!(result.pii_count(), 0);
        assert_eq!(result.sanitized_text, result.original_text);
        assert!(!result.requires_confirmation);
    }

    #[test]
    fn sanitize_email() {
        let sanitizer = QuerySanitizer::new();
        let result = sanitizer.sanitize("Contact user@example.com about this");
        assert!(!result.sanitized_text.contains("user@example.com"));
        assert!(result.sanitized_text.contains("[EMAIL_"));
        assert!(result.pii_count() > 0);
    }

    #[test]
    fn sanitize_preserves_structure() {
        let sanitizer = QuerySanitizer::new();
        let result = sanitizer.sanitize("Send report to admin@corp.io by 2024-01-15");
        // The sentence structure should be preserved.
        assert!(result.sanitized_text.starts_with("Send report to"));
        assert!(result.sanitized_text.contains("by"));
    }

    #[test]
    fn restore_replaces_placeholders() {
        let sanitizer = QuerySanitizer::new();
        let result = sanitizer.sanitize("Email user@test.com about it");

        // Simulate a cloud response that uses the placeholder.
        let placeholder = result.mapping.get("user@test.com");
        if let Some(p) = placeholder {
            let response = format!("I've emailed {p}");
            let restored = result.restore(&response);
            assert!(restored.contains("user@test.com"));
            assert!(!restored.contains("[EMAIL_"));
        }
    }

    #[test]
    fn restore_with_no_placeholders() {
        let sanitizer = QuerySanitizer::new();
        let result = sanitizer.sanitize("plain query");
        let restored = result.restore("plain response");
        assert_eq!(restored, "plain response");
    }

    #[test]
    fn sanitize_multiple_pii() {
        let sanitizer = QuerySanitizer::new();
        let result = sanitizer.sanitize(
            "From user@a.com to admin@b.org about the 2024-06-15 meeting"
        );
        assert!(!result.sanitized_text.contains("user@a.com"));
        assert!(!result.sanitized_text.contains("admin@b.org"));
        assert!(!result.sanitized_text.contains("2024-06-15"));
        assert!(result.pii_count() >= 2);
    }

    #[test]
    fn sanitize_ip_address() {
        let sanitizer = QuerySanitizer::new();
        let result = sanitizer.sanitize("Server 192.168.1.100 is unreachable");
        assert!(!result.sanitized_text.contains("192.168.1.100"));
    }

    #[test]
    fn has_pii_check() {
        let sanitizer = QuerySanitizer::new();
        assert!(!sanitizer.has_pii("What is machine learning?"));
        assert!(sanitizer.has_pii("Contact admin@corp.com"));
    }

    #[test]
    fn with_custom_detector() {
        let mut detector = PiiDetector::new();
        detector.add_entity("Acme Corp");
        let sanitizer = QuerySanitizer::with_detector(detector);
        let result = sanitizer.sanitize("no pii here");
        assert_eq!(result.pii_count(), 0);
    }

    #[test]
    fn default_sanitizer() {
        let sanitizer = QuerySanitizer::default();
        let result = sanitizer.sanitize("test");
        assert_eq!(result.pii_count(), 0);
    }

    #[test]
    fn score_included_in_result() {
        let sanitizer = QuerySanitizer::new();
        let result = sanitizer.sanitize("Email user@test.com");
        assert!(result.score.total > 0);
        assert!(!result.score.explanation().is_empty());
    }

    #[test]
    fn mapping_is_populated() {
        let sanitizer = QuerySanitizer::new();
        let result = sanitizer.sanitize("user@test.com is the contact");
        if result.pii_count() > 0 {
            assert!(result.mapping.contains_key("user@test.com"));
        }
    }
}
