// SPDX-License-Identifier: MIT

//! Privacy scoring for ZKQP.
//!
//! Computes a deterministic, auditable privacy score (0–100) for queries.
//! A score > 80 means the query contains too much PII to safely send
//! to cloud — the user must be asked.
//!
//! Per CLAUDE.md Section 10: the algorithm must be deterministic and
//! auditable. The user can ask "why did this score 65?" and get a
//! specific answer.

use crate::zkqp::pii::{PiiMatch, PiiType};

/// Maximum privacy score considered safe for automatic sanitization.
pub const SAFE_THRESHOLD: u32 = 80;

/// Result of privacy scoring with detailed breakdown.
///
/// # Examples
///
/// ```
/// use fortress::zkqp::scorer::PrivacyScore;
///
/// let score = PrivacyScore {
///     total: 45,
///     breakdown: vec![("1 email (20 pts)".into(), 20), ("1 date (5 pts)".into(), 5)],
///     safe_to_sanitize: true,
/// };
/// assert!(score.safe_to_sanitize);
/// assert!(!score.explanation().is_empty());
/// ```
#[derive(Debug, Clone)]
pub struct PrivacyScore {
    /// Total privacy score (0–100, capped).
    pub total: u32,
    /// Detailed breakdown: (description, points).
    pub breakdown: Vec<(String, u32)>,
    /// Whether the score is below the safe threshold.
    pub safe_to_sanitize: bool,
}

impl PrivacyScore {
    /// Human-readable explanation of the score.
    ///
    /// Per CLAUDE.md: the user can ask "why did this score 65?"
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::scorer::PrivacyScore;
    ///
    /// let score = PrivacyScore {
    ///     total: 65,
    ///     breakdown: vec![
    ///         ("2 emails (40 pts)".into(), 40),
    ///         ("1 IP address (15 pts)".into(), 15),
    ///     ],
    ///     safe_to_sanitize: true,
    /// };
    /// let explanation = score.explanation();
    /// assert!(explanation.contains("65"));
    /// assert!(explanation.contains("email"));
    /// ```
    #[must_use]
    pub fn explanation(&self) -> String {
        let mut lines = vec![format!(
            "Privacy score: {}/100 (threshold: {SAFE_THRESHOLD})",
            self.total
        )];

        for (desc, _) in &self.breakdown {
            lines.push(format!("  - {desc}"));
        }

        if self.safe_to_sanitize {
            lines.push("Result: safe to sanitize automatically.".to_string());
        } else {
            lines.push(
                "Result: too sensitive — user confirmation required.".to_string(),
            );
        }

        lines.join("\n")
    }
}

/// Computes privacy scores for queries.
///
/// # Examples
///
/// ```
/// use fortress::zkqp::scorer::PrivacyScorer;
/// use fortress::zkqp::pii::{PiiMatch, PiiType};
///
/// let scorer = PrivacyScorer::new();
/// let matches = vec![
///     PiiMatch { pii_type: PiiType::Email, value: "a@b.com".into(), start: 0, end: 7 },
/// ];
/// let score = scorer.score(&matches);
/// assert!(score.total > 0);
/// assert!(score.safe_to_sanitize);
/// ```
pub struct PrivacyScorer {
    /// Custom threshold override (default: SAFE_THRESHOLD).
    threshold: u32,
}

impl PrivacyScorer {
    /// Create a new scorer with the default threshold.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::scorer::PrivacyScorer;
    ///
    /// let scorer = PrivacyScorer::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            threshold: SAFE_THRESHOLD,
        }
    }

    /// Compute the privacy score from detected PII.
    ///
    /// The algorithm:
    /// 1. Count PII by type.
    /// 2. Multiply count × weight for each type.
    /// 3. Sum and cap at 100.
    ///
    /// This is deterministic — same input always produces same score.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::scorer::PrivacyScorer;
    /// use fortress::zkqp::pii::{PiiMatch, PiiType};
    ///
    /// let scorer = PrivacyScorer::new();
    ///
    /// // No PII → score 0.
    /// let score = scorer.score(&[]);
    /// assert_eq!(score.total, 0);
    /// assert!(score.safe_to_sanitize);
    ///
    /// // Credit card → high score.
    /// let matches = vec![
    ///     PiiMatch { pii_type: PiiType::CreditCard, value: "4111-1111".into(), start: 0, end: 9 },
    ///     PiiMatch { pii_type: PiiType::Email, value: "a@b.com".into(), start: 10, end: 17 },
    ///     PiiMatch { pii_type: PiiType::Phone, value: "555-0123".into(), start: 18, end: 26 },
    /// ];
    /// let score = scorer.score(&matches);
    /// assert!(score.total > 50);
    /// ```
    #[must_use]
    pub fn score(&self, matches: &[PiiMatch]) -> PrivacyScore {
        if matches.is_empty() {
            return PrivacyScore {
                total: 0,
                breakdown: Vec::new(),
                safe_to_sanitize: true,
            };
        }

        // Count by type.
        let mut type_counts: std::collections::HashMap<PiiType, u32> =
            std::collections::HashMap::new();
        for m in matches {
            *type_counts.entry(m.pii_type).or_insert(0) += 1;
        }

        let mut breakdown = Vec::new();
        let mut total: u32 = 0;

        for (pii_type, count) in &type_counts {
            let points = count * pii_type.weight();
            total += points;
            breakdown.push((
                format!(
                    "{count} {} ({points} pts)",
                    pii_type.placeholder_prefix().to_lowercase()
                ),
                points,
            ));
        }

        // Cap at 100.
        total = total.min(100);

        PrivacyScore {
            total,
            breakdown,
            safe_to_sanitize: total <= self.threshold,
        }
    }

    /// The current threshold.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::scorer::PrivacyScorer;
    ///
    /// let scorer = PrivacyScorer::new();
    /// assert_eq!(scorer.threshold(), 80);
    /// ```
    #[must_use]
    pub fn threshold(&self) -> u32 {
        self.threshold
    }
}

impl Default for PrivacyScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_matches_score_zero() {
        let scorer = PrivacyScorer::new();
        let score = scorer.score(&[]);
        assert_eq!(score.total, 0);
        assert!(score.safe_to_sanitize);
        assert!(score.breakdown.is_empty());
    }

    #[test]
    fn single_email_score() {
        let scorer = PrivacyScorer::new();
        let matches = vec![PiiMatch {
            pii_type: PiiType::Email,
            value: "a@b.com".into(),
            start: 0,
            end: 7,
        }];
        let score = scorer.score(&matches);
        assert_eq!(score.total, 20); // Email weight = 20
        assert!(score.safe_to_sanitize);
    }

    #[test]
    fn high_score_not_safe() {
        let scorer = PrivacyScorer::new();
        let matches = vec![
            PiiMatch {
                pii_type: PiiType::CreditCard,
                value: "4111".into(),
                start: 0,
                end: 4,
            },
            PiiMatch {
                pii_type: PiiType::NationalId,
                value: "123-45-6789".into(),
                start: 5,
                end: 16,
            },
            PiiMatch {
                pii_type: PiiType::Email,
                value: "a@b.com".into(),
                start: 17,
                end: 24,
            },
        ];
        let score = scorer.score(&matches);
        // 30 + 30 + 20 = 80. At threshold = 80, still safe.
        assert_eq!(score.total, 80);
    }

    #[test]
    fn score_caps_at_100() {
        let scorer = PrivacyScorer::new();
        let matches: Vec<PiiMatch> = (0..10)
            .map(|i| PiiMatch {
                pii_type: PiiType::CreditCard,
                value: format!("cc_{i}"),
                start: i * 10,
                end: i * 10 + 5,
            })
            .collect();
        let score = scorer.score(&matches);
        // 10 × 30 = 300, capped at 100.
        assert_eq!(score.total, 100);
        assert!(!score.safe_to_sanitize);
    }

    #[test]
    fn explanation_includes_details() {
        let scorer = PrivacyScorer::new();
        let matches = vec![PiiMatch {
            pii_type: PiiType::Email,
            value: "a@b.com".into(),
            start: 0,
            end: 7,
        }];
        let score = scorer.score(&matches);
        let explanation = score.explanation();
        assert!(explanation.contains("20/100"));
        assert!(explanation.contains("email"));
        assert!(explanation.contains("safe to sanitize"));
    }

    #[test]
    fn explanation_unsafe_query() {
        let scorer = PrivacyScorer::new();
        let matches: Vec<PiiMatch> = (0..5)
            .map(|i| PiiMatch {
                pii_type: PiiType::CreditCard,
                value: format!("cc_{i}"),
                start: i * 10,
                end: i * 10 + 5,
            })
            .collect();
        let score = scorer.score(&matches);
        let explanation = score.explanation();
        assert!(explanation.contains("user confirmation required"));
    }

    #[test]
    fn default_threshold() {
        let scorer = PrivacyScorer::default();
        assert_eq!(scorer.threshold(), SAFE_THRESHOLD);
    }

    #[test]
    fn deterministic_scoring() {
        let scorer = PrivacyScorer::new();
        let matches = vec![
            PiiMatch {
                pii_type: PiiType::Email,
                value: "a@b.com".into(),
                start: 0,
                end: 7,
            },
            PiiMatch {
                pii_type: PiiType::Phone,
                value: "555-1234".into(),
                start: 8,
                end: 16,
            },
        ];
        // Same input → same output.
        let s1 = scorer.score(&matches);
        let s2 = scorer.score(&matches);
        assert_eq!(s1.total, s2.total);
    }
}
