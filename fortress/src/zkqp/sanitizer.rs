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
/// Carries the sanitized text (safe to send to cloud), the privacy score,
/// the confirmation flag, AND the in-memory PII->placeholder mapping needed
/// to de-sanitize the cloud response.
///
/// # Structural memory contract (SVC-1)
///
/// This type is **the mapping-carrying capability**, and its API is
/// deliberately locked down so the mapping cannot be logged or outlive a
/// single request:
///
/// - **All fields are private.** External code reaches the safe parts via
///   accessors ([`sanitized_text`](Self::sanitized_text),
///   [`score`](Self::score), [`requires_confirmation`](Self::requires_confirmation),
///   [`pii_count`](Self::pii_count)). There is **no** accessor for `mapping`
///   — it is reachable only by [`restore`](Self::restore), which consumes it.
///   The raw original query is not retained at all.
/// - **No `Debug` and no `Clone`.** It cannot be `{:?}`-printed into a log
///   (so the mapping/original PII cannot leak via tracing — the 3A.5 F7
///   class) and cannot be duplicated to outlive its single use.
/// - **[`restore`](Self::restore) consumes `self`** (SVC-1 Adjustment 1):
///   once the cloud response is de-sanitized, the mapping is *structurally*
///   gone — "single use / does not outlive the request" is a type-level
///   guarantee, not a scope-discipline convention. The egress gateway owns
///   the result across the cloud `.await`, restores immediately, and drops
///   it; it is never stored on a long-lived struct.
///
/// # Examples
///
/// ```
/// use fortress::zkqp::QuerySanitizer;
///
/// let sanitizer = QuerySanitizer::new();
/// let result = sanitizer.sanitize("Contact user@example.com for details");
/// assert!(!result.sanitized_text().contains("user@example.com"));
/// assert!(result.pii_count() > 0);
/// assert!(!result.requires_confirmation());
/// ```
pub struct SanitizationResult {
    /// The sanitized query text (PII replaced with placeholders).
    sanitized_text: String,
    /// Privacy score with detailed breakdown.
    score: PrivacyScore,
    /// PII-to-placeholder mapping (MEMORY ONLY — never persist, never log).
    /// This is the ONLY field that retains PII-derived data; the raw
    /// original query is intentionally NOT stored (SVC-1 — minimal PII
    /// footprint), so the only way the originals leave this struct is via
    /// [`restore`](Self::restore), which consumes them.
    mapping: HashMap<String, String>,
    /// Whether user confirmation is needed (score > threshold).
    requires_confirmation: bool,
}

impl SanitizationResult {
    /// The sanitized text — PII replaced with placeholders. This is the
    /// only text that may cross the network boundary.
    #[must_use]
    pub fn sanitized_text(&self) -> &str {
        &self.sanitized_text
    }

    /// The privacy score for this query.
    #[must_use]
    pub fn score(&self) -> &PrivacyScore {
        &self.score
    }

    /// Whether the privacy score is high enough to require explicit user
    /// confirmation before sending (CLAUDE.md ZKQP rule 4).
    #[must_use]
    pub fn requires_confirmation(&self) -> bool {
        self.requires_confirmation
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

    /// Restore original PII values in a cloud response, **consuming** the
    /// mapping (SVC-1 Adjustment 1).
    ///
    /// Replaces placeholders in the response text with the original PII
    /// values. Taking `self` by value means the mapping is dropped the
    /// moment de-sanitization completes — it is structurally impossible to
    /// reuse the mapping or let it outlive this single call.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::QuerySanitizer;
    ///
    /// let sanitizer = QuerySanitizer::new();
    /// let result = sanitizer.sanitize("Email user@example.com about it");
    /// // A cloud response that echoes the placeholder from the sanitized text:
    /// let response = result.sanitized_text().to_string();
    /// let restored = result.restore(&response); // consumes `result`
    /// assert!(restored.contains("user@example.com"));
    /// assert!(!restored.contains("[EMAIL_"));
    /// ```
    #[must_use]
    pub fn restore(self, response: &str) -> String {
        let mut restored = response.to_string();
        for (original, placeholder) in &self.mapping {
            restored = restored.replace(placeholder, original);
        }
        restored
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
/// assert!(!result.sanitized_text().contains("user@company.com"));
/// assert!(!result.sanitized_text().contains("2024-03-15"));
/// assert!(result.sanitized_text().contains("[EMAIL_"));
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
    /// assert!(!result.requires_confirmation());
    ///
    /// // Query with PII — gets sanitized.
    /// let result = sanitizer.sanitize("Email john@acme.com about the project");
    /// assert!(result.pii_count() > 0);
    /// assert!(!result.sanitized_text().contains("john@acme.com"));
    /// ```
    #[must_use]
    pub fn sanitize(&self, query: &str) -> SanitizationResult {
        // Step 1: Detect PII.
        let matches = self.detector.detect(query);

        // Step 2: Score privacy.
        let score = self.scorer.score(&matches);

        // Step 3: Build mapping (memory-only). The query-bound token makes
        // placeholders collision-resistant against look-alikes in cloud responses
        // (FORT-R1-02), while staying deterministic for the same query.
        let mapping = self.detector.build_mapping(&matches, &query_token(query));

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

/// A short, deterministic, query-bound token mixed into every placeholder so a
/// literal placeholder-shaped string in a cloud response cannot collide with a
/// minted one (FORT-R1-02). Derived from `SHA-256(query)` — stateless and stable
/// for the same query, so sanitization stays deterministic for the cloud-egress
/// HMAC binding, and unguessable to the cloud (which never sees the query hash).
fn query_token(query: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(query.as_bytes());
    digest[..4].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_clean_query() {
        let sanitizer = QuerySanitizer::new();
        let result = sanitizer.sanitize("What is the capital of France?");
        assert_eq!(result.pii_count(), 0);
        // No PII -> the sanitized text is the original input verbatim
        // (original_text is now private; assert against the known input).
        assert_eq!(result.sanitized_text(), "What is the capital of France?");
        assert!(!result.requires_confirmation());
    }

    #[test]
    fn sanitize_email() {
        let sanitizer = QuerySanitizer::new();
        let result = sanitizer.sanitize("Contact user@example.com about this");
        assert!(!result.sanitized_text().contains("user@example.com"));
        assert!(result.sanitized_text().contains("[EMAIL_"));
        assert!(result.pii_count() > 0);
    }

    #[test]
    fn sanitize_preserves_structure() {
        let sanitizer = QuerySanitizer::new();
        let result = sanitizer.sanitize("Send report to admin@corp.io by 2024-01-15");
        // The sentence structure should be preserved.
        assert!(result.sanitized_text().starts_with("Send report to"));
        assert!(result.sanitized_text().contains("by"));
    }

    #[test]
    fn restore_replaces_placeholders() {
        let sanitizer = QuerySanitizer::new();
        let result = sanitizer.sanitize("Email user@test.com about it");
        assert!(result.pii_count() > 0, "email should be detected");

        // Simulate a cloud response that echoes the sanitized text (which
        // carries the placeholder). The mapping is private now, so we drive
        // restore through the sanitized_text rather than reading the map.
        let response = result.sanitized_text().to_string();
        let restored = result.restore(&response); // consumes `result`
        assert!(restored.contains("user@test.com"));
        assert!(!restored.contains("[EMAIL_"));
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
        assert!(!result.sanitized_text().contains("user@a.com"));
        assert!(!result.sanitized_text().contains("admin@b.org"));
        assert!(!result.sanitized_text().contains("2024-06-15"));
        assert!(result.pii_count() >= 2);
    }

    #[test]
    fn sanitize_ip_address() {
        let sanitizer = QuerySanitizer::new();
        let result = sanitizer.sanitize("Server 192.168.1.100 is unreachable");
        assert!(!result.sanitized_text().contains("192.168.1.100"));
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
        assert!(result.score().total > 0);
        assert!(!result.score().explanation().is_empty());
    }

    #[test]
    fn mapping_is_populated() {
        let sanitizer = QuerySanitizer::new();
        let result = sanitizer.sanitize("user@test.com is the contact");
        // The mapping is private (SVC-1). Prove it was populated indirectly:
        // the email is gone from the sanitized text, and restore() round-trips
        // it back from the (consumed) mapping.
        assert!(result.pii_count() > 0);
        assert!(!result.sanitized_text().contains("user@test.com"));
        let echoed = result.sanitized_text().to_string();
        let restored = result.restore(&echoed);
        assert!(restored.contains("user@test.com"));
    }

    /// SVC-1-R1-1 PRECONDITION: sanitization must be deterministic.
    ///
    /// The cloud-egress `ConfirmationToken` (die-inference) binds an HMAC to
    /// the sanitized text, so a confirmed retry re-sanitizes and re-checks the
    /// HMAC. That only works if `sanitize` is byte-stable for the same input:
    /// same input -> same `sanitized_text`, across repeated calls AND across
    /// fresh sanitizer instances (no per-instance state perturbs the
    /// placeholder assignment). If this ever fails, the token design is
    /// unsound and the non-determinism must be fixed before relying on it.
    #[test]
    fn sanitize_is_deterministic() {
        let input = "Email a@a.com and b@b.com from 10.0.0.1 on 2024-06-15";
        let s1 = QuerySanitizer::new().sanitize(input).sanitized_text().to_string();
        let s2 = QuerySanitizer::new().sanitize(input).sanitized_text().to_string();
        assert_eq!(s1, s2, "sanitization must be deterministic for token HMAC binding");

        // Also stable across repeated calls on the same instance.
        let sanitizer = QuerySanitizer::new();
        let a = sanitizer.sanitize(input).sanitized_text().to_string();
        let b = sanitizer.sanitize(input).sanitized_text().to_string();
        assert_eq!(a, b);
        assert_eq!(a, s1);
    }

    #[test]
    fn zkqp_detection_completeness_table_fort_r1_01() {
        // FORT-R1-01 (P1 LIVE): a false negative in ZKQP is a SILENT PII LEAK to
        // the cloud — the score reads clean, the send proceeds, raw PII egresses.
        // Each row carries PII of a CLAIMED-supported class in a valid-but-unusual
        // form; `canary` is a distinctive substring that MUST be redacted. This
        // single test reports the WHOLE table of leaks at once (it does NOT abort
        // on the first), so the full false-negative surface is visible in the RED
        // run before it is closed.
        let cases: &[(&str, &str, &str)] = &[
            // (input, leaked canary that must be redacted, axis)
            ("Contact johndoe+tag@example.com please", "johndoe", "email +atext (RFC 5322)"),
            ("Mail user.name+filter@mail.example now", "user.name", "email +atext (RFC 5322)"),
            ("See HTTPS://secret-host.example/p?k=v here", "secret-host.example", "URL scheme uppercase (RFC 3986)"),
            ("Visit HtTp://other.example/x now", "other.example", "URL scheme mixed case (RFC 3986)"),
            ("Host 8.8.8.8, is up", "8.8.8.8", "IPv4 trailing comma"),
            ("End at 8.8.4.4.", "8.8.4.4", "IPv4 trailing period"),
            ("Paren (1.2.3.4) here", "1.2.3.4", "IPv4 surrounding parens"),
            ("Call 555\u{00A0}867\u{00A0}5309 today", "5309", "phone NBSP separators"),
            ("Ring 555\u{202F}123\u{202F}4567 now", "4567", "phone narrow-NBSP separators"),
            ("Card 4111\u{00A0}1111\u{00A0}1111\u{00A0}1111 ok", "4111", "card NBSP separators"),
            ("Pay 4111\u{2011}1111\u{2011}1111\u{2011}1111 now", "4111", "card non-breaking-hyphen separators"),
            ("SSN 123\u{2011}45\u{2011}6789 filed", "6789", "SSN non-breaking-hyphen separators"),
            // Full-width digits (U+FF10..U+FF19): look like digits, but
            // is_ascii_digit() is false, so the digit scanners skipped them.
            (
                "Call \u{FF15}\u{FF15}\u{FF15}-\u{FF18}\u{FF16}\u{FF17}-\u{FF15}\u{FF13}\u{FF10}\u{FF19} today",
                "\u{FF15}\u{FF13}\u{FF10}\u{FF19}",
                "phone full-width digits",
            ),
            (
                "Card \u{FF14}\u{FF11}\u{FF11}\u{FF11} \u{FF11}\u{FF11}\u{FF11}\u{FF11} \u{FF11}\u{FF11}\u{FF11}\u{FF11} \u{FF11}\u{FF11}\u{FF11}\u{FF11} ok",
                "\u{FF14}\u{FF11}\u{FF11}\u{FF11}",
                "card full-width digits",
            ),
            (
                "SSN \u{FF11}\u{FF12}\u{FF13}-\u{FF14}\u{FF15}-\u{FF16}\u{FF17}\u{FF18}\u{FF19} filed",
                "\u{FF16}\u{FF17}\u{FF18}\u{FF19}",
                "SSN full-width digits",
            ),
            // FORT-R2-01: digits from OTHER Unicode scripts (General_Category =
            // Nd). Hand-enumerated ranges (ASCII, then +full-width) missed these
            // — the category, not another range, is the fix. Thai is the proof
            // row: a script never specifically enumerated anywhere in this file.
            (
                "Call \u{0665}\u{0665}\u{0665}-\u{0668}\u{0666}\u{0667}-\u{0665}\u{0663}\u{0660}\u{0669} today",
                "\u{0665}\u{0663}\u{0660}\u{0669}",
                "phone Arabic-Indic digits",
            ),
            (
                "Card \u{06F4}\u{06F1}\u{06F1}\u{06F1} \u{06F1}\u{06F1}\u{06F1}\u{06F1} \u{06F1}\u{06F1}\u{06F1}\u{06F1} \u{06F1}\u{06F1}\u{06F1}\u{06F1} ok",
                "\u{06F4}\u{06F1}\u{06F1}\u{06F1}",
                "card Extended-Arabic-Indic digits",
            ),
            (
                "SSN \u{0967}\u{0968}\u{0969}-\u{096A}\u{096B}-\u{096C}\u{096D}\u{096E}\u{096F} filed",
                "\u{096C}\u{096D}\u{096E}\u{096F}",
                "SSN Devanagari digits",
            ),
            (
                "Call \u{09E7}\u{09E8}\u{09E9}\u{09EA}\u{09EB}\u{09EC}\u{09ED}\u{09EE}\u{09EF}\u{09E6} now",
                "\u{09ED}\u{09EE}\u{09EF}\u{09E6}",
                "phone Bengali digits",
            ),
            (
                "Card \u{0E54}\u{0E51}\u{0E51}\u{0E51} \u{0E51}\u{0E51}\u{0E51}\u{0E51} \u{0E51}\u{0E51}\u{0E51}\u{0E51} \u{0E51}\u{0E51}\u{0E51}\u{0E51} ok",
                "\u{0E54}\u{0E51}\u{0E51}\u{0E51}",
                "card Thai digits (never-enumerated script)",
            ),
        ];
        let sanitizer = QuerySanitizer::new();
        let mut leaks = Vec::new();
        for &(input, canary, axis) in cases {
            let out = sanitizer.sanitize(input);
            if out.sanitized_text().contains(canary) {
                leaks.push(format!(
                    "  LEAK [{axis}]: {canary:?} survived -> {:?}",
                    out.sanitized_text()
                ));
            }
        }
        assert!(
            leaks.is_empty(),
            "ZKQP silent PII leaks: {} of {} variants egressed raw PII:\n{}",
            leaks.len(),
            cases.len(),
            leaks.join("\n")
        );
    }

    #[test]
    fn restore_ignores_response_lookalike_placeholders_fort_r1_02() {
        // FORT-R1-02: placeholders were predictable ([EMAIL_001]) and restore did
        // a global string replace, so a cloud RESPONSE containing a bare
        // [EMAIL_001] look-alike was rewritten to the original PII (re-injection).
        let sanitizer = QuerySanitizer::new();
        let result = sanitizer.sanitize("Contact alice@example.com please");
        // The cloud response echoes the (query-bound) minted placeholder AND also
        // contains a bare predictable-format look-alike the model emitted itself.
        let minted = result.sanitized_text().to_string();
        let response = format!("{minted} -- see also [EMAIL_001] in the archive");
        let restored = result.restore(&response);
        // The minted placeholder restores to the real email...
        assert!(
            restored.contains("alice@example.com"),
            "the minted placeholder must restore to the original"
        );
        // ...but the bare look-alike must survive untouched (no re-injection).
        // RED pre-fix: predictable [EMAIL_001] minted == the look-alike, so it was
        // rewritten to alice@example.com.
        assert!(
            restored.contains("[EMAIL_001]"),
            "a bare look-alike placeholder must NOT be rewritten to PII"
        );
    }
}
