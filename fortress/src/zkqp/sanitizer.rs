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

use crate::zkqp::pii::{PiiDetector, PiiMatch};
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
    /// Per-instance random placeholder namespace (FORT-R2-02). Generated once at
    /// construction and STORED, so it is stable for this instance's lifetime
    /// (per-instance determinism = the SVC-1 retry binding holds) yet RANDOM
    /// across instances (unlinkable across sessions). It is NOT derived from any
    /// query, so the wire-visible placeholder leaks nothing about the query.
    namespace: String,
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
            namespace: random_namespace(),
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
            namespace: random_namespace(),
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

        // Step 3: Build mapping (memory-only). The per-instance namespace makes
        // placeholders collision-resistant against look-alikes in cloud responses
        // (FORT-R1-02) WITHOUT deriving any wire-visible value from the query
        // (FORT-R2-02); it is stable for this instance, so retry is deterministic.
        let mapping = self.detector.build_mapping(&matches, &self.namespace);

        // Step 4: Replace PII with placeholders by BYTE SPAN, single pass over
        // the ORIGINAL text (FORT-R2-03). Value-based global replace let a later
        // replacement land inside an already-minted placeholder (an entity named
        // "EMAIL" rewriting [EMAIL_<ns>_001]); span replacement appends
        // placeholders and never re-scans them.
        let sanitized_text = replace_spans(query, &matches, &mapping);

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

/// Replace every PII match with its placeholder by BYTE SPAN, in a single pass
/// over the ORIGINAL text (FORT-R2-03).
///
/// `matches` are start-sorted (`PiiDetector::detect`). Overlapping matches — a
/// URL containing an email, an SSN also matched as a phone — are absorbed into
/// one maximal cover interval whose placeholder is the FIRST match's (by start;
/// detect order breaks ties). Two properties hold by construction:
///
/// - **No placeholder corruption:** the output is built only from the original
///   text, and appended placeholders are never re-scanned, so no replacement can
///   land inside a minted placeholder (the value-based global-replace bug).
/// - **Coverage by something:** every byte of every match is inside an emitted
///   redaction, even under overlap — no PII byte survives.
///
/// All offsets are byte offsets the detectors produced via `char_indices`, so
/// the slices are always on char boundaries.
fn replace_spans(text: &str, matches: &[PiiMatch], mapping: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    let mut i = 0usize;
    while i < matches.len() {
        let m = &matches[i];
        if m.end <= cursor {
            i += 1;
            continue;
        }
        let Some(placeholder) = mapping.get(&m.value) else {
            i += 1;
            continue;
        };
        let interval_start = m.start.max(cursor);
        let mut interval_end = m.end;
        // Absorb later matches that overlap this (growing) interval.
        let mut j = i + 1;
        while j < matches.len() && matches[j].start < interval_end {
            interval_end = interval_end.max(matches[j].end);
            j += 1;
        }
        out.push_str(&text[cursor..interval_start]);
        out.push_str(placeholder);
        cursor = interval_end;
        i = j;
    }
    out.push_str(&text[cursor..]);
    out
}

/// Generate a fresh random placeholder namespace (8 hex chars) for a sanitizer
/// instance (FORT-R2-02).
///
/// The namespace's only jobs are to be UNGUESSABLE to the cloud (so a literal
/// placeholder-shaped string in a response cannot collide with a minted one —
/// FORT-R1-02) and STABLE for the instance (so a confirmed retry on the same
/// gateway re-sanitizes identically — the SVC-1 HMAC binding). It is
/// query-INDEPENDENT: the earlier `SHA-256(query)` derivation was wire-visible
/// and let the cloud link identical queries and offline-verify guessed PII; a
/// random, query-independent namespace removes that fingerprint.
fn random_namespace() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 4];
    rand::rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
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

    /// SVC-1-R1-1 PRECONDITION: sanitization is deterministic PER INSTANCE.
    ///
    /// The cloud-egress `ConfirmationToken` (die-inference) binds an HMAC to the
    /// sanitized text, so a confirmed retry re-sanitizes and re-checks the HMAC.
    /// The egress gateway holds ONE `QuerySanitizer` for its lifetime
    /// (`egress.rs`), so the original send and the retry re-sanitize on the SAME
    /// instance -> same `sanitized_text` -> the token re-verifies.
    ///
    /// Cross-INSTANCE determinism is deliberately NOT a property (FORT-R2-02): a
    /// query-derived, instance-stable token was a wire-visible fingerprint that
    /// let the cloud link identical queries / offline-verify guessed PII. The
    /// placeholder namespace is now a per-instance secret, so two instances
    /// differ by design. This is a CORRECTION of the contract the test encodes
    /// (per-instance is what SVC-1 actually needs), not a weakening of it.
    #[test]
    fn sanitize_is_deterministic_per_instance_fort_r2_02() {
        let input = "Email a@a.com and b@b.com from 10.0.0.1 on 2024-06-15";
        let sanitizer = QuerySanitizer::new();
        let a = sanitizer.sanitize(input).sanitized_text().to_string();
        let b = sanitizer.sanitize(input).sanitized_text().to_string();
        assert_eq!(a, b, "same instance must be byte-stable (SVC-1 retry binding)");
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

    #[test]
    fn identical_queries_are_unlinkable_across_instances_fort_r2_02() {
        // R2-02: the wire-visible placeholder token must not let the cloud
        // correlate identical queries across sessions. Pre-fix the token was
        // SHA-256(query)[..4], a keyless function of the query -> identical for
        // the same query in any instance -> linkable. RED pre-fix: p1 == p2.
        let input = "Contact alice@example.com please";
        let p1 = QuerySanitizer::new().sanitize(input).sanitized_text().to_string();
        let p2 = QuerySanitizer::new().sanitize(input).sanitized_text().to_string();
        assert_ne!(
            p1, p2,
            "identical queries must not yield correlatable placeholders across instances"
        );
    }

    #[test]
    fn placeholder_token_is_not_a_query_hash_fort_r2_02() {
        // R2-02: no offline verifier. Pre-fix the placeholder embedded
        // SHA-256(query)[..4] hex, which the cloud could recompute from a GUESSED
        // query to confirm the guess. RED pre-fix: the sanitized text contains it.
        use sha2::{Digest, Sha256};
        let input = "Contact alice@example.com please";
        let sanitized = QuerySanitizer::new().sanitize(input).sanitized_text().to_string();
        let leaked: String = Sha256::digest(input.as_bytes())[..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(
            !sanitized.contains(&leaked),
            "placeholder must not embed a query-derived hash the cloud can recompute"
        );
    }

    #[test]
    fn replacement_does_not_corrupt_minted_placeholders_fort_r2_03() {
        // FORT-R2-03: global String::replace over length-sorted values let a
        // known-entity named "EMAIL" replace INSIDE the minted [EMAIL_<ns>_001]
        // placeholder, destroying it. Span-based single-pass replacement builds
        // the output from the ORIGINAL text only, so nothing lands in a minted
        // placeholder.
        let mut detector = PiiDetector::new();
        detector.add_entity("EMAIL");
        let sanitizer = QuerySanitizer::with_detector(detector);
        let sanitized = sanitizer
            .sanitize("EMAIL alice@example.com please")
            .sanitized_text()
            .to_string();
        // Exactly one INTACT email placeholder. RED pre-fix: the entity "EMAIL"
        // replaced inside it, so the "[EMAIL_" count was 0 (corrupted).
        assert_eq!(
            sanitized.matches("[EMAIL_").count(),
            1,
            "the minted email placeholder must survive intact, got: {sanitized}"
        );
        assert!(!sanitized.contains("alice@example.com"), "email must be redacted");
    }

    #[test]
    fn overlapping_matches_are_fully_covered_fort_r2_03() {
        // Overlap-resolution rule: overlapping matches are absorbed into one
        // maximal cover interval (the first by start owns the placeholder; later
        // overlapping matches are absorbed). The property is coverage-by-
        // SOMETHING: every byte of every detected PII value is redacted even when
        // one detector's match sits inside another's (a URL containing an email).
        let sanitizer = QuerySanitizer::new();
        let input = "Visit https://host.example/u?cc=user@host.example now";
        let sanitized = sanitizer.sanitize(input).sanitized_text().to_string();
        assert!(
            !sanitized.contains("user@host.example"),
            "the embedded email must be covered, got: {sanitized}"
        );
        assert!(
            !sanitized.contains("host.example"),
            "the URL host must be covered, got: {sanitized}"
        );
    }
}
