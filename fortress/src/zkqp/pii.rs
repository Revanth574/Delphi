// SPDX-License-Identifier: MIT

//! PII (Personally Identifiable Information) detection.
//!
//! Detects and categorizes PII in text using regex patterns. Per CLAUDE.md
//! Section 10, the regex set must cover: email addresses, phone numbers,
//! physical addresses, IP addresses, full names, project/company names,
//! geographic locations, dates that could identify events.

use std::collections::HashMap;

/// Types of PII that can be detected.
///
/// # Examples
///
/// ```
/// use fortress::zkqp::pii::PiiType;
///
/// let t = PiiType::Email;
/// assert_eq!(t.placeholder_prefix(), "EMAIL");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PiiType {
    /// Email address (user@domain.tld).
    Email,
    /// Phone number (various formats).
    Phone,
    /// IP address (IPv4 or IPv6).
    IpAddress,
    /// Date that could identify an event.
    Date,
    /// URL containing path/query information.
    Url,
    /// Social security or national ID number.
    NationalId,
    /// Credit card number.
    CreditCard,
}

impl PiiType {
    /// Prefix used in placeholder replacements.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::pii::PiiType;
    ///
    /// assert_eq!(PiiType::Phone.placeholder_prefix(), "PHONE");
    /// ```
    #[must_use]
    pub fn placeholder_prefix(&self) -> &'static str {
        match self {
            Self::Email => "EMAIL",
            Self::Phone => "PHONE",
            Self::IpAddress => "IP",
            Self::Date => "DATE",
            Self::Url => "URL",
            Self::NationalId => "ID",
            Self::CreditCard => "CC",
        }
    }

    /// Privacy weight for scoring (higher = more sensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::pii::PiiType;
    ///
    /// assert!(PiiType::CreditCard.weight() > PiiType::Date.weight());
    /// ```
    #[must_use]
    pub fn weight(&self) -> u32 {
        match self {
            Self::CreditCard => 30,
            Self::NationalId => 30,
            Self::Email => 20,
            Self::Phone => 20,
            Self::IpAddress => 15,
            Self::Url => 10,
            Self::Date => 5,
        }
    }
}

/// A detected PII occurrence in text.
///
/// # Examples
///
/// ```
/// use fortress::zkqp::pii::{PiiMatch, PiiType};
///
/// let m = PiiMatch {
///     pii_type: PiiType::Email,
///     value: "user@example.com".to_string(),
///     start: 10,
///     end: 26,
/// };
/// assert_eq!(m.len(), 16);
/// ```
#[derive(Debug, Clone)]
pub struct PiiMatch {
    /// Type of PII detected.
    pub pii_type: PiiType,
    /// The matched text.
    pub value: String,
    /// Start byte offset in the original text.
    pub start: usize,
    /// End byte offset in the original text.
    pub end: usize,
}

impl PiiMatch {
    /// Length of the matched text.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::pii::{PiiMatch, PiiType};
    ///
    /// let m = PiiMatch {
    ///     pii_type: PiiType::Phone,
    ///     value: "+1-555-0123".to_string(),
    ///     start: 0,
    ///     end: 11,
    /// };
    /// assert_eq!(m.len(), 11);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the match is empty (shouldn't happen, but for completeness).
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::pii::{PiiMatch, PiiType};
    ///
    /// let m = PiiMatch {
    ///     pii_type: PiiType::Email,
    ///     value: "a@b.c".to_string(),
    ///     start: 0,
    ///     end: 5,
    /// };
    /// assert!(!m.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// Detects PII in text using pattern matching.
///
/// Uses simple substring/pattern matching for each PII type. A full
/// implementation would use compiled regex patterns for performance.
///
/// # Examples
///
/// ```
/// use fortress::zkqp::PiiDetector;
///
/// let detector = PiiDetector::new();
/// let matches = detector.detect("Contact me at user@example.com");
/// assert!(!matches.is_empty());
/// assert!(matches.iter().any(|m| m.pii_type == fortress::zkqp::pii::PiiType::Email));
/// ```
pub struct PiiDetector {
    /// Known entity names (company, project names) to detect.
    known_entities: Vec<String>,
}

impl PiiDetector {
    /// Create a new detector with no known entities.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::PiiDetector;
    ///
    /// let detector = PiiDetector::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            known_entities: Vec::new(),
        }
    }

    /// Add a known entity name for detection.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::PiiDetector;
    ///
    /// let mut detector = PiiDetector::new();
    /// detector.add_entity("Acme Corp");
    /// ```
    pub fn add_entity(&mut self, name: &str) {
        self.known_entities.push(name.to_string());
    }

    /// Detect all PII occurrences in text.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::PiiDetector;
    ///
    /// let detector = PiiDetector::new();
    /// let text = "Email john@acme.com or call 555-0123";
    /// let matches = detector.detect(text);
    /// assert!(matches.len() >= 2);
    /// ```
    #[must_use]
    pub fn detect(&self, text: &str) -> Vec<PiiMatch> {
        let mut matches = Vec::new();

        matches.extend(self.detect_emails(text));
        // National IDs before phones: an SSN's 9 digits also satisfy the phone
        // heuristic, so detect it first to win the placeholder classification.
        matches.extend(self.detect_national_ids(text));
        matches.extend(self.detect_phones(text));
        matches.extend(self.detect_ips(text));
        matches.extend(self.detect_dates(text));
        matches.extend(self.detect_urls(text));
        matches.extend(self.detect_credit_cards(text));

        // Sort by position for consistent replacement order.
        matches.sort_by_key(|m| m.start);
        matches
    }

    /// Count of detected PII items.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::PiiDetector;
    ///
    /// let detector = PiiDetector::new();
    /// assert_eq!(detector.detect("no pii here").len(), 0);
    /// ```
    #[must_use]
    pub fn count_pii(&self, text: &str) -> usize {
        self.detect(text).len()
    }

    /// Detect email addresses.
    fn detect_emails(&self, text: &str) -> Vec<PiiMatch> {
        let mut matches = Vec::new();
        // Simple pattern: word@word.word
        for (i, _) in text.match_indices('@') {
            let before = &text[..i];
            let after = &text[i + 1..];

            let local_start = before
                .rfind(|c: char| !c.is_alphanumeric() && c != '.' && c != '_' && c != '-')
                // `rfind` returns the byte index of the matched separator char;
                // advance past the WHOLE char (not +1) so a multibyte separator
                // can't leave `local_start` mid-codepoint and panic the slice.
                .map(|p| p + before[p..].chars().next().map_or(1, char::len_utf8))
                .unwrap_or(0);

            let domain_end = after
                .find(|c: char| !c.is_alphanumeric() && c != '.' && c != '-')
                .unwrap_or(after.len());

            let local = &before[local_start..];
            let domain = &after[..domain_end];

            if !local.is_empty() && domain.contains('.') && domain.len() > 2 {
                let start = local_start;
                let end = i + 1 + domain_end;
                matches.push(PiiMatch {
                    pii_type: PiiType::Email,
                    value: text[start..end].to_string(),
                    start,
                    end,
                });
            }
        }
        matches
    }

    /// Detect phone numbers (simple patterns).
    fn detect_phones(&self, text: &str) -> Vec<PiiMatch> {
        let mut matches = Vec::new();
        let chars: Vec<char> = text.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            // Look for sequences of digits possibly separated by -/./space
            if chars[i].is_ascii_digit()
                || (chars[i] == '+' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit())
            {
                let start = i;
                let mut digit_count = 0;
                let mut j = i;

                while j < chars.len()
                    && (chars[j].is_ascii_digit()
                        || chars[j] == '-'
                        || chars[j] == '.'
                        || chars[j] == ' '
                        || chars[j] == '('
                        || chars[j] == ')'
                        || chars[j] == '+')
                {
                    if chars[j].is_ascii_digit() {
                        digit_count += 1;
                    }
                    j += 1;
                }

                // Phone numbers typically have 7-15 digits.
                if (7..=15).contains(&digit_count) {
                    let value: String = chars[start..j].iter().collect();
                    let byte_start = text
                        .char_indices()
                        .nth(start)
                        .map(|(bi, _)| bi)
                        .unwrap_or(0);
                    let byte_end = text
                        .char_indices()
                        .nth(j)
                        .map(|(bi, _)| bi)
                        .unwrap_or(text.len());

                    matches.push(PiiMatch {
                        pii_type: PiiType::Phone,
                        value,
                        start: byte_start,
                        end: byte_end,
                    });
                    i = j;
                    continue;
                }
            }
            i += 1;
        }
        matches
    }

    /// Detect IP addresses (IPv4).
    fn detect_ips(&self, text: &str) -> Vec<PiiMatch> {
        let mut matches = Vec::new();
        let words: Vec<&str> = text.split_whitespace().collect();

        let mut offset = 0;
        for word in &words {
            if let Some(pos) = text[offset..].find(word) {
                let start = offset + pos;
                let end = start + word.len();
                offset = end;

                // Simple IPv4: four groups of 1-3 digits separated by dots.
                let parts: Vec<&str> = word.split('.').collect();
                if parts.len() == 4
                    && parts.iter().all(|p| {
                        p.len() <= 3
                            && !p.is_empty()
                            && p.chars().all(|c| c.is_ascii_digit())
                    })
                {
                    let valid = parts.iter().all(|p| {
                        p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
                    });
                    if valid {
                        matches.push(PiiMatch {
                            pii_type: PiiType::IpAddress,
                            value: word.to_string(),
                            start,
                            end,
                        });
                    }
                }
            }
        }
        matches
    }

    /// Detect date patterns (YYYY-MM-DD, MM/DD/YYYY, etc.).
    fn detect_dates(&self, text: &str) -> Vec<PiiMatch> {
        let mut matches = Vec::new();

        // ISO date: YYYY-MM-DD
        let chars: Vec<char> = text.chars().collect();
        let mut i = 0;
        while i + 9 < chars.len() {
            if chars[i].is_ascii_digit()
                && chars[i + 1].is_ascii_digit()
                && chars[i + 2].is_ascii_digit()
                && chars[i + 3].is_ascii_digit()
                && chars[i + 4] == '-'
                && chars[i + 5].is_ascii_digit()
                && chars[i + 6].is_ascii_digit()
                && chars[i + 7] == '-'
                && chars[i + 8].is_ascii_digit()
                && chars[i + 9].is_ascii_digit()
            {
                let value: String = chars[i..i + 10].iter().collect();
                let byte_start = text.char_indices().nth(i).map(|(b, _)| b).unwrap_or(0);
                matches.push(PiiMatch {
                    pii_type: PiiType::Date,
                    value,
                    start: byte_start,
                    end: byte_start + 10,
                });
                i += 10;
                continue;
            }
            i += 1;
        }

        matches
    }

    /// Detect URLs.
    fn detect_urls(&self, text: &str) -> Vec<PiiMatch> {
        let mut matches = Vec::new();
        let prefixes = ["https://", "http://"];

        for prefix in &prefixes {
            let mut search_from = 0;
            while let Some(pos) = text[search_from..].find(prefix) {
                let start = search_from + pos;
                let rest = &text[start..];
                let end = rest
                    .find(|c: char| c.is_whitespace() || c == ')' || c == ']' || c == '>')
                    .unwrap_or(rest.len());

                if end > prefix.len() {
                    matches.push(PiiMatch {
                        pii_type: PiiType::Url,
                        value: rest[..end].to_string(),
                        start,
                        end: start + end,
                    });
                }
                search_from = start + end;
            }
        }

        matches
    }

    /// Detect credit card numbers (13-19 digits in space/dash-separated groups).
    fn detect_credit_cards(&self, text: &str) -> Vec<PiiMatch> {
        let mut matches = Vec::new();

        // Scan the ORIGINAL text, not a whitespace-collapsed copy: the reported
        // value and byte offsets MUST line up with the input. The old code
        // scanned `text.split_whitespace().join(" ")` and emitted char-indices
        // into THAT copy as byte offsets, so the value did not substring-match
        // the original and sanitize() could not redact the card.
        let chars: Vec<char> = text.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            if chars[i].is_ascii_digit() {
                let start = i;
                let mut digit_count = 0;
                let mut last_digit = i + 1; // exclusive char-end of the last digit
                let mut j = i;

                while j < chars.len()
                    && (chars[j].is_ascii_digit() || chars[j] == '-' || chars[j] == ' ')
                {
                    if chars[j].is_ascii_digit() {
                        digit_count += 1;
                        last_digit = j + 1;
                    }
                    j += 1;
                }

                if (13..=19).contains(&digit_count) {
                    // Span [start, last_digit): trim trailing separators so the
                    // value ends on a digit. Map char indices to byte offsets so
                    // the match is correct even with a multibyte prefix.
                    let byte_start = text.char_indices().nth(start).map_or(0, |(b, _)| b);
                    let byte_end = text
                        .char_indices()
                        .nth(last_digit)
                        .map_or(text.len(), |(b, _)| b);
                    matches.push(PiiMatch {
                        pii_type: PiiType::CreditCard,
                        value: text[byte_start..byte_end].to_string(),
                        start: byte_start,
                        end: byte_end,
                    });
                    i = j;
                    continue;
                }
            }
            i += 1;
        }

        matches
    }

    /// Detect US national IDs / SSNs in the form XXX-XX-XXXX.
    fn detect_national_ids(&self, text: &str) -> Vec<PiiMatch> {
        let mut matches = Vec::new();
        let chars: Vec<char> = text.chars().collect();
        let mut i = 0;
        // SSN: 3 digits '-' 2 digits '-' 4 digits (11 chars total).
        while i + 10 < chars.len() {
            let shaped = chars[i].is_ascii_digit()
                && chars[i + 1].is_ascii_digit()
                && chars[i + 2].is_ascii_digit()
                && chars[i + 3] == '-'
                && chars[i + 4].is_ascii_digit()
                && chars[i + 5].is_ascii_digit()
                && chars[i + 6] == '-'
                && chars[i + 7].is_ascii_digit()
                && chars[i + 8].is_ascii_digit()
                && chars[i + 9].is_ascii_digit()
                && chars[i + 10].is_ascii_digit();
            // Reject when embedded in a longer digit run (e.g. inside a card).
            let isolated = (i == 0 || !chars[i - 1].is_ascii_digit())
                && (i + 11 >= chars.len() || !chars[i + 11].is_ascii_digit());
            if shaped && isolated {
                let byte_start = text.char_indices().nth(i).map_or(0, |(b, _)| b);
                let byte_end = text
                    .char_indices()
                    .nth(i + 11)
                    .map_or(text.len(), |(b, _)| b);
                matches.push(PiiMatch {
                    pii_type: PiiType::NationalId,
                    value: text[byte_start..byte_end].to_string(),
                    start: byte_start,
                    end: byte_end,
                });
                i += 11;
                continue;
            }
            i += 1;
        }
        matches
    }

    /// Build a placeholder mapping from detected PII.
    ///
    /// Returns a map from original value to placeholder. This map
    /// MUST be kept in memory only — never serialized to disk.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::zkqp::PiiDetector;
    ///
    /// let detector = PiiDetector::new();
    /// let matches = detector.detect("user@example.com");
    /// let mapping = detector.build_mapping(&matches);
    /// assert!(mapping.contains_key("user@example.com"));
    /// assert!(mapping["user@example.com"].starts_with("[EMAIL_"));
    /// ```
    #[must_use]
    pub fn build_mapping(&self, matches: &[PiiMatch]) -> HashMap<String, String> {
        let mut mapping = HashMap::new();
        let mut counters: HashMap<PiiType, u32> = HashMap::new();

        for m in matches {
            if mapping.contains_key(&m.value) {
                continue;
            }
            let count = counters.entry(m.pii_type).or_insert(0);
            *count += 1;
            let placeholder = format!("[{}_{:03}]", m.pii_type.placeholder_prefix(), count);
            mapping.insert(m.value.clone(), placeholder);
        }

        mapping
    }
}

impl Default for PiiDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pii_type_placeholders() {
        assert_eq!(PiiType::Email.placeholder_prefix(), "EMAIL");
        assert_eq!(PiiType::Phone.placeholder_prefix(), "PHONE");
        assert_eq!(PiiType::IpAddress.placeholder_prefix(), "IP");
        assert_eq!(PiiType::CreditCard.placeholder_prefix(), "CC");
    }

    #[test]
    fn pii_type_weights() {
        assert!(PiiType::CreditCard.weight() > PiiType::Email.weight());
        assert!(PiiType::Email.weight() > PiiType::Date.weight());
    }

    #[test]
    fn pii_match_length() {
        let m = PiiMatch {
            pii_type: PiiType::Email,
            value: "a@b.com".to_string(),
            start: 0,
            end: 7,
        };
        assert_eq!(m.len(), 7);
        assert!(!m.is_empty());
    }

    #[test]
    fn detect_email() {
        let detector = PiiDetector::new();
        let matches = detector.detect("Contact user@example.com for info");
        assert!(matches.iter().any(|m| m.pii_type == PiiType::Email));
        assert!(matches.iter().any(|m| m.value == "user@example.com"));
    }

    #[test]
    fn detect_multiple_emails() {
        let detector = PiiDetector::new();
        let matches = detector.detect("From a@x.com to b@y.org");
        let emails: Vec<_> = matches
            .iter()
            .filter(|m| m.pii_type == PiiType::Email)
            .collect();
        assert!(emails.len() >= 2);
    }

    #[test]
    fn detect_no_email_in_plain_text() {
        let detector = PiiDetector::new();
        let matches = detector.detect("hello world no pii here");
        let emails: Vec<_> = matches
            .iter()
            .filter(|m| m.pii_type == PiiType::Email)
            .collect();
        assert!(emails.is_empty());
    }

    #[test]
    fn detect_ip_address() {
        let detector = PiiDetector::new();
        let matches = detector.detect("Server at 192.168.1.100 is down");
        assert!(matches.iter().any(|m| m.pii_type == PiiType::IpAddress));
    }

    #[test]
    fn reject_invalid_ip() {
        let detector = PiiDetector::new();
        let matches = detector.detect("Version 999.999.999.999 not valid");
        let ips: Vec<_> = matches
            .iter()
            .filter(|m| m.pii_type == PiiType::IpAddress)
            .collect();
        assert!(ips.is_empty());
    }

    #[test]
    fn detect_iso_date() {
        let detector = PiiDetector::new();
        let matches = detector.detect("Meeting on 2024-03-15 at noon");
        assert!(matches.iter().any(|m| m.pii_type == PiiType::Date));
        assert!(matches.iter().any(|m| m.value == "2024-03-15"));
    }

    #[test]
    fn detect_url() {
        let detector = PiiDetector::new();
        let matches = detector.detect("Visit https://example.com/path?key=value for details");
        assert!(matches.iter().any(|m| m.pii_type == PiiType::Url));
    }

    #[test]
    fn detect_phone_number() {
        let detector = PiiDetector::new();
        let matches = detector.detect("Call +1-555-867-5309 anytime");
        let phones: Vec<_> = matches
            .iter()
            .filter(|m| m.pii_type == PiiType::Phone)
            .collect();
        assert!(!phones.is_empty());
    }

    #[test]
    fn build_mapping_creates_placeholders() {
        let detector = PiiDetector::new();
        let matches = detector.detect("Email user@test.com about it");
        let mapping = detector.build_mapping(&matches);
        assert!(!mapping.is_empty());
        // Each placeholder should have the type prefix.
        for placeholder in mapping.values() {
            assert!(placeholder.starts_with('['));
            assert!(placeholder.ends_with(']'));
        }
    }

    #[test]
    fn build_mapping_deduplicates() {
        let detector = PiiDetector::new();
        let matches = detector.detect("user@a.com and user@a.com again");
        let mapping = detector.build_mapping(&matches);
        // Same email appears once in the mapping.
        let email_placeholders: Vec<_> = mapping
            .values()
            .filter(|v| v.contains("EMAIL"))
            .collect();
        assert_eq!(email_placeholders.len(), 1);
    }

    #[test]
    fn empty_text_no_matches() {
        let detector = PiiDetector::new();
        assert!(detector.detect("").is_empty());
        assert_eq!(detector.count_pii(""), 0);
    }

    #[test]
    fn add_entity() {
        let mut detector = PiiDetector::new();
        detector.add_entity("Acme Corp");
        assert_eq!(detector.known_entities.len(), 1);
    }

    #[test]
    fn detect_email_after_multibyte_separator_zkqp() {
        let detector = PiiDetector::new();
        // A multibyte separator ('\u{2022}' bullet, 3 bytes) immediately before
        // the local part. RED pre-fix: rfind returns the bullet's byte index,
        // +1 lands mid-codepoint, and slicing panics inside detect_emails.
        let matches = detector.detect("Contact\u{2022}user@example.com now");
        assert!(
            matches
                .iter()
                .any(|m| m.pii_type == PiiType::Email && m.value == "user@example.com"),
            "email after a multibyte separator must be detected without panicking"
        );
    }

    #[test]
    fn credit_card_value_is_a_substring_of_the_original_zkqp() {
        let detector = PiiDetector::new();
        // Irregular (double) spacing between groups. RED pre-fix: detection ran
        // on a whitespace-collapsed copy (words.join(" ")), so the reported
        // value/offsets did not line up with the original input -- the value was
        // not a substring of `input`, so QuerySanitizer::sanitize could not
        // redact it and the card leaked into the cloud-bound text.
        let input = "pay 4111  1111  1111  1111 now";
        let cc = detector
            .detect(input)
            .into_iter()
            .find(|m| m.pii_type == PiiType::CreditCard)
            .expect("a credit card must be detected");
        assert_eq!(
            cc.value.as_str(),
            &input[cc.start..cc.end],
            "value must equal the original-text slice at [start, end)"
        );
        assert!(
            input.contains(cc.value.as_str()),
            "detected value must be a substring of the original so sanitize can redact it: {:?}",
            cc.value
        );
    }

    #[test]
    fn national_id_is_detected_zkqp() {
        let detector = PiiDetector::new();
        // PiiType::NationalId is defined, weighted (30), and scored -- but no
        // detector ever produced it, so an SSN was never classified or redacted
        // as an ID (only incidentally caught by the phone heuristic and
        // mis-scored as 20). RED pre-fix: no NationalId match is produced.
        let matches = detector.detect("SSN 123-45-6789 on file");
        assert!(
            matches
                .iter()
                .any(|m| m.pii_type == PiiType::NationalId && m.value == "123-45-6789"),
            "an SSN must be detected as NationalId"
        );
    }
}
