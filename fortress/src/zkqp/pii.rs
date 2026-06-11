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
    /// A registered known entity (company / project / person name).
    Entity,
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
            Self::Entity => "ENTITY",
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
            Self::Entity => 15,
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
        matches.extend(self.detect_entities(text));

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
                .rfind(|c: char| !is_email_local_char(c))
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
            if is_pii_digit(chars[i])
                || (chars[i] == '+' && i + 1 < chars.len() && is_pii_digit(chars[i + 1]))
            {
                let start = i;
                let mut digit_count = 0;
                let mut j = i;

                while j < chars.len()
                    && (is_pii_digit(chars[j])
                        || is_pii_separator(chars[j])
                        || chars[j] == '.'
                        || chars[j] == '('
                        || chars[j] == ')'
                        || chars[j] == '+')
                {
                    if is_pii_digit(chars[j]) {
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

        let mut offset = 0;
        for word in text.split_whitespace() {
            let Some(pos) = text[offset..].find(word) else {
                continue;
            };
            let word_start = offset + pos;
            offset = word_start + word.len();

            // Boundary-aware: trim leading/trailing non-digits so an IPv4 with
            // surrounding punctuation ("8.8.8.8," / "8.8.4.4." / "(1.2.3.4)") is
            // still detected. The core stays a substring of the original at the
            // adjusted offset, so the value still redacts.
            let core = word.trim_matches(|c: char| !c.is_ascii_digit());
            if core.is_empty() {
                continue;
            }
            let lead = word.len() - word.trim_start_matches(|c: char| !c.is_ascii_digit()).len();
            let start = word_start + lead;
            let end = start + core.len();

            // IPv4: four groups of 1-3 digits, each 0-255, separated by dots.
            let parts: Vec<&str> = core.split('.').collect();
            if parts.len() == 4
                && parts.iter().all(|p| {
                    !p.is_empty()
                        && p.len() <= 3
                        && p.chars().all(|c| c.is_ascii_digit())
                        && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
                })
            {
                matches.push(PiiMatch {
                    pii_type: PiiType::IpAddress,
                    value: core.to_string(),
                    start,
                    end,
                });
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
        // URI schemes are case-insensitive (RFC 3986). Search a byte-length-
        // preserving ASCII-lowercased copy so HTTPS:// / HtTp:// match, but take
        // OFFSETS into the ORIGINAL text — ASCII lowercasing keeps every byte
        // boundary identical, so offsets line up and the value stays a real
        // substring the sanitizer can redact.
        let lower = text.to_ascii_lowercase();
        let prefixes = ["https://", "http://"];

        for prefix in &prefixes {
            let mut search_from = 0;
            while let Some(pos) = lower[search_from..].find(prefix) {
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
            if is_pii_digit(chars[i]) {
                let start = i;
                let mut digit_count = 0;
                let mut last_digit = i + 1; // exclusive char-end of the last digit
                let mut j = i;

                while j < chars.len()
                    && (is_pii_digit(chars[j]) || is_pii_separator(chars[j]))
                {
                    if is_pii_digit(chars[j]) {
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
            let shaped = is_pii_digit(chars[i])
                && is_pii_digit(chars[i + 1])
                && is_pii_digit(chars[i + 2])
                && is_pii_separator(chars[i + 3])
                && is_pii_digit(chars[i + 4])
                && is_pii_digit(chars[i + 5])
                && is_pii_separator(chars[i + 6])
                && is_pii_digit(chars[i + 7])
                && is_pii_digit(chars[i + 8])
                && is_pii_digit(chars[i + 9])
                && is_pii_digit(chars[i + 10]);
            // Reject when embedded in a longer digit run (e.g. inside a card).
            let isolated = (i == 0 || !is_pii_digit(chars[i - 1]))
                && (i + 11 >= chars.len() || !is_pii_digit(chars[i + 11]));
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

    /// Detect occurrences of registered known entities (company / project /
    /// person names added via [`add_entity`](Self::add_entity)).
    ///
    /// Exact (verbatim) substring match of each registered name, so the value
    /// equals the original slice and sanitize() can redact it. Case-insensitive
    /// matching is a deliberate non-goal here (kept deterministic for the
    /// cloud-egress token binding).
    fn detect_entities(&self, text: &str) -> Vec<PiiMatch> {
        let mut matches = Vec::new();
        for entity in &self.known_entities {
            if entity.is_empty() {
                continue;
            }
            let mut from = 0;
            while let Some(pos) = text[from..].find(entity.as_str()) {
                let start = from + pos;
                let end = start + entity.len();
                matches.push(PiiMatch {
                    pii_type: PiiType::Entity,
                    value: entity.clone(),
                    start,
                    end,
                });
                from = end;
            }
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
    /// let mapping = detector.build_mapping(&matches, "q1a2b3c4");
    /// assert!(mapping.contains_key("user@example.com"));
    /// assert!(mapping["user@example.com"].starts_with("[EMAIL_"));
    /// ```
    #[must_use]
    pub fn build_mapping(&self, matches: &[PiiMatch], token: &str) -> HashMap<String, String> {
        let mut mapping = HashMap::new();
        let mut counters: HashMap<PiiType, u32> = HashMap::new();

        for m in matches {
            if mapping.contains_key(&m.value) {
                continue;
            }
            let count = counters.entry(m.pii_type).or_insert(0);
            *count += 1;
            // The query-bound `token` makes the placeholder unguessable to the
            // cloud (which never sees it), so a literal [EMAIL_001]-style string
            // in a response cannot collide with a minted placeholder (FORT-R1-02).
            let placeholder =
                format!("[{}_{}_{:03}]", m.pii_type.placeholder_prefix(), token, count);
            mapping.insert(m.value.clone(), placeholder);
        }

        mapping
    }
}

/// True for characters that may separate digit groups in phone numbers, credit
/// cards, and national IDs — ASCII space/hyphen plus their common Unicode
/// confusables (NBSP, narrow NBSP, figure space; Unicode hyphen, non-breaking
/// hyphen, figure dash).
///
/// Detectors accept these **in place on the original text**. We deliberately do
/// NOT normalize-then-scan: that would emit matches whose value is in
/// normalized coordinates and no longer substring-matches the input (the
/// `c86e075` credit-card offset class), so `sanitize()` could not redact them.
fn is_pii_separator(c: char) -> bool {
    matches!(
        c,
        ' ' | '-' | '\u{00A0}' | '\u{202F}' | '\u{2007}' | '\u{2010}' | '\u{2011}' | '\u{2012}'
    )
}

/// True for characters that function as digits in phone numbers, credit cards,
/// and national IDs — Unicode **General_Category = Decimal_Number (Nd)**, the
/// authoritative definition of "decimal digit, any script" (FORT-R2-01).
///
/// Hand-enumerated ranges proved incomplete twice in one sweep: ASCII-only
/// missed full-width forms (U+FF10..), and ASCII+full-width missed Arabic-Indic
/// — with Devanagari, Bengali, Thai, and every other Nd script behind it. The
/// category closes the class non-enumeratively: a script never listed here is
/// still caught because its digits are Nd by definition. The ASCII check is a
/// fast path only (ASCII `0-9` is itself Nd); the property-table lookup is a
/// pure function, so detection stays deterministic for the egress HMAC binding.
/// Deliberately NOT `char::is_numeric()`, which also accepts Letter_Number /
/// Other_Number (Roman numerals, fractions) and would over-match.
///
/// Same broaden-in-place rule as [`is_pii_separator`]: the scanners accept these
/// **in the original text** rather than normalizing to ASCII first, which would
/// put the match value/offsets in normalized coordinates that no longer
/// substring-match the input (the `c86e075` offset class). Nd digits are
/// multibyte, so all offsets must flow through `char_indices` — never byte
/// arithmetic on a digit count.
fn is_pii_digit(c: char) -> bool {
    use unicode_general_category::{GeneralCategory, get_general_category};
    c.is_ascii_digit() || get_general_category(c) == GeneralCategory::DecimalNumber
}

/// True for characters valid in an email local part: the RFC 5322 `atext` set
/// plus `.` (dot-atom). The old scan allowed only alphanumerics and `._-`, so a
/// local part like `johndoe+tag` was truncated at `+`, leaking the prefix.
///
/// `/` is `atext` per RFC 5322 but is deliberately EXCLUDED (FORT-R2-04): real
/// local parts essentially never contain it, and treating it as a local-part
/// character made `/api/users@host` redact the whole URL path as one email
/// (over-redaction). Excluding it keeps the left boundary at the path separator.
fn is_email_local_char(c: char) -> bool {
    c.is_alphanumeric()
        || c == '.'
        || matches!(
            c,
            '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '=' | '?' | '^' | '_' | '`'
                | '{' | '|' | '}' | '~'
        )
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
        let mapping = detector.build_mapping(&matches, "q1a2b3c4");
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
        let mapping = detector.build_mapping(&matches, "q1a2b3c4");
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

    #[test]
    fn full_width_card_value_is_a_substring_of_the_original_zkqp() {
        // FORT-R1-01 class, byte-vs-char guard: full-width digits are 3 BYTES
        // each (vs 1 for ASCII), so any scanner conflating byte length with
        // digit count would emit a value/offsets that no longer line up with
        // the original — and sanitize() could not redact it (the c86e075
        // class). The value must equal the original-text slice exactly.
        let detector = PiiDetector::new();
        let input = "pay \u{FF14}\u{FF11}\u{FF11}\u{FF11} \u{FF11}\u{FF11}\u{FF11}\u{FF11} \u{FF11}\u{FF11}\u{FF11}\u{FF11} \u{FF11}\u{FF11}\u{FF11}\u{FF11} now";
        let cc = detector
            .detect(input)
            .into_iter()
            .find(|m| m.pii_type == PiiType::CreditCard)
            .expect("a full-width-digit credit card must be detected");
        assert_eq!(
            cc.value.as_str(),
            &input[cc.start..cc.end],
            "full-width value must equal the original-text slice at [start, end)"
        );
    }

    #[test]
    fn registered_entity_is_detected_zkqp() {
        let mut detector = PiiDetector::new();
        detector.add_entity("Acme Corp");
        // add_entity stored the name, but detect() never scanned known_entities,
        // so registering an entity was a silent no-op -- the company/project
        // name passed through to the cloud unredacted. RED pre-fix: no match.
        let matches = detector.detect("Meeting with Acme Corp today");
        assert!(
            matches.iter().any(|m| m.value == "Acme Corp"),
            "a registered known entity must be detected"
        );
    }

    #[test]
    fn placeholder_is_not_a_stable_function_of_the_value_fort_r2_02() {
        // R2-02 residual-linkability guard: a value's placeholder must depend on
        // its POSITION (the per-query ordinal counter), not be a stable function
        // of the value -- else the cloud could correlate two queries as
        // containing the same hidden value. Same value at a different position
        // gets a different placeholder, even with the namespace held fixed.
        let detector = PiiDetector::new();
        let ns = "fixed_ns";
        let a = detector.detect("Email alice@example.com today");
        let ma = detector.build_mapping(&a, ns);
        let b = detector.detect("Email bob@x.com cc alice@example.com");
        let mb = detector.build_mapping(&b, ns);
        assert_ne!(
            ma["alice@example.com"], mb["alice@example.com"],
            "same value at a different position must get a different placeholder"
        );
    }

    #[test]
    fn atext_email_does_not_slurp_url_path_fort_r2_04() {
        // FORT-R2-04: '/' is RFC 5322 atext, but treating it as a local-part char
        // made "/api/users@example.com" redact the whole path as one email
        // (over-redaction). '/' is now excluded, so detection stops at the path
        // separator and only the real email is captured.
        let detector = PiiDetector::new();
        let matches = detector.detect("GET /api/users@example.com HTTP");
        let email = matches
            .iter()
            .find(|m| m.pii_type == PiiType::Email)
            .expect("an email must be detected");
        // RED pre-fix: value was "/api/users@example.com" (path slurped).
        assert_eq!(
            email.value, "users@example.com",
            "only the email must be captured, not the URL path"
        );
    }
}
