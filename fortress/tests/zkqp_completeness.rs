// SPDX-License-Identifier: MIT

//! ZKQP PII-detector completeness properties (leverage pass P4).
//!
//! Property-based tests (stable `proptest`, not nightly cargo-fuzz) asserting the
//! per-detector contract the fortress sweep hardened. The invariant is
//! shape-driven — "a PII shape written in ANY decimal-digit script is detected" —
//! a GENERATION problem the structured generators express directly, not a
//! coverage-guided byte-DISCOVERY problem. The generators cover the FORT-R2-01
//! completeness table (Arabic-Indic, Devanagari, Bengali, Thai, full-width) BY
//! CONSTRUCTION rather than seeding a corpus.
//!
//! Each detector's invariant is stated from its ACTUAL CODE SCOPE (Iron Law #11 —
//! code is ground truth, not the doc comment):
//!
//! - **Unicode-complete** (email / phone / credit-card / national-id): metamorphic
//!   — an ASCII instance remapped to another `Nd` script (and Unicode separator
//!   confusables) is still detected as the same `PiiType`. This is the
//!   `is_pii_digit` = General_Category Nd contract (FORT-R2-01).
//! - **ASCII-only by design** (IP; date = ISO `YYYY-MM-DD` ONLY per the code): the
//!   ASCII form is detected, and the suite does NOT assert Nd detection for them
//!   — a non-ASCII-digit "IP"/"date" correctly is not classified as one (it lands
//!   in the phone digit-run band instead, so the date check asserts "not `Date`",
//!   not "not detected"). NOTE: `detect_dates`' comment also claims `MM/DD/YYYY`,
//!   but the code implements ISO only; that doc drift is flagged to the P5 honesty
//!   pass and the non-ISO gap to a separate detector-scope triage — NOT asserted
//!   here (asserting the comment would fail against the real code).
//!
//! Public-API only (`fortress::zkqp::PiiDetector` / `pii::PiiType`), so no fortress
//! source file is touched. Every property was RED-proven against the pre-fix
//! regression it guards (e.g. `is_pii_digit` reverted to ASCII-only) before commit.

use fortress::zkqp::pii::PiiType;
use fortress::zkqp::PiiDetector;
use proptest::prelude::*;

/// Code points of digit `0` for contiguous-`Nd` scripts (digit `d` == base + d).
/// Covers the FORT-R2-01 completeness table incl. Thai (the never-enumerated
/// proof row) by construction.
const ND_ZERO_BASES: &[u32] = &[
    0x0030, // ASCII
    0x0660, // Arabic-Indic
    0x06F0, // Extended Arabic-Indic
    0x0966, // Devanagari
    0x09E6, // Bengali
    0x0E50, // Thai
    0xFF10, // Fullwidth
];

/// Separator confusables the detectors accept == fortress `is_pii_separator`.
const SEPARATORS: &[char] = &[
    ' ', '-', '\u{00A0}', '\u{202F}', '\u{2007}', '\u{2010}', '\u{2011}', '\u{2012}',
];

/// Non-ASCII letters that are Unicode-alphanumeric (for the email local/domain).
const UNICODE_LETTERS: &[char] = &[
    'α', 'β', 'γ', 'δ', 'ε', 'ζ', 'λ', 'ω', 'Я', 'ж', 'д', 'п', '和', '字',
];

/// Map a `0..=9` digit to the given `Nd` script base.
fn nd_digit(base: u32, d: u8) -> char {
    char::from_u32(base + u32::from(d)).expect("contiguous Nd digit code point is valid")
}

/// Render `digits` as a string in the given `Nd` script.
fn nd_run(base: u32, digits: &[u8]) -> String {
    digits.iter().map(|&d| nd_digit(base, d)).collect()
}

/// Decimal digits of `n` as a fixed-width, leading-zero-padded vec.
fn digits_of(n: u16, width: usize) -> Vec<u8> {
    format!("{n:0width$}").bytes().map(|b| b - b'0').collect()
}

proptest! {
    // ---- Unicode-complete detectors: metamorphic completeness ----

    /// Phone: a 7..=15 `Nd`-digit run in ANY script is detected as Phone.
    /// RED: `is_pii_digit` reverted to ASCII-only -> a non-ASCII-script run is no
    /// longer detected (the FORT-R2-01 pre-fix miss; e.g. Thai / Arabic-Indic).
    #[test]
    fn phone_detected_in_any_nd_script(
        base_idx in 0usize..ND_ZERO_BASES.len(),
        digits in prop::collection::vec(0u8..10, 7..=15usize),
    ) {
        let base = ND_ZERO_BASES[base_idx];
        let text = nd_run(base, &digits);
        let matches = PiiDetector::new().detect(&text);
        prop_assert!(
            matches.iter().any(|m| m.pii_type == PiiType::Phone),
            "phone not detected: base={base:#x} text={text:?}"
        );
    }

    /// Credit card: a 13..=19 `Nd`-digit run in any script is detected as CreditCard.
    /// RED: `is_pii_digit` ASCII-only.
    #[test]
    fn credit_card_detected_in_any_nd_script(
        base_idx in 0usize..ND_ZERO_BASES.len(),
        digits in prop::collection::vec(0u8..10, 13..=19usize),
    ) {
        let base = ND_ZERO_BASES[base_idx];
        let text = nd_run(base, &digits);
        let matches = PiiDetector::new().detect(&text);
        prop_assert!(
            matches.iter().any(|m| m.pii_type == PiiType::CreditCard),
            "credit card not detected: base={base:#x} text={text:?}"
        );
    }

    /// National ID / SSN: `DDD<sep>DD<sep>DDDD` with `Nd` digits + Unicode
    /// separator confusables, embedded in non-digit context (so the isolation
    /// check and the `i + 10 < len` bound hold), is detected as NationalId.
    /// RED: `is_pii_digit` ASCII-only OR `is_pii_separator` hand-enumerated.
    #[test]
    fn national_id_detected_in_any_nd_script(
        base_idx in 0usize..ND_ZERO_BASES.len(),
        sep_a in prop::sample::select(SEPARATORS),
        sep_b in prop::sample::select(SEPARATORS),
        d in prop::collection::vec(0u8..10, 9usize),
    ) {
        let base = ND_ZERO_BASES[base_idx];
        let ssn = format!(
            "{}{sep_a}{}{sep_b}{}",
            nd_run(base, &d[0..3]),
            nd_run(base, &d[3..5]),
            nd_run(base, &d[5..9]),
        );
        let text = format!("ref {ssn} end");
        let matches = PiiDetector::new().detect(&text);
        prop_assert!(
            matches.iter().any(|m| m.pii_type == PiiType::NationalId),
            "SSN not detected: text={text:?}"
        );
    }

    /// Email: `local@domain.tld` with non-ASCII Unicode letters is detected as
    /// Email. RED: `is_email_local_char` reverted to ASCII-only -> a Unicode-letter
    /// local part is no longer recognized.
    #[test]
    fn email_detected_with_unicode_letters(
        local in prop::collection::vec(prop::sample::select(UNICODE_LETTERS), 1..=5usize),
        domain in prop::collection::vec(prop::sample::select(UNICODE_LETTERS), 1..=5usize),
        tld in prop::collection::vec(prop::sample::select(UNICODE_LETTERS), 2..=4usize),
    ) {
        let l: String = local.into_iter().collect();
        let dom: String = domain.into_iter().collect();
        let t: String = tld.into_iter().collect();
        let text = format!("{l}@{dom}.{t}");
        let matches = PiiDetector::new().detect(&text);
        prop_assert!(
            matches.iter().any(|m| m.pii_type == PiiType::Email),
            "email not detected: text={text:?}"
        );
    }

    // ---- ASCII-only detectors: scope stated from the code ----

    /// IP: an ASCII dotted-quad (octets 0..=255) is detected as IpAddress.
    /// Deliberately ASCII-only (machine-format) — the suite generates ASCII only
    /// and does not assert `Nd` detection (a `Nd` "IP" is correctly not an
    /// IpAddress; `parse::<u16>` rejects non-ASCII digits). RED: break the octet
    /// validity check -> a valid dotted-quad is no longer detected.
    #[test]
    fn ipv4_ascii_detected(
        a in 0u16..=255, b in 0u16..=255, c in 0u16..=255, e in 0u16..=255,
    ) {
        let text = format!("{a}.{b}.{c}.{e}");
        let matches = PiiDetector::new().detect(&text);
        prop_assert!(
            matches.iter().any(|m| m.pii_type == PiiType::IpAddress),
            "IPv4 not detected: text={text:?}"
        );
    }

    /// Date: ISO `YYYY-MM-DD` is the ACTUAL code scope (the comment also claims
    /// `MM/DD/YYYY`, not asserted here). (a) an ASCII ISO date is detected as Date;
    /// (b) the SAME digits in a non-ASCII `Nd` script are NOT detected as Date —
    /// the deliberate ASCII-only scope (they may register as Phone via the digit
    /// run, so the assertion is "not Date", not "not detected").
    /// RED(a): break the ISO shape check. RED(b): make `detect_dates` `Nd`-aware.
    #[test]
    fn iso_date_ascii_only_scope(
        y in 1000u16..=9999, mo in 1u8..=12, da in 1u8..=28,
        nd_base_idx in 1usize..ND_ZERO_BASES.len(),
    ) {
        let ascii = format!("{y:04}-{mo:02}-{da:02}");
        let am = PiiDetector::new().detect(&ascii);
        prop_assert!(
            am.iter().any(|m| m.pii_type == PiiType::Date),
            "ISO date not detected: {ascii:?}"
        );

        let base = ND_ZERO_BASES[nd_base_idx];
        let nd = format!(
            "{}-{}-{}",
            nd_run(base, &digits_of(y, 4)),
            nd_run(base, &digits_of(u16::from(mo), 2)),
            nd_run(base, &digits_of(u16::from(da), 2)),
        );
        let nm = PiiDetector::new().detect(&nd);
        prop_assert!(
            !nm.iter().any(|m| m.pii_type == PiiType::Date),
            "Nd-digit date wrongly classified as Date (ASCII-only scope broken): {nd:?}"
        );
    }
}
