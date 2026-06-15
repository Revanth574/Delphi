# ADR 0004: Broaden PII detection in-place, never normalize-then-scan

- **Status:** Accepted
- **Date:** 2026-06 (fortress sweep)
- **Deciders:** Delphi maintainers (Codex adversarial review)

## Context

ZKQP must detect PII written in any script and with look-alike separators, then **redact it from
the original query**. A detector reports a match as a value plus byte offsets into the original
text; the sanitizer replaces that exact span. Two failure modes surfaced during the fortress
sweep:

1. **Under-coverage by enumeration.** Hand-enumerated digit ranges missed full-width digits,
   then Arabic-Indic — and would keep missing scripts (Devanagari, Bengali, Thai, …).
2. **Offset drift from normalization.** A detector that normalizes text (collapse whitespace,
   fold digits to ASCII) and then scans produces match offsets in *normalized* coordinates that
   no longer substring-match the original — so the sanitizer cannot redact the PII (it leaks).

## Decision

- Classify digits by Unicode **General_Category = Decimal_Number (Nd)** — the authoritative
  "decimal digit, any script" — not by enumerated ranges. Likewise accept a fixed set of
  Unicode separator confusables.
- **Scan the original text in place.** Never normalize-then-scan. All offsets flow through
  `char_indices` (never byte arithmetic on a multibyte digit), so every reported value is a
  true substring of the input the sanitizer can redact.

## Consequences

- New scripts are covered by construction (the category cannot miss one); Thai is the
  never-enumerated proof row in the tests.
- Detectors are slightly more complex (char-index bookkeeping) but cannot reintroduce the
  offset-drift leak class.
- The deliberate scope boundary stays explicit: IP and date scanners remain ASCII-only
  (machine-format identifiers), and that is asserted as a property, not an accident.

## Grounding (recorded history)

- Code: `fortress/src/zkqp/pii.rs` `is_pii_digit` / `is_pii_separator` doc comments state the
  rule and cite the failures.
- Commits: `84bb641` (digit detection via Unicode Nd — FORT-R2-01), `70ae808` (full-width digits
  — FORT-R1-01 class), `c86e075` (credit-card scans the original, not a copy — the offset class),
  `807b36c` (close ZKQP false-negatives — FORT-R1-01); merged at `84d84b3`.
- `PROGRESS.md` fortress-sweep "Convergence" section ("Digit completeness — CLOSED
  non-enumeratively") and the property tests in `fortress/tests/zkqp_completeness.rs`.
