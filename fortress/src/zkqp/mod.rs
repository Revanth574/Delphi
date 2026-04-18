// SPDX-License-Identifier: MIT

//! Zero-Knowledge Query Protocol (ZKQP).
//!
//! ZKQP sanitizes cloud-bound queries by detecting and replacing
//! personally identifiable information (PII) with placeholders. The
//! mapping table exists **only in memory** — never serialized to disk,
//! never logged.
//!
//! # Invariants (CLAUDE.md Section 10)
//!
//! 1. ALL Tier 3 cloud queries MUST pass through ZKQP
//! 2. ZKQP MUST NOT modify semantic content — only strip/replace PII
//! 3. PII-to-placeholder mapping is memory-only (never disk)
//! 4. Privacy score > 80 → MUST pause and ask the user
//! 5. ZKQP is ALWAYS active for Tier 3 — no disable option
//!
//! # Performance Budget
//!
//! ZKQP query sanitization: **< 50ms** (CLAUDE.md Section 9).

pub mod pii;
pub mod sanitizer;
pub mod scorer;

pub use pii::PiiDetector;
pub use sanitizer::{SanitizationResult, QuerySanitizer};
pub use scorer::PrivacyScorer;
