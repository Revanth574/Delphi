// SPDX-License-Identifier: MIT

//! # delphi-hardening
//!
//! Shared hardening primitives lifted from the project's adversarial-review
//! history (F4–F18, ORCH-R1/R2, the fortress sweep R1/R2/R3, INF-1). Each module
//! forecloses a recurring **defect class** by construction, so future code is
//! safe by default rather than safe-only-if-reviewed. The defect classes and the
//! finding IDs that motivated each primitive are catalogued in
//! `docs/DEFECT_CLASSES.md`.
//!
//! This is a foundation crate: it has **no internal workspace dependencies**, so
//! `fortress`, `die-orchestrator`, and `services` can all depend on it.
//!
//! Modules are added one at a time as their already-reviewed in-place
//! implementations are lifted and generalized (leverage pass, Phase 2):
//!
//! - [`canonical_hash`] — injective, length-prefixed hashing with a
//!   declared-field-count guard (forecloses under-coverage hashing /
//!   non-injective encoding).

pub mod canonical_hash;
