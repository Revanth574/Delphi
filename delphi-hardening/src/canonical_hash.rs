// SPDX-License-Identifier: MIT

//! Canonical, injective SHA-256 hashing with a declared-field-count guard.
//!
//! # Defect class foreclosed: under-coverage hashing / non-injective encoding
//!
//! This primitive lifts two hash-discipline lessons the project learned the hard
//! way, and pins them into a type:
//!
//! 1. **Non-injective encoding (delimiter / boundary collision).** Concatenating
//!    variable-length fields lets `("ab","c")` and `("a","bc")` hash identically,
//!    so one record can be rewritten as another without changing the digest.
//!    Every variable-length field here is **length-prefixed** (`u64`-LE byte
//!    length ++ bytes — the git `blob <len>\0` idea), and every collection is
//!    count-prefixed, so the byte stream is unambiguous. (Motivated by
//!    ORCH-R2-02 — the consent-fingerprint delimiter collision — and applied to
//!    the fortress audit chain.)
//!
//! 2. **Under-coverage (a field exists but is not hashed).** The audit chain
//!    once omitted `result` and `permission_tier`, so a `Denied`/`Biometric`
//!    record could be edited to `Allowed`/`Autonomous` without breaking the
//!    chain; `Workflow::fingerprint` once omitted `confidence`. Hashing fewer
//!    fields than the record has is the recurring bug (it bit the project 3–4
//!    times). [`CanonicalHasher`] takes a **declared field count** and refuses to
//!    [`finish`](CanonicalHasher::finish) if the number of fields actually
//!    appended differs.
//!
//! ## The guard closes only HALF the class — both halves are required
//!
//! The declared-count guard catches **append ≠ declare** (the hasher drifts from
//! its own stated field count). It does **not** catch **struct-grew** (a field is
//! added to the record and *both* the declaration and the hasher fail to keep
//! up — the new field is silently unhashed). That second case is the one that
//! actually recurred. Closing it is the **call site's** responsibility: each site
//! that hashes a struct MUST have a regression test that **exhaustively
//! destructures the struct with no `..`**, e.g.
//! `let AuditEntry { action_id, timestamp, .. /* NO: forbidden */ } = entry;`
//! written WITHOUT the `..`. Adding a field then fails that test at **compile
//! time** until someone decides whether the new field must be hashed. The guard
//! (this type) + the no-`..` destructure test (each call site) together foreclose
//! the class; neither alone does. See `docs/DEFECT_CLASSES.md`.
//!
//! A field-counting derive macro would be the strongest version, but it is
//! machinery for two call sites today; it is a rule-of-three future option if a
//! third flat-struct hash site appears.
//!
//! # Examples
//!
//! Flat record (declared count = number of top-level fields):
//!
//! ```
//! use delphi_hardening::canonical_hash::CanonicalHasher;
//!
//! let mut h = CanonicalHasher::new(3);
//! h.field(b"alice")          // variable: length-prefixed
//!     .fixed(&7u64.to_le_bytes()) // fixed-width: raw, no prefix
//!     .field(b"target");
//! let digest = h.finish().expect("declared 3, appended 3");
//! assert_eq!(digest.len(), 32);
//! ```
//!
//! Nested collection (a sequence is ONE top-level field):
//!
//! ```
//! use delphi_hardening::canonical_hash::CanonicalHasher;
//!
//! let items: &[&str] = &["a", "bb", "ccc"];
//! let mut h = CanonicalHasher::new(2);
//! h.field(b"name").seq(items.len(), |s| {
//!     for it in items {
//!         s.field(it.as_bytes());
//!     }
//! });
//! let digest = h.finish().expect("declared 2: name + the seq");
//! assert_eq!(digest.len(), 32);
//! ```

use sha2::{Digest, Sha256};

/// Returned by [`CanonicalHasher::finish`] when the number of appended fields
/// differs from the declared count (append ≠ declare).
///
/// In **debug** builds the mismatch also fires a `debug_assert!` panic so it is
/// caught in tests; in **release** builds this `Err` is returned and **no digest
/// is produced** (fail-closed — a misused security hash must never silently emit
/// a wrong value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldCountError {
    /// The count declared at [`CanonicalHasher::new`].
    pub declared: usize,
    /// The number of fields actually appended before [`CanonicalHasher::finish`].
    pub appended: usize,
}

impl std::fmt::Display for FieldCountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "canonical_hash field-count mismatch: declared {} field(s), appended {}",
            self.declared, self.appended
        )
    }
}

impl std::error::Error for FieldCountError {}

/// A canonical, injective SHA-256 hasher with a declared-field-count guard.
///
/// Append top-level fields with [`field`](Self::field) (variable-length,
/// length-prefixed), [`fixed`](Self::fixed) (fixed-width, raw), or
/// [`seq`](Self::seq) (a count-prefixed collection — one top-level field), then
/// call [`finish`](Self::finish). See the module docs for the defect class this
/// forecloses and why each call site also needs a no-`..` destructure test.
#[must_use]
pub struct CanonicalHasher {
    hasher: Sha256,
    declared: usize,
    appended: usize,
}

impl CanonicalHasher {
    /// Start a hasher declaring exactly `declared_fields` top-level fields. A
    /// collection appended via [`seq`](Self::seq) counts as one top-level field.
    pub fn new(declared_fields: usize) -> Self {
        Self {
            hasher: Sha256::new(),
            declared: declared_fields,
            appended: 0,
        }
    }

    /// Append a variable-length field: `u64`-LE byte length, then the bytes.
    /// Counts as one top-level field.
    pub fn field(&mut self, bytes: &[u8]) -> &mut Self {
        push_len_prefixed(&mut self.hasher, bytes);
        self.appended += 1;
        self
    }

    /// Append fixed-width bytes verbatim (no length prefix) — for fields whose
    /// width is constant: integers via `to_le_bytes`, enum discriminants, a
    /// `f64` via `to_bits().to_le_bytes()`. Counts as one top-level field.
    pub fn fixed(&mut self, bytes: &[u8]) -> &mut Self {
        self.hasher.update(bytes);
        self.appended += 1;
        self
    }

    /// Append a collection as one top-level field: emit the element count
    /// (`u64`-LE), then the elements via the [`SeqHasher`] passed to `f`. The
    /// closure's per-element fields are NOT counted against the top-level
    /// declared count (the collection is the single field); element coverage is
    /// guarded by the call site's no-`..` destructure test.
    pub fn seq(&mut self, len: usize, f: impl FnOnce(&mut SeqHasher<'_>)) -> &mut Self {
        self.hasher.update((len as u64).to_le_bytes());
        let mut seq = SeqHasher {
            hasher: &mut self.hasher,
        };
        f(&mut seq);
        self.appended += 1;
        self
    }

    /// Finalize the digest, enforcing the declared-field-count guard.
    ///
    /// # Errors
    ///
    /// Returns [`FieldCountError`] if the number of appended fields differs from
    /// the count declared at [`new`](Self::new). In debug builds this case also
    /// panics via `debug_assert!` so tests catch it; in release builds the `Err`
    /// is returned and no digest is produced (fail-closed).
    pub fn finish(self) -> Result<[u8; 32], FieldCountError> {
        if self.appended != self.declared {
            debug_assert!(
                false,
                "canonical_hash: declared {} field(s) but appended {}",
                self.declared, self.appended
            );
            return Err(FieldCountError {
                declared: self.declared,
                appended: self.appended,
            });
        }
        Ok(self.hasher.finalize().into())
    }
}

/// Element hasher inside a [`CanonicalHasher::seq`] closure.
///
/// Same `field`/`fixed`/`seq` vocabulary as [`CanonicalHasher`], but with no
/// top-level field counting — the enclosing `seq` is the single counted field,
/// and per-element coverage is enforced by the call site's no-`..` destructure
/// test rather than a per-element declared count.
pub struct SeqHasher<'a> {
    hasher: &'a mut Sha256,
}

impl SeqHasher<'_> {
    /// Append a variable-length element field (length-prefixed).
    pub fn field(&mut self, bytes: &[u8]) -> &mut Self {
        push_len_prefixed(self.hasher, bytes);
        self
    }

    /// Append fixed-width element bytes verbatim (no length prefix).
    pub fn fixed(&mut self, bytes: &[u8]) -> &mut Self {
        self.hasher.update(bytes);
        self
    }

    /// Append a nested count-prefixed collection (e.g. a step's `depends_on`).
    pub fn seq(&mut self, len: usize, f: impl FnOnce(&mut SeqHasher<'_>)) -> &mut Self {
        self.hasher.update((len as u64).to_le_bytes());
        let mut inner = SeqHasher {
            hasher: self.hasher,
        };
        f(&mut inner);
        self
    }
}

/// Length-prefix a variable-length field into `hasher`: `u64`-LE byte length,
/// then the bytes. The single shared encoding used by both hashers, so a value's
/// content can never be confused with a field boundary.
fn push_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Re-implement the raw length-prefixed encoding independently, to prove the
    /// builder produces exactly `len_le ++ bytes` per field (the byte-identical
    /// contract every migrated call site relies on).
    fn manual(fields: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha256::new();
        for f in fields {
            h.update((f.len() as u64).to_le_bytes());
            h.update(*f);
        }
        h.finalize().into()
    }

    #[test]
    fn field_encoding_is_length_prefixed_and_matches_manual() {
        let mut h = CanonicalHasher::new(2);
        h.field(b"ab").field(b"c");
        assert_eq!(h.finish().unwrap(), manual(&[b"ab", b"c"]));
    }

    #[test]
    fn length_prefix_prevents_boundary_collision() {
        // ("ab","c") vs ("a","bc") must differ — the non-injective-encoding class.
        let mut a = CanonicalHasher::new(2);
        a.field(b"ab").field(b"c");
        let mut b = CanonicalHasher::new(2);
        b.field(b"a").field(b"bc");
        assert_ne!(a.finish().unwrap(), b.finish().unwrap());
    }

    #[test]
    fn fixed_fields_are_raw_unprefixed() {
        // fixed() must NOT length-prefix: a single 8-byte fixed field equals a
        // bare Sha256 of those 8 bytes.
        let mut h = CanonicalHasher::new(1);
        h.fixed(&7u64.to_le_bytes());
        let mut raw = Sha256::new();
        raw.update(7u64.to_le_bytes());
        assert_eq!(h.finish().unwrap(), <[u8; 32]>::from(raw.finalize()));
    }

    #[test]
    fn under_declared_is_a_field_count_error_in_release() {
        // declared 3, append 2 -> Err in release. (In debug this path also
        // debug_assert!-panics; the release Err is the fail-closed backstop.)
        let mut h = CanonicalHasher::new(3);
        h.field(b"x").field(b"y");
        // Exercise the release path explicitly regardless of build profile by
        // checking the error a debug build would panic on is well-formed.
        #[cfg(not(debug_assertions))]
        {
            assert_eq!(
                h.finish(),
                Err(FieldCountError { declared: 3, appended: 2 })
            );
        }
        #[cfg(debug_assertions)]
        {
            // In debug, finish() panics via debug_assert!; prove that.
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h.finish()));
            assert!(caught.is_err(), "debug build must panic on append != declare");
        }
    }

    #[test]
    fn over_declared_is_caught_too() {
        // declared 1, append 2 -> mismatch (the symmetric drift).
        let mut h = CanonicalHasher::new(1);
        h.field(b"x").field(b"y");
        #[cfg(not(debug_assertions))]
        assert_eq!(h.finish(), Err(FieldCountError { declared: 1, appended: 2 }));
        #[cfg(debug_assertions)]
        {
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h.finish()));
            assert!(caught.is_err());
        }
    }

    #[test]
    fn exact_count_succeeds() {
        let mut h = CanonicalHasher::new(2);
        h.field(b"x").fixed(&[1u8]);
        assert!(h.finish().is_ok());
    }

    #[test]
    fn seq_is_count_prefixed_and_one_field() {
        // A seq counts as ONE top-level field; its body emits the u64 count then
        // the elements. Prove the byte stream: count_le ++ (len_le ++ bytes)*.
        let items: &[&[u8]] = &[b"a", b"bb"];
        let mut h = CanonicalHasher::new(1);
        h.seq(items.len(), |s| {
            for it in items {
                s.field(it);
            }
        });
        let got = h.finish().unwrap();

        let mut manual = Sha256::new();
        manual.update((items.len() as u64).to_le_bytes());
        for it in items {
            manual.update((it.len() as u64).to_le_bytes());
            manual.update(*it);
        }
        assert_eq!(got, <[u8; 32]>::from(manual.finalize()));
    }

    #[test]
    fn seq_length_distinguishes_otherwise_equal_streams() {
        // The count prefix makes [] ++ ["a"] distinguishable from ["a"] ++ []
        // when they are two separate seqs (no aliasing across collection edges).
        let mut a = CanonicalHasher::new(2);
        a.seq(0, |_| {}).seq(1, |s| {
            s.field(b"a");
        });
        let mut b = CanonicalHasher::new(2);
        b.seq(1, |s| {
            s.field(b"a");
        })
        .seq(0, |_| {});
        assert_ne!(a.finish().unwrap(), b.finish().unwrap());
    }
}
