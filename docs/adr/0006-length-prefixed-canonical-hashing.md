# ADR 0006: Length-prefixed, count-guarded canonical hashing

- **Status:** Accepted
- **Date:** 2026-06 (leverage pass; pattern predates it in the audit chain)
- **Deciders:** Delphi maintainers

## Context

Several subsystems hash structured records for integrity (the audit chain, the workflow
consent fingerprint). Two defect classes bit the project repeatedly:

1. **Non-injective encoding.** Concatenating variable-length fields lets `("ab","c")` and
   `("a","bc")` hash identically — one record can be rewritten as another without changing the
   digest.
2. **Under-coverage.** A field that exists but is not hashed (the audit chain once omitted
   `result` and `permission_tier`; a workflow fingerprint once omitted `confidence`) lets a
   record be edited without breaking the digest.

## Decision

Provide one shared primitive (`delphi-hardening::canonical_hash`) used by every structured-hash
site:

- **Length-prefix every variable field** (`u64`-LE length ++ bytes) and **count-prefix every
  collection**, so the byte stream is unambiguous (injective encoding).
- **Declare the field count** up front; `finish()` refuses to produce a digest if the number of
  appended fields differs (fail-closed). This closes *append ≠ declare*.
- The other half — *struct grew, nobody hashed the new field* — is closed at each call site by a
  **no-`..` exhaustive destructure test** that fails to compile when a field is added. Both
  halves are required; neither alone suffices.

## Consequences

- Adding a field to a hashed struct now forces a compile-time decision about whether to hash it.
- Call sites migrated byte-identically (golden digests pinned before/after), so the change is
  provably behavior-preserving.
- A field-counting derive macro is a future option if a third flat-struct site appears
  (rule-of-three).

## Grounding (recorded history)

- Code: `delphi-hardening/src/canonical_hash.rs` module docs (the two defect classes, the
  both-halves rule) and `fortress/tests/…` / the call-site destructure tests.
- Commits: `b95e9c7` (canonical_hash module), `dec4026` (audit hash migration, byte-identical),
  `dc03a5f` (workflow fingerprint migration, byte-identical); injectivity property tests added
  later in the leverage pass.
- `docs/DEFECT_CLASSES.md` Class 1 (the centerpiece, with the worked consent-field destructure
  example); the ORCH-R2-02 delimiter-collision finding that motivated the encoding rule.
