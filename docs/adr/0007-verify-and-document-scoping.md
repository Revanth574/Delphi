# ADR 0007: Verify-and-document scoping (ratify before migrate)

- **Status:** Accepted
- **Date:** 2026-06 (leverage pass)
- **Deciders:** Delphi maintainers

## Context

Extracting shared primitives and reconciling status across a partly-built codebase is exactly
where fabrication creeps in: an assumed API shape, a "should work" migration, a grep that
classifies an error-returning shell as "built." Delphi's value rests on a verifiable record, so
the *process* of making structural changes needs the same rigor as the code.

## Decision

- **Ratify the API/scope before migrating** (a "stop point"): decide a primitive's surface and
  which call sites it covers *before* touching them; surface rough cases (a forced extraction, a
  dependency-direction conflict) and **defer with a recorded reason** rather than forcing the
  refactor (rule-of-two, don't-refactor-reviewed-code).
- **Lift, don't rewrite.** Migrate call sites byte-identically — capture a golden from the
  pre-extraction code and reproduce it exactly — so the change is provably behavior-preserving.
- **Ground every claim.** Numbers come from a command just run; "built/stub" comes from reading
  what the function *does*, not from markers it carries or its interface shape; uncertainty is
  stated and checked, never plastered over.
- **Show before committing** load-bearing artifacts (the honest status table, the doc-lie batch)
  and the **RED-proof** for every regression test (it must fail against the pre-fix code).

## Consequences

- Slower per change, but the record stays trustworthy — which is the asset.
- Deferrals are first-class: `atomic_migration`, `uniform_reject`, and `TrustedRoot` were
  surfaced and *not* extracted, each with a recorded reason, rather than forced.
- A guard/detector must cover **all forms** of what it guards (a stub-grep misses an
  error-returning shell; a gitignore dir-pattern misses the file form) — the reliable check is
  reading behavior, not pattern-matching markers.

## Grounding (recorded history)

- `CLAUDE.md` §13 (anti-hallucination protocol: the verification hierarchy, the "I don't know"
  rule, the self-audit and dependency-addition protocols) and §13.9 (defect-class attention
  allocation).
- `PROGRESS.md` leverage-pass section (P2 byte-identical extractions; the three recorded
  deferrals) and `docs/DEFECT_CLASSES.md` (the deferred patterns + the "guard must cover all
  forms" class with its two instances).
- The leverage-pass commits demonstrate the discipline (byte-identical migrations `dec4026` /
  `dc03a5f` / `6ebbd5a`; the defect-class corpus `e2e7cfc`).
