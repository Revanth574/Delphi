# Architecture Decision Records

This directory records significant architecture decisions for Delphi, in the lightweight ADR
format. Each record captures the context, the decision, and its consequences.

**Grounding rule (Delphi-specific).** Delphi's culture is verifiable-record: an ADR may only
claim a *historical rationale* that is grounded in recorded history — a commit, a `PROGRESS.md`
entry, or a `CLAUDE.md` section. Every ADR carries an explicit **Grounding** section citing
that history. Where the decision was made but its rationale was never separately recorded
(e.g. a starting-point assumption rather than a weighed choice), the ADR says so with a
**GAP** marker rather than inventing a plausible-sounding justification. These ADRs were
written retroactively (2026-06) during the leverage pass; the Grounding sections distinguish
what is documented from what is reconstructed.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-linux-first.md) | Linux-first, cross-OS deferred to Phase 3C | Accepted |
| [0002](0002-die-operates-tools-not-agi.md) | The engine operates the user's tools (not an AGI) | Accepted |
| [0003](0003-three-tier-inference.md) | Three-tier inference (local / hybrid / cloud) | Accepted |
| [0004](0004-broaden-in-place-pii-detection.md) | Broaden PII detection in-place, never normalize-then-scan | Accepted |
| [0005](0005-three-bucket-adversarial-sweep.md) | Three-bucket scope discipline for adversarial sweeps | Accepted |
| [0006](0006-length-prefixed-canonical-hashing.md) | Length-prefixed, count-guarded canonical hashing | Accepted |
| [0007](0007-verify-and-document-scoping.md) | Verify-and-document scoping (ratify before migrate) | Accepted |

New ADRs start from [`0000-template.md`](0000-template.md).
