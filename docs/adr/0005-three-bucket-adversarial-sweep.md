# ADR 0005: Three-bucket scope discipline for adversarial sweeps

- **Status:** Accepted
- **Date:** 2026-06 (fortress sweep)
- **Deciders:** Delphi maintainers

## Context

Delphi crates are partly built — a crate can hold working-and-live code, honest stubs, and
never-built layers all at once (fortress is ~20% built). A cold adversarial review (Codex) that
treats every interface as live wastes budget hunting "vulnerabilities" in code that does
nothing, and risks reporting an unbuilt layer as a defect.

## Decision

Scope each adversarial sweep into three buckets and review them differently:

1. **Built-and-live surface** — review for real defects (this is where findings count).
2. **Honest stubs** — confirm they are marked and inert; not defects, but record their
   forward-requirement status.
3. **Never-built layers** — inventory as forward-requirements, not findings.

Pair this with attention-allocation from `docs/DEFECT_CLASSES.md`: partition the relevant
defect classes into those already foreclosed by a `delphi-hardening` primitive (skip — do not
re-hunt) and those still applicable (cover explicitly).

## Consequences

- Review effort concentrates on the surface that can actually be exploited.
- "Fix what you find" still applies on the live surface: dead detection paths get wired before
  round 1 rather than reported as findings (the fortress sweep wired SSN and known-entity
  scanning that were registered-but-never-called).
- The buckets must be re-drawn each sweep as code moves from stub to built.

## Grounding (recorded history)

- `PROGRESS.md` Phase 3B.0 fortress-sweep → "Bucket discipline (the crate is ~20% built)" and
  the "7 pre-review fixes + 3 dead detection paths wired before round 1" entry.
- `CLAUDE.md` §6 "Codex Adversarial Review Process" (rounds, convergence signal, budget) and
  §13.9 (the `DEFECT_CLASSES.md` partition into pre-foreclosed vs. applicable-but-not).
- Sweep merge `84d84b3`.
