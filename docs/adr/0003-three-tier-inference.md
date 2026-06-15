# ADR 0003: Three-tier inference (local / hybrid / cloud)

- **Status:** Accepted
- **Date:** —
- **Deciders:** Delphi maintainers

## Context

Delphi must run on hardware from a 2 GB Raspberry Pi to a 128 GB workstation, keep sensitive
data local, and still reach frontier capability when a task needs it. A single inference target
cannot satisfy latency, cost, privacy, and capability simultaneously.

## Decision

Route inference across three tiers, selecting the cheapest capable model per task:

- **Tier 1 — always local** (small quantized models): intent classification, autocomplete,
  quick answers; real-time latency budget.
- **Tier 2 — local or cloud**: code generation, writing, analysis.
- **Tier 3 — cloud with ZKQP** (frontier models): complex reasoning, research, creative work;
  every cloud query passes through the Zero-Knowledge Query Protocol first.

Sensitive data forces local routing regardless of the cheapest-capable choice.

## Consequences

- The model router (`die-inference`) owns tier selection; the inference scheduler manages *how
  and when* inference runs, never *what* to infer (a module-boundary rule).
- Tier 3 is inseparable from ZKQP — there is no path that sends a raw query to the cloud (see
  ADR-0004 and the egress gate in `die-inference`).
- Graceful degradation: offline, only Tier 1 is available; the system degrades, never breaks.

## Grounding (recorded history)

- `CLAUDE.md` "Three-Tier Inference Architecture" table (Tier 1/2/3 definitions, models, use
  cases) and "The model router selects the cheapest capable model per task. Sensitive data
  forces local routing."
- `CLAUDE.md` Module Boundary #4 (the scheduler decides how/when, the orchestrator decides
  what) and §10 Rule 4 (all cloud calls go through ZKQP).
- The router and cloud client exist in `die-inference` (`router.rs`, `cloud.rs`, `egress.rs`).
- **GAP:** the tier *boundaries* (which model sizes, the exact latency budgets) are stated in
  the spec as targets; they are not yet validated by recorded benchmarks (no `benches/` exist).
