# ADR 0001: Linux-first, cross-OS deferred to Phase 3C

- **Status:** Accepted
- **Date:** — (starting-point assumption; not recorded as a dated decision)
- **Deciders:** Delphi maintainers

## Context

Delphi targets an agentic OS that ultimately runs cross-platform (Linux, macOS, Windows). The
current codebase had to start somewhere. The compositor is built on Smithay, a Wayland
compositor library, which is Linux-specific; per-OS accessibility APIs, a cross-platform UI
layer, and per-OS hardware security integrations (TPM, Secure Enclave) are substantial work.

## Decision

Build the first deployment Linux-first. Defer cross-OS expansion to Phase 3C, and make
substrate decisions from now on with all three platforms in mind (so the deferral does not
become a rewrite).

## Consequences

- The compositor and any Wayland-coupled code are Linux-only today; off-Linux builds use
  `cargo … --exclude compositor`.
- File-path and platform code must use the `dirs` crate rather than hardcoded XDG layouts so
  the cross-OS move is mechanical (a known violation exists — see INF-6 in the review).
- Cross-OS adds substantial Phase 3C scope (per-OS accessibility, Tauri-style UI, per-OS
  Fortress hardware integration, tri-platform CI). This is the acknowledged cost of preserving
  consumer launchability.

## Grounding (recorded history)

- `CLAUDE.md` "Architectural risk mitigations" → *Multi-OS support from Phase 3C* ("The current
  Linux-targeted compositor work is the first deployment; cross-OS expansion in Phase 3C") and
  the "Cross-OS expansion adds substantial Phase 3C scope" acknowledgment.
- The compositor crate depends on Smithay (Wayland) — Linux coupling is in the code, not just
  the docs.
- **GAP (documentation, not substance):** the Linux-first choice may well have been
  well-reasoned — Smithay maturity, a single platform to harden first, solo-founder capacity.
  That reasoning was simply never written as a decision record; only the standing commitment is
  in `CLAUDE.md`. This ADR documents the commitment **as recorded** — it does not reconstruct,
  and does not second-guess, the original deliberation. "Rationale not recorded" here means
  *undocumented*, not *unconsidered*.
