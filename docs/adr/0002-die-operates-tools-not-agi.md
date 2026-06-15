# ADR 0002: The engine operates the user's tools (not an AGI)

- **Status:** Accepted
- **Date:** —
- **Deciders:** Delphi maintainers

## Context

There are two postures an "AI OS" can take: build a general intelligence that *generates*
outputs, or build an agent that *operates the user's existing software* to produce native
artifacts. The distinction shapes the entire architecture — and the value proposition against
frontier labs and OS incumbents.

## Decision

Delphi is an agentic OS that operates whatever software the user already has, on their behalf.
The user provides intent and judgment; Delphi provides skilled tool-use and execution. When
asked to "draw a picture," Delphi operates a real tool (e.g. Photoshop) to produce an actual
editable file with real layers — not a generated PNG. Heavy reasoning may call out to cloud
frontier models, but tool-use happens locally and outputs are native artifacts in the user's
real applications.

## Consequences

- The hard engineering problem becomes *reliable tool operation* (see ADR-0004 on fidelity),
  not model training. Delphi's value depends on being reliable at complex workflows, which is
  why low-fidelity screen-scraping is a last resort, not a default.
- Delphi never depends on a single AI lab — multi-vendor frontier support is architectural.
- "DIE" is the Delphi Intelligence Engine (orchestration + tool-use), explicitly *not* an AGI
  claim. Capability is bounded by what tools exist and what the engine can drive.

## Grounding (recorded history)

- `CLAUDE.md` "Delphi Vision and Architecture" → *The North Star* ("operates the user's
  existing software tools on their behalf… The user provides intent and judgment; Delphi
  provides skilled tool-use and execution") and the Photoshop/PowerPoint examples there.
- `CLAUDE.md` Iron Law #14 ("Capabilities must not retreat from the North Star") encodes this
  as a standing constraint on every change.
- Multi-vendor commitment: `CLAUDE.md` "Architectural risk mitigations" → *Multi-vendor
  frontier model support*.
