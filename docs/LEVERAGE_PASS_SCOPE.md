# Leverage Pass Scope

Status: active branch `infra/leverage-pass`
Date: 2026-06-11

## Intent

The leverage pass reconciles the Phase 3B quality review into one runtime-centered slice. The goal is not to widen Delphi into the full custom OS yet. The goal is to convert the hardened substrate into a local, persistent runtime that can prove one living workflow end to end.

Implementation moves through four labels:

- `Designed`: intent, interface, or design exists.
- `Built`: library/module exists and has local tests.
- `Wired`: reachable through the runtime or shell bridge.
- `Proven`: exercised as a real workflow with receipts, timeline state, and verification.

## Reconciled Review Inputs

The WIP review in `C:/dev/Delphi-quality/docs/CODEBASE_REVIEW.md` is folded into this pass rather than run as a second branch. Relevant leverage findings:

| Review item | Leverage-pass disposition |
| --- | --- |
| `WS-1`: no executable target; `delphi-daemon` missing | Address now with a minimal local-dev daemon owning shared runtime state. |
| `SFS-1`: semantic-fs incremental correctness gap | Top-priority follow-up, but not inside the first daemon slice unless needed for the proof workflow. |
| Built-but-unwired security and learning surfaces | Track in the capability ledger and wire only the first workflow path now. |
| `INF-1`, `BVB-3`, `BVB-4`, `FORT-Q4` | Security-sensitive candidates. Triage separately before implementation. |
| Shell/timeline/learning surfaces exist but are partial | Use them as the living surface for runtime status, progress, receipts, and learning candidates. |

## Capability Ledger

| Capability | Current label | Reason | Leverage-pass target |
| --- | --- | --- | --- |
| `delphi-daemon` runtime spine | Designed | `CLAUDE.md` requires collective start, but no binary existed. | Built and Wired in local-dev mode. |
| Shell WebSocket bridge | Built | Server and handler exist with tests. | Wired to runtime/action APIs on `127.0.0.1:9800`. |
| Inference router | Built | Router exists and is surfaced through bridge status/query. | Wired as shared daemon state. |
| Semantic file search | Built | Indexer and bridge search exist. | Wired as shared daemon state; correctness follow-up remains open. |
| Timeline / undo receipts | Built | Timeline supports pending, complete, partial, undoing, undone, irreversible. | Proven for first developer workflow with pending-before-execute and terminal receipt. |
| Learning facade | Built | Focus gate and accept-to-practice semantics exist. | Wired to workflow episodes; proof stays Assisted/Practicing, not autonomous. |
| Mode map / Focus mode | Wired | D-Bus and bridge mode changes arm the learning facade. | Proven that Focus blocks workflow observation. |
| Developer workstation workflow | Designed | Workflow intent is defined but not implemented. | Proven: inspect repo, run approved checks, summarize result, propose next step. |
| Fortress vault / encryption service | Built/Designed mix | Vault exists, encryption service remains stub/unwired. | Not in this slice; tracked as a hardening follow-up. |
| Permission/Auth guard | Built | Services auth exists; WebSocket caller binding follow-up remains. | No broad autonomy until caller identity is complete. |
| Living shell surfaces | Built-but-unwired | Timeline, learning, cloud consent, task progress surfaces exist. | Wire to new bridge methods as additive API; UI polish remains later. |
| Custom Delphi OS distribution | Designed | North-star target remains Linux-based Delphi OS. | Explicitly out of scope for this unit. |

## First Proven Workflow

Workflow: `developer_repo_check`

Input:

- repository path
- optional approved test/check command as an argv array
- server-issued one-shot approval token bound to workflow, repository path, argv, timeout, and expiry

Steps:

1. Plan the exact request and mint an approval token if the request is executable.
2. Consume the approval token once before execution.
3. Record a pending timeline entry before execution.
4. Inspect project context.
5. Run `git status --short`.
6. Run `git log --oneline -5`.
7. Run the approved check command if provided.
8. Verify by command exit statuses.
9. Finalize the timeline entry as complete or failed.
10. Return an `ActionReceipt` with status, redacted output summary, timeline id, undo status, and verification result.
11. Observe a metadata-only learning episode unless Focus mode is active.

Promotion rule:

- First run is Assisted.
- Accepting a learning suggestion moves it to Practicing.
- No workflow becomes Autonomous in this pass.

## Out Of Scope

- Production installer, systemd units, distro packaging, and kernel work.
- Broad autonomy or unapproved destructive tools.
- New cloud paths, browser navigation policy changes, SSI execution, or Fortress rewrites.
- Semantic-fs correctness repair unless it blocks the workflow proof.

## Review Gate

This pass introduces controlled local command execution behind one-shot approval capabilities. Before merging beyond local development, run the existing adversarial review protocol for tool execution changes and the normal verification gate:

- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cd shell && pnpm test --run && pnpm build`
