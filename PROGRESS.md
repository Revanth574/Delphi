# Delphi OS — Progress State

Last updated: 2026-04-25 (Task 3A.3 complete — fidelity-first ambient environmental awareness shipped, self-audit re-run; CLAUDE.md gained Iron Law #13 + Fidelity-declarations subsection at commit `9313e16`)
Current phase: Phase 3A (in progress — tasks 3A.1, 3A.2, 3A.3 complete; task 3A.4 is next)
Current task: 3A.4 — Predictive crisis prevention (not yet started)
Current step: Begin `die/orchestrator/src/health.rs` — SMART data probes, crash-frequency analysis, deadline-risk synthesis with goal graph, security monitoring, D-Bus `org.delphi.Health`, 15+ tests
Status: not started (3A.3 just landed at commit `62201ee`)
Tests passing: **1,269 verified 2026-04-25** (1,196 Rust + 73 TypeScript), 0 failures, 0 clippy warnings

## Completed phases

- Phase 0: bootstrap Cargo workspace (6 crates) — commit `1c65bcb` — no tag
- Phase 0 continuation: protobuf IPC, fortress, action timeline, shell UI, semantic-fs — commit `5fd5e83` — no tag
- Phase 0 continuation: Wayland compositor, local LLM inference — commit `53a2205` — no tag
- Phase 1+2 (combined, granular split infeasible due to interwoven files — see commit body): inference router, voice, browser, bridge, services, compositor rendering, shell command-bar/timeline/onboarding, die-learning, die-builder, SSI auto-gen, fortress/ZKQP, cross-app orchestration DAG — commit `90a25f8` — tag `v0.3.0-phase2`
- Phase 3A infrastructure: CLAUDE.md Session Recovery Protocol + Phase-end Verification Protocol + Iron Law #11, PROGRESS.md, .gitignore (.claude-flow/, .mcp.json) — commit `4e4f32e` — no tag
- Phase 3A Task 0 (pre-3A.1): CLAUDE.md Section 13 anti-hallucination protocol + Iron Law #12 — commit `dae8bf2` — no tag
- Phase 3A Task 3A.1: persistent conversation memory (`die/orchestrator/src/{conversation,reference}.rs` + `services/src/conversation.rs`; SQLite + FTS5 + WAL, 9-method ConversationStore, ReferenceEntity resolution, 24h/7d/older memory tiering, D-Bus `org.delphi.Conversation`, 49 new tests) — commit `2d67a29` — no tag (end-of-phase-3A tag is `v0.4.0-phase3a`)
- Phase 3A Task 3A.2: goal graph with DAG validation, timeline estimation, and stale detection (`die/orchestrator/src/goals.rs` ~1,100 LOC with 42 tests + `services/src/goals.rs` ~700 LOC with 27 tests; SQLite forest with O(depth) ancestor-walk cycle detection, GoalStatus/Priority/DeadlineRisk enums, GoalPatch `Option<Option<T>>` tri-state for deadline/parent, TimelineEstimator with priority heuristic 7/21/45/90 days + learned-pace sessions/hours model, find_stale + find_approaching_deadline, D-Bus `org.delphi.Goals` at `/org/delphi/Goals` with 10 methods, JSON patch parser for tri-state wire encoding, 4 signal declarations (goal_created / goal_completed / goal_deadline_approaching / goal_stale, each with `timestamp: i64` per D-Bus rule 3), RFC 3339 timestamp encoding) — commit `609826d` — no tag
- Phase 3A pre-3A.3 governance: Iron Law #13 (Highest fidelity wins, lowest fidelity is last resort) + 10-level fidelity hierarchy + Section 4 "Fidelity declarations" subsection requiring per-module declared probe order — commit `9313e16` — no tag
- Phase 3A Task 3A.3: ambient environmental awareness with fidelity-first sensor probing (`die/orchestrator/src/environment.rs` ~1,970 LOC with 69 tests + `services/src/environment.rs` ~620 LOC with 18 tests; `Fidelity` enum {Direct, NativeApi, Subprocess, Unavailable} threaded through every reading, layered battery probe (BAT*/uevent → per-field capacity/status fallback) with BAT* glob (verified against WSL2 BAT1, not hardcoded BAT0), thermal zones with cooling-device + 85°C throttling heuristic, /proc/meminfo with optional /proc/pressure/memory PSI augmentation, integer-math pressure-level boundaries at exactly 40/20/10%, `PressureLevel`/`PowerState`/`TimeBand`/`ActivityState` enums with wire-stable `as_str()`, `df -P /` subprocess for disk usage, `nmcli -t -f active,ssid` subprocess for WiFi SSID, direct sysfs read for wired detection, TOML LocationMap with SSID precedence over wired fallback under `dirs::data_local_dir()`, pure `classify_activity` precedence Idle (strict-`>`) → Meeting (mic beats Gaming) → Gaming (fullscreen + GPU ≥ 70%) → DeepWork → CasualBrowsing → Unknown, `EnvironmentSensor` trait with `LinuxSensor::with_roots(sys, proc)` for tempfile-based mock filesystem trees, `EnvironmentMonitor::snapshot()` composes a single `EnvironmentState` carrying per-domain Fidelity, D-Bus `org.delphi.Environment` at `/org/delphi/Environment` with 8 methods (GetState/GetBattery/GetThermal/GetMemory/GetTimeContext/GetLocation/SetLocationLabel/RemoveLocationLabel) and 6 signal declarations (BatteryLow/ThermalWarning/MemoryPressureHigh/TimeBandChanged/LocationChanged/ActivityStateChanged), no `#[cfg(target_os)]` gating — sensors return Fidelity::Unavailable on missing paths/binaries so the workspace `cargo check` passes on Windows) — commit `62201ee` — no tag

## Active work

- **Last action (2026-04-25):** added Iron Law #13 (Highest fidelity wins) + Section 4 fidelity-declaration requirement to CLAUDE.md at `9313e16` (62 insertions, 13 Iron Laws total in Section 12, "Fidelity declarations" appears once at line 402). Then landed Task 3A.3 — ambient environmental awareness — at `62201ee` (8 files, 2,586 insertions / 2 deletions): created `die/orchestrator/src/environment.rs` (1,970 LOC, 69 tests covering Fidelity enum stability, parse_meminfo / parse_psi_memory / parse_battery_uevent / parse_df_output / parse_nmcli_wifi pure parsers, PressureLevel boundary correctness at 40/20/10%, Battery uevent → capacity-files fallback, BAT* glob (proves not hardcoded BAT0), thermal CPU-zone preference + cooling-device-induced throttling, MemoryInfo PSI augmentation, on-wired sysfs detection, TimeBand boundaries, weekend, LocationMap TOML round-trip, activity-classifier precedence including mic-beats-gaming and idle-strict-greater-than, MockSensor monitor composition); created `services/src/environment.rs` (620 LOC, 18 tests covering JSON shape per domain, Fidelity provenance preserved on every reading, default-observation sentinel, location-label set/remove/persist, activity classification round-trip); wired `pub mod environment;` into both `die/orchestrator/src/lib.rs` (alphabetical between `conversation` and `error`) and `services/src/lib.rs` (alphabetical between `conversation` and `file_search`, plus updated "All 7 interfaces" → "All 8 interfaces"); promoted `tempfile = "3"` to `[workspace.dependencies]` and switched die-inference + die-orchestrator dev-deps to `tempfile = { workspace = true }`; added `OrchestratorError::Environment(String)` for graceful sensor errors. Section 13.4 self-audit: `cargo check --workspace` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean (one initial `manual_split_once` warning fixed at root cause to a `let-else continue` form preserving robustness against malformed input), `cargo test --workspace` summed via Python regex over `/tmp/test_results.txt` = **1,196 passed / 0 failed / 0 ignored** (+87 vs. 3A.2 baseline of 1,109; matches 69 + 18 = 87 new tests exactly), `pnpm test --run` Windows-side = **73 passed / 0 failed**. Total **1,269 tests passing**. Pre-flight verification on WSL2 Ubuntu-24.04 confirmed BAT1 (not BAT0) under `/sys/class/power_supply/` with 22 individual capacity-related files, no `thermal_zone*` directories on WSL Hyper-V (only 12 cooling_devices labeled "Processor"), `/proc/meminfo` has all expected fields, `/proc/pressure/memory` exists with PSI data, neither `nmcli` nor `iwgetid` is installed (graceful Fidelity::Unavailable path is primary on this dev box) — these reality checks shaped the implementation directly per Iron Law #13 and CLAUDE.md §13.2.
- **Next action:** begin Task 3A.4 — predictive crisis prevention. Module `die/orchestrator/src/health.rs` — SMART data probes (smartctl subprocess; declared upgrade to libatasmart Direct), crash-frequency analysis (parse `/var/log/journal/` or systemd-coredump output), deadline-risk synthesis with the existing goal graph (cross-module call to `goals::find_approaching_deadline`), security monitoring (failed-login frequency, sudo audit log), D-Bus `org.delphi.Health` wrapper in `services/src/health.rs` with severity-banded signals. Target 15+ tests. Per Iron Law #13: declare every fidelity level in the module doc comment.
- **Uncommitted WIP:** none — clean working tree at `62201ee`.
- **Verification artefacts (this session):** Iron Law count verified by `awk '/^## Section 12/,/^## Section 13/' CLAUDE.md | grep -cE "^[0-9]+\\. \\*\\*"` → 13. Test totals verified by Python regex parser over `/tmp/test_results.txt` (avoiding awk-escape mangling in nested WSL bash). Battery glob fix verified by test `battery_uevent_path_is_glob_not_hardcoded` which mock-builds BAT1 (not BAT0). All numbers above come from commands executed this session, not memory.

## Workspace crate layout (13 Cargo members + shell React app)

```
compositor/             # Wayland compositor (Smithay)
proto/                  # Protobuf IPC definitions
shell-bridge/           # React <-> D-Bus WebSocket bridge
services/               # D-Bus service wrappers (8 interfaces: conversation, environment, file_search, goals, inference, learning, mode, timeline)
fortress/               # Security layer (incl. zkqp/)
semantic-fs/            # Indexed file search
die/orchestrator/       # Central brain + planner + timeline + apps + brain
die/inference/          # Three-tier inference router + cloud
die/browser/            # Playwright headless Chromium
die/builder/            # Full-stack project builder
die/voice/              # Whisper STT + Piper TTS
die/learning/           # Universal learning engine
ssi/sdk-rust/           # Rust SSI SDK
(shell/ — React 19 + TypeScript + Vite + Tailwind, not a Cargo member)
```

## Capability tracker (mirror of CLAUDE.md Section 11)

| # | Capability | Status | Phase |
|---|-----------|--------|-------|
| 1 | Behavioral learning engine | Phase 2 complete (built + tested) | 0+2 |
| 2 | Deep internet agency | Phase 1 complete (built + tested) | 1 |
| 3 | Multi-specialty reasoning | Partial — router exists; specialist mesh → Phase 3 | 3 |
| 4 | Infinite task chaining | Phase 1+2 complete (brain + checkpoints + apps) | 1+2 |
| 5 | Conversational presence | **Task 3A.1 complete** — persistent memory + FTS + reference resolution + memory tiering shipped at `2d67a29`; voice I/O from Phase 1 | 3A |
| 6 | Goal and planning architecture | **Task 3A.2 complete** — goal graph + timeline estimation + stale/deadline detection + D-Bus `org.delphi.Goals` shipped at `609826d` | 3A |
| 7 | Full-stack builder | Phase 2 complete (built + tested) | 2 |
| 8 | Client/company workspace adaptation | Not started | 3B |
| 9 | Sovereign local intelligence | Partial — Fortress + ZKQP built | 0+2 |
| 10 | Non-interference philosophy | Encoded (no code) | 0 |
| 11 | Endurance and resilience | Partial — checkpointing exists; rolling context → 3B | 3B |
| 12 | Ambient environmental awareness | **Task 3A.3 complete** — fidelity-tagged sensors (battery / thermal / memory / disk / time / location / activity) + D-Bus `org.delphi.Environment` shipped at `62201ee` | 3A |
| 13 | Predictive crisis prevention | **Task 3A.4** | 3A |
| 14 | Relationship intelligence | Not started | 3B |
| 15 | Cross-device federated sync | Not started | 3B |
| 16 | Temporal intelligence | Not started | 3B |
| 17 | Knowledge synthesis engine | **Task 3A.5** | 3A |
| 18 | Generative workspace creation | **Task 3A.6** | 3A |

## Fortress tracker (mirror of CLAUDE.md Section 11)

| Layer | Name | Status | Phase |
|-------|------|--------|-------|
| 1 | Hardware root of trust (TPM) | Not started | 3B |
| 2 | LUKS2 + hidden volumes | Partial (LUKS2 basic); hidden volumes deferred | 3B |
| 3 | ZKQP | Phase 2 complete (built + tested) | 2 |
| 4 | FHE | Not started | 3+ |
| 5 | Federated behavioral sync | Not started | 3B |
| 6 | zk-SNARK audit proofs | Not started (SHA-256 precursor exists) | 3+ |
| 7 | Post-quantum cryptography | Not started | 3B |

Currently implemented: AES-256-GCM vault, Argon2id key derivation, SHA-256 audit chain, 4-tier permission model, ZKQP.

## Phase 3A task list

- **3A.0** — verification baseline + commit/tag Phase 1+2 ✅ **complete** (combined into `v0.3.0-phase2`)
- **3A.1** — Persistent conversation memory (`die/orchestrator/src/conversation.rs` + `reference.rs` + `services/src/conversation.rs` — SQLite with FTS5 + WAL, reference resolution, memory tiering, "forget today"/"forget topic"/"forget older than", D-Bus `org.delphi.Conversation`, 49 tests) — ✅ **complete** at commit `2d67a29`
- **3A.2** — Goal and planning architecture (`die/orchestrator/src/goals.rs` + `services/src/goals.rs` — DAG with O(depth) cycle detection, priority heuristic (7/21/45/90 days) + learned-pace timeline estimator, DeadlineRisk banding (OnTrack/Tight/AtRisk/Missed/NoDeadline), stale detection, D-Bus `org.delphi.Goals` with tri-state JSON patch and 4 signal declarations, 42 + 27 tests) — ✅ **complete** at commit `609826d`
- **3A.3** — Ambient environmental awareness (`die/orchestrator/src/environment.rs` + `services/src/environment.rs` — fidelity-tagged sensors, layered battery probe, /proc/meminfo + PSI, TOML LocationMap, activity classifier, D-Bus `org.delphi.Environment` with 8 methods + 6 signal declarations, 69 + 18 = 87 tests) — ✅ **complete** at commit `62201ee`
- **3A.4** — Predictive crisis prevention (SMART data, crash frequency, deadline risk, security monitoring, D-Bus `org.delphi.Health`, 15+ tests)
- **3A.5** — Knowledge synthesis engine (`KnowledgeNode` + `KnowledgeEdge`, LanceDB vectors, contradiction detection, D-Bus `org.delphi.Knowledge`, 20+ tests)
- **3A.6** — Generative workspace creation (natural language → complete project, smart additions, calendar integration, D-Bus `org.delphi.Workspace`, 15+ tests)
- **End of Phase 3A** — phase-end verification protocol (CLAUDE.md Section 8), git tag `v0.4.0-phase3a`, target 1,150+ tests

## Notes

- **Blocker:** None active.
- **Phase 1+2 split caveat:** `git log` shows a single combined commit `90a25f8` for both phases. Granular 16-commit split was infeasible because Phase 2 code is interwoven with Phase 1 files (`services/src/learning.rs` inside the services crate, `shell-bridge/src/handler.rs` has 150+ lines of learning handlers mixed with Phase 1 handlers, `die/orchestrator/src/error.rs` enum has both `BrowserError` and `LearningError` variants). Tagging both v0.2.0-phase1 and v0.3.0-phase2 at the same SHA would have been misleading, so only `v0.3.0-phase2` was created. A later `git rebase -i` with file-level patches can reconstruct the boundary if desired.
- **Remote:** None configured — user to create private GitHub repo and push for off-disk backup.
- **WIP:** none. `dirs` workspace dep landed with 3A.1; `chrono` promoted to workspace dep with 3A.2 (orchestrator + services both depend on it for RFC 3339 encoding and deadline arithmetic); `tempfile = "3"` promoted to `[workspace.dependencies]` with 3A.3 (orchestrator + inference dev-deps now share it for tempdir-backed mock-filesystem tests).
- **Dev environment:** Windows host (source of truth), WSL2 Ubuntu-24.04 at `/home/raven/delphi` mirror for cargo operations (Smithay/llama-cpp-2 need Linux system libs). Shell (pnpm) works on either. `rsync -a --delete --exclude='target/' --exclude='node_modules/' --exclude='.claude/' --exclude='.claude-flow/' --exclude='.mcp.json' /mnt/c/Users/kvlnr/OneDrive/Desktop/Delphi/ /home/raven/delphi/` syncs Windows → WSL.
- **Anti-hallucination protocol:** CLAUDE.md Section 13 in effect. All test counts, commit counts, and codebase claims must come from executed commands in the current session. Section 13 + Iron Law #12 landed at commit `dae8bf2`. The 3A.2 session-report numbers (1,109 Rust tests, 73 TS tests, 42 + 27 = 69 new unit tests, 4,044 insertions) were all produced by commands executed this session (`cargo test --workspace`, `pnpm test --run`, `grep -cE`, `git diff --stat`, `git show --stat 609826d`).
- **Phase 3A.2 zbus 5.x signal pattern (for future reference):** signal declarations live inside the `#[interface]` impl block as `#[zbus(signal)] async fn name(signal_emitter: &SignalEmitter<'_>, ...) -> zbus::Result<()>;` with no body and no `&self`. The macro generates both the introspection XML entry and the emission method on `SignalEmitter<'_>`. Emission requires a live `Connection`, so the services wrapper declares signals (for introspection completeness + unit-testability without a bus) and defers actual emission to the orchestrator daemon that owns the `SignalEmitter`.
- **Phase 3A.3 fidelity-first design notes (for future reference per Iron Law #13):** every external-source integration must declare its fidelity hierarchy in module doc comments and probe top-down (highest fidelity first; fall back on failure with a `tracing::debug!` log). The `Fidelity` enum is wire-stable via `as_str()` so D-Bus consumers can filter or weight readings. `Fidelity::Unavailable` is the cross-platform default — sensors return it when target paths/binaries don't exist, which is how the module compiles cleanly on Windows without `#[cfg(target_os = "linux")]`. Cross-platform compile is achieved through `Path` being platform-agnostic and `Command::new("missing-binary")` returning `Err` (mapped to Unavailable). Per-domain Fidelity provenance (one Fidelity per BatteryInfo / ThermalInfo / MemoryInfo / LocationContext, plus a `disk_fidelity` field on EnvironmentState) is finer-grained than per-state and gives consumers actionable provenance for each subdomain. The activity classifier is a pure function with no I/O — observations come from compositor + learning observer wiring (a future task) and the classifier just maps observations → ActivityState. WSL Hyper-V dev-system caveat: `/sys/class/thermal/` exposes only `cooling_device*` (12 of them, all type "Processor"), no `thermal_zone*`, so on this dev box thermal readings are legitimately Fidelity::Unavailable; the same code on a real laptop will return Fidelity::Direct.
