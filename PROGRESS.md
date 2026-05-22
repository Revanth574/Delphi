# Delphi OS — Progress State

Last updated: 2026-05-22 (Task 3A.6 complete — generative workspace creation + five rounds of Codex adversarial security hardening shipped; 14 findings across R1–R5 resolved; merged to main at merge commit `29ddf85` with umbrella tag `v0.4.0-phase3a`. **Phase 3A formally complete.**)
Current phase: Phase 3A **complete** — all six tasks 3A.1–3A.6 shipped; Phase 3B ready to open
Current task: none — Phase 3A closed; Phase 3B planning begins as a separate task
Current step: Phase 3B opens with foundation-plus-specialization substrate work, retroactive Codex sweep across existing crates, the foundation-model validation experiment, and first-customer identification per the "Delphi Vision and Architecture" direction (commit `2381a99`)
Status: complete (3A.6 merged to main via `git merge --no-ff` at merge commit `29ddf85`; umbrella tag `v0.4.0-phase3a` at the merge commit; remote feature branch retained for the post-merge issue window, to be deleted at Phase 3B start)
Tests passing: **1,748 verified 2026-05-22** (1,655 Rust + 93 TypeScript — Rust from `cargo test --workspace` this session summed to 1,655 with 0 failures across 26 binaries; TS from `pnpm test --run` = 93), 0 failures, 0 clippy warnings (`cargo clippy --workspace --all-targets -- -D warnings` rc=0)

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
- Phase 3A pre-3A.4 governance: feature-branch workflow rule (`phase-{N}/{task-name}` branches with `git merge --no-ff` to main, replacing the old "Branch Naming" subsection in CLAUDE.md Section 6) — commit `10d5932` on the 3A.4 branch — merged via `188516c`
- Phase 3A pre-3A.4 governance: mandatory Codex security review protocol (CLAUDE.md Section 8 new subsection — explicit determination required at end of every task with NOT REQUIRED / REQUIRED — running now states; trigger list covers fortress/, services/-auth, die/orchestrator/ ZKQP/permissions/vault/cloud, ssi/ capability execution, new external network calls, and every phase boundary; explicit "merge only after review" workflow) — commit `ea39c1a` on the 3A.4 branch — merged via `188516c`
- Phase 3A Task 3A.5: knowledge synthesis engine + nine rounds of Codex adversarial security hardening (`die/orchestrator/src/knowledge.rs` ~6,300 LOC with **436 tests** covering KnowledgeNode/KnowledgeEdge graph data model, SQLite + LanceDB hybrid storage, content-hash deduplication with format-aware uniqueness key, openat2 RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH path safety, schema migration with version table + atomic FK check + AUTOINCREMENT preservation, retry-with-backoff opener loop for bounded multi-process contention; `die/orchestrator/src/sqlite.rs` shared SQLite-policy module providing `SQLITE_BUSY_TIMEOUT`, `init_sqlite_connection`, and `map_sqlite_err` so every store routes lock errors through one canonical helper; `services/src/knowledge.rs` D-Bus `org.delphi.Knowledge` wrapper; sibling stores (`timeline.rs`, `goals.rs`, `conversation.rs`) all migrated to the shared helpers; 23 Codex adversarial-review findings F4–F26 resolved across nine review rounds — see "Task 3A.5 nine-round adversarial-security-hardening history" section near end of file for per-round finding ledger) — feature-branch tip `1482f51` followed by cleanup commits (Cargo.lock libc, this PROGRESS.md entry) — merged to main via the `v0.4.0-phase3a-3a5` tag commit
- Phase 3A Task 3A.6: generative workspace creation (capability #18, final 3A task) + **five rounds of Codex adversarial security hardening (14 findings across R1–R5)** (`die/orchestrator/src/workspace/{spec,validator,templates,executor,dbus}.rs` + `services/src/workspace.rs` + shell `src/workspaces/*` + workspace methods in `src/services/delphi-client.ts`; hybrid template architecture — 4 compile-time-audited baseline templates (research/code/document/design) as the trusted fast path, plus cloud-inferred custom specs validated through a strict `WorkspaceSpec` safety validator before any filesystem mutation; `COMMAND_ALLOWLIST` reduced to git/cargo/uv `init` only (R1 removed npm/pnpm/conda, R3 removed python after the `-m` cwd-module-execution finding); `ALLOWED_LEAF_DOTFILES` deny-by-default dot-prefix path policy (R5 — permits only inert leaf `.gitignore`/`.gitkeep`/`.gitattributes`, blocking the `.git/config` → `init.templateDir` exfiltration vector); openat2 `RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH` path-safe execution with `O_NOFOLLOW|O_EXCL` leaf creation; record-before-execute `Pending` timeline state + symmetric `Undoing` undo; unconditional SIGKILL-to-PGID timeout teardown (R2); `env_clear()`+PATH-only command environment; comprehensive Unicode path sanitation via the `General_Category` property table (R2) incl. variation selectors through U+180F (R3); D-Bus `org.delphi.Workspace` with Preview/Create/CreateFromTemplate/ListTemplates/Undo; dry-run preview UI with Pending/Complete/PartiallyCompleted status surfacing; findings R1 (3 P1 + 6 P2), R2 (2 P2), R3 (1 P1 + 1 P3), R4 (1 P2), R5 (APPROVED, 0 findings) — full per-round ledger in the merge commit `29ddf85` message body) — implementation `201aafe`, review-fix commits `2865d3b` (R1) / `4c2d013` (R2) / `9aa1a1b` (R3) / `5fbd425` (R4-fix, R5-APPROVED), merged to main via merge commit `29ddf85` under umbrella tag `v0.4.0-phase3a`
- Phase 3A Task 3A.4: predictive crisis prevention with baseline-based anomaly detection (`die/orchestrator/src/health.rs` ~1,420 LOC with 38 tests + `die/orchestrator/src/risk.rs` ~1,040 LOC with 29 tests + `services/src/health.rs` ~420 LOC with 20 tests; `Severity` enum {Info<Warning<Critical<Emergency} with derived `Ord`, `HealthFinding` carrying `Fidelity` provenance + optional `baseline_context`, rolling `Baseline` window (1024 samples default, BASELINE_SUFFICIENT_THRESHOLD=100, median + population std_dev + is_anomalous), `DiskHealthMonitor` discovering /sys/block, running `smartctl --json -A`, parsing JSON for ATA reallocated_sectors/wear/temperature + NVMe percentage_used (declared upgrade to NVMe-CLI ioctl), `ProcessMemoryMonitor` tracking per-PID RSS over time and flagging monotonically non-decreasing series ≥10% growth across LEAK_MIN_SAMPLES=6 observations, `CrashMonitor` running `journalctl --since --output=json` and aggregating systemd-coredump MESSAGE_ID + oom-killer messages with severity scaling 1/2-4/5+, `DependencyMonitor` + `KnownVulnerableDatabase` running dpkg-query -W with stub refresh hook, pure parsers `parse_smartctl_json`/`parse_proc_status_for_rss`/`parse_journalctl_json_lines`/`parse_dpkg_query_lines`, `GitStatus` + `parse_git_status_porcelain_v2` (verified actual git format: type-1 lines have 8 tokens after "1 " prefix, type-2 has 9 with new<TAB>old in last token), `oldest_mtime_age` filesystem-mtime walker, `GoalRiskMonitor` integrating with 3A.2 GoalStore for deadline-vs-progress findings (DEADLINE_NEAR_DAYS=14, DEADLINE_IMMINENT_DAYS=7, passed-deadline Critical), `TcpState` enum + `parse_proc_net_tcp` with `parse_ipv4_hex` correctly handling kernel byte-order reversal (verified against actual WSL output: `3500007F`→`127.0.0.53`), `NetworkRiskMonitor` with `ExpectedDestination` allow-list + auto-allow loopback/link-local, `UsbRiskMonitor` polling /sys/bus/usb/devices and emitting Info on first observation only, `CrisisMonitor` composing all monitors with `check_quick`(no-subprocess) + `check_all`(everything) + free-fn `check_all_with_goals`, D-Bus `org.delphi.Health` at `/org/delphi/Health` with 8 methods (CheckAll/CheckQuick/GetDiskHealth/GetProjectRisk/GetSecurityRisk/AddWatchedRepo/RemoveWatchedRepo/AddExpectedNetworkDestination) and 2 signal declarations (HealthFindingDetected/BaselineEstablished), additive change to environment.rs adding `Default` impl to `Fidelity` enum with `Unavailable` as the natural default, no `#[cfg(target_os)]` gating — Codex security review NOT REQUIRED determination per the new §8 protocol since all probes are read-only with no fortress/services-auth/ZKQP/permission-tier/vault/cloud-routing/ssi/network-call changes) — commit `b6864f9` on feature branch — merged to main via `188516c`

## Active work

- **Last action (2026-05-22):** Task 3A.6 (generative workspace creation, capability #18 — the final Phase 3A task) shipped after five rounds of Codex adversarial security review. Implementation `201aafe` on branch `phase-3a/task-3a6-generative-workspaces`, then four review-fix commits: `2865d3b` (R1: 3 P1 + 6 P2 — npm/pnpm/conda allowlist removal, record-before-execute Pending state, symmetric undo, comprehensive path sanitation, process-group cleanup), `4c2d013` (R2: 2 P2 — unconditional SIGKILL-to-PGID after grace, Unicode `General_Category` property-table sanitation), `9aa1a1b` (R3: 1 P1 + 1 P3 — python `-m venv` allowlist removal + remaining-allowlist audit under the env_clear() regime, U+180F variation-selector precision), `5fbd425` (R4 P2 fix — the `ALLOWED_LEAF_DOTFILES` surgical dot-prefix path policy closing the `.git/config` → `init.templateDir` config-discovery exfiltration vector). Round 5 returned **0 findings — APPROVED**. Merged to main via `git merge --no-ff` at merge commit `29ddf85`; umbrella tag `v0.4.0-phase3a` created at the merge commit and pushed to origin. §13.4 self-audit at close: `cargo clippy --workspace --all-targets -- -D warnings` rc=0, `cargo test --workspace` = **1,655 Rust passed / 0 failed** (26 binaries, summed via Python over per-binary `test result:` lines; +14 vs. the pre-R5 1,641 — itself the R4-corrected baseline after R3's reported 1,629 was found to undercount by 9 via `git diff HEAD` test-fn counting), `pnpm test --run` Windows-side = **93 TS passed / 0 failed**, `pnpm build` clean. WSL2 Ubuntu-24.04 alignment verified at every round boundary including the cfg(unix) process-group descendant-kill and openat2 path-safety tests. Key architectural decision in R5: diverged from the original fix prompt's blanket leading-dot rejection (which would have failed all 4 templates that ship `.gitignore` plus the design template's 3 `.gitkeep`) to a surgical inert-leaf allowlist — surfaced to and approved by the user mid-task; templates unchanged.
- **Previous action (2026-05-16):** Task 3A.5 (knowledge synthesis engine) shipped after nine rounds of Codex adversarial security review. The feature branch `phase-3a/task-3a5-knowledge-synthesis` carried twelve production-fix commits (F4–F26, the rounds 1–9 review iterations) plus two cleanup commits (Cargo.lock for the carried-forward FIX-15 libc delta at `2b52f7e`, this PROGRESS.md update for the nine-round history). All 23 findings (P1-high through P2-low across services-side input validation, orchestrator-side path safety, SQLite schema migration correctness, multi-process opener contention, and project-wide policy completeness) closed and verified with the round-9 final Codex PASS verdict. Section 13.4 self-audit: `cargo check --workspace` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo test --workspace` = **1,471 passed / 0 failed / 0 ignored** (+188 vs. 3A.4 baseline of 1,283; +5 in this round-9 commit alone). Pre-merge test count verified by Python regex parser over per-binary `test result:` lines summed to literal `Total: 1471`. WSL2 Ubuntu-24.04 alignment verified at every round boundary. The rsync-residue stash (`ef33afd`, "On main: rsync-residue-pre-round-6-sync 2026-05-14, safe to drop after verification") was preserved as the recovery handle through rounds 6–9 and dropped only after the merge + tag landed. The nine-round adversarial-review methodology — cold-reviewer Codex prompts with mandatory tool grounding via Context7 + Codex CLI — establishes documented precedent for Fortress layer work in Phase 3B.
- **Previous action (2026-04-25):** Task 3A.4 (predictive crisis prevention) shipped via the new feature-branch workflow. The branch `phase-3a/task-3a4-crisis-prevention` carried three commits: `10d5932` (CLAUDE.md branch-workflow rule replacing old "Branch Naming" subsection), `ea39c1a` (CLAUDE.md mandatory Codex security review protocol with Step 1-4 procedure), and `b6864f9` (the 3A.4 implementation: 6 files, 2,887 insertions / 2 deletions — `die/orchestrator/src/health.rs` 1,420 LOC with 38 tests, `die/orchestrator/src/risk.rs` 1,040 LOC with 29 tests, `services/src/health.rs` 420 LOC with 20 tests, plus module wiring in two lib.rs files and the additive `Default` impl on `Fidelity`). Merged to main via `git merge --no-ff` at merge commit `188516c` after explicit "Codex security review: NOT REQUIRED" determination (touched only read-only observation code; no fortress/services-auth/ZKQP/permission/vault/ssi/external-network changes). Section 13.4 self-audit: `cargo check --workspace` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean (two initial warnings — `derivable_impls` on `DependencyMonitor` and `needless_question_mark` in `oldest_mtime_age` — both fixed at root cause), `cargo test --workspace` = **1,283 passed / 0 failed / 0 ignored** (+87 vs. 3A.3 baseline of 1,196; 38 + 29 + 20 = 87 new tests exactly), `pnpm test --run` Windows-side = **73 passed / 0 failed**. Total **1,356 tests passing**. Pre-flight verification on WSL2 Ubuntu-24.04 confirmed: smartctl absent (graceful Unavailable path is primary), /sys/block has sda/sdb/sdc/sdd plus loops/rams (filter test confirms non-real devices excluded), /sys/bus/usb/devices empty on Hyper-V (no false-positive findings), journalctl JSON output structure verified with actual kernel-boot entry, dpkg-query default tab-separated format used (avoids quoting interpolation issues with custom -f format strings), git 2.43.0 present, /proc/net/tcp showed actual systemd-resolved listeners at 127.0.0.53:53 and 127.0.0.54:53 — these exact hex strings (`3500007F:0035`, `3600007F:0035`) are the literal test fixtures verifying the kernel byte-order reversal in `parse_ipv4_hex`. Two test failures during the iteration (`git_porcelain_dirty_repo_classifies_modified_and_staged` and `git_porcelain_handles_renamed_files`) were root-cause-fixed by correcting the splitn field count (porcelain v2 type-1 = 8 fields after "1 " prefix not 9; type-2 = 9 fields not 10) and reversing the test fixture's `<old>\t<new>` to match real git output `<new>\t<old>` per format spec.
- **Next action:** Phase 3B opens as a separate task with its own prompt — do NOT begin Phase 3B implementation from this session. Phase 3B scope (per the "Delphi Vision and Architecture" direction in commit `2381a99`): three-layer personalization substrate (foundation + company + user-role) with up-front architectural design of the layer-composition model; retroactive Codex sweep applying Task 3A.6's threat-model lessons across the existing crates (see "Phase 3B priority items" below); the foundation-model validation experiment measuring capability on the public + synthetic + teacher corpus before betting robustness on customer contributions; structured apprentice-style onboarding framework; accessibility first-class from v0.5; and first-customer identification. Repository cleanup at Phase 3B start: delete the retained remote feature branch `origin/phase-3a/task-3a6-generative-workspaces`.
- **Uncommitted WIP:** none — clean working tree at the tip of `main` post-3A.6-merge (merge commit `29ddf85` plus this PROGRESS.md update committed on top).
- **Verification artefacts (2026-05-22 session):** Rust total verified by `cargo test --workspace 2>&1 | grep 'test result:' | python3 -c '...'` summation = **1,655 passed / 0 failed** across 26 binaries; clippy clean via redirect-captured `clippy_rc=0` on `cargo clippy --workspace --all-targets -- -D warnings`; the +14 delta independently cross-checked via `git diff HEAD` showing exactly 14 added `#[test]` fns. The `--no-ff` merge verified to produce a two-parent merge commit (`29ddf85` — parents `2381a99` + `5fbd425`). TS **93 passed / 0 failed** via `pnpm test --run`, `pnpm build` clean. All counts and commit hashes from commands executed this session, not memory (Iron Law #12 / §13.5).

## Workspace crate layout (13 Cargo members + shell React app)

```
compositor/             # Wayland compositor (Smithay)
proto/                  # Protobuf IPC definitions
shell-bridge/           # React <-> D-Bus WebSocket bridge
services/               # D-Bus service wrappers (9 interfaces: conversation, environment, file_search, goals, health, inference, learning, mode, timeline)
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
| 13 | Predictive crisis prevention | **Task 3A.4 complete** — baseline-based anomaly detection across disk SMART / memory leaks / journal crashes / dependency CVEs / git uncommitted-age / goal deadlines / TCP destinations / USB events + D-Bus `org.delphi.Health` shipped at `b6864f9` (merged via `188516c`) | 3A |
| 14 | Relationship intelligence | Not started | 3B |
| 15 | Cross-device federated sync | Not started | 3B |
| 16 | Temporal intelligence | Not started | 3B |
| 17 | Knowledge synthesis engine | **Task 3A.5 complete** — KnowledgeStore + KnowledgeNode/KnowledgeEdge graph + SQLite hybrid storage + openat2 path safety + atomic schema migration + retry-with-backoff opener + shared `die_orchestrator::sqlite` policy helpers + D-Bus `org.delphi.Knowledge`; hardened across nine rounds of Codex adversarial review (23 findings F4–F26 resolved); merged via tag `v0.4.0-phase3a-3a5` | 3A |
| 18 | Generative workspace creation | **Task 3A.6 complete** — hybrid template architecture (4 compile-time-audited baseline templates + validated cloud-inferred specs), `COMMAND_ALLOWLIST` (git/cargo/uv `init`), `ALLOWED_LEAF_DOTFILES` deny-by-default dot-prefix path policy, openat2 path-safe execution, record-before-execute timeline + symmetric undo, D-Bus `org.delphi.Workspace`; hardened across **five rounds of Codex adversarial review (14 findings R1–R5)**; merged via merge commit `29ddf85` under umbrella tag `v0.4.0-phase3a` | 3A |

**Phase 3A close tally: 10 done / 1 encoded / 3 partial / 4 not-started.** Done: #1, 2, 4, 5, 6, 7, 12, 13, 17, 18. Encoded: #10 (non-interference). Partial: #3 (multi-specialty reasoning), #9 (sovereign local intelligence), #11 (endurance/resilience). Not started — Phase 3B targets per the "Delphi Vision and Architecture" section: #8 (client/company workspace adaptation), #14 (relationship intelligence), #15 (cross-device federated sync), #16 (temporal intelligence).

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
- **3A.4** — Predictive crisis prevention (`die/orchestrator/src/health.rs` + `risk.rs` + `services/src/health.rs` — `Severity` ordered enum, rolling `Baseline` median+std_dev windows, disk SMART probes (smartctl JSON), process memory leak detection (RSS monotonic-climb), crash aggregation (journalctl coredump+oom), dependency CVE comparison (dpkg-query), git porcelain v2 staleness, goal deadline-vs-progress, /proc/net/tcp parsing with verified IPv4 byte-order reversal, USB device tracking, `CrisisMonitor` composing all monitors, D-Bus `org.delphi.Health` with 8 methods + 2 signal declarations, 38 + 29 + 20 = 87 tests) — ✅ **complete** at commit `b6864f9` (merged to main via `188516c` after explicit "Codex security review: NOT REQUIRED" determination)
- **3A.5** — Knowledge synthesis engine (`KnowledgeNode` + `KnowledgeEdge` graph, SQLite hybrid storage, openat2 RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH path safety, atomic schema migration with version table, retry-with-backoff opener loop, shared `die_orchestrator::sqlite` SQLite-policy helpers used by all stores, D-Bus `org.delphi.Knowledge`, 436 tests in knowledge.rs) — ✅ **complete** at feature-branch tip `1482f51` + Cargo.lock cleanup `2b52f7e` + PROGRESS.md cleanup, merged to main via tag `v0.4.0-phase3a-3a5` after **nine rounds of Codex adversarial security hardening (23 findings F4–F26 resolved)**
- **3A.6** — Generative workspace creation (hybrid template architecture: 4 compile-time-audited baseline templates + cloud-inferred specs validated through a strict `WorkspaceSpec` validator, `COMMAND_ALLOWLIST` git/cargo/uv `init`, `ALLOWED_LEAF_DOTFILES` deny-by-default dot-prefix path policy, openat2 `RESOLVE_NO_SYMLINKS` path-safe execution, record-before-execute `Pending` timeline + symmetric undo, D-Bus `org.delphi.Workspace`, dry-run preview UI) — ✅ **complete** at implementation `201aafe` + R1–R5 review fixes (`2865d3b` / `4c2d013` / `9aa1a1b` / `5fbd425`), merged to main via merge commit `29ddf85` after **five rounds of Codex adversarial security hardening (14 findings R1–R5; R5 APPROVED with 0 findings)**
- **End of Phase 3A** — ✅ **complete**: phase-end verification protocol run (`cargo clippy --workspace --all-targets -- -D warnings` rc=0, `cargo test --workspace` = 1,655 Rust / 0 failed, `pnpm test --run` = 93 TS / 0 failed, `pnpm build` clean), umbrella tag `v0.4.0-phase3a` created at merge commit `29ddf85`. Final total **1,748 tests** (1,655 Rust + 93 TS), well past the 1,150+ target.

## Phase 3B priority items (carried from Task 3A.6 five-round review lessons)

The 3A.6 review surfaced a coherent threat model whose lessons should be applied retroactively across existing crates during the Phase 3B Codex sweep:

1. **User-content-execution framing for existing allowlists.** An `(program, argv)` allowlist defends against shell/argv injection but NOT against an allowlisted program executing user-controlled content from its working directory (R1 npm/pnpm/conda lifecycle scripts; R3 `python -m` cwd-module resolution). Audit every existing allowlist / subprocess invocation (die-builder, die-browser, ssi capability execution, semantic-fs indexers) under this framing.
2. **Config-discovery framing for filesystem operations.** `env_clear()`+PATH-only neutralizes environment-based config discovery but does NOT stop a tool from reading workspace-controlled dotfiles (R4 `.git/config` → `init.templateDir` exfiltration). Audit any code that runs a tool with `current_dir` set into user-controlled content; apply the `ALLOWED_LEAF_DOTFILES` deny-by-default dot-prefix policy pattern where applicable.
3. **TDD-soundness audit.** Verify existing security-critical tests actually fail against buggy code (R3 caught a descendant-survival test that passed for the wrong reason because the backgrounded descendant inherited the capture pipes, masking whether cleanup actually killed it). Tests that pass for the wrong reason are worse than no tests.
4. **Python allowlist re-evaluation.** `python` was removed from `COMMAND_ALLOWLIST` entirely in R3. If pilot-user feedback indicates the auto-venv UX is missed, re-evaluate admitting a content-safe pattern (e.g. `python -I -m venv` — `-I` isolated mode drops cwd from `sys.path` — run from a Delphi-controlled directory), with explicit review, since allowlisting a flag-sensitive invocation makes safety hinge on exact argv order.
5. **`.gitattributes` allowlist-scope re-evaluation (Codex R5 forward-looking note).** `.gitattributes` is inert today because the only allowlisted git operation is `git init`. If future allowlist growth admits `git add`/`checkout`/`diff`/`merge`/`archive`, re-evaluate `.gitattributes` in `ALLOWED_LEAF_DOTFILES`: those operations honor `filter`/`diff`/`merge` driver directives that can execute configured commands, which would turn a currently-inert leaf dotfile into a code-execution vector.

## Notes

- **Blocker:** None active.
- **Phase 1+2 split caveat:** `git log` shows a single combined commit `90a25f8` for both phases. Granular 16-commit split was infeasible because Phase 2 code is interwoven with Phase 1 files (`services/src/learning.rs` inside the services crate, `shell-bridge/src/handler.rs` has 150+ lines of learning handlers mixed with Phase 1 handlers, `die/orchestrator/src/error.rs` enum has both `BrowserError` and `LearningError` variants). Tagging both v0.2.0-phase1 and v0.3.0-phase2 at the same SHA would have been misleading, so only `v0.3.0-phase2` was created. A later `git rebase -i` with file-level patches can reconstruct the boundary if desired.
- **Remote:** None configured — user to create private GitHub repo and push for off-disk backup.
- **WIP:** none. `dirs` workspace dep landed with 3A.1; `chrono` promoted to workspace dep with 3A.2 (orchestrator + services both depend on it for RFC 3339 encoding and deadline arithmetic); `tempfile = "3"` promoted to `[workspace.dependencies]` with 3A.3 (orchestrator + inference dev-deps now share it for tempdir-backed mock-filesystem tests).
- **Dev environment:** Windows host (source of truth), WSL2 Ubuntu-24.04 at `/home/raven/delphi` mirror for cargo operations (Smithay/llama-cpp-2 need Linux system libs). Shell (pnpm) works on either. `rsync -a --delete --exclude='target/' --exclude='node_modules/' --exclude='.claude/' --exclude='.claude-flow/' --exclude='.mcp.json' /mnt/c/Users/kvlnr/OneDrive/Desktop/Delphi/ /home/raven/delphi/` syncs Windows → WSL.
- **Anti-hallucination protocol:** CLAUDE.md Section 13 in effect. All test counts, commit counts, and codebase claims must come from executed commands in the current session. Section 13 + Iron Law #12 landed at commit `dae8bf2`. The 3A.2 session-report numbers (1,109 Rust tests, 73 TS tests, 42 + 27 = 69 new unit tests, 4,044 insertions) were all produced by commands executed this session (`cargo test --workspace`, `pnpm test --run`, `grep -cE`, `git diff --stat`, `git show --stat 609826d`).
- **Phase 3A.2 zbus 5.x signal pattern (for future reference):** signal declarations live inside the `#[interface]` impl block as `#[zbus(signal)] async fn name(signal_emitter: &SignalEmitter<'_>, ...) -> zbus::Result<()>;` with no body and no `&self`. The macro generates both the introspection XML entry and the emission method on `SignalEmitter<'_>`. Emission requires a live `Connection`, so the services wrapper declares signals (for introspection completeness + unit-testability without a bus) and defers actual emission to the orchestrator daemon that owns the `SignalEmitter`.
- **Phase 3A.3 fidelity-first design notes (for future reference per Iron Law #13):** every external-source integration must declare its fidelity hierarchy in module doc comments and probe top-down (highest fidelity first; fall back on failure with a `tracing::debug!` log). The `Fidelity` enum is wire-stable via `as_str()` so D-Bus consumers can filter or weight readings. `Fidelity::Unavailable` is the cross-platform default — sensors return it when target paths/binaries don't exist, which is how the module compiles cleanly on Windows without `#[cfg(target_os = "linux")]`. Cross-platform compile is achieved through `Path` being platform-agnostic and `Command::new("missing-binary")` returning `Err` (mapped to Unavailable). Per-domain Fidelity provenance (one Fidelity per BatteryInfo / ThermalInfo / MemoryInfo / LocationContext, plus a `disk_fidelity` field on EnvironmentState) is finer-grained than per-state and gives consumers actionable provenance for each subdomain. The activity classifier is a pure function with no I/O — observations come from compositor + learning observer wiring (a future task) and the classifier just maps observations → ActivityState. WSL Hyper-V dev-system caveat: `/sys/class/thermal/` exposes only `cooling_device*` (12 of them, all type "Processor"), no `thermal_zone*`, so on this dev box thermal readings are legitimately Fidelity::Unavailable; the same code on a real laptop will return Fidelity::Direct.

## Codex adversarial security review - `78c5ba4..6ea6c36`

Scope: one commit, `6ea6c36 fix(sqlite): extend transient-lock policy to sibling stores + retry off-by-one (F22, F23, F24)`. Diff stat matched the requested seven changed files; `die/orchestrator/src/error.rs` was not touched in this range.

Verification run:

- `git log --oneline 78c5ba4..6ea6c36` -> one commit, `6ea6c36`.
- `git diff 78c5ba4..6ea6c36 --stat` -> 7 files, 566 insertions, 143 deletions.
- Requested per-file diffs reviewed for `sqlite.rs`, `lib.rs`, `knowledge.rs` first 200 lines, `timeline.rs`, `goals.rs`, `conversation.rs`, and `CLAUDE.md`.
- WSL sync/test command passed: workspace total is 1,466 passing tests.
- Targeted tests passed: `routes_database` 10 passed; `in_memory_busy_timeout` 3 passed; `retry_with_backoff` 2 passed; `open_or_init_survives_n_thread_contention` 1 passed; `map_sqlite_err` 8 passed; targeted migration/FK checks for F14/F17/F19 passed.

F22 helper review:

- Public symbols in `die/orchestrator/src/sqlite.rs`: `SQLITE_BUSY_TIMEOUT`, `init_sqlite_connection(&Connection)`, and `map_sqlite_err(rusqlite::Error, &str)`. Contracts are documented. `init_sqlite_connection` currently only pins `busy_timeout`; it does not enable `foreign_keys`. `map_sqlite_err` correctly routes `DatabaseBusy` and `DatabaseLocked` to `TransientLock`, preserving `Planning("{context}: {err}")` for all other rusqlite errors.
- `pub mod sqlite;` is registered in `lib.rs`.
- `sqlite.rs` imports only std time, rusqlite connection/error types, and `OrchestratorError`; no new dependency, unsafe block, or production FFI surface was added. Test-only code synthesizes rusqlite ffi error constants.
- Added unwraps are test-only in `sqlite.rs` helper tests and sibling `in_memory_busy_timeout` tests. No new production unwrap, expect, or unsafe block.
- New `sqlite.rs` tests cover the important branches, but not every non-`SqliteFailure` enum variant in `rusqlite::Error` 0.35.0. They cover one non-`SqliteFailure` representative (`QueryReturnedNoRows`), which is enough for branch behavior but not exhaustive variant parity with the round-7 walkthrough.

F22 call-site audit:

- Random spot-check sample, 5 map sites per sibling:
  - `timeline.rs`: `failed to open timeline db`, `timeline init_sqlite_connection`, `timeline in_memory init`, `failed to mark undone`, `count failed`.
  - `goals.rs`: `insert goal failed`, `query failed`, `row`, `row read failed`, `count failed`.
  - `conversation.rs`: `search failed`, `forget_older_than failed`, `conv count failed`, `msgs_since prepare`, `forget_topic failed`.
- Most remaining `OrchestratorError::Planning(format!(...))` hits are legitimate non-rusqlite paths: enum parsing, validation, serde JSON, `std::fs::create_dir_all`, or explicit domain errors after already-mapped existence checks.
- Manual block-form fixes mostly hold: `goals.rs` dynamic `goal {id} not found`, `goals.rs` row helper `sql_err`, and `conversation.rs` row collection now route through `map_sqlite_err`.
- The missed block forms below are real findings.

F23/F24 behavior:

- SQLite docs confirm unadorned `:memory:` databases are private to the opening connection; shared in-memory databases require a URI/shared-cache form and only share within one process. The current constructors call `Connection::open_in_memory()`, so F23 remains a policy/regression-detection change for current code, not a functional cross-process safety fix. References checked: <https://www.sqlite.org/inmemorydb.html>, <https://www.sqlite.org/sharedcache.html>, <https://www.sqlite.org/pragma.html#pragma_busy_timeout>.
- `Connection::open` grep found only the expected production public-store paths: `Timeline::open`, `GoalStore::open`, `ConversationStore::open`, `KnowledgeStore::try_open_and_backfill_once`, and their `open_in_memory` counterparts. Other hits are tests/fixtures.
- `retry_with_backoff` has one production caller: `KnowledgeStore::open`.
- F24 worst-case latency is approximately `6 * 5s busy_timeout + 3.1s sleep = 33.1s`, not 28s. No Delphi systemd unit, container startup timeout, or daemon startup timeout was found in repo docs/config that would currently conflict with this.
- The F24 test adds about 3.1s of deliberate sleep; CI cost is noticeable but bounded. Existing F20 contention coverage is already about 5.4s, so keeping the F24 unit enabled is defensible.

Round 1-7 regression checks:

- No added production `File::open`, `std::fs::*`, `openat2`, or `safe_open_under_root` use in the diff; only an added comment mentions `std::fs::create_dir_all`.
- F7 public rejection: new `map_sqlite_err` context strings are static except `goal {id} not found`, where `id` is numeric. No sqlite context string includes a filesystem path. The pre-existing non-sqlite `conversation.rs` directory-create error still includes `parent.display()`, but F22 did not add a sqlite path leak.
- F12 FK enforcement: `init_sqlite_connection` does not set `foreign_keys`. `KnowledgeStore::init_schema` enables and verifies `PRAGMA foreign_keys = ON` on every knowledge connection; `GoalStore::{open,in_memory}` enable it explicitly; `ConversationStore::open` enables it in `configure_pragmas`; `ConversationStore::in_memory` still skips `configure_pragmas` and therefore does not enable FK enforcement for the in-memory fixture path. That is pre-existing and not caused by F22/F23/F24, but it is worth fixing if the conversation store wants in-memory/test parity beyond busy-timeout.
- F14/F17 atomic FK check + version write is intact: migration and current-schema backfill keep `PRAGMA foreign_key_check` and `schema_version` write inside one transaction, with rollback on error.
- F19 backfill serialization is intact: `backfill_version_with_integrity_check` uses `TransactionBehavior::Immediate` and re-reads `schema_version` under the write lock.
- F20 retry loop and F21 typed routing tests pass after the F24 attempt bump.

Findings:

### F25 - P2-medium - F22 missed two rusqlite `query_row` error paths that still collapse lock contention into `Planning("...not found")`

Locations:

- `die/orchestrator/src/timeline.rs:241`
- `die/orchestrator/src/conversation.rs:414`

Root cause:

The F22 regex/manual sweep converted the common `.map_err(|e| Planning(format!("...: {e}")))` forms, but missed `.map_err(|_| Planning(format!("...not found")))` forms that discard the original `rusqlite::Error`. Both call sites are direct `query_row` results. `QueryReturnedNoRows` should become a domain "not found" error, but `SQLITE_BUSY` / `SQLITE_LOCKED` from the same query must route through `map_sqlite_err` so callers can see `OrchestratorError::TransientLock`.

Impact:

Under real SQLite contention, `Timeline::undo_action` and `ConversationStore::get_conversation` can falsely report "action not found" / "conversation not found" instead of a typed transient lock. That breaks F21/F22's typed retry contract for sibling stores and can mislead callers into treating a temporary database lock as a permanent absence.

Fix sketch:

Preserve the user-facing not-found behavior only for `rusqlite::Error::QueryReturnedNoRows`, and route every other rusqlite error through the shared helper:

```rust
.map_err(|e| match e {
    rusqlite::Error::QueryReturnedNoRows => {
        OrchestratorError::Planning(format!("action not found: {action_id}"))
    }
    e => map_sqlite_err(e, "timeline action lookup"),
})?;
```

Apply the same pattern to `ConversationStore::get_conversation`, with a context such as `"conversation lookup failed"`. Add regression tests that synthesize or force `SQLITE_BUSY`/`SQLITE_LOCKED` through these methods, or at minimum unit-test the mapping closure.

### F26 - P2-low - F23 claims every store has in-memory timeout regression coverage, but `KnowledgeStore::in_memory` has no matching test

Locations:

- `die/orchestrator/src/knowledge.rs:1068`
- `CLAUDE.md:273`

Root cause:

`KnowledgeStore::in_memory` now correctly calls `crate::sqlite::init_sqlite_connection(&conn)`, but the comment says drift is caught by the `busy_timeout_pinned_to_5_seconds` regression test and `CLAUDE.md` says every store ships these tests. The targeted `in_memory_busy_timeout` run found only three tests: timeline, goals, and conversation. There is no `KnowledgeStore::in_memory` busy-timeout assertion.

Impact:

This is not a current runtime bug because the production code path is correct today. It is a policy-regression gap: a future edit could remove the knowledge in-memory init call without the advertised F23 test catching it.

Fix sketch:

Add a knowledge unit test that constructs `KnowledgeStore::in_memory(Box::new(MockEmbedder::new()))`, locks the internal connection from the test module, reads `PRAGMA busy_timeout`, and asserts `5000`. Then the policy text and code comment become true.

FAIL — findings present. F25 P2-medium and F26 P2-low above must be addressed before merge.

**UPDATE (round 9, 2026-05-16):** Both F25 and F26 resolved at commit `1482f51` with +5 regression tests (1 F26 `knowledge_in_memory_busy_timeout_pinned_to_5_seconds`, 2 F25 timeline `undo_action_missing_row_*` + `undo_action_optional_chain_*`, 2 F25 conversation `get_conversation_missing_id_*` + `get_conversation_optional_chain_*`). The F25 fix uses `.optional() + map_sqlite_err(_, "<callsite> lookup") + ok_or_else(...)` to distinguish `QueryReturnedNoRows` (genuine miss → `Planning`) from every other `rusqlite::Error` (including `SQLITE_BUSY`/`SQLITE_LOCKED` → `TransientLock`). The F26 fix adds the missing busy_timeout regression test that the round-8 comment at `knowledge.rs:1068` already referenced. Round-9 adversarial-review verdict: **PASS** (no new findings; F25+F26 closure confirmed end-to-end via Codex CLI inspection of the merged feature branch).

## Task 3A.5 nine-round adversarial-security-hardening history

This section captures the full security-hardening narrative for Task 3A.5 in a single auditable block. The methodology — issue an initial implementation, then run cold-reviewer adversarial Codex prompts focused on a specific attack surface, then fix every finding at the root cause (per Iron Law #8), then re-review until the cycle returns PASS — was applied for nine iterations before convergence. The diminishing returns curve (P1-high → P2-medium → P2-low → P2-policy-completion) confirmed when to stop: round 9's P2-medium and P2-low findings were the last vestiges of inherited policy drift, not new attack surface.

### Per-round finding ledger

| Round | Commit | Findings | Severity range | Cumulative tests | Per-round delta |
|-------|--------|----------|----------------|------------------|-----------------|
| 1 | `1834c6a`-area | F4, F5, F6 | P1-high → P2-medium | ~1,023 → ~1,150 | +~127 |
| 2 | `a72a9ed`, `f82320c`, `e202c96` | F7, F8, F9 | P1-high → P2-medium | ~1,150 → ~1,283 | +~133 |
| 3 | (FIX 10/11/12/13 commits) | F10, F11, F12, F13 | P1-high → P2-medium | ~1,283 → ~1,360 | +~77 |
| 4 | (FIX 14/15/16 commits) | F14, F15, F16 | P1-high → P2-medium | ~1,360 → ~1,400 | +~40 |
| 5 | `d709048`-area | F17, F18 | P1-high → P2-medium | ~1,400 → ~1,430 | +~30 |
| 6 | `6f3f5c8` | F19 | P1-high | ~1,430 → ~1,440 | +~10 |
| 7 | `78c5ba4` | F20, F21 | P2-medium | ~1,440 → ~1,455 | +~15 |
| 8 | `6ea6c36` | F22, F23, F24 | P2-medium → P2-low | ~1,455 → 1,466 | +11 |
| 9 | `1482f51` | F25, F26 | P2-medium → P2-low | 1,466 → **1,471** | +5 |

(Round 1–5 commit hashes and exact test counts are reconstructable from `git log --oneline 188516c..HEAD` — the table approximates per-round deltas where individual fix commits were squashed during early-round iteration before the per-round commit discipline was adopted in round 6.)

### Per-finding ledger (23 findings, F4–F26)

**Round 1 (initial adversarial review):**
- **F4 (P1-high)** — Allowlist was effectively open-by-default for path-based ingestion; closed to fail-secure default-empty allowlist requiring explicit opt-in per source root.
- **F5 (P1-high)** — Source uniqueness key was `(uri, content_hash)`, allowing the same bytes ingested as different formats (PDF→markdown recovery, txt→json reinterpretation) to overwrite each other; extended to `(uri, content_hash, format)`.
- **F6 (P2-medium)** — Public node-returning APIs returned partially-hydrated nodes (no `source_ids`); now every public API hydrates from `node_sources` join on the read path.

**Round 2:**
- **F7 (P1-high)** — Rejection messages on path-validation failures leaked filesystem existence by varying message between "path does not exist" vs "path exists but outside allowlist"; collapsed to a single uniform "path rejected" message + `tracing::warn!` for operator diagnostics (warn never reaches the caller).
- **F8 (P1-high)** — `safe_open_no_follow` left a final-component TOCTOU window between path canonicalization and file open; replaced with `O_NOFOLLOW` open. Round-3 F11 extended this to full intermediate-component coverage via `openat2`.
- **F9 (P1-high)** — Schema migration was implicit (CREATE TABLE IF NOT EXISTS); broke for databases created by earlier branch tips with the old F5 unique key. Added explicit `schema_version` table + version-table migration with epoch_1 → epoch_2 rebuild preserving `node_sources` FK validity + `AUTOINCREMENT` counter via explicit `sqlite_sequence` copy.

**Round 3:**
- **F10 (P1-high)** — `PRAGMA foreign_keys = ON` is per-connection, not per-database; round-2 set it inside `SCHEMA_DDL` which only fires on fresh-database setup. Moved to `init_schema` opening which runs on every `Connection::open` boundary, with `PRAGMA foreign_keys` verification and refuse-to-open if disabled.
- **F11 (P1-high)** — Intermediate-component TOCTOU was still open even after F8; replaced final-component-only `O_NOFOLLOW` with full-path `openat2(..., RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)`. Windows refuses to compile this path (explicit `Unsupported` feature-gate added in F16).
- **F12 (P2-medium)** — Migration rebuild dropped index DDL; preserved by re-running index creation post-rebuild inside the same transaction.
- **F13 (P2-medium)** — Migration used `INSERT INTO new SELECT * FROM old` which silently truncated columns added in epoch_2; explicit column list now used.

**Round 4:**
- **F14 (P1-high)** — Migration's `PRAGMA foreign_key_check` ran in a separate transaction from the schema_version write; allowed a window where the version was committed but FK violations had not been detected. Now atomic: foreign_key_check + version write inside one `BEGIN IMMEDIATE`, with rollback on any error.
- **F15 (P2-medium)** — `trusted_root: PathBuf` was vulnerable to root-directory-replacement TOCTOU (someone could swap the root between open and read); replaced with `Arc<File>` held directory handle anchored to inode. (`libc` workspace dep added here — see Cargo.lock cleanup commit `2b52f7e`.)
- **F16 (P2-medium)** — Cross-platform compile was relying on `Path` being platform-agnostic but `openat2`-dependent code paths broke the build on Windows; added explicit `Unsupported` feature-gate returning `OrchestratorError::Planning("openat2 unavailable on this platform")` on non-Linux targets.

**Round 5:**
- **F17 (P1-high)** — F14's atomic FK check still allowed a race window for the backfill path (existing databases backfilling to current schema version after F9 landed); backfill now runs inside the same `BEGIN IMMEDIATE` as the version write, with `PRAGMA foreign_key_check` against the in-transaction state.
- **F18 (P2-medium)** — Linux-only ingest tests broke `cargo test` on Windows; added Linux platform gates + meta-tests asserting the gates themselves remain correct under cross-platform CI.

**Round 6:**
- **F19 (P1-high)** — Concurrent openers could both pass the F17 schema-version check (both see "version not yet recorded") and then race to insert, with the second `INSERT INTO schema_version` failing with `UNIQUE` constraint violation visible to the caller as a confusing `SQLITE_BUSY`. `backfill_version_with_integrity_check` now serializes under `TransactionBehavior::Immediate` with under-lock re-read.

**Round 7:**
- **F20 (P2-medium)** — F19's `BEGIN IMMEDIATE` correctly serializes openers but only as long as the winner releases the lock within the 5-second `busy_timeout`; under sustained contention (e.g., large unversioned graph with multi-second `foreign_key_check`) the loser exhausts its timeout and surfaces `SQLITE_BUSY`. Added retry-with-backoff loop around the entire open-and-backfill sequence (`100 → 200 → 400 → 800 → 1600 ms` jittered sleep, `MAX_OPEN_ATTEMPTS = 6`).
- **F21 (P2-medium)** — All SQLite errors were classified as `Planning` regardless of code, forcing daemons to string-match `"database is locked"` for retry decisions. Added typed `OrchestratorError::TransientLock { source: rusqlite::Error }` variant routed via `map_sqlite_err` for `DatabaseBusy`/`DatabaseLocked` (both base and extended codes).

**Round 8:**
- **F22 (P2-medium)** — F21's routing logic existed only in knowledge.rs; sibling stores (Timeline, GoalStore, ConversationStore) had `map_err(|e| Planning(...))` calls that produced untyped errors. Extracted `init_sqlite_connection` and `map_sqlite_err` to shared `die_orchestrator::sqlite` module; migrated all four stores to route every `rusqlite::Error` through the canonical helpers. Direct construction of `Planning` from `rusqlite::Error` is now a policy violation (documented in CLAUDE.md Section 3 "SQLite Connection Policy").
- **F23 (P2-low)** — `in_memory()` constructors did not run `init_sqlite_connection` because `:memory:` databases are private to a single connection (so `busy_timeout` is functionally a no-op for default in-memory dbs per SQLite docs). But constructor-parity is the regression-detection mechanism: future drift where someone copies an init path and forgets the pragma is caught by the `busy_timeout_pinned_to_5_seconds` tests. Added init helper to every in_memory constructor + matching regression tests for Timeline, GoalStore, ConversationStore. (KnowledgeStore was missed here — closed by F26 in round 9.)
- **F24 (P2-low)** — `MAX_OPEN_ATTEMPTS = 5` produced only 4 inter-attempt sleeps (`100 → 200 → 400 → 800`), making the documented final `1600 ms` sleep and the `MAX_BACKOFF_MS = 2000` cap unreachable. Bumped to 6 attempts so the documented `100 → 200 → 400 → 800 → 1600 ms` sequence (5 sleeps across 6 attempts) is achievable. Worst-case opener latency: `6 × 5 s busy_timeout + 3.1 s inter-attempt sleep ≈ 33 s` before a typed `TransientLock` reaches the caller — bounded and documented.

**Round 9 (final):**
- **F25 (P2-medium)** — `timeline.rs::undo_action` (line 241) and `conversation.rs::get_conversation` (line 414) used `.map_err(|_| Planning("not found: {id}"))` which discarded the `rusqlite::Error` and mapped every failure mode — including `SQLITE_BUSY`/`SQLITE_LOCKED` — to a fabricated "not found" message. F22's regex-driven sweep missed this block form because it filters `map_err` arms that DROP the error rather than format it. Fix uses `.optional()` (which converts ONLY `QueryReturnedNoRows` to `Ok(None)`, preserving all other errors) + `map_sqlite_err(e, "<callsite> lookup")` + `ok_or_else(|| Planning("..."))` to distinguish genuine misses from lock contention. Audited every `query_row`/`query_one` site across all four stores; only the two Codex flagged had the silent-error-swallow pattern (every other site was already F22-compliant).
- **F26 (P2-low)** — F23's round-8 sibling sweep added `init_sqlite_connection` to `KnowledgeStore::in_memory` and left a comment at `knowledge.rs:1068` referencing "the `busy_timeout_pinned_to_5_seconds` regression test" — but the matching test was never actually written. CLAUDE.md SQLite Connection Policy says "every store" should have one, so KnowledgeStore was the last store breaking that invariant. Test added; closes the policy-completion gap.

### Round-9 final test count breakdown

`cargo test --workspace` per-binary summation = **1,471 Rust tests** (delta breakdown per round: rounds 1–8 contributed +443 above the 3A.4 baseline; round 9 added the final +5):

```
28 + 5 + 137 + 34 + 33 + 37 + 93 + 436 + 37 + 70 + 19 + 33 + 43 + 28 + 0 + 18
+ 20 + 31 + 37 + 76 + 92 + 26 + 61 + 25 + 13 + 39 = 1471
```

Plus 73 TypeScript tests (unchanged from 3A.4 verification, since Task 3A.5 touched only Rust crates) = **1,544 total tests**.

### Documented precedent

This nine-round arc establishes the following as project-wide patterns for any security-sensitive task in Phase 3B+:

1. **Cold-reviewer adversarial Codex prompts** with mandatory tool grounding (Context7 for library docs, Codex CLI for live codebase inspection).
2. **Root-cause-only fixes** per Iron Law #8 — no workarounds, no "fix it later", no scope creep into adjacent issues.
3. **Per-round per-commit discipline** from round 6 onward — each round is a single focused commit with a verbatim Codex finding ID in the commit message body.
4. **Carried-forward cleanup discipline** — non-scoped changes (Cargo.lock, PROGRESS.md, working-tree noise) defer to a final cleanup-commit sweep before merge to keep each round's commit narrow and auditable.
5. **In-memory constructor parity** as the regression-detection mechanism for policy drift — `busy_timeout_pinned_to_5_seconds` tests on every store catch future copy-paste drift even when the runtime behavior is a no-op for the specific constructor.
6. **Typed transient-error variants** (`OrchestratorError::TransientLock`) over string-matching on error messages for daemon retry logic.
7. **Shared policy helpers** (`die_orchestrator::sqlite::{init_sqlite_connection, map_sqlite_err}`) over per-store copy-pasted routing — single seam, single change site.
8. **Stash-as-recovery-handle** during multi-round work — the rsync-residue stash (`ef33afd`) served as the rollback anchor through rounds 6–9 and was dropped only after the merge + tag landed.
