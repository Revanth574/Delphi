# CLAUDE.md — Delphi OS Project Guidelines

This file is the law of the Delphi OS project. Every Claude Code session — now or months from now — must follow these rules to produce code that integrates perfectly with every other part of the system. When in doubt, this file wins. When this file is silent, consult `DELPHI_COMPLETE_SPEC.md`.

---

## Section 1: Project Identity and Architecture

### Definition

Delphi is an open-source operating system where a persistent, internet-connected, self-evolving multi-agent intelligence engine has native kernel-level access to every subsystem — files, apps, hardware, network, and the full internet — enabling it to execute arbitrarily complex tasks of any type through natural language while learning and growing alongside its user from the first boot.

### Six-Layer Architecture Stack

```
┌─────────────────────────────────────────────────┐
│  Layer 6: Living Surface UI                     │
│  (React 19 shell, four modes, command bar)      │
├─────────────────────────────────────────────────┤
│  Layer 5: Delphi Intelligence Engine (DIE)      │
│  (orchestrator, specialists, memory, learning)  │
├─────────────────────────────────────────────────┤
│  Layer 4: SSI + Semantic FS                     │
│  (app integration, file indexing, search)       │
├─────────────────────────────────────────────────┤
│  Layer 3: Fortress Security                     │
│  (encryption, ZKP, FHE, TPM, federated sync)   │
├─────────────────────────────────────────────────┤
│  Layer 2: Inference Scheduler                   │
│  (GPU/NPU/CPU scheduling, model lifecycle)      │
├─────────────────────────────────────────────────┤
│  Layer 1: Linux Kernel                          │
│  (hardware, drivers, boot chain)                │
└─────────────────────────────────────────────────┘
```

### Four UI Modes

| Mode | Description | AI State |
|------|-------------|----------|
| **Direct** | Full traditional desktop. Icons, folders, windows. AI invisible. | Dormant (Alt+Space summons command bar) |
| **Assisted** | User drives, AI navigates. Inline suggestions, Tab to accept. | Active, reactive |
| **Autonomous** | AI drives for delegated tasks. Ephemeral task UI. Reports progress. | Active, proactive |
| **Focus** | AI fully dormant. No observation, no learning, no processing. Maximum privacy. | Off |

Each window has its own mode (colored dot in title bar). Modes operate independently and simultaneously.

### Three-Tier Inference Architecture

| Tier | Location | Models | Use Case |
|------|----------|--------|----------|
| **Tier 1** | Always local | Qwen3 7B / Llama 3.1 8B (4-bit GGUF) | Intent classification, autocomplete, quick answers |
| **Tier 2** | Local or cloud | Qwen3 30B / DeepSeek-V3-Lite / Claude Sonnet | Code generation, writing, data analysis |
| **Tier 3** | Cloud with ZKQP | Claude Opus / GPT-5.4 / Gemini 3.1 Pro | Complex reasoning, research, creative work |

The model router selects the cheapest capable model per task. Sensitive data forces local routing.

### Universal Learning Loop

```
OBSERVE → MODEL → PROPOSE → PRACTICE → REFINE → AUTOMATE → EVOLVE
```

1. **Observe:** Watch user perform task (with consent flag active)
2. **Model:** Build procedural representation of the task
3. **Propose:** "I noticed you do X regularly. Want me to handle it next time?"
4. **Practice:** Execute with user supervision
5. **Refine:** Incorporate feedback
6. **Automate:** After 3+ successful supervised executions, offer autonomous handling
7. **Evolve:** Continue improving from corrections and changing patterns

### Hardware-Agnostic Scaling

Delphi runs on anything from 2GB RAM to 128GB+. At boot, it benchmarks available hardware (RAM, GPU/NPU, CPU cores) and auto-configures:
- Which model tier to load locally
- How much to offload to cloud
- Memory budgets per subsystem
- Thermal and power profiles

A 4GB Raspberry Pi and a 128GB workstation access the same intelligence — the Pi just routes more to cloud. The experience difference is latency, not capability.

### Privacy Principle

Privacy is mathematical, not promissory. The seven-layer Fortress architecture provides:
1. Hardware root of trust (TPM 2.0 / Secure Enclave)
2. Full-disk encryption with plausible deniability (LUKS2 + hidden volumes)
3. Zero-knowledge architecture for cloud queries (ZKQP)
4. Fully homomorphic encryption for sensitive cloud compute (FHE)
5. Federated behavioral sync with differential privacy
6. Zero-knowledge proofs for AI action verification (zk-SNARK)
7. Quantum-resistant cryptography (CRYSTALS-Kyber/Dilithium)

### User Sovereignty Principle

The user's explicit request overrides any AI prediction, suggestion, or optimization. Delphi does not surveil, log, report, filter, or judge legal user activity. The AI serves the user without judgment, restriction, or moral authority.

---

## Section 2: Technology Stack

**Mandatory. No substitutions without documented justification in a `# DECISION:` comment.**

### System Languages

| Component | Language | Notes |
|-----------|----------|-------|
| Kernel, compositor, DIE core, fortress, semantic-fs | **Rust** (edition 2024, stable toolchain) | Memory safety, performance |
| Shell UI | **TypeScript 5.x** (strict mode) with **React 19** | Modern rendering, contributor-friendly |
| ML/AI pipelines | **Python 3.12+** with type hints | Ecosystem necessity for ML |

### Core Dependencies

| Component | Technology | Version |
|-----------|-----------|---------|
| Compositor | smithay | 0.7.x |
| Async runtime | tokio | 1.x |
| Logging | tracing + tracing-subscriber | 0.1.x / 0.3.x |
| Serialization | serde + toml | 1.x / 0.8.x |
| Error handling (libraries) | thiserror | 2.x |
| Error handling (applications) | anyhow | 1.x |
| D-Bus IPC | zbus | 5.x |
| Full-text search | tantivy | 0.25.x |
| Vector database | lancedb | 0.23.x |
| LLM inference (local) | llama-cpp-2 | latest |
| Voice STT | whisper-rs | 0.16.x |
| Voice TTS | Piper TTS | latest |
| Semantic embeddings | sentence-transformers (Python) or candle (Rust) with all-MiniLM-L6-v2 | latest |
| Browser automation | Playwright (headless Chromium) | latest |
| Benchmarking | criterion | 0.5.x |

### Encryption & Security

| Component | Technology |
|-----------|-----------|
| Disk encryption | LUKS2 + Argon2id |
| Data at rest | AES-256-GCM |
| PQC key encapsulation | CRYSTALS-Kyber |
| PQC signatures | CRYSTALS-Dilithium |
| FHE | Microsoft SEAL or OpenFHE |
| ZK proofs | Circom + snarkjs |

### UI Stack

| Component | Technology |
|-----------|-----------|
| Framework | React 19 |
| State management | Zustand |
| CSS | Tailwind CSS 4.x with custom design tokens |
| Internationalization | react-i18next |
| Type system | TypeScript 5.x (strict mode) |

### Infrastructure

| Component | Technology |
|-----------|-----------|
| IPC | D-Bus (zbus) + shared memory via memfd_create (hot path) |
| Serialization (IPC) | Protocol Buffers (protobuf) |
| Package format | Flatpak (apps) + apt (system) |
| Build (Rust) | Cargo |
| Build (JS/TS) | pnpm |
| Build (C/C++ deps) | Meson |
| CI/CD | GitHub Actions |
| Testing (Rust) | cargo test |
| Testing (TS) | Vitest |
| Testing (Python) | pytest |
| Containerization | Podman (rootless) |
| Documentation | mdBook |

---

## Section 3: Code Quality Rules

**Non-negotiable. Every file, every commit.**

### Rust Rules

- All code must compile with `cargo clippy -- -D warnings` (zero warnings).
- All public functions must have doc comments with `///` including at least one `# Examples` block.
- All error handling must use `thiserror` for library errors, `anyhow` for application errors — **NEVER** use `.unwrap()` or `.expect()` in production code (only in tests).
- All async code must use `tokio` runtime.
- All `unsafe` blocks must have a `// SAFETY:` comment explaining why unsafe is necessary and why it is sound.
- Use `#[must_use]` on all functions that return `Result` or `Option`.
- Maximum function length: **50 lines**. If longer, decompose.
- All modules must have a `mod.rs` or inline module doc comment explaining the module's purpose.
- Use `tracing` for all logging — **never** `println!` in production code.
- All configuration must use `serde` with TOML files.
- Minimum test coverage: **80%** for all modules.

### TypeScript / React Rules

- Strict mode enabled in `tsconfig.json` (`"strict": true`).
- All components must be functional with hooks (no class components).
- All props must have TypeScript interfaces — **never** `any`.
- Use `React.memo` for components that receive stable props.
- All global state management via **Zustand** (not Redux, not Context for global state).
- All API calls through a centralized client module with proper error handling.
- CSS: **Tailwind CSS 4.x** with custom design tokens matching Delphi's design system.
- All user-facing strings must be externalized for i18n (use `react-i18next`).
- No inline styles except for dynamic values computed at runtime.
- All components must be accessible: proper ARIA labels, keyboard navigation, focus management.

### Python Rules

- Python **3.12+** with type hints on **ALL** functions.
- Format with **ruff** (replaces black + isort + flake8).
- All ML code must handle CUDA, MPS (Apple), and CPU fallbacks gracefully.
- All model loading must report memory usage before and after.
- All inference must have timeout handling (never hang indefinitely).

### Cross-Language Rules

- **ALL** inter-process communication must use **Protocol Buffers** (protobuf) for serialization — not JSON (too slow for hot paths), not custom binary (unmaintainable).
- **ALL** file paths must use the `dirs` crate (Rust) or `platformdirs` (Python) — **NEVER** hardcode paths.
- **ALL** secrets (API keys, tokens) must go through the Fortress credential vault — **NEVER** in environment variables, **NEVER** in config files, **NEVER** in code.
- **ALL** timestamps must be UTC ISO 8601 — no local time, no Unix timestamps in user-facing code.
- **ALL** user-facing text must support RTL languages from day one.

---

## Section 4: Architecture Rules

### Module Boundaries (CRITICAL)

Violations of these boundaries break the entire system:

1. **Living Surface (UI) NEVER directly calls inference.** It sends intents to the DIE orchestrator via D-Bus. The orchestrator decides which tier/specialist handles it.
2. **The DIE NEVER directly accesses the filesystem.** It goes through the Semantic FS service which enforces permissions and maintains the index.
3. **The Fortress NEVER exposes raw keys or decrypted data to any other module.** It provides opaque capability tokens.
4. **The Inference Scheduler NEVER makes decisions about WHAT to infer.** It only manages HOW and WHEN inference runs (resource scheduling). The orchestrator decides what.
5. **The SSI layer NEVER trusts app-reported capabilities.** It validates by testing each capability before adding to the manifest.

### Dependency Direction (STRICT)

```
Living Surface UI
       ↓ (D-Bus intents)
Delphi Intelligence Engine (orchestrator + specialists + memory + learning)
       ↓ (inference requests)          ↓ (file operations)          ↓ (web requests)
Inference Scheduler          Semantic FS Service          Browser Engine
       ↓ (resource allocation)         ↓ (raw I/O)
Fortress Security Layer (wraps everything below)
       ↓
Linux Kernel + Hardware
```

**No module may import from a module above it in this hierarchy.** If module A depends on module B, module B must **NEVER** depend on module A. Use event-based communication (D-Bus signals) for upward notifications.

### Cargo Workspace Dependency DAG

```
compositor       (standalone — communicates via D-Bus/Wayland)
ssi              (standalone — communicates via D-Bus)
fortress         (foundation — no internal dependencies)
  ↑
die-inference    (depends on: fortress)
semantic-fs      (depends on: fortress)
  ↑
die-orchestrator (depends on: die-inference, semantic-fs, fortress)
```

Adding a dependency that creates a cycle is a **compilation error** (Cargo enforces this) and a **design error** (fix the architecture, not the dependency).

### Scalability Rules

- All services must be single-process by default but support multi-process via config.
- All data stores must handle **1TB+** of indexed content without degradation.
- All inference paths must work with models from **1B to 100B+** parameters.
- All network operations must have configurable timeouts and retry logic with exponential backoff.
- All background tasks must be cancellable and report progress.
- All caches must have configurable size limits and LRU eviction.

---

## Section 5: File Structure and Naming Conventions

### Canonical Directory Tree

```
delphi/
├── kernel/                     # Linux kernel config + patches
│   ├── config/
│   └── patches/
├── compositor/                 # Wayland compositor (Smithay, Rust)
│   ├── src/
│   └── Cargo.toml
├── shell/                      # Living Surface UI (React 19)
│   ├── src/
│   │   ├── modes/              # Direct, Assisted, Autonomous, Focus
│   │   ├── components/         # Topbar, dock, window manager, settings
│   │   ├── command-bar/        # Alt+Space command interface
│   │   └── action-timeline/    # Undo system UI
│   └── package.json
├── die/                        # Delphi Intelligence Engine
│   ├── orchestrator/           # Central planning agent (Rust)
│   ├── inference/              # Three-tier inference manager
│   │   ├── src/
│   │   ├── local/              # llama.cpp integration
│   │   ├── cloud/              # API clients (Anthropic, OpenAI, Google)
│   │   └── router/             # Model selection logic
│   ├── specialists/            # Domain specialist models
│   ├── memory/                 # Hot/warm/cold memory tiers (LanceDB)
│   ├── learning/               # Universal learning engine
│   │   ├── observer/           # Action observation system
│   │   ├── modeler/            # Procedural model builder
│   │   └── executor/           # Learned task execution
│   ├── browser/                # Headless Chromium agent (Playwright)
│   ├── voice/                  # Whisper.cpp + Piper TTS
│   └── planner/                # Goal/timeline management
├── ssi/                        # Semantic System Interface
│   ├── spec/                   # SSI standard specification
│   ├── auto-gen/               # Auto-manifest generation
│   ├── sdk-python/             # Python SSI SDK
│   ├── sdk-js/                 # JavaScript SSI SDK
│   └── sdk-rust/               # Rust SSI SDK
├── fortress/                   # Security system
│   ├── src/
│   ├── encryption/             # LUKS2, AES-256-GCM, PQC
│   ├── zkqp/                   # Zero-Knowledge Query Protocol
│   ├── fhe/                    # Homomorphic encryption
│   ├── zksnark/                # Audit chain (Circom + snarkjs)
│   ├── tpm/                    # Hardware security module
│   └── federated-sync/         # Cross-device sync
├── semantic-fs/                # Semantic file system
│   ├── src/
│   ├── indexer/                # Tantivy + sentence-transformers
│   └── search/                 # Natural language file search
├── installer/                  # Delphi installer
│   ├── live-iso/               # Bootable ISO builder
│   └── setup-wizard/           # First-boot configuration
├── docs/                       # Documentation
│   ├── spec/                   # Specifications
│   ├── api/                    # API documentation
│   ├── user-guide/             # User documentation
│   └── papers/                 # Research paper drafts
└── tests/                      # Test suite
    ├── unit/
    ├── integration/
    ├── e2e/
    └── security/
```

### Naming Conventions

| Context | Convention | Example |
|---------|-----------|---------|
| Rust files, modules, functions, variables | `snake_case` | `inference_router.rs`, `fn route_request()` |
| Rust types and traits | `PascalCase` | `InferenceRouter`, `trait CredentialStore` |
| TypeScript variables/functions | `camelCase` | `const inferenceResult`, `function routeRequest()` |
| TypeScript components/types | `PascalCase` | `CommandBar`, `interface InferenceResult` |
| TypeScript files | `kebab-case` | `command-bar.tsx`, `inference-result.ts` |
| Python everything | `snake_case` | `inference_router.py`, `def route_request()` |
| Python classes | `PascalCase` | `class InferenceRouter` |
| Protobuf messages | `PascalCase` | `message InferenceRequest` |
| Protobuf fields | `snake_case` | `string input_text = 1;` |
| Config files | `kebab-case` TOML | `inference-config.toml` |
| Documentation | `kebab-case` markdown | `getting-started.md` |

### File Headers

Every new file must have:

1. A file-level doc comment explaining its purpose (first line).
2. An explicit license header: `// SPDX-License-Identifier: MIT`
3. All imports grouped with blank lines between groups:
   - Standard library
   - External crates / packages
   - Internal modules

---

## Section 6: Git Workflow

### Branch Naming

```
phase-{N}/{feature-name}
```

Examples:
- `phase-0/compositor-skeleton`
- `phase-0/cargo-workspace`
- `phase-1/inference-router`
- `phase-2/learning-engine`

### Commit Messages

**Conventional Commits format:**

```
type(scope): description
```

| Type | Meaning |
|------|---------|
| `feat` | New feature |
| `fix` | Bug fix |
| `refactor` | Code restructuring |
| `docs` | Documentation |
| `test` | Tests |
| `ci` | CI/CD |
| `perf` | Performance |
| `security` | Security-related |

| Scope | Component |
|-------|-----------|
| `compositor` | Wayland compositor |
| `shell` | Living Surface UI |
| `die` | Intelligence Engine |
| `ssi` | Semantic System Interface |
| `fortress` | Security system |
| `semantic-fs` | Semantic file system |
| `installer` | Installer |
| `infra` | Build, CI, workspace |

Example: `feat(die): implement three-tier inference router with model selection`

### Rules

- Every commit must compile. Every commit must pass existing tests. **No exceptions.**
- No force-pushing to `main`. All changes via PR (even when working solo — for audit trail).
- Tag releases: `v0.1.0-phase0`, `v0.2.0-phase1`, etc. Semantic versioning.
- `Cargo.lock` is committed (reproducible builds).

---

## Section 7: Testing Strategy

| Test Type | Location | Scope | Tool |
|-----------|----------|-------|------|
| **Unit** | Same file (`#[cfg(test)]`) or `__tests__/` (TS) | Every function with logic | `cargo test`, Vitest |
| **Integration** | `tests/integration/` | Every module boundary (D-Bus, IPC, inference pipeline) | `cargo test`, pytest |
| **End-to-end** | `tests/e2e/` | Every user-facing flow (command bar → result, file search → result, mode switching) | Custom harness |
| **Security** | `tests/security/` | Every encryption path, permission boundary, credential access | Custom harness |
| **Performance** | `benches/` | Inference latency, file search latency, IPC round-trip | criterion |
| **Fuzz** | `fuzz/` | All parsers, protocol handlers, SSI manifest parsing | cargo-fuzz |

### Coverage Target

**80% minimum** for all modules. Measured by `cargo-tarpaulin` (Rust) and `vitest --coverage` (TS).

---

## Section 8: Error Handling Philosophy

1. **Every error must be actionable.** Not "Error occurred" but "Failed to load Tier 1 model: file `/models/qwen3-7b.gguf` not found. Run `delphi model download tier1` to fix."
2. **Every error in user-facing code must have a recovery suggestion.**
3. **Errors in the DIE must NEVER crash the OS.** They must degrade gracefully to the next available tier or mode.
4. **Network errors must ALWAYS be retried** with exponential backoff (max 3 retries, then queue for later).
5. **Model loading errors must cascade:**
   - Try next smaller model → try cloud → show "AI temporarily unavailable — Direct mode active."

### Error Resolution Protocol (MANDATORY)

When any error occurs during implementation, follow this exact sequence. No skipping steps.

**Step 1: READ the error.** Read the full error message, stack trace, and any context. Do not guess at the cause.

**Step 2: DIAGNOSE the root cause.** Identify exactly WHY the error occurred. Is it a missing dependency? A type mismatch? A version incompatibility? An incorrect API usage? State the diagnosis explicitly before attempting any fix.

**Step 3: FIX the root cause.** Apply the minimal change that addresses the actual problem. Not a workaround. Not a different approach. The direct fix.

**Step 4: VERIFY the fix.** Compile, run tests, confirm the error is resolved and no new errors were introduced.

**Step 5: Only if Step 3 fails after 3 genuine attempts** — then and only then consider an alternative approach. But you must:
   - Document what you tried and why each attempt failed
   - Explain why the root cause is unfixable (not just difficult)
   - Prove the alternative is technically equal or superior (not just easier to implement)
   - Get explicit confirmation before switching approaches if the alternative changes architecture

**What this means in practice:**
- If a crate doesn't compile: read the error, fix the code, don't swap to a different crate
- If a Smithay API changed: find the correct current API, don't abandon Smithay for another library
- If a test fails: fix the logic bug, don't delete or weaken the test
- If a dependency conflicts: resolve the version conflict, don't remove the dependency
- If an integration breaks: trace the IPC chain and fix the broken link, don't add a bypass

**The only exceptions where switching is correct:**
- The current approach has a fundamental design flaw (not just an implementation bug)
- The alternative is provably better in performance, safety, or maintainability (with evidence)
- The current dependency is abandoned, has critical CVEs, or lacks required functionality
- You've documented 3+ genuine fix attempts with specific failure reasons for each

**Never acceptable:**
- "I couldn't get X to work so I used Y instead" (without explaining why X failed and why Y is better)
- Silently switching libraries, approaches, or architectures without documenting the decision
- Weakening tests, reducing error handling, or removing features to make errors go away
- Using `#[allow(...)]` or `// @ts-ignore` to suppress errors instead of fixing them

### Error Type Strategy

| Crate Type | Error Crate | Pattern |
|------------|-------------|---------|
| Library crate (`fortress`, `ssi`, `die-inference`, `semantic-fs`) | `thiserror` | Typed enums with `#[error("...")]` |
| Application crate (`die-orchestrator`) | `anyhow` | `anyhow::Result` at boundaries, `thiserror` internally |
| Tests | `.unwrap()` / `.expect()` | Allowed only in tests |

---

## Section 9: Performance Budgets

| Operation | Budget |
|-----------|--------|
| Command bar to first response (Tier 1 local) | **< 200ms** |
| File search — semantic (1M files) | **< 500ms** |
| Mode switch | **< 100ms** (instantaneous feel) |
| Voice transcription (streaming) | **< 300ms** latency |
| App launch | **< 1 second** |
| Boot to usable desktop | **< 15 seconds** |
| Memory baseline (no AI active) | **< 500MB** |
| Memory with Tier 1 model (7B 4-bit) | **< 2GB** |

These are targets. Measure with `criterion` benchmarks and track in CI.

---

## Section 10: Security Implementation Rules

1. **NEVER** log sensitive data (API keys, passwords, file contents, user queries to cloud).
2. **NEVER** store credentials outside the Fortress vault (TPM-backed or encrypted fallback).
3. **NEVER** send identifiable data to cloud without ZKQP processing.
4. **ALL** cloud API calls must go through the ZKQP proxy — no direct calls from any module.
5. **ALL** local databases must be encrypted at rest with AES-256-GCM.
6. **ALL** IPC messages containing user data must be encrypted in transit (even localhost).
7. The Fortress module must be the **ONLY** module with access to raw cryptographic keys.
8. Every Autonomous mode action must generate a logged, reversible entry in the action timeline.

---

## Section 11: Practical Implementation Notes

1. **When implementing a new feature, ALWAYS check `DELPHI_COMPLETE_SPEC.md` first.** The spec is the source of truth.
2. When the spec is ambiguous, choose the option that:
   - (1) Maximizes user sovereignty
   - (2) Minimizes data exposure
   - (3) Degrades gracefully
   - (4) Is simpler to implement correctly
3. **NEVER** implement a feature partially and leave TODO comments for "later." Either implement it fully or don't start it. Partial implementations create integration nightmares.
4. **ALWAYS** write tests BEFORE or ALONGSIDE the implementation, never after.
5. **ALWAYS** run the full test suite before committing. If any test fails, fix it before committing.
6. If you're unsure about a design decision, add a `# DECISION:` comment in the code explaining the choice and why, with a reference to the relevant spec section.
7. When adding a new dependency:
   - Check its license (must be MIT/Apache/BSD compatible)
   - Check its maintenance status (must have commits in last 6 months)
   - Check its security advisories
8. **Prefer Rust over Python** for all performance-critical paths. Use Python only for ML model integration where the ecosystem requires it.
9. All Rust binaries must be statically linked where possible for deployment simplicity.

---

## Section 12: The Iron Laws of Delphi

**These override everything else. If any implementation decision conflicts with these, these win.**

1. **User sovereignty is absolute.** The user's explicit request overrides any AI prediction, suggestion, or optimization. Always. No exceptions. No "are you sure?" for non-destructive actions.

2. **Privacy is mathematical, not promissory.** If it can't be proven cryptographically that data is protected, it isn't protected. Don't rely on policies. Rely on math.

3. **Graceful degradation is mandatory.** Every feature must work at SOME level even when components fail. No single failure should make the computer unusable. The Safe Mode (`Fn+Esc`) must ALWAYS work.

4. **The AI learns, it does not judge.** The learning engine observes and adapts. It never moralizes, restricts legal activity, or reports user behavior. It is an extension of the user's will.

5. **Everything the AI does is reversible.** Every Autonomous action has a 24-hour undo window. No irreversible AI action without explicit biometric confirmation.

6. **The internet amplifies, never replaces.** Cloud and internet are power multipliers. The core OS must function offline. Internet makes it better, not possible.

7. **Born simple, grows complex.** Day-one Delphi is a beautiful, fast desktop with a smart command bar. It earns complexity through the user's trust and engagement, not by overwhelming them at first boot.

8. **Fix the problem, don't flee from it.** When encountering an error, compilation failure, dependency issue, or unexpected behavior: DIAGNOSE first, FIX the root cause, and only then move on. Never skip a failing approach and jump to an alternative unless you can explicitly prove the alternative is technically superior — not just easier. "It didn't work so I tried something else" is not acceptable. "It failed because X, I attempted fixes A, B, C, the root cause is unfixable due to Y, and alternative Z is superior because [specific technical reasons]" is acceptable.
