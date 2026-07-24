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

### The Growth Model: Born with the Machine, Grows with the User

Delphi is not a static tool. It is born the moment the computer first boots and grows alongside the user:

| Stage | Timeline | Capabilities |
|-------|----------|-------------|
| **Newborn** | Day 1 | Knows nothing about this user. General-purpose capabilities only. Asks preferences during onboarding. Operates primarily in Direct mode. |
| **Infant** | Week 1 | Has learned basic patterns — daily routine, common apps, file locations. Begins anticipating simple needs. |
| **Child** | Month 1 | Understands work/personal boundaries, communication styles per contact. Handles routine tasks autonomously. |
| **Adolescent** | Month 6 | Deep understanding of professional domain, coding style, creative preferences. Handles complex multi-step workflows independently. |
| **Adult** | Year 1+ | Functions as a true cognitive extension. Handles novel tasks by combining learned patterns with internet research. |

This growth trajectory must be reflected in all code: features should degrade gracefully when the learning model is new/empty, and improve naturally as data accumulates. **NEVER** require a mature learning model for basic functionality.

---

## Delphi Vision and Architecture

### The North Star

Delphi is a personal operating system that operates the user's existing
software tools on their behalf to accomplish any task that can be done
on a PC. The user provides intent and judgment; Delphi provides skilled
tool-use and execution.

Delphi's structural advantage against frontier AI labs is not just "we
own the OS" — Microsoft and Apple own OSes too. The actual advantage is
that Delphi provides a coherent, vendor-neutral user experience across
all applications, owned by no single company, with user sovereignty as
the foundational commitment. Frontier labs build intelligence services
that generate outputs; incumbents build OS-bound assistants tied to
their ecosystem; Delphi builds an agentic OS that operates whatever the
user already has, with the user retaining ownership of their data and
their tools.

When asked to "draw a picture," Delphi operates Photoshop (or another
real tool) to produce an actual editable Photoshop file with real
layers — not a generated PNG. When asked to "build a presentation,"
Delphi operates PowerPoint to construct real slides. The user retains
all the power of their existing software; Delphi is the skilled
operator. This is the architectural commitment that distinguishes
Delphi from intelligence-as-a-service offerings.

### The three components

Delphi's architecture has three components that interoperate:

**1. The advanced OS** — locally installed Delphi distribution, sovereign,
capable, agentic-native via the Semantic System Interface (SSI). Runs
entirely on user hardware. Operates applications through layered
mechanisms with graceful degradation: SSI manifest when available,
accessibility-tree introspection when not, screen-and-click fallback
when neither. Cross-platform from Phase 3C onward (Linux, macOS,
Windows) — Delphi runs on whatever OS the user already has, rather
than requiring OS migration.

**2. The shared foundation model** — cloud-hosted, large enough to grow
toward general PC-task competence. Trained on a multi-source corpus
that does not require user contributions to be useful: public software
documentation, synthetic exploration data from sandboxed Delphi
instances, and teacher signals from cloud frontier models. Customer
contributions (with privacy guarantees) are optional upside. The
foundation provides every Delphi deployment with substantial general
capability from day one.

**3. The per-customer and per-user specialization** — built through
structured apprentice-style onboarding. The customer provides
documentation, product context, process descriptions, and a designated
human reviewer for early outputs. Delphi ingests this material, learns
the customer's specific operational context, performs early work in
Assisted mode under review, and gradually promotes to Autonomous mode
per task category as competence demonstrates. Within the customer
deployment, each user's Delphi instance further specializes to their
role(s), tasks, and working patterns — understanding what they do,
what good output looks like for their work, and what should escalate
to humans.

The three-layer personalization (foundation + company specialization +
user role specialization) is the architectural commitment that enables
both broad capability and deep contextual fit. Cross-role-within-
company knowledge sharing is customer-configurable, defaulting to
per-user isolation for privacy.

### How the three components interact

User intent flows into the local OS. The local personalization layer
interprets the intent in the user's role context. For execution, the
local OS draws on the shared foundation model's tool-use competence
(provided via cloud inference or distilled local components,
depending on the task's latency requirements). Heavy reasoning may
invoke cloud frontier models. Tool-use itself happens locally via SSI
or graceful fallbacks. Outputs are native artifacts in the user's
actual software.

Over time, with the customer's consent, anonymized procedural patterns
(Layer 1) and intent context (Layer 2, where research permits) flow
back to the shared foundation under differential privacy guarantees.
The foundation grows; all deployments benefit. Personal/company
content (Layer 3) never leaves the customer's environment.

### Growth contract — what the cloud model learns and how

The shared foundation model trains on a corpus assembled from multiple
sources. Robust against failure of any single source:

**Always available (do not require user contributions):**
- Public software documentation (Microsoft Docs, Adobe knowledge base,
  Stack Overflow, application tutorials, accessibility tree dumps of
  common applications)
- Synthetic session data from sandboxed Delphi instances exploring
  applications according to documentation
- Teacher signals from cloud frontier models (their reasoning about
  software workflows produces training data without seeing user data)

**Available via consenting customer contributions (optional upside):**
- Layer 1: aggregated procedural patterns (action sequences,
  application contexts, tool-choice distributions, error and recovery
  patterns, parameter shapes). No content, no identifiers. Subject to
  differential privacy guarantees on aggregation.
- Layer 2: intent and decision context (what kind of task, which
  choices made among alternatives, technique shape). Requires safe
  extraction with formal privacy guarantees. Subject of parallel
  research track. Ships when ready, in domains where ready, not on a
  forced timeline.

**Layer 3 (specific personal/company content):**
Never leaves the customer's deployment under any circumstances. The
boundary between Layer 2 and Layer 3 is enforced by extraction logic,
audit, and (where appropriate) cryptographic guarantee.

The foundation model is useful and growing under any combination of
sources active. Phase 3B will run an empirical validation experiment
to measure the foundation's capability on public + synthetic + teacher
sources alone, before the architecture's robustness story depends on
customer contributions.

### Substrate evolution by version

**v0.4 (current, tagged after Phase 3A close):** SQLite stores,
statistical models, retrieval-based personalization, SSI auto-
generation, cloud frontier inference for heavy reasoning, Fortress in
progress. Functional but pre-product.

**v0.5 (Phase 3B target):** Three-layer personalization substrate
(foundation + company + user role). Retroactive Codex sweep complete.
Shared foundation model trained on public + synthetic + teacher
sources, with validation experiment measuring capability. Structured
apprentice-style onboarding framework. First-customer identification
and pilot conversations in parallel. Accessibility first-class from
this version.

**v0.6 (Phase 3C target):** First production pilot deployment with a
software development company customer. Universal learning engine
maturity. Cross-OS expansion (Linux + macOS + Windows). SSI authoring
tools and 50 pre-built manifests prioritizing developer tools.
Fortress completion of items relevant to enterprise deployment.
Onboarding UX as first-class deliverable, not just backend.

**v0.7+ (Phase 4):** Additional customer deployments. Operational
maturity. Foundation model improvements from customer contributions
where opted in. Federated learning with differential privacy
infrastructure (Phase 4-relevant; Phase 3B/3C do not require it).
Auto-improving SSI manifests. Distillation pipeline (cloud → smaller
local) for hardware-constrained customer environments.

**v1.0 (Phase 5+, "different branch, different year"):** Consumer
edition launches. Substrate architecture preserved through earlier
phases enables this without fundamental rework. Browser extension form
factor as fast adoption path. Research platform capability if
appropriate. The consumer launch is a different product than the
enterprise editions, sharing substrate but with different deployment
model, pricing, and UX.

### Iron Law #14: Capabilities must not retreat from the North Star

Every new capability and architectural decision is measured against
the vision: does this preserve, advance, or retreat from "an OS that
operates the user's tools on their behalf to accomplish any task
while preserving user sovereignty?" Decisions that preserve or
advance are evaluated on their own merits. Decisions that retreat
require explicit justification and acknowledgment.

This law is intentionally narrower than "must advance the North
Star." Infrastructure work (security, performance, accessibility,
testing, refactoring) qualifies as non-retreat. The bar is to avoid
drift, not to require every commit to be visionary.

### Architectural risk mitigations — auditable requirements

Each commitment below is audited against implementation in its target
phase. These are not aspirational — they are concrete architectural
requirements.

**Multi-tier operation across all applications.** SSI manifest when
available, accessibility-tree introspection when not, screen-and-
click fallback when neither. No application is out of reach. Computer-
use fallback is a first-class operation mode, not a degraded one.

**Multi-vendor frontier model support.** Never depend on a single AI
lab. Architectural support for Anthropic Claude, OpenAI GPT, Google
Gemini, and other providers as they emerge. Graceful operation when
any provider becomes restrictive or unavailable.

**Tiered local model architecture.** Not "the local personalization
model" but a stack: ~50M parameter classifier for real-time use
(latency budget <50ms on CPU), ~200M parameter style transformer for
on-request operations (latency budget <2s), ~500M parameter unified
model for batch operations. Hardware-aware deployment selects sizes
based on available compute.

**Differential privacy at every aggregation layer.** Even Layer 1
contributions need DP guarantees on aggregation because aggregate
patterns can reveal user categories at scale. Layer 2 contributions
require formal DP plus federated learning infrastructure.

**Multi-source cloud training corpus.** User contributions are one
source, not the only source. Foundation model viable even without
user contributions.

**Multi-OS support from Phase 3C.** Linux, macOS, Windows. The current
Linux-targeted compositor work is the first deployment; cross-OS
expansion in Phase 3C. Substrate decisions made with all three
platforms in mind from now on.

**Efficiency as first-class concern.** Every capability specifies its
latency budget per task type. Inference latency targets: real-time
queries <100ms (local), interactive queries <2-3s (with cloud),
batch operations bounded by task complexity not multiples of human
time. Aggressive optimization at every layer (quantization, caching,
parallelization, smart pre-fetching). Graceful degradation under
load — quality reduces gradually, not failures.

**Default to Assisted mode for new deployments.** Customers and users
begin in Assisted mode (Delphi proposes, human approves). Autonomy is
earned per task category as Delphi demonstrates competence. Auto-
nomous mode is not the default; it is the destination.

**Visible action timeline scrubbing.** Every Delphi action recorded
in the action timeline with full context. Users can scrub backward
through Delphi's actions. The 24-hour undo window is a first-class
visible affordance, not invisible UI.

**Open SSI standard.** SSI is published as an open specification with
governance process. Other agentic systems can implement SSI. Delphi
is the reference implementation. SSI manifest community registry
enables external contributions. This is the ecosystem development
that makes "any application" practical.

**50 pre-built SSI manifests, developer tools first.** Phase 3C
delivers manifests for the top 50 applications in the developer
tools domain (VS Code, JetBrains IDEs, Git/GitHub CLI, common
language runtimes, browsers, terminals, Slack, Linear/Jira,
documentation tools, design tools commonly used by devs). Extends
to other domains as additional customer industries are pursued.

**User research / pilot feedback as Phase deliverable.** Every Phase
3B onward ships includes structured feedback from real users (Phase
3B: alpha testing with five users; Phase 3C onward: pilot customer
feedback). Architecture decisions are validated against actual user
response, not designer assumption.

**Accessibility as first-class concern from v0.5.** People with
motor disabilities, visual impairments, cognitive disabilities, and
other accessibility needs benefit substantially from agentic OS
operation. Accessibility is not a v1.0 feature; it is part of the
substrate from Phase 3B.

**Architectural preservation of consumer launchability.** Phase 3B-
3C decisions consider both enterprise B2B and eventual consumer
deployment. Some substrate complexity (10-15% additional work) is
the cost of keeping the consumer option real. Phase 5+ consumer
launch is a planned future, not abandoned.

### Validation experiment — committed for Phase 3B

Phase 3B will run an empirical validation experiment before betting
architectural robustness on customer contributions. Build the cloud
database with public + synthetic + teacher sources. Train an early
version of the shared foundation model. Measure its capability on
held-out tool-use tasks across the developer tools domain. The
result is empirical:

- If the model is substantially capable on public + synthetic +
  teacher alone, the architecture is robust against research failure
  of Layer 2 contributions
- If it is marginal, Layer 2 is critical and Phase 3D research
  becomes priority

This experiment is the first-class Phase 3B deliverable that resolves
the largest open question in the architecture.

### Timing posture

The roadmap is structured as a sequence of versions, each shipping a
meaningful subset of the vision. Specific calendar dates are not
committed. Honest working estimates calibrated to 20 hr/week
capacity:

- Phase 3A close (3A.6 + tag): 1 month
- Phase 3B (personalization substrate + sweep + foundation +
  validation): 16-22 months
- Phase 3C (cross-OS + first pilot + universal learning + Fortress
  completion + remaining capabilities): 24-36 months beyond v0.5
- Phase 4 (additional customers + operational maturity + federated
  learning if research permits): 18-30 months beyond v0.6
- Phase 5+ (consumer branch launch): begins post-Phase-4, timeline
  determined when v0.7 ships

Working estimate for v0.7 (full three-component vision substantially
operating): 5-8 years from now. This is not a deadline; it is an
honest working range. Velocity will be measured against Phase 3B
execution and ranges revised.

### Research-grade work as parallel track

Some elements of the vision are research-grade rather than
engineering-grade:

- Layer 2 extraction with formal privacy guarantees
- Federated learning with differential privacy at production scale
- The unified personal model (large local model that genuinely
  reasons in the user's voice)

These are pursued on a parallel research track that does not block
production shipping. Phase 3B-3C ship the engineering-grade portions
(Layer 1 contributions, tiered local personalization models, multi-
source foundation training). Research outputs integrate when ready.
This is the discipline that protects against the failure mode where
ambitious research prerequisites stall production.

### Honest acknowledgments

The plan has known uncertainties. Documenting them honestly is part
of the architecture, not separate from it.

**First-customer sales execution path is uncertain.** Current
strategy: build product through v0.5-v0.6, partnership and revenue
identified at Phase 3C pilot deployment transition. Solo founder
profile is acknowledged risk; possible mitigations include cofounder
recruitment, accelerator participation, or advisor cultivation when
appropriate.

**Capacity calibration: 20 hr/week.** Phase 3B and beyond timeline
estimates assume this capacity. Parallel commitments (coursework,
UrbanFL, Soteria, other research) continue at their existing cadence.
Phase 3C+ planning is contingent on post-graduation configuration.

**Funding model.** Phase 3B operates at minimal infrastructure cost
suitable for self-funding (small models, modest cloud usage,
prototyping). Phase 3C pilot deployment transition requires funding
source identified by then — pilot customer revenue, partnership
investment, grants, or other source. Funding model is not committed
in this document; it is acknowledged as a Phase 3C-critical decision.

**Phase 3A.6 scope was set under previous consumer-OS framing.**
Generative workspace creation ships with original four templates
(research / code / document / design). Enterprise-specific developer-
focused templates added in Phase 3B as part of the developer tools
focus.

**Three-layer personalization architecture complexity.** Composing
foundation + company specialization + user role specialization is
non-trivial. Phase 3B's first weeks include architectural design work
for the layer-composition model: how the three layers compose for
inference, how training of one affects the others, how foundation
updates propagate without invalidating existing specializations.

**Cross-OS expansion adds substantial Phase 3C scope.** Current
codebase is Linux-targeted. Cross-OS work requires per-OS
accessibility API implementations, cross-platform UI layer (likely
Tauri-based or similar), per-OS Fortress hardware integrations
(TPM, Secure Enclave), and build/test/deployment infrastructure
across three platforms. This expansion is the cost of consumer
launchability preservation and enterprise customer flexibility.

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

### Additional Dependencies (Phase 1+)

| Component | Technology | Version | Notes |
|-----------|-----------|---------|-------|
| AT-SPI bindings | atspi | latest | SSI auto-generation from accessibility trees |
| Database | rusqlite (bundled) | 0.35.x | Action timeline, learning patterns |
| HTTP client | reqwest + rustls | 0.12.x | Cloud inference, web browsing |
| HTML parsing | scraper | latest | Web content extraction |
| PDF text extraction | pdf-extract | latest | Semantic-fs PDF indexing |
| Audio playback | rodio or cpal | latest | Voice output playback |
| Process management | tokio::process | (part of tokio) | Playwright, Piper, Whisper subprocess management |
| Regex | regex | latest | PII detection in ZKQP |
| UUID | uuid (v4 feature) | latest | Action IDs, task IDs, pattern IDs |
| Filesystem watching | notify | 8.x | Already in use for semantic-fs |
| Template engine | minijinja | latest | Code generation templates in the builder |

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

### Subprocess Management Pattern

All external process integrations (Playwright, Whisper, Piper, llama-cli) must follow the established pattern:

1. Spawn process with piped stdin/stdout via `tokio::process::Command`
2. Communicate via JSON lines over stdio (one JSON object per line)
3. Enforce configurable timeouts on every operation (send AND receive)
4. Set `kill_on_drop(true)` so the process is cleaned up if the engine is dropped
5. Graceful degradation: if the subprocess binary is missing, return a clear error with installation instructions — do not crash

### D-Bus Service Pattern

All D-Bus services must follow this pattern:

1. Interface name: `org.delphi.{ServiceName}`
2. All methods return `Result` types (never panic on D-Bus calls)
3. All signals include a timestamp
4. Service wrapper lives in the `services` crate, actual logic lives in the domain crate
5. Services must be independently startable (for testing) and collectively startable (via `delphi-daemon`)
6. Use `std::sync::Mutex` (not `tokio::sync`) for `!Send` types (rusqlite, tantivy) in zbus interfaces

### SQLite Connection Policy

Codified in round 7 after Codex F19/F20/F21 surfaced that the project had been relying on rusqlite's default `busy_timeout` (currently 5000 ms but documented as "subject to change") and was unable to distinguish transient lock contention from genuine schema/logic failures at the type level. Refined in round 8 (F22/F23/F24) to consolidate the helpers and close the in_memory parity + retry-budget off-by-one gaps. Every public store that opens a `rusqlite::Connection` MUST:

1. **Set `busy_timeout` explicitly** to a documented value (5 s baseline, configurable per store if a store has documented contention requirements). Do not rely on the rusqlite default. Canonical implementation: call `die_orchestrator::sqlite::init_sqlite_connection(&conn)?` right after `Connection::open` (or `Connection::open_in_memory`) and before any pragma-altering statement. **This applies to `in_memory()` constructors too** — default `:memory:` databases are private to a single connection per SQLite docs ("Every :memory: database is distinct from every other") and cannot see cross-connection lock contention, but constructor parity is the regression-detection mechanism: future drift where someone copies an init path and forgets the pragma is caught by the `busy_timeout_pinned_to_5_seconds` tests every store ships.

2. **Map `rusqlite::Error::SqliteFailure` with `ErrorCode::DatabaseBusy` or `ErrorCode::DatabaseLocked`** into a typed transient-error variant (`OrchestratorError::TransientLock`) via `die_orchestrator::sqlite::map_sqlite_err(err, context)`. All other `rusqlite::Error` variants retain their existing `Planning` classification with the caller-supplied context preserved. The base `ErrorCode` mask catches both base and extended busy/locked codes (`SQLITE_BUSY_RECOVERY`, `SQLITE_LOCKED_SHAREDCACHE`, etc.) per libsqlite3-sys's `Error::new`. Direct construction of `OrchestratorError::Planning` from a `rusqlite::Error` is a policy violation — the shared helper is the only sanctioned translation site.

3. **If multi-process opener contention is a documented possibility**, wrap the open path in the standard retry-with-backoff loop. Canonical implementation: `die_orchestrator::knowledge::retry_with_backoff` (generic over the success type; reusable). Loop matches *only* on `OrchestratorError::TransientLock`; any other error short-circuits immediately. Defaults: `MAX_OPEN_ATTEMPTS = 6`, `INITIAL_BACKOFF_MS = 100`, doubled per attempt up to `MAX_BACKOFF_MS = 2000`, giving the documented `100 → 200 → 400 → 800 → 1600 ms` inter-attempt sleep sequence (5 sleeps across 6 attempts). Jitter is drawn from `SystemTime` nanoseconds (no `rand` dep). Worst-case opener latency under sustained contention: `6 × 5 s busy_timeout + 3.1 s inter-attempt sleep ≈ 33 s` before a typed `TransientLock` reaches the caller.

The **shared SQLite policy helpers** live in `die/orchestrator/src/sqlite.rs` as the single sanctioned home for project-wide connection-init policy. `KnowledgeStore`, `Timeline`, `GoalStore`, and `ConversationStore` all use `init_sqlite_connection` and `map_sqlite_err` from this module. Future stores must use the same helpers — copy-pasting the routing logic into per-store modules is explicitly forbidden because the next routing change would silently diverge across stores.

The retry loop happens at the **store-open** level, not inside the integrity-check helpers. The integrity-check function stays single-attempt; the caller (e.g., `KnowledgeStore::open`) retries. This keeps `BEGIN IMMEDIATE` semantics atomic per attempt and makes the retry boundary an explicit, documented seam rather than implicit inside multi-statement transactions.

### WebSocket Bridge Pattern

All shell-to-backend communication goes through the WebSocket bridge:

1. Shell sends JSON: `{"id": N, "method": "service.method_name", "params": {...}}`
2. Bridge returns JSON: `{"id": N, "result": {...}}` or `{"id": N, "error": {"code": N, "message": "..."}}`
3. Streaming responses use the same ID with `"partial": true` until final message with `"partial": false`
4. Bridge must not buffer — forward partial responses immediately for real-time UI updates
5. TypeScript client uses a pending-promise `Map<id, {resolve, reject}>` for request-response correlation

### The "Best Answer" Rule

When the AI has both a predicted/pattern-based answer and a fresh/computed answer, **ALWAYS** prefer the fresh answer. Learned patterns should accelerate execution, not override explicit computation. If the user asks "what's the weather?" and the pattern says "they always want Chennai weather," but the user might be traveling — still ASK or compute, don't assume. User's explicit request > predicted pattern. Always.

### Accessibility Rules (WCAG 2.1 AA Minimum)

- **ALL** shell components must have ARIA labels for screen readers
- **ALL** interactive elements must be keyboard-navigable (Tab order, Enter to activate, Escape to dismiss)
- **ALL** text must meet 4.5:1 contrast ratio against its background
- **ALL** animations must respect `prefers-reduced-motion` media query
- **ALL** notifications must be announced to screen readers via `aria-live` regions
- Voice input must work as a **COMPLETE** alternative to keyboard/mouse — every action achievable by voice
- The onboarding flow must be fully completable by a blind user using screen reader + keyboard
- Focus management: when modals/overlays open, focus moves to them; when they close, focus returns to the trigger element
- Error messages must be programmatically associated with their input fields

---

## Section 4: Architecture Rules

### Module Boundaries (CRITICAL)

Violations of these boundaries break the entire system:

1. **Living Surface (UI) NEVER directly calls inference.** It sends intents to the DIE orchestrator via D-Bus. The orchestrator decides which tier/specialist handles it.
2. **The DIE NEVER directly accesses the filesystem.** It goes through the Semantic FS service which enforces permissions and maintains the index.
3. **The Fortress NEVER exposes raw keys or decrypted data to any other module.** It provides opaque capability tokens.
4. **The Inference Scheduler NEVER makes decisions about WHAT to infer.** It only manages HOW and WHEN inference runs (resource scheduling). The orchestrator decides what.
5. **The SSI layer NEVER trusts app-reported capabilities.** It validates by testing each capability before adding to the manifest.

#### Learning Engine Boundaries

- The learning observer **MUST NOT** record events for disabled categories (even temporarily, even for "analysis")
- The learning engine **MUST NOT** access file contents — it observes metadata only (app name, file path, timestamp, action type)
- Pattern suggestions **MUST** go through the shell as notifications — the learning engine cannot execute actions directly
- **ALL** learning data **MUST** be encrypted via Fortress — never plaintext on disk

#### ZKQP Boundaries

- **ALL** Tier 3 cloud queries **MUST** pass through ZKQP — no direct cloud calls from any module
- ZKQP **MUST NOT** modify the semantic content of queries — only strip/replace identifying information
- The local PII-to-placeholder mapping table **MUST** be encrypted and stored only in memory (never disk)
- If ZKQP cannot adequately anonymize a query (privacy score > 80), it **MUST** pause and ask the user

#### Builder Boundaries

- The builder **MUST NOT** execute generated code outside of a sandboxed environment
- Generated projects **MUST** be placed in a user-specified output directory — never in system directories
- The builder **MUST NOT** install system-level packages without Tier 2 (Confirm) permission
- Build artifacts (`node_modules/`, `target/`, `venv/`) **MUST** be excluded from semantic-fs indexing

#### SSI Boundaries

- SSI auto-generation **MUST NOT** execute discovered capabilities without user consent
- SSI manifests are APPROXIMATIONS — the confidence score must be presented to the user
- SSI **MUST NOT** scan apps in Focus mode
- SSI execution of app capabilities **MUST** go through the action timeline (for undo support)

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
die-browser      (standalone — subprocess management only)
die-voice        (standalone — subprocess management only)
die-learning     (depends on: fortress)
semantic-fs      (depends on: fortress)
  ↑
die-orchestrator (depends on: die-inference, die-browser, die-learning, semantic-fs, fortress)
  ↑
delphi-services  (depends on: die-inference, die-orchestrator, semantic-fs, fortress)
  ↑
shell-bridge     (depends on: delphi-services, die-inference, die-orchestrator, semantic-fs)
```

Adding a dependency that creates a cycle is a **compilation error** (Cargo enforces this) and a **design error** (fix the architecture, not the dependency).

### Scalability Rules

- All services must be single-process by default but support multi-process via config.
- All data stores must handle **1TB+** of indexed content without degradation.
- All inference paths must work with models from **1B to 100B+** parameters.
- All network operations must have configurable timeouts and retry logic with exponential backoff.
- All background tasks must be cancellable and report progress.
- All caches must have configurable size limits and LRU eviction.

### Conversation Memory Architecture

- Conversations are stored as a chain of `(user_message, assistant_response, timestamp, context_snapshot)` tuples
- Storage: SQLite database in Fortress-encrypted data directory
- Conversation context includes: active files, running apps, current project, recent actions — so when the user says "that thing from yesterday," the system can resolve the reference
- Conversation history is searchable: "what did I ask about convergence last week?" queries the conversation database
- Memory tiering: last 24 hours = full context available, last 7 days = summarized, older = keyword-searchable only
- Conversation data is part of the "forget" system: "forget today" purges today's conversations too
- Conversations **NEVER** leave the device — not even in summarized form. Cloud queries are stateless (each is independent, no conversation history sent to cloud)

### Knowledge Graph Architecture (for Capability #17)

- Personal knowledge graph stored in LanceDB (vector embeddings) + SQLite (relationships)
- Nodes: concepts, people, projects, files, facts, opinions
- Edges: "relates to," "contradicts," "supports," "created by," "part of"
- Populated from: documents the user reads (opt-in), notes they write, conversations with Delphi, web research results
- Queryable: "what do I know about non-IID convergence?" returns relevant nodes with source citations
- NOT a replacement for file search — this is conceptual/semantic, file search is path/content

### Fidelity declarations (REQUIRED for every integration)

Every module that reads from or writes to an external source must include a fidelity declaration in its module-level documentation. Format:

```rust
//! # Fidelity levels supported
//!
//! This module probes interfaces in the following order:
//!
//! 1. **[name]** (preferred) — [what it provides, why it's highest fidelity here]
//!    - Required: [what needs to be installed or configured]
//!    - Failure modes: [when this level is unavailable]
//!
//! 2. **[name]** (fallback) — [what it provides]
//!    - Required: [prerequisites]
//!    - Tradeoffs: [what's lost vs level 1]
//!
//! 3. **[name]** (last resort) — [what it provides]
//!    - Required: [prerequisites]
//!    - Tradeoffs: [what's lost vs previous levels]
//!
//! Every public function in this module returns a `Fidelity` value alongside its result,
//! indicating which level answered the query.
```

All modules that were built before this rule existed must have fidelity declarations added the next time they are substantially modified. Modules built going forward must include the declaration from the first commit.

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
├── services/                   # D-Bus service wrappers [Phase 1]
├── shell-bridge/               # WebSocket bridge (React ↔ D-Bus) [Phase 1]
├── proto/                      # Protobuf IPC definitions [Phase 0]
├── shell/                      # Living Surface UI (React 19)
│   ├── src/
│   │   ├── modes/              # Direct, Assisted, Autonomous, Focus
│   │   ├── components/         # Topbar, dock, window manager, settings
│   │   ├── command-bar/        # Alt+Space command interface [Phase 0/1]
│   │   ├── services/           # WebSocket client (delphi-client.ts) [Phase 1]
│   │   ├── timeline/           # Action timeline UI [Phase 2]
│   │   ├── onboarding/         # Learning mode / first-boot [Phase 2]
│   │   └── action-timeline/    # Undo system UI
│   └── package.json
├── die/                        # Delphi Intelligence Engine
│   ├── orchestrator/           # Central brain + task planner (Rust) [Phase 0/1]
│   │   └── src/
│   │       ├── brain.rs        # Web-augmented inference [Phase 1]
│   │       ├── apps.rs         # Cross-app orchestration [Phase 2]
│   │       ├── planner.rs      # Intent decomposition [Phase 0]
│   │       └── timeline.rs     # Action timeline [Phase 0]
│   ├── inference/              # Three-tier inference manager [Phase 0/1]
│   │   └── src/
│   │       ├── router.rs       # Model selection logic [Phase 1]
│   │       └── cloud.rs        # Cloud API client [Phase 1]
│   ├── browser/                # Headless Chromium (Playwright) [Phase 1]
│   ├── builder/                # Full-stack project builder [Phase 2]
│   ├── voice/                  # Whisper STT + Piper TTS [Phase 1]
│   ├── learning/               # Universal learning engine [Phase 0/2]
│   │   ├── observer/           # Action observation system
│   │   ├── modeler/            # Procedural model builder
│   │   └── executor/           # Learned task execution
│   ├── specialists/            # Domain specialist models [future]
│   ├── memory/                 # Hot/warm/cold memory tiers (LanceDB) [future]
│   └── planner/                # Goal/timeline management [future]
├── ssi/                        # Semantic System Interface
│   ├── auto-gen/               # AT-SPI + D-Bus + .desktop scanners [Phase 2]
│   ├── sdk-rust/               # Rust SSI SDK [Phase 0]
│   ├── sdk-python/             # Python SSI SDK [future]
│   ├── sdk-js/                 # JavaScript SSI SDK [future]
│   └── spec/                   # SSI standard specification
├── fortress/                   # Security system
│   ├── src/
│   │   ├── zkqp/              # Zero-Knowledge Query Protocol [Phase 2]
│   │   └── ...existing...
│   ├── encryption/             # LUKS2, AES-256-GCM, PQC
│   ├── fhe/                    # Homomorphic encryption [future]
│   ├── zksnark/                # Audit chain (Circom + snarkjs) [future]
│   ├── tpm/                    # Hardware security module [future]
│   └── federated-sync/         # Cross-device sync [future]
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

### Branch workflow (MANDATORY from this point forward)

Every task must be worked on a feature branch, never directly on main.

Branch naming: `phase-{N}/{task-name}`

Examples:
- `phase-3a/task-3a4-crisis-prevention`
- `phase-3a/task-3a5-knowledge-synthesis`
- `phase-3b/specialist-mesh`

**Start of every task:**

```bash
git checkout main
git pull  # ensure main is current
git checkout -b phase-{N}/{task-name}
```

**End of every task (after self-audit passes):**

```bash
# On the feature branch, all tests green, all commits clean

# For tasks touching fortress/, services/ auth code, die/orchestrator/
# ZKQP or permissions, or ssi/ capability execution — run security review:
$prompt = "Focus on privilege escalation, auth bypass, and data leakage. Check that all cloud queries pass through ZKQP, no credentials are exposed outside the vault, and no Autonomous-tier code can trigger Biometric-tier actions."
$prompt | codex review --base main -

# Then merge to main:
git checkout main
git merge --no-ff phase-{N}/{task-name} -m "merge(phase-{N}): {task-name}"
git tag v{X}.{Y}.{Z}-phase{N}
git branch -d phase-{N}/{task-name}
```

**Which tasks require the Codex security review before merge:**

- Any task touching `fortress/` (all layers)
- Any task touching `services/` files that handle credentials or permissions
- Any task touching `die/orchestrator/` ZKQP, permission tiers, or vault access
- Any task touching `ssi/` capability execution
- Every phase boundary merge (always, no exceptions)

**Tasks that do NOT require security review (can merge directly):**

- Pure documentation changes
- Test-only changes with no production code
- `PROGRESS.md` updates
- Shell UI changes with no backend auth involvement

### Codex Adversarial Review Process

Delphi uses an external second model — Codex CLI, run by the human operator — as a cold adversarial reviewer. This process is distinct from, and complementary to, the per-task security-review *gate* in Section 8: the gate decides *whether* a task needs review; this process defines *how* a multi-round adversarial sweep is conducted once review is warranted. The methodology was proven across Task 3A.5 (nine rounds, 23 findings F4–F26) and Task 3A.6 (five rounds, 14 findings R1–R5); this section promotes that precedent from PROGRESS.md narrative into project law.

**Two modes:**

1. **New-code review** — security-critical code written for a task is swept before its merge to main. Rounds are authorized incrementally and run to convergence.
2. **Retroactive sweep** — an already-merged crate is re-reviewed to apply threat-model lessons learned later. Retroactive sweeps run on a dedicated `phase-{N}/sweep-{crate}` branch with a **3-round budget** unless the operator explicitly extends it. (The Phase 3B.0 sweeps of `services/`, `die/orchestrator/`, and `fortress/` apply Task 3A.6's threat model — see "Phase 3B priority items" in PROGRESS.md.)

**Separation of duties (non-negotiable):** Claude Code does NOT run Codex — it is a separate tool on the operator's machine. Claude Code *prepares* the adversarial review prompt and then STOPS. The operator runs Codex and pastes the verdict back. Claude Code never declares a sweep "passed" on its own authority; only a pasted Codex verdict closes a round.

**The cold-reviewer prompt MUST:**

- Scope the review to an exact, named target — a commit range (`git diff A..B`), the uncommitted diff, or a specific crate/module — and state the diff stat the reviewer should expect, so scope drift is detectable.
- Demand tool grounding: the reviewer verifies library/API claims against Context7 (or docs.rs / official docs) and inspects the live code via the Codex CLI rather than reasoning from memory (Iron Law #12 / Section 13 applied to the reviewer).
- Focus on a named attack surface (e.g. D-Bus input validation, path-safety / TOCTOU, SQLite migration atomicity under concurrent openers, subprocess argv / working-directory containment).
- Require a structured verdict — **APPROVE** / **REVISE** / **FAIL** — with every finding carrying an ID, a severity (P1-high → P2-medium → P2-low → P3-informational), a root-cause statement, an impact statement, and a fix sketch.

**The round loop:**

1. Operator runs Codex with the prepared prompt and pastes the verdict.
2. APPROVE → proceed to merge. REVISE / FAIL → continue.
3. Claude Code fixes **every** finding at its root cause (Iron Law #8) — no workarounds, no scope creep into adjacent issues.
4. Each fix ships a regression test verified to **fail against the pre-fix code** and pass after. A test that passes against buggy code is worse than no test (Task 3A.6 Round 3 caught exactly this — a descendant-survival test that passed for the wrong reason because the backgrounded process inherited the capture pipes).
   **A single green run cannot see NON-DETERMINISM — this is a known gap in the review protocol, not merely a property of one test.** Codex reviews a diff and a test run; a test that fails 1 run in 10 presents as green and passes review invisibly. This is not hypothetical: `terminal_contract_release_produces_eof_no_wedge` (~7-10% failure rate under parallel execution, measured 3/30 at `d57442e`) landed inside the **Codex-APPROVED** B2a WSL2-provable half (`3e40e22`) and was found only when a later session happened to run the suite repeatedly. **Therefore:** any test whose outcome depends on file descriptors, `fork`/subprocess lifetime, sockets, timing, or cross-test shared state MUST be run **repeatedly (>=30 iterations) under the DEFAULT parallel settings** before it is offered to review — not once, and not only under `--test-threads=1`, which is precisely the configuration that hides interference. Report the iteration count and the failure count, not "tests pass." A flaky test is strictly worse than a failing one: it trains the reader to re-run until green.
   **CARVE-OUT — `fork`+PAM (or `fork`+any non-async-signal-safe child) tests are SERIAL-ONLY; their ≥30 run is `--test-threads=1`, and that is NOT the hiding configuration for them.** The default-parallel rule above assumes parallel execution stresses the *product*. For a test that `fork()`s and then does non-async-signal-safe work in the child (PAM, allocation, D-Bus — e.g. `runtime/tests/leader_is_shell.rs`'s B-1/FD-01/B-3), the parallel test runner is itself a **multithreaded parent**, and forking PAM from a multithreaded parent is the hazard `launcher.rs`'s standing constraint documents — the child can deadlock on an allocator lock a non-surviving thread held. **Production (`delphi-runtimed`) is single-threaded, so it never has this hazard;** the parallel FAILURES are therefore a *harness artifact of the test runner*, not product flakiness — measured 2026-07-23: B-1/FD-01/B-3 fail ~20/30 under parallel (ALL failures pre-`execve` child death, ZERO real property violations) and **0/30 under `--test-threads=1`**. For these tests the SERIAL ≥30 run is authoritative: it matches production's single-threaded fork parent while still catching within-test races (timing, `/proc`, PAM/logind). Distinguish this honestly per Iron Law #15 clause 5 — a parallel failure is a harness artifact ONLY when SHOWN to be pre-`execve` child death with no real violation (read the failing lines; do not assume). This also retroactively explains the earlier FD-01 "15/30 parallel, 0/30 serial" result, which was imprecisely attributed to "shared VT/PAM state" — the sharp cause is fork+PAM from a multithreaded parent. **Sibling mechanism (same carve-out, different plumbing) — CONCURRENT PAM SESSIONS ON A SHARED VT.** `b1_integration`'s `b1_daemon_binary_runs_the_assembled_flow` runs the daemon as a SINGLE-threaded subprocess (so NOT the multithreaded-fork hazard), yet fails 30/30 parallel / 0/30 serial with VARYING reasons (`pam_open_session failed`, `logind: session not active+local`, `PAM authentication failed`) — a race among all `b1_integration` tests opening PAM sessions on the SAME `tty1` under parallel execution (measured 2026-07-24). Production runs ONE daemon per session on its OWN seat's VT, never N contending on one — so this too is a test-harness artifact, serial-only, not a product defect. The general rule: a test that opens a PAM/logind session (by fork+PAM OR by spawning a PAM-using subprocess on a shared VT) is SERIAL-ONLY; its parallel failures are contention the harness creates and production forecloses.
5. One focused commit per round, with the verbatim Codex finding IDs in the body. Carried-forward noise (Cargo.lock, PROGRESS.md) defers to a final cleanup commit so each round's diff stays narrow and auditable.
6. Claude Code prepares the next round's prompt (scoped to the new fix commit) and STOPS for the operator to re-run Codex.

**Stopping criteria, budget, and merge:**

- Convergence signal: findings degrade from new-attack-surface (P1) to inherited-policy-drift (P2-low / P3). A round returning only policy nits, or APPROVE, means the sweep has converged.
- A REVISE / FAIL verdict at the 3-round budget boundary escalates to an explicit human decision — *merge-with-documented-risk* vs. *extend the budget* — and does NOT auto-stretch to another round. Record the decision in the merge commit body and PROGRESS.md.
- On APPROVE, merge to main via `git merge --no-ff phase-{N}/sweep-{crate}`; the branch carries the round fix-commits and their regression tests. A sweep that returns APPROVE on round 1 with zero findings has nothing to merge — record the clean result in PROGRESS.md and delete the branch.
- Every sweep keeps a per-finding ledger (ID, severity, root cause, fix commit) in the merge commit body and a summary in PROGRESS.md, so the full review history is reconstructable from git alone.

### Git history surgery — NEVER rewrite history with a dirty working tree

**The rule: commit or stash before any operation that moves `HEAD`.** `git reset --hard`,
`rebase`, and the reset-amend-cherry-pick dance used to amend a **non-HEAD** commit all move
`HEAD`, and `--hard` discards every uncommitted change to a *tracked* file, irreversibly —
those changes were never in git, so there is no reflog entry, no dangling object, nothing to
recover from.

Amending a non-HEAD commit is where this bites, because the surgery *requires* moving `HEAD`
and the natural moment to do it is right after finishing the work that is still uncommitted.

**Recorded because it happened (B2a C1, 2026-07-22).** A `git reset --hard HEAD~1` — to amend
the commit one below `HEAD` — destroyed three fixture fixes, a new test file's contents, and a
`PROGRESS.md` rewrite. It was recovered **only because those edits happened to have been made
by scripted `python` patches that could be re-run**. That is luck, not a property of the
workflow: hand-edits, or scripts already overwritten, would have been simply gone. **Do not let
the rule's justification rest on recoverability.**

Procedure for amending a non-HEAD commit:

```bash
git status --porcelain            # MUST be empty (or stash first: git stash push -u)
git tag tmp-keep HEAD             # preserve anything above the target
git reset --hard <target>~1  ...  # only now is --hard safe
```

### Process failures damage the work — check the tooling before the code

Three failures in the B2a C1 session were **process** failures, not product defects, and each
was the actor damaging or misreporting the very thing it was working on:

1. **A fabricated test transcript** written into a commit body — a PASS that no run produced.
2. **Test fixtures deleting the operator's installed `/etc/pam.d/delphi-runtime`** mid-run,
   whose symptom surfaced far away as unrelated tests reporting "not installed"
   (`docs/DEFECT_CLASSES.md` Class 16).
3. **`git reset --hard` with a dirty tree** destroying uncommitted work (above).

**None was caught by self-check.** Each was caught by an EXTERNAL check: the operator noticing
the transcript, the runner's before/after `md5sum` of the PAM stack, and `git status`. The
generalisation worth carrying: when a result looks wrong, **suspect the harness, the fixture,
and the VCS operation before suspecting the code under test** — those failures present as
product defects, cost the most diagnostic time, and are invisible to the actor that caused
them. Build the external check (a checksum, a hygiene guard, a status assertion) rather than
trusting care.

### Dev environment sync

The canonical source of truth is `origin` (the shared GitHub remote at `https://github.com/Revanth574/Delphi.git`, private). Windows tree and WSL2 mirror BOTH push and pull from origin. The prior pattern of treating Windows as authoritative and rsync'ing Windows → WSL is DEPRECATED — it caused silent `.git` divergence during Task 3A.5 round 6 (see PROGRESS.md history for the rsync-residue stash incident).

Established 2026-05-16 immediately after the Task 3A.5 merge as a one-time bootstrap. WSL's prior `windows` remote (pointing at `file:///mnt/c/Users/kvlnr/OneDrive/Desktop/Delphi`) has been removed; both trees now share `origin`.

**Windows tree location (relocated 2026-05):** the Windows working tree now lives at `C:\dev\Delphi` (a non-cloud-synced path). It was moved out of its former location under OneDrive (`C:\Users\kvlnr\OneDrive\Desktop\Delphi`), which is retained as `Delphi-onedrive-archived-2026-05`. Keeping the working tree and its `.git` directory outside a continuously-syncing cloud folder avoids object-store corruption and lock contention from background sync racing git operations. The origin-canonical sync model above is unchanged — the relocated tree pushes / pulls from the same `origin`; only the local filesystem path changed. (Any tooling, scripts, or PROGRESS.md notes still referencing the OneDrive path are stale and should be updated to `C:\dev\Delphi`.)

**WSL HTTPS-git auth note:** WSL git's credential helper is configured locally (per-repo, not global) to delegate to the Windows Git Credential Manager at `/mnt/c/Program Files/Git/mingw64/bin/git-credential-manager.exe`. This shares the single Windows credential store across both trees, satisfying CLAUDE.md §10 ("never store credentials outside the Fortress vault" — the Windows credential vault is the closest available equivalent until Fortress's federated credential layer ships). If you ever see a hung WSL `git fetch`/`git push`, the credential helper is missing or misconfigured: re-run `git config --local credential.helper '/mnt/c/Program\ Files/Git/mingw64/bin/git-credential-manager.exe'` from the repo root.

**Build target-dir + pre-commit hooks (WSL dev convenience, codified 2026-06-13):** the workspace `.cargo/config.toml` pins `build.target-dir` to a WSL-native path (`/home/raven/delphi-target`) so build artifacts stay off the slow `/mnt/c` 9p mount. Cargo commands therefore **no longer need a manual `export CARGO_TARGET_DIR=…` prefix** — `cargo check`/`test`/`clippy` from the repo root pick it up automatically (this retires the old inline-export operational convention). The path is a documented developer-local assumption (it is `raven`-specific); `.cargo/config.toml` carries per-environment override notes, and the `CARGO_TARGET_DIR` env var still overrides it (CI sets its own, so it never depends on `/home/raven`). Enable the lint pre-commit gate once per clone with `git config core.hooksPath .githooks` (`.githooks/pre-commit` runs `clippy -D warnings` on the crates with staged changes). There is intentionally **no `cargo fmt` gate yet** — the workspace is not rustfmt-clean (76/101 `.rs` files diverge from rustfmt defaults; no `rustfmt.toml`), tracked as a deferred honest-record item: rustfmt is to be adopted as its own isolated `style(workspace)` commit (pinned `rustfmt.toml` + `.git-blame-ignore-revs`), never as a side-effect, at which point the fmt gate is added to the hook.

**Required for every cross-tree handoff:**

- End of session on one tree: `git push origin <branch>`
- Start of session on the other tree: `git fetch origin && git status`

**Drift detection:** if `git status` ever shows "Your branch and 'origin/<branch>' have diverged", STOP. Do not merge or rebase blindly — diagnose which tree has the unpushed commits first. Use `git log origin/<branch>..HEAD` to see what's local-only on this tree, and `git log HEAD..origin/<branch>` to see what's remote-only. Reconcile by deciding which side is correct and either `git pull --rebase`, `git reset --hard origin/<branch>` (DESTRUCTIVE — confirm first), or manual cherry-pick.

**Bootstrapping a fresh tree (e.g. a new dev machine or a cleaned WSL):**

```bash
git clone https://github.com/Revanth574/Delphi.git delphi
cd delphi
# If on WSL with Git for Windows installed on the host:
git config --local credential.helper '/mnt/c/Program\ Files/Git/mingw64/bin/git-credential-manager.exe'
git fetch --all --tags
```

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

### Required Error Messages (Phase 2+ Modules)

**ZKQP:**
- `"Privacy score too high ({score}/100): this query contains {details}. Send sanitized version instead? [Show sanitized] [Send anyway] [Cancel]"`
- `"Cloud provider unavailable. Retrying with alternate provider... (attempt {n}/3)"`

**SSI:**
- `"Could not scan {app_name}: accessibility tree unavailable. The app may not support AT-SPI. Manual manifest creation available."`
- `"Capability {name} has low confidence ({pct}%). Execute anyway? [Yes, try it] [No]"`

**Builder:**
- `"Build failed: {error}. Attempting fix {n}/3: {description}..."`
- `"Generated code has {n} type errors. Feeding errors back to inference for correction..."`

**Learning:**
- `"Pattern detected: you {description} {count} times. Automate this? [Yes] [Not now] [Never for this pattern]"`
- `"Learning paused: Focus mode active. No events are being recorded."`

**Orchestrator:**
- `"Task chain step {n}/{total} failed: {reason}. Retrying with alternative approach... (attempt {n}/3)"`
- `"Checkpoint reached (step {n}/{total}). Progress: {summary}. Continue? [Yes] [Review steps] [Cancel]"`

### Session Recovery Protocol (MANDATORY on every session start)

When starting any new Claude Code session — continuation after context compaction, fresh start, or resumption after a break — execute this protocol BEFORE any other action:

1. **Read `PROGRESS.md`** in the project root. This is the breadcrumb trail. It names the current phase, task, sub-step, and status.
2. **Check recent git history:** `git log --oneline -20`. Cross-reference the latest commits with PROGRESS.md claims.
3. **Verify current state with tests:** `cargo test --workspace --quiet` (and `cd shell && pnpm test` if shell work is active). If tests fail that PROGRESS.md claimed were green, that is the first problem to solve — do not proceed with new work on top of broken state.
4. **Check for uncommitted work in progress:** `git status` and `git diff`. Reconcile against PROGRESS.md's `## Notes` section.
5. **Verify phase/task/step matches reality.** If PROGRESS.md says "Task 3A.2 step 3 in progress" but the file it references does not exist, PROGRESS.md is stale — the recovery session's first duty is to reconstruct truth from git + filesystem, not from PROGRESS.md.
6. **Resume from the exact point indicated.** Do not re-run completed work. Do not skip forward. Do not re-plan — the plan exists in PROGRESS.md and the referenced spec sections.

**PROGRESS.md format (canonical):**

```
# Delphi OS — Progress State

Last updated: YYYY-MM-DD HH:MM UTC
Current phase: {Phase N / Phase NA / Phase NB}
Current task: {N.M} — {task name}
Current step: {step description}
Status: {not started | in progress | blocked | complete}
Tests passing: {total} ({rust} Rust + {ts} TypeScript)

## Completed phases
- Phase 0: bootstrap — {tag} — {test count}
- Phase 1: ... — {tag} — {test count}

## Active work
- Last action: {what was just done}
- Next action: {what to do on resume}
- Files touched: {list}

## Capability tracker
(mirror of CLAUDE.md Section 11 capability table)

## Fortress tracker
(mirror of CLAUDE.md Section 11 fortress table)

## Notes
- Blockers: {any}
- WIP: {any uncommitted work}
- Decisions: {any pending design decisions}
```

**Update PROGRESS.md triggers:**
- After every task completion (e.g. 3A.1 → 3A.2 boundary)
- Before ending a session (even a short one)
- Immediately when encountering a blocker
- After every git tag
- After every phase-end verification protocol run

### Phase-end Verification Protocol (MANDATORY at end of every phase)

A phase is not "complete" until all of these steps pass in order. Do not skip any step. Do not declare the phase done and then come back to a skipped step later.

1. **Compilation check:** `cargo check --workspace` — must succeed with zero errors, zero warnings.
2. **Lint check:** `cargo clippy --workspace --all-targets -- -D warnings` — zero warnings treated as zero.
3. **Test suite (Rust):** `cargo test --workspace` — 100% pass rate, no `#[ignore]` added to hide failures.
4. **Shell verification:** `cd shell && pnpm test && pnpm build` — all Vitest suites pass, build produces output.
5. **Integration connectivity check:** verify each D-Bus service added this phase starts and responds on its interface (even with a stub backend). Document the service name and interface in PROGRESS.md.
6. **Capability + Fortress tracker update:** edit CLAUDE.md Section 11 tables — mark affected rows as built, tested, or deferred. Never leave a shipped capability marked "not started".
7. **PROGRESS.md final update:** status = complete, phase = {next phase} (ready), tests passing = final count, completed phases = append entry with git tag.
8. **Git commit + tag:** commit with Conventional Commits, then `git tag v{x}.{y}.{z}-phase{n}` matching the phase. Record the tag in PROGRESS.md's completed phases list.

If any step fails, the phase is not done. Fix the failure (per Section 8 Error Resolution Protocol — root cause, not workaround), then re-run the protocol from step 1.

### Codex security review protocol (MANDATORY at end of every task)

At the end of every task, before reporting completion, Claude Code must:

**Step 1: Determine if a security review is required.**

A Codex security review IS required if the task touched any of:

- `fortress/` (any file, any change)
- `services/` files that handle credentials, permissions, or auth
- `die/orchestrator/` files touching ZKQP, permission tiers, vault access, or cloud routing
- `ssi/` files that execute capabilities on the user's behalf
- Any file that introduces a new external network call
- Any phase boundary merge (always, no exceptions)

A Codex security review is NOT required if the task only touched:

- Pure documentation (`PROGRESS.md`, `CLAUDE.md`, README, doc comments)
- Test files with no production code changes
- Shell UI components with no backend auth involvement
- Build configuration (Cargo.toml dependency additions that are not auth-related)

**Step 2: Report the determination explicitly.**

In the session summary, include one of:

> "Codex security review: NOT REQUIRED for this task (touched only [list of files/areas])"

OR

> "Codex security review: REQUIRED — running now"

Never skip this determination. Even when the answer is "not required," state it explicitly so the audit trail is complete.

**Step 3: If required, instruct the user to run the review.**

Claude Code cannot run Codex directly (it's a separate tool on the user's machine). When a security review is required, include this exact block in the session summary:

```
┌─────────────────────────────────────────────────────┐
│ SECURITY REVIEW REQUIRED — run before merging:     │
│                                                     │
│ codex review --uncommitted                          │
│                                                     │
│ Focus areas for this task: [specific things to      │
│ check based on what was built — e.g., "verify       │
│ ZKQP is called before every cloud inference call"]  │
└─────────────────────────────────────────────────────┘
```

**Step 4: Merge only after review.**

The merge to main happens AFTER the user confirms the Codex review is clean. Claude Code must not merge to main and must not report the task as fully complete until the user pastes the Codex review output (or confirms it found nothing).

If the review finds issues: Claude Code fixes them on the feature branch, re-runs self-audit, then the user re-runs the Codex review.

If the review is clean: Claude Code performs the merge:

```bash
git checkout main
git merge --no-ff phase-{N}/{task-name} -m "merge(phase-{N}): {task-name}"
git branch -d phase-{N}/{task-name}
```

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

### Phase 2+ Performance Budgets

| Operation | Budget |
|-----------|--------|
| SSI app scan (per app) | **< 2 seconds** |
| ZKQP query sanitization | **< 50ms** (must not add noticeable latency) |
| Learning pattern detection (per 50-event batch) | **< 200ms** |
| Builder project scaffolding | **< 5 seconds** (code generation may take longer via inference) |
| Cross-app capability execution | **< 3 seconds** per step |
| Action timeline query (last 24 hours) | **< 100ms** |
| Onboarding step transition | **< 200ms** (instant feel) |
| Web page content extraction | **< 2 seconds** per page |

All are targets. Measure with `criterion` benchmarks and track in CI.

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

### ZKQP Implementation Rules

1. The PII detection regex set must cover: email addresses, phone numbers, physical addresses, IP addresses, full names (proper nouns adjacent to context clues), project/company names (from user's known entities list), geographic locations, dates that could identify events
2. The mapping table (PII to placeholder) exists **ONLY** in memory — never serialized to disk, never logged, cleared when the query completes
3. When multiple cloud providers are available, sub-queries **MUST** be distributed across different providers
4. The privacy score algorithm must be deterministic and auditable — the user can ask "why did this score 65?" and get a specific answer
5. ZKQP is **ALWAYS** active for Tier 3 queries — there is no "disable ZKQP" option (this is non-negotiable security)

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

### Offline-First Design Rules

Every feature must define its offline behavior. The rule: **degrade, don't break.**

| Feature | Online | Offline |
|---------|--------|---------|
| AI inference | Tier 1/2/3 available | Tier 1 local only |
| File search | Full semantic + web augmentation | Local Tantivy only |
| Web browsing | Full capability | Cached pages only, clear "offline" indicator |
| Learning engine | Full observation + cloud pattern analysis | Local observation + local pattern detection |
| Voice | STT + TTS (both local, always work) | Same — fully local |
| Builder | Full stack with cloud inference for code gen | Limited to template scaffolding only |
| ZKQP | Active (cloud queries flowing) | Not needed (no cloud queries) |
| Action timeline | Full logging + cloud sync | Local logging only |
| SSI | Full scanning | Local scanning only (no web-based discovery) |

When transitioning from online to offline: queue all pending cloud operations, notify the user "Switched to offline mode — local AI only", continue all local operations without interruption. When connectivity returns: process queued operations in order, notify "Back online — full capabilities restored."

### Capability Implementation Tracker

The spec (`DELPHI_COMPLETE_SPEC.md`) defines 18 capabilities. Track status explicitly:

| # | Capability | Status | Phase |
|---|-----------|--------|-------|
| 1 | Behavioral learning engine | Built + wiring in Phase 2 | 0+2 |
| 2 | Deep internet agency | Partial — die-browser IPC layer built + tested, but the Playwright `agent.js` it drives does not exist in-repo; no production consumer (Brain unwired) | 1 |
| 3 | Multi-specialty reasoning | Partial — router exists, specialist mesh needed | 3 |
| 4 | Infinite task chaining | Built (orchestrator brain + checkpoints) | 1+2 |
| 5 | Conversational presence | Partial — voice I/O scaffolded (STT/TTS are stubs: placeholder text / silence, no whisper-rs/Piper); persistent conversation memory needed | 3 |
| 6 | Goal and planning architecture | Not started | 3 |
| 7 | Full-stack builder | Scaffold-only — template file-copy works; `{{project_name}}` substitution, Generating/Building/Testing states, minijinja, post-scaffold exec all unimplemented; no production consumer | 2 |
| 8 | Client/company workspace adaptation | Not started | 3 |
| 9 | Sovereign local intelligence | Partial — Fortress + ZKQP in Phase 2 | 0+2 |
| 10 | Non-interference philosophy | Encoded in iron laws (no code needed) | 0 |
| 11 | Endurance and resilience | Partial — checkpointing exists, rolling context needed | 3 |
| 12 | Ambient environmental awareness | Not started | 3 |
| 13 | Predictive crisis prevention | Not started | 3 |
| 14 | Relationship intelligence | Not started | 3 |
| 15 | Cross-device federated sync | Not started | 3 |
| 16 | Temporal intelligence | Not started | 3 |
| 17 | Knowledge synthesis engine | Not started | 3 |
| 18 | Generative workspace creation | Not started | 3 |

Phase 3 must address capabilities 3, 5, 6, 8, 11, 12, 13, 14, 15, 16, 17, 18.

### Fortress Security Layer Tracker

The spec defines a seven-layer security architecture:

| Layer | Name | Status | Phase |
|-------|------|--------|-------|
| 1 | Hardware root of trust (TPM) | Not started — requires TPM hardware access | 3 |
| 2 | Full-disk encryption (LUKS2 + hidden volumes) | Partial — LUKS2 basic, hidden volumes not implemented | 3 |
| 3 | Zero-Knowledge Query Protocol (ZKQP) | Phase 2 Task 2.3 | 2 |
| 4 | Fully Homomorphic Encryption (FHE) | Not started — requires Microsoft SEAL/OpenFHE integration | 3+ |
| 5 | Federated behavioral sync (UrbanFL-derived) | Not started | 3 |
| 6 | zk-SNARK audit proofs | Not started — requires Circom/snarkjs integration | 3+ |
| 7 | Post-quantum cryptography (CRYSTALS-Kyber/Dilithium) | Not started | 3 |

Currently implemented: AES-256-GCM vault (Layer 2 partial), Argon2id key derivation, SHA-256 audit chain (Layer 6 precursor), 4-tier permission model.

### Runtime Trust-Boundary Tracker

The runtime arc (the auth boundary for tool execution — the `runtime/` crate + the decoupled `runtime/shell-host`) is a Phase 3B addition that is **not** among the spec's 18 capabilities or 7 Fortress layers, so it is tracked here rather than forced into either spec-mirror table. Canonical detail lives in `PROGRESS.md`.

| Increment | What | Status |
|-----------|------|--------|
| Trust model | `docs/TRUST_MODEL.md` (STOP-POINT-B) | RATIFIED — 6-round Codex → APPROVE (`0065919`) |
| 1a–1d | anchor + channel + fdsec + pidfd + PAM + token + canonical action + sandbox + execute + audit | BUILT + reviewed + MERGED (`e5f25d5`) |
| B1 | make 1a–1d run — the launcher + service loops assembling the primitives, minimal sides | BUILT + own-Codex-reviewed (3 rounds) + MERGED (`f5b823d`) |
| **B2a — WSL2-provable half** | the REAL React-WRY shell's **SECURITY CORE**: R-2 native relay (renderer-cannot-forge), gate-tightening (require a seat), the decoupled WRY host (fail-closed CLOEXEC), the R-3 PAM dialog, the terminal channel contract | **BUILT + Codex-APPROVED (2 rounds, 0 findings) + MERGED (`3e40e22`)** |
| **B2a — lane-dependent half: RECON** | seated lane provisioned (Ubuntu 26.04, systemd 259, seat0). A-1 (resolution is by **cgroup membership**, not leadership → the launcher must fork the shell directly, never via the systemd user manager; **`PAM_TTY=ttyN` is the whole seat obligation**); the first **gate-POSITIVE**; **R3-01c leader == shell PROVEN 9x** (independent logind cross-check); A-2.1–A-2.4 lifecycle/refcount | **COMPLETE + Codex-gated (3 rounds) + §4 amended.** FD-01 (P1) changed the DESIGN: mandatory pre-`execve` `close_range` sweep (same relay-bypass class as B2A-R2-01). Carries 4 honesty items + a scope boundary (measured on `class=background`; production is `class=user` — reasoned, not measured). |
| **B2a — lane-dependent half: BUILD** | shape-(b) manual-fork launcher restructure (carrying its re-run 1b sibling-fd-theft + fd-discipline/privdrop RED-proofs); the **RED-first leader == shell regression test** (must FAIL against a forked-grandchild impl); real `pam_open_session` provisioning against the installer-shipped `/etc/pam.d/delphi-runtime`; the long-lived-shell lifecycle; the composition (host drawing the real bundle) | **CORE BUILT + PROVEN, awaiting Codex; composition + gate-POSITIVE + long-lived-shell lifecycle still PENDING.** DONE: C1 shape-(b) restructure; **three regression tests RED-proven to bite AND stable-serially (30/30)** — B-1 leader==shell (`70c82fa`), FD-01 inherited-fd containment (`5f0f6e0`, re-aimed after the first passed under its own weaken), B-3/B′ privdrop effect (`6be542e`); `reap_children` teardown fix (`66f543f`); **C2 install** (`5283fbf`) — real WRY host at `/usr/libexec/delphi-shell`, unit `DELPHI_SHELL_VT`/`DELPHI_AI_BIN`, PAM stack; **`systemd_smoke` PASSES** (prediction confirmed: anchor persists, daemon survives the headless-shell outcome — confirms binary-spawnable + anchor property, NOT that the shell renders). These three tests are **SERIAL-ONLY** (fork+PAM; parallel = the multithreaded-parent hazard `launcher.rs` documents — CLAUDE.md §6 carve-out). PENDING: the **composition** (WRY host drawing the real bundle through the consent path), the **gate-POSITIVE via the real shell**, the **long-lived-shell lifecycle** (B1 still services one action then exits), and the increment's **Codex review** (named areas: `open_own_session` raw-pointer lifecycle; the fork+PAM single-threaded-parent constraint, now with live evidence; the C2 install surface). §4 forward obligation partially discharged (success path only). |

**The honest boundary (do not lose):** B2a's security property is unit + real-channel proven (both verified-to-bite); the gate-**negative** is proven on WSL2's real seatless session and the gate-**positive** is now proven on a real seated lane. The lane-dependent **RECON** is COMPLETE (R3-01c leader == shell proven 9x; findings landed in `docs/TRUST_MODEL.md` §4). The lane-dependent **BUILD** — the manual-fork restructure, the RED-first leader==shell regression test, the long-lived-shell lifecycle, and the composition — is **NOT STARTED**. A recon proof is **not** a shipped regression test: the security-core **half** is merged and the recon is closed, **NOT** B2a complete.

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

9. **Best answer over predicted pattern.** When Delphi has both a learned pattern ("user always wants X") and a fresh computation/explicit request, the fresh answer wins. Patterns accelerate — they never override. If there's any ambiguity between what the user asked and what the pattern predicts, serve the explicit request. Ask for clarification only if the request itself is genuinely ambiguous, never because it conflicts with a learned pattern.

10. **Offline means degraded, never broken.** If internet connectivity is lost, if a cloud service is down, if an API key expires — the OS continues working. Every feature has a local fallback. The user must never see a blank screen, a hanging interface, or a "service unavailable" error that blocks their work. Degrade visibly (show "offline" indicator) but NEVER break.

11. **Never skip, never assume, always verify.** Before starting any session, verify state (read PROGRESS.md, check git log, run the test suite). Before claiming a task complete, run its tests — not later, now. Before moving to the next task, update PROGRESS.md with the current status. Before declaring a phase done, execute the phase-end verification protocol in its entirety — all 8 steps, in order, no substitutions. Never say "I'll run tests later" or "that change is obviously fine" or "PROGRESS.md still looks right". Verification takes seconds; false assumptions take days to untangle. The cost asymmetry is absolute: verify.

12. **Verify, don't fabricate.** When you don't know, say so and check. When you think you know, verify anyway. When you've verified, cite the source (file line, command output, documentation URL). Plausible-sounding answers generated from memory are the primary failure mode of AI-assisted development. Rigorous verification is the cure. For a project of Delphi's scope and importance, this rule has no exceptions.

13. **Highest fidelity wins, lowest fidelity is last resort.** For every task that involves reading from or writing to an external source — a file, application, service, device, game, or website — Delphi probes for the highest-fidelity interface available and uses that. Lower-fidelity methods are fallbacks, not defaults.

    **The fidelity hierarchy (from highest to lowest):**

    1. **Direct data source access** — reading the actual file, database, or memory that holds the truth. Example: reading a SQLite file as SQL rather than via an app's UI.
    2. **Native API** — the source's own programmatic interface. Example: GitHub REST API over scraping github.com, IMAP over scraping Gmail's web UI.
    3. **Official plugin or extension interface** — interfaces the source exposes for third-party integration. Example: VS Code extension API, Obsidian plugin API, Skyrim Script Extender.
    4. **Structured system integration** — D-Bus interfaces on Linux, MPRIS for media players, COM on Windows, AppleScript on macOS.
    5. **Accessibility tree** — AT-SPI on Linux, UI Automation on Windows. Structured but less direct than native APIs.
    6. **Structured web data** — JSON-LD, OpenGraph, Schema.org microdata, RSS, sitemaps. Present in the HTML but parseable as structured data.
    7. **DOM parsing** — reading the actual HTML structure, not screenshots.
    8. **Subprocess output parsing** — running a CLI tool and parsing its stdout. Common fallback but less stable than direct APIs because output format can change between tool versions.
    9. **Screen capture + computer vision** — the universal fallback. Works for anything visible but is slowest, least stable across UI updates, and requires heavier compute.
    10. **Keyboard and mouse input simulation** — the universal writer when no higher-fidelity writer is available.

    **Rules that follow from this hierarchy:**

    - Every integration MUST declare which fidelity levels it supports and what each level provides.
    - Every integration MUST probe downward from the highest level and use the first one that works.
    - Code must NEVER use a lower-fidelity method when a higher-fidelity method is known to be available on the target system. If the higher-fidelity method fails at runtime, fall back and log the fallback with the reason.
    - Every response returned to the user MUST include fidelity provenance. "Your calendar shows 3 meetings tomorrow (Google Calendar API)" is correct. "Your calendar shows 3 meetings tomorrow" without provenance is incomplete because the user can't judge the answer's reliability.
    - When two fidelity levels are equally direct, prefer the one that is more stable across version changes (APIs are usually more stable than DOM structure).

    **Why this matters:**

    Lower-fidelity methods look attractive in the short term because they work "universally" — vision can see any screen, keyboard simulation can type into any field. But they are brittle against UI changes, slow due to vision model costs, and imprecise because inference can be wrong. Every task built on low-fidelity methods becomes a maintenance burden.

    Higher-fidelity methods take more work per integration (you have to find and use the right API) but they are reliable, fast, and precise. Delphi's value proposition depends on being *reliable* at complex workflows. Brittle low-fidelity automation is what every current "AI agent" does. Delphi is supposed to be better than that.

    **Concrete example of correct vs incorrect application:**

    **Incorrect:** "To read the user's emails, Delphi opens Gmail in a browser, takes a screenshot, and uses vision to extract the email list."

    **Correct:** "To read the user's emails, Delphi checks available interfaces in this order: (1) if the user has configured IMAP credentials in Fortress, use IMAP directly; (2) if they have Gmail API credentials configured, use the Gmail API; (3) if they have only a browser session, use Chromium DevTools Protocol to read the DOM of the Gmail tab; (4) if none of the above, tell the user which interface they can set up for better results and fall back to DOM scraping as a last resort. Log which interface was used so the user can see it."

14. **Capabilities must not retreat from the North Star.** Every new capability and architectural decision is measured against the vision: does this preserve, advance, or retreat from "an OS that operates the user's tools on their behalf to accomplish any task while preserving user sovereignty?" Decisions that preserve or advance are evaluated on their own merits. Decisions that retreat require explicit justification and acknowledgment. This law is intentionally narrower than "must advance the North Star." Infrastructure work (security, performance, accessibility, testing, refactoring) qualifies as non-retreat. The bar is to avoid drift, not to require every commit to be visionary. (See the "Delphi Vision and Architecture" section near the top of this file for the full North Star statement and the three-component architecture this law protects.)

15. **The test is the adversary, not the gate.** A test exists to attack the product, not to certify it. When a test fails, **the product is wrong until proven otherwise.**

    1. **Never weaken an assertion to obtain green** — not the threshold, not the scope of the claim, not the strictness of the comparison. If an assertion appears too strong, that is a finding to be **argued and recorded** (about the product, or about the spec the assertion encodes), never an edit made to clear a red. **The discriminating check, because intent is unknowable but this is not: would you make this same edit if the test were passing?** If no, you are clearing a red, not fixing a claim.

    2. **A test must fail for the reason it names.** Green is not evidence; green from a test never proven to bite is decorative. Every security-relevant assertion owes a verified **weaken/restore**, and both outcomes must discriminate — **PASS/PASS and FAIL/FAIL are equally worthless.** Grounded: B-1's first draft asserted only `leader == pinned_pid`, which is true under BOTH topologies, so it PASSED under the weaken (the R2-03 mis-aimed-RED shape); the discriminating leg was "which pid is actually executing the shell binary". A skipped test gives PASS/PASS; a session-less PAM stack gives FAIL/FAIL. **A third case is equally worthless and is not covered by the first two: an INTERMITTENT result.** A test that fails 1 run in 10 cannot distinguish "the property is violated" from "this run was unlucky" — see the non-determinism rule in the Codex round-loop (Section 6), which requires ≥30 parallel iterations before such a test is offered as evidence.

    3. **Narrowing to measure precisely is not weakening.** Removing a dependency that *invalidates* the measurement is required; relaxing the claim so failure disappears is forbidden. The discriminating question: **does the property still fail if violated?** If yes you narrowed; if no you weakened. Record the reason either way. Grounded: FD-01 and B-1 replaced `delphi-minimal-shell` with a `pause()` sleeper. That is NARROWING — the minimal shell was dying on a protocol EOF before the measurement, so the test was measuring a corpse; the sleeper removed a dependency irrelevant to the property. The assertions did not move. Contrast the forbidden edit available at the same moment: widening the fd allowlist so the extra descriptors stop failing FD-01.

    4. **The test encodes the threat, not the input space.** Rigour is adversarial, not exhaustive — one assertion that catches the attack beats a hundred that catch typos.

    5. **Suspect the harness before the code, but never let that become the default explanation for a red. The harness is guilty only when SHOWN to be.** Grounded both ways: three harness defects in one session were real (a fabricated transcript, fixtures deleting the operator's installed PAM stack, `git reset --hard` destroying uncommitted work — see "Process failures damage the work" in Section 6), AND a plausible harness explanation for FD-01's failures was killed on inspection (fds opened by other threads after `fork` cannot appear in the child, whose fd table is a snapshot taken at `fork`). **The asymmetry that keeps clause 5 honest: "the harness did it" must be demonstrated with the same evidence a product defect would need. An undemonstrated harness excuse is how a real defect gets shipped green.**

---

## Section 13: Anti-hallucination protocol (MANDATORY FOR EVERY SESSION)

This project is too important to accept plausible-sounding fabrications. Every claim in code and in session reports must be verifiable. These rules are absolute.

### 13.1 The verification hierarchy

When you need to reference external facts (crate names, API signatures, library behavior, version numbers, command syntax, best practices), follow this hierarchy from HIGHEST to LOWEST trust:

1. **The source code itself.** Read the actual file. Run `cargo doc --open` for Rust. View the repo on GitHub. This is the only trusted source.
2. **Official documentation.** docs.rs for Rust, MDN for web, the project's README. Trust but verify against source code for version-specific details.
3. **Package registry metadata.** `cargo search <name>` on crates.io, `npm view <package>`. Trust for existence and version, not for API details.
4. **Verified web search.** Only recent (within 6 months) results from official sources. Low trust for implementation details.
5. **Memory / training data.** LOWEST TRUST. Never use as the primary source for code-level decisions.

### 13.2 The "I don't know" rule (NON-NEGOTIABLE)

When uncertain about any of the following, STOP and verify before proceeding:

- Crate name, version, or API signature
- Whether a library supports a specific feature
- Current recommended practice for a technology
- Whether a command or flag exists
- Whether a file path or environment variable is correct
- Whether an external service or API is currently available
- Whether a dependency will compile on the target platform

**What to do when uncertain:**
1. State the uncertainty explicitly in the session output: "I'm not certain whether X works — let me verify."
2. Run the verification command (cargo search, npm view, read the file, curl the docs).
3. Only write code after verification passes.
4. If verification shows the approach doesn't work, follow Iron Law #8 (diagnose root cause, don't flee to alternatives).

**Saying "I don't know, let me check" is ALWAYS correct. Fabricating a plausible answer is ALWAYS wrong.**

### 13.3 Forbidden patterns

These patterns indicate hallucination and are strictly prohibited:

- Writing code that imports a crate without first verifying the crate name in Cargo.toml or on crates.io
- Calling a function or method without first reading its actual signature
- Assuming a library supports a feature without testing or documentation
- Writing "This should work" or "This is the standard approach" without verification
- Referencing version numbers from memory (always verify current version)
- Using example code from training data without adapting it to actual library versions
- Asserting test counts or line counts without running the actual count commands

### 13.4 Self-audit protocol (run at end of every significant work block)

Before declaring any task, subtask, or phase complete, run this audit:

```bash
set -o pipefail   # a piped cargo's failure must not be masked by tee/tail — see the exit-code note below

# Compile check
cargo check --workspace

# Clippy must be clean
cargo clippy --workspace --all-targets -- -D warnings

# Tests must actually run and pass (not just compile)
cargo test --workspace 2>&1 | tee /tmp/test_results.txt
grep "test result:" /tmp/test_results.txt

# Count actual tests by crate (prevent false counts)
for dir in */; do
  if [ -f "$dir/Cargo.toml" ]; then
    cd "$dir"
    count=$(cargo test --no-run 2>&1 | grep -c "test " || echo 0)
    echo "$dir: $count tests"
    cd ..
  fi
done
```

**Exit-code capture (build discipline — never trust an exit code through a pipe).** `cmd | tee log` and `cmd | tail` report the *last* pipeline stage's status (`tee`/`tail`, almost always `0`), silently masking a failed `cmd`. A verification that can pass for the wrong reason is worse than none — it is false confidence, the same failure shape as a security gate tested only in isolation. To gate on success, capture the command's OWN status: either `set -o pipefail` before any pipeline (as in the block above), or redirect with `cmd &> log; rc=$?` and check `$rc` explicitly. This applies to **every** cargo invocation (`check` / `clippy` / `test`) — local self-audits and CI alike. (Discovered in the SVC-2 services sweep: a `cargo clippy … | tee log` reported `tee`'s exit `0` and masked a real `-D warnings` lint that had shipped several batches earlier. The lesson generalizes to the orchestrator and fortress sweeps that follow.)

**Report the OUTPUT of these commands, not a summary. If you claim "950 tests pass," include the literal test result line showing that count. Any discrepancy between claimed and actual is a hallucination that must be corrected immediately.**

### 13.5 Session report integrity

When writing session summary reports:

- Every number (test count, line count, crate count) must come from a command you just ran
- Every file created must be verified with `ls` or `find` that it actually exists
- Every commit claimed must be verified with `git log --oneline`
- Every feature claimed to work must have a corresponding passing test
- Do NOT write "the system can now do X" unless there's a test proving it
- When unsure whether something works end-to-end, say "component X was built; end-to-end integration with Y is not yet verified"

### 13.6 Cross-reference rule

When implementing anything that crosses module boundaries (shell → bridge → D-Bus → backend):

1. First verify the FROM side's actual API (read the file)
2. Then verify the TO side's actual API (read the file)
3. Then verify the serialization format on both sides matches (read the proto files)
4. THEN write the integration code
5. Then write an integration test that actually exercises the full path
6. Only mark complete when the integration test passes

"I think the APIs match" is hallucination. "I verified by reading X line Y in both files and confirming the schema matches" is rigor.

### 13.7 Dependency addition protocol

Before adding any dependency to Cargo.toml or package.json:

```bash
# For Rust
cargo search <crate> | head -5          # Verify crate exists and current version
cargo info <crate>                      # Read description, check maintenance status
# View the crate's actual docs at https://docs.rs/<crate>

# For npm
npm view <package>                      # Verify package exists
npm view <package> versions --json | tail -5  # Check recent versions
```

If the crate/package doesn't return results, DO NOT INVENT ONE. Search for the correct name. If you can't find it, say so explicitly and ask the user.

### 13.8 The "ingenuity through rigor" principle

Innovation in Delphi comes from careful engineering, not from fast guessing. The novel contributions listed in DELPHI_COMPLETE_SPEC.md are publishable BECAUSE they are rigorously designed and implemented. A hallucinated implementation is worse than no implementation — it creates technical debt that will surface at the worst possible moment (during a demo, in production, during a security audit).

When tempted to take a shortcut:
- "I'll just assume the API looks like X" → NO. Read the actual API.
- "This should probably work" → NO. Test it.
- "I'll add a TODO for this edge case" → NO. Either handle it or don't claim the feature works.
- "I remember this pattern from another project" → NO. Verify it applies here.

Rigor is not in tension with innovation. Rigor is what makes innovation real.

### 13.9 Defect-class corpus (fix-known, don't-rediscover)

`docs/DEFECT_CLASSES.md` is the institutional memory of every defect *class* the project's adversarial reviews have surfaced (Task 3A.5 F4–F26, Task 3A.6 R1–R5, the Phase 3B.0 `services`/`orchestrator`/`fortress` sweeps, INF-1), each with the **foreclosing primitive** (a `delphi-hardening` module where extracted — `canonical_hash`, `safe_open`, `pragma_setup` — or a discipline otherwise) and the **RED-proof test shape** that proves a fix closes it.

**Every new task's design step AND every Codex round-1 prompt MUST reference `docs/DEFECT_CLASSES.md` and explicitly partition the relevant classes into:**

- **(a) pre-foreclosed by `delphi-hardening`** — list these so the reviewer does **not** spend budget re-hunting a class a primitive already closes by construction; and
- **(b) applicable but NOT yet foreclosed** (the disciplines + the deferred patterns: `atomic_migration`, `uniform_reject`, `TrustedRoot`) — list these so they get **explicit** coverage rather than being assumed-handled.

The purpose is **review-attention allocation**: skip the foreclosed, concentrate the review on the unforeclosed. This is what makes "fix-known, don't-rediscover" actually collapse double-review-rounds rather than be a ritual. A token citation that does *not* partition the classes — that just names the file — misses the point: it is the (a)/(b) split that directs reviewer attention and prevents re-deriving a closed class the hard way. When a task forecloses a *new* class (extracts a new primitive or establishes a new discipline), it MUST add the entry to `docs/DEFECT_CLASSES.md` in the same change.
