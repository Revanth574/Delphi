# DELPHI OS — Complete Implementation Specification for Claude Code
# Version 2.0 Final | March 31, 2026

---

# SECTION 0: WHAT THIS DOCUMENT IS

This is the complete technical specification for Delphi OS. It contains everything needed to begin implementation. Every architectural decision is made. Every audit finding is resolved. Every capability is specified. Claude Code should use this as the authoritative reference for all implementation work.

---

# SECTION 1: IDENTITY

## 1.1 Definition

Delphi is an open-source operating system where a persistent, internet-connected, self-evolving multi-agent intelligence engine has native kernel-level access to every subsystem — files, apps, hardware, network, and the full internet — enabling it to execute arbitrarily complex tasks of any type through natural language while learning and growing alongside its user from the first boot.

## 1.2 Core philosophy: born with the machine, grows with the user

Delphi is NOT a static tool installed on a computer. It is a living intelligence that:
- Is born the moment the computer first boots — starting as a lightweight, curious assistant
- Learns continuously from the user's behavior, preferences, skills, and goals (with explicit consent)
- Grows its capabilities over time — becoming more specialized, faster, and more attuned to this specific user
- Adapts to whatever hardware it runs on — from a 4GB RAM Raspberry Pi to a 128GB workstation
- Is not limited to any specific task type — it can learn to do ANYTHING the user does by observing and practicing
- Connects to the internet as a constant knowledge source, making it infinitely more capable than any local-only system

## 1.3 What Delphi is NOT

- Not "AGI" — it is a Delphi Intelligence Engine (DIE): a multi-agent orchestration system
- Not a surveillance system — all behavioral learning is opt-in, transparent, and user-controlled
- Not a moral authority — it serves the user without judgment
- Not locked to expensive hardware — it scales from minimal to maximal

---

# SECTION 2: THE DELPHI INTELLIGENCE ENGINE (DIE)

## 2.1 Always-online internet intelligence

The DIE is permanently connected to the internet (when available) and uses the web as an extension of its intelligence. This is NOT just "web search." The DIE treats the entire internet as a live knowledge source, toolbox, and execution environment.

### 2.1.1 Internet capabilities

**Live knowledge access:**
- Real-time web search for any query (using multiple search engines simultaneously)
- Deep research: follows links, reads full articles, cross-references sources, synthesizes findings
- Monitors news, trends, and updates relevant to user's interests and projects
- Accesses documentation, APIs, tutorials, and forums for any technology
- Pulls real-time data: weather, stocks, prices, availability, sports scores, traffic

**Active web agency:**
- Headless Chromium engine in sandboxed container
- Direct DOM interaction (reads HTML structure, not screenshots)
- Full JavaScript execution, session management, cookie handling
- Logs into user's accounts via hardware-secured credential vault (TPM/Secure Enclave)
- Fills forms, navigates multi-step workflows, completes purchases (with permission tiers)
- Runs multiple browser tabs in parallel for simultaneous research/action
- Monitors web pages for changes (price drops, availability, new content)

**API and service integration:**
- REST, GraphQL, WebSocket connections to any public API
- OAuth flow handling for service authentication
- Webhook listeners for real-time notifications from external services
- MCP (Model Context Protocol) server connections for deep app integration

**Learning from the internet:**
- When encountering an unknown task, searches for tutorials, documentation, and examples
- Synthesizes multiple sources into an actionable procedure
- Caches learned procedures locally for offline use
- Updates cached knowledge when internet is available

### 2.1.2 Offline graceful degradation

When internet is unavailable:
- Tier 1 local model handles all conversation, file management, system tasks
- Cached knowledge base provides answers from previously learned information
- Previously visited web content available from local cache
- Queues internet-dependent tasks for execution when connectivity returns
- Clear indicator: "Offline — using local knowledge only"

## 2.2 The universal learning model

This is the core innovation that makes Delphi different from every other AI assistant. The DIE is not pre-programmed for specific tasks. It LEARNS to do what the user does, by watching and practicing.

### 2.2.1 Learning by observation (opt-in per category)

**How it works:**
The DIE observes the user's actions (with consent) and builds procedural models:

- **App usage patterns:** Which apps are opened when, in what sequence, for what purpose. After observing you open Photoshop → adjust levels → apply sharpen → export as PNG fifty times, it can do this workflow autonomously.
- **Communication style:** How you write emails to different people. Formal to advisor, casual to friends, structured to clients. It learns not just tone but structure, common phrases, and sign-off patterns.
- **Coding patterns:** Your naming conventions, folder structure, preferred libraries, testing approach, commit message style, PR description format.
- **Research methods:** How you search, which sources you trust, how you evaluate information, how you organize findings.
- **Creative workflows:** Your design preferences, color choices, layout patterns, writing voice.
- **Domain expertise:** As you work in a field, the DIE absorbs the domain knowledge — terminology, relationships, common procedures, best practices.
- **Problem-solving approach:** How you decompose problems, what you try first, when you pivot.
- **ANY repeated procedure:** If you do something more than 3 times in a similar pattern, Delphi can learn to do it.

**The learning loop:**
1. OBSERVE: Watch user perform task (with consent flag active)
2. MODEL: Build procedural representation of the task
3. PROPOSE: "I noticed you do X regularly. Want me to handle it next time?"
4. PRACTICE: Execute with user supervision ("I'll do it, you verify")
5. REFINE: Incorporate feedback ("Not quite — use this font instead")
6. AUTOMATE: After 3+ successful supervised executions, offer autonomous handling
7. EVOLVE: Continue improving from corrections and changing patterns

### 2.2.2 Learning by searching (when it doesn't know something)

When the DIE encounters a task it has never seen:

1. **Admit ignorance immediately:** "I haven't done this before. Let me learn."
2. **Search the internet:** Finds tutorials, documentation, examples, forum discussions
3. **Synthesize a procedure:** Combines multiple sources into a step-by-step plan
4. **Show the plan to the user:** "Here's how I'd approach this. Looks right?"
5. **Execute with supervision:** Performs each step, pauses for verification
6. **Cache the learned procedure:** Stores locally for future use, even offline
7. **Improve on next attempt:** Gets faster and more confident each time

**Example:**
User: "Create a 3D model of a chair in Blender"
- Delphi has never used Blender
- Searches: "Blender 3D modeling chair tutorial step by step"
- Reads 5 tutorials, watches 2 video transcripts
- Synthesizes a procedure: create cube, scale, duplicate for legs, extrude seat, etc.
- Opens Blender (via SSI if available, or via accessibility tree / keyboard shortcuts)
- Executes each step, showing progress
- On the third chair, does it in 30 seconds with no supervision

### 2.2.3 Learning from the user (watching, not surveilling)

**Critical distinction: watching ≠ surveilling**

Surveillance = recording everything, always, without consent, for external use
Watching = observing actions during enabled sessions, locally only, for the user's benefit

**Implementation:**
- Learning is OFF by default for every category
- First boot: "What would you like me to learn from? You can change this anytime."
- Categories presented as simple toggles: Work habits / Communication style / Coding patterns / Creative workflow / Research methods / Domain knowledge
- Real-time indicator in topbar when learning is active (eye icon — click to see what's being observed)
- "Forget" commands: "Forget today" / "Forget everything about X" / "Stop learning"
- All learned data stored in local encrypted database — NEVER transmitted
- User can export, inspect, and delete any learned pattern

### 2.2.4 Growth trajectory: birth to maturity

**Day 1 (newborn):**
- Knows nothing about this specific user
- Uses general-purpose capabilities from base models
- Asks questions to understand preferences: "What's your main work? How do you like to organize files? Formal or casual communication?"
- Operates primarily in Direct mode with available Assisted suggestions

**Week 1 (infant):**
- Has learned basic patterns: daily routine, common apps, file locations
- Can autocomplete frequent actions: "You usually open VS Code and terminal together. Want me to set up your workspace?"
- Begins anticipating simple needs

**Month 1 (child):**
- Understands work/personal boundaries, communication styles per contact
- Can handle routine tasks autonomously: email triage, file organization, meeting prep
- Has built a preliminary knowledge graph from user's documents and activity
- Specialist models beginning to fine-tune to user's domain

**Month 6 (adolescent):**
- Deep understanding of user's professional domain, coding style, creative preferences
- Can independently handle complex multi-step workflows
- Predictive capabilities mature: anticipates needs before they're expressed
- Cross-references across projects and time periods
- Relationship intelligence fully developed

**Year 1+ (adult):**
- Functions as a true cognitive extension of the user
- Handles novel tasks by combining learned patterns with internet research
- Professional-grade output in user's primary domains
- Continues learning and adapting to changing interests and roles

## 2.3 Hardware-agnostic architecture: runs on anything

### 2.3.1 Dynamic model scaling

Delphi does NOT require specific hardware. It detects available resources at boot and configures itself accordingly:

| Available RAM | Available GPU/NPU | Local model | Capability level |
|---|---|---|---|
| 2-4 GB | None | Tiny (1-3B, CPU quantized) | Basic: intent classification, quick answers, file search. Most tasks via cloud. |
| 4-8 GB | None/iGPU | Small (3-7B, 4-bit quantized) | Good: conversation, code completion, writing assistance, system management |
| 8-16 GB | dGPU 4-8GB | Medium (7-13B) | Strong: full code gen, document writing, data analysis, moderate reasoning |
| 16-32 GB | dGPU 8-16GB | Large (13-30B) | Powerful: complex reasoning, multi-step planning, specialist models loaded |
| 32GB+ | dGPU 16GB+ | XL (30B+, multiple models) | Maximum: multiple specialists concurrent, minimal cloud dependency |

**Automatic scaling:**
- On boot: benchmark hardware, select optimal model configuration
- During use: monitor resource usage, dynamically load/unload models
- When resources are scarce: offload to cloud tier transparently
- When resources are abundant: keep more specialists in memory for instant access

### 2.3.2 Growth with hardware upgrades

When the user upgrades their hardware:
- Delphi detects new resources on next boot
- Offers to upgrade: "I see you now have 32GB RAM and an RTX 5080. I can load much more powerful local models. This means faster responses, more privacy, and less cloud dependency. Upgrade?"
- Downloads larger model weights if user agrees
- All learned patterns, memories, and behavioral data carry forward unchanged

### 2.3.3 Cloud as the great equalizer

A user with a 4GB Raspberry Pi and a user with a 128GB workstation can both access the same frontier-class intelligence — the Pi user just routes more to cloud. The experience difference is latency, not capability.

## 2.4 Specialist model mesh with internet augmentation

| Specialist | Domain | Learning source | Internet augmentation |
|---|---|---|---|
| CodeSmith | Software engineering | User's codebase + coding patterns | GitHub, Stack Overflow, documentation |
| Counsel | Legal analysis | User's jurisdiction + document patterns | Legal databases, case law, regulations |
| Medic | Health information | User's health context (if shared) | PubMed, medical guidelines (always + disclaimer) |
| Analyst | Data & finance | User's financial patterns + data style | Market data, economic indicators, APIs |
| Scholar | Academic research | User's paper library + writing style | arXiv, Semantic Scholar, Google Scholar |
| Architect | System design | User's architecture patterns | Cloud docs, best practices, benchmarks |
| Lingua | Translation & language | User's language pairs + tone | Context-aware translation with cultural nuance |
| Canvas | Visual & design | User's design preferences + brand | Design trends, reference images, tutorials |
| Maker | Physical world tasks | Observed DIY/repair patterns | YouTube transcripts, WikiHow, manuals |
| Social | Communication & networking | User's relationship graph + styles | Contact enrichment, scheduling norms |
| Planner | Time & project management | User's actual work speed + patterns | Calendar optimization, deadline tracking |
| Guardian | Security & privacy | System threat patterns | Threat intelligence feeds, CVE databases |

**Any specialist can be created on-demand.** If the user starts working in a new domain (say, music production), Delphi creates a new specialist by:
1. Searching the internet for domain knowledge
2. Observing the user's workflow in this domain
3. Fine-tuning from observed patterns
4. Growing more capable with each session

## 2.5 Task capability: ANYTHING, not just code and documents

The DIE is not limited to text-based tasks. It can learn and execute any task that can be performed on a computer:

**Software development:** Full-stack building, testing, deployment, monitoring, debugging
**Document creation:** Reports, papers, presentations, spreadsheets, emails, letters
**Data work:** Analysis, visualization, pipeline building, ML training, database management
**Creative work:** Image editing, design, music production, video editing (via SSI-native apps or learned app control)
**Research:** Literature review, data gathering, synthesis, citation management
**Communication:** Email management, scheduling, follow-ups, social media, messaging
**System administration:** Server management, deployment, monitoring, security
**Web tasks:** Shopping, booking, form filling, account management, price monitoring
**File management:** Organization, backup, sync, conversion, cleanup
**Learning and education:** Tutorial following, course work, practice exercises
**Physical world integration:** Smart home control, IoT management, device coordination
**Financial:** Budgeting, expense tracking, tax preparation, invoice management
**ANY REPEATED PROCEDURE:** If the user does it on a computer, Delphi can learn to do it

## 2.6 Conversational presence

**Voice model:** Locally-run speech synthesis + recognition. Persistent conversation across sessions — remembers what was discussed days, weeks, months ago.

**Natural understanding:**
- "That thing" → resolves from context
- "Send it to her" → resolves both referents
- "Make it better" → infers from document type and past feedback
- Understands sarcasm, urgency, frustration, humor
- Adapts tone: concise when user is busy, detailed when user is exploring

**Personality:** User-configurable. Professional / Casual / Minimal / Custom prompt. Adapts within session based on user's energy and context.

**Verbal command chains:** Handles long stretches of multiple commands naturally:
"Okay Delphi, first check if my GPU cluster reservation is still active, then pull the latest UrbanFL training logs, compare convergence rates across the three silos, generate a chart showing the comparison, put it in the weekly report template, add a paragraph explaining why silo 2 is lagging, email it to Dr. Mehmet with a note that I'll call him Thursday, and block Thursday 2-3pm on my calendar for that call."
→ Executes all steps, shows progress, pauses only for the email send confirmation.

---

# SECTION 3: THE FORTRESS — DELPHI'S PRIVACY AND SECURITY SYSTEM

## 3.1 Design principle: mathematically provable privacy

Delphi's privacy is not based on promises, policies, or trust. It is based on mathematics. The system is designed so that even if an attacker gains complete physical access to the machine, a government issues a subpoena, or a state-level adversary targets the user, the private data remains cryptographically inaccessible.

## 3.2 The seven-layer security architecture

### Layer 1: Hardware root of trust

- All encryption keys derived from TPM 2.0 / Secure Enclave hardware
- Measured boot chain: every component verified from firmware to userspace
- If hardware lacks TPM: software fallback with LUKS + Argon2id key derivation (user warned about reduced security)
- Biometric binding: behavioral model encryption key derived from biometric + passphrase

### Layer 2: Full-disk encryption with plausible deniability

- LUKS2 with Argon2id KDF for full-disk encryption
- Hidden volume support: a second encrypted volume accessible with a different passphrase
- Under duress, user provides the decoy passphrase → decoy OS boots with decoy data
- Real data volume is indistinguishable from random disk data

### Layer 3: Zero-knowledge architecture for cloud queries

When the DIE sends queries to cloud AI (Tier 2/3):

**Zero-Knowledge Query Protocol (ZKQP):**
1. User's query is decomposed into sub-queries
2. Each sub-query is stripped of: personal names, locations, specific dates, project names, company names, identifying details
3. Sub-queries are shuffled and sent to DIFFERENT cloud providers (no single provider sees the full query)
4. Responses are reassembled locally
5. The cloud sees fragmented, anonymized query pieces — cannot reconstruct the user's intent

**Example:**
User asks: "How is my UrbanFL project's convergence rate for the Istanbul traffic silo compared to published benchmarks?"
Cloud provider A receives: "What are typical convergence rates for federated learning on traffic data?"
Cloud provider B receives: "Compare these convergence numbers: [raw numbers, no context] to state-of-the-art"
Cloud provider C receives: "Summarize recent literature on non-IID federated learning convergence"
→ Reassembled locally with full context. No provider knows the project name, the city, or the user.

### Layer 4: Fully Homomorphic Encryption for sensitive compute

For tasks requiring cloud compute on private data (model training, large analysis):

- Data encrypted with FHE (Fully Homomorphic Encryption) using Microsoft SEAL or OpenFHE
- Encrypted data sent to cloud for computation
- Cloud performs operations ON ENCRYPTED DATA — never sees plaintext
- Results returned encrypted, decrypted locally
- Even if the cloud server is compromised, attacker gets only ciphertext

**Current limitation:** FHE is 1000-10000x slower than plaintext computation. Used only for sensitive operations where privacy is paramount. Intel's Heracles FHE accelerator chip (announced 2026) will reduce this overhead by orders of magnitude.

### Layer 5: Federated behavioral sync (UrbanFL-derived)

Cross-device sync without raw data transfer:

- Each device trains its own behavioral model locally
- Only encrypted model gradients (not data) are shared via peer-to-peer
- Rényi differential privacy with per-device epsilon budgets (ε = 1.0 default, user-adjustable)
- Gaussian noise injection on gradients before transmission
- FedHetero-inspired modality-aware aggregation for different device types
- Even if an attacker intercepts all sync traffic, they get differentially private noise

### Layer 6: Zero-knowledge proofs for AI action verification

Every AI action in Autonomous mode generates a zk-SNARK proof:

- The proof certifies: "This action was authorized by the user's permission tier, used only data the user consented to share, and produced the claimed result"
- The proof can be verified WITHOUT revealing the action details, the data used, or the user's identity
- Stored in a local audit chain (hash-linked log)
- If the user ever needs to prove what the AI did (legal, compliance), they can selectively reveal specific proofs

### Layer 7: Quantum-resistant cryptography

All encryption uses post-quantum algorithms:

- CRYSTALS-Kyber for key encapsulation (NIST PQC standard)
- CRYSTALS-Dilithium for digital signatures (NIST PQC standard)
- SPHINCS+ as backup signature scheme
- Hybrid mode: classical + post-quantum in parallel until PQC is fully proven
- When quantum computers arrive, Delphi's encryption remains secure

## 3.3 The non-interference principle

Delphi does not surveil, log, report, filter, or judge legal user activity.

**What this means in implementation:**
- No content filtering for legal content of any kind
- No activity logging in Direct and Focus modes (unless user enables learning for specific categories)
- No reporting to any external entity, ever, under any circumstances
- No moral judgments about time use, content consumption, or lifestyle choices
- The AI model itself has no refusal training for legal user requests (Delphi ships with uncensored base models for local inference)

**Where Delphi protects (informs, never blocks):**
- Malware detection: "This file contains known malware. Quarantine?"
- Phishing detection: "This email/site matches phishing patterns. Proceed carefully."
- Security risks: "This action exposes [specific risk]. Your decision."
- System health: "Your disk is 95% full. Want me to help free space?"

---

# SECTION 4: THE LIVING SURFACE (UI)

## 4.1 Four modes

**Direct** — Full traditional desktop. Icons, folders, windows, taskbar, dock. AI invisible. Keyboard shortcut (Alt+Space) summons command bar. For: gaming, browsing, manual work, just vibing.

**Assisted** — User drives, AI navigates. Inline suggestions (grayed text, side panels, edge hints). Everything requires Tab to accept. For: coding, writing, research, email.

**Autonomous** — AI drives for delegated tasks. Generates ephemeral task UI. Reports progress live. Pauses at permission boundaries. For: meeting prep, complex multi-step tasks, batch operations.

**Focus** — AI fully dormant. No observation, no learning, no processing. Maximum privacy. Only hardware monitoring active. For: when you want absolute quiet and privacy.

## 4.2 Per-window mode assignment

Each window has a mode (colored dot in title bar). Modes operate independently and simultaneously. Autonomous windows cannot overlay Direct windows without permission. Confirmations appear as edge-bar notifications, never modal popups.

## 4.3 The Learning mode (first 7 days)

Active by default for new users. Delphi demonstrates capabilities through the user's real workflow. "I noticed you just organized 20 files manually. Want to see how I'd handle that?" Builds trust through evidence. User can exit anytime.

## 4.4 Complete desktop experience

- Full file manager with traditional folders + semantic search
- App store with SSI-native badges
- System settings with full AGI behavior controls
- Wallpaper, themes, fonts, sounds — all customizable
- Dock, taskbar, window management — all traditional controls present
- Right-click menus, keyboard shortcuts, drag-and-drop — everything expected
- Gaming mode: full GPU allocation, notification suppression, thermal optimization
- Accessibility: voice-first interaction, screen reader, motor assistance — founding principle

---

# SECTION 5: ARCHITECTURE

## 5.1 Kernel strategy

**Phase 1 (months 1-14): Linux kernel + Delphi userspace**
- Standard Linux kernel (Ubuntu/Arch base) handles all hardware
- All drivers work out of the box
- Delphi innovation lives in userspace: DIE, SSI, semantic FS, Living Surface
- The inference scheduler runs as a privileged userspace daemon with direct GPU/NPU access

**Phase 2 (months 20+): Custom microkernel migration**
- HongMeng-style driver containers for Linux driver reuse
- Differentiated isolation classes for AI runtime performance
- Formal verification of trust enforcement module
- Transparent to users — same experience, stronger foundation

## 5.2 The inference scheduler

Privileged service that manages AI workloads as kernel-level resources:
- Schedules inference across CPU/GPU/NPU based on hardware availability, latency requirements, power budget, thermal state
- Priority queue: user-facing requests highest, background tasks lowest
- Model lifecycle: loads/unloads weights based on usage patterns and available memory
- Power-aware: throttles AI on battery
- Thermal-aware: reduces load when approaching thermal limits

## 5.3 The Semantic System Interface (SSI)

Open standard for apps to expose capabilities as machine-readable APIs.

**Backwards compatible with MCP.** Every MCP server works with Delphi.

**Auto-generatable:** Delphi infers approximate SSI manifests from:
- Linux accessibility tree (AT-SPI)
- D-Bus interfaces
- CLI flags and man pages
- Electron app JavaScript introspection
- X11/Wayland window properties

**Trivially easy to implement:** `@ssi.capability("image.adjust_brightness")` (Python), `data-ssi-action` (HTML).

**Manifest includes:** capability name, parameters, latency estimate, compute requirements, offline support, data types consumed/produced.

## 5.4 Failure modes

- DIE crash → OS continues as Linux desktop. Direct mode fully functional. AI restarts automatically.
- Model corruption → automatic rollback to checksummed known-good version.
- Cloud unavailable → graceful degradation to local tiers. User notified.
- Total AI failure → Safe mode via Fn+Esc (2 sec). Clean desktop, zero AI. Non-negotiable.
- All Autonomous actions reversible for 24 hours via action timeline.

---

# SECTION 6: BUSINESS MODEL

**Delphi Core (free, open source, MIT):** Complete OS, Tier 1 local AI, Direct/Assisted/Focus modes, semantic FS, SSI auto-generation, full customization, accessibility.

**Delphi Pro (₹500/month or $10/month):** Tier 2-3 cloud AI, Autonomous mode complex orchestration, premium specialist models, cross-device sync, priority inference, advanced learning.

**Delphi Enterprise (per-seat licensing):** Workspace management, compliance features, admin controls, fleet deployment, custom specialist training, on-premise deployment.

---

# SECTION 7: TECHNOLOGY STACK

## 7.1 Core technologies

| Component | Technology | Rationale |
|---|---|---|
| Base kernel | Linux 6.x (Phase 1) | Driver compatibility, proven stability |
| System language | Rust | Memory safety, performance, modern tooling |
| UI framework | React 19 + Wayland compositor (Smithay) | Modern rendering, familiar for contributors |
| Local inference | llama.cpp / Ollama / vLLM | Optimized for on-device, supports quantization |
| Cloud inference | Anthropic API, OpenAI API, Google API (user choice) | Best-in-class frontier models |
| Model format | GGUF (local), API (cloud) | Universal compatibility, efficient quantization |
| Vector database | LanceDB (local, embedded) | Rust-native, fast, no server needed |
| Encryption | LUKS2 + Argon2id (disk), AES-256-GCM (data), CRYSTALS-Kyber (PQC) | Industry standard + post-quantum ready |
| FHE library | Microsoft SEAL / OpenFHE | Most mature FHE implementations |
| ZK proofs | Circom + snarkjs | Widely used, well-documented |
| Browser engine | Chromium headless (via Playwright) | Full web compatibility |
| Voice | Whisper.cpp (STT) + Piper (TTS) | Fast local speech processing |
| File search | Tantivy (Rust search engine) + sentence-transformers | Full-text + semantic |
| IPC | D-Bus + shared memory (hot path) | Linux standard + performance |
| Cross-device sync | Custom protocol (UrbanFL-derived) | Novel contribution |
| Package management | Flatpak + apt | Sandboxed apps + system packages |

## 7.2 Models by tier

**Tier 1 (always local):**
- Default: Qwen3 7B (4-bit GGUF) or Llama 3.1 8B (4-bit GGUF)
- Tiny hardware: Qwen3 1.5B or Gemma 3 2B
- Functions: intent classification, autocomplete, quick answers, system monitoring

**Tier 2 (local or cloud):**
- Default local: Qwen3 30B (4-bit) or DeepSeek-V3-Lite
- Cloud fallback: Claude Sonnet 4.6 or GPT-5.4 mini
- Functions: code generation, writing, data analysis, moderate reasoning

**Tier 3 (cloud with ZKQP privacy):**
- Default: Claude Opus 4.6 (best reasoning) / GPT-5.4 (best agentic) / Gemini 3.1 Pro (best multimodal)
- Model router selects best per task type
- Functions: complex reasoning, research synthesis, creative work, specialist domains

---

# SECTION 8: IMPLEMENTATION ROADMAP

## Phase 0: Bootstrap (months 1-3)
**Goal:** Bootable system with Delphi shell and working AI command bar

Tasks:
1. Create minimal Linux distribution (Arch base, custom installer)
2. Build Wayland compositor using Smithay (Rust)
3. Implement four-mode Living Surface UI shell (React 19)
4. Build Alt+Space command bar with Tier 1 model (llama.cpp)
5. Implement basic semantic file indexing daemon (Tantivy + sentence-transformers)
6. Set up LUKS2 full-disk encryption with custom installer
7. Design and implement topbar with mode badges, learning indicator, tier indicator
8. Create system settings panel with AGI behavior controls
9. Set up CI/CD pipeline, documentation, contribution guide

Deliverable: A Linux distro that boots beautifully with a working AI command bar

## Phase 1: Intelligence engine (months 3-8)
**Goal:** Working multi-agent system with persistent memory and internet connectivity

Tasks:
1. Implement three-tier inference architecture (local + cloud API integration)
2. Build orchestrator agent with task decomposition and dependency graphing
3. Implement persistent memory (hot/warm/cold tiers with LanceDB)
4. Build headless browser engine (Playwright) with DOM-level access
5. Implement checkpoint-and-verify chain execution (max depth 30, checkpoints every 5)
6. Add voice I/O (Whisper.cpp + Piper TTS)
7. Build SSI auto-generation from accessibility trees and D-Bus
8. Implement behavioral learning engine (opt-in, per-category, with transparency UI)
9. Build ZKQP (Zero-Knowledge Query Protocol) for cloud privacy
10. Set up model router for specialist dispatch

Deliverable: An OS where you can say "research this topic and write a summary" and it works

## Phase 2: Deep integration (months 8-14)
**Goal:** Full app orchestration, universal learning, internet agency

Tasks:
1. Build SSI SDK for Python, JavaScript, Rust
2. Implement cross-app parallel orchestration
3. Build the universal learning engine (observe → model → propose → practice → refine → automate)
4. Implement all 12 specialist models with internet augmentation
5. Build action timeline with 24-hour undo system
6. Implement goal/planning architecture with timeline intelligence
7. Build knowledge synthesis engine (personal knowledge graph)
8. Implement FHE integration for sensitive cloud compute (Microsoft SEAL)
9. Build zk-SNARK audit chain for Autonomous mode actions
10. Implement cross-device federated sync protocol
11. Build Learning mode (onboarding experience)
12. Implement generative workspace creation

Deliverable: An OS that learns from the user, operates across the internet, and handles complex multi-step tasks

## Phase 3: Polish and harden (months 14-20)
**Goal:** Production-quality, security-audited, publishable

Tasks:
1. Implement quantum-resistant crypto (CRYSTALS-Kyber/Dilithium)
2. Build hidden volume support for plausible deniability
3. Full accessibility implementation (voice-first, screen reader, motor assistance)
4. Performance optimization: model quantization, inference scheduling, memory management
5. Security audit (external) + penetration testing
6. Implement dynamic model scaling (detect hardware, auto-configure)
7. Build hardware upgrade detection and model upgrade flow
8. Stress testing: long chains, concurrent tasks, resource pressure, network loss
9. Write and submit research papers (inference scheduler, SSI standard, federated sync, Living Surface)
10. Public beta release

Deliverable: A beta OS that people want to use daily + papers submitted to top venues

## Phase 4: Ecosystem and scale (months 20-30)
**Goal:** Community adoption, commercial viability

Tasks:
1. Launch Delphi App Store
2. Build enterprise features (workspace management, compliance, fleet deployment)
3. Begin microkernel migration (Phase 2 kernel)
4. Launch Delphi Pro and Enterprise subscriptions
5. Developer documentation, SSI certification program
6. OEM partnership outreach
7. Community building, contributor ecosystem

Deliverable: Commercially viable OS with growing ecosystem

---

# SECTION 9: NOVEL CONTRIBUTIONS (publishable)

1. **Inference scheduler as kernel-level service** — first formalization of AI workloads as first-class OS resources
2. **SSI open standard** — semantic capability interfaces for AI-native app integration, MCP-compatible
3. **Federated behavioral sync protocol** — UrbanFL-derived privacy-preserving cross-device personalization with Rényi DP
4. **Four-mode Living Surface** — formal UX framework for human-AI control balance
5. **Zero-Knowledge Query Protocol (ZKQP)** — query decomposition + anonymization + multi-provider routing for private cloud AI
6. **Universal learning engine** — observe-model-propose-practice-refine-automate loop for learning any computer task
7. **Seven-layer Fortress security architecture** — TPM + LUKS + ZKP + FHE + federated DP + zk-SNARK audit + PQC

---

# SECTION 10: RISK MITIGATION

| Risk | Mitigation |
|---|---|
| Cloud AI costs exceed revenue | Model router picks cheapest capable model per task; aggressive caching; cost caps |
| SSI adoption fails | Auto-generation makes SSI valuable without developer buy-in |
| Performance on weak hardware | Tier 1 must be exceptional; invest in quantization and optimization |
| Security breach via AI | Seven-layer Fortress; zk-SNARK audit chain; biometric for sensitive actions |
| Legal liability for AI actions | Clear disclaimers; action timeline as audit trail; user confirms high-stakes actions |
| User trust failure | Opt-in everything; radical transparency; exportable data; no lock-in |
| Competitor launches similar product | Speed of execution; SSI standard creates defensible position; learning model is unique moat |
| FHE too slow for practical use | Use selectively for high-sensitivity operations only; Intel Heracles will improve over time |
| Model quality degrades locally | Continuous benchmarking; automatic rollback; cloud fallback |

---

# SECTION 11: FILE STRUCTURE FOR IMPLEMENTATION

```
delphi/
├── kernel/                     # Linux kernel config + patches
│   ├── config/                 # Custom kernel configuration
│   └── patches/                # Delphi-specific kernel patches
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
│   ├── auto-gen/               # Auto-manifest generation from AT-SPI, D-Bus
│   ├── sdk-python/             # Python SSI SDK
│   ├── sdk-js/                 # JavaScript SSI SDK
│   └── sdk-rust/               # Rust SSI SDK
├── fortress/                   # Security system
│   ├── encryption/             # LUKS2, AES-256-GCM, PQC
│   ├── zkqp/                   # Zero-Knowledge Query Protocol
│   ├── fhe/                    # Homomorphic encryption integration
│   ├── zksnark/                # Audit chain (Circom + snarkjs)
│   ├── tpm/                    # Hardware security module integration
│   └── federated-sync/         # UrbanFL-derived cross-device sync
├── semantic-fs/                # Semantic file system
│   ├── indexer/                # Tantivy + sentence-transformers
│   └── search/                 # Natural language file search
├── installer/                  # Delphi installer
│   ├── live-iso/               # Bootable ISO builder
│   └── setup-wizard/           # First-boot configuration
├── docs/                       # Documentation
│   ├── spec/                   # This specification
│   ├── api/                    # API documentation
│   ├── user-guide/             # User documentation
│   └── papers/                 # Research paper drafts
└── tests/                      # Test suite
    ├── unit/
    ├── integration/
    ├── e2e/
    └── security/
```

---

# SECTION 12: START HERE (for Claude Code)

Begin with Phase 0. The first task is:

1. Set up the repository with the file structure above
2. Create the Wayland compositor skeleton using Smithay (Rust)
3. Build the Living Surface shell with four-mode support (React 19)
4. Integrate a Tier 1 local model via llama.cpp for the command bar
5. Implement the topbar with mode badges and system indicators

The specification in this document is the source of truth for all architectural decisions. When in doubt, refer back to this document. The core principles are:
- Born with the machine, grows with the user
- Learns anything by observation + internet research
- Runs on any hardware (scales dynamically)
- Privacy through mathematics (Fortress architecture)
- User sovereignty is absolute (no judgment, no filtering, no reporting)
- Internet is always available as an intelligence amplifier
- Everything is reversible (24-hour undo for all AI actions)

Build Delphi.
