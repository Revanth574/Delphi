# Delphi OS

An open-source operating system where a persistent, internet-connected, self-evolving multi-agent intelligence engine has native kernel-level access to every subsystem — files, apps, hardware, network, and the full internet — enabling it to execute arbitrarily complex tasks of any type through natural language while learning and growing alongside its user from the first boot.

## Architecture

```
Living Surface UI (React 19)
       ↓
Delphi Intelligence Engine (Rust)
       ↓                    ↓                ↓
Inference Scheduler    Semantic FS     Browser Engine
       ↓                    ↓
Fortress Security Layer
       ↓
Linux Kernel
```

## Key Principles

- **Born with the machine, grows with the user** — starts simple, earns complexity through trust
- **Runs on anything** — 2GB Raspberry Pi to 128GB workstation, auto-configures at boot
- **Privacy through mathematics** — seven-layer Fortress architecture with post-quantum crypto
- **User sovereignty is absolute** — no judgment, no filtering, no reporting

## Prerequisites

- **Rust** 1.85+ (edition 2024 support) — install via [rustup](https://rustup.rs)
- **Node.js** 22+ with pnpm — for the shell UI
- **Python** 3.12+ — for ML/AI pipelines
- **Linux system libraries** (for full build): libwayland-dev, libudev-dev, libinput-dev, libxkbcommon-dev

## Quick Start

```bash
# Check workspace compiles (excludes compositor on non-Linux)
cargo check --workspace --exclude compositor

# Run tests
cargo test --workspace --exclude compositor

# Full build (Linux only)
cargo build --workspace
```

## Project Structure

See `CLAUDE.md` for the complete file structure, coding standards, and architectural rules.
See `DELPHI_COMPLETE_SPEC.md` for the authoritative technical specification.

## Cargo Workspace

| Crate | Description |
|-------|-------------|
| `compositor` | Wayland compositor built on Smithay |
| `die-orchestrator` | Central planning agent for the Intelligence Engine |
| `die-inference` | Three-tier inference manager (local/cloud/hybrid) |
| `ssi` | Semantic System Interface — Rust SDK |
| `fortress` | Security subsystem (encryption, ZKP, TPM) |
| `semantic-fs` | Semantic file system with full-text and vector search |

## License

MIT
