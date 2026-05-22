// SPDX-License-Identifier: MIT

//! Generative workspace creation — capability #18.
//!
//! When a user starts a new project, Delphi generates the entire working
//! environment: directory structure, scaffolding files, allowlisted setup
//! commands (e.g. `git init`), and suggested calendar blocks. This is the
//! "ultimate expression of the full-stack builder" from
//! `DELPHI_COMPLETE_SPEC.md` — Delphi produces a *real, immediately usable*
//! working environment, not a description of one (Iron Law #14: this
//! advances the North Star of operating the user's tools on their behalf).
//!
//! # Architecture
//!
//! ```text
//! intent → [templates | cloud inference] → WorkspaceSpec
//!                                              │
//!                                     validate_spec (validator.rs)
//!                                              │  (reject on any violation)
//!                                              ▼
//!                                   dry-run preview (D-Bus Preview)
//!                                              │  (user approves)
//!                                              ▼
//!                                     execute (executor.rs)
//!                                              │  re-validate (defense in depth)
//!                                              │  safe_create_under_root (openat2)
//!                                              │  allowlisted commands (explicit argv)
//!                                              ▼
//!                                   action-timeline record (undoable 24h)
//! ```
//!
//! # Security model
//!
//! - **Two spec sources, one validator.** The four baseline templates
//!   ([`templates`]) are compile-time-audited Rust literals. Cloud-inferred
//!   custom specs are UNTRUSTED. Both pass through the same
//!   [`validator::validate_spec`] before any filesystem mutation.
//! - **Defense in depth.** The executor re-validates the spec before
//!   execution; it never trusts that the validator ran (Iron Law #11).
//! - **Filesystem boundary.** Every file/dir creation goes through
//!   `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)` anchored to a held
//!   directory handle — the same kernel-level race-free mechanism as
//!   `knowledge.rs::safe_open_under_root_handle`, extended here for
//!   create/write. Symlinks are never followed or created.
//! - **Command boundary.** Setup commands run via `std::process::Command`
//!   with an explicit argv vector and a minimal environment (PATH only).
//!   No shell, no interpolation. The allowlist in [`validator`] is the
//!   single source of truth.
//! - **Reversibility.** Every creation is recorded in the action timeline
//!   and is undoable within 24 hours (Iron Law #5). The undo removal is
//!   itself symlink-safe and idempotent.
//!
//! # Fidelity levels supported
//!
//! This module writes to one external source — the local filesystem —
//! and runs local subprocesses. It probes for the highest-fidelity safe
//! mechanism available:
//!
//! 1. **Linux `openat2` + `RESOLVE_BENEATH`** (preferred) — kernel-level
//!    race-free directory-anchored path resolution.
//!    - Required: Linux kernel ≥ 5.6.
//!    - Failure modes: older kernels return `ENOSYS`; surfaced as a typed
//!      error rather than falling back to an unsafe path-string walk.
//!
//! 2. **(no lower-fidelity fallback for writes)** — unlike read paths,
//!    workspace *creation* deliberately has NO lower-fidelity fallback.
//!    A path-string component walk has unfixable TOCTOU races for
//!    create-with-side-effects (the FIX 16 rationale from 3A.5). On
//!    non-Linux targets the executor returns `ErrorKind::Unsupported`
//!    rather than create files through a racy mechanism.
//!
//! Every executor result carries which mechanism ran in its error/return
//! path; the D-Bus layer surfaces this to the caller.

pub mod executor;
pub mod manager;
pub mod spec;
pub mod templates;
pub mod validator;

pub use executor::{
    CommandOutcome, ExecutionOutcome, ExecutionStatus, ExecutorError, WorkspaceExecutor,
};
pub use manager::{
    CreateResult, PreviewResult, TemplateInfo, WorkspaceManager, WorkspaceManagerError,
};
pub use spec::{
    CalendarBlock, DirectoryEntry, EntryKind, SetupCommand, TemplateId, WorkspaceMetadata,
    WorkspaceSpec,
};
pub use templates::TemplateParams;
pub use validator::{validate_spec, ValidatorError};
