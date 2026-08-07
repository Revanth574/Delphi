// SPDX-License-Identifier: MIT

//! The environment-variable names the launcher and the minimal sides agree on.
//!
//! # Why these are constants and not string literals (D0A-R2-01)
//!
//! They were literals in seven places. A test passed `DELPHI_TEST_PASSWORD` /
//! `DELPHI_TEST_EXE` / `DELPHI_TEST_CWD` while the binaries read `DELPHI_PASSWORD` /
//! `DELPHI_AI_EXE` / `DELPHI_AI_BIND_RW` — three names that exist nowhere. **Nothing could
//! detect it**: the types matched, it compiled, and the failure was a hang (the AI panicked
//! before connecting, so the daemon blocked in `accept` forever) rather than an error naming
//! the cause. The test could never have passed, and only running it would have said so.
//!
//! This is the silent-no-op class one layer out — an **interface** mismatch rather than a text
//! one — and the fix is the same shape that has held everywhere else on this branch:
//! foreclosure over detection. With one construction site a wrong name is a compile error, not
//! a hang.
//!
//! These are **scaffolding** names: the minimal shell/AI are B1 stand-ins, not the real shell
//! or Brain. They live in the lib rather than a test helper because the binaries read them too,
//! and the whole point is that both sides name the same constant.

/// The inherited fd number carrying the private consent channel (set by the launcher).
pub const CHANNEL_FD: &str = "DELPHI_CHANNEL_FD";

/// The approval socket path handed to the AI side.
pub const APPROVE_SOCK: &str = "DELPHI_APPROVE_SOCK";

/// Scripted password for the minimal shell. **Test scaffolding only** — in production a human
/// types it into the real dialog and it never touches the environment.
pub const PASSWORD: &str = "DELPHI_PASSWORD";

/// Executable the minimal AI proposes.
pub const AI_EXE: &str = "DELPHI_AI_EXE";

/// Argument for that executable.
pub const AI_ARG: &str = "DELPHI_AI_ARG";

/// Directory the sandbox binds read-write for the proposed action.
pub const AI_BIND_RW: &str = "DELPHI_AI_BIND_RW";
