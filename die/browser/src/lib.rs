// SPDX-License-Identifier: MIT

//! # Delphi Browser Engine
//!
//! Headless browser automation for the Delphi Intelligence Engine.
//! Wraps Playwright (headless Chromium) to provide web interaction
//! capabilities for the orchestrator.
//!
//! # Architecture
//!
//! ```text
//! Orchestrator → BrowserEngine → [child process] Playwright Node.js
//!                    ↓ stdin (JSON commands)
//!                    ↑ stdout (JSON results)
//! ```
//!
//! The engine manages the Playwright child process lifecycle,
//! enforces timeouts, and provides a typed Rust API for:
//!
//! - Page navigation
//! - Content extraction (text, HTML, structured data)
//! - Screenshot capture
//! - Form interaction
//! - JavaScript evaluation
//!
//! # Security
//!
//! The browser runs in a sandboxed headless context. No credentials
//! are passed directly — the Fortress vault provides session tokens
//! via capability tokens.

pub mod command;
pub mod engine;
pub mod error;

pub use command::{BrowserCommand, BrowserResult, ExtractTarget, ScreenshotFormat};
pub use engine::BrowserEngine;
pub use error::BrowserError;
