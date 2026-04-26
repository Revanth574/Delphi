// SPDX-License-Identifier: MIT

//! # Delphi D-Bus Services
//!
//! Provides the D-Bus interface layer that bridges the Living Surface
//! shell (React UI) to the Rust backends. Each interface corresponds
//! to a major subsystem:
//!
//! - [`inference`] — AI query routing (Tier 1/2/3)
//! - [`file_search`] — Semantic file search (Tantivy)
//! - [`mode`] — Window UI mode management
//! - [`timeline`] — Action timeline with 24-hour undo
//! - [`learning`] — Learning engine suggestions
//! - [`conversation`] — Persistent conversation memory with FTS search
//! - [`goals`] — Goal graph with deadline intelligence and timeline estimation
//! - [`environment`] — Ambient environmental awareness with fidelity-tagged sensor readings
//! - [`health`] — Predictive crisis prevention with baseline-based anomaly detection
//!
//! # Architecture
//!
//! ```text
//! Living Surface (React) ←WebSocket→ shell-bridge ←D-Bus→ delphi-services
//!                                                              ↓
//!                                           die-inference / semantic-fs / die-orchestrator
//! ```
//!
//! All 9 interfaces are registered on the session bus under
//! `org.delphi.Services`.

pub mod conversation;
pub mod environment;
pub mod file_search;
pub mod goals;
pub mod health;
pub mod inference;
pub mod learning;
pub mod mode;
pub mod timeline;

/// D-Bus well-known name for the Delphi services.
pub const DBUS_NAME: &str = "org.delphi.Services";

/// D-Bus object path prefix.
pub const DBUS_PATH: &str = "/org/delphi";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dbus_name_is_valid() {
        assert!(DBUS_NAME.starts_with("org."));
        assert!(DBUS_NAME.contains("delphi"));
    }

    #[test]
    fn dbus_path_is_valid() {
        assert!(DBUS_PATH.starts_with('/'));
    }
}
