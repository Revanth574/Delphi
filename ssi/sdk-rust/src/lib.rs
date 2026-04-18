// SPDX-License-Identifier: MIT

//! # SSI — Semantic System Interface
//!
//! The Semantic System Interface replaces traditional syscalls with
//! intent-based, semantically rich operations. Apps declare capabilities
//! via SSI manifests, and the system validates each capability by testing
//! it before adding to the manifest.
//!
//! SSI is a standalone crate that communicates with the DIE orchestrator
//! and other system services via D-Bus. It has no internal workspace
//! dependencies.
//!
//! # Architecture
//!
//! ```text
//! App → SSI SDK → D-Bus → DIE Orchestrator → (inference, semantic-fs, etc.)
//! ```
//!
//! The SSI layer never trusts app-reported capabilities. It validates
//! by testing each capability before adding to the manifest.

pub mod error;
pub mod generator;
pub mod manifest;
pub mod scanner;

pub use error::SsiError;

/// A semantic intent that can be dispatched to the system.
///
/// Intents represent what the user or app wants to accomplish, not how.
/// The DIE orchestrator decomposes intents into concrete operations.
///
/// # Examples
///
/// ```
/// use ssi::Intent;
///
/// struct OpenFileIntent {
///     query: String,
/// }
///
/// impl Intent for OpenFileIntent {
///     fn description(&self) -> &str {
///         "Open a file matching a natural language query"
///     }
///
///     fn category(&self) -> IntentCategory {
///         IntentCategory::FileSystem
///     }
/// }
///
/// use ssi::IntentCategory;
/// let intent = OpenFileIntent { query: "my tax return from last year".into() };
/// assert_eq!(intent.category(), IntentCategory::FileSystem);
/// ```
pub trait Intent: Send + Sync {
    /// Human-readable description of what this intent does.
    fn description(&self) -> &str;

    /// The category of system resources this intent accesses.
    fn category(&self) -> IntentCategory;
}

/// Categories of system resources an intent may access.
///
/// Used by the Fortress security layer to determine what capability
/// tokens are required.
///
/// # Examples
///
/// ```
/// use ssi::IntentCategory;
/// let cat = IntentCategory::Network;
/// assert_eq!(format!("{cat:?}"), "Network");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentCategory {
    /// File system operations (read, write, search).
    FileSystem,
    /// Network operations (HTTP, WebSocket, DNS).
    Network,
    /// Inference operations (local or cloud AI).
    Inference,
    /// System operations (process management, hardware).
    System,
    /// UI operations (notifications, window management).
    UserInterface,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestIntent;

    impl Intent for TestIntent {
        fn description(&self) -> &str {
            "A test intent for unit testing"
        }

        fn category(&self) -> IntentCategory {
            IntentCategory::FileSystem
        }
    }

    #[test]
    fn intent_provides_description() {
        let intent = TestIntent;
        assert!(!intent.description().is_empty());
    }

    #[test]
    fn intent_category_is_filesystem() {
        let intent = TestIntent;
        assert_eq!(intent.category(), IntentCategory::FileSystem);
    }
}
