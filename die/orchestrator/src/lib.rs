// SPDX-License-Identifier: MIT

//! # DIE Orchestrator
//!
//! Central planning agent for the Delphi Intelligence Engine.
//!
//! The orchestrator receives user intents via D-Bus from the Living Surface
//! shell, decomposes them into steps, and coordinates execution across
//! the inference engine, semantic file system, and other subsystems.
//!
//! # Architecture
//!
//! The orchestrator sits at the top of the internal dependency DAG:
//!
//! ```text
//! Living Surface UI → (D-Bus) → DIE Orchestrator
//!                                    ↓           ↓           ↓
//!                              die-inference  semantic-fs  fortress
//! ```
//!
//! It is the **only** application-level crate, using `anyhow` at its
//! boundaries while using `thiserror` internally.
//!
//! # Dependencies
//!
//! - [`fortress`] — security policy enforcement and credential access
//! - [`die_inference`] — AI model routing and execution
//! - [`semantic_fs`] — file search and knowledge retrieval

pub mod apps;
pub mod brain;
pub mod conversation;
pub mod environment;
pub mod error;
pub mod goals;
pub mod health;
pub mod planner;
pub mod reference;
pub mod risk;
pub mod timeline;

pub use error::OrchestratorError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_type_is_accessible() {
        let err = OrchestratorError::Planning("test".to_string());
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn all_downstream_errors_convert() {
        // Verify fortress → orchestrator conversion.
        let fortress_err = fortress::FortressError::CredentialNotFound("key".to_string());
        let orch_err: OrchestratorError = fortress_err.into();
        assert!(orch_err.to_string().contains("key"));

        // Verify inference → orchestrator conversion.
        let inf_err = die_inference::InferenceError::NoBackend;
        let orch_err: OrchestratorError = inf_err.into();
        assert!(orch_err.to_string().contains("backend"));

        // Verify semantic-fs → orchestrator conversion.
        let fs_err = semantic_fs::SemanticFsError::Search("query failed".to_string());
        let orch_err: OrchestratorError = fs_err.into();
        assert!(orch_err.to_string().contains("query failed"));

        // Verify browser → orchestrator conversion.
        let browser_err = die_browser::BrowserError::Timeout { seconds: 60 };
        let orch_err: OrchestratorError = browser_err.into();
        assert!(orch_err.to_string().contains("60"));

        // Verify learning → orchestrator conversion.
        let learning_err = die_learning::LearningError::ObserverPaused;
        let orch_err: OrchestratorError = learning_err.into();
        assert!(orch_err.to_string().contains("paused"));
    }
}
