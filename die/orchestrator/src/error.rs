// SPDX-License-Identifier: MIT

//! Error types for the DIE orchestrator.
//!
//! The orchestrator aggregates errors from all downstream crates via
//! `#[from]` conversions. If this file compiles, the entire dependency
//! DAG is proven correct.
//!
//! Per CLAUDE.md Section 8: orchestrator errors must **never** crash
//! the OS. They degrade gracefully to the next available tier or mode.

use die_inference::InferenceError;
use fortress::FortressError;
use semantic_fs::SemanticFsError;

/// Errors produced by the DIE orchestrator.
///
/// This enum has `From` implementations for all downstream error types,
/// enabling the `?` operator across crate boundaries.
///
/// # Examples
///
/// ```
/// use die_orchestrator::OrchestratorError;
/// use fortress::FortressError;
///
/// let err = FortressError::Tpm("device not found".to_string());
/// let orch_err: OrchestratorError = err.into();
/// assert!(orch_err.to_string().contains("TPM"));
/// ```
#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    /// Intent planning or decomposition failed.
    #[error("planning failed: {0}")]
    Planning(String),

    /// D-Bus communication with the shell failed.
    #[error("D-Bus error: {0}")]
    Dbus(String),

    /// Inference subsystem error (propagated from die-inference).
    #[error("inference error: {0}")]
    Inference(#[from] InferenceError),

    /// Semantic file system error (propagated from semantic-fs).
    #[error("search error: {0}")]
    Search(#[from] SemanticFsError),

    /// Security subsystem error (propagated from fortress).
    #[error("security error: {0}")]
    Security(#[from] FortressError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inference_error_converts() {
        let err = InferenceError::Timeout(3000);
        let orch_err: OrchestratorError = err.into();
        assert!(orch_err.to_string().contains("3000"));
    }

    #[test]
    fn semantic_fs_error_converts() {
        let err = SemanticFsError::Indexing("corrupt index".to_string());
        let orch_err: OrchestratorError = err.into();
        assert!(orch_err.to_string().contains("corrupt"));
    }

    #[test]
    fn fortress_error_converts() {
        let err = FortressError::VaultInaccessible("locked".to_string());
        let orch_err: OrchestratorError = err.into();
        assert!(orch_err.to_string().contains("locked"));
    }

    #[test]
    fn planning_error_is_descriptive() {
        let err = OrchestratorError::Planning(
            "could not decompose intent: ambiguous file reference".to_string(),
        );
        assert!(err.to_string().contains("ambiguous"));
    }
}
