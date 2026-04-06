// SPDX-License-Identifier: MIT

//! Error types for the inference subsystem.
//!
//! Inference errors cascade gracefully per CLAUDE.md Section 8:
//! local model failure → try cloud → "AI temporarily unavailable."

use fortress::FortressError;

/// Errors produced by the inference subsystem.
///
/// The `#[from] FortressError` conversion allows using `?` on fortress
/// operations within inference code, proving the dependency direction
/// (die-inference → fortress) at compile time.
///
/// # Examples
///
/// ```
/// use die_inference::InferenceError;
/// use fortress::FortressError;
///
/// // FortressError converts automatically via From trait.
/// let fortress_err = FortressError::CredentialNotFound("openai-key".to_string());
/// let inference_err: InferenceError = fortress_err.into();
/// assert!(inference_err.to_string().contains("openai-key"));
/// ```
#[derive(Debug, thiserror::Error)]
pub enum InferenceError {
    /// No inference backend is available (all tiers failed).
    #[error("no inference backend available — all tiers exhausted. Check model files and cloud credentials.")]
    NoBackend,

    /// A model failed to load from disk.
    #[error("model load failed: {0}")]
    ModelLoad(String),

    /// Inference timed out.
    #[error("inference timed out after {0} ms")]
    Timeout(u64),

    /// Cloud API returned an error.
    #[error("cloud API error: {0}")]
    CloudApi(String),

    /// Credential access failed (propagated from fortress).
    #[error("credential access failed: {0}")]
    Credential(#[from] FortressError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fortress_error_converts_to_inference_error() {
        let fortress_err = FortressError::CredentialNotFound("anthropic-key".to_string());
        let inference_err: InferenceError = fortress_err.into();
        assert!(inference_err.to_string().contains("anthropic-key"));
    }

    #[test]
    fn no_backend_error_is_actionable() {
        let err = InferenceError::NoBackend;
        let msg = err.to_string();
        assert!(msg.contains("model files"));
        assert!(msg.contains("cloud credentials"));
    }

    #[test]
    fn timeout_includes_duration() {
        let err = InferenceError::Timeout(5000);
        assert!(err.to_string().contains("5000"));
    }
}
