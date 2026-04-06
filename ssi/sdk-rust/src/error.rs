// SPDX-License-Identifier: MIT

//! Error types for the Semantic System Interface SDK.
//!
//! Errors include context about what failed and how to resolve it,
//! per CLAUDE.md Section 8.

/// Errors produced by the SSI SDK.
///
/// # Examples
///
/// ```
/// use ssi::SsiError;
///
/// let err = SsiError::DispatchFailed("orchestrator not responding".to_string());
/// assert!(err.to_string().contains("orchestrator"));
/// ```
#[derive(Debug, thiserror::Error)]
pub enum SsiError {
    /// Failed to dispatch an intent to the system.
    #[error("intent dispatch failed: {0}")]
    DispatchFailed(String),

    /// D-Bus communication error.
    #[error("D-Bus communication error: {0}")]
    Dbus(String),

    /// The requested capability is not available for the calling app.
    #[error("capability denied: {0}")]
    CapabilityDenied(String),

    /// Manifest validation failed.
    #[error("manifest validation error: {0}")]
    ManifestValidation(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_error_is_descriptive() {
        let err = SsiError::DispatchFailed(
            "orchestrator not responding on org.delphi.die".to_string(),
        );
        let msg = err.to_string();
        assert!(msg.contains("orchestrator"));
        assert!(msg.contains("dispatch"));
    }

    #[test]
    fn capability_denied_includes_reason() {
        let err = SsiError::CapabilityDenied(
            "app 'notes' lacks filesystem.write permission".to_string(),
        );
        assert!(err.to_string().contains("filesystem.write"));
    }
}
