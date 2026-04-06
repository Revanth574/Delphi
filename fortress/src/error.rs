// SPDX-License-Identifier: MIT

//! Error types for the Fortress security subsystem.
//!
//! All errors are actionable per CLAUDE.md Section 8: each variant
//! includes enough context to diagnose and resolve the issue.

/// Errors produced by the Fortress security subsystem.
///
/// Downstream crates (`die-inference`, `semantic-fs`, `die-orchestrator`)
/// convert this into their own error types via `#[from]`.
///
/// # Examples
///
/// ```
/// use fortress::FortressError;
///
/// let err = FortressError::CredentialNotFound("api-key".to_string());
/// assert!(err.to_string().contains("api-key"));
/// ```
#[derive(Debug, thiserror::Error)]
pub enum FortressError {
    /// An encryption or decryption operation failed.
    #[error("encryption error: {0}")]
    Encryption(String),

    /// The requested credential was not found in the vault.
    #[error("credential not found: {0}")]
    CredentialNotFound(String),

    /// Communication with the TPM hardware module failed.
    #[error("TPM error: {0}")]
    Tpm(String),

    /// The vault is locked or inaccessible.
    #[error("vault inaccessible: {0}")]
    VaultInaccessible(String),

    /// A permission check failed.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Audit chain integrity verification failed.
    #[error("audit chain broken: {0}")]
    AuditIntegrity(String),

    /// Configuration file error.
    #[error("config error: {0}")]
    Config(String),

    /// File I/O error within the fortress subsystem.
    #[error("fortress I/O error: {path} — {reason}")]
    Io {
        /// Path involved.
        path: String,
        /// What went wrong.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_messages_are_actionable() {
        let err = FortressError::CredentialNotFound("anthropic-api-key".to_string());
        let msg = err.to_string();
        assert!(msg.contains("anthropic-api-key"));
        assert!(msg.contains("credential not found"));
    }

    #[test]
    fn encryption_error_contains_context() {
        let err = FortressError::Encryption("AES-256-GCM nonce reuse detected".to_string());
        assert!(err.to_string().contains("AES-256-GCM"));
    }
}
