// SPDX-License-Identifier: MIT

//! Error types for the Fortress security subsystem.
//!
//! All errors are actionable per CLAUDE.md Section 8: each variant
//! includes enough context to diagnose and resolve the issue.

use std::fmt;

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
/// // Display is redacted (it crosses `#[from]` boundaries); the name is not leaked.
/// assert!(!err.to_string().contains("api-key"));
/// // The detail stays available via the controlled `diagnostic()` channel.
/// assert!(err.diagnostic().contains("api-key"));
/// ```
#[derive(thiserror::Error)]
pub enum FortressError {
    /// An encryption or decryption operation failed.
    #[error("encryption error: {0}")]
    Encryption(String),

    /// The requested credential was not found in the vault.
    ///
    /// Display is redacted (no credential name); the name is available via
    /// [`diagnostic`](Self::diagnostic) for controlled local use (FORT-R1-04).
    #[error("credential not found")]
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
    ///
    /// Display is redacted (no path/reason); both are available via
    /// [`diagnostic`](Self::diagnostic) for controlled local use (FORT-R1-04).
    #[error("fortress I/O error")]
    Io {
        /// Path involved.
        path: String,
        /// What went wrong.
        reason: String,
    },
}

impl fmt::Debug for FortressError {
    /// `Debug` delegates to the redacted [`Display`](fmt::Display) so `{:?}`
    /// cannot leak a caller-supplied credential name or filesystem path at a
    /// trust boundary — the downstream `#[from]` error types derive `Debug` over
    /// this. Full detail is available via [`diagnostic`](Self::diagnostic).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl FortressError {
    /// Full diagnostic detail INCLUDING the caller-supplied identifiers
    /// (credential name, filesystem path) that `Display`/`Debug` redact.
    ///
    /// This is the CONTROLLED diagnostic channel — for local tracing and audit
    /// only. It MUST NOT cross a trust boundary or reach an untrusted log sink;
    /// for those, use `Display` (redacted).
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::FortressError;
    ///
    /// let err = FortressError::CredentialNotFound("api-key".to_string());
    /// assert!(err.diagnostic().contains("api-key"));
    /// assert!(!err.to_string().contains("api-key"));
    /// ```
    #[must_use]
    pub fn diagnostic(&self) -> String {
        match self {
            Self::CredentialNotFound(name) => format!("credential not found: {name}"),
            Self::Io { path, reason } => format!("fortress I/O error: {path} — {reason}"),
            other => other.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_channel_stays_actionable_fort_r1_04() {
        // Genuine invariant preserved: the detail stays available via the
        // CONTROLLED diagnostic() channel (local tracing/audit), and Display is
        // still minimally actionable — just without the caller-supplied identifier.
        let err = FortressError::CredentialNotFound("anthropic-api-key".to_string());
        assert!(
            err.to_string().contains("credential not found"),
            "Display stays minimally actionable"
        );
        assert!(
            err.diagnostic().contains("anthropic-api-key"),
            "diagnostic() carries the caller-supplied detail"
        );
    }

    #[test]
    fn encryption_error_contains_context() {
        let err = FortressError::Encryption("AES-256-GCM nonce reuse detected".to_string());
        assert!(err.to_string().contains("AES-256-GCM"));
    }

    #[test]
    fn display_and_debug_redact_caller_identifiers_fort_r1_04() {
        // Leak-freedom (FORT-R1-04): public Display AND Debug must NOT carry the
        // caller-supplied credential name or filesystem path — they cross #[from]
        // boundaries and untrusted log sinks. RED pre-fix: both render the inner
        // strings (and a test even asserted the credential-name disclosure).
        let cred = FortressError::CredentialNotFound("anthropic-api-key".to_string());
        assert!(
            !cred.to_string().contains("anthropic-api-key"),
            "credential name leaked in Display"
        );
        assert!(
            !format!("{cred:?}").contains("anthropic-api-key"),
            "credential name leaked in Debug"
        );
        let io = FortressError::Io {
            path: "/home/user/.secret/vault".to_string(),
            reason: "denied".to_string(),
        };
        assert!(
            !io.to_string().contains("/home/user/.secret/vault"),
            "path leaked in Display"
        );
        assert!(
            !format!("{io:?}").contains("/home/user/.secret/vault"),
            "path leaked in Debug"
        );
    }
}
