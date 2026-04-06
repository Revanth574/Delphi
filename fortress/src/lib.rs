// SPDX-License-Identifier: MIT

//! # Fortress
//!
//! Security subsystem for Delphi OS providing encryption at rest,
//! zero-knowledge proofs, TPM integration, and federated synchronization.
//!
//! Fortress is the foundational security layer that all other Delphi crates
//! depend on. It never exposes raw keys or decrypted data — only opaque
//! capability tokens.
//!
//! # Architecture
//!
//! Fortress sits at the bottom of the dependency DAG:
//! ```text
//! die-orchestrator → die-inference → fortress
//!                  → semantic-fs   → fortress
//! ```
//!
//! No module above fortress in the hierarchy may be imported here.

pub mod encryption;
pub mod error;

pub use error::FortressError;

/// Secure credential storage backed by TPM or encrypted fallback.
///
/// All secrets (API keys, tokens, passwords) in Delphi must flow through
/// a `CredentialStore` implementation. Direct access to environment variables,
/// config files, or hardcoded values is forbidden per CLAUDE.md Section 10.
///
/// # Examples
///
/// ```
/// use fortress::credentials::CredentialStore;
///
/// struct MockStore;
///
/// impl CredentialStore for MockStore {
///     fn get(&self, key: &str) -> Result<Option<String>, fortress::FortressError> {
///         Ok(Some(format!("mock-value-for-{key}")))
///     }
///
///     fn store(&self, _key: &str, _value: &str) -> Result<(), fortress::FortressError> {
///         Ok(())
///     }
///
///     fn delete(&self, _key: &str) -> Result<(), fortress::FortressError> {
///         Ok(())
///     }
/// }
/// ```
pub mod credentials {
    use crate::FortressError;

    /// Trait for secure credential management.
    ///
    /// Implementations must ensure credentials are encrypted at rest
    /// and never logged or exposed in error messages.
    pub trait CredentialStore: Send + Sync {
        /// Retrieve a credential by key.
        ///
        /// Returns `Ok(None)` if the key does not exist, or
        /// `Err(FortressError::CredentialNotFound)` if the vault is
        /// inaccessible.
        ///
        /// # Examples
        ///
        /// ```
        /// use fortress::credentials::CredentialStore;
        /// // See trait-level docs for a full implementation example.
        /// ```
        fn get(&self, key: &str) -> Result<Option<String>, FortressError>;

        /// Store a credential securely.
        ///
        /// # Examples
        ///
        /// ```
        /// use fortress::credentials::CredentialStore;
        /// // See trait-level docs for a full implementation example.
        /// ```
        fn store(&self, key: &str, value: &str) -> Result<(), FortressError>;

        /// Delete a credential from the vault.
        ///
        /// # Examples
        ///
        /// ```
        /// use fortress::credentials::CredentialStore;
        /// // See trait-level docs for a full implementation example.
        /// ```
        fn delete(&self, key: &str) -> Result<(), FortressError>;
    }
}

#[cfg(test)]
mod tests {
    use super::credentials::CredentialStore;
    use super::FortressError;

    struct TestStore;

    impl CredentialStore for TestStore {
        fn get(&self, _key: &str) -> Result<Option<String>, FortressError> {
            Ok(Some("test-secret".to_string()))
        }

        fn store(&self, _key: &str, _value: &str) -> Result<(), FortressError> {
            Ok(())
        }

        fn delete(&self, _key: &str) -> Result<(), FortressError> {
            Ok(())
        }
    }

    #[test]
    fn credential_store_get_returns_value() {
        let store = TestStore;
        let result = store.get("api-key").unwrap();
        assert_eq!(result, Some("test-secret".to_string()));
    }

    #[test]
    fn credential_store_roundtrip() {
        let store = TestStore;
        store.store("key", "value").unwrap();
        store.delete("key").unwrap();
    }
}
