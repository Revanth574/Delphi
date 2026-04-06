// SPDX-License-Identifier: MIT

//! Encryption at rest module for the Fortress security subsystem.
//!
//! Provides AES-256-GCM encryption services used by `semantic-fs`
//! and other subsystems that store user data. Raw keys never leave
//! this module — callers receive opaque handles.

use crate::FortressError;

/// Service for encrypting and decrypting data at rest.
///
/// Wraps AES-256-GCM operations. Keys are managed internally and
/// never exposed to callers.
///
/// # Examples
///
/// ```
/// use fortress::encryption::EncryptionService;
///
/// let service = EncryptionService::new();
/// // In production, keys are loaded from TPM or derived from passphrase.
/// // The service provides opaque encrypt/decrypt operations.
/// ```
pub struct EncryptionService {
    _initialized: bool,
}

impl EncryptionService {
    /// Create a new encryption service.
    ///
    /// In production, this will initialize key material from the TPM
    /// or derive it from the user's passphrase via Argon2id.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::encryption::EncryptionService;
    /// let service = EncryptionService::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            _initialized: true,
        }
    }

    /// Encrypt a plaintext byte slice, returning ciphertext.
    ///
    /// Uses AES-256-GCM with a random nonce. The nonce is prepended
    /// to the ciphertext for later decryption.
    ///
    /// # Errors
    ///
    /// Returns `FortressError::Encryption` if key material is not loaded
    /// or if the encryption operation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::encryption::EncryptionService;
    ///
    /// let service = EncryptionService::new();
    /// let result = service.encrypt(b"sensitive data");
    /// // Will return Err until real crypto is wired up.
    /// assert!(result.is_err());
    /// ```
    pub fn encrypt(&self, _plaintext: &[u8]) -> Result<Vec<u8>, FortressError> {
        // Real implementation will use AES-256-GCM via a crypto crate.
        // Returning an error here because no key material is loaded yet.
        Err(FortressError::Encryption(
            "no key material loaded — run fortress init first".to_string(),
        ))
    }

    /// Decrypt a ciphertext byte slice, returning plaintext.
    ///
    /// Expects the nonce to be prepended to the ciphertext (as produced
    /// by `encrypt`).
    ///
    /// # Errors
    ///
    /// Returns `FortressError::Encryption` if decryption fails (wrong key,
    /// corrupted data, or key material not loaded).
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::encryption::EncryptionService;
    ///
    /// let service = EncryptionService::new();
    /// let result = service.decrypt(b"ciphertext");
    /// assert!(result.is_err());
    /// ```
    pub fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>, FortressError> {
        Err(FortressError::Encryption(
            "no key material loaded — run fortress init first".to_string(),
        ))
    }
}

impl Default for EncryptionService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_service_is_initialized() {
        let service = EncryptionService::new();
        // Service creates successfully — no panic.
        let _default = EncryptionService::default();
        // Encrypt without keys returns a descriptive error.
        let err = service.encrypt(b"test").unwrap_err();
        assert!(err.to_string().contains("no key material loaded"));
    }

    #[test]
    fn decrypt_without_keys_returns_error() {
        let service = EncryptionService::new();
        let err = service.decrypt(b"fake-ciphertext").unwrap_err();
        assert!(err.to_string().contains("fortress init"));
    }
}
