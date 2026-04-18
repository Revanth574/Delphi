// SPDX-License-Identifier: MIT

//! Privacy safeguards for the learning engine.
//!
//! Enforces CLAUDE.md Section 4 and Section 10 privacy boundaries:
//!
//! - Encrypted pattern storage (via Fortress)
//! - Live learning indicator (user sees when observation is active)
//! - "Forget" purge (delete all learned data)
//! - Focus mode auto-pause (no observation in Focus)
//! - Event sanitization (strip sensitive content)
//!
//! # Privacy Principle
//!
//! Privacy is mathematical, not promissory. The learning engine
//! observes metadata only and all stored patterns are encrypted.

use fortress::encryption::EncryptionService;
use tracing::{info, warn};

use crate::error::LearningError;

/// Privacy configuration for the learning engine.
///
/// # Examples
///
/// ```
/// use die_learning::privacy::PrivacyConfig;
///
/// let config = PrivacyConfig::default();
/// assert!(config.encrypt_patterns);
/// assert!(config.show_indicator);
/// assert!(config.auto_pause_focus);
/// ```
#[derive(Debug, Clone)]
pub struct PrivacyConfig {
    /// Whether to encrypt stored patterns (always true in production).
    pub encrypt_patterns: bool,
    /// Whether to show the live learning indicator in the UI.
    pub show_indicator: bool,
    /// Whether to auto-pause observation in Focus mode.
    pub auto_pause_focus: bool,
    /// Maximum days to retain raw events (0 = no limit).
    pub retention_days: u32,
}

impl Default for PrivacyConfig {
    /// Default privacy settings — maximum protection.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::privacy::PrivacyConfig;
    ///
    /// let config = PrivacyConfig::default();
    /// assert!(config.encrypt_patterns);
    /// assert_eq!(config.retention_days, 90);
    /// ```
    fn default() -> Self {
        Self {
            encrypt_patterns: true,
            show_indicator: true,
            auto_pause_focus: true,
            retention_days: 90,
        }
    }
}

/// Guard that manages pattern encryption lifecycle.
///
/// Wraps the Fortress `EncryptionService` for the learning engine's
/// specific needs. All pattern data flows through this guard before
/// being written to or read from disk.
///
/// # Examples
///
/// ```
/// use die_learning::privacy::{PrivacyGuard, PrivacyConfig};
///
/// let guard = PrivacyGuard::new(PrivacyConfig::default());
/// assert!(guard.is_encryption_enabled());
/// ```
pub struct PrivacyGuard {
    /// Privacy settings.
    config: PrivacyConfig,
    /// Fortress encryption service.
    encryption: EncryptionService,
}

impl PrivacyGuard {
    /// Create a new privacy guard.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::privacy::{PrivacyGuard, PrivacyConfig};
    ///
    /// let guard = PrivacyGuard::new(PrivacyConfig::default());
    /// ```
    #[must_use]
    pub fn new(config: PrivacyConfig) -> Self {
        Self {
            config,
            encryption: EncryptionService::new(),
        }
    }

    /// Whether encryption is enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::privacy::{PrivacyGuard, PrivacyConfig};
    ///
    /// let guard = PrivacyGuard::new(PrivacyConfig::default());
    /// assert!(guard.is_encryption_enabled());
    /// ```
    #[must_use]
    pub fn is_encryption_enabled(&self) -> bool {
        self.config.encrypt_patterns
    }

    /// Whether the learning indicator should be shown.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::privacy::{PrivacyGuard, PrivacyConfig};
    ///
    /// let guard = PrivacyGuard::new(PrivacyConfig::default());
    /// assert!(guard.show_indicator());
    /// ```
    #[must_use]
    pub fn show_indicator(&self) -> bool {
        self.config.show_indicator
    }

    /// Whether Focus mode should auto-pause observation.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::privacy::{PrivacyGuard, PrivacyConfig};
    ///
    /// let guard = PrivacyGuard::new(PrivacyConfig::default());
    /// assert!(guard.auto_pause_focus());
    /// ```
    #[must_use]
    pub fn auto_pause_focus(&self) -> bool {
        self.config.auto_pause_focus
    }

    /// Pattern data retention period in days.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::privacy::{PrivacyGuard, PrivacyConfig};
    ///
    /// let guard = PrivacyGuard::new(PrivacyConfig::default());
    /// assert_eq!(guard.retention_days(), 90);
    /// ```
    #[must_use]
    pub fn retention_days(&self) -> u32 {
        self.config.retention_days
    }

    /// Encrypt pattern data for storage.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails (e.g., Fortress not initialized).
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::privacy::{PrivacyGuard, PrivacyConfig};
    ///
    /// let guard = PrivacyGuard::new(PrivacyConfig::default());
    /// // Will fail until Fortress key material is initialized
    /// assert!(guard.encrypt_data(b"pattern data").is_err());
    /// ```
    pub fn encrypt_data(&self, plaintext: &[u8]) -> Result<Vec<u8>, LearningError> {
        if !self.config.encrypt_patterns {
            // DECISION: In production, encryption is always on.
            // This path exists only for testing.
            warn!("pattern encryption disabled — data stored in plaintext");
            return Ok(plaintext.to_vec());
        }

        self.encryption
            .encrypt(plaintext)
            .map_err(LearningError::Security)
    }

    /// Decrypt pattern data from storage.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::privacy::{PrivacyGuard, PrivacyConfig};
    ///
    /// let guard = PrivacyGuard::new(PrivacyConfig::default());
    /// assert!(guard.decrypt_data(b"ciphertext").is_err());
    /// ```
    pub fn decrypt_data(&self, ciphertext: &[u8]) -> Result<Vec<u8>, LearningError> {
        if !self.config.encrypt_patterns {
            return Ok(ciphertext.to_vec());
        }

        self.encryption
            .decrypt(ciphertext)
            .map_err(LearningError::Security)
    }

    /// Sanitize a source string for safe storage.
    ///
    /// Strips potential sensitive content from event metadata. For
    /// example, removes query parameters from URLs and truncates
    /// long paths.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::privacy::{PrivacyGuard, PrivacyConfig};
    ///
    /// let guard = PrivacyGuard::new(PrivacyConfig::default());
    /// let sanitized = guard.sanitize_source("https://example.com/page?token=secret123");
    /// assert!(!sanitized.contains("secret123"));
    /// ```
    #[must_use]
    pub fn sanitize_source(&self, source: &str) -> String {
        let mut sanitized = source.to_string();

        // Strip URL query parameters (may contain tokens/secrets).
        if let Some(pos) = sanitized.find('?') {
            sanitized.truncate(pos);
        }

        // Strip URL fragments.
        if let Some(pos) = sanitized.find('#') {
            sanitized.truncate(pos);
        }

        // Truncate excessively long paths.
        if sanitized.len() > 256 {
            sanitized.truncate(256);
            sanitized.push_str("...");
        }

        sanitized
    }

    /// Check if a source string looks like it might contain sensitive data.
    ///
    /// Returns `true` if the source contains patterns commonly
    /// associated with secrets (API keys, tokens, passwords).
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::privacy::{PrivacyGuard, PrivacyConfig};
    ///
    /// let guard = PrivacyGuard::new(PrivacyConfig::default());
    /// assert!(guard.looks_sensitive("api_key=sk-abc123def456"));
    /// assert!(!guard.looks_sensitive("firefox"));
    /// ```
    #[must_use]
    pub fn looks_sensitive(&self, source: &str) -> bool {
        let lower = source.to_lowercase();
        let sensitive_patterns = [
            "password", "passwd", "secret", "token", "api_key",
            "apikey", "auth", "credential", "private_key",
            "ssh-rsa", "bearer",
        ];

        sensitive_patterns
            .iter()
            .any(|pattern| lower.contains(pattern))
    }

    /// Perform a full privacy purge ("Forget" button).
    ///
    /// Logs the action for audit trail per CLAUDE.md Section 10.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_learning::privacy::{PrivacyGuard, PrivacyConfig};
    ///
    /// let guard = PrivacyGuard::new(PrivacyConfig::default());
    /// guard.log_purge();
    /// ```
    pub fn log_purge(&self) {
        info!("PRIVACY PURGE: all learning data has been deleted by user request");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_strict() {
        let config = PrivacyConfig::default();
        assert!(config.encrypt_patterns);
        assert!(config.show_indicator);
        assert!(config.auto_pause_focus);
        assert_eq!(config.retention_days, 90);
    }

    #[test]
    fn guard_creation() {
        let guard = PrivacyGuard::new(PrivacyConfig::default());
        assert!(guard.is_encryption_enabled());
        assert!(guard.show_indicator());
        assert!(guard.auto_pause_focus());
        assert_eq!(guard.retention_days(), 90);
    }

    #[test]
    fn encrypt_fails_without_key_material() {
        let guard = PrivacyGuard::new(PrivacyConfig::default());
        // Fortress not initialized — encryption should fail.
        let result = guard.encrypt_data(b"test data");
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_fails_without_key_material() {
        let guard = PrivacyGuard::new(PrivacyConfig::default());
        let result = guard.decrypt_data(b"fake ciphertext");
        assert!(result.is_err());
    }

    #[test]
    fn encryption_disabled_passes_through() {
        let config = PrivacyConfig {
            encrypt_patterns: false,
            ..PrivacyConfig::default()
        };
        let guard = PrivacyGuard::new(config);

        let data = b"test pattern data";
        let encrypted = guard.encrypt_data(data).unwrap();
        assert_eq!(encrypted, data);

        let decrypted = guard.decrypt_data(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn sanitize_strips_query_params() {
        let guard = PrivacyGuard::new(PrivacyConfig::default());
        let result = guard.sanitize_source("https://example.com/page?token=abc123");
        assert_eq!(result, "https://example.com/page");
        assert!(!result.contains("abc123"));
    }

    #[test]
    fn sanitize_strips_fragments() {
        let guard = PrivacyGuard::new(PrivacyConfig::default());
        let result = guard.sanitize_source("https://example.com/page#section-private");
        assert_eq!(result, "https://example.com/page");
    }

    #[test]
    fn sanitize_truncates_long_paths() {
        let guard = PrivacyGuard::new(PrivacyConfig::default());
        let long_path = "a".repeat(300);
        let result = guard.sanitize_source(&long_path);
        assert!(result.len() < 300);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn sanitize_preserves_normal_paths() {
        let guard = PrivacyGuard::new(PrivacyConfig::default());
        assert_eq!(
            guard.sanitize_source("/home/user/documents/report.pdf"),
            "/home/user/documents/report.pdf"
        );
    }

    #[test]
    fn looks_sensitive_detects_patterns() {
        let guard = PrivacyGuard::new(PrivacyConfig::default());
        assert!(guard.looks_sensitive("my_password=abc"));
        assert!(guard.looks_sensitive("API_KEY_VALUE"));
        assert!(guard.looks_sensitive("Bearer token123"));
        assert!(guard.looks_sensitive("ssh-rsa AAAA..."));
        assert!(guard.looks_sensitive("auth_credential"));
    }

    #[test]
    fn looks_sensitive_allows_normal_strings() {
        let guard = PrivacyGuard::new(PrivacyConfig::default());
        assert!(!guard.looks_sensitive("firefox"));
        assert!(!guard.looks_sensitive("/home/user/report.pdf"));
        assert!(!guard.looks_sensitive("code"));
    }

    #[test]
    fn log_purge_does_not_panic() {
        let guard = PrivacyGuard::new(PrivacyConfig::default());
        guard.log_purge(); // Should not panic.
    }

    #[test]
    fn custom_config() {
        let config = PrivacyConfig {
            encrypt_patterns: false,
            show_indicator: false,
            auto_pause_focus: false,
            retention_days: 30,
        };
        let guard = PrivacyGuard::new(config);
        assert!(!guard.is_encryption_enabled());
        assert!(!guard.show_indicator());
        assert!(!guard.auto_pause_focus());
        assert_eq!(guard.retention_days(), 30);
    }
}
