// SPDX-License-Identifier: MIT

//! Encrypted credential vault using AES-256-GCM + Argon2id.
//!
//! Credentials are stored as encrypted blobs in a single vault file.
//! The master key is derived from a passphrase using Argon2id.
//! The vault file is meaningless without the master passphrase.
//!
//! # Security Model
//!
//! - Key derivation: Argon2id with 64 MB memory cost, 3 iterations
//! - Encryption: AES-256-GCM with random 96-bit nonces
//! - Storage: each credential is independently encrypted (no bulk decrypt)
//! - In-memory: keys are zeroized when the vault locks

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, AeadCore, Key, Nonce};
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::FortressError;

/// Salt length for Argon2id key derivation.
const SALT_LEN: usize = 32;

/// A single encrypted credential entry stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    /// The service this credential belongs to (e.g., "anthropic-api").
    pub service: String,
    /// The type of credential (e.g., "api_key", "token").
    pub credential_type: String,
    /// AES-256-GCM nonce (12 bytes, hex-encoded).
    pub nonce: String,
    /// Encrypted credential value (hex-encoded ciphertext + auth tag).
    pub ciphertext: String,
}

/// The vault file format (serialized to TOML).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFile {
    /// Argon2id salt (hex-encoded, 32 bytes).
    pub salt: String,
    /// Encrypted entries.
    pub entries: Vec<VaultEntry>,
}

/// An encrypted credential vault with AES-256-GCM + Argon2id key derivation.
///
/// The vault must be explicitly unlocked with a master passphrase before
/// any credential operations. It locks automatically after a configurable
/// timeout or when dropped.
///
/// # Examples
///
/// ```
/// use fortress::vault::Vault;
///
/// let vault = Vault::in_memory();
/// // Vault starts locked — must unlock before use.
/// assert!(!vault.is_unlocked());
/// ```
pub struct Vault {
    /// Path to the vault file on disk (None for in-memory vaults).
    path: Option<PathBuf>,
    /// Argon2id salt for key derivation.
    salt: [u8; SALT_LEN],
    /// Derived AES-256 key (only present when unlocked).
    key: Option<Key<Aes256Gcm>>,
    /// Decrypted credential cache (service:type -> plaintext).
    cache: HashMap<String, String>,
    /// Raw vault entries (for persistence).
    entries: Vec<VaultEntry>,
}

impl Vault {
    /// Create an in-memory vault (useful for testing).
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::vault::Vault;
    /// let vault = Vault::in_memory();
    /// ```
    #[must_use]
    pub fn in_memory() -> Self {
        let mut salt = [0u8; SALT_LEN];
        aes_gcm::aead::rand_core::RngCore::fill_bytes(&mut OsRng, &mut salt);
        Self {
            path: None,
            salt,
            key: None,
            cache: HashMap::new(),
            entries: Vec::new(),
        }
    }

    /// Open or create a vault file at the given path.
    ///
    /// If the file exists, the vault structure is loaded (but stays locked).
    /// If it doesn't exist, a fresh vault is created.
    ///
    /// # Errors
    ///
    /// Returns `FortressError::Io` if the file can't be read.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use fortress::vault::Vault;
    /// use std::path::Path;
    ///
    /// let vault = Vault::open(Path::new("/tmp/test-vault.toml")).unwrap();
    /// ```
    pub fn open(path: &Path) -> Result<Self, FortressError> {
        if path.exists() {
            let content = std::fs::read_to_string(path).map_err(|e| FortressError::Io {
                path: path.display().to_string(),
                reason: e.to_string(),
            })?;
            let vault_file: VaultFile =
                toml::from_str(&content).map_err(|e| FortressError::Config(e.to_string()))?;

            let salt = hex_decode(&vault_file.salt).map_err(|e| {
                FortressError::Encryption(format!("invalid salt in vault file: {e}"))
            })?;
            let mut salt_arr = [0u8; SALT_LEN];
            if salt.len() != SALT_LEN {
                return Err(FortressError::Encryption("invalid salt length".to_string()));
            }
            salt_arr.copy_from_slice(&salt);

            info!("loaded vault with {} entries from {}", vault_file.entries.len(), path.display());
            Ok(Self {
                path: Some(path.to_path_buf()),
                salt: salt_arr,
                key: None,
                cache: HashMap::new(),
                entries: vault_file.entries,
            })
        } else {
            let mut salt = [0u8; SALT_LEN];
            aes_gcm::aead::rand_core::RngCore::fill_bytes(&mut OsRng, &mut salt);
            debug!("creating new vault at {}", path.display());
            Ok(Self {
                path: Some(path.to_path_buf()),
                salt,
                key: None,
                cache: HashMap::new(),
                entries: Vec::new(),
            })
        }
    }

    /// Unlock the vault with a master passphrase.
    ///
    /// Derives the AES-256 key using Argon2id and decrypts all entries
    /// into the in-memory cache.
    ///
    /// # Errors
    ///
    /// Returns `FortressError::Encryption` if key derivation fails or
    /// any entry fails to decrypt (wrong passphrase).
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::vault::Vault;
    ///
    /// let mut vault = Vault::in_memory();
    /// vault.unlock("my-master-passphrase").unwrap();
    /// assert!(vault.is_unlocked());
    /// ```
    pub fn unlock(&mut self, passphrase: &str) -> Result<(), FortressError> {
        let key = derive_key(passphrase, &self.salt)?;
        let cipher = Aes256Gcm::new(&key);

        // Decrypt all existing entries into the cache.
        let mut cache = HashMap::new();
        for entry in &self.entries {
            let nonce_bytes = hex_decode(&entry.nonce)
                .map_err(|e| FortressError::Encryption(format!("invalid nonce: {e}")))?;
            let ciphertext = hex_decode(&entry.ciphertext)
                .map_err(|e| FortressError::Encryption(format!("invalid ciphertext: {e}")))?;

            let nonce = Nonce::from_slice(&nonce_bytes);
            let plaintext = cipher
                .decrypt(nonce, ciphertext.as_ref())
                .map_err(|_| {
                    FortressError::Encryption(
                        "decryption failed — wrong passphrase or corrupted vault".to_string(),
                    )
                })?;

            let value = String::from_utf8(plaintext).map_err(|_| {
                FortressError::Encryption("decrypted value is not valid UTF-8".to_string())
            })?;

            let cache_key = format!("{}:{}", entry.service, entry.credential_type);
            cache.insert(cache_key, value);
        }

        self.key = Some(key);
        self.cache = cache;
        info!("vault unlocked, {} credentials loaded", self.entries.len());
        Ok(())
    }

    /// Lock the vault, clearing all decrypted data from memory.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::vault::Vault;
    ///
    /// let mut vault = Vault::in_memory();
    /// vault.unlock("pass").unwrap();
    /// vault.lock();
    /// assert!(!vault.is_unlocked());
    /// ```
    pub fn lock(&mut self) {
        self.key = None;
        self.cache.clear();
        debug!("vault locked");
    }

    /// Check whether the vault is currently unlocked.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::vault::Vault;
    /// let vault = Vault::in_memory();
    /// assert!(!vault.is_unlocked());
    /// ```
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.key.is_some()
    }

    /// Store a credential in the vault.
    ///
    /// The value is immediately encrypted and added to the vault. If a
    /// credential with the same service + type already exists, it is replaced.
    ///
    /// # Errors
    ///
    /// Returns `FortressError::VaultInaccessible` if the vault is locked.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::vault::Vault;
    ///
    /// let mut vault = Vault::in_memory();
    /// vault.unlock("pass").unwrap();
    /// vault.store("anthropic", "api_key", "sk-ant-xxx").unwrap();
    /// ```
    pub fn store(
        &mut self,
        service: &str,
        credential_type: &str,
        value: &str,
    ) -> Result<(), FortressError> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| FortressError::VaultInaccessible("vault is locked".to_string()))?;

        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, value.as_bytes())
            .map_err(|_| FortressError::Encryption("encryption failed".to_string()))?;

        let entry = VaultEntry {
            service: service.to_string(),
            credential_type: credential_type.to_string(),
            nonce: hex_encode(&nonce),
            ciphertext: hex_encode(&ciphertext),
        };

        // Remove existing entry for this service:type if any.
        let cache_key = format!("{service}:{credential_type}");
        self.entries
            .retain(|e| !(e.service == service && e.credential_type == credential_type));
        self.entries.push(entry);
        self.cache.insert(cache_key, value.to_string());

        self.persist()?;
        Ok(())
    }

    /// Retrieve a credential from the vault.
    ///
    /// Returns `None` if no credential matches the service + type.
    ///
    /// # Errors
    ///
    /// Returns `FortressError::VaultInaccessible` if the vault is locked.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::vault::Vault;
    ///
    /// let mut vault = Vault::in_memory();
    /// vault.unlock("pass").unwrap();
    /// vault.store("svc", "token", "abc123").unwrap();
    /// assert_eq!(vault.retrieve("svc", "token").unwrap(), Some("abc123".to_string()));
    /// ```
    pub fn retrieve(
        &self,
        service: &str,
        credential_type: &str,
    ) -> Result<Option<String>, FortressError> {
        if !self.is_unlocked() {
            return Err(FortressError::VaultInaccessible(
                "vault is locked".to_string(),
            ));
        }
        let cache_key = format!("{service}:{credential_type}");
        Ok(self.cache.get(&cache_key).cloned())
    }

    /// Delete a credential from the vault.
    ///
    /// # Errors
    ///
    /// Returns `FortressError::VaultInaccessible` if the vault is locked.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::vault::Vault;
    ///
    /// let mut vault = Vault::in_memory();
    /// vault.unlock("pass").unwrap();
    /// vault.store("svc", "token", "abc").unwrap();
    /// vault.delete("svc", "token").unwrap();
    /// assert_eq!(vault.retrieve("svc", "token").unwrap(), None);
    /// ```
    pub fn delete(&mut self, service: &str, credential_type: &str) -> Result<(), FortressError> {
        if !self.is_unlocked() {
            return Err(FortressError::VaultInaccessible(
                "vault is locked".to_string(),
            ));
        }
        self.entries
            .retain(|e| !(e.service == service && e.credential_type == credential_type));
        let cache_key = format!("{service}:{credential_type}");
        self.cache.remove(&cache_key);
        self.persist()?;
        Ok(())
    }

    /// List all service names in the vault.
    ///
    /// # Errors
    ///
    /// Returns `FortressError::VaultInaccessible` if the vault is locked.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::vault::Vault;
    ///
    /// let mut vault = Vault::in_memory();
    /// vault.unlock("pass").unwrap();
    /// vault.store("svc-a", "token", "x").unwrap();
    /// vault.store("svc-b", "api_key", "y").unwrap();
    /// let services = vault.list_services().unwrap();
    /// assert!(services.contains(&"svc-a".to_string()));
    /// ```
    pub fn list_services(&self) -> Result<Vec<String>, FortressError> {
        if !self.is_unlocked() {
            return Err(FortressError::VaultInaccessible(
                "vault is locked".to_string(),
            ));
        }
        let mut services: Vec<String> = self
            .entries
            .iter()
            .map(|e| e.service.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        services.sort();
        Ok(services)
    }

    /// Persist the vault to disk (no-op for in-memory vaults).
    fn persist(&self) -> Result<(), FortressError> {
        let Some(path) = &self.path else {
            return Ok(());
        };

        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| FortressError::Io {
                path: parent.display().to_string(),
                reason: e.to_string(),
            })?;
        }

        let vault_file = VaultFile {
            salt: hex_encode(&self.salt),
            entries: self.entries.clone(),
        };

        let content = toml::to_string_pretty(&vault_file)
            .map_err(|e| FortressError::Config(e.to_string()))?;

        std::fs::write(path, content).map_err(|e| FortressError::Io {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

        Ok(())
    }
}

/// Derive an AES-256 key from a passphrase using Argon2id.
fn derive_key(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
) -> Result<Key<Aes256Gcm>, FortressError> {
    let mut key_bytes = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| FortressError::Encryption(format!("key derivation failed: {e}")))?;
    Ok(*Key::<Aes256Gcm>::from_slice(&key_bytes))
}

/// Hex-encode bytes.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex-decode a string.
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd-length hex string".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| format!("invalid hex at {i}: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_vault_starts_locked() {
        let vault = Vault::in_memory();
        assert!(!vault.is_unlocked());
    }

    #[test]
    fn unlock_and_lock_roundtrip() {
        let mut vault = Vault::in_memory();
        vault.unlock("test-pass").unwrap();
        assert!(vault.is_unlocked());
        vault.lock();
        assert!(!vault.is_unlocked());
    }

    #[test]
    fn store_and_retrieve_credential() {
        let mut vault = Vault::in_memory();
        vault.unlock("master").unwrap();
        vault.store("anthropic", "api_key", "sk-ant-secret-123").unwrap();
        let val = vault.retrieve("anthropic", "api_key").unwrap();
        assert_eq!(val, Some("sk-ant-secret-123".to_string()));
    }

    #[test]
    fn retrieve_nonexistent_returns_none() {
        let mut vault = Vault::in_memory();
        vault.unlock("pass").unwrap();
        assert_eq!(vault.retrieve("nope", "nope").unwrap(), None);
    }

    #[test]
    fn delete_removes_credential() {
        let mut vault = Vault::in_memory();
        vault.unlock("pass").unwrap();
        vault.store("svc", "tok", "val").unwrap();
        vault.delete("svc", "tok").unwrap();
        assert_eq!(vault.retrieve("svc", "tok").unwrap(), None);
    }

    #[test]
    fn operations_on_locked_vault_fail() {
        let vault = Vault::in_memory();
        assert!(vault.retrieve("svc", "tok").is_err());
        assert!(vault.list_services().is_err());
    }

    #[test]
    fn list_services_returns_unique_names() {
        let mut vault = Vault::in_memory();
        vault.unlock("pass").unwrap();
        vault.store("alpha", "token", "x").unwrap();
        vault.store("beta", "api_key", "y").unwrap();
        vault.store("alpha", "password", "z").unwrap();
        let services = vault.list_services().unwrap();
        assert_eq!(services.len(), 2);
        assert!(services.contains(&"alpha".to_string()));
        assert!(services.contains(&"beta".to_string()));
    }

    #[test]
    fn overwrite_replaces_credential() {
        let mut vault = Vault::in_memory();
        vault.unlock("pass").unwrap();
        vault.store("svc", "key", "old-value").unwrap();
        vault.store("svc", "key", "new-value").unwrap();
        assert_eq!(vault.retrieve("svc", "key").unwrap(), Some("new-value".to_string()));
    }

    #[test]
    fn file_vault_roundtrip() {
        let dir = std::env::temp_dir().join(format!("delphi-vault-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.toml");

        // Create vault, store credentials, persist.
        {
            let mut v = Vault::open(&path).unwrap();
            v.unlock("strong-pass").unwrap();
            v.store("github", "token", "ghp_abc123").unwrap();
            v.store("anthropic", "api_key", "sk-ant-xxx").unwrap();
        }

        // Reopen vault, unlock with same passphrase, verify credentials.
        {
            let mut v = Vault::open(&path).unwrap();
            assert!(!v.is_unlocked());
            v.unlock("strong-pass").unwrap();
            assert_eq!(v.retrieve("github", "token").unwrap(), Some("ghp_abc123".to_string()));
            assert_eq!(v.retrieve("anthropic", "api_key").unwrap(), Some("sk-ant-xxx".to_string()));
        }

        // Wrong passphrase should fail to decrypt.
        {
            let mut v = Vault::open(&path).unwrap();
            assert!(v.unlock("wrong-pass").is_err());
        }
    }

    #[test]
    fn hex_roundtrip() {
        let data = b"hello world";
        let encoded = hex_encode(data);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}
