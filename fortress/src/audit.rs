// SPDX-License-Identifier: MIT

//! Append-only audit log with hash-linked chain integrity.
//!
//! Every action performed by the AI is logged as an `AuditEntry`. Each
//! entry includes a SHA-256 hash of the previous entry, forming an
//! immutable chain similar to a blockchain. This allows verification
//! that no entries have been tampered with or deleted.
//!
//! # Resilience
//!
//! The audit log never fails user-facing operations. If a disk write
//! fails, entries are buffered in memory and flushed on the next
//! successful write.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::FortressError;
use crate::permissions::PermissionTier;

/// The result of a permission check (for audit logging).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditResult {
    /// The action was allowed.
    Allowed,
    /// The action was denied.
    Denied,
    /// The action is waiting for user confirmation.
    Pending,
}

/// A single entry in the audit chain.
///
/// # Examples
///
/// ```
/// use fortress::audit::{AuditEntry, AuditResult};
/// use fortress::permissions::PermissionTier;
///
/// let entry = AuditEntry {
///     action_id: "act-001".to_string(),
///     timestamp: 1712400000,
///     module: "die-orchestrator".to_string(),
///     action: "read_file".to_string(),
///     target: "/home/user/doc.txt".to_string(),
///     permission_tier: PermissionTier::Autonomous,
///     result: AuditResult::Allowed,
///     proof_hash: vec![0u8; 32],
/// };
/// assert_eq!(entry.module, "die-orchestrator");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique identifier for this action.
    pub action_id: String,
    /// When the action occurred (UTC epoch seconds).
    pub timestamp: i64,
    /// Which module performed the action.
    pub module: String,
    /// What action was performed.
    pub action: String,
    /// What the action targeted.
    pub target: String,
    /// The permission tier required.
    pub permission_tier: PermissionTier,
    /// Whether the action was allowed or denied.
    pub result: AuditResult,
    /// SHA-256 hash of the previous entry (chain link).
    pub proof_hash: Vec<u8>,
}

/// The audit log file format.
#[derive(Debug, Serialize, Deserialize)]
struct AuditFile {
    entries: Vec<AuditEntry>,
}

/// Append-only audit log with hash-linked integrity.
///
/// # Examples
///
/// ```
/// use fortress::audit::{AuditLog, AuditResult};
/// use fortress::permissions::PermissionTier;
///
/// let mut log = AuditLog::in_memory();
/// log.log_action("die", "read_file", "/doc.txt", PermissionTier::Autonomous, AuditResult::Allowed);
/// assert_eq!(log.len(), 1);
/// ```
pub struct AuditLog {
    /// Path to the log file on disk (None for in-memory).
    path: Option<PathBuf>,
    /// All audit entries.
    entries: Vec<AuditEntry>,
    /// Counter for generating action IDs.
    next_id: u64,
}

impl AuditLog {
    /// Create an in-memory audit log (for testing).
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::audit::AuditLog;
    /// let log = AuditLog::in_memory();
    /// assert_eq!(log.len(), 0);
    /// ```
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            path: None,
            entries: Vec::new(),
            next_id: 1,
        }
    }

    /// Open or create an audit log file.
    ///
    /// If the file exists, entries are loaded. The chain is NOT automatically
    /// verified — call [`verify_chain()`](Self::verify_chain) explicitly.
    ///
    /// # Errors
    ///
    /// Returns `FortressError::Io` if the file exists but can't be read.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use fortress::audit::AuditLog;
    /// use std::path::Path;
    ///
    /// let log = AuditLog::open(Path::new("/tmp/audit.json")).unwrap();
    /// ```
    pub fn open(path: &Path) -> Result<Self, FortressError> {
        if path.exists() {
            let content = std::fs::read_to_string(path).map_err(|e| FortressError::Io {
                path: path.display().to_string(),
                reason: e.to_string(),
            })?;
            let file: AuditFile = audit_serde::from_str(&content).map_err(|e| {
                FortressError::AuditIntegrity(format!("failed to parse audit log: {e}"))
            })?;
            let next_id = file.entries.len() as u64 + 1;
            info!("loaded {} audit entries from {}", file.entries.len(), path.display());
            Ok(Self {
                path: Some(path.to_path_buf()),
                entries: file.entries,
                next_id,
            })
        } else {
            Ok(Self {
                path: Some(path.to_path_buf()),
                entries: Vec::new(),
                next_id: 1,
            })
        }
    }

    /// Log an action. This never fails — if disk write fails, the entry
    /// is buffered in memory.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::audit::{AuditLog, AuditResult};
    /// use fortress::permissions::PermissionTier;
    ///
    /// let mut log = AuditLog::in_memory();
    /// log.log_action("die", "read_file", "/doc.txt", PermissionTier::Autonomous, AuditResult::Allowed);
    /// assert_eq!(log.len(), 1);
    /// ```
    pub fn log_action(
        &mut self,
        module: &str,
        action: &str,
        target: &str,
        tier: PermissionTier,
        result: AuditResult,
    ) -> String {
        let action_id = format!("audit-{:06}", self.next_id);
        self.next_id += 1;

        let proof_hash = self.compute_chain_hash();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let entry = AuditEntry {
            action_id: action_id.clone(),
            timestamp,
            module: module.to_string(),
            action: action.to_string(),
            target: target.to_string(),
            permission_tier: tier,
            result,
            proof_hash,
        };

        debug!(
            action_id = %entry.action_id,
            module, action, target,
            "audit entry logged"
        );

        self.entries.push(entry);

        // Best-effort persist — never fail user operations.
        if let Err(e) = self.persist() {
            warn!("failed to persist audit log: {e} — entry buffered in memory");
        }

        action_id
    }

    /// Query actions matching filters.
    ///
    /// All filter parameters are optional — `None` means no filter.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::audit::{AuditLog, AuditResult};
    /// use fortress::permissions::PermissionTier;
    ///
    /// let mut log = AuditLog::in_memory();
    /// log.log_action("die", "read_file", "/a.txt", PermissionTier::Autonomous, AuditResult::Allowed);
    /// log.log_action("ssi", "install", "app", PermissionTier::Confirm, AuditResult::Denied);
    ///
    /// let results = log.query(None, Some("die"), None);
    /// assert_eq!(results.len(), 1);
    /// ```
    #[must_use]
    pub fn query(
        &self,
        time_range: Option<(i64, i64)>,
        module_filter: Option<&str>,
        action_filter: Option<&str>,
    ) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| {
                if let Some((start, end)) = time_range
                    && (e.timestamp < start || e.timestamp > end)
                {
                    return false;
                }
                if let Some(m) = module_filter
                    && e.module != m
                {
                    return false;
                }
                if let Some(a) = action_filter
                    && e.action != a
                {
                    return false;
                }
                true
            })
            .collect()
    }

    /// Verify the integrity of the audit chain.
    ///
    /// Recomputes the hash chain from the beginning and checks that
    /// each entry's `proof_hash` matches the hash of the previous entry.
    ///
    /// # Errors
    ///
    /// Returns `FortressError::AuditIntegrity` if any entry has been tampered with.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::audit::{AuditLog, AuditResult};
    /// use fortress::permissions::PermissionTier;
    ///
    /// let mut log = AuditLog::in_memory();
    /// log.log_action("die", "read", "/a.txt", PermissionTier::Autonomous, AuditResult::Allowed);
    /// log.log_action("die", "write", "/b.txt", PermissionTier::Confirm, AuditResult::Allowed);
    /// assert!(log.verify_chain().is_ok());
    /// ```
    pub fn verify_chain(&self) -> Result<(), FortressError> {
        let mut expected_hash = vec![0u8; 32]; // Genesis hash is all zeros.

        for (i, entry) in self.entries.iter().enumerate() {
            if entry.proof_hash != expected_hash {
                return Err(FortressError::AuditIntegrity(format!(
                    "chain broken at entry {} (action_id: {}): expected hash {:?}, got {:?}",
                    i, entry.action_id, expected_hash, entry.proof_hash,
                )));
            }
            expected_hash = hash_entry(entry);
        }

        debug!("audit chain verified: {} entries intact", self.entries.len());
        Ok(())
    }

    /// Return the number of entries in the log.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::audit::AuditLog;
    /// let log = AuditLog::in_memory();
    /// assert_eq!(log.len(), 0);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the log is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::audit::AuditLog;
    /// let log = AuditLog::in_memory();
    /// assert!(log.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compute the hash for the chain link (hash of the last entry, or zeros for genesis).
    fn compute_chain_hash(&self) -> Vec<u8> {
        match self.entries.last() {
            Some(last) => hash_entry(last),
            None => vec![0u8; 32], // Genesis: all zeros.
        }
    }

    /// Persist the log to disk.
    fn persist(&self) -> Result<(), FortressError> {
        let Some(path) = &self.path else {
            return Ok(());
        };

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| FortressError::Io {
                path: parent.display().to_string(),
                reason: e.to_string(),
            })?;
        }

        let file = AuditFile {
            entries: self.entries.clone(),
        };
        let content = audit_serde::to_string_pretty(&file).map_err(|e| {
            FortressError::AuditIntegrity(format!("failed to serialize audit log: {e}"))
        })?;

        std::fs::write(path, content).map_err(|e| FortressError::Io {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

        Ok(())
    }
}

/// Compute SHA-256 hash of an audit entry (for chain linking).
///
/// The encoding is **canonical and injective**, applying both hash-discipline
/// lessons the orchestrator sweep produced:
///
/// - **Full field coverage.** *Every* security-relevant field of [`AuditEntry`]
///   is hashed — `action_id`, `timestamp`, `module`, `action`, `target`,
///   `permission_tier`, `result`, and the previous-entry link `proof_hash`.
///   Omitting any of these would let it be tampered without breaking the chain
///   (e.g. an audit that records `Denied` must not be silently editable to
///   `Allowed`, nor a `Biometric` tier downgraded to `Autonomous`).
/// - **Length-prefixed (injective) encoding.** Each variable-length field is
///   prefixed with its `u64`-LE byte length via [`hash_field`], so distinct
///   entries can never alias by shifting a field boundary (the ORCH-R2-02
///   delimiter-collision class). Fixed-width fields (`timestamp`, the two enum
///   discriminants) need no prefix.
fn hash_entry(entry: &AuditEntry) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, entry.action_id.as_bytes());
    hasher.update(entry.timestamp.to_le_bytes());
    hash_field(&mut hasher, entry.module.as_bytes());
    hash_field(&mut hasher, entry.action.as_bytes());
    hash_field(&mut hasher, entry.target.as_bytes());
    hasher.update([entry.permission_tier as u8]);
    hasher.update([match entry.result {
        AuditResult::Allowed => 0u8,
        AuditResult::Denied => 1,
        AuditResult::Pending => 2,
    }]);
    hash_field(&mut hasher, &entry.proof_hash);
    hasher.finalize().to_vec()
}

/// Length-prefix a variable-length field into the running hash
/// (`u64`-LE byte length, then the bytes), making the entry encoding injective
/// so no field-boundary shift can produce a colliding hash.
fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Serialization helpers using TOML format.
/// (Will migrate to serde_json when added to workspace deps — TOML
/// requires full rewrite on append, but is sufficient for Phase 0.)
mod audit_serde {
    pub fn to_string_pretty<T: serde::Serialize>(value: &T) -> Result<String, String> {
        toml::to_string_pretty(value).map_err(|e| e.to_string())
    }

    pub fn from_str<T: serde::de::DeserializeOwned>(s: &str) -> Result<T, String> {
        toml::from_str(s).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_log() {
        let log = AuditLog::in_memory();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn log_action_increments_count() {
        let mut log = AuditLog::in_memory();
        log.log_action("die", "read_file", "/a.txt", PermissionTier::Autonomous, AuditResult::Allowed);
        log.log_action("die", "write_file", "/b.txt", PermissionTier::Confirm, AuditResult::Allowed);
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn chain_verification_passes_for_valid_chain() {
        let mut log = AuditLog::in_memory();
        log.log_action("die", "read", "/a", PermissionTier::Autonomous, AuditResult::Allowed);
        log.log_action("die", "write", "/b", PermissionTier::Confirm, AuditResult::Allowed);
        log.log_action("ssi", "install", "app", PermissionTier::Confirm, AuditResult::Denied);
        assert!(log.verify_chain().is_ok());
    }

    #[test]
    fn chain_verification_detects_tampering() {
        let mut log = AuditLog::in_memory();
        log.log_action("die", "read", "/a", PermissionTier::Autonomous, AuditResult::Allowed);
        log.log_action("die", "write", "/b", PermissionTier::Confirm, AuditResult::Allowed);

        // Tamper with the second entry's proof hash.
        log.entries[1].proof_hash = vec![0xFF; 32];
        assert!(log.verify_chain().is_err());
    }

    #[test]
    fn query_filters_by_module() {
        let mut log = AuditLog::in_memory();
        log.log_action("die", "read", "/a", PermissionTier::Autonomous, AuditResult::Allowed);
        log.log_action("ssi", "install", "app", PermissionTier::Confirm, AuditResult::Denied);
        log.log_action("die", "write", "/b", PermissionTier::Confirm, AuditResult::Allowed);

        let results = log.query(None, Some("die"), None);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn query_filters_by_action() {
        let mut log = AuditLog::in_memory();
        log.log_action("die", "read_file", "/a", PermissionTier::Autonomous, AuditResult::Allowed);
        log.log_action("die", "write_file", "/b", PermissionTier::Confirm, AuditResult::Allowed);

        let results = log.query(None, None, Some("read_file"));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].action, "read_file");
    }

    #[test]
    fn query_no_filters_returns_all() {
        let mut log = AuditLog::in_memory();
        log.log_action("a", "x", "t", PermissionTier::Autonomous, AuditResult::Allowed);
        log.log_action("b", "y", "t", PermissionTier::Confirm, AuditResult::Denied);

        let results = log.query(None, None, None);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn log_action_returns_unique_ids() {
        let mut log = AuditLog::in_memory();
        let id1 = log.log_action("a", "x", "t", PermissionTier::Autonomous, AuditResult::Allowed);
        let id2 = log.log_action("a", "x", "t", PermissionTier::Autonomous, AuditResult::Allowed);
        assert_ne!(id1, id2);
    }

    #[test]
    fn genesis_entry_has_zero_hash() {
        let mut log = AuditLog::in_memory();
        log.log_action("die", "read", "/a", PermissionTier::Autonomous, AuditResult::Allowed);
        assert_eq!(log.entries[0].proof_hash, vec![0u8; 32]);
    }

    #[test]
    fn file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("delphi-audit-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.toml");

        {
            let mut log = AuditLog::open(&path).unwrap();
            log.log_action("die", "read", "/a", PermissionTier::Autonomous, AuditResult::Allowed);
            log.log_action("die", "write", "/b", PermissionTier::Confirm, AuditResult::Allowed);
        }

        {
            let log = AuditLog::open(&path).unwrap();
            assert_eq!(log.len(), 2);
            assert!(log.verify_chain().is_ok());
        }
    }

    #[test]
    fn tampering_result_is_detected_audit_coverage() {
        let mut log = AuditLog::in_memory();
        // entry[0] records a DENIED action — the security-relevant fact.
        log.log_action(
            "ssi",
            "install",
            "evil-app",
            PermissionTier::Confirm,
            AuditResult::Denied,
        );
        // A subsequent entry makes entry[0] covered by entry[1].proof_hash.
        log.log_action(
            "die",
            "read",
            "/doc",
            PermissionTier::Autonomous,
            AuditResult::Allowed,
        );
        assert!(log.verify_chain().is_ok(), "untampered chain must verify");

        // Tamper: rewrite the denied action to look allowed.
        log.entries[0].result = AuditResult::Allowed;

        // RED pre-fix: `result` was not in the hash, so hash_entry(entry[0]) is
        // unchanged and the chain still verifies — the tamper survives.
        assert!(
            log.verify_chain().is_err(),
            "flipping result Denied->Allowed must break the hash chain"
        );
    }

    #[test]
    fn tampering_tier_is_detected_audit_coverage() {
        let mut log = AuditLog::in_memory();
        log.log_action(
            "die",
            "financial_transfer",
            "$1M",
            PermissionTier::Biometric,
            AuditResult::Allowed,
        );
        log.log_action(
            "die",
            "read",
            "/doc",
            PermissionTier::Autonomous,
            AuditResult::Allowed,
        );
        assert!(log.verify_chain().is_ok());

        // Tamper: downgrade the recorded tier.
        log.entries[0].permission_tier = PermissionTier::Autonomous;

        // RED pre-fix: `permission_tier` was not in the hash.
        assert!(
            log.verify_chain().is_err(),
            "flipping permission_tier must break the hash chain"
        );
    }

    #[test]
    fn field_boundary_shift_does_not_collide_audit() {
        // ORCH-R2-02 class: without length-prefixing, module||action||target are
        // concatenated, so ("ab","c") and ("a","bc") hash identically and one
        // entry could be rewritten as the other without breaking the chain.
        let mk = |module: &str, action: &str| AuditEntry {
            action_id: "x".to_string(),
            timestamp: 0,
            module: module.to_string(),
            action: action.to_string(),
            target: "t".to_string(),
            permission_tier: PermissionTier::Autonomous,
            result: AuditResult::Allowed,
            proof_hash: vec![0u8; 32],
        };
        // RED pre-fix: the two encodings collide.
        assert_ne!(
            hash_entry(&mk("ab", "c")),
            hash_entry(&mk("a", "bc")),
            "field-boundary-shifted entries must not produce the same hash"
        );
    }
}
