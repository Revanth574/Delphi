// SPDX-License-Identifier: MIT

//! The typed runtime audit entry — audit = reality (Increment 1d, F6).
//!
//! `docs/TRUST_MODEL.md` §7: a typed entry whose hash derives from the **same**
//! canonical [`PendingAction`] + [`SandboxProfile`] that drove preview/approval/
//! execute, so the log cannot be tampered and matches what was approved. But F6
//! was specifically *integrity ≠ truth*, and "audit = reality" has **two** parts:
//!
//! 1. **approved-action fields** — derived from the canonical object (the
//!    `action_digest`, the `sandbox_profile_digest`, the tier). These give
//!    **audit = approval**: the log records the action that was approved. The hash
//!    covers them under an exhaustive **no-`..` destructure** (mirroring
//!    `fortress::audit::AuditEntry`), so a new field cannot be silently omitted —
//!    the pre-foreclosed half.
//! 2. **outcome fields** — the *actual* execution result (`outcome`, `exit_code`),
//!    which are **not** in the canonical object (it is built before exec). These
//!    give **audit = reality**: they MUST be wired from the real
//!    [`execute_approved`](crate::execute::execute_approved) return value, never a
//!    synthesized/assumed "success" (the F6 "log the description, not what
//!    happened" trap).
//!
//! So audit = reality is: the log records the **approved action** (digest-bound,
//! tamper-evident) AND its **actual outcome** (wired from the real execution) —
//! integrity AND truth.

use std::process::Output;

use delphi_hardening::canonical_hash::CanonicalHasher;

use crate::action::{canonical_action_digest, PendingAction, RequiredTier};
use crate::sandbox::SandboxProfile;
use crate::RuntimeError;

/// What actually happened to the action — a post-execution fact wired from the
/// real [`execute_approved`](crate::execute::execute_approved) result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExecOutcome {
    /// The sandbox ran to completion (see `exit_code`).
    Completed = 0,
    /// The consent gate denied the action — it never executed.
    Denied = 1,
    /// The sandbox could not be spawned.
    SpawnFailed = 2,
}

/// A typed, hash-chainable runtime audit entry.
///
/// The approved-action fields derive from the canonical object; the outcome
/// fields record the real execution result.
pub struct RuntimeAuditEntry {
    /// The action's single-use id (approved-action).
    pub pending_id: String,
    /// `canonical_action_digest(action)` — binds the whole approved action.
    pub action_digest: [u8; 32],
    /// Digest of the derived sandbox profile (the enforced scope).
    pub sandbox_profile_digest: [u8; 32],
    /// The required consent tier (approved-action).
    pub required_tier: RequiredTier,
    /// What actually happened (outcome — wired from the real result).
    pub outcome: ExecOutcome,
    /// The real process exit code, if it ran (outcome).
    pub exit_code: Option<i32>,
    /// When the entry was recorded (unix seconds).
    pub timestamp_unix: u64,
}

impl RuntimeAuditEntry {
    /// Record an entry from the canonical object + profile (approved-action) and
    /// the **real** execution `result` (outcome). The outcome is taken from
    /// `result` — never synthesized.
    #[must_use]
    pub fn record(
        action: &PendingAction,
        profile: &SandboxProfile,
        result: &Result<Output, RuntimeError>,
        now: u64,
    ) -> Self {
        let (outcome, exit_code) = match result {
            Ok(output) => (ExecOutcome::Completed, output.status.code()),
            Err(RuntimeError::Unapproved) => (ExecOutcome::Denied, None),
            Err(_) => (ExecOutcome::SpawnFailed, None),
        };
        Self {
            pending_id: action.pending_id.clone(),
            action_digest: canonical_action_digest(action),
            sandbox_profile_digest: profile_digest(profile),
            required_tier: action.required_tier,
            outcome,
            exit_code,
            timestamp_unix: now,
        }
    }

    /// The entry hash, over **every** field under an exhaustive no-`..`
    /// destructure (mirrors `fortress::audit::AuditEntry` — a new field fails to
    /// compile here until it is hashed).
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        let RuntimeAuditEntry {
            pending_id,
            action_digest,
            sandbox_profile_digest,
            required_tier,
            outcome,
            exit_code,
            timestamp_unix,
        } = self;
        let mut h = CanonicalHasher::new(7);
        h.field(pending_id.as_bytes())
            .fixed(action_digest)
            .fixed(sandbox_profile_digest)
            .fixed(&[*required_tier as u8])
            .fixed(&[*outcome as u8])
            .seq(usize::from(exit_code.is_some()), |s| {
                if let Some(c) = exit_code {
                    s.fixed(&c.to_le_bytes());
                }
            })
            .fixed(&timestamp_unix.to_le_bytes());
        h.finish().expect("declared 7 fields, appended 7")
    }
}

/// Digest of a sandbox profile's args (the enforced scope), as one canonical seq.
fn profile_digest(profile: &SandboxProfile) -> [u8; 32] {
    let mut h = CanonicalHasher::new(1);
    h.seq(profile.args().len(), |s| {
        for a in profile.args() {
            s.field(a.as_bytes());
        }
    });
    h.finish().expect("declared 1 field, appended 1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::Duration;

    use crate::action::{BindMode, NetPolicy};
    use crate::execute::execute_approved;
    use crate::token::{mint, MintingKey};

    const NOW: u64 = 1_000;

    fn denied() -> Result<Output, RuntimeError> {
        Err(RuntimeError::Unapproved)
    }

    fn sample_action() -> PendingAction {
        PendingAction {
            pending_id: "act-audit".into(),
            preview_version: 1,
            executable_fd: fs::File::open("/dev/null").unwrap().into(),
            executable_digest: [0xAB; 32],
            argv: vec!["tool".into()],
            cwd: PathBuf::from("/"),
            env_delta: vec![],
            fs_binds: vec![(PathBuf::from("/data"), BindMode::ReadOnly)],
            net_policy: NetPolicy::None,
            timeout: Duration::from_secs(30),
            required_tier: RequiredTier::Biometric,
            script: None,
        }
    }

    /// Build an entry directly with a chosen outcome (the fields are public).
    fn entry_with(
        a: &PendingAction,
        p: &SandboxProfile,
        outcome: ExecOutcome,
        exit_code: Option<i32>,
    ) -> RuntimeAuditEntry {
        RuntimeAuditEntry {
            pending_id: a.pending_id.clone(),
            action_digest: canonical_action_digest(a),
            sandbox_profile_digest: profile_digest(p),
            required_tier: a.required_tier,
            outcome,
            exit_code,
            timestamp_unix: NOW,
        }
    }

    /// no-`..` coverage (mirrors AuditEntry): a new field fails to compile in both
    /// `hash()` and here. Hash is deterministic.
    #[test]
    fn hash_destructure_covers_every_field() {
        let a = sample_action();
        let p = SandboxProfile::derive(&a);
        let e = RuntimeAuditEntry::record(&a, &p, &denied(), NOW);
        let RuntimeAuditEntry {
            pending_id,
            action_digest,
            sandbox_profile_digest,
            required_tier,
            outcome,
            exit_code,
            timestamp_unix,
        } = &e;
        let _ = (
            pending_id,
            action_digest,
            sandbox_profile_digest,
            required_tier,
            outcome,
            exit_code,
            timestamp_unix,
        );
        let e2 = RuntimeAuditEntry::record(&sample_action(), &p, &denied(), NOW);
        assert_eq!(e.hash(), e2.hash(), "deterministic over identical inputs");
    }

    /// audit = APPROVAL: `action_digest` IS the canonical digest of the approved
    /// object, and the recorded outcome is inside the integrity hash (the recorded
    /// reality cannot be edited without breaking the chain).
    #[test]
    fn audit_binds_the_approved_action_and_the_recorded_outcome() {
        let a = sample_action();
        let p = SandboxProfile::derive(&a);
        let denied_entry = RuntimeAuditEntry::record(&a, &p, &denied(), NOW);
        assert_eq!(
            denied_entry.action_digest,
            canonical_action_digest(&a),
            "audit binds the approved action"
        );
        let done = entry_with(&a, &p, ExecOutcome::Completed, Some(0));
        assert_ne!(
            denied_entry.hash(),
            done.hash(),
            "changing the recorded outcome changes the hash (integrity over the recorded reality)"
        );
    }

    fn bwrap_available() -> bool {
        Command::new("bwrap")
            .args([
                "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib", "--ro-bind", "/lib64",
                "/lib64", "--unshare-all", "--die-with-parent", "--", "/usr/bin/true",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Build an action whose executable is the script at `exe` (which really
    /// `exit 7`s), with the toolset bound so `/bin/sh` runs.
    fn exit7_action(exe: &Path) -> PendingAction {
        fs::write(exe, "#!/bin/sh\nexit 7\n").unwrap();
        fs::set_permissions(exe, fs::Permissions::from_mode(0o755)).unwrap();
        PendingAction {
            pending_id: "act-exit7".into(),
            preview_version: 1,
            executable_fd: fs::File::open(exe).unwrap().into(),
            executable_digest: [0x11; 32],
            argv: vec!["tool".into()],
            cwd: PathBuf::from("/"),
            env_delta: vec![],
            fs_binds: vec![
                (PathBuf::from("/usr"), BindMode::ReadOnly),
                (PathBuf::from("/bin"), BindMode::ReadOnly),
                (PathBuf::from("/lib"), BindMode::ReadOnly),
                (PathBuf::from("/lib64"), BindMode::ReadOnly),
            ],
            net_policy: NetPolicy::None,
            timeout: Duration::from_secs(30),
            required_tier: RequiredTier::Biometric,
            script: None,
        }
    }

    /// audit = REALITY: the outcome is wired from the REAL `execute_approved`
    /// return. A real run that exits 7 records exit 7; feeding a synthesized result
    /// records that wrong outcome instead (RED — F6 "log what happened, not the
    /// description").
    #[test]
    fn outcome_records_the_real_execution_result() {
        if !bwrap_available() {
            eprintln!("SKIP outcome_records_the_real_execution_result: requires bwrap + unprivileged userns");
            return;
        }
        let dir = PathBuf::from(format!("/tmp/delphi-audit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("tool.sh");
        let action = exit7_action(&exe);
        let profile = SandboxProfile::derive(&action);
        let key = MintingKey::from_bytes([1u8; 32]);
        let token = mint(&key, &canonical_action_digest(&action), NOW);

        let real = execute_approved(&action, &token, &key, NOW);
        let audit = RuntimeAuditEntry::record(&action, &profile, &real, NOW);
        assert_eq!(
            audit.exit_code,
            Some(7),
            "audit = reality: the REAL exit code 7 is recorded, wired from execute_approved"
        );
        assert!(matches!(audit.outcome, ExecOutcome::Completed));

        // RED: an audit built from a synthesized/wrong result records THAT outcome
        // (Denied) — the real run Completed(7). Audit=reality requires wiring the
        // outcome from the real execution, not assuming one.
        let mis = RuntimeAuditEntry::record(&action, &profile, &denied(), NOW);
        let _ = fs::remove_dir_all(&dir);
        assert!(
            matches!(mis.outcome, ExecOutcome::Denied) && mis.exit_code.is_none(),
            "RED: a synthesized result records the wrong outcome (Denied) while reality was \
             Completed(7) — the outcome MUST be wired from the real execution result"
        );
    }
}
