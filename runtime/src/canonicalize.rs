// SPDX-License-Identifier: MIT

//! Canonicalization — AI `Propose` → the ONE canonical `PendingAction` (Increment B1).
//!
//! `docs/TRUST_MODEL.md` §3: "the arbiter `open`s the executable **before** preview,
//! hashes the bytes read *through that fd*, and execs **that exact fd**." This is the
//! BUILT piece of B1 — new glue over proven parts:
//!
//! * **open + hash-through-the-held-fd** — the TOCTOU-safe difference from the test
//!   helper's read-bytes-separately: the bytes hashed into `executable_digest` are
//!   read through the very fd [`execute`](crate::execute) later exec's, so there is
//!   no path→exec swap window.
//! * **`#!` detect/parse** — the only other new logic.
//! * **reused-proven** — [`ScriptPin::sealed`](crate::action::ScriptPin::sealed)
//!   (round-3 full seal set), [`canonical_action_digest`](crate::action), and
//!   `execute`'s fd-exec are unchanged.
//!
//! The AI never sees this object or its fds; it gets only a `pending_id`.

use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::action::{BindMode, NetPolicy, PendingAction, RequiredTier, ScriptPin};
use crate::wire::pb;
use crate::RuntimeError;

/// SHA-256 of `bytes`.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Build the canonical [`PendingAction`] from an AI [`pb::Propose`], assigning
/// `pending_id`.
///
/// # Errors
///
/// [`RuntimeError::Filesystem`] if the proposed executable (or a script's
/// interpreter) cannot be opened/read; [`RuntimeError::Protocol`] for a malformed
/// shebang; [`RuntimeError::Syscall`] if sealing a script memfd fails.
pub fn canonicalize(
    proposal: &pb::Propose,
    pending_id: String,
) -> Result<PendingAction, RuntimeError> {
    // Open the executable, then hash the bytes READ THROUGH the held fd — the same
    // fd `execute` re-exec's, so the hash and the exec see the same kernel object.
    let mut file = File::open(&proposal.exe_path).map_err(|source| RuntimeError::Filesystem {
        op: "open proposed executable",
        path: PathBuf::from(&proposal.exe_path),
        source,
    })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|source| RuntimeError::Filesystem {
        op: "read proposed executable",
        path: PathBuf::from(&proposal.exe_path),
        source,
    })?;
    let executable_digest = sha256(&bytes);
    let executable_fd: OwnedFd = file.into();

    // Shebang → pin the interpreter object + seal the script content (R3-04).
    let script = if bytes.starts_with(b"#!") {
        Some(build_script_pin(&bytes)?)
    } else {
        None
    };

    Ok(PendingAction {
        pending_id,
        preview_version: 1,
        executable_fd,
        executable_digest,
        argv: proposal.argv.clone(),
        cwd: PathBuf::from(&proposal.cwd),
        env_delta: proposal
            .env_delta
            .iter()
            .map(|e| (e.key.clone(), e.value.clone()))
            .collect(),
        fs_binds: proposal
            .fs_binds
            .iter()
            .map(|b| (PathBuf::from(&b.path), map_bind_mode(b.mode())))
            .collect(),
        net_policy: map_net(proposal.net_policy()),
        timeout: Duration::from_secs(proposal.timeout_secs),
        required_tier: map_tier(proposal.required_tier()),
        script,
    })
}

/// Parse the shebang, open + hash the interpreter through its fd, and seal the
/// script content (`ScriptPin::sealed` applies the full immutability seal set).
fn build_script_pin(script_bytes: &[u8]) -> Result<ScriptPin, RuntimeError> {
    let line_end = script_bytes.iter().position(|&b| b == b'\n').unwrap_or(script_bytes.len());
    let shebang = std::str::from_utf8(&script_bytes[2..line_end])
        .map_err(|_| RuntimeError::Protocol("non-UTF-8 shebang line".into()))?;
    let interp_path = shebang
        .split_whitespace()
        .next()
        .ok_or_else(|| RuntimeError::Protocol("empty shebang interpreter".into()))?;

    let mut interp = File::open(interp_path).map_err(|source| RuntimeError::Filesystem {
        op: "open script interpreter",
        path: PathBuf::from(interp_path),
        source,
    })?;
    let mut interp_bytes = Vec::new();
    interp.read_to_end(&mut interp_bytes).map_err(|source| RuntimeError::Filesystem {
        op: "read script interpreter",
        path: PathBuf::from(interp_path),
        source,
    })?;
    let interpreter_digest = sha256(&interp_bytes);
    let interpreter_fd: OwnedFd = interp.into();

    ScriptPin::sealed(interpreter_fd, interpreter_digest, script_bytes)
}

fn map_bind_mode(m: pb::BindMode) -> BindMode {
    match m {
        pb::BindMode::BindReadOnly => BindMode::ReadOnly,
        pb::BindMode::BindReadWrite => BindMode::ReadWrite,
    }
}

fn map_net(n: pb::NetPolicy) -> NetPolicy {
    match n {
        pb::NetPolicy::NetNone => NetPolicy::None,
        pb::NetPolicy::NetFull => NetPolicy::Full,
    }
}

fn map_tier(t: pb::RequiredTier) -> RequiredTier {
    match t {
        pb::RequiredTier::TierAutonomous => RequiredTier::Autonomous,
        pb::RequiredTier::TierConfirm => RequiredTier::Confirm,
        pb::RequiredTier::TierBiometric => RequiredTier::Biometric,
        pb::RequiredTier::TierHardware => RequiredTier::Hardware,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::canonical_action_digest;
    use std::os::unix::fs::PermissionsExt;

    fn write_exe(dir: &std::path::Path, name: &str, content: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn base_proposal(exe_path: &str) -> pb::Propose {
        pb::Propose {
            argv: vec!["tool".into()],
            cwd: "/".into(),
            env_delta: vec![],
            fs_binds: vec![],
            exe_path: exe_path.into(),
            net_policy: pb::NetPolicy::NetNone as i32,
            timeout_secs: 30,
            required_tier: pb::RequiredTier::TierBiometric as i32,
        }
    }

    /// Canonicalization hashes the bytes read THROUGH the opened fd — so
    /// `executable_digest` equals the on-disk content's SHA-256, and the digest is
    /// stable/derivable.
    #[test]
    fn canonicalize_binary_hashes_through_the_held_fd() {
        let dir = tempdir();
        let content = b"\x7fELF not-really but binary-ish";
        let exe = write_exe(&dir, "tool", content);
        let action = canonicalize(&base_proposal(exe.to_str().unwrap()), "act-1".into()).unwrap();

        assert_eq!(action.executable_digest, sha256(content), "digest = content hash through fd");
        assert_eq!(action.pending_id, "act-1");
        assert!(action.script.is_none(), "no shebang → binary, no ScriptPin");
        // The canonical digest is well-formed over the whole object.
        assert_eq!(canonical_action_digest(&action).len(), 32);
    }

    /// A `#!` proposal yields a ScriptPin (interpreter pinned + script sealed).
    #[test]
    fn canonicalize_script_builds_a_sealed_scriptpin() {
        let dir = tempdir();
        let script = b"#!/bin/sh\necho hi\n";
        let exe = write_exe(&dir, "tool.sh", script);
        let action = canonicalize(&base_proposal(exe.to_str().unwrap()), "act-2".into()).unwrap();

        let sp = action.script.as_ref().expect("shebang → ScriptPin");
        assert_eq!(sp.script_digest, sha256(script), "script content bound");
        // /bin/sh exists on the build host; its interpreter digest is non-zero.
        assert_ne!(sp.interpreter_digest, [0u8; 32]);
    }

    /// A missing executable surfaces a typed, actionable error (not a panic).
    #[test]
    fn missing_executable_is_a_typed_error() {
        // `PendingAction` has no `Debug` (live fds), so match the Result rather than
        // `unwrap_err` (which would need the Ok value to be Debug).
        let result = canonicalize(&base_proposal("/no/such/binary"), "act-3".into());
        assert!(matches!(result, Err(RuntimeError::Filesystem { .. })), "missing exe → typed error");
    }

    fn tempdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("delphi-canon-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        d
    }
}
