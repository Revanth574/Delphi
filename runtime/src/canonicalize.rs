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
    // TRUST_MODEL v7 (D0A-R9-02): bind an IMMUTABLE SNAPSHOT, not the filesystem object.
    // The mutable source fd is dropped here — after this line nothing in the action can be
    // changed by whoever owns the path.
    let executable_fd = crate::action::seal_executable_snapshot(&bytes)?;
    let executable_digest = sha256(&bytes);
    drop(file);

    // Shebang → pin the interpreter object + seal the script content (R3-04).
    let script = if bytes.starts_with(b"#!") {
        Some(build_script_pin(&bytes)?)
    } else {
        None
    };

    // VALIDATE untrusted wire enums (fail-CLOSED): prost's enum accessors silently
    // normalize an out-of-range i32 to the default (`required_tier` → the most
    // permissive AUTONOMOUS) — the opposite of fail-closed. Reject unknown instead.
    let net_policy = map_net(
        pb::NetPolicy::try_from(proposal.net_policy)
            .map_err(|_| RuntimeError::Protocol(format!("invalid net_policy {}", proposal.net_policy)))?,
    );
    let required_tier = map_tier(
        pb::RequiredTier::try_from(proposal.required_tier)
            .map_err(|_| RuntimeError::Protocol(format!("invalid required_tier {}", proposal.required_tier)))?,
    );
    let fs_binds = proposal
        .fs_binds
        .iter()
        .map(|b| {
            let mode = pb::BindMode::try_from(b.mode)
                .map_err(|_| RuntimeError::Protocol(format!("invalid bind mode {}", b.mode)))?;
            Ok((PathBuf::from(&b.path), map_bind_mode(mode)))
        })
        .collect::<Result<Vec<_>, RuntimeError>>()?;

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
        fs_binds,
        net_policy,
        timeout: Duration::from_secs(proposal.timeout_secs),
        required_tier,
        script,
    })
}

/// Parse the shebang, open + hash the interpreter through its fd, and seal the
/// script content (`ScriptPin::sealed` applies the full immutability seal set).
fn build_script_pin(script_bytes: &[u8]) -> Result<ScriptPin, RuntimeError> {
    let line_end = script_bytes.iter().position(|&b| b == b'\n').unwrap_or(script_bytes.len());
    // Kernel cap (BINPRM_BUF_SIZE): the interpreted `#!` line is bounded; a longer one
    // is malformed/hostile — reject before parsing.
    if line_end > 255 {
        return Err(RuntimeError::Protocol("shebang line exceeds the kernel length cap".into()));
    }
    let shebang = std::str::from_utf8(&script_bytes[2..line_end])
        .map_err(|_| RuntimeError::Protocol("non-UTF-8 shebang line".into()))?
        .trim();
    // Kernel semantics: interpreter = the first token; everything after the first
    // whitespace is ONE optional argument (e.g. `-I` in `#!/usr/bin/python3 -I`).
    let mut parts = shebang.splitn(2, char::is_whitespace);
    let interp_path = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| RuntimeError::Protocol("empty shebang interpreter".into()))?;
    let interpreter_arg = parts.next().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);

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
    // TRUST_MODEL v7 NAMED LIMIT 1: a nested shebang is REFUSED, here, before anything
    // executes. The kernel opens every interpreter in a chain BY PATH, recursively
    // (fs/binfmt_script.c), so pinning one interpreter leaves the rest unpinned; and
    // recursively snapshotting a chain fails SILENTLY at exec if it misses an element,
    // which is R9-02's own shape. Refusing fails closed, loudly, where a human can be told.
    if interp_bytes.starts_with(b"#!") {
        return Err(RuntimeError::Protocol(format!(
            "the script's interpreter `{interp_path}` is itself a `#!` script. The kernel \
             resolves each interpreter in the chain by PATH, so only the first can be \
             pinned — a nested chain is refused rather than partially bound \
             (TRUST_MODEL.md §3 v7, named limit 1)."
        )));
    }
    let interpreter_digest = sha256(&interp_bytes);
    // Snapshotted too: for a script it is the interpreter that actually executes.
    let interpreter_fd = crate::action::seal_executable_snapshot(&interp_bytes)?;
    drop(interp);

    ScriptPin::sealed(interpreter_fd, interpreter_digest, interpreter_arg, script_bytes)
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
        let exe = write_exe(dir.path(), "tool", content);
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
        let exe = write_exe(dir.path(), "tool.sh", script);
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

    /// B1-02: the shebang's optional interpreter arg is parsed + stored (kernel
    /// semantics — the first token is the interpreter, the rest is ONE arg).
    #[test]
    fn canonicalize_parses_the_shebang_interpreter_arg() {
        let dir = tempdir();
        let exe = write_exe(dir.path(), "iso.py", b"#!/usr/bin/python3 -I\nprint(1)\n");
        let action = canonicalize(&base_proposal(exe.to_str().unwrap()), "act-arg".into()).unwrap();
        let sp = action.script.as_ref().expect("shebang → ScriptPin");
        assert_eq!(sp.interpreter_arg.as_deref(), Some("-I"), "the interpreter arg is bound, not dropped");

        // No arg → None.
        let plain = write_exe(dir.path(), "plain.sh", b"#!/bin/sh\n:\n");
        let a2 = canonicalize(&base_proposal(plain.to_str().unwrap()), "act-na".into()).unwrap();
        assert_eq!(a2.script.as_ref().unwrap().interpreter_arg, None);
    }

    /// B1-03: an out-of-range wire enum is REJECTED (fail-closed), not normalized to
    /// the default (required_tier → AUTONOMOUS, the most permissive).
    #[test]
    fn out_of_range_wire_enum_is_rejected() {
        let dir = tempdir();
        let exe = write_exe(dir.path(), "tool", b"binary");
        let mut p = base_proposal(exe.to_str().unwrap());
        p.required_tier = 99; // not a valid RequiredTier
        assert!(
            matches!(canonicalize(&p, "x".into()), Err(RuntimeError::Protocol(_))),
            "RED: an out-of-range required_tier must be rejected, not normalized to AUTONOMOUS"
        );
        let mut p2 = base_proposal(exe.to_str().unwrap());
        p2.net_policy = 42;
        assert!(matches!(canonicalize(&p2, "y".into()), Err(RuntimeError::Protocol(_))), "invalid net_policy rejected");
    }

    /// A temp dir that removes itself on drop — including when a test panics.
    ///
    /// The previous version built `/tmp/delphi-canon-<pid>` by hand and **never removed it**,
    /// on any path. It was the only site in this crate with no cleanup at all, and it is the
    /// source of the `delphi-canon-*` accumulation on `/tmp` (8 present when this was fixed).
    /// Callers bind the returned `TempDir`, so the directory lives exactly as long as the
    /// test does.
    fn tempdir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("delphi-canon-")
            .tempdir()
            .expect("tempdir")
    }
}
